//! Plugin side of the `http` transport wire.
//!
//! An `http`-wire transport (see [`crate::ffi::SyncTransport::start_http`])
//! receives HTTP requests somewhere the gateway cannot see (a tunnel, a
//! relay) and hands each one to the gateway with
//! [`HttpIngressServer::serve`]. The gateway answers through its own HTTP
//! router; the plugin reads the answer from the returned
//! [`IngressResponse`] and writes it to its client.
//!
//! The answer is queued here until the plugin reads it. When the queue
//! holds [`QUEUE_LIMIT_BYTES`], the gateway waits before it sends more, so a
//! slow client slows the gateway's side of that response, not its memory.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use abi_stable::std_types::{RString, RVec};
use mcpg_plugin_protocol::abi::{
    HTTP_SINK_ACCEPTED, HTTP_SINK_CLOSED, HTTP_SINK_FULL, HttpResponderRef, HttpServerRef,
};
use mcpg_plugin_protocol::transport::{HttpIngressRequestHead, HttpIngressResponseHead};

/// The most body bytes one [`IngressResponse`] queues before the gateway
/// waits. One frame larger than this is still taken when the queue is
/// empty.
pub const QUEUE_LIMIT_BYTES: usize = 1024 * 1024;

/// The gateway's HTTP server, as an `http`-wire transport receives it in
/// `start_http`. Cheap to copy; usable from any thread.
///
/// Every [`IngressResponse`] it returns MUST be dropped before the
/// plugin's `transport_handle_drop` returns: after that the gateway frees
/// the server.
#[derive(Clone, Copy, Debug)]
pub struct HttpIngressServer {
    cb: HttpServerRef,
}

impl HttpIngressServer {
    /// Wrap the FFI server the host passed to `start_http`. The SDK macro
    /// calls this; plugin code receives the wrapped value.
    #[doc(hidden)]
    #[must_use]
    pub fn from_ffi(cb: HttpServerRef) -> Self {
        Self { cb }
    }

    /// Hand one request to the gateway. Returns at once; read the answer
    /// from the [`IngressResponse`]. Dropping the response before it ends
    /// tells the gateway the client went away.
    #[must_use]
    pub fn serve(&self, head: &HttpIngressRequestHead, body: Vec<u8>) -> IngressResponse {
        let shared = Arc::new(Shared::default());
        let head_json = match serde_json::to_string(head) {
            Ok(json) => json,
            Err(e) => {
                shared
                    .lock()
                    .finish(Some(format!("request head encode failed: {e}")));
                return IngressResponse {
                    shared,
                    server: self.cb,
                    id: 0,
                };
            }
        };
        let responder = HttpResponderRef {
            ctx: Box::into_raw(Box::new(Arc::clone(&shared))) as usize,
            head: responder_head,
            chunk: responder_chunk,
            end: responder_end,
        };
        let id = (self.cb.serve)(
            self.cb.ctx,
            RString::from(head_json),
            RVec::from(body),
            responder,
        );
        IngressResponse {
            shared,
            server: self.cb,
            id,
        }
    }
}

/// The gateway's answer to one request: a head, then body frames.
pub struct IngressResponse {
    shared: Arc<Shared>,
    server: HttpServerRef,
    id: u64,
}

impl std::fmt::Debug for IngressResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngressResponse")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl IngressResponse {
    /// Wait for the response head. An `Err` means the gateway produced no
    /// response; answer the client with a gateway error.
    pub async fn head(&mut self) -> Result<HttpIngressResponseHead, String> {
        poll_fn(|cx| self.poll_head(cx)).await
    }

    /// Poll form of [`Self::head`].
    pub fn poll_head(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<HttpIngressResponseHead, String>> {
        let mut state = self.shared.lock();
        match state.queue.front() {
            Some(Event::Head(_)) => {
                let Some(Event::Head(head)) = state.queue.pop_front() else {
                    unreachable!("front checked above");
                };
                return Poll::Ready(Ok(head));
            }
            Some(Event::Data(_)) => {
                return Poll::Ready(Err("the gateway sent body data before a head".into()));
            }
            None => {}
        }
        match &state.ended {
            Some(Some(reason)) => Poll::Ready(Err(reason.clone())),
            Some(None) => Poll::Ready(Err("the gateway ended the response without a head".into())),
            None => {
                state.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// The next body frame. `None` when the body is complete; an `Err` when
    /// the gateway stopped it early (abort the client's response).
    pub async fn next_chunk(&mut self) -> Option<Result<Vec<u8>, String>> {
        poll_fn(|cx| self.poll_chunk(cx)).await
    }

    /// Poll form of [`Self::next_chunk`].
    pub fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Vec<u8>, String>>> {
        let mut state = self.shared.lock();
        if let Some(event) = state.queue.pop_front() {
            return Poll::Ready(match event {
                Event::Data(data) => {
                    state.queued_bytes -= data.len();
                    Some(Ok(data))
                }
                Event::Head(_) => Some(Err("the gateway sent a second head".into())),
            });
        }
        match &state.ended {
            Some(None) => Poll::Ready(None),
            Some(Some(_)) if state.error_taken => Poll::Ready(None),
            Some(Some(reason)) => {
                let reason = reason.clone();
                state.error_taken = true;
                Poll::Ready(Some(Err(reason)))
            }
            None => {
                state.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl Drop for IngressResponse {
    fn drop(&mut self) {
        let unfinished = {
            let mut state = self.shared.lock();
            state.closed = true;
            state.queue.clear();
            state.queued_bytes = 0;
            state.ended.is_none()
        };
        if unfinished && self.id != 0 {
            (self.server.cancel)(self.server.ctx, self.id);
        }
    }
}

enum Event {
    Head(HttpIngressResponseHead),
    Data(Vec<u8>),
}

#[derive(Default)]
struct State {
    queue: VecDeque<Event>,
    queued_bytes: usize,
    /// `Some(None)`: the body is complete. `Some(Some(reason))`: it stopped.
    ended: Option<Option<String>>,
    error_taken: bool,
    /// The plugin dropped its [`IngressResponse`].
    closed: bool,
    waker: Option<Waker>,
}

impl State {
    fn finish(&mut self, error: Option<String>) {
        if self.ended.is_none() {
            self.ended = Some(error);
        }
        self.wake();
    }

    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// # Safety
/// `ctx` is a live `Box<Arc<Shared>>` from [`HttpIngressServer::serve`]; the
/// host stops using it after `end`.
unsafe fn shared_of<'a>(ctx: usize) -> &'a Arc<Shared> {
    unsafe { &*(ctx as *const Arc<Shared>) }
}

extern "C" fn responder_head(ctx: usize, head_json: RString) -> u8 {
    std::panic::catch_unwind(|| {
        // SAFETY: see `shared_of`; the host calls `head` before `end`.
        let shared = unsafe { shared_of(ctx) };
        let mut state = shared.lock();
        if state.closed || state.ended.is_some() {
            return HTTP_SINK_CLOSED;
        }
        match serde_json::from_str::<HttpIngressResponseHead>(head_json.as_str()) {
            Ok(head) => {
                state.queue.push_back(Event::Head(head));
                state.wake();
                HTTP_SINK_ACCEPTED
            }
            Err(e) => {
                state.finish(Some(format!("the gateway sent an undecodable head: {e}")));
                HTTP_SINK_CLOSED
            }
        }
    })
    .unwrap_or(HTTP_SINK_CLOSED)
}

extern "C" fn responder_chunk(ctx: usize, data: RVec<u8>) -> u8 {
    std::panic::catch_unwind(move || {
        // SAFETY: see `shared_of`; the host calls `chunk` before `end`.
        let shared = unsafe { shared_of(ctx) };
        let mut state = shared.lock();
        if state.closed || state.ended.is_some() {
            return HTTP_SINK_CLOSED;
        }
        if data.is_empty() {
            return HTTP_SINK_ACCEPTED;
        }
        if state.queued_bytes >= QUEUE_LIMIT_BYTES && !state.queue.is_empty() {
            return HTTP_SINK_FULL;
        }
        state.queued_bytes += data.len();
        state.queue.push_back(Event::Data(data.into_vec()));
        state.wake();
        HTTP_SINK_ACCEPTED
    })
    .unwrap_or(HTTP_SINK_CLOSED)
}

extern "C" fn responder_end(ctx: usize, error: RString) {
    let _ = std::panic::catch_unwind(move || {
        // SAFETY: `ctx` is the `Box<Arc<Shared>>` leaked in `serve`; the host
        // calls `end` exactly once, so taking it back here is the only free.
        let shared = unsafe { Box::from_raw(ctx as *mut Arc<Shared>) };
        let error = (!error.is_empty()).then(|| error.into_string());
        shared.lock().finish(error);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A host stand-in: records requests and keeps their responders, so a
    /// test plays the gateway's side by hand.
    #[derive(Default)]
    struct FakeHost {
        next: AtomicU64,
        requests: Mutex<Vec<(String, Vec<u8>)>>,
        responders: Mutex<HashMap<u64, HttpResponderRef>>,
        cancelled: Mutex<Vec<u64>>,
    }

    extern "C" fn fake_serve(
        ctx: usize,
        head_json: RString,
        body: RVec<u8>,
        responder: HttpResponderRef,
    ) -> u64 {
        let host = unsafe { &*(ctx as *const FakeHost) };
        let id = host.next.fetch_add(1, Ordering::SeqCst) + 1;
        host.requests
            .lock()
            .unwrap()
            .push((head_json.into_string(), body.into_vec()));
        host.responders.lock().unwrap().insert(id, responder);
        id
    }

    extern "C" fn fake_cancel(ctx: usize, id: u64) {
        let host = unsafe { &*(ctx as *const FakeHost) };
        host.cancelled.lock().unwrap().push(id);
    }

    fn server(host: &FakeHost) -> HttpIngressServer {
        HttpIngressServer::from_ffi(HttpServerRef {
            ctx: host as *const FakeHost as usize,
            serve: fake_serve,
            cancel: fake_cancel,
        })
    }

    fn responder(host: &FakeHost, id: u64) -> HttpResponderRef {
        host.responders.lock().unwrap()[&id]
    }

    fn head_json(status: u16) -> RString {
        RString::from(
            serde_json::to_string(&HttpIngressResponseHead {
                status,
                headers: vec![("content-type".into(), "text/event-stream".into())],
            })
            .unwrap(),
        )
    }

    fn poll_chunk(resp: &mut IngressResponse) -> Poll<Option<Result<Vec<u8>, String>>> {
        resp.poll_chunk(&mut Context::from_waker(Waker::noop()))
    }

    fn poll_head(resp: &mut IngressResponse) -> Poll<Result<HttpIngressResponseHead, String>> {
        resp.poll_head(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn a_request_reaches_the_host_and_its_streamed_answer_comes_back_in_order() {
        let host = FakeHost::default();
        let head = HttpIngressRequestHead {
            method: "POST".into(),
            uri: "/mcp".into(),
            headers: vec![("host".into(), "x.ngrok.app".into())],
            remote_addr: Some("203.0.113.7:4242".into()),
            ..Default::default()
        };
        let mut resp = server(&host).serve(&head, b"{}".to_vec());
        let (sent_head, sent_body) = host.requests.lock().unwrap()[0].clone();
        let sent: HttpIngressRequestHead = serde_json::from_str(&sent_head).unwrap();
        assert_eq!(sent.uri, "/mcp");
        assert_eq!(sent.remote_addr.as_deref(), Some("203.0.113.7:4242"));
        assert_eq!(sent_body, b"{}");

        assert!(poll_head(&mut resp).is_pending());
        let r = responder(&host, 1);
        assert_eq!((r.head)(r.ctx, head_json(200)), HTTP_SINK_ACCEPTED);
        assert_eq!(
            (r.chunk)(r.ctx, RVec::from(b"event: a\n\n".to_vec())),
            HTTP_SINK_ACCEPTED
        );
        assert_eq!(
            (r.chunk)(r.ctx, RVec::from(b"event: b\n\n".to_vec())),
            HTTP_SINK_ACCEPTED
        );
        let Poll::Ready(Ok(got)) = poll_head(&mut resp) else {
            panic!("head not ready");
        };
        assert_eq!(got.status, 200);
        assert!(matches!(poll_chunk(&mut resp), Poll::Ready(Some(Ok(d))) if d == b"event: a\n\n"));
        assert!(matches!(poll_chunk(&mut resp), Poll::Ready(Some(Ok(d))) if d == b"event: b\n\n"));
        assert!(poll_chunk(&mut resp).is_pending());
        (r.end)(r.ctx, RString::new());
        assert!(matches!(poll_chunk(&mut resp), Poll::Ready(None)));
        drop(resp);
        assert!(
            host.cancelled.lock().unwrap().is_empty(),
            "a finished response is not cancelled"
        );
    }

    #[test]
    fn a_full_queue_asks_the_host_to_wait_and_takes_the_frame_after_a_read() {
        let host = FakeHost::default();
        let mut resp = server(&host).serve(&HttpIngressRequestHead::default(), Vec::new());
        let r = responder(&host, 1);
        assert_eq!((r.head)(r.ctx, head_json(200)), HTTP_SINK_ACCEPTED);
        let big = vec![b'x'; QUEUE_LIMIT_BYTES];
        assert_eq!((r.chunk)(r.ctx, RVec::from(big)), HTTP_SINK_ACCEPTED);
        assert_eq!(
            (r.chunk)(r.ctx, RVec::from(b"more".to_vec())),
            HTTP_SINK_FULL
        );
        assert!(poll_head(&mut resp).is_ready());
        assert!(
            matches!(poll_chunk(&mut resp), Poll::Ready(Some(Ok(d))) if d.len() == QUEUE_LIMIT_BYTES)
        );
        assert_eq!(
            (r.chunk)(r.ctx, RVec::from(b"more".to_vec())),
            HTTP_SINK_ACCEPTED
        );
        (r.end)(r.ctx, RString::new());
    }

    #[test]
    fn dropping_an_open_response_cancels_it_and_the_host_sees_closed() {
        let host = FakeHost::default();
        let resp = server(&host).serve(&HttpIngressRequestHead::default(), Vec::new());
        let r = responder(&host, 1);
        drop(resp);
        assert_eq!(*host.cancelled.lock().unwrap(), vec![1]);
        assert_eq!((r.head)(r.ctx, head_json(200)), HTTP_SINK_CLOSED);
        assert_eq!(
            (r.chunk)(r.ctx, RVec::from(b"x".to_vec())),
            HTTP_SINK_CLOSED
        );
        (r.end)(r.ctx, RString::from("cancelled"));
    }

    #[test]
    fn an_early_end_reaches_the_plugin_as_an_error_once() {
        let host = FakeHost::default();
        let mut resp = server(&host).serve(&HttpIngressRequestHead::default(), Vec::new());
        let r = responder(&host, 1);
        assert_eq!((r.head)(r.ctx, head_json(200)), HTTP_SINK_ACCEPTED);
        (r.end)(r.ctx, RString::from("router body failed"));
        assert!(poll_head(&mut resp).is_ready());
        assert!(
            matches!(poll_chunk(&mut resp), Poll::Ready(Some(Err(e))) if e == "router body failed")
        );
        assert!(matches!(poll_chunk(&mut resp), Poll::Ready(None)));
    }

    #[test]
    fn an_end_without_a_head_is_a_head_error() {
        let host = FakeHost::default();
        let mut resp = server(&host).serve(&HttpIngressRequestHead::default(), Vec::new());
        let r = responder(&host, 1);
        (r.end)(r.ctx, RString::from("gateway refused the request"));
        assert!(
            matches!(poll_head(&mut resp), Poll::Ready(Err(e)) if e == "gateway refused the request")
        );
    }
}
