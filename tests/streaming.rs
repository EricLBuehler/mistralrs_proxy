mod support;

use std::{
    convert::Infallible,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    response::Response,
};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use tokio::sync::{Mutex, mpsc};

use support::{Proxy, Upstream, http_client, one_key, record_for};

const FIRST_CHUNK: &[u8] =
    b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n";
const SECOND_CHUNK: &[u8] =
    b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":19,\"completion_tokens\":3,\"total_tokens\":22}}\n\n";

struct ChannelBody {
    rx: mpsc::Receiver<Bytes>,
}

impl HttpBody for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.rx.is_closed() && self.rx.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[derive(Clone)]
struct UpstreamState {
    body_rx: Arc<Mutex<Option<mpsc::Receiver<Bytes>>>>,
}

async fn streaming_upstream(State(state): State<UpstreamState>) -> Response {
    let rx = state
        .body_rx
        .lock()
        .await
        .take()
        .expect("the streaming upstream should receive exactly one request");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::new(ChannelBody { rx }))
        .unwrap()
}

#[tokio::test]
async fn frames_are_forwarded_without_buffering_and_usage_lands_in_one_record() {
    let (upstream_body_tx, upstream_body_rx) = mpsc::channel(2);
    let upstream = Upstream::start(Router::new().fallback(streaming_upstream).with_state(
        UpstreamState {
            body_rx: Arc::new(Mutex::new(Some(upstream_body_rx))),
        },
    ))
    .await;
    let (keys, key) = one_key();
    let proxy = Proxy::start(upstream.uri(""), keys).await;

    let client = http_client();
    let request = Request::builder()
        .method("POST")
        .uri(proxy.url("/v1/responses"))
        .header(header::HOST, "api.client.example")
        .header(header::AUTHORIZATION, format!("Bearer {}", key.secret))
        .body(Body::empty())
        .unwrap();

    // No upstream DATA frame has been released yet. Receiving this response
    // therefore proves that neither socket hop buffers the body before headers.
    let mut response = tokio::time::timeout(Duration::from_secs(2), client.request(request))
        .await
        .expect("proxy buffered response headers while waiting for body data")
        .expect("streaming proxy request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response.headers()["x-proxy-request-id"]
        .to_str()
        .unwrap()
        .to_owned();

    upstream_body_tx
        .send(Bytes::from_static(FIRST_CHUNK))
        .await
        .unwrap();
    let first_frame = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
        .await
        .expect("first response frame was buffered")
        .expect("response ended before its first frame")
        .expect("first response frame failed");
    assert_eq!(
        first_frame.into_data().expect("first frame was not DATA"),
        FIRST_CHUNK
    );

    // The second item is still gated at the mpsc sender, so another network
    // frame must not be observable until the test explicitly releases it.
    assert!(
        tokio::time::timeout(Duration::from_millis(150), response.body_mut().frame())
            .await
            .is_err(),
        "a response frame arrived before the second upstream frame was released"
    );

    upstream_body_tx
        .send(Bytes::from_static(SECOND_CHUNK))
        .await
        .unwrap();
    let second_frame = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
        .await
        .expect("second response frame was buffered")
        .expect("response ended before its second frame")
        .expect("second response frame failed");
    assert_eq!(
        second_frame.into_data().expect("second frame was not DATA"),
        SECOND_CHUNK
    );

    drop(upstream_body_tx);
    let end = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
        .await
        .expect("stream did not finish after the upstream body channel closed");
    assert!(end.is_none(), "expected end of response body, got {end:?}");

    drop(response);
    drop(client);
    let records = proxy.stop().await;
    upstream.stop().await;

    // A stream that produced two frames still yields exactly one record.
    let record = record_for(&records, &request_id);
    assert_eq!(record["event"], "request");
    assert_eq!(record["status"], 200);
    assert_eq!(
        record["response_bytes"],
        (FIRST_CHUNK.len() + SECOND_CHUNK.len()) as u64
    );
    assert_eq!(record["input_tokens"], 19);
    assert_eq!(record["output_tokens"], 3);
    assert_eq!(record["total_tokens"], 22);
    assert_eq!(record["complete"], true);
    assert_eq!(record["termination"], "complete");
    assert!(record["time_to_first_byte_ms"].is_u64());
}

#[tokio::test]
async fn a_client_that_abandons_a_stream_is_recorded_as_incomplete() {
    let (upstream_body_tx, upstream_body_rx) = mpsc::channel(2);
    let upstream = Upstream::start(Router::new().fallback(streaming_upstream).with_state(
        UpstreamState {
            body_rx: Arc::new(Mutex::new(Some(upstream_body_rx))),
        },
    ))
    .await;
    let (keys, key) = one_key();
    let proxy = Proxy::start(upstream.uri(""), keys).await;

    let client = http_client();
    let request = Request::builder()
        .method("POST")
        .uri(proxy.url("/v1/responses"))
        .header(header::AUTHORIZATION, format!("Bearer {}", key.secret))
        .body(Body::empty())
        .unwrap();
    let mut response = client.request(request).await.unwrap();
    let request_id = response.headers()["x-proxy-request-id"]
        .to_str()
        .unwrap()
        .to_owned();

    upstream_body_tx
        .send(Bytes::from_static(FIRST_CHUNK))
        .await
        .unwrap();
    response.body_mut().frame().await.unwrap().unwrap();

    // Hang up mid-stream, before the chunk that would have carried usage.
    drop(response);
    drop(client);
    drop(upstream_body_tx);

    let records = proxy.stop().await;
    upstream.stop().await;

    let record = record_for(&records, &request_id);
    assert_eq!(record["complete"], false);
    assert_eq!(record["termination"], "body_dropped");
    assert_eq!(record["input_tokens"], serde_json::Value::Null);
    assert_eq!(record["response_bytes"], FIRST_CHUNK.len());
}
