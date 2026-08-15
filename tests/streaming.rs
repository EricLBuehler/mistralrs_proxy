use std::{
    convert::Infallible,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
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
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use mistralrs_proxy::{logging, proxy};
use serde_json::Value;
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
};
use uuid::Uuid;

const FIRST_CHUNK: &[u8] = b"data: first\n\n";
const SECOND_CHUNK: &[u8] = b"data: second\n\n";

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

fn http_client() -> Client<HttpConnector, Body> {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    Client::builder(TokioExecutor::new()).build(connector)
}

async fn stop_server(shutdown: oneshot::Sender<()>, task: JoinHandle<()>) {
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("server did not shut down")
        .expect("server task panicked");
}

struct TempLogPath(PathBuf);

impl TempLogPath {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "mistralrs-proxy-streaming-{}.jsonl",
            Uuid::new_v4()
        )))
    }

    fn as_path(&self) -> &Path {
        &self.0
    }

    fn records(&self) -> Vec<Value> {
        fs::read_to_string(&self.0)
            .expect("read streaming test log")
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse streaming JSON log record"))
            .collect()
    }
}

impl Drop for TempLogPath {
    fn drop(&mut self) {
        match fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove test log {}: {error}", self.0.display()),
        }
    }
}

#[tokio::test]
async fn proxy_forwards_response_headers_and_frames_without_buffering() {
    let (upstream_body_tx, upstream_body_rx) = mpsc::channel(2);
    let upstream_state = UpstreamState {
        body_rx: Arc::new(Mutex::new(Some(upstream_body_rx))),
    };
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_app = Router::new()
        .fallback(streaming_upstream)
        .with_state(upstream_state);
    let (upstream_shutdown_tx, upstream_shutdown_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_app)
            .with_graceful_shutdown(async move {
                let _ = upstream_shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let log_path = TempLogPath::new();
    let (logger, log_worker) = logging::start(log_path.as_path()).unwrap();
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let state = Arc::new(proxy::AppState::new(
        http_client(),
        format!("http://{upstream_addr}").parse().unwrap(),
        logger,
    ));
    let proxy_app = proxy::router(state);
    let (proxy_shutdown_tx, proxy_shutdown_rx) = oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        axum::serve(
            proxy_listener,
            proxy_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = proxy_shutdown_rx.await;
        })
        .await
        .unwrap();
    });

    let client = http_client();
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{proxy_addr}/v1/responses"))
        .header(header::HOST, "api.client.example")
        .header(header::AUTHORIZATION, "Bearer foobar")
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
    stop_server(proxy_shutdown_tx, proxy_task).await;
    log_worker.join().unwrap();
    stop_server(upstream_shutdown_tx, upstream_task).await;

    let records = log_path.records();
    let response_records: Vec<_> = records
        .iter()
        .filter(|record| record["request_id"] == request_id && record["event"] != "request")
        .collect();
    let response_events: Vec<_> = response_records
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        response_events,
        [
            "response_start",
            "response_body",
            "response_body",
            "response_end"
        ]
    );

    let body_records: Vec<_> = response_records
        .iter()
        .filter(|record| record["event"] == "response_body")
        .collect();
    assert_eq!(body_records[0]["sequence"], 0);
    assert_eq!(body_records[0]["offset"], 0);
    assert_eq!(
        body_records[0]["body"].as_str().unwrap(),
        std::str::from_utf8(FIRST_CHUNK).unwrap()
    );
    assert_eq!(body_records[1]["sequence"], 1);
    assert_eq!(body_records[1]["offset"], FIRST_CHUNK.len() as u64);
    assert_eq!(
        body_records[1]["body"].as_str().unwrap(),
        std::str::from_utf8(SECOND_CHUNK).unwrap()
    );

    let response_end = response_records.last().unwrap();
    assert_eq!(response_end["event"], "response_end");
    assert_eq!(
        response_end["total_body_bytes"],
        (FIRST_CHUNK.len() + SECOND_CHUNK.len()) as u64
    );
    assert_eq!(response_end["complete"], true);
    assert_eq!(response_end["termination"], "complete");
}
