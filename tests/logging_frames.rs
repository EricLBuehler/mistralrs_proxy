use std::{
    collections::VecDeque,
    convert::Infallible,
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header::HOST},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use mistralrs_proxy::logging::{self, LogSender, LogWorker};
use serde_json::Value;
use uuid::Uuid;

struct FramesBody {
    frames: VecDeque<Result<Frame<Bytes>, Infallible>>,
}

impl FramesBody {
    fn new(frames: impl IntoIterator<Item = Frame<Bytes>>) -> Self {
        Self {
            frames: frames.into_iter().map(Ok).collect(),
        }
    }
}

impl HttpBody for FramesBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.get_mut().frames.pop_front())
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

struct TestLog {
    path: PathBuf,
    sender: Option<LogSender>,
    worker: Option<LogWorker>,
}

impl TestLog {
    fn start() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mistralrs-proxy-logging-frames-{}.jsonl",
            Uuid::new_v4()
        ));
        let (sender, worker) = logging::start(&path).expect("start test log worker");
        Self {
            path,
            sender: Some(sender),
            worker: Some(worker),
        }
    }

    fn sender(&self) -> &LogSender {
        self.sender.as_ref().expect("test logger is still running")
    }

    fn finish(mut self) -> Vec<Value> {
        drop(self.sender.take());
        self.worker
            .take()
            .expect("test log worker exists")
            .join()
            .expect("join test log worker");

        fs::read_to_string(&self.path)
            .expect("read test log")
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse JSON log record"))
            .collect()
    }
}

impl Drop for TestLog {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove test log {}: {error}", self.path.display()),
        }
    }
}

#[tokio::test]
async fn request_data_and_trailers_log_as_one_complete_request() {
    let log = TestLog::start();
    let request_id = Uuid::new_v4();
    let request = Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header(HOST, "api.client.example")
        .body(())
        .unwrap();
    let (parts, ()) = request.into_parts();
    log.sender().request_started(
        request_id,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 4242)),
        Some("foobar".to_owned()),
        true,
        &parts,
    );

    let mut trailers = HeaderMap::new();
    trailers.insert("x-request-checksum", HeaderValue::from_static("abc123"));
    let body = Body::new(FramesBody::new([
        Frame::data(Bytes::from_static(b"hello from frames")),
        Frame::trailers(trailers),
    ]));
    let collected = log
        .sender()
        .request_body(request_id, body)
        .collect()
        .await
        .unwrap();
    assert_eq!(collected.to_bytes(), "hello from frames");

    let records = log.finish();
    assert_eq!(records.len(), 1, "request must be logged exactly once");
    let request = &records[0];
    assert_eq!(request["event"], "request");
    assert_eq!(request["request_id"], request_id.to_string());
    assert_eq!(request["body"], "hello from frames");
    assert_eq!(request["complete"], true);
    assert_eq!(request["termination"], "complete");
    assert_eq!(
        request["trailers"],
        serde_json::json!([[{
            "name": "x-request-checksum",
            "value": "abc123"
        }]])
    );
}

#[tokio::test]
async fn response_trailers_are_followed_by_one_complete_response_end() {
    let log = TestLog::start();
    let request_id = Uuid::new_v4();
    let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
    let (parts, ()) = response.into_parts();
    log.sender().response_started(request_id, &parts);

    let mut trailers = HeaderMap::new();
    trailers.insert("x-response-checksum", HeaderValue::from_static("def456"));
    let body = Body::new(FramesBody::new([
        Frame::data(Bytes::from_static(b"streamed response")),
        Frame::trailers(trailers),
    ]));
    let collected = log
        .sender()
        .response_body(request_id, body)
        .collect()
        .await
        .unwrap();
    assert_eq!(collected.to_bytes(), "streamed response");

    let records = log.finish();
    let events: Vec<_> = records
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        events,
        [
            "response_start",
            "response_body",
            "response_trailers",
            "response_end"
        ]
    );

    let ends: Vec<_> = records
        .iter()
        .filter(|record| record["event"] == "response_end")
        .collect();
    assert_eq!(ends.len(), 1, "response must have exactly one end record");
    assert_eq!(ends[0]["request_id"], request_id.to_string());
    assert_eq!(ends[0]["complete"], true);
    assert_eq!(ends[0]["termination"], "complete");
    assert!(
        records
            .iter()
            .all(|record| record["termination"] != "body_dropped")
    );
}

#[tokio::test]
async fn split_utf8_response_frames_reconstruct_the_original_text() {
    let log = TestLog::start();
    let request_id = Uuid::new_v4();
    let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
    let (parts, ()) = response.into_parts();
    log.sender().response_started(request_id, &parts);

    // U+1F525 (fire) is F0 9F 94 A5 in UTF-8. Neither individual frame is a
    // complete UTF-8 string, but the byte stream is valid when reassembled.
    let body = Body::new(FramesBody::new([
        Frame::data(Bytes::from_static(&[0xf0, 0x9f])),
        Frame::data(Bytes::from_static(&[0x94, 0xa5])),
    ]));
    let collected = log
        .sender()
        .response_body(request_id, body)
        .collect()
        .await
        .unwrap();
    assert_eq!(collected.to_bytes().as_ref(), "🔥".as_bytes());

    let records = log.finish();
    let reconstructed: String = records
        .iter()
        .filter(|record| record["event"] == "response_body")
        .map(|record| record["body"].as_str().unwrap())
        .collect();
    assert_eq!(reconstructed, "🔥");
}

#[tokio::test]
async fn incomplete_utf8_tail_is_logged_before_response_trailers() {
    let log = TestLog::start();
    let request_id = Uuid::new_v4();
    let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
    let (parts, ()) = response.into_parts();
    log.sender().response_started(request_id, &parts);

    let mut trailers = HeaderMap::new();
    trailers.insert("x-response-checksum", HeaderValue::from_static("tail"));
    let body = Body::new(FramesBody::new([
        Frame::data(Bytes::from_static(b"text \xf0")),
        Frame::trailers(trailers),
    ]));
    let collected = log
        .sender()
        .response_body(request_id, body)
        .collect()
        .await
        .unwrap();
    assert_eq!(collected.to_bytes(), Bytes::from_static(b"text \xf0"));

    let records = log.finish();
    let events: Vec<_> = records
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        events,
        [
            "response_start",
            "response_body",
            "response_body",
            "response_trailers",
            "response_end"
        ]
    );
    let tail = &records[2];
    assert_eq!(tail["utf8_tail"], true);
    assert_eq!(tail["body_utf8_valid"], false);
    assert_eq!(tail["body_bytes_hex"], "f0");
    assert_eq!(tail["sequence"], 0);
    assert_eq!(records[3]["sequence"], 1);
}
