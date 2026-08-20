//! Logger-level behaviour: one record per request regardless of how the
//! response body is framed.

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
    http::{HeaderMap, Request, Response, StatusCode, header::HOST},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use mistralrs_proxy::{
    auth::{KeyStore, authenticate},
    keys::KeyRecord,
    logging::{self, LogSender, LogWorker, RequestInfo},
};
use serde_json::Value;
use uuid::Uuid;

struct FramesBody {
    frames: VecDeque<Result<hyper::body::Frame<Bytes>, Infallible>>,
}

impl FramesBody {
    fn new(frames: impl IntoIterator<Item = hyper::body::Frame<Bytes>>) -> Self {
        Self {
            frames: frames.into_iter().map(Ok).collect(),
        }
    }
}

impl hyper::body::Body for FramesBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.get_mut().frames.pop_front())
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::default()
    }
}

struct Harness {
    path: PathBuf,
    logger: LogSender,
    worker: LogWorker,
    store: KeyStore,
    key: String,
}

impl Harness {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("proxy-records-{}.jsonl", Uuid::new_v4()));
        let (logger, worker) = logging::start(&path, false).unwrap();
        let (record, key) = KeyRecord::generate("alice", true).unwrap();

        Self {
            path,
            logger,
            worker,
            store: KeyStore::from_records(vec![record]).unwrap(),
            key,
        }
    }

    fn begin(&self, id: Uuid, uri: &str) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header(HOST, "localhost:3000")
            .header("authorization", format!("Bearer {}", self.key))
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        let auth = authenticate(&parts.headers, &self.store);
        self.logger
            .request_started(
                id,
                RequestInfo::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 4242)), &parts, &auth),
            )
            .disarm();
    }

    fn respond(&self, id: Uuid, status: StatusCode) {
        let response = Response::builder().status(status).body(()).unwrap();
        let (parts, ()) = response.into_parts();
        self.logger.response_started(id, &parts);
    }

    fn finish(self) -> Vec<Value> {
        drop(self.logger);
        self.worker.join().unwrap();
        let lines = fs::read_to_string(&self.path).unwrap();
        fs::remove_file(&self.path).unwrap();

        lines
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

#[tokio::test]
async fn usage_split_across_many_small_frames_is_still_recovered() {
    let harness = Harness::new();
    let id = Uuid::new_v4();
    harness.begin(id, "/v1/chat/completions");
    harness.respond(id, StatusCode::OK);

    // Split the usage object at awkward points, including inside the field name.
    let pieces: Vec<&str> = vec![
        "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}],\"us",
        "age\":null}\n\ndata: {\"choices\":[],\"usa",
        "ge\"",
        ":{\"prompt_tokens\"",
        ":41,\"completion",
        "_tokens\":9,\"total_tokens\":50}}\n\ndata: [DONE]\n\n",
    ];
    let total: usize = pieces.iter().map(|piece| piece.len()).sum();
    let body = harness.logger.response_body(
        id,
        Body::new(FramesBody::new(pieces.iter().map(|piece| {
            hyper::body::Frame::data(Bytes::copy_from_slice(piece.as_bytes()))
        }))),
    );
    body.collect().await.unwrap();

    let records = harness.finish();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["input_tokens"], 41);
    assert_eq!(records[0]["output_tokens"], 9);
    assert_eq!(records[0]["total_tokens"], 50);
    assert_eq!(records[0]["response_bytes"], total);
    assert_eq!(records[0]["complete"], true);
}

#[tokio::test]
async fn a_non_streaming_json_response_yields_the_same_record_shape() {
    let harness = Harness::new();
    let id = Uuid::new_v4();
    harness.begin(id, "/v1/responses");
    harness.respond(id, StatusCode::OK);

    let body = harness.logger.response_body(
        id,
        Body::from(
            r#"{"id":"resp_1","output":[{"content":[{"text":"answer"}]}],"usage":{"input_tokens":6,"output_tokens":14,"total_tokens":20}}"#,
        ),
    );
    body.collect().await.unwrap();

    let records = harness.finish();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "request");
    assert_eq!(records[0]["uri"], "/v1/responses");
    assert_eq!(records[0]["input_tokens"], 6);
    assert_eq!(records[0]["output_tokens"], 14);
    assert!(
        !serde_json::to_string(&records[0])
            .unwrap()
            .contains("answer")
    );
}

#[tokio::test]
async fn trailers_do_not_add_records_and_do_not_break_completion() {
    let harness = Harness::new();
    let id = Uuid::new_v4();
    harness.begin(id, "/v1/chat/completions");
    harness.respond(id, StatusCode::OK);

    let mut trailers = HeaderMap::new();
    trailers.insert("x-upstream", "done".parse().unwrap());
    let body = harness.logger.response_body(
        id,
        Body::new(FramesBody::new([
            hyper::body::Frame::data(Bytes::from_static(
                br#"{"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}"#,
            )),
            hyper::body::Frame::trailers(trailers),
        ])),
    );
    body.collect().await.unwrap();

    let records = harness.finish();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["complete"], true);
    assert_eq!(records[0]["termination"], "complete");
    assert_eq!(records[0]["input_tokens"], 1);
}

#[tokio::test]
async fn an_unpolled_empty_body_still_produces_a_record() {
    let harness = Harness::new();
    let id = Uuid::new_v4();
    harness.begin(id, "/v1/models");
    harness.respond(id, StatusCode::NO_CONTENT);

    // Never polled, as Hyper does for some zero-length bodies.
    drop(harness.logger.response_body(id, Body::empty()));

    let records = harness.finish();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["status"], 204);
    assert_eq!(records[0]["response_bytes"], 0);
    assert_eq!(records[0]["complete"], true);
}

#[tokio::test]
async fn concurrent_requests_get_independent_records() {
    let harness = Harness::new();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();

    harness.begin(first, "/v1/chat/completions");
    harness.begin(second, "/v1/responses");
    harness.respond(first, StatusCode::OK);
    harness.respond(second, StatusCode::OK);

    let first_body = harness.logger.response_body(
        first,
        Body::from(r#"{"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}"#),
    );
    let second_body = harness.logger.response_body(
        second,
        Body::from(r#"{"usage":{"input_tokens":20,"output_tokens":2,"total_tokens":22}}"#),
    );
    first_body.collect().await.unwrap();
    second_body.collect().await.unwrap();

    let records = harness.finish();

    assert_eq!(records.len(), 2);
    let find = |id: Uuid| {
        records
            .iter()
            .find(|record| record["request_id"] == id.to_string())
            .unwrap()
    };
    assert_eq!(find(first)["input_tokens"], 10);
    assert_eq!(find(first)["uri"], "/v1/chat/completions");
    assert_eq!(find(second)["input_tokens"], 20);
    assert_eq!(find(second)["uri"], "/v1/responses");
}
