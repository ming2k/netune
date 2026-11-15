use super::*;

fn head(status: StatusCode) -> ResponseHead {
    ResponseHead::new(status)
}

async fn collect<F, Fut>(method: Method, head: ResponseHead, build: F) -> Vec<u8>
where
    F: FnOnce(ResponseWriter<Vec<u8>>) -> Fut,
    Fut: std::future::Future<Output = ResponseWriter<Vec<u8>>>,
{
    let writer = ResponseWriter::start(Vec::new(), &method, &head)
        .await
        .expect("head");
    build(writer).await.finish().await.expect("body").to_vec()
}

#[tokio::test]
async fn a_length_delimited_body_is_written_verbatim() {
    let bytes = collect(
        Method::GET,
        head(StatusCode::OK).with_body(b"hello"),
        async |mut w: ResponseWriter<Vec<u8>>| {
            w.write(b"hello").await.expect("write");
            w
        },
    )
    .await;
    let text = String::from_utf8(bytes).expect("utf8");
    assert_eq!(text, "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello");
}

#[tokio::test]
async fn a_body_under_an_unframed_head_is_refused() {
    let head = head(StatusCode::OK);
    let mut writer = ResponseWriter::start(Vec::new(), &Method::GET, &head)
        .await
        .expect("head");
    let error = writer.write(b"hello").await.expect_err("must refuse");
    assert!(
        format!("{error}").contains("declares no framing"),
        "{error}"
    );
}

#[tokio::test]
async fn a_body_under_two_hundred_four_is_refused_before_it_reaches_the_wire() {
    let head = head(StatusCode::NO_CONTENT).with_body(b"oops");
    let error = ResponseWriter::start(Vec::new(), &Method::GET, &head)
        .await
        .expect_err("must refuse");
    assert!(format!("{error}").contains("1xx/204"), "{error}");
}

#[tokio::test]
async fn a_head_response_declares_a_length_and_writes_no_body() {
    let head = head(StatusCode::OK).with_body(b"hello");
    let mut writer = ResponseWriter::start(Vec::new(), &Method::HEAD, &head)
        .await
        .expect("head");
    assert!(!writer.writes_body());
    let error = writer.write(b"hello").await.expect_err("must refuse");
    assert!(format!("{error}").contains("carries none"), "{error}");
    let bytes = writer.finish().await.expect("finish");
    let text = String::from_utf8(bytes).expect("utf8");
    assert!(text.contains("content-length: 5"), "{text}");
    assert!(
        text.ends_with("\r\n\r\n"),
        "no body after the head: {text:?}"
    );
}

#[tokio::test]
async fn a_truncated_length_is_refused_at_finish() {
    let head = head(StatusCode::OK).with_body(&b"hello"[..]);
    let mut writer = ResponseWriter::start(Vec::new(), &Method::GET, &head)
        .await
        .expect("head");
    writer.write(b"hel").await.expect("write");
    let error = writer.finish().await.expect_err("must refuse");
    assert!(format!("{error}").contains("content-length"), "{error}");
}

#[tokio::test]
async fn exceeding_the_declared_length_is_refused_mid_write() {
    let head = head(StatusCode::OK).with_body(&b"hello"[..]);
    let mut writer = ResponseWriter::start(Vec::new(), &Method::GET, &head)
        .await
        .expect("head");
    let error = writer.write(b"hello!").await.expect_err("must refuse");
    assert!(format!("{error}").contains("exceeds"), "{error}");
}

#[tokio::test]
async fn a_chunked_body_is_framed_and_terminated() {
    let head = head(StatusCode::OK).with_chunked_body();
    let mut writer = ResponseWriter::start(Vec::new(), &Method::GET, &head)
        .await
        .expect("head");
    assert!(writer.is_chunked());
    writer.write(b"hello").await.expect("chunk");
    writer.write(b"").await.expect("an empty write is a no-op");
    writer.write(b" world").await.expect("chunk");
    let bytes = writer.finish().await.expect("finish");
    let text = String::from_utf8(bytes).expect("utf8");
    assert!(
        text.ends_with("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"),
        "{text:?}"
    );
}

#[tokio::test]
async fn a_head_of_a_chunked_response_is_never_terminated() {
    let head = head(StatusCode::OK).with_chunked_body();
    let writer = ResponseWriter::start(Vec::new(), &Method::HEAD, &head)
        .await
        .expect("head");
    let text = String::from_utf8(writer.finish().await.expect("finish")).expect("utf8");
    assert!(
        !text.ends_with("0\r\n\r\n"),
        "a HEAD response has no body to terminate: {text:?}"
    );
}

#[tokio::test]
async fn a_connect_tunnel_response_carries_no_body() {
    let head = head(StatusCode::OK);
    let mut writer = ResponseWriter::start(Vec::new(), &Method::CONNECT, &head)
        .await
        .expect("head");
    assert!(!writer.writes_body());
    assert!(writer.write(b"x").await.is_err());
}

#[tokio::test]
async fn a_not_modified_response_may_repeat_the_length_without_a_body() {
    let head = head(StatusCode::NOT_MODIFIED).with_body(&b"hello"[..]);
    let writer = ResponseWriter::start(Vec::new(), &Method::GET, &head)
        .await
        .expect("head");
    assert!(!writer.writes_body());
    writer.finish().await.expect("no bytes were promised");
}

#[tokio::test]
async fn an_interim_response_must_be_informational() {
    let mut out = Vec::new();
    let error = write_interim(&mut out, StatusCode::OK, &http::HeaderMap::new())
        .await
        .expect_err("must refuse");
    assert!(format!("{error}").contains("1xx"), "{error}");
    write_interim(&mut out, StatusCode::CONTINUE, &http::HeaderMap::new())
        .await
        .expect("continue");
    let text = String::from_utf8(out).expect("utf8");
    assert_eq!(text, "HTTP/1.1 100 Continue\r\n\r\n");
}
