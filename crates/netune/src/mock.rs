//! Request-level mocking: a transport that answers from a script.
//!
//! [`Mock`] is a [`RoundTrip`], so it plugs into [`crate::Client`] exactly
//! where real connections do. Code under test keeps using the same `Client`
//! type and the same calls; only what is behind the seam changes. Because the
//! client's own machinery (planning, redirects, decoding, bounds, the trace)
//! sits above the seam, a mocked attempt exercises all of it: a mocked `302`
//! is followed, a mocked gzip body is decoded, a mocked stall trips the same
//! timeout a real one would, and every attempt leaves a trace.
//!
//! ```
//! use http::{Method, StatusCode};
//! use netune::mock::{Matcher, Mock, MockResponse};
//! use netune::{Client, ClientConfig, RequestHead, Target};
//!
//! # async fn demo() -> Result<(), netune::AttemptError> {
//! let mock = Mock::new();
//! mock.on(Matcher::get("/health")).reply(MockResponse::ok("up"));
//! mock.on(Matcher::post("/jobs"))
//!     .reply_once(MockResponse::new(StatusCode::SERVICE_UNAVAILABLE))
//!     .reply(MockResponse::new(StatusCode::CREATED));
//!
//! let client = Client::with_transport(mock.clone(), ClientConfig::default());
//! let target = Target::plain("api.example:80");
//! let mut response = client
//!     .request(&target, RequestHead::new(Method::GET, "/health"), None)
//!     .await?;
//! assert_eq!(response.body.read_to_end().await?.as_ref(), b"up");
//! assert_eq!(mock.calls().len(), 1);
//! # Ok(())
//! # }
//! ```
//!
//! A mock answers at the request level, so it cannot express byte-level
//! misbehaviour (a split read, a reset at byte 37 of a chunk header). That is
//! [`crate::FaultConnector`]'s job, on a real connection.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use netune_http1::{BodyKind, IncomingResponse};
use netune_trace::{ConnectionInfo, EventKind};

use crate::connect::{Established, Transport};
use crate::error::NetError;
use crate::exchange::{Attempt, BodySource, BoxFuture, Exchange, Released, Request, RoundTrip};

/// One request a [`Mock`] received, as the transport saw it: after the client
/// added its own headers, and once per redirect hop.
#[derive(Debug, Clone)]
pub struct Recorded {
    /// `host:port` the request was addressed to.
    pub authority: String,
    /// HTTP request method.
    pub method: Method,
    /// The request target (origin-form path and query).
    pub target: String,
    /// Final request headers sent by the client.
    pub headers: HeaderMap,
    /// Buffered request body bytes.
    pub body: Bytes,
}

type Predicate = Arc<dyn Fn(&Recorded) -> bool + Send + Sync>;

#[derive(Clone)]
enum PathMatch {
    Any,
    Exact(String),
    Prefix(String),
}

/// Which requests a route answers. Every condition set must hold.
#[derive(Clone)]
pub struct Matcher {
    method: Option<Method>,
    authority: Option<String>,
    path: PathMatch,
    headers: Vec<(String, String)>,
    predicate: Option<Predicate>,
}

impl Matcher {
    /// Matches every request.
    pub fn any() -> Self {
        Self {
            method: None,
            authority: None,
            path: PathMatch::Any,
            headers: Vec::new(),
            predicate: None,
        }
    }

    /// Matches `method` on exactly `path`.
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self::any().method(method).path(path)
    }

    /// Matches `GET` on exactly `path`.
    pub fn get(path: impl Into<String>) -> Self {
        Self::new(Method::GET, path)
    }

    /// Matches `POST` on exactly `path`.
    pub fn post(path: impl Into<String>) -> Self {
        Self::new(Method::POST, path)
    }

    /// Require the request method to equal `method`.
    #[must_use]
    pub fn method(mut self, method: Method) -> Self {
        self.method = Some(method);
        self
    }

    /// Require the request target to equal `path` exactly (query included).
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = PathMatch::Exact(path.into());
        self
    }

    /// Require the request target to start with `prefix`.
    #[must_use]
    pub fn path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path = PathMatch::Prefix(prefix.into());
        self
    }

    /// Require the request to be addressed to `authority` (`host:port`).
    #[must_use]
    pub fn authority(mut self, authority: impl Into<String>) -> Self {
        self.authority = Some(authority.into());
        self
    }

    /// Require a header with exactly this value. Names compare
    /// case-insensitively.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .push((name.into().to_ascii_lowercase(), value.into()));
        self
    }

    /// Require an arbitrary predicate over the recorded request.
    #[must_use]
    pub fn when(mut self, predicate: impl Fn(&Recorded) -> bool + Send + Sync + 'static) -> Self {
        self.predicate = Some(Arc::new(predicate));
        self
    }

    /// Whether this matcher inspects the request body.
    fn needs_body(&self) -> bool {
        self.predicate.is_some()
    }

    /// Whether `request` satisfies every condition.
    pub fn matches(&self, request: &Recorded) -> bool {
        if self.method.as_ref().is_some_and(|m| *m != request.method) {
            return false;
        }
        if self
            .authority
            .as_ref()
            .is_some_and(|a| *a != request.authority)
        {
            return false;
        }
        let path_ok = match &self.path {
            PathMatch::Any => true,
            PathMatch::Exact(path) => *path == request.target,
            PathMatch::Prefix(prefix) => request.target.starts_with(prefix.as_str()),
        };
        if !path_ok {
            return false;
        }
        for (name, value) in &self.headers {
            let found = request
                .headers
                .get_all(name.as_str())
                .iter()
                .any(|candidate| candidate.as_bytes() == value.as_bytes());
            if !found {
                return false;
            }
        }
        self.predicate
            .as_ref()
            .is_none_or(|predicate| predicate(request))
    }
}

impl std::fmt::Debug for Matcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = match &self.path {
            PathMatch::Any => "*".to_string(),
            PathMatch::Exact(path) => path.clone(),
            PathMatch::Prefix(prefix) => format!("{prefix}*"),
        };
        f.debug_struct("Matcher")
            .field("method", &self.method)
            .field("authority", &self.authority)
            .field("path", &path)
            .field("headers", &self.headers)
            .field("predicate", &self.predicate.is_some())
            .finish()
    }
}

/// A scripted response: head, body chunks, pacing and an optional failure.
#[derive(Debug, Clone)]
pub struct MockResponse {
    status: StatusCode,
    headers: Vec<(String, String)>,
    chunks: Vec<Bytes>,
    head_delay: Option<Duration>,
    chunk_delay: Option<Duration>,
    failure: Option<(FailAt, std::io::ErrorKind)>,
}

#[derive(Debug, Clone, Copy)]
enum FailAt {
    /// No response head is ever produced.
    BeforeHead,
    /// The body fails after this many chunks were delivered.
    AfterChunks(usize),
}

impl MockResponse {
    /// An empty response with `status`.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            chunks: Vec::new(),
            head_delay: None,
            chunk_delay: None,
            failure: None,
        }
    }

    /// `200 OK` with `body`.
    pub fn ok(body: impl Into<Bytes>) -> Self {
        Self::new(StatusCode::OK).body(body)
    }

    /// A redirect to `location`.
    pub fn redirect(status: StatusCode, location: impl Into<String>) -> Self {
        Self::new(status).header("location", location)
    }

    /// Add a response header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the body as one chunk, replacing any chunks set before.
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.chunks = vec![body.into()];
        self
    }

    /// Set the body as a sequence of chunks, each delivered by its own read:
    /// the shape of a streaming response.
    #[must_use]
    pub fn chunks<B: Into<Bytes>>(mut self, chunks: impl IntoIterator<Item = B>) -> Self {
        self.chunks = chunks.into_iter().map(Into::into).collect();
        self
    }

    /// Wait this long before producing the response head.
    #[must_use]
    pub fn delay_head(mut self, delay: Duration) -> Self {
        self.head_delay = Some(delay);
        self
    }

    /// Wait this long before each body chunk.
    #[must_use]
    pub fn delay_chunks(mut self, delay: Duration) -> Self {
        self.chunk_delay = Some(delay);
        self
    }

    /// Fail with a transport error instead of producing a response head, as a
    /// peer that accepts the request and then drops the connection does.
    #[must_use]
    pub fn fail_before_head(mut self, kind: std::io::ErrorKind) -> Self {
        self.failure = Some((FailAt::BeforeHead, kind));
        self
    }

    /// Deliver the head and the first `chunks` body chunks, then fail with a
    /// transport error: a stream cut off part way.
    #[must_use]
    pub fn fail_after_chunks(mut self, chunks: usize, kind: std::io::ErrorKind) -> Self {
        self.failure = Some((FailAt::AfterChunks(chunks), kind));
        self
    }
}

type Responder = Arc<dyn Fn(&Recorded) -> MockResponse + Send + Sync>;

struct Route {
    matcher: Matcher,
    /// Responses used once each, in order, before `standing` takes over.
    queued: VecDeque<MockResponse>,
    /// The response for every request once the queue is empty. A route with
    /// neither is exhausted and no longer matches.
    standing: Option<Responder>,
}

impl Route {
    fn is_live(&self) -> bool {
        !self.queued.is_empty() || self.standing.is_some()
    }

    fn respond(&mut self, request: &Recorded) -> Option<MockResponse> {
        if let Some(response) = self.queued.pop_front() {
            return Some(response);
        }
        self.standing.as_ref().map(|responder| responder(request))
    }
}

#[derive(Default)]
struct Inner {
    routes: Mutex<Vec<Route>>,
    calls: Mutex<Vec<Recorded>>,
    streams: Mutex<VecDeque<Box<dyn Transport>>>,
    fallback: Mutex<Option<Arc<dyn RoundTrip>>>,
}

/// A scripted transport. Cloning yields another handle to the same script and
/// the same call log, so a test keeps one handle and gives the client another.
#[derive(Clone, Default)]
pub struct Mock {
    inner: Arc<Inner>,
}

/// Adds responses to the route started by [`Mock::on`].
pub struct RouteBuilder<'a> {
    mock: &'a Mock,
    index: usize,
}

impl RouteBuilder<'_> {
    fn update(&self, change: impl FnOnce(&mut Route)) {
        let mut routes = lock(&self.mock.inner.routes);
        if let Some(route) = routes.get_mut(self.index) {
            change(route);
        }
    }

    /// Answer the next matching request with `response`, once. Chain several
    /// to script a sequence; chain [`RouteBuilder::reply`] last for what
    /// follows the sequence.
    pub fn reply_once(self, response: MockResponse) -> Self {
        self.update(|route| route.queued.push_back(response));
        self
    }

    /// Answer every further matching request with `response`.
    pub fn reply(self, response: MockResponse) {
        self.update(|route| route.standing = Some(Arc::new(move |_| response.clone())));
    }

    /// Answer every further matching request with what `responder` builds
    /// from it.
    pub fn reply_with(self, responder: impl Fn(&Recorded) -> MockResponse + Send + Sync + 'static) {
        self.update(|route| route.standing = Some(Arc::new(responder)));
    }
}

impl Mock {
    /// Construct an empty mock transport with no routes and no fallback.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a route for requests `matcher` accepts. Routes are tried in the
    /// order they were added; the first live one that matches answers.
    pub fn on(&self, matcher: Matcher) -> RouteBuilder<'_> {
        let mut routes = lock(&self.inner.routes);
        routes.push(Route {
            matcher,
            queued: VecDeque::new(),
            standing: None,
        });
        RouteBuilder {
            mock: self,
            index: routes.len() - 1,
        }
    }

    /// Send requests no route matches to `transport` instead of failing them:
    /// mock a few endpoints and let everything else reach the real network.
    pub fn fallback(&self, transport: impl RoundTrip) {
        *lock(&self.inner.fallback) = Some(Arc::new(transport));
    }

    /// Queue a byte stream for the next upgrade ([`crate::Client::connect_ws`]).
    /// Typically one end of a `tokio::io::duplex` whose other end the test
    /// drives as the peer.
    pub fn push_stream(&self, stream: impl Transport + 'static) {
        lock(&self.inner.streams).push_back(Box::new(stream));
    }

    /// Every request received so far, in order.
    pub fn calls(&self) -> Vec<Recorded> {
        lock(&self.inner.calls).clone()
    }

    /// How many received requests `matcher` accepts.
    pub fn hits(&self, matcher: &Matcher) -> usize {
        lock(&self.inner.calls)
            .iter()
            .filter(|call| matcher.matches(call))
            .count()
    }

    fn fallback_transport(&self) -> Option<Arc<dyn RoundTrip>> {
        lock(&self.inner.fallback).clone()
    }

    async fn answer(&self, attempt: Attempt<'_>, request: &Request) -> Result<Exchange, NetError> {
        let mut recorded = Recorded {
            authority: attempt.plan.target.authority.clone(),
            method: request.head.method.clone(),
            target: request.head.target.clone(),
            headers: request.head.headers.clone(),
            body: request
                .body
                .as_bytes()
                .map_or_else(Bytes::new, Bytes::copy_from_slice),
        };
        let needs_body_for_match = request.body.known_len().is_none()
            && lock(&self.inner.routes)
                .iter()
                .any(|route| route.is_live() && route.matcher.needs_body());
        if needs_body_for_match {
            recorded.body = request.body.collect_bytes().await?;
        }
        let response = {
            let mut routes = lock(&self.inner.routes);
            routes
                .iter_mut()
                .filter(|route| route.is_live() && route.matcher.matches(&recorded))
                .find_map(|route| route.respond(&recorded))
        };
        let Some(response) = response else {
            if let Some(fallback) = self.fallback_transport() {
                return fallback.round_trip(attempt, request).await;
            }
            return Err(NetError::Protocol(format!(
                "mock: no route matches {} {} on {}",
                recorded.method, recorded.target, recorded.authority
            )));
        };
        if request.body.known_len().is_none() && !needs_body_for_match {
            recorded.body = request.body.collect_bytes().await?;
        }
        let body_len = recorded.body.len();
        lock(&self.inner.calls).push(recorded);

        // The same milestones a real transport marks, so derivations over a
        // mocked trace measure the scripted pacing.
        let recorder = attempt.recorder;
        recorder.mark(EventKind::RequestWriteStart, 0, 0);
        recorder.mark(EventKind::RequestWriteEnd, body_len as u32, 0);

        let MockResponse {
            status,
            headers,
            chunks,
            head_delay,
            chunk_delay,
            failure,
        } = response;
        let limit = attempt.config.response_head_timeout;
        let head_phase = async {
            if let Some(delay) = head_delay {
                tokio::time::sleep(delay).await;
            }
            match failure {
                Some((FailAt::BeforeHead, kind)) => Err(NetError::Io(kind.into())),
                _ => Ok(()),
            }
        };
        match limit {
            Some(limit) => tokio::time::timeout(limit, head_phase)
                .await
                .map_err(|_| NetError::Timeout {
                    phase: netune_trace::DiagnosticPhase::Response,
                    waiting_for: "response head",
                    limit,
                })??,
            None => head_phase.await?,
        }

        let mut header_map = HeaderMap::new();
        for (name, value) in &headers {
            let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                NetError::Protocol(format!("mock: header name {name:?}: {error}"))
            })?;
            let value = http::HeaderValue::from_str(value)
                .map_err(|error| NetError::Protocol(format!("mock: header value: {error}")))?;
            header_map.append(name, value);
        }
        let total: u64 = chunks.iter().map(|chunk| chunk.len() as u64).sum();
        Ok(Exchange {
            head: IncomingResponse {
                version: http::Version::HTTP_11,
                status,
                headers: header_map,
                body: if chunks.len() > 1 {
                    BodyKind::Chunked
                } else {
                    BodyKind::Length(total)
                },
            },
            body: Box::new(Body {
                chunks: chunks.into(),
                delivered: 0,
                chunk_delay,
                fail_after: match failure {
                    Some((FailAt::AfterChunks(count), kind)) => Some((count, kind)),
                    _ => None,
                },
            }),
            connection: ConnectionInfo::default(),
        })
    }
}

impl RoundTrip for Mock {
    fn round_trip<'a>(
        &'a self,
        attempt: Attempt<'a>,
        request: &'a Request,
    ) -> BoxFuture<'a, Result<Exchange, NetError>> {
        Box::pin(self.answer(attempt, request))
    }

    fn open_stream<'a>(
        &'a self,
        attempt: Attempt<'a>,
    ) -> BoxFuture<'a, Result<Established, NetError>> {
        Box::pin(async move {
            if let Some(stream) = lock(&self.inner.streams).pop_front() {
                return Ok(Established {
                    stream,
                    local_port: None,
                    socket: None,
                    alpn: None,
                    alpn_protocol: None,
                });
            }
            if let Some(fallback) = self.fallback_transport() {
                return fallback.open_stream(attempt).await;
            }
            Err(NetError::Protocol(format!(
                "mock: no stream is queued for an upgrade to {}",
                attempt.plan.target.authority
            )))
        })
    }
}

struct Body {
    chunks: VecDeque<Bytes>,
    delivered: usize,
    chunk_delay: Option<Duration>,
    fail_after: Option<(usize, std::io::ErrorKind)>,
}

impl BodySource for Body {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Bytes>, NetError>> {
        Box::pin(async move {
            if let Some((count, kind)) = self.fail_after
                && self.delivered >= count
            {
                return Err(NetError::Io(kind.into()));
            }
            let Some(chunk) = self.chunks.pop_front() else {
                return Ok(None);
            };
            if let Some(delay) = self.chunk_delay {
                tokio::time::sleep(delay).await;
            }
            self.delivered += 1;
            Ok(Some(chunk))
        })
    }

    fn release(self: Box<Self>, _complete: bool) -> Released {
        Released::untapped()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recorded(method: Method, target: &str) -> Recorded {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", http::HeaderValue::from_static("blue"));
        Recorded {
            authority: "api.example:443".into(),
            method,
            target: target.into(),
            headers,
            body: Bytes::from_static(b"{}"),
        }
    }

    #[test]
    fn a_matcher_requires_every_condition_it_was_given() {
        let request = recorded(Method::POST, "/v1/jobs?dry=1");
        assert!(Matcher::any().matches(&request));
        assert!(Matcher::post("/v1/jobs?dry=1").matches(&request));
        assert!(!Matcher::get("/v1/jobs?dry=1").matches(&request));
        assert!(!Matcher::post("/v1/jobs").matches(&request));
        assert!(Matcher::any().path_prefix("/v1/").matches(&request));
        assert!(
            Matcher::any()
                .authority("api.example:443")
                .matches(&request)
        );
        assert!(
            !Matcher::any()
                .authority("other.example:443")
                .matches(&request)
        );
        assert!(Matcher::any().header("X-Tenant", "blue").matches(&request));
        assert!(!Matcher::any().header("x-tenant", "red").matches(&request));
        assert!(
            Matcher::any()
                .when(|request| request.body.as_ref() == b"{}")
                .matches(&request)
        );
        assert!(!Matcher::any().when(|_| false).matches(&request));
    }

    #[test]
    fn a_route_spends_its_one_shot_replies_before_its_standing_one() {
        let mut route = Route {
            matcher: Matcher::any(),
            queued: VecDeque::from([MockResponse::new(StatusCode::SERVICE_UNAVAILABLE)]),
            standing: Some(Arc::new(|_| MockResponse::ok("ok"))),
        };
        let request = recorded(Method::GET, "/");
        assert_eq!(
            route.respond(&request).map(|r| r.status),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert_eq!(
            route.respond(&request).map(|r| r.status),
            Some(StatusCode::OK)
        );
        assert!(route.is_live());

        let spent = Route {
            matcher: Matcher::any(),
            queued: VecDeque::new(),
            standing: None,
        };
        assert!(
            !spent.is_live(),
            "a route with nothing left no longer matches"
        );
    }
}
