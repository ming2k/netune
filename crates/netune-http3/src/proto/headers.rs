// SPDX-License-Identifier: MIT

//! HTTP/3 field-section conversion and validation (RFC 9114 Section 4).
//!
//! QPACK is byte-oriented; this module is the boundary where `http` types become
//! ordered field lines and back. It enforces the HTTP/3 rules that a generic
//! header map cannot express: pseudo-header placement, required request
//! pseudo-fields, lowercase names, and forbidden connection-specific fields.

use http::header::{HOST, HeaderMap, HeaderName, HeaderValue};
use http::uri::{Authority, PathAndQuery, Scheme, Uri};
use http::{Method, Request, Response, StatusCode, Version};

use crate::qpack::HeaderField;

/// The order in which request pseudo-headers and regular headers are emitted
/// into the QPACK header block.
///
/// This is a wire-order policy, not a connection setting. Pseudo-fields omitted
/// from `pseudo` are appended in the protocol's default order so a request
/// cannot lose a required pseudo-header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeaderOrder {
    pub pseudo: Vec<&'static str>,
    pub regular: Vec<&'static str>,
}

impl Default for RequestHeaderOrder {
    fn default() -> Self {
        Self {
            pseudo: vec![
                ":method",
                ":scheme",
                ":authority",
                ":path",
                ":status",
                ":protocol",
            ],
            regular: Vec::new(),
        }
    }
}

impl RequestHeaderOrder {
    pub fn new(
        pseudo: impl IntoIterator<Item = &'static str>,
        regular: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        Self {
            pseudo: pseudo.into_iter().collect(),
            regular: regular.into_iter().collect(),
        }
    }

    fn ordered_pseudo(&self) -> Vec<&'static str> {
        let mut order = Vec::new();
        for name in self.pseudo.iter().copied() {
            if !order.contains(&name) {
                order.push(name);
            }
        }
        for required in Self::default().pseudo {
            if !order.contains(&required) {
                order.push(required);
            }
        }
        order
    }
}

/// A malformed HTTP/3 field section.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("HTTP/3 pseudo-header {0} is not allowed here")]
    UnexpectedPseudo(&'static str),
    #[error("duplicate HTTP/3 pseudo-header {0}")]
    DuplicatePseudo(&'static str),
    #[error("HTTP/3 pseudo-header {0} appears after a regular header")]
    PseudoAfterRegular(String),
    #[error("missing HTTP/3 pseudo-header {0}")]
    MissingPseudo(&'static str),
    #[error("invalid HTTP/3 header name")]
    InvalidName,
    #[error("invalid HTTP/3 header value")]
    InvalidValue,
    #[error("HTTP/3 authority and Host disagree")]
    ContradictedAuthority,
    #[error("HTTP/3 connection-specific header {0} is forbidden")]
    ForbiddenHeader(&'static str),
    #[error("HTTP/3 `te` must be `trailers`")]
    InvalidTe,
    #[error("extended CONNECT is not supported")]
    ExtendedConnectUnsupported,
    #[error("invalid HTTP/3 request URI: {0}")]
    InvalidUri(String),
    #[error("HTTP/3 HTTP type error: {0}")]
    Http(String),
}

/// Encode a request head into ordered QPACK field lines.
pub fn encode_request(
    request: &Request<()>,
    order: &RequestHeaderOrder,
) -> Result<Vec<HeaderField>, HeaderError> {
    let method = request.method();
    let uri = request.uri();
    let mut authority = uri.authority().map(|a| a.as_str().to_string());
    if let Some(host) = request.headers().get(HOST) {
        let host = host.to_str().map_err(|_| HeaderError::InvalidValue)?;
        if let Some(existing) = &authority {
            if existing != host {
                return Err(HeaderError::ContradictedAuthority);
            }
        } else {
            authority = Some(host.to_string());
        }
    }

    let scheme = uri.scheme_str().unwrap_or("https");
    let path = uri.path_and_query().map_or("/", PathAndQuery::as_str);
    let is_connect = *method == Method::CONNECT;
    if !is_connect && authority.is_none() {
        return Err(HeaderError::MissingPseudo(":authority"));
    }

    let mut available: Vec<(&'static str, Vec<u8>)> = Vec::new();
    available.push((":method", method.as_str().as_bytes().to_vec()));
    if !is_connect {
        available.push((":scheme", scheme.as_bytes().to_vec()));
        available.push((":path", path.as_bytes().to_vec()));
    }
    if let Some(authority) = authority {
        if authority.is_empty() {
            return Err(HeaderError::InvalidValue);
        }
        available.push((":authority", authority.into_bytes()));
    }

    let mut fields = Vec::new();
    for name in order.ordered_pseudo() {
        if let Some((_, value)) = available.iter().find(|(candidate, _)| *candidate == name) {
            fields.push(HeaderField::new(name.as_bytes(), value.clone()));
        }
    }

    let mut regular = Vec::new();
    for name in request.headers().keys() {
        let name_bytes = name.as_str().as_bytes();
        for value in request.headers().get_all(name) {
            validate_regular(name, value)?;
            regular.push((name_bytes.to_vec(), value.as_bytes().to_vec()));
        }
    }
    emit_regular(order, regular, &mut fields);
    Ok(fields)
}

/// Encode a response head into QPACK field lines.
pub fn encode_response(response: &Response<()>) -> Result<Vec<HeaderField>, HeaderError> {
    let mut fields = vec![HeaderField::new(
        b":status".as_slice(),
        response.status().as_str().as_bytes().to_vec(),
    )];
    let mut regular = Vec::new();
    for name in response.headers().keys() {
        let name_bytes = name.as_str().as_bytes();
        for value in response.headers().get_all(name) {
            validate_regular(name, value)?;
            regular.push((name_bytes.to_vec(), value.as_bytes().to_vec()));
        }
    }
    emit_regular(&RequestHeaderOrder::default(), regular, &mut fields);
    Ok(fields)
}

/// Encode a trailer section. Pseudo-headers are forbidden.
pub fn encode_trailers(trailers: &HeaderMap) -> Result<Vec<HeaderField>, HeaderError> {
    let mut regular = Vec::new();
    for name in trailers.keys() {
        let name_bytes = name.as_str().as_bytes();
        for value in trailers.get_all(name) {
            validate_regular(name, value)?;
            regular.push((name_bytes.to_vec(), value.as_bytes().to_vec()));
        }
    }
    let mut fields = Vec::new();
    emit_regular(&RequestHeaderOrder::default(), regular, &mut fields);
    Ok(fields)
}

/// Decode a request field section.
pub fn decode_request(fields: &[HeaderField]) -> Result<Request<()>, HeaderError> {
    let mut method = None;
    let mut scheme = None;
    let mut authority = None;
    let mut path = None;
    let mut protocol = None;
    let mut headers = HeaderMap::new();
    let mut seen_regular = false;

    for field in fields {
        if field.name.first() == Some(&b':') {
            if seen_regular {
                return Err(HeaderError::PseudoAfterRegular(
                    String::from_utf8_lossy(&field.name).into_owned(),
                ));
            }
            match field.name.as_slice() {
                b":method" => {
                    set_once(
                        &mut method,
                        ":method",
                        Method::from_bytes(&field.value).map_err(|_| HeaderError::InvalidValue)?,
                    )?;
                }
                b":scheme" => {
                    set_once(
                        &mut scheme,
                        ":scheme",
                        Scheme::try_from(field.value.as_slice())
                            .map_err(|_| HeaderError::InvalidValue)?,
                    )?;
                }
                b":authority" => {
                    if field.value.is_empty() {
                        return Err(HeaderError::InvalidValue);
                    }
                    set_once(
                        &mut authority,
                        ":authority",
                        Authority::try_from(field.value.as_slice())
                            .map_err(|_| HeaderError::InvalidValue)?,
                    )?;
                }
                b":path" => {
                    if field.value.is_empty() {
                        return Err(HeaderError::InvalidValue);
                    }
                    set_once(
                        &mut path,
                        ":path",
                        PathAndQuery::try_from(field.value.as_slice())
                            .map_err(|_| HeaderError::InvalidValue)?,
                    )?;
                }
                b":protocol" => {
                    if field.value.is_empty() {
                        return Err(HeaderError::InvalidValue);
                    }
                    set_once(&mut protocol, ":protocol", field.value.clone())?;
                }
                b":status" => return Err(HeaderError::UnexpectedPseudo(":status")),
                _ => return Err(HeaderError::InvalidName),
            }
        } else {
            seen_regular = true;
            insert_regular(&mut headers, field)?;
        }
    }

    let method = method.ok_or(HeaderError::MissingPseudo(":method"))?;
    if protocol.is_some() {
        return Err(HeaderError::ExtendedConnectUnsupported);
    }
    let is_connect = method == Method::CONNECT;
    if !is_connect {
        if scheme.is_none() {
            return Err(HeaderError::MissingPseudo(":scheme"));
        }
        if path.is_none() {
            return Err(HeaderError::MissingPseudo(":path"));
        }
    }

    if authority.is_none() {
        authority = headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .map(|value| Authority::try_from(value).map_err(|_| HeaderError::InvalidValue))
            .transpose()?;
    } else if let Some(host) = headers.get(HOST) {
        let host = host.to_str().map_err(|_| HeaderError::InvalidValue)?;
        if authority
            .as_ref()
            .is_some_and(|value| value.as_str() != host)
        {
            return Err(HeaderError::ContradictedAuthority);
        }
    }

    let mut builder = Uri::builder();
    if let Some(scheme) = scheme {
        builder = builder.scheme(scheme);
    }
    if let Some(authority) = authority {
        builder = builder.authority(authority);
    }
    if let Some(path) = path {
        builder = builder.path_and_query(path);
    }
    let uri = builder
        .build()
        .map_err(|error| HeaderError::InvalidUri(error.to_string()))?;

    Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_3)
        .body(())
        .map(|mut request| {
            *request.headers_mut() = headers;
            request
        })
        .map_err(|error| HeaderError::Http(error.to_string()))
}

/// Decode a response field section.
pub fn decode_response(fields: &[HeaderField]) -> Result<Response<()>, HeaderError> {
    let mut status = None;
    let mut headers = HeaderMap::new();
    let mut seen_regular = false;

    for field in fields {
        if field.name.first() == Some(&b':') {
            if seen_regular {
                return Err(HeaderError::PseudoAfterRegular(
                    String::from_utf8_lossy(&field.name).into_owned(),
                ));
            }
            match field.name.as_slice() {
                b":status" => {
                    set_once(
                        &mut status,
                        ":status",
                        StatusCode::from_bytes(&field.value)
                            .map_err(|_| HeaderError::InvalidValue)?,
                    )?;
                }
                b":method" | b":scheme" | b":authority" | b":path" | b":protocol" => {
                    return Err(HeaderError::UnexpectedPseudo(":status"));
                }
                _ => return Err(HeaderError::InvalidName),
            }
        } else {
            seen_regular = true;
            insert_regular(&mut headers, field)?;
        }
    }

    let status = status.ok_or(HeaderError::MissingPseudo(":status"))?;
    Response::builder()
        .status(status)
        .version(Version::HTTP_3)
        .body(())
        .map(|mut response| {
            *response.headers_mut() = headers;
            response
        })
        .map_err(|error| HeaderError::Http(error.to_string()))
}

/// Decode a trailer field section.
pub fn decode_trailers(fields: &[HeaderField]) -> Result<HeaderMap, HeaderError> {
    let mut headers = HeaderMap::new();
    for field in fields {
        if field.name.first() == Some(&b':') {
            return Err(HeaderError::UnexpectedPseudo(":status"));
        }
        insert_regular(&mut headers, field)?;
    }
    Ok(headers)
}

fn set_once<T>(slot: &mut Option<T>, name: &'static str, value: T) -> Result<(), HeaderError> {
    if slot.is_some() {
        return Err(HeaderError::DuplicatePseudo(name));
    }
    *slot = Some(value);
    Ok(())
}

fn insert_regular(headers: &mut HeaderMap, field: &HeaderField) -> Result<(), HeaderError> {
    let name = HeaderName::from_lowercase(&field.name).map_err(|_| HeaderError::InvalidName)?;
    let value = HeaderValue::from_bytes(&field.value).map_err(|_| HeaderError::InvalidValue)?;
    validate_regular(&name, &value)?;
    headers.append(name, value);
    Ok(())
}

fn validate_regular(name: &HeaderName, value: &HeaderValue) -> Result<(), HeaderError> {
    match name.as_str() {
        "connection" => Err(HeaderError::ForbiddenHeader("connection")),
        "proxy-connection" => Err(HeaderError::ForbiddenHeader("proxy-connection")),
        "keep-alive" => Err(HeaderError::ForbiddenHeader("keep-alive")),
        "transfer-encoding" => Err(HeaderError::ForbiddenHeader("transfer-encoding")),
        "upgrade" => Err(HeaderError::ForbiddenHeader("upgrade")),
        "te" if value.as_bytes() != b"trailers".as_slice() => Err(HeaderError::InvalidTe),
        _ => Ok(()),
    }
}

fn emit_regular(
    order: &RequestHeaderOrder,
    regular: Vec<(Vec<u8>, Vec<u8>)>,
    fields: &mut Vec<HeaderField>,
) {
    let mut used = vec![false; regular.len()];
    for wanted in &order.regular {
        for (index, (name, value)) in regular.iter().enumerate() {
            if !used[index] && name.as_slice() == wanted.as_bytes() {
                used[index] = true;
                fields.push(HeaderField::new(name.clone(), value.clone()));
            }
        }
    }
    for (index, (name, value)) in regular.into_iter().enumerate() {
        if !used[index] {
            fields.push(HeaderField::new(name, value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request<()> {
        Request::builder()
            .method("GET")
            .uri("https://example.com/path?q=1")
            .header("user-agent", "netune")
            .header("accept", "*/*")
            .header("x-test", "one")
            .header("x-test", "two")
            .body(())
            .expect("request")
    }

    #[test]
    fn profile_order_is_applied_before_qpack() {
        let fields = encode_request(
            &request(),
            &RequestHeaderOrder::new(
                [":method", ":authority", ":scheme", ":path"],
                ["user-agent", "accept"],
            ),
        )
        .expect("encode");
        let names: Vec<&[u8]> = fields.iter().map(|field| field.name.as_slice()).collect();
        assert_eq!(
            names,
            vec![
                b":method".as_slice(),
                b":authority".as_slice(),
                b":scheme".as_slice(),
                b":path".as_slice(),
                b"user-agent".as_slice(),
                b"accept".as_slice(),
                b"x-test".as_slice(),
                b"x-test".as_slice(),
            ]
        );
        assert_eq!(fields[7].value, b"two");
    }

    #[test]
    fn duplicate_pseudo_entries_in_a_profile_are_emitted_once() {
        let fields = encode_request(
            &request(),
            &RequestHeaderOrder::new([":method", ":method"], []),
        )
        .expect("encode");
        assert_eq!(
            fields
                .iter()
                .filter(|field| field.name == b":method")
                .count(),
            1
        );
    }

    #[test]
    fn request_round_trip_preserves_method_uri_and_fields() {
        let fields = encode_request(&request(), &RequestHeaderOrder::default()).expect("encode");
        let decoded = decode_request(&fields).expect("decode");
        assert_eq!(decoded.method(), Method::GET);
        assert_eq!(decoded.uri().scheme_str(), Some("https"));
        assert_eq!(
            decoded.uri().authority().map(|a| a.as_str()),
            Some("example.com")
        );
        assert_eq!(
            decoded.uri().path_and_query().map(|p| p.as_str()),
            Some("/path?q=1")
        );
        assert_eq!(decoded.headers()["user-agent"], "netune");
        assert_eq!(decoded.headers().get_all("x-test").iter().count(), 2);
    }

    #[test]
    fn response_round_trip() {
        let response = Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(())
            .expect("response");
        let fields = encode_response(&response).expect("encode");
        assert_eq!(fields[0].name, b":status");
        assert_eq!(fields[0].value, b"200");
        let decoded = decode_response(&fields).expect("decode");
        assert_eq!(decoded.status(), StatusCode::OK);
        assert_eq!(decoded.headers()["content-type"], "text/plain");
    }

    #[test]
    fn forbidden_and_misordered_fields_are_rejected() {
        let fields = vec![
            HeaderField::new(b"x-test".as_slice(), b"one".as_slice()),
            HeaderField::new(b":method".as_slice(), b"GET".as_slice()),
        ];
        assert!(matches!(
            decode_request(&fields),
            Err(HeaderError::PseudoAfterRegular(_))
        ));

        let fields = vec![
            HeaderField::new(b":method".as_slice(), b"GET".as_slice()),
            HeaderField::new(b":scheme".as_slice(), b"https".as_slice()),
            HeaderField::new(b":path".as_slice(), b"/".as_slice()),
            HeaderField::new(b"connection".as_slice(), b"close".as_slice()),
        ];
        assert!(matches!(
            decode_request(&fields),
            Err(HeaderError::ForbiddenHeader("connection"))
        ));
    }

    #[test]
    fn trailers_reject_pseudo_headers() {
        let fields = vec![HeaderField::new(b":status".as_slice(), b"200".as_slice())];
        assert!(matches!(
            decode_trailers(&fields),
            Err(HeaderError::UnexpectedPseudo(_))
        ));
    }
}
