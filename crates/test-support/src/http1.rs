//! HTTP/1.1 wire fixtures shared by codec and server suites.

/// A response with a `Content-Length` body.
pub const CONTENT_LENGTH_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
content-type: application/json\r\n\
content-length: 11\r\n\
\r\n\
hello world";

/// A chunked response with a chunk extension and a trailer.
pub const CHUNKED_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
content-type: text/event-stream\r\n\
transfer-encoding: chunked\r\n\
\r\n\
7;ext=1\r\ndata: a\r\n\
8\r\n\ndata: b\r\n\
0\r\n\
x-trace: done\r\n\
\r\n";

/// A close-delimited body: no length, no chunking.
pub const UNTIL_CLOSE_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
content-type: text/plain\r\n\
\r\n\
until the socket closes";
