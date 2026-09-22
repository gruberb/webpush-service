//! Black-box harness for the conformance suite. Everything here speaks the
//! wire protocols only (HTTPS and WebSocket), except `TestServer::start`,
//! which launches the server under test. The ES256 signer and the
//! `aes128gcm` builders are independent of `src/` so a bug in the
//! implementation cannot validate itself.
#![allow(dead_code)]

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{Aes128Gcm, KeyInit, aead::Aead};
use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use http::{HeaderMap, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::rand_core::{OsRng, RngCore},
};
use serde_json::{Value, json};
use tokio::{net::TcpStream, sync::Mutex, task::JoinHandle, time::timeout};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{self, ClientConfig, RootCertStore, pki_types::ServerName},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message as Frame, client::IntoClientRequest},
};

/// Link relation for a receipt subscription (RFC 8030 §9.1).
pub const REL_RECEIPT: &str = "urn:ietf:params:push:receipt";
/// Upper bound on any single wait in the harness.
const WAIT: Duration = Duration::from_secs(5);

/// Base64url without padding, the encoding every Web Push RFC uses.
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url without padding. Panics on invalid input.
pub fn unb64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("base64url")
}

/// Current time in seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `N` random octets from the OS CSPRNG.
pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// A fresh lowercase UUID, as Firefox generates channel ids.
pub fn channel_id() -> String {
    use std::fmt::Write;
    let h = random::<16>().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

// ---------------------------------------------------------------------------
// Server under test

/// A push service under test with its own store. With
/// `PUSH_TEST_STORE=bigtable` (and the `bigtable` feature) the store is a
/// Bigtable emulator started for this server alone. Everything stops when
/// this is dropped.
pub struct TestServer {
    /// `https://localhost:{port}`: the base of every URI the server issues.
    pub origin: String,
    /// Address to connect to; `localhost` in `origin` resolves here.
    pub addr: SocketAddr,
    /// The server certificate, trusted by every client the harness builds.
    cert_der: Vec<u8>,
    /// The emulator process, when testing against Bigtable.
    _emulator: Option<Emulator>,
    /// The serving task.
    server: JoinHandle<Result<(), webpush_service::BoxError>>,
}

impl TestServer {
    /// Start a server on a free port with a fresh self-signed certificate for
    /// `localhost`.
    pub async fn start() -> TestServer {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = format!("https://localhost:{}", addr.port());
        let cfg = webpush_service::Config {
            origin: origin.clone(),
            tls_cert_pem: cert.cert.pem(),
            tls_key_pem: cert.signing_key.serialize_pem(),
            max_ttl: 60 * 24 * 3600,
            max_payload: 4096,
            reaper_interval: Duration::from_millis(100),
        };
        let backend = std::env::var("PUSH_TEST_STORE").unwrap_or_default();
        let (emulator, server) = match backend.as_str() {
            "" | "memory" => {
                let store = webpush_service::store::MemoryStore::new();
                (
                    None,
                    tokio::spawn(webpush_service::serve(listener, cfg, store)),
                )
            }
            #[cfg(feature = "bigtable")]
            "bigtable" => {
                let (emulator, store) = bigtable::start(cfg.max_ttl).await;
                (
                    Some(emulator),
                    tokio::spawn(webpush_service::serve(listener, cfg, store)),
                )
            }
            other => panic!("PUSH_TEST_STORE={other} is not supported by this build"),
        };
        TestServer {
            origin,
            addr,
            cert_der: cert.cert.der().to_vec(),
            _emulator: emulator,
            server,
        }
    }

    /// An absolute URL on this server.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }

    /// A TLS connection offering exactly one ALPN protocol.
    async fn tls(&self, alpn: &[u8]) -> TlsStream<TcpStream> {
        let mut roots = RootCertStore::empty();
        roots.add(self.cert_der.clone().into()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![alpn.to_vec()];
        let tcp = TcpStream::connect(self.addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .expect("TLS handshake")
    }

    /// An HTTPS client over HTTP/2.
    pub async fn http(&self) -> Http {
        let io = TokioIo::new(self.tls(b"h2").await);
        let (send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .expect("h2 handshake");
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });
        Http {
            send: Mutex::new(Sender::H2(send)),
            origin: self.origin.clone(),
            _conn: AbortOnDrop(task),
        }
    }

    /// An HTTPS client over HTTP/1.1.
    pub async fn h1(&self) -> Http {
        let io = TokioIo::new(self.tls(b"http/1.1").await);
        let (send, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("h1 handshake");
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });
        Http {
            send: Mutex::new(Sender::H1(send)),
            origin: self.origin.clone(),
            _conn: AbortOnDrop(task),
        }
    }

    /// A WebSocket connection to `/` offering the `push-notification`
    /// subprotocol, as Firefox connects.
    pub async fn ua(&self) -> Ua {
        let tls = self.tls(b"http/1.1").await;
        let mut req = format!("wss://localhost:{}/", self.addr.port())
            .into_client_request()
            .unwrap();
        req.headers_mut().insert(
            "sec-websocket-protocol",
            http::HeaderValue::from_static("push-notification"),
        );
        let (ws, resp) = tokio_tungstenite::client_async(req, tls)
            .await
            .expect("WebSocket handshake");
        Ua {
            ws,
            origin: self.origin.clone(),
            protocol: resp
                .headers()
                .get("sec-websocket-protocol")
                .map(|v| v.to_str().unwrap().to_owned()),
        }
    }

    /// Open a receipt stream: `GET` on a receipt subscription over HTTP/2.
    pub async fn receipts(&self, uri: &str, headers: &[(&str, &str)]) -> ReceiptStream {
        let http = self.http().await;
        let resp = http.send(Method::GET, uri, headers, b"").await;
        let (parts, body) = resp.into_parts();
        ReceiptStream {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body,
            buf: String::new(),
            _http: http,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// Kills the emulator on drop, including when `start` panics part way.
pub struct Emulator(std::process::Child);

impl Drop for Emulator {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Aborts a background task when dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Bigtable emulator setup, used by `PUSH_TEST_STORE=bigtable` and the store
/// contract suite.
#[cfg(feature = "bigtable")]
pub mod bigtable {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    use webpush_service::store::{BigtableConfig, BigtableStore};

    use super::Emulator;

    /// A TCP port that was free a moment ago.
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// Path to the Bigtable emulator: `$CBTEMULATOR`, else the gcloud SDK
    /// copy.
    fn cbtemulator() -> String {
        if let Ok(p) = std::env::var("CBTEMULATOR") {
            return p;
        }
        let out = Command::new("gcloud")
            .args(["info", "--format=value(installation.sdk_root)"])
            .output()
            .expect("set $CBTEMULATOR or install gcloud with the bigtable emulator");
        let root = String::from_utf8(out.stdout).unwrap();
        format!("{}/platform/bigtable-emulator/cbtemulator", root.trim())
    }

    /// Start an emulator, create the table, and connect a store to it.
    pub async fn start(max_ttl: u32) -> (Emulator, BigtableStore) {
        let port = free_port();
        let emulator = Emulator(
            Command::new(cbtemulator())
                .args(["-host", "127.0.0.1", "-port", &port.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn cbtemulator"),
        );
        let cfg = BigtableConfig {
            endpoint: format!("http://127.0.0.1:{port}"),
            project: "test".to_owned(),
            instance: "test".to_owned(),
            table: "push".to_owned(),
            max_ttl,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match BigtableStore::ensure_table(&cfg).await {
                Ok(()) => break,
                Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => panic!("ensure_table: {e}"),
            }
        }
        let store = BigtableStore::connect(&cfg).await.expect("connect");
        (emulator, store)
    }
}

// ---------------------------------------------------------------------------
// HTTPS client

/// A complete response.
#[derive(Debug)]
pub struct Resp {
    /// Status code.
    pub status: u16,
    /// Response header fields.
    pub headers: HeaderMap,
    /// The complete response body.
    pub body: Bytes,
}

impl Resp {
    /// A header value as text. Panics if it is not visible ASCII.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }

    /// `Location`, resolved against `origin`.
    pub fn location(&self, origin: &str) -> String {
        resolve(origin, self.header("location").expect("Location header"))
    }

    /// Targets of links with relation `rel`, resolved against `origin`.
    pub fn links(&self, origin: &str, rel: &str) -> Vec<String> {
        links(&self.headers, rel)
            .iter()
            .map(|t| resolve(origin, t))
            .collect()
    }
}

/// A response future, boxed so both HTTP versions share one type.
type ResponseFuture = Pin<Box<dyn Future<Output = hyper::Result<http::Response<Incoming>>> + Send>>;

/// The HTTP version a client speaks.
enum Sender {
    /// HTTP/1.1: requests in origin form with a `Host` header.
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    /// HTTP/2: requests with absolute URIs.
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

/// An HTTPS connection to the server under test.
pub struct Http {
    /// The connection, serialized so HTTP/1.1 requests do not interleave.
    send: Mutex<Sender>,
    /// Origin used to resolve relative `Location` and `Link` targets.
    pub origin: String,
    /// Drives the connection.
    _conn: AbortOnDrop,
}

impl Http {
    /// Send a request and return the response with its body unread.
    async fn send(
        &self,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> http::Response<Incoming> {
        let parsed: http::Uri = uri.parse().unwrap();
        let build = |target: &str| {
            let mut req = Request::builder().method(method.clone()).uri(target);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            req
        };
        let body = Full::new(Bytes::copy_from_slice(body));
        let fut: ResponseFuture = {
            let mut send = self.send.lock().await;
            match &mut *send {
                Sender::H1(s) => {
                    s.ready().await.expect("h1 ready");
                    let req = build(parsed.path())
                        .header("host", parsed.authority().unwrap().as_str())
                        .body(body)
                        .unwrap();
                    Box::pin(s.send_request(req))
                }
                Sender::H2(s) => {
                    s.ready().await.expect("h2 ready");
                    Box::pin(s.send_request(build(uri).body(body).unwrap()))
                }
            }
        };
        timeout(WAIT, fut)
            .await
            .expect("response timed out")
            .expect("response")
    }

    /// Send a request and read the whole response. Panics after 5 s.
    pub async fn request(
        &self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Resp {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let resp = self.send(method, uri, headers, body).await;
        let (parts, body) = resp.into_parts();
        Resp {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body: timeout(WAIT, body.collect())
                .await
                .expect("body timed out")
                .expect("body")
                .to_bytes(),
        }
    }
}

// ---------------------------------------------------------------------------
// User agent (Firefox protocol) client

/// A subscription created through `register`.
#[derive(Clone, Debug)]
pub struct Sub {
    /// The channel id the client chose.
    pub channel_id: String,
    /// The push resource (`pushEndpoint`), given to the application server.
    pub push: String,
}

/// A WebSocket session speaking the Firefox push protocol.
pub struct Ua {
    /// The connection.
    ws: WebSocketStream<TlsStream<TcpStream>>,
    /// Origin of the server, for building expected URIs.
    pub origin: String,
    /// The subprotocol the server selected, if any.
    pub protocol: Option<String>,
}

impl Ua {
    /// Send a text frame.
    pub async fn send_raw(&mut self, text: &str) {
        use futures_util::SinkExt;
        self.ws
            .send(Frame::Text(text.into()))
            .await
            .expect("send frame");
    }

    /// Send a JSON message.
    pub async fn send(&mut self, value: &Value) {
        self.send_raw(&value.to_string()).await;
    }

    /// The next text frame as JSON, skipping control frames. `None` once the
    /// server closes the connection. Panics after 5 s.
    pub async fn recv(&mut self) -> Option<Value> {
        timeout(WAIT, self.next_json())
            .await
            .expect("no message within 5 s")
    }

    /// Like [`Ua::recv`] with a custom wait; `Err` on timeout.
    async fn recv_within(&mut self, ms: u64) -> Result<Option<Value>, ()> {
        timeout(Duration::from_millis(ms), self.next_json())
            .await
            .map_err(|_| ())
    }

    /// Read frames until a text frame or the end of the connection.
    async fn next_json(&mut self) -> Option<Value> {
        use futures_util::StreamExt;
        loop {
            match self.ws.next().await? {
                Ok(Frame::Text(t)) => return Some(serde_json::from_str(&t).expect("JSON frame")),
                Ok(Frame::Close(_)) | Err(_) => return None,
                Ok(_) => {}
            }
        }
    }

    /// Send `hello` the way Firefox does and return the issued `uaid`.
    /// Asserts the reply fields Firefox checks.
    pub async fn hello(&mut self, uaid: Option<&str>) -> String {
        let mut msg = json!({ "messageType": "hello", "broadcasts": {}, "use_webpush": true });
        if let Some(uaid) = uaid {
            msg["uaid"] = uaid.into();
        }
        self.send(&msg).await;
        let reply = self.recv().await.expect("hello reply");
        assert_eq!(reply["messageType"], "hello", "{reply}");
        assert_eq!(reply["status"], 200, "{reply}");
        assert_eq!(reply["use_webpush"], true, "{reply}");
        reply["uaid"].as_str().expect("uaid").to_owned()
    }

    /// Send `register` and return the reply.
    pub async fn register(&mut self, channel_id: &str, key: Option<&str>) -> Value {
        let mut msg = json!({ "messageType": "register", "channelID": channel_id });
        if let Some(key) = key {
            msg["key"] = key.into();
        }
        self.send(&msg).await;
        let reply = self.recv().await.expect("register reply");
        assert_eq!(reply["messageType"], "register", "{reply}");
        reply
    }

    /// Register a fresh channel, optionally restricted to `key` (sent padded,
    /// as Firefox does), and assert success.
    pub async fn subscribe(&mut self, key: Option<&AppServerKey>) -> Sub {
        let channel_id = channel_id();
        let padded = key.map(|k| URL_SAFE.encode(k.public()));
        let reply = self.register(&channel_id, padded.as_deref()).await;
        assert_eq!(reply["status"], 200, "{reply}");
        Sub {
            channel_id,
            push: reply["pushEndpoint"]
                .as_str()
                .expect("pushEndpoint")
                .to_owned(),
        }
    }

    /// Send `unregister` and return the reply.
    pub async fn unregister(&mut self, channel_id: &str) -> Value {
        self.send(&json!({ "messageType": "unregister", "channelID": channel_id, "code": 200 }))
            .await;
        self.recv().await.expect("unregister reply")
    }

    /// Acknowledge one message.
    pub async fn ack(&mut self, channel_id: &str, version: &str, code: u16) {
        self.send(&json!({
            "messageType": "ack",
            "updates": [{ "channelID": channel_id, "version": version, "code": code }],
        }))
        .await;
    }

    /// The next message, which must be a notification. Panics after 5 s.
    pub async fn next_notification(&mut self) -> Notification {
        let msg = self.recv().await.expect("connection closed");
        assert_eq!(msg["messageType"], "notification", "{msg}");
        Notification(msg)
    }

    /// Panics if a message arrives within `ms` milliseconds.
    pub async fn expect_no_notification(&mut self, ms: u64) {
        if let Ok(Some(msg)) = self.recv_within(ms).await {
            panic!("unexpected message: {msg}");
        }
    }

    /// Every message that arrives until none has for `ms` milliseconds.
    pub async fn drain(&mut self, ms: u64) -> Vec<Notification> {
        let mut out = Vec::new();
        while let Ok(Some(msg)) = self.recv_within(ms).await {
            out.push(Notification(msg));
        }
        out
    }

    /// Whether the server closes the connection within 5 s.
    pub async fn closed(&mut self) -> bool {
        loop {
            match timeout(WAIT, self.next_json()).await {
                Ok(None) => return true,
                Ok(Some(_)) => {}
                Err(_) => return false,
            }
        }
    }
}

/// A `notification` message.
#[derive(Clone, Debug)]
pub struct Notification(pub Value);

impl Notification {
    /// `channelID`.
    pub fn channel_id(&self) -> &str {
        self.0["channelID"].as_str().expect("channelID")
    }

    /// `version`: the message id.
    pub fn version(&self) -> &str {
        self.0["version"].as_str().expect("version")
    }

    /// The decoded body. Empty when `data` is absent.
    pub fn data(&self) -> Vec<u8> {
        self.0["data"]
            .as_str()
            .map(|d| {
                URL_SAFE_NO_PAD
                    .decode(d.trim_end_matches('='))
                    .expect("data is base64url")
            })
            .unwrap_or_default()
    }

    /// `headers.encoding`, if present.
    pub fn encoding(&self) -> Option<&str> {
        self.0["headers"]["encoding"].as_str()
    }
}

// ---------------------------------------------------------------------------
// Receipt stream (Server-Sent Events) client

/// An open `GET` on a receipt subscription.
pub struct ReceiptStream {
    /// Response status.
    pub status: u16,
    /// Response header fields.
    pub headers: HeaderMap,
    /// The event stream.
    body: Incoming,
    /// Text received but not yet parsed into events.
    buf: String,
    /// Keeps the connection open.
    _http: Http,
}

/// One Server-Sent Event.
#[derive(Debug)]
pub struct Sse {
    /// `event:` field.
    pub event: String,
    /// `id:` field.
    pub id: Option<String>,
    /// `data:` field.
    pub data: String,
}

impl ReceiptStream {
    /// The next event, skipping comments. `None` when the stream ends.
    /// Panics after 5 s.
    pub async fn next_event(&mut self) -> Option<Sse> {
        timeout(WAIT, self.read_event())
            .await
            .expect("no event within 5 s")
    }

    /// Read until a complete event or the end of the stream.
    async fn read_event(&mut self) -> Option<Sse> {
        loop {
            if let Some(end) = self.buf.find("\n\n") {
                let block: String = self.buf.drain(..end + 2).collect();
                let mut sse = Sse {
                    event: "message".to_owned(),
                    id: None,
                    data: String::new(),
                };
                let mut fields = false;
                for line in block.lines() {
                    if let Some((field, value)) = line.split_once(": ") {
                        fields = true;
                        match field {
                            "event" => value.clone_into(&mut sse.event),
                            "id" => sse.id = Some(value.to_owned()),
                            "data" => sse.data.push_str(value),
                            _ => {}
                        }
                    }
                }
                if fields {
                    return Some(sse);
                }
                continue;
            }
            let frame = self.body.frame().await?.expect("body frame");
            if let Ok(data) = frame.into_data() {
                self.buf
                    .push_str(std::str::from_utf8(&data).expect("UTF-8"));
            }
        }
    }

    /// The next event, which must be a receipt: `(message URI, status)`.
    pub async fn next_receipt(&mut self) -> (String, u16) {
        let ev = self.next_event().await.expect("stream ended");
        assert_eq!(ev.event, "receipt", "{ev:?}");
        let data: Value = serde_json::from_str(&ev.data).expect("receipt JSON");
        (
            data["message"].as_str().expect("message").to_owned(),
            u16::try_from(data["status"].as_u64().expect("status")).unwrap(),
        )
    }

    /// Panics if an event arrives within `ms` milliseconds.
    pub async fn expect_no_receipt(&mut self, ms: u64) {
        if let Ok(Some(ev)) = timeout(Duration::from_millis(ms), self.read_event()).await {
            panic!("unexpected event: {ev:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Links and URIs

/// Resolve an absolute or absolute-path reference against `origin`.
pub fn resolve(origin: &str, target: &str) -> String {
    if target.starts_with("https://") || target.starts_with("http://") {
        target.to_owned()
    } else {
        assert!(target.starts_with('/'), "unsupported reference {target}");
        format!("{origin}{target}")
    }
}

/// The last path segment of a URI.
pub fn last_segment(uri: &str) -> &str {
    uri.rsplit('/').next().unwrap()
}

/// Minimal RFC 8288 parser: several header instances, comma-separated
/// link-values, quoted or bare `rel`, space-separated relation types.
pub fn links(headers: &HeaderMap, rel: &str) -> Vec<String> {
    let mut out = Vec::new();
    for value in headers.get_all("link") {
        let value = value.to_str().unwrap();
        for link in split_outside(value, ',') {
            let link = link.trim();
            let Some(rest) = link.strip_prefix('<') else {
                continue;
            };
            let Some((target, params)) = rest.split_once('>') else {
                continue;
            };
            let has_rel = split_outside(params, ';').iter().any(|p| {
                let Some((name, val)) = p.split_once('=') else {
                    return false;
                };
                name.trim().eq_ignore_ascii_case("rel")
                    && val
                        .trim()
                        .trim_matches('"')
                        .split_ascii_whitespace()
                        .any(|r| r.eq_ignore_ascii_case(rel))
            });
            if has_rel {
                out.push(target.to_owned());
            }
        }
    }
    out
}

/// Split on `sep`, ignoring separators inside `<...>` or quoted strings.
fn split_outside(s: &str, sep: char) -> Vec<&str> {
    let (mut parts, mut start, mut angle, mut quote) = (Vec::new(), 0, false, false);
    for (i, c) in s.char_indices() {
        match c {
            '<' if !quote => angle = true,
            '>' if !quote => angle = false,
            '"' if !angle => quote = !quote,
            c if c == sep && !angle && !quote => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// A `Link` header value with a quoted `rel` (RFC 8288).
pub fn link_header(target: &str, rel: &str) -> String {
    format!("<{target}>; rel=\"{rel}\"")
}

/// Replace the last path segment of a discovered URI with a same-length id
/// that the server never issued.
pub fn mangle(uri: &str) -> String {
    let (base, seg) = uri.rsplit_once('/').unwrap();
    let fake = if seg.chars().all(|c| c == 'A') {
        "B".repeat(seg.len())
    } else {
        "A".repeat(seg.len())
    };
    format!("{base}/{fake}")
}

// ---------------------------------------------------------------------------
// VAPID oracle: an ES256 JWT signer independent of src/vapid.rs

/// An application server's VAPID signing key (RFC 8292 §2).
pub struct AppServerKey {
    /// The private key.
    key: SigningKey,
}

impl AppServerKey {
    /// A fresh random P-256 key.
    pub fn new() -> Self {
        AppServerKey {
            key: SigningKey::random(&mut OsRng),
        }
    }

    /// Uncompressed public key, 65 octets.
    pub fn public(&self) -> [u8; 65] {
        let point = self.key.verifying_key().to_encoded_point(false);
        point.as_bytes().try_into().unwrap()
    }

    /// The public key as the `k` parameter expects it (RFC 8292 §3.2).
    pub fn k_b64(&self) -> String {
        b64(&self.public())
    }

    /// ES256 signature over `data`.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.key.sign(data)
    }

    /// `b64(header).b64(claims).b64(raw r||s signature)`.
    pub fn token_raw(&self, header_json: &str, claims_json: &str) -> String {
        let input = format!(
            "{}.{}",
            b64(header_json.as_bytes()),
            b64(claims_json.as_bytes())
        );
        let sig = self.sign(input.as_bytes());
        format!("{input}.{}", b64(&sig.to_bytes()))
    }

    /// A signed VAPID JWT with the given claims and an ES256 header.
    pub fn token(&self, aud: &str, exp: u64, sub: Option<&str>) -> String {
        let mut claims = serde_json::json!({ "aud": aud, "exp": exp });
        if let Some(sub) = sub {
            claims["sub"] = sub.into();
        }
        self.token_raw(r#"{"typ":"JWT","alg":"ES256"}"#, &claims.to_string())
    }

    /// A complete `Authorization` header value.
    pub fn auth(&self, aud: &str, exp: u64, sub: Option<&str>) -> String {
        format!("vapid t={}, k={}", self.token(aud, exp, sub), self.k_b64())
    }
}

/// Flip the y coordinate of an uncompressed point by one, which takes it off
/// the curve.
pub fn off_curve(point: &[u8; 65]) -> [u8; 65] {
    let mut p = *point;
    for b in p[33..].iter_mut().rev() {
        let (v, carry) = b.overflowing_add(1);
        *b = v;
        if !carry {
            break;
        }
    }
    p
}

// ---------------------------------------------------------------------------
// aes128gcm oracle: record builders independent of src/ece.rs

/// `salt || rs || idlen || keyid`.
pub fn ece_header(salt: &[u8; 16], rs: u32, keyid: &[u8]) -> Vec<u8> {
    let mut h = salt.to_vec();
    h.extend_from_slice(&rs.to_be_bytes());
    h.push(u8::try_from(keyid.len()).expect("keyid fits the one-octet idlen"));
    h.extend_from_slice(keyid);
    h
}

/// Seal one record whose plaintext (data, delimiter, padding) is `plaintext`,
/// using a given CEK and base nonce at sequence number `seq`.
pub fn ece_record(cek: &[u8; 16], nonce: &[u8; 12], seq: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut n = *nonce;
    for (b, s) in n[4..].iter_mut().zip(seq.to_be_bytes()) {
        *b ^= s;
    }
    Aes128Gcm::new(cek.into())
        .encrypt(&n.into(), plaintext)
        .unwrap()
}

/// A syntactically valid `aes128gcm` body with random salt and ciphertext.
/// The push service only inspects the header, so this needs no real keys.
pub fn opaque_aes128gcm(keyid: &[u8]) -> Vec<u8> {
    let mut body = ece_header(&random(), 4096, keyid);
    body.extend_from_slice(&random::<48>());
    body
}
