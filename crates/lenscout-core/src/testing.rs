//! Faux réseau pour les tests (feature `testing`). Les enregistrements ne
//! portent jamais de mot de passe : seul le login est gardé.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;

use crate::transport::{
    ByteStream, CameraHttp, Credentials, Datagram, HttpRequest, HttpResponse, Method, NetError,
};

#[derive(Debug, Clone, PartialEq)]
pub struct RecordedRequest {
    pub method: Method,
    pub url: String,
    pub body: Vec<u8>,
    pub login: Option<String>,
}

enum Reply {
    Full(u16, Vec<u8>),
    Stream(String, Vec<Vec<u8>>),
}

struct Route {
    method: Method,
    prefix: String,
    reply: Reply,
}

#[derive(Default)]
pub struct FakeHttp {
    routes: Vec<Route>,
    requests: Mutex<Vec<RecordedRequest>>,
}

/// `http://10.0.50.11:8080/a/b?c` → `/a/b?c`.
fn path_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.find('/').map_or("/", |i| &rest[i..])
}

impl FakeHttp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on(mut self, method: Method, path_prefix: &str, status: u16, body: impl Into<Vec<u8>>) -> Self {
        self.routes.push(Route {
            method,
            prefix: path_prefix.to_string(),
            reply: Reply::Full(status, body.into()),
        });
        self
    }

    pub fn on_stream(mut self, path_prefix: &str, content_type: &str, chunks: Vec<Vec<u8>>) -> Self {
        self.routes.push(Route {
            method: Method::Get,
            prefix: path_prefix.to_string(),
            reply: Reply::Stream(content_type.to_string(), chunks),
        });
        self
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    fn record(&self, req: &HttpRequest, creds: Option<&Credentials>) {
        self.requests.lock().unwrap().push(RecordedRequest {
            method: req.method,
            url: req.url.clone(),
            body: req.body.clone().unwrap_or_default(),
            login: creds.map(|c| c.login.clone()),
        });
    }

    fn route(&self, req: &HttpRequest) -> Result<&Route, NetError> {
        let path = path_of(&req.url);
        self.routes
            .iter()
            .find(|r| r.method == req.method && path.starts_with(&r.prefix))
            .ok_or_else(|| NetError::Unreachable(format!("route inconnue : {path}")))
    }
}

#[async_trait]
impl CameraHttp for FakeHttp {
    async fn send(&self, req: HttpRequest, creds: Option<&Credentials>) -> Result<HttpResponse, NetError> {
        self.record(&req, creds);
        match &self.route(&req)?.reply {
            Reply::Full(status, body) => Ok(HttpResponse { status: *status, headers: vec![], body: body.clone() }),
            Reply::Stream(ct, chunks) => Ok(HttpResponse {
                status: 200,
                headers: vec![("Content-Type".into(), ct.clone())],
                body: chunks.concat(),
            }),
        }
    }

    async fn stream(&self, req: HttpRequest, creds: Option<&Credentials>) -> Result<(HttpResponse, ByteStream), NetError> {
        self.record(&req, creds);
        match &self.route(&req)?.reply {
            Reply::Stream(ct, chunks) => {
                let items: Vec<Result<Bytes, NetError>> =
                    chunks.iter().map(|c| Ok(Bytes::from(c.clone()))).collect();
                Ok((
                    HttpResponse { status: 200, headers: vec![("Content-Type".into(), ct.clone())], body: vec![] },
                    Box::pin(futures_util::stream::iter(items)),
                ))
            }
            Reply::Full(status, body) => {
                let items: Vec<Result<Bytes, NetError>> = vec![Ok(Bytes::from(body.clone()))];
                Ok((
                    HttpResponse { status: *status, headers: vec![], body: vec![] },
                    Box::pin(futures_util::stream::iter(items)),
                ))
            }
        }
    }
}

pub struct FakeDatagram {
    replies: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
}

impl FakeDatagram {
    pub fn new(replies: Vec<(Vec<u8>, SocketAddr)>) -> Self {
        FakeDatagram { replies: Mutex::new(replies.into()), sent: Mutex::new(vec![]) }
    }

    pub fn sent(&self) -> Vec<(Vec<u8>, SocketAddr)> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl Datagram for FakeDatagram {
    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> Result<(), NetError> {
        self.sent.lock().unwrap().push((buf.to_vec(), dest));
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        let (data, from) = self.replies.lock().unwrap().pop_front().ok_or(NetError::Timeout)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;

    #[tokio::test]
    async fn fake_http_records_requests_without_password() {
        let http = FakeHttp::new().on(Method::Get, "/axis-cgi/param.cgi", 200, "ok");
        let creds = Credentials { login: "root".into(), password: Secret::new("pw-unique".into()) };
        let req = HttpRequest {
            method: Method::Get,
            url: "http://10.0.50.11/axis-cgi/param.cgi?action=list".into(),
            body: None,
            content_type: None,
        };
        let resp = http.send(req, Some(&creds)).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
        let rec = http.requests();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].login.as_deref(), Some("root"));
        assert!(!format!("{:?}", rec[0]).contains("pw-unique"));
    }

    #[tokio::test]
    async fn fake_http_unknown_route_is_unreachable() {
        let http = FakeHttp::new();
        let req = HttpRequest { method: Method::Get, url: "http://10.0.50.11/x".into(), body: None, content_type: None };
        assert!(matches!(http.send(req, None).await, Err(NetError::Unreachable(_))));
    }

    #[tokio::test]
    async fn fake_http_streams_chunks() {
        use futures_util::StreamExt;
        let http = FakeHttp::new().on_stream("/mjpg", "multipart/x-mixed-replace; boundary=b", vec![b"ab".to_vec(), b"cd".to_vec()]);
        let req = HttpRequest { method: Method::Get, url: "http://10.0.50.11/mjpg/video.cgi".into(), body: None, content_type: None };
        let (resp, mut s) = http.stream(req, None).await.unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.is_empty());
        assert!(resp.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("boundary")));
        let mut all = Vec::new();
        while let Some(c) = s.next().await { all.extend_from_slice(&c.unwrap()); }
        assert_eq!(all, b"abcd");
    }

    #[tokio::test]
    async fn fake_datagram_replays_then_times_out() {
        let addr: SocketAddr = "10.0.50.11:3702".parse().unwrap();
        let d = FakeDatagram::new(vec![(b"hello".to_vec(), addr)]);
        d.send_to(b"probe", addr).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = d.recv_from(&mut buf).await.unwrap();
        assert_eq!((&buf[..n], from), (&b"hello"[..], addr));
        assert!(matches!(d.recv_from(&mut buf).await, Err(NetError::Timeout)));
        assert_eq!(d.sent(), vec![(b"probe".to_vec(), addr)]);
    }
}
