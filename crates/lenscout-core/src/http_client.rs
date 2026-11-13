//! Client HTTP réel des caméras : Digest et Basic, sans fuite du mot de passe.

use std::time::Duration;

use async_trait::async_trait;
use digest_auth::{AuthContext, HttpMethod, WwwAuthenticateHeader};
use futures_util::StreamExt;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, WWW_AUTHENTICATE};
use reqwest::{Client, Url};

use crate::debug_log;
use crate::transport::{
    ByteStream, CameraHttp, Credentials, HttpRequest, HttpResponse, Method, NetError,
};

/// Plafond du corps lu par `send()` : un appareil hostile ne doit pas pouvoir
/// remplir la mémoire.
const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, PartialEq)]
enum AuthChoice<'a> {
    Digest(&'a str),
    Basic,
    RefuseBasic,
    None,
}

/// Jeton de schéma d'un défi, comparé exactement et sans tenir compte de la
/// casse (`DigestX` n'est pas `Digest`).
fn has_scheme(challenge: &str, scheme: &str) -> bool {
    challenge
        .split_whitespace()
        .next()
        .is_some_and(|t| t.eq_ignore_ascii_case(scheme))
}

/// Digest l'emporte ; Basic n'est accepté qu'en HTTPS, sinon un faux appareil
/// du LAN récupérerait en clair le mot de passe du compte.
fn choose_auth<'a>(https: bool, challenges: &[&'a str]) -> AuthChoice<'a> {
    if let Some(d) = challenges.iter().find(|c| has_scheme(c, "digest")) {
        return AuthChoice::Digest(d);
    }
    if challenges.iter().any(|c| has_scheme(c, "basic")) {
        return if https {
            AuthChoice::Basic
        } else {
            AuthChoice::RefuseBasic
        };
    }
    AuthChoice::None
}

pub struct ReqwestCameraHttp {
    client: Client,
    timeout: Duration,
}

impl ReqwestCameraHttp {
    /// `timeout` borne la connexion et chaque attente de données, pas la durée
    /// totale : un flux MJPEG doit pouvoir durer.
    pub fn new(timeout: Duration) -> Self {
        let client = Client::builder()
            .connect_timeout(timeout)
            .read_timeout(timeout)
            // Pas de redirection : l'en-tête d'authentification ne doit pas
            // suivre une caméra vers un autre hôte.
            .redirect(reqwest::redirect::Policy::none())
            // Une caméra neuve sert son HTTPS avec un certificat auto-signé :
            // il n'existe aucune autorité à laquelle la rattacher.
            .danger_accept_invalid_certs(true)
            // Jamais de proxy : les variables HTTP(S)_PROXY du poste ne doivent
            // voir passer ni le trafic des caméras ni leurs réponses Digest.
            .no_proxy()
            .build()
            .expect("client HTTP");
        Self { client, timeout }
    }

    fn build(
        &self,
        req: &HttpRequest,
        authorization: Option<HeaderValue>,
    ) -> Result<reqwest::RequestBuilder, NetError> {
        let method = match req.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Put => reqwest::Method::PUT,
        };
        let mut b = self.client.request(method, &req.url);
        if let Some(ct) = &req.content_type {
            b = b.header(CONTENT_TYPE, ct);
        }
        if let Some(body) = &req.body {
            b = b.body(body.clone());
        }
        if let Some(mut v) = authorization {
            v.set_sensitive(true);
            b = b.header(AUTHORIZATION, v);
        }
        Ok(b)
    }

    /// Ouvre et referme une connexion TCP avant la requête. reqwest ne sait
    /// pas dire si un délai est tombé pendant la connexion ou pendant la
    /// lecture (même erreur `TimedOut`) ; or « rien n'est parti » (`Unreachable`)
    /// et « la requête est partie, la caméra se tait » (`Timeout`) n'ont pas le
    /// même sens pour `vapix::set_network`.
    async fn check_connect(&self, url: &str) -> Result<(), NetError> {
        let unreachable = || NetError::Unreachable("connexion impossible".into());
        let Ok(url) = Url::parse(url) else {
            return Ok(());
        };
        let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
            return Ok(());
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        match tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect((host, port))).await
        {
            Ok(Ok(_)) => Ok(()),
            _ => Err(unreachable()),
        }
    }

    /// Requête sans `Authorization`, puis, sur 401, une seule relance avec la
    /// réponse au défi. Un second 401 est un refus d'authentification.
    async fn execute(
        &self,
        req: &HttpRequest,
        creds: Option<&Credentials>,
    ) -> Result<reqwest::Response, NetError> {
        self.check_connect(&req.url).await?;
        let first = self.build(req, None)?.send().await.map_err(map_err)?;
        if first.status().as_u16() != 401 {
            return Ok(first);
        }
        let Some(creds) = creds else {
            return Err(NetError::Auth);
        };
        let auth = answer_challenge(&first, req, creds)?;
        let second = self.build(req, Some(auth))?.send().await.map_err(map_err)?;
        if second.status().as_u16() == 401 {
            return Err(NetError::Auth);
        }
        Ok(second)
    }
}

/// Calcule l'en-tête `Authorization` selon `choose_auth`.
fn answer_challenge(
    resp: &reqwest::Response,
    req: &HttpRequest,
    creds: &Credentials,
) -> Result<HeaderValue, NetError> {
    let challenges: Vec<&str> = resp
        .headers()
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let url = Url::parse(&req.url).map_err(|_| NetError::Io("URL invalide".into()))?;
    let header = match choose_auth(url.scheme() == "https", &challenges) {
        AuthChoice::Digest(digest) => {
            let uri = match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_string(),
            };
            let mut prompt = WwwAuthenticateHeader::parse(digest).map_err(|_| NetError::Auth)?;
            let method = match req.method {
                Method::Get => HttpMethod::GET,
                Method::Post => HttpMethod::POST,
                Method::Put => HttpMethod::PUT,
            };
            let ctx = AuthContext::new_with_method(
                creds.login.as_str(),
                creds.password.expose(),
                uri,
                req.body.as_deref(),
                method,
            );
            let answer = prompt.respond(&ctx).map_err(|_| NetError::Auth)?;
            answer.to_header_string()
        }
        AuthChoice::Basic => {
            use base64::Engine;
            let raw = format!("{}:{}", creds.login, creds.password.expose());
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(raw)
            )
        }
        AuthChoice::RefuseBasic => return Err(NetError::InsecureBasic),
        AuthChoice::None => return Err(NetError::Auth),
    };
    HeaderValue::from_str(&header).map_err(|_| NetError::Auth)
}

/// Le message n'est jamais celui de reqwest tel quel : il embarque l'URL.
fn map_err(e: reqwest::Error) -> NetError {
    // Une connexion qui échoue, délai compris, n'a rien envoyé : `Unreachable`.
    // Seul un délai de lecture (requête déjà partie) est un `Timeout`.
    if e.is_connect() {
        NetError::Unreachable("connexion impossible".into())
    } else if e.is_timeout() {
        NetError::Timeout
    } else {
        NetError::Io(e.without_url().to_string())
    }
}

fn head(resp: &reqwest::Response) -> HttpResponse {
    HttpResponse {
        status: resp.status().as_u16(),
        headers: resp
            .headers()
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
            .collect(),
        body: Vec::new(),
    }
}

impl ReqwestCameraHttp {
    async fn send_inner(&self, req: &HttpRequest, creds: Option<&Credentials>) -> Result<HttpResponse, NetError> {
        let mut resp = self.execute(req, creds).await?;
        let mut out = head(&resp);
        // Lecture par morceaux : on s'arrête dès que le plafond est franchi.
        while let Some(chunk) = resp.chunk().await.map_err(map_err)? {
            if out.body.len() + chunk.len() > MAX_BODY {
                return Err(NetError::Io("réponse trop volumineuse".into()));
            }
            out.body.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// Chaque réponse (ou échec) passe au journal de mise au point, s'il est
/// actif : jamais le corps de la requête ni un en-tête.
#[async_trait]
impl CameraHttp for ReqwestCameraHttp {
    async fn send(
        &self,
        req: HttpRequest,
        creds: Option<&Credentials>,
    ) -> Result<HttpResponse, NetError> {
        let r = self.send_inner(&req, creds).await;
        match &r {
            Ok(resp) => debug_log::response(&req, resp),
            Err(e) => debug_log::failure(&req, e),
        }
        r
    }

    async fn stream(
        &self,
        req: HttpRequest,
        creds: Option<&Credentials>,
    ) -> Result<(HttpResponse, ByteStream), NetError> {
        let resp = match self.execute(&req, creds).await {
            Ok(r) => r,
            Err(e) => {
                debug_log::failure(&req, &e);
                return Err(e);
            }
        };
        let out = head(&resp);
        debug_log::response(&req, &out);
        let stream: ByteStream = Box::pin(resp.bytes_stream().map(|c| c.map_err(map_err)));
        Ok((out, stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use crate::transport::Method;
    use digest_auth::{AuthContext, AuthorizationHeader, WwwAuthenticateHeader};
    use futures_util::StreamExt;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const PASSWORD: &str = "S3cr3t-Unique!";
    const CHALLENGE: &str = "Digest realm=\"AXIS_ACCC8E123456\", nonce=\"abc\", qop=\"auth\"";

    /// Faux serveur HTTP : `handler(n° de requête, requête brute)` rend les
    /// octets de la réponse ; la connexion est fermée après chaque réponse.
    struct TestServer {
        port: u16,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl TestServer {
        async fn start<F>(handler: F) -> Self
        where
            F: Fn(usize, &str) -> Vec<u8> + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let seen = requests.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 2048];
                    while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => raw.extend_from_slice(&buf[..n]),
                        }
                    }
                    if raw.is_empty() {
                        // Simple test de connexion (`check_connect`), pas une requête.
                        continue;
                    }
                    let text = String::from_utf8_lossy(&raw).into_owned();
                    let n = {
                        let mut g = seen.lock().unwrap();
                        g.push(text.clone());
                        g.len()
                    };
                    let _ = sock.write_all(&handler(n, &text)).await;
                    let _ = sock.shutdown().await;
                }
            });
            Self { port, requests }
        }

        fn url(&self, path: &str) -> String {
            format!("http://127.0.0.1:{}{path}", self.port)
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    fn response(status: &str, extra: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn header_value(raw: &str, name: &str) -> Option<String> {
        raw.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }

    /// Vérifie l'en-tête Digest reçu en recalculant la réponse attendue.
    fn digest_ok(raw: &str, password: &str) -> bool {
        let Some(auth) = header_value(raw, "authorization") else {
            return false;
        };
        let Ok(got) = AuthorizationHeader::parse(&auth) else {
            return false;
        };
        let mut prompt = WwwAuthenticateHeader::parse(CHALLENGE).unwrap();
        let mut ctx = AuthContext::new(got.username.clone(), password, got.uri.clone());
        ctx.set_custom_cnonce(got.cnonce.clone().unwrap_or_default());
        let want = prompt.respond(&ctx).unwrap();
        want.response == got.response && got.nc == 1 && got.uri == "/axis-cgi/x.cgi?a=1"
    }

    fn digest_server(expected_password: &'static str) -> impl Fn(usize, &str) -> Vec<u8> {
        move |_, raw| {
            if digest_ok(raw, expected_password) {
                response("200 OK", "", "OK")
            } else {
                response(
                    "401 Unauthorized",
                    &format!("WWW-Authenticate: {CHALLENGE}\r\n"),
                    "",
                )
            }
        }
    }

    fn get(url: String) -> HttpRequest {
        HttpRequest {
            method: Method::Get,
            url,
            body: None,
            content_type: None,
        }
    }

    fn creds(login: &str, password: &str) -> Credentials {
        Credentials {
            login: login.into(),
            password: Secret::new(password.into()),
        }
    }

    fn client() -> ReqwestCameraHttp {
        ReqwestCameraHttp::new(Duration::from_millis(500))
    }

    #[tokio::test]
    async fn digest_challenge_is_answered_once() {
        let server = TestServer::start(digest_server(PASSWORD)).await;
        let r = client()
            .send(
                get(server.url("/axis-cgi/x.cgi?a=1")),
                Some(&creds("root", PASSWORD)),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"OK");
        assert_eq!(server.request_count(), 2);
    }

    #[tokio::test]
    async fn wrong_password_gives_auth_error_after_one_retry() {
        let server = TestServer::start(digest_server(PASSWORD)).await;
        let err = client()
            .send(
                get(server.url("/axis-cgi/x.cgi?a=1")),
                Some(&creds("root", "mauvais")),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::Auth), "{err:?}");
        assert_eq!(server.request_count(), 2);
    }

    #[tokio::test]
    async fn no_challenge_no_credentials_sent() {
        let server = TestServer::start(|_, _| response("200 OK", "", "OK")).await;
        let r = client()
            .send(get(server.url("/")), Some(&creds("root", PASSWORD)))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(server.request_count(), 1);
        assert!(
            server
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|q| !q.to_lowercase().contains("authorization"))
        );
    }

    #[tokio::test]
    async fn basic_challenge_over_http_is_refused_without_replay() {
        let server = TestServer::start(|_, _| {
            response(
                "401 Unauthorized",
                "WWW-Authenticate: Basic realm=\"cam\"\r\n",
                "",
            )
        })
        .await;
        let err = client()
            .send(get(server.url("/")), Some(&creds("root", PASSWORD)))
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::InsecureBasic), "{err:?}");
        assert_eq!(server.request_count(), 1);
        assert!(
            !server.requests.lock().unwrap()[0]
                .to_lowercase()
                .contains("authorization")
        );
    }

    #[tokio::test]
    async fn challenge_without_credentials_is_auth_error() {
        let server = TestServer::start(digest_server(PASSWORD)).await;
        let err = client().send(get(server.url("/")), None).await.unwrap_err();
        assert!(matches!(err, NetError::Auth), "{err:?}");
        assert_eq!(server.request_count(), 1);
    }

    /// Une connexion qui échoue (délai compris) n'a rien envoyé : c'est
    /// `Unreachable`, jamais `Timeout`, que `vapix::set_network` lirait
    /// comme « la caméra a changé d'adresse ». 192.0.2.0/24 (TEST-NET-1)
    /// n'est routée nulle part.
    #[tokio::test]
    async fn connect_failure_is_unreachable_not_timeout() {
        let http = ReqwestCameraHttp::new(Duration::from_millis(300));
        let err = http
            .send(get("http://192.0.2.1/".into()), None)
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::Unreachable(_)), "{err:?}");
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let server =
            TestServer::start(|_, _| response("200 OK", "", &"x".repeat(MAX_BODY + 1))).await;
        let err = client().send(get(server.url("/")), None).await.unwrap_err();
        assert!(matches!(err, NetError::Io(_)), "{err:?}");
    }

    #[test]
    fn auth_choice_rules() {
        let basic = ["Basic realm=\"c\""];
        let digest = ["basic realm=\"c\"", "DIGEST realm=\"c\", nonce=\"n\""];
        assert_eq!(choose_auth(true, &basic), AuthChoice::Basic);
        assert_eq!(choose_auth(false, &basic), AuthChoice::RefuseBasic);
        assert_eq!(
            choose_auth(false, &digest),
            AuthChoice::Digest("DIGEST realm=\"c\", nonce=\"n\"")
        );
        assert_eq!(
            choose_auth(true, &digest),
            AuthChoice::Digest("DIGEST realm=\"c\", nonce=\"n\"")
        );
        assert_eq!(
            choose_auth(true, &["DigestX realm=\"c\""]),
            AuthChoice::None
        );
        assert_eq!(choose_auth(true, &[]), AuthChoice::None);
    }

    #[tokio::test]
    async fn post_body_is_replayed_after_challenge() {
        let server = TestServer::start(|_, raw| {
            if header_value(raw, "authorization").is_some() {
                response("200 OK", "", "OK")
            } else {
                response(
                    "401 Unauthorized",
                    &format!("WWW-Authenticate: {CHALLENGE}\r\n"),
                    "",
                )
            }
        })
        .await;
        let req = HttpRequest {
            method: Method::Post,
            url: server.url("/axis-cgi/x.cgi?a=1"),
            body: Some(b"pwd=1".to_vec()),
            content_type: Some("application/x-www-form-urlencoded".into()),
        };
        let r = client()
            .send(req, Some(&creds("root", PASSWORD)))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(server.request_count(), 2);
    }

    #[tokio::test]
    async fn closed_port_is_unreachable() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let err = client()
            .send(
                get(format!("http://127.0.0.1:{port}/")),
                Some(&creds("root", PASSWORD)),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::Unreachable(_)), "{err:?}");
    }

    #[tokio::test]
    async fn silent_server_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _hold = tokio::spawn(async move {
            let _conn = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let err = ReqwestCameraHttp::new(Duration::from_millis(200))
            .send(get(format!("http://127.0.0.1:{port}/")), None)
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::Timeout), "{err:?}");
    }

    #[tokio::test]
    async fn errors_never_contain_password() {
        // Auth
        let server = TestServer::start(digest_server("autre")).await;
        let c = creds("root", PASSWORD);
        let e_auth = client()
            .send(get(server.url("/axis-cgi/x.cgi?a=1")), Some(&c))
            .await
            .unwrap_err();
        // Unreachable
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let e_unreach = client()
            .send(get(format!("http://127.0.0.1:{port}/")), Some(&c))
            .await
            .unwrap_err();
        // Timeout
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tport = listener.local_addr().unwrap().port();
        let _hold = tokio::spawn(async move {
            let _conn = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let e_timeout = ReqwestCameraHttp::new(Duration::from_millis(200))
            .send(get(format!("http://127.0.0.1:{tport}/")), Some(&c))
            .await
            .unwrap_err();
        assert!(matches!(e_auth, NetError::Auth));
        assert!(matches!(e_unreach, NetError::Unreachable(_)));
        assert!(matches!(e_timeout, NetError::Timeout));
        for e in [e_auth, e_unreach, e_timeout] {
            assert!(!format!("{e:?} {e}").contains("S3cr3t"));
        }
    }

    #[tokio::test]
    async fn stream_yields_body_chunks() {
        let server = TestServer::start(|_, raw| {
            if digest_ok(raw, PASSWORD) {
                let mut out =
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        .to_vec();
                for part in ["aaa", "bbb", "ccc"] {
                    out.extend_from_slice(format!("{:x}\r\n{part}\r\n", part.len()).as_bytes());
                }
                out.extend_from_slice(b"0\r\n\r\n");
                out
            } else {
                response(
                    "401 Unauthorized",
                    &format!("WWW-Authenticate: {CHALLENGE}\r\n"),
                    "",
                )
            }
        })
        .await;
        let (head, mut stream) = client()
            .stream(
                get(server.url("/axis-cgi/x.cgi?a=1")),
                Some(&creds("root", PASSWORD)),
            )
            .await
            .unwrap();
        assert_eq!(head.status, 200);
        assert!(head.body.is_empty());
        let mut all = Vec::new();
        while let Some(chunk) = stream.next().await {
            all.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(all, b"aaabbbccc");
        assert_eq!(server.request_count(), 2);
    }
}
