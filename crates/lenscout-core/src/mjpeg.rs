//! Flux MJPEG pour le cadrage : découpe d'un `multipart/x-mixed-replace`
//! en images JPEG. Le parser ne panique jamais et ne garde jamais plus de
//! `MAX_FRAME_BYTES` d'une image en mémoire.

use bytes::Bytes;
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::model::{Camera, Family};
use crate::transport::{CameraHttp, Credentials, HttpRequest, Method, NetError};

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Au-delà, des en-têtes de partie sans ligne vide ne sont plus des en-têtes.
const MAX_HEADER_BYTES: usize = 8 * 1024;

enum State {
    /// Cherche le prochain délimiteur ; sert aussi de « saut » après une
    /// partie refusée (trop grande, en-têtes absurdes).
    Seeking,
    Headers,
    Body { len: Option<usize> },
}

pub struct MjpegParser {
    /// `--` + boundary.
    delim: Vec<u8>,
    buf: Vec<u8>,
    state: State,
    /// Octets de `buf` déjà fouillés sans succès (évite de rescanner une
    /// grosse image à chaque morceau reçu).
    scanned: usize,
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() || from > hay.len() - needle.len() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w == needle).map(|i| i + from)
}

/// `Content-Length` d'un bloc d'en-têtes. `Err` = présent mais illisible
/// (ou énorme) : la partie est refusée. `Ok(None)` = absent.
fn content_length(headers: &[u8]) -> Result<Option<usize>, ()> {
    for line in headers.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else { continue };
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            return v.trim().parse::<usize>().map(Some).map_err(|_| ());
        }
    }
    Ok(None)
}

impl MjpegParser {
    /// Le boundary se lit avec ou sans `--`, avec ou sans guillemets.
    pub fn from_content_type(ct: &str) -> Option<Self> {
        let lower = ct.to_ascii_lowercase();
        let start = lower.find("boundary=")? + "boundary=".len();
        let rest = &ct[start..];
        let value = rest.split(';').next()?.trim().trim_matches('"').trim();
        let value = value.strip_prefix("--").unwrap_or(value);
        if value.is_empty() {
            return None;
        }
        Some(Self {
            delim: format!("--{value}").into_bytes(),
            buf: Vec::new(),
            state: State::Seeking,
            scanned: 0,
        })
    }

    /// Rend les images JPEG complètes contenues dans ce que l'on a reçu
    /// jusqu'ici ; le reste attend le prochain morceau.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Bytes> {
        self.buf.extend_from_slice(chunk);
        let mut frames = Vec::new();
        loop {
            match self.state {
                State::Seeking => match find(&self.buf, &self.delim, self.scanned) {
                    Some(i) => {
                        self.buf.drain(..i + self.delim.len());
                        self.scanned = 0;
                        self.state = State::Headers;
                    }
                    None => {
                        // Garde de quoi reconnaître un délimiteur coupé en deux.
                        let keep = self.delim.len() - 1;
                        let drop = self.buf.len().saturating_sub(keep);
                        self.buf.drain(..drop);
                        self.scanned = 0;
                        break;
                    }
                },
                State::Headers => match find(&self.buf, b"\r\n\r\n", self.scanned.saturating_sub(3)) {
                    Some(i) => {
                        let parsed = content_length(&self.buf[..i]);
                        self.buf.drain(..i + 4);
                        self.scanned = 0;
                        self.state = match parsed {
                            Ok(Some(n)) if n > MAX_FRAME_BYTES => State::Seeking,
                            Ok(len) => State::Body { len },
                            Err(()) => State::Seeking,
                        };
                    }
                    None if self.buf.len() > MAX_HEADER_BYTES => {
                        self.state = State::Seeking;
                        self.scanned = 0;
                    }
                    None => {
                        self.scanned = self.buf.len();
                        break;
                    }
                },
                State::Body { len: Some(n) } => {
                    if self.buf.len() < n {
                        break;
                    }
                    if self.buf.starts_with(&[0xFF, 0xD8]) {
                        frames.push(Bytes::copy_from_slice(&self.buf[..n]));
                    }
                    self.buf.drain(..n);
                    self.state = State::Seeking;
                }
                State::Body { len: None } => match find(&self.buf, &self.delim, self.scanned) {
                    Some(i) => {
                        let mut part = &self.buf[..i];
                        if let Some(p) = part.strip_suffix(b"\r\n") {
                            part = p;
                        }
                        if part.len() <= MAX_FRAME_BYTES && part.starts_with(&[0xFF, 0xD8]) {
                            frames.push(Bytes::copy_from_slice(part));
                        }
                        // Le délimiteur reste : `Seeking` le consomme.
                        self.buf.drain(..i);
                        self.scanned = 0;
                        self.state = State::Seeking;
                    }
                    None if self.buf.len() > MAX_FRAME_BYTES + self.delim.len() + 2 => {
                        self.state = State::Seeking;
                        self.scanned = 0;
                    }
                    None => {
                        self.scanned = self.buf.len().saturating_sub(self.delim.len() - 1);
                        break;
                    }
                },
            }
        }
        frames
    }
}

/// Flux de cadrage : image réduite, pour que l'installateur oriente la
/// caméra sans saturer le réseau.
pub fn stream_url(cam: &Camera) -> Option<String> {
    let host = if cam.http_port == 80 {
        cam.ip.to_string()
    } else {
        format!("{}:{}", cam.ip, cam.http_port)
    };
    match cam.family {
        Family::Axis => Some(format!(
            "http://{host}/axis-cgi/mjpg/video.cgi?resolution=640x360&fps=10&compression=40"
        )),
        // NON VÉRIFIÉ sur une vraie caméra LTS — écrit d'après la documentation ISAPI.
        Family::Hikvision => Some(format!("http://{host}/ISAPI/Streaming/channels/102/httpPreview")),
        Family::Other => None,
    }
}

/// `Ok(())` à l'annulation ; `Err` si le flux se ferme ou si l'auth échoue.
pub async fn run_stream(
    http: &dyn CameraHttp,
    url: String,
    creds: &Credentials,
    cancel: CancellationToken,
    mut on_frame: impl FnMut(Bytes) + Send,
) -> Result<(), NetError> {
    let req = HttpRequest { method: Method::Get, url, body: None, content_type: None };
    let (resp, mut body) = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(()),
        r = http.stream(req, Some(creds)) => r?,
    };
    match resp.status {
        200 => {}
        401 | 403 => return Err(NetError::Auth),
        s => return Err(NetError::Status(s)),
    }
    let ct = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let mut parser = MjpegParser::from_content_type(ct)
        .ok_or_else(|| NetError::Io("flux non multipart".into()))?;
    loop {
        let item = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            item = body.next() => item,
        };
        match item {
            None => return Err(NetError::Io("flux fermé".into())),
            Some(Err(e)) => return Err(e),
            Some(Ok(chunk)) => {
                for frame in parser.push(&chunk) {
                    on_frame(frame);
                }
                if cancel.is_cancelled() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Activation, Family};
    use crate::secret::Secret;
    use crate::testing::FakeHttp;

    const CT: &str = "multipart/x-mixed-replace; boundary=myboundary";

    fn jpeg(n: usize) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend((0..n).map(|i| (i % 200) as u8 + 1));
        v.extend([0xFF, 0xD9]);
        v
    }

    fn multipart(boundary: &str, frames: &[Vec<u8>], with_length: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for f in frames {
            out.extend(format!("--{boundary}\r\nContent-Type: image/jpeg\r\n").as_bytes());
            if with_length {
                out.extend(format!("Content-Length: {}\r\n", f.len()).as_bytes());
            }
            out.extend(b"\r\n");
            out.extend(f);
            out.extend(b"\r\n");
        }
        out.extend(format!("--{boundary}--\r\n").as_bytes());
        out
    }

    fn push_all(data: &[u8]) -> Vec<Bytes> {
        MjpegParser::from_content_type(CT).unwrap().push(data)
    }

    fn frames3() -> Vec<Vec<u8>> {
        vec![jpeg(10), jpeg(300), jpeg(5)]
    }

    fn cam(family: Family) -> Camera {
        Camera {
            ip: "192.0.2.11".parse().unwrap(),
            mac: None,
            family,
            brand: None,
            model: None,
            serial: None,
            firmware: None,
            activation: Activation::Unknown,
            http_port: 80,
            sources: vec![],
        }
    }

    #[test]
    fn three_frames_with_content_length() {
        let out = push_all(&multipart("myboundary", &frames3(), true));
        assert_eq!(out.len(), 3);
        for (o, f) in out.iter().zip(frames3()) {
            assert_eq!(o.as_ref(), f.as_slice());
        }
    }

    #[test]
    fn three_frames_without_content_length_hikvision_style() {
        let out = push_all(&multipart("myboundary", &frames3(), false));
        assert_eq!(out.len(), 3);
        for (o, f) in out.iter().zip(frames3()) {
            assert_eq!(o.as_ref(), f.as_slice());
        }
    }

    #[test]
    fn any_chunking_gives_same_frames() {
        for with_length in [true, false] {
            let data = multipart("myboundary", &frames3(), with_length);
            for cut in 1..data.len() {
                let mut p = MjpegParser::from_content_type(CT).unwrap();
                let mut out = p.push(&data[..cut]);
                out.extend(p.push(&data[cut..]));
                assert_eq!(out.len(), 3, "cut={cut} with_length={with_length}");
                for (o, f) in out.iter().zip(frames3()) {
                    assert_eq!(o.as_ref(), f.as_slice());
                }
            }
        }
    }

    #[test]
    fn byte_by_byte_gives_same_frames() {
        let data = multipart("myboundary", &frames3(), false);
        let mut p = MjpegParser::from_content_type(CT).unwrap();
        let out: Vec<Bytes> = data.iter().flat_map(|b| p.push(&[*b])).collect();
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn garbage_before_first_boundary_is_skipped() {
        let mut data = b"HTTP junk \xFF\xD8 not a frame\r\n".to_vec();
        data.extend(multipart("myboundary", &frames3(), true));
        assert_eq!(push_all(&data).len(), 3);
    }

    #[test]
    fn missing_boundary_yields_nothing_and_does_not_grow() {
        let mut p = MjpegParser::from_content_type(CT).unwrap();
        for _ in 0..40 {
            assert!(p.push(&vec![0xAB; 1024 * 1024]).is_empty());
        }
        // Toujours utilisable ensuite.
        assert_eq!(p.push(&multipart("myboundary", &frames3(), true)).len(), 3);
    }

    #[test]
    fn truncated_frame_is_not_emitted() {
        let data = multipart("myboundary", &[jpeg(500)], true);
        assert!(push_all(&data[..data.len() - 60]).is_empty());
        let data = multipart("myboundary", &[jpeg(500)], false);
        assert!(push_all(&data[..data.len() - 60]).is_empty());
    }

    #[test]
    fn non_jpeg_parts_are_not_emitted() {
        let frames = vec![b"hello world".to_vec(), jpeg(8)];
        assert_eq!(push_all(&multipart("myboundary", &frames, true)).len(), 1);
        assert_eq!(push_all(&multipart("myboundary", &frames, false)).len(), 1);
    }

    #[test]
    fn oversized_part_is_dropped_and_parser_recovers() {
        for with_length in [true, false] {
            let mut p = MjpegParser::from_content_type(CT).unwrap();
            let mut data = multipart("myboundary", &[jpeg(MAX_FRAME_BYTES + 1)], with_length);
            data.truncate(data.len() - "--myboundary--\r\n".len());
            data.extend(multipart("myboundary", &[jpeg(20)], with_length));
            let mut out = Vec::new();
            for c in data.chunks(64 * 1024) {
                out.extend(p.push(c));
            }
            assert_eq!(out.len(), 1, "with_length={with_length}");
            assert_eq!(out[0].as_ref(), jpeg(20).as_slice());
        }
    }

    #[test]
    fn huge_content_length_is_refused_without_allocating() {
        let mut data = b"--myboundary\r\nContent-Length: 99999999999999999999\r\n\r\n".to_vec();
        data.extend(jpeg(10));
        data.extend(b"\r\n");
        data.extend(multipart("myboundary", &[jpeg(7)], true));
        let out = push_all(&data);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_ref(), jpeg(7).as_slice());
    }

    #[test]
    fn unterminated_headers_do_not_grow_unbounded() {
        let mut p = MjpegParser::from_content_type(CT).unwrap();
        p.push(b"--myboundary\r\n");
        for _ in 0..100 {
            assert!(p.push(&vec![b'a'; 4096]).is_empty());
        }
        assert_eq!(p.push(&multipart("myboundary", &[jpeg(3)], true)).len(), 1);
    }

    #[test]
    fn boundary_parsing_variants() {
        assert!(MjpegParser::from_content_type("multipart/x-mixed-replace;boundary=myboundary").is_some());
        assert!(MjpegParser::from_content_type("multipart/x-mixed-replace; boundary=\"--myboundary\"").is_some());
        assert!(MjpegParser::from_content_type("multipart/x-mixed-replace; BOUNDARY=--myboundary; x=y").is_some());
        assert!(MjpegParser::from_content_type("image/jpeg").is_none());
        assert!(MjpegParser::from_content_type("multipart/x-mixed-replace; boundary=").is_none());
        assert!(MjpegParser::from_content_type("").is_none());
        // Avec `--` dans l'en-tête, les images sortent quand même.
        let mut p = MjpegParser::from_content_type("multipart/x-mixed-replace; boundary=\"--myboundary\"").unwrap();
        assert_eq!(p.push(&multipart("myboundary", &frames3(), true)).len(), 3);
    }

    #[test]
    fn stream_url_by_family() {
        let u = stream_url(&cam(Family::Axis)).unwrap();
        assert!(u.contains("/axis-cgi/mjpg/video.cgi"));
        assert!(u.starts_with("http://192.0.2.11/"));
        assert!(stream_url(&cam(Family::Hikvision)).unwrap().contains("/ISAPI/Streaming/channels/102/httpPreview"));
        assert!(stream_url(&cam(Family::Other)).is_none());
        let mut c = cam(Family::Axis);
        c.http_port = 8080;
        assert!(stream_url(&c).unwrap().starts_with("http://192.0.2.11:8080/"));
    }

    fn creds() -> Credentials {
        Credentials { login: "root".into(), password: Secret::new("pw".into()) }
    }

    #[tokio::test]
    async fn run_stream_stops_on_cancel() {
        let data = multipart("myboundary", &frames3(), true);
        let http = FakeHttp::new().on_stream("/axis-cgi/mjpg", CT, vec![data]);
        let cancel = CancellationToken::new();
        let mut seen = 0;
        let c2 = cancel.clone();
        let r = run_stream(&http, "http://192.0.2.11/axis-cgi/mjpg/video.cgi".into(), &creds(), cancel, |_| {
            seen += 1;
            c2.cancel();
        })
        .await;
        assert!(r.is_ok());
        assert!(seen >= 1);
    }

    #[tokio::test]
    async fn run_stream_errors_when_stream_closes() {
        let data = multipart("myboundary", &frames3(), true);
        let http = FakeHttp::new().on_stream("/axis-cgi/mjpg", CT, vec![data]);
        let mut seen = 0;
        let r = run_stream(&http, "http://192.0.2.11/axis-cgi/mjpg/video.cgi".into(), &creds(), CancellationToken::new(), |_| seen += 1).await;
        assert!(r.is_err());
        assert_eq!(seen, 3);
    }

    #[tokio::test]
    async fn run_stream_rejects_non_multipart_and_bad_status() {
        let http = FakeHttp::new().on_stream("/a", "image/jpeg", vec![jpeg(5)]);
        let r = run_stream(&http, "http://192.0.2.11/a".into(), &creds(), CancellationToken::new(), |_| {}).await;
        assert!(matches!(r, Err(NetError::Io(_))));
        let http = FakeHttp::new().on(crate::transport::Method::Get, "/b", 401, "");
        let r = run_stream(&http, "http://192.0.2.11/b".into(), &creds(), CancellationToken::new(), |_| {}).await;
        assert!(matches!(r, Err(NetError::Auth)));
        let http = FakeHttp::new().on(crate::transport::Method::Get, "/c", 500, "");
        let r = run_stream(&http, "http://192.0.2.11/c".into(), &creds(), CancellationToken::new(), |_| {}).await;
        assert!(matches!(r, Err(NetError::Status(500))));
    }
}
