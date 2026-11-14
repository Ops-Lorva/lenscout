//! Journal de mise au point, pour un essai sur le terrain.
//!
//! Actif si `LENSCOUT_DEBUG=1`, ou si un fichier `debug` existe dans le
//! dossier de données de l'app (`app_data_dir`) : un lancement depuis le
//! Finder ne passe aucune variable d'environnement.
//!
//! Chaque réponse d'une caméra (VAPIX, flux) y laisse une ligne : méthode,
//! hôte et chemin, statut, Content-Type et les 300 premiers octets du corps.
//! Jamais un corps de requête ni un en-tête (ni `Authorization`, ni les
//! autres) ; la query de `pwdgrp.cgi` est retirée par principe (c'est le CGI
//! des comptes), les autres n'en portent aucun secret (`param.cgi?action=list`,
//! `video.cgi?resolution=`).
//!
//! Fichier `<app_data_dir>/lenscout-debug.log`, plafonné à 5 Mo : au-delà il
//! devient `lenscout-debug.log.1` (l'ancien `.1` est remplacé). Les captures
//! de découverte vont dans `<app_data_dir>/captures` quand
//! `LENSCOUT_CAPTURE_DIR` n'est pas défini ; plafonnées elles aussi
//! (`CAPTURE_MAX_FILES` fichiers ou `CAPTURE_MAX_BYTES`, au premier atteint),
//! après quoi plus rien n'y est écrit.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::transport::{HttpRequest, HttpResponse, Method, NetError};

pub const FILE: &str = "lenscout-debug.log";
/// Présence de ce fichier dans `app_data_dir` : journal actif.
pub const SWITCH: &str = "debug";
pub const MAX_BYTES: u64 = 5 * 1024 * 1024;
/// Plafonds du dossier des captures de découverte, au premier atteint.
pub const CAPTURE_MAX_FILES: usize = 1000;
pub const CAPTURE_MAX_BYTES: u64 = 20 * 1024 * 1024;
const BODY_PREVIEW: usize = 300;

/// `LENSCOUT_DEBUG=1`, ou un fichier `debug` dans `data_dir`.
pub fn enabled(env: Option<&OsStr>, data_dir: &Path) -> bool {
    env.is_some_and(|v| v == "1") || data_dir.join(SWITCH).exists()
}

/// Pose ou retire le fichier `debug` (la case « Journal de diagnostic » des
/// Réglages). Idempotent : il n'y a rien à faire si l'état est déjà le bon.
pub fn set_switch(data_dir: &Path, on: bool) -> std::io::Result<()> {
    let path = data_dir.join(SWITCH);
    if on {
        std::fs::create_dir_all(data_dir)?;
        File::create(path).map(drop)
    } else {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// Fichier à taille bornée : passé `cap` octets, l'actuel devient `.1`.
pub struct DebugLog {
    path: PathBuf,
    cap: u64,
    file: Option<File>,
    len: u64,
}

impl DebugLog {
    pub fn new(path: PathBuf, cap: u64) -> Self {
        DebugLog { path, cap, file: None, len: 0 }
    }

    fn rotated(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".1");
        self.path.with_file_name(name)
    }

    /// Ajoute une ligne. Une erreur d'écriture est ignorée : le journal ne
    /// doit jamais gêner l'app.
    pub fn line(&mut self, text: &str) {
        let line = format!("{} {text}\n", unix_seconds());
        if self.file.is_none() {
            self.file = OpenOptions::new().create(true).append(true).open(&self.path).ok();
            self.len = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        }
        if self.len > 0 && self.len + line.len() as u64 > self.cap {
            self.file = None;
            let _ = std::fs::rename(&self.path, self.rotated());
            self.file = OpenOptions::new().create(true).append(true).truncate(false).open(&self.path).ok();
            self.len = 0;
        }
        if let Some(f) = self.file.as_mut()
            && f.write_all(line.as_bytes()).is_ok()
        {
            self.len += line.len() as u64;
        }
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// État global : posé une fois au démarrage de l'app, s'il est actif.
struct Diagnostics {
    log: DebugLog,
    captures: PathBuf,
}

static DIAG: Mutex<Option<Diagnostics>> = Mutex::new(None);

/// Active le journal dans `data_dir` (à appeler si `enabled`).
pub fn install(data_dir: &Path) {
    let _ = std::fs::create_dir_all(data_dir);
    let diag = Diagnostics { log: DebugLog::new(data_dir.join(FILE), MAX_BYTES), captures: data_dir.join("captures") };
    if let Ok(mut d) = DIAG.lock() {
        *d = Some(diag);
    }
}

/// Arrête le journal (case décochée dans les Réglages). Le fichier reste ;
/// `is_on` et `capture_dir` lisent l'état à chaque appel, l'effet est immédiat.
pub fn uninstall() {
    if let Ok(mut d) = DIAG.lock() {
        *d = None;
    }
}

/// Dossier des captures de découverte, si le journal est actif.
pub fn capture_dir() -> Option<PathBuf> {
    DIAG.lock().ok()?.as_ref().map(|d| d.captures.clone())
}

/// Une ligne au journal, s'il est actif ; aussi sur stderr sous
/// `LENSCOUT_DEBUG` (lancement depuis un terminal).
pub fn log(text: &str) {
    if std::env::var_os("LENSCOUT_DEBUG").is_some() {
        eprintln!("{text}");
    }
    if let Ok(mut d) = DIAG.lock()
        && let Some(d) = d.as_mut()
    {
        d.log.line(text);
    }
}

fn is_on() -> bool {
    DIAG.lock().is_ok_and(|d| d.is_some())
}

fn method_name(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
    }
}

/// Hôte et chemin d'une URL ; la query n'est gardée que hors `pwdgrp.cgi`.
fn host_and_path(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let rest = rest.split('#').next().unwrap_or("");
    let (before, query) = match rest.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (rest, None),
    };
    // Jamais d'identifiants d'URL (`user:pass@hôte`).
    let before = match before.split_once('/') {
        Some((auth, path)) => format!("{}/{path}", auth.rsplit_once('@').map_or(auth, |(_, h)| h)),
        None => before.rsplit_once('@').map_or(before, |(_, h)| h).to_string(),
    };
    match query {
        Some(q) if !before.ends_with("pwdgrp.cgi") => format!("{before}?{q}"),
        _ => before,
    }
}

/// La ligne d'une réponse : rien de la requête hormis méthode et chemin.
pub fn response_line(req: &HttpRequest, resp: &HttpResponse) -> String {
    let ct = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map_or("-", |(_, v)| v.as_str());
    let body = &resp.body[..resp.body.len().min(BODY_PREVIEW)];
    format!(
        "[http] {} {} -> {} {ct} {:?}",
        method_name(req.method),
        host_and_path(&req.url),
        resp.status,
        String::from_utf8_lossy(body)
    )
}

/// Réponse reçue (le corps peut être vide pour un flux).
pub fn response(req: &HttpRequest, resp: &HttpResponse) {
    if is_on() {
        log(&response_line(req, resp));
    }
}

/// Échec avant toute réponse. `NetError` ne porte jamais l'URL ni un secret.
pub fn failure(req: &HttpRequest, e: &NetError) {
    if is_on() {
        log(&format!("[http] {} {} -> {e}", method_name(req.method), host_and_path(&req.url)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> crate::testing::TmpDir {
        crate::testing::TmpDir::new("lenscout-debug")
    }

    fn req(method: Method, url: &str, body: &str) -> HttpRequest {
        HttpRequest { method, url: url.into(), body: Some(body.as_bytes().to_vec()), content_type: None }
    }

    fn resp(status: u16, ct: &str, body: &[u8]) -> HttpResponse {
        HttpResponse { status, headers: vec![("Content-Type".into(), ct.into())], body: body.to_vec() }
    }

    #[test]
    fn enabled_by_the_variable_or_a_file_in_the_data_dir() {
        let dir = tmp();
        assert!(!enabled(None, &dir));
        assert!(!enabled(Some(OsStr::new("0")), &dir));
        assert!(enabled(Some(OsStr::new("1")), &dir));
        std::fs::write(dir.join("debug"), "").unwrap();
        assert!(enabled(None, &dir));
    }

    #[test]
    fn a_response_line_has_method_path_status_type_and_300_bytes_never_the_request_body() {
        let r = req(Method::Post, "http://192.0.2.11/axis-cgi/basicdeviceinfo.cgi", "SECRET-BODY");
        let long = vec![b'a'; 1000];
        let line = response_line(&r, &resp(200, "application/json", &long));
        assert!(line.contains("POST 192.0.2.11/axis-cgi/basicdeviceinfo.cgi -> 200 application/json"), "{line}");
        assert!(line.contains(&"a".repeat(300)));
        assert!(!line.contains(&"a".repeat(301)));
        assert!(!line.contains("SECRET-BODY"));
    }

    #[test]
    fn the_pwdgrp_query_and_url_credentials_are_never_logged() {
        let r = req(Method::Get, "http://root:pw@192.0.2.11/axis-cgi/pwdgrp.cgi?action=get&pwd=x", "");
        let line = response_line(&r, &resp(401, "text/html", b""));
        assert!(line.contains("GET 192.0.2.11/axis-cgi/pwdgrp.cgi -> 401"), "{line}");
        assert!(!line.contains("action=") && !line.contains("pwd=x") && !line.contains("root:pw"), "{line}");
        let p = req(Method::Get, "http://192.0.2.11/axis-cgi/param.cgi?action=list&group=Properties.System.SerialNumber", "");
        assert!(response_line(&p, &resp(200, "text/plain", b"")).contains("param.cgi?action=list&group="));
    }

    #[test]
    fn the_switch_file_is_created_and_removed_and_decides_enabled() {
        let base = tmp();
        let dir = base.join("sous-dossier-absent");
        set_switch(&dir, true).unwrap();
        assert!(dir.join(SWITCH).is_file());
        assert!(enabled(None, &dir));
        // Deux fois de suite : pas d'erreur.
        set_switch(&dir, true).unwrap();
        set_switch(&dir, false).unwrap();
        assert!(!dir.join(SWITCH).exists());
        assert!(!enabled(None, &dir));
        set_switch(&dir, false).unwrap();
    }

    #[test]
    fn install_then_uninstall_switches_logging_at_runtime() {
        let dir = tmp();
        install(&dir);
        assert!(capture_dir().is_some());
        log("[test] une ligne");
        assert!(std::fs::read_to_string(dir.join(FILE)).unwrap().contains("[test] une ligne"));
        uninstall();
        assert!(capture_dir().is_none());
        log("[test] après arrêt");
        assert!(!std::fs::read_to_string(dir.join(FILE)).unwrap().contains("après arrêt"));
    }

    #[test]
    fn the_file_is_capped_and_rotated() {
        let dir = tmp();
        let mut log = DebugLog::new(dir.join(FILE), 200);
        for i in 0..50 {
            log.line(&format!("ligne {i}"));
        }
        let cur = std::fs::metadata(dir.join(FILE)).unwrap().len();
        let old = std::fs::metadata(dir.join(format!("{FILE}.1"))).unwrap().len();
        assert!(cur <= 200 && old <= 200, "{cur} {old}");
        assert!(std::fs::read_to_string(dir.join(FILE)).unwrap().contains("ligne 49"));
    }
}
