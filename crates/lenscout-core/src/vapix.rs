//! Client VAPIX (Axis). Tout passe par `CameraHttp` : aucun réseau ici.
//!
//! Sources (VAPIX Library, https://developer.axis.com/vapix/, lue le 2026-11-13) :
//! - Basic device information : `/axis-cgi/basicdeviceinfo.cgi`,
//!   `getAllUnrestrictedProperties` (sécurité « Anonymous », AXIS OS 8.40+) ;
//!   champs `Brand`, `ProdFullName`, `ProdNbr`, `ProdShortName`,
//!   `SerialNumber`, `Version`.
//! - Systemready API : `/axis-cgi/systemready.cgi`, anonyme, AXIS OS 9.50+ ;
//!   `data.needsetup = "yes"` : « an initial admin user must first be created
//!   using /axis-cgi/pwdgrp.cgi ». C'est le test documenté « caméra neuve ».
//! - System settings, `pwdgrp.cgi` : `action=add&user=&pwd=&grp=&sgrp=`. Le
//!   premier compte : `grp=root`, `sgrp=admin:operator:viewer:ptz`, sans
//!   authentification, une seule fois ; avant AXIS OS 11.5 le nom doit être
//!   `root` ; nom de 1 à 14 caractères `[A-Za-z0-9]`, mot de passe de 1 à 64
//!   caractères conforme à la politique de la caméra. La doc recommande de
//!   passer les arguments dans le corps (POST), pas dans l'URL.
//! - Network settings (`param.cgi`) : `Network.BootProto` (`dhcp`|`none`),
//!   `Network.IPAddress`, `Network.SubnetMask`, `Network.DefaultRouter`,
//!   `Network.DNSServer1`, `Network.DNSServer2`. `param.cgi?action=update`
//!   répond `OK`, ou `# Error: Error setting '<nom>' to '<valeur>'!` avec un
//!   statut 200.
//! - Time API : `/axis-cgi/time.cgi`, `setTimeZone` avec un nom IANA
//!   (AXIS OS 9.30+, rôle Operator).
//! - NTP API : `/axis-cgi/ntp.cgi`, `setNTPClientConfiguration` (AXIS OS
//!   9.10+, Administrator) ; déclarée obsolète depuis AXIS OS 12.11.
//! - Repli `param.cgi` : `Time.SyncSource` (`PC`|`NTP`|`None`),
//!   `Time.NTP.Server`, `Time.ObtainFromDHCP`.
//!
//! Les API JSON répondent 200 même en échec, avec un objet `error`.

use std::net::Ipv4Addr;

use serde_json::{Value, json};

use crate::model::Activation;
use crate::transport::{CameraHttp, Credentials, HttpRequest, HttpResponse, Method, NetError};

const FORM: &str = "application/x-www-form-urlencoded";
const JSON: &str = "application/json";

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceInfo {
    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware: Option<String>,
    pub brand: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkSettings {
    Dhcp,
    Static {
        ip: Ipv4Addr,
        mask: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        dns: Vec<Ipv4Addr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct TimeSettings {
    pub ntp_servers: Vec<String>,
    /// Nom IANA, p. ex. `Europe/Paris`.
    pub timezone: String,
}

#[derive(thiserror::Error, Debug)]
pub enum VapixError {
    #[error("{0}")]
    Net(#[from] NetError),
    #[error("refusé par la caméra : {0}")]
    Rejected(String),
    #[error("réponse illisible : {0}")]
    Parse(String),
}

/// `base` est `http://hôte[:port]`, avec ou sans barre finale.
fn url(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

fn post(base: &str, path: &str, content_type: &str, body: String) -> HttpRequest {
    HttpRequest {
        method: Method::Post,
        url: url(base, path),
        body: Some(body.into_bytes()),
        content_type: Some(content_type.to_string()),
    }
}

fn json_post(base: &str, path: &str, body: Value) -> HttpRequest {
    post(base, path, JSON, body.to_string())
}

/// Encodage pour une valeur de formulaire : tout sauf les caractères non
/// réservés de la RFC 3986 est échappé (`a&b=c` → `a%26b%3Dc`).
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Journal de mise au point : le statut brut seulement, jamais de corps ni de
/// secret. Actif avec `LENSCOUT_DEBUG` dans l'environnement.
fn debug(msg: &str) {
    if std::env::var_os("LENSCOUT_DEBUG").is_some() {
        eprintln!("[vapix] {msg}");
    }
}

fn require_success(resp: &HttpResponse) -> Result<(), VapixError> {
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(NetError::Status(resp.status).into())
    }
}

/// Première ligne d'un message de la caméra, bornée : sert aux erreurs
/// affichées. La caméra ne renvoie jamais le mot de passe.
fn short(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

/// CGI texte (`pwdgrp.cgi`, `param.cgi`) : un échec est un 200 dont le corps
/// contient `Error` (`# Error: …` / `Error: …`).
fn require_text_ok(resp: &HttpResponse) -> Result<(), VapixError> {
    require_success(resp)?;
    let body = String::from_utf8_lossy(&resp.body);
    // Seule une ligne qui commence par `# Error` (param.cgi) ou `Error`
    // (pwdgrp.cgi, « Error: invalid password. ») est un échec.
    let failed = body
        .lines()
        .map(str::trim_start)
        .any(|l| l.starts_with("# Error") || l.starts_with("Error"));
    if failed {
        return Err(VapixError::Rejected(short(&body)));
    }
    Ok(())
}

/// API JSON : un échec est un 200 avec `"error": {code, message}`.
fn parse_json_reply(resp: &HttpResponse) -> Result<Value, VapixError> {
    require_success(resp)?;
    let v: Value =
        serde_json::from_slice(&resp.body).map_err(|e| VapixError::Parse(e.to_string()))?;
    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("erreur inconnue");
        return Err(VapixError::Rejected(short(msg)));
    }
    Ok(v)
}

fn text(props: &Value, key: &str) -> Option<String> {
    props
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub fn parse_basic_device_info(json: &[u8]) -> Result<DeviceInfo, VapixError> {
    let v: Value = serde_json::from_slice(json).map_err(|e| VapixError::Parse(e.to_string()))?;
    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("erreur inconnue");
        return Err(VapixError::Rejected(short(msg)));
    }
    let props = v
        .pointer("/data/propertyList")
        .filter(|p| p.is_object())
        .ok_or_else(|| VapixError::Parse("data.propertyList absent".into()))?;
    // `ProdShortName` (« AXIS M3106-L Mk II ») est le libellé court ;
    // `ProdFullName` ajoute le type (« … Network Camera »).
    let model = text(props, "ProdShortName")
        .or_else(|| text(props, "ProdFullName"))
        .or_else(|| text(props, "ProdNbr"));
    Ok(DeviceInfo {
        model,
        serial: text(props, "SerialNumber"),
        firmware: text(props, "Version"),
        brand: text(props, "Brand"),
    })
}

/// Sonde de repli (`GET pwdgrp.cgi?action=get` sans identifiants).
/// À VÉRIFIER sur vraie Axis : la doc (« Example 12 ») dit qu'une caméra SANS
/// compte répond elle aussi 401 (« initial admin user must be created
/// first »), donc cette sonde ne sépare pas neuve et activée ;
/// `activation_state` lui préfère `systemready.cgi` et ne s'en sert qu'en
/// repli.
pub fn interpret_activation_probe(status: u16) -> Activation {
    match status {
        200 => Activation::New,
        401 => Activation::Activated,
        _ => Activation::Unknown,
    }
}

/// `data.needsetup` de `systemready.cgi` : `yes` = pas encore de compte admin.
fn interpret_systemready(body: &[u8]) -> Option<Activation> {
    let v: Value = serde_json::from_slice(body).ok()?;
    match v.pointer("/data/needsetup")?.as_str()? {
        "yes" => Some(Activation::New),
        "no" => Some(Activation::Activated),
        _ => None,
    }
}

pub async fn device_info(http: &dyn CameraHttp, base: &str) -> Result<DeviceInfo, VapixError> {
    let req = json_post(
        base,
        "/axis-cgi/basicdeviceinfo.cgi",
        json!({"apiVersion": "1.0", "method": "getAllUnrestrictedProperties"}),
    );
    let resp = http.send(req, None).await?;
    require_success(&resp)?;
    parse_basic_device_info(&resp.body)
}

/// N° de série par `param.cgi` (repli d'AXIS OS < 8.40, sans
/// `basicdeviceinfo.cgi`) : `root.Properties.System.SerialNumber=…`. Anonyme
/// d'abord, puis avec le compte sur un 401. La query ne porte aucun secret.
pub async fn serial_from_params(
    http: &dyn CameraHttp,
    base: &str,
    creds: &Credentials,
) -> Result<String, VapixError> {
    let req = || HttpRequest {
        method: Method::Get,
        url: url(base, "/axis-cgi/param.cgi?action=list&group=Properties.System.SerialNumber"),
        body: None,
        content_type: None,
    };
    let resp = match http.send(req(), None).await {
        Ok(r) if r.status != 401 => r,
        Ok(_) | Err(NetError::Auth) => http.send(req(), Some(creds)).await?,
        Err(e) => return Err(e.into()),
    };
    require_success(&resp)?;
    let body = String::from_utf8_lossy(&resp.body);
    body.lines()
        .filter_map(|l| l.trim().split_once('='))
        .find(|(k, _)| k.ends_with("Properties.System.SerialNumber"))
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| VapixError::Parse("SerialNumber absent".into()))
}

pub async fn activation_state(http: &dyn CameraHttp, base: &str) -> Activation {
    // 1. `systemready.cgi` : anonyme, documenté pour cet usage (AXIS OS 9.50+).
    // `timeout` borne l'attente d'une caméra encore en démarrage.
    // À VÉRIFIER sur vraie Axis : `needsetup` sur une caméra neuve.
    let ready = json_post(
        base,
        "/axis-cgi/systemready.cgi",
        json!({"apiVersion": "1.1", "method": "systemready", "params": {"timeout": 2}}),
    );
    match http.send(ready, None).await {
        Ok(resp) => {
            debug(&format!("systemready.cgi : statut {}", resp.status));
            if resp.status == 200
                && let Some(state) = interpret_systemready(&resp.body)
            {
                return state;
            }
        }
        Err(e) => debug(&format!("systemready.cgi : {e}")),
    }
    // 2. Repli : la sonde pwdgrp. Sans identifiants, le vrai client rend
    // `Err(Auth)` sur un 401 au lieu d'une réponse.
    let probe = HttpRequest {
        method: Method::Get,
        url: url(base, "/axis-cgi/pwdgrp.cgi?action=get"),
        body: None,
        content_type: None,
    };
    let status = match http.send(probe, None).await {
        Ok(resp) => resp.status,
        Err(NetError::Auth) => 401,
        Err(e) => {
            debug(&format!("pwdgrp.cgi : {e}"));
            return Activation::Unknown;
        }
    };
    debug(&format!("pwdgrp.cgi : statut brut {status}"));
    interpret_activation_probe(status)
}

/// Crée le premier compte (administrateur avec PTZ), sans authentification :
/// la caméra n'en accepte aucune tant qu'elle n'a pas de compte.
pub async fn activate(
    http: &dyn CameraHttp,
    base: &str,
    account: &Credentials,
) -> Result<(), VapixError> {
    let login = &account.login;
    if login.is_empty() || login.len() > 14 || !login.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(VapixError::Rejected(
            "identifiant invalide (1 à 14 lettres ou chiffres)".into(),
        ));
    }
    let pwd = account.password.expose();
    if pwd.is_empty() || pwd.len() > 64 {
        return Err(VapixError::Rejected(
            "mot de passe invalide (1 à 64 caractères)".into(),
        ));
    }
    // Les `:` de `sgrp` restent littéraux, comme dans les exemples de la doc.
    let body = format!(
        "action=add&user={}&pwd={}&grp=root&sgrp=admin:operator:viewer:ptz",
        form_encode(login),
        form_encode(pwd)
    );
    // https d'abord (certificat auto-signé accepté, comme partout en v1) ;
    // http clair seulement si https ne se connecte pas (port fermé, échec
    // TLS : `Unreachable`, rien n'est parti). Jamais après une réponse HTTP ni
    // un silence après l'envoi : le mot de passe a pu arriver.
    if let Some(secure) = https_base(base) {
        match http.send(post(&secure, "/axis-cgi/pwdgrp.cgi", FORM, body.clone()), None).await {
            Err(NetError::Unreachable(_)) => debug("pwdgrp.cgi : https injoignable, repli http"),
            done => return require_text_ok(&done?),
        }
    }
    let resp = http
        .send(post(base, "/axis-cgi/pwdgrp.cgi", FORM, body), None)
        .await?;
    require_text_ok(&resp)
}

/// `http://hôte[:port]` → `https://hôte` (port 443 : le port https d'une
/// caméra n'est pas annoncé). `None` si `base` n'est pas en http.
fn https_base(base: &str) -> Option<String> {
    let rest = base.strip_prefix("http://")?;
    let authority = rest.split('/').next()?;
    let host = authority.split(':').next().filter(|h| !h.is_empty())?;
    Some(format!("https://{host}"))
}

/// Une coupure après l'envoi (la caméra quitte son adresse) n'est pas une
/// erreur : le rescan confirmera. Seule une connexion impossible (rien n'est
/// parti) ou un refus d'authentification en sont.
/// Refuse avant l'envoi ce qu'une caméra n'appliquerait pas ou qui la rendrait
/// injoignable.
fn validate_static(
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    dns: &[Ipv4Addr],
) -> Result<(), VapixError> {
    let reject = |m: &str| Err(VapixError::Rejected(m.to_string()));
    let m = u32::from(mask);
    if m.leading_ones() + m.trailing_zeros() != 32 {
        return reject("masque invalide");
    }
    if m.leading_ones() == 0 || m.leading_ones() >= 31 {
        return reject("masque /0, /31 ou /32 refusé");
    }
    let a = u32::from(ip);
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_link_local()
        || ip.is_broadcast()
    {
        return reject("adresse IP non utilisable");
    }
    if a & m == a || a | !m == a {
        return reject("adresse réseau ou broadcast refusée");
    }
    if let Some(gw) = gateway {
        if gw == ip {
            return reject("passerelle identique à l'IP");
        }
        if u32::from(gw) & m != a & m {
            return reject("passerelle hors du sous-réseau");
        }
    }
    if dns.len() > 2 {
        return reject("2 DNS au plus");
    }
    Ok(())
}

pub async fn set_network(
    http: &dyn CameraHttp,
    base: &str,
    creds: &Credentials,
    net: &NetworkSettings,
) -> Result<(), VapixError> {
    let mut body = String::from("action=update");
    match net {
        NetworkSettings::Dhcp => body.push_str("&Network.BootProto=dhcp"),
        NetworkSettings::Static {
            ip,
            mask,
            gateway,
            dns,
        } => {
            validate_static(*ip, *mask, *gateway, dns)?;
            body.push_str(&format!(
                "&Network.BootProto=none&Network.IPAddress={ip}&Network.SubnetMask={mask}"
            ));
            if let Some(gw) = gateway {
                body.push_str(&format!("&Network.DefaultRouter={gw}"));
            }
            // La caméra n'a que deux emplacements DNS (`validate_static`).
            for (i, server) in dns.iter().enumerate() {
                body.push_str(&format!("&Network.DNSServer{}={server}", i + 1));
            }
        }
    }
    match http
        .send(post(base, "/axis-cgi/param.cgi", FORM, body), Some(creds))
        .await
    {
        Ok(resp) => require_text_ok(&resp),
        Err(NetError::Timeout | NetError::Io(_)) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub async fn set_time(
    http: &dyn CameraHttp,
    base: &str,
    creds: &Credentials,
    t: &TimeSettings,
) -> Result<(), VapixError> {
    let tz = json_post(
        base,
        "/axis-cgi/time.cgi",
        json!({"apiVersion": "1.0", "method": "setTimeZone", "params": {"timeZone": t.timezone}}),
    );
    parse_json_reply(&http.send(tz, Some(creds)).await?)?;

    let Some(first) = t.ntp_servers.first() else {
        return Ok(());
    };
    let ntp = json_post(
        base,
        "/axis-cgi/ntp.cgi",
        json!({
            "apiVersion": "1.0",
            "method": "setNTPClientConfiguration",
            "params": {"enabled": true, "serversSource": "static", "staticServers": t.ntp_servers}
        }),
    );
    let resp = http.send(ntp, Some(creds)).await?;
    if resp.status != 404 {
        return parse_json_reply(&resp).map(|_| ());
    }
    // `ntp.cgi` absent (AXIS OS < 9.10 ou retiré) : l'ancien paramètre ne
    // connaît qu'un serveur. // À VÉRIFIER sur vraie Axis
    let body = format!(
        "action=update&Time.ObtainFromDHCP=no&Time.SyncSource=NTP&Time.NTP.Server={}",
        form_encode(first)
    );
    require_text_ok(
        &http
            .send(post(base, "/axis-cgi/param.cgi", FORM, body), Some(creds))
            .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use crate::testing::FakeHttp;
    use crate::transport::{ByteStream, HttpRequest, HttpResponse, Method};
    use async_trait::async_trait;

    const BASE: &str = "http://192.0.2.11";
    const INFO: &[u8] = include_bytes!("../tests/fixtures/vapix_basicdeviceinfo.json");

    fn creds(login: &str, pw: &str) -> Credentials {
        Credentials {
            login: login.into(),
            password: Secret::new(pw.into()),
        }
    }

    fn body_of(req: &crate::testing::RecordedRequest) -> String {
        String::from_utf8_lossy(&req.body).into_owned()
    }

    /// Caméra qui répond à `reply` pour toute requête (pour simuler une coupure).
    struct Always(Result<u16, fn() -> NetError>);

    #[async_trait]
    impl CameraHttp for Always {
        async fn send(
            &self,
            _r: HttpRequest,
            _c: Option<&Credentials>,
        ) -> Result<HttpResponse, NetError> {
            match &self.0 {
                Ok(status) => Ok(HttpResponse {
                    status: *status,
                    headers: vec![],
                    body: b"OK".to_vec(),
                }),
                Err(e) => Err(e()),
            }
        }
        async fn stream(
            &self,
            _r: HttpRequest,
            _c: Option<&Credentials>,
        ) -> Result<(HttpResponse, ByteStream), NetError> {
            unimplemented!()
        }
    }

    #[test]
    fn parses_basicdeviceinfo_fixture() {
        let info = parse_basic_device_info(INFO).unwrap();
        assert_eq!(info.model.as_deref(), Some("AXIS M3106-L Mk II"));
        assert_eq!(info.serial.as_deref(), Some("ACCC8E123456"));
        assert_eq!(info.firmware.as_deref(), Some("11.11.73"));
        assert_eq!(info.brand.as_deref(), Some("AXIS"));
    }

    #[test]
    fn model_falls_back_to_full_name_then_part_number() {
        let full = br#"{"data":{"propertyList":{"ProdFullName":"AXIS Q1785-LE Network Camera","ProdNbr":"Q1785-LE"}}}"#;
        assert_eq!(
            parse_basic_device_info(full).unwrap().model.as_deref(),
            Some("AXIS Q1785-LE Network Camera")
        );
        let nbr = br#"{"data":{"propertyList":{"ProdNbr":"Q1785-LE"}}}"#;
        assert_eq!(
            parse_basic_device_info(nbr).unwrap().model.as_deref(),
            Some("Q1785-LE")
        );
        let none = br#"{"data":{"propertyList":{}}}"#;
        assert_eq!(parse_basic_device_info(none).unwrap().model, None);
    }

    #[test]
    fn basicdeviceinfo_error_and_garbage_are_errors() {
        let err = br#"{"apiVersion":"1.0","error":{"code":1000,"message":"Internal error"}}"#;
        assert!(matches!(
            parse_basic_device_info(err),
            Err(VapixError::Rejected(_))
        ));
        assert!(matches!(
            parse_basic_device_info(b"<html>"),
            Err(VapixError::Parse(_))
        ));
        assert!(matches!(
            parse_basic_device_info(b"{}"),
            Err(VapixError::Parse(_))
        ));
    }

    #[tokio::test]
    async fn device_info_posts_unrestricted_request_without_credentials() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO);
        let info = device_info(&http, "http://192.0.2.11/").await.unwrap();
        assert_eq!(info.serial.as_deref(), Some("ACCC8E123456"));
        let req = &http.requests()[0];
        assert_eq!(req.url, "http://192.0.2.11/axis-cgi/basicdeviceinfo.cgi");
        assert_eq!(req.login, None);
        assert!(body_of(req).contains("getAllUnrestrictedProperties"));
    }

    #[tokio::test]
    async fn device_info_non_200_is_status_error() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "");
        assert!(matches!(
            device_info(&http, BASE).await,
            Err(VapixError::Net(NetError::Status(404)))
        ));
    }

    #[test]
    fn activation_probe_mapping() {
        assert_eq!(interpret_activation_probe(200), Activation::New);
        assert_eq!(interpret_activation_probe(401), Activation::Activated);
        assert_eq!(interpret_activation_probe(500), Activation::Unknown);
    }

    #[tokio::test]
    async fn activation_state_reads_systemready_needsetup() {
        let yes = br#"{"apiVersion":"1.4","method":"systemready","data":{"systemready":"yes","needsetup":"yes"}}"#;
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/systemready.cgi", 200, yes.to_vec());
        assert_eq!(activation_state(&http, BASE).await, Activation::New);
        let req = &http.requests()[0];
        assert_eq!(req.login, None);
        assert!(body_of(req).contains("\"method\":\"systemready\""));

        let no = br#"{"data":{"systemready":"yes","needsetup":"no"}}"#;
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/systemready.cgi", 200, no.to_vec());
        assert_eq!(activation_state(&http, BASE).await, Activation::Activated);
        assert_eq!(http.requests().len(), 1);
    }

    #[tokio::test]
    async fn activation_state_falls_back_to_pwdgrp_probe() {
        // systemready.cgi absent (AXIS OS < 9.50) : 404 puis sonde pwdgrp.
        let http = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/systemready.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/pwdgrp.cgi?action=get", 401, "");
        assert_eq!(activation_state(&http, BASE).await, Activation::Activated);
        let reqs = http.requests();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().all(|r| r.login.is_none()));
    }

    #[tokio::test]
    async fn activation_state_unreachable_is_unknown() {
        assert_eq!(
            activation_state(&FakeHttp::new(), BASE).await,
            Activation::Unknown
        );
    }

    #[tokio::test]
    async fn activation_state_auth_refusal_on_probe_means_activated() {
        // Le vrai client rend `Err(Auth)` (et non une réponse 401) sans identifiants.
        let http = Always(Err(|| NetError::Auth));
        assert_eq!(activation_state(&http, BASE).await, Activation::Activated);
    }

    #[tokio::test]
    async fn activate_puts_password_in_body_not_url() {
        let http = FakeHttp::new().on(
            Method::Post,
            "/axis-cgi/pwdgrp.cgi",
            200,
            "Created account root.",
        );
        activate(&http, BASE, &creds("root", "S3cr3t"))
            .await
            .unwrap();
        let req = &http.requests()[0];
        assert!(!req.url.contains("S3cr3t"));
        assert_eq!(req.url, "https://192.0.2.11/axis-cgi/pwdgrp.cgi");
        let body = body_of(req);
        assert!(body.contains("pwd=S3cr3t"));
        assert!(body.contains("action=add&user=root&"));
        assert!(body.contains("grp=root&sgrp=admin:operator:viewer:ptz"));
        assert_eq!(req.login, None);
    }

    /// Caméra scriptée par URL complète (schéma compris), qui les enregistre.
    struct ByUrl {
        reply: fn(&str) -> Result<HttpResponse, NetError>,
        urls: std::sync::Mutex<Vec<String>>,
    }

    impl ByUrl {
        fn new(reply: fn(&str) -> Result<HttpResponse, NetError>) -> Self {
            ByUrl { reply, urls: Default::default() }
        }
        fn urls(&self) -> Vec<String> {
            self.urls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CameraHttp for ByUrl {
        async fn send(&self, r: HttpRequest, _c: Option<&Credentials>) -> Result<HttpResponse, NetError> {
            self.urls.lock().unwrap().push(r.url.clone());
            (self.reply)(&r.url)
        }
        async fn stream(&self, _r: HttpRequest, _c: Option<&Credentials>) -> Result<(HttpResponse, ByteStream), NetError> {
            unimplemented!()
        }
    }

    fn created() -> Result<HttpResponse, NetError> {
        Ok(HttpResponse { status: 200, headers: vec![], body: b"Created account root.".to_vec() })
    }

    /// Le mot de passe part d'abord en https (certificat accepté) ; http clair
    /// seulement si https ne se connecte pas (port fermé, échec TLS).
    #[tokio::test]
    async fn activate_tries_https_first_then_http_only_without_a_connection() {
        let https_ok = ByUrl::new(|_| created());
        activate(&https_ok, "http://192.0.2.11:8080", &creds("root", "x")).await.unwrap();
        assert_eq!(https_ok.urls(), ["https://192.0.2.11/axis-cgi/pwdgrp.cgi"]);

        let no_tls = ByUrl::new(|u| {
            if u.starts_with("https://") { Err(NetError::Unreachable("connexion impossible".into())) } else { created() }
        });
        activate(&no_tls, "http://192.0.2.11:8080", &creds("root", "x")).await.unwrap();
        assert_eq!(
            no_tls.urls(),
            ["https://192.0.2.11/axis-cgi/pwdgrp.cgi", "http://192.0.2.11:8080/axis-cgi/pwdgrp.cgi"]
        );
    }

    /// Une réponse HTTP en https (refus, erreur) ou un silence après l'envoi :
    /// jamais de seconde tentative en clair.
    #[tokio::test]
    async fn activate_never_falls_back_to_http_after_an_https_reply() {
        for reply in [
            (|_: &str| Ok(HttpResponse { status: 200, headers: vec![], body: b"Error: invalid password.".to_vec() }))
                as fn(&str) -> _,
            |_| Ok(HttpResponse { status: 500, headers: vec![], body: vec![] }),
            |_| Err(NetError::Auth),
            |_| Err(NetError::Timeout),
            |_| Err(NetError::Io("coupure".into())),
        ] {
            let http = ByUrl::new(reply);
            assert!(activate(&http, BASE, &creds("root", "x")).await.is_err());
            assert_eq!(http.urls(), ["https://192.0.2.11/axis-cgi/pwdgrp.cgi"]);
        }
    }

    #[tokio::test]
    async fn activate_error_body_is_rejected() {
        let http = FakeHttp::new().on(
            Method::Post,
            "/axis-cgi/pwdgrp.cgi",
            200,
            "# Error: user exists",
        );
        let err = activate(&http, BASE, &creds("root", "S3cr3t"))
            .await
            .unwrap_err();
        assert!(matches!(err, VapixError::Rejected(_)), "{err:?}");
        assert!(!err.to_string().contains("S3cr3t"));
    }

    #[tokio::test]
    async fn activate_rejects_bad_login_without_sending() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/pwdgrp.cgi", 200, "ok");
        for login in ["", "a&b", "dix-huit-lettres-xx", "élève"] {
            let err = activate(&http, BASE, &creds(login, "S3cr3t"))
                .await
                .unwrap_err();
            assert!(matches!(err, VapixError::Rejected(_)), "{login}: {err:?}");
        }
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn special_chars_in_password_are_urlencoded() {
        let http = FakeHttp::new().on(
            Method::Post,
            "/axis-cgi/pwdgrp.cgi",
            200,
            "Created account root.",
        );
        activate(&http, BASE, &creds("root", "a&b=c"))
            .await
            .unwrap();
        assert!(body_of(&http.requests()[0]).contains("pwd=a%26b%3Dc&"));
    }

    #[tokio::test]
    async fn static_network_sends_all_params() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/param.cgi", 200, "OK");
        let net = NetworkSettings::Static {
            ip: "10.0.50.11".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            gateway: Some("10.0.50.1".parse().unwrap()),
            dns: vec!["10.0.50.1".parse().unwrap(), "10.0.50.2".parse().unwrap()],
        };
        set_network(&http, BASE, &creds("root", "S3cr3t"), &net)
            .await
            .unwrap();
        let req = &http.requests()[0];
        let body = body_of(req);
        for want in [
            "action=update",
            "Network.BootProto=none",
            "Network.IPAddress=10.0.50.11",
            "Network.SubnetMask=255.255.255.0",
            "Network.DefaultRouter=10.0.50.1",
            "Network.DNSServer1=10.0.50.1",
            "Network.DNSServer2=10.0.50.2",
        ] {
            assert!(
                body.split('&').any(|p| p == want),
                "manque {want} dans {body}"
            );
        }
        assert_eq!(req.url, "http://192.0.2.11/axis-cgi/param.cgi");
        assert_eq!(req.login.as_deref(), Some("root"));
        assert!(!req.url.contains("S3cr3t") && !body.contains("S3cr3t"));
    }

    #[tokio::test]
    async fn static_network_omits_missing_gateway_and_dns() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/param.cgi", 200, "OK");
        let net = NetworkSettings::Static {
            ip: "10.0.50.11".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            gateway: None,
            dns: vec![],
        };
        set_network(&http, BASE, &creds("root", "x"), &net)
            .await
            .unwrap();
        let body = body_of(&http.requests()[0]);
        assert!(
            !body.contains("DefaultRouter") && !body.contains("DNSServer"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn dhcp_network_sends_bootproto_dhcp_only() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/param.cgi", 200, "OK");
        set_network(&http, BASE, &creds("root", "x"), &NetworkSettings::Dhcp)
            .await
            .unwrap();
        assert_eq!(
            body_of(&http.requests()[0]),
            "action=update&Network.BootProto=dhcp"
        );
    }

    #[tokio::test]
    async fn param_error_body_is_rejected() {
        let http = FakeHttp::new().on(
            Method::Post,
            "/axis-cgi/param.cgi",
            200,
            "# Error: Error setting 'Network.IPAddress' to 'x'!",
        );
        let err = set_network(&http, BASE, &creds("root", "x"), &NetworkSettings::Dhcp)
            .await
            .unwrap_err();
        assert!(matches!(err, VapixError::Rejected(_)), "{err:?}");
    }

    #[tokio::test]
    async fn network_cut_after_send_is_ok_but_connect_failure_is_not() {
        let net = NetworkSettings::Dhcp;
        for cut in [|| NetError::Timeout, || NetError::Io("reset".into())] {
            assert!(
                set_network(&Always(Err(cut)), BASE, &creds("root", "x"), &net)
                    .await
                    .is_ok()
            );
        }
        let unreachable = Always(Err(|| NetError::Unreachable("connexion impossible".into())));
        assert!(matches!(
            set_network(&unreachable, BASE, &creds("root", "x"), &net).await,
            Err(VapixError::Net(NetError::Unreachable(_)))
        ));
        assert!(matches!(
            set_network(
                &Always(Err(|| NetError::Auth)),
                BASE,
                &creds("root", "x"),
                &net
            )
            .await,
            Err(VapixError::Net(NetError::Auth))
        ));
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn static_net(addr: &str, mask: &str, gw: Option<&str>, dns: &[&str]) -> NetworkSettings {
        NetworkSettings::Static {
            ip: ip(addr),
            mask: ip(mask),
            gateway: gw.map(ip),
            dns: dns.iter().map(|d| ip(d)).collect(),
        }
    }

    #[tokio::test]
    async fn invalid_static_settings_are_rejected_without_sending() {
        let cases = [
            (
                "masque non contigu",
                static_net("10.0.50.11", "255.0.255.0", None, &[]),
            ),
            ("masque /0", static_net("10.0.50.11", "0.0.0.0", None, &[])),
            (
                "masque /31",
                static_net("10.0.50.11", "255.255.255.254", None, &[]),
            ),
            (
                "masque /32",
                static_net("10.0.50.11", "255.255.255.255", None, &[]),
            ),
            (
                "IP 0.0.0.0",
                static_net("0.0.0.0", "255.255.255.0", None, &[]),
            ),
            (
                "IP loopback",
                static_net("127.0.0.1", "255.255.255.0", None, &[]),
            ),
            (
                "IP multicast",
                static_net("224.0.0.5", "255.255.255.0", None, &[]),
            ),
            (
                "IP link-local",
                static_net("169.254.10.5", "255.255.0.0", None, &[]),
            ),
            (
                "adresse réseau",
                static_net("10.0.50.0", "255.255.255.0", None, &[]),
            ),
            (
                "broadcast",
                static_net("10.0.50.255", "255.255.255.0", None, &[]),
            ),
            (
                "passerelle hors sous-réseau",
                static_net("10.0.50.11", "255.255.255.0", Some("10.0.51.1"), &[]),
            ),
            (
                "passerelle = IP",
                static_net("10.0.50.11", "255.255.255.0", Some("10.0.50.11"), &[]),
            ),
            (
                "3 DNS",
                static_net(
                    "10.0.50.11",
                    "255.255.255.0",
                    None,
                    &["10.0.50.1", "10.0.50.2", "10.0.50.3"],
                ),
            ),
        ];
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/param.cgi", 200, "OK");
        for (name, net) in cases {
            let err = set_network(&http, BASE, &creds("root", "x"), &net)
                .await
                .unwrap_err();
            assert!(
                matches!(&err, VapixError::Rejected(m) if !m.contains('\n')),
                "{name}: {err:?}"
            );
        }
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn valid_static_settings_pass_validation() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/param.cgi", 200, "OK");
        for net in [
            static_net(
                "10.0.50.11",
                "255.255.255.0",
                Some("10.0.50.1"),
                &["10.0.50.1", "10.0.50.2"],
            ),
            static_net("10.0.50.11", "255.255.254.0", Some("10.0.51.1"), &[]),
            static_net("10.0.50.10", "255.255.255.252", None, &[]),
        ] {
            set_network(&http, BASE, &creds("root", "x"), &net)
                .await
                .unwrap();
        }
        assert_eq!(http.requests().len(), 3);
    }

    #[tokio::test]
    async fn pwdgrp_style_error_line_is_rejected_but_mid_text_error_is_not() {
        let http = FakeHttp::new().on(
            Method::Post,
            "/axis-cgi/pwdgrp.cgi",
            200,
            "Error: invalid password.",
        );
        assert!(matches!(
            activate(&http, BASE, &creds("root", "x")).await,
            Err(VapixError::Rejected(_))
        ));
        let http = FakeHttp::new().on(
            Method::Post,
            "/axis-cgi/pwdgrp.cgi",
            200,
            "Created account root. (No Error)",
        );
        assert!(activate(&http, BASE, &creds("root", "x")).await.is_ok());
    }

    fn time(servers: &[&str]) -> TimeSettings {
        TimeSettings {
            ntp_servers: servers.iter().map(|s| s.to_string()).collect(),
            timezone: "Europe/Paris".into(),
        }
    }

    #[tokio::test]
    async fn set_time_sends_timezone_then_ntp() {
        let http = FakeHttp::new()
            .on(
                Method::Post,
                "/axis-cgi/time.cgi",
                200,
                r#"{"data":{"timeZone":"Europe/Paris"}}"#,
            )
            .on(Method::Post, "/axis-cgi/ntp.cgi", 200, r#"{"data":{}}"#);
        set_time(
            &http,
            BASE,
            &creds("root", "x"),
            &time(&["192.0.2.1", "pool.ntp.org"]),
        )
        .await
        .unwrap();
        let reqs = http.requests();
        assert_eq!(reqs.len(), 2);
        let tz: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(tz["method"], "setTimeZone");
        assert_eq!(tz["params"]["timeZone"], "Europe/Paris");
        let ntp: serde_json::Value = serde_json::from_slice(&reqs[1].body).unwrap();
        assert_eq!(ntp["method"], "setNTPClientConfiguration");
        assert_eq!(ntp["params"]["enabled"], true);
        assert_eq!(ntp["params"]["serversSource"], "static");
        assert_eq!(
            ntp["params"]["staticServers"],
            serde_json::json!(["192.0.2.1", "pool.ntp.org"])
        );
        assert!(reqs.iter().all(|r| r.login.as_deref() == Some("root")));
    }

    #[tokio::test]
    async fn set_time_falls_back_to_param_cgi_on_404() {
        let http = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/time.cgi", 200, r#"{"data":{}}"#)
            .on(Method::Post, "/axis-cgi/ntp.cgi", 404, "")
            .on(Method::Post, "/axis-cgi/param.cgi", 200, "OK");
        set_time(
            &http,
            BASE,
            &creds("root", "x"),
            &time(&["192.0.2.1", "192.0.2.2"]),
        )
        .await
        .unwrap();
        let reqs = http.requests();
        let urls: Vec<&str> = reqs
            .iter()
            .map(|r| r.url.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(urls, ["time.cgi", "ntp.cgi", "param.cgi"]);
        let body = body_of(&reqs[2]);
        assert!(body.contains("Time.SyncSource=NTP"), "{body}");
        assert!(body.contains("Time.NTP.Server=192.0.2.1"), "{body}");
        assert!(!body.contains("192.0.2.2"), "{body}");
    }

    #[tokio::test]
    async fn set_time_json_error_is_rejected() {
        let http = FakeHttp::new().on(
            Method::Post,
            "/axis-cgi/time.cgi",
            200,
            r#"{"apiVersion":"1.0","method":"setTimeZone","error":{"code":2100,"message":"Invalid time zone"}}"#,
        );
        let err = set_time(&http, BASE, &creds("root", "x"), &time(&["192.0.2.1"]))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, VapixError::Rejected(m) if m.contains("Invalid time zone")),
            "{err:?}"
        );
        assert_eq!(http.requests().len(), 1);
    }

    #[tokio::test]
    async fn set_time_without_ntp_server_only_sets_timezone() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/time.cgi", 200, r#"{"data":{}}"#);
        set_time(&http, BASE, &creds("root", "x"), &time(&[]))
            .await
            .unwrap();
        assert_eq!(http.requests().len(), 1);
    }
}
