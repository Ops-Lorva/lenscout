//! Client ISAPI (Hikvision), le minimum : identité et réinitialisation. Tout
//! passe par `CameraHttp` (Digest géré par le client), comme `vapix.rs` ;
//! les erreurs sont celles de `vapix` pour partager leur traduction.
//!
//! D'après la documentation ISAPI publique (non vérifié sur une vraie caméra
//! au moment de l'écriture) :
//! - `GET /ISAPI/System/deviceInfo` : `<DeviceInfo>` avec `serialNumber`,
//!   `macAddress`, `model`, `firmwareVersion` (déjà lu par `identify.rs`).
//! - `PUT /ISAPI/System/factoryReset?mode=basic|full` : `basic` garde les
//!   réglages réseau, `full` remet tout d'usine ; la caméra répond un
//!   `<ResponseStatus>` (`statusCode` 1 = OK, 7 = redémarrage requis) puis
//!   redémarre. À VÉRIFIER sur vraie Hikvision : ce que `basic` garde
//!   exactement selon le firmware.

use crate::model::normalize_mac;
use crate::transport::{CameraHttp, Credentials, HttpRequest, Method, NetError};
use crate::vapix::{ResetMode, VapixError};

/// Ce qu'il faut pour confirmer qu'on vise la bonne caméra.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub serial: Option<String>,
    /// Normalisée (`C0:56:E3:5A:7D:01`).
    pub mac: Option<String>,
}

/// `base` est `http://hôte[:port]`, avec ou sans barre finale.
fn url(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

/// Texte du premier `<tag>…</tag>` (ISAPI : pas de préfixe d'espace de noms).
fn tag(xml: &str, name: &str) -> Option<String> {
    let start = xml.find(&format!("<{name}>"))? + name.len() + 2;
    let end = start + xml[start..].find(&format!("</{name}>"))?;
    Some(xml[start..end].trim().to_string()).filter(|s| !s.is_empty())
}

fn require_success(status: u16) -> Result<(), VapixError> {
    if (200..300).contains(&status) { Ok(()) } else { Err(NetError::Status(status).into()) }
}

pub async fn device_identity(http: &dyn CameraHttp, base: &str, creds: &Credentials) -> Result<Identity, VapixError> {
    let req = HttpRequest { method: Method::Get, url: url(base, "/ISAPI/System/deviceInfo"), body: None, content_type: None };
    let resp = http.send(req, Some(creds)).await?;
    require_success(resp.status)?;
    let xml = String::from_utf8_lossy(&resp.body);
    if !xml.contains("<DeviceInfo") && !xml.contains("<deviceInfo") {
        return Err(VapixError::Parse("DeviceInfo absent".into()));
    }
    Ok(Identity { serial: tag(&xml, "serialNumber"), mac: tag(&xml, "macAddress").as_deref().and_then(normalize_mac) })
}

/// Réinitialisation d'usine : `KeepIp` → `mode=basic`, `Full` → `mode=full`.
/// Une réponse sans `ResponseStatus` lisible mais en 2xx est acceptée ; un
/// `statusCode` autre que 1 (OK) ou 7 (redémarrage requis) est un refus, avec
/// le texte de la caméra.
pub async fn factory_reset(http: &dyn CameraHttp, base: &str, creds: &Credentials, mode: ResetMode) -> Result<(), VapixError> {
    let query = match mode {
        ResetMode::KeepIp => "basic",
        ResetMode::Full => "full",
    };
    let req = HttpRequest {
        method: Method::Put,
        url: url(base, &format!("/ISAPI/System/factoryReset?mode={query}")),
        body: None,
        content_type: None,
    };
    let resp = http.send(req, Some(creds)).await?;
    require_success(resp.status)?;
    let xml = String::from_utf8_lossy(&resp.body);
    match tag(&xml, "statusCode").as_deref() {
        None | Some("1") | Some("7") => Ok(()),
        Some(code) => Err(VapixError::Rejected(tag(&xml, "statusString").unwrap_or_else(|| code.to_string()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use crate::testing::FakeHttp;
    use crate::transport::NetError;

    const BASE: &str = "http://192.0.2.31";
    const OK: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ResponseStatus version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<requestURL>/ISAPI/System/factoryReset</requestURL>
<statusCode>1</statusCode>
<statusString>OK</statusString>
<subStatusCode>ok</subStatusCode>
</ResponseStatus>"#;

    fn creds() -> Credentials {
        Credentials { login: "admin".into(), password: Secret::new("x".into()) }
    }

    #[tokio::test]
    async fn factory_reset_is_a_put_with_the_mode_and_the_account() {
        for (mode, query) in [(ResetMode::KeepIp, "mode=basic"), (ResetMode::Full, "mode=full")] {
            let http = FakeHttp::new().on(Method::Put, "/ISAPI/System/factoryReset", 200, OK);
            factory_reset(&http, BASE, &creds(), mode).await.unwrap();
            let r = &http.requests()[0];
            assert_eq!(r.method, Method::Put);
            assert_eq!(r.url, format!("http://192.0.2.31/ISAPI/System/factoryReset?{query}"));
            assert_eq!(r.login.as_deref(), Some("admin"));
        }
    }

    #[tokio::test]
    async fn factory_reset_refusals_are_errors() {
        let http = FakeHttp::new().on(Method::Put, "/ISAPI/System/factoryReset", 401, "");
        assert!(matches!(
            factory_reset(&http, BASE, &creds(), ResetMode::KeepIp).await,
            Err(VapixError::Net(NetError::Status(401)))
        ));
        let refused = OK.replace("<statusCode>1</statusCode>", "<statusCode>4</statusCode>").replace(
            "<statusString>OK</statusString>",
            "<statusString>Invalid Operation</statusString>",
        );
        let http = FakeHttp::new().on(Method::Put, "/ISAPI/System/factoryReset", 200, refused);
        match factory_reset(&http, BASE, &creds(), ResetMode::Full).await {
            Err(VapixError::Rejected(t)) => assert_eq!(t, "Invalid Operation"),
            other => panic!("{other:?}"),
        }
        // Redémarrage requis (7) : la demande est prise.
        let reboot = OK.replace("<statusCode>1</statusCode>", "<statusCode>7</statusCode>");
        let http = FakeHttp::new().on(Method::Put, "/ISAPI/System/factoryReset", 200, reboot);
        assert!(factory_reset(&http, BASE, &creds(), ResetMode::KeepIp).await.is_ok());
    }

    #[tokio::test]
    async fn factory_reset_without_reply_is_an_error() {
        // Aucune route : le faux transport rend `Unreachable`.
        let http = FakeHttp::new();
        assert!(matches!(
            factory_reset(&http, BASE, &creds(), ResetMode::KeepIp).await,
            Err(VapixError::Net(NetError::Unreachable(_)))
        ));
    }

    #[tokio::test]
    async fn device_identity_is_read_with_the_account() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<deviceName>IP CAMERA</deviceName>
<model>DS-2CD2043G2-I</model>
<serialNumber>DS-2CD2043G2-I20240101AAWRE00000001</serialNumber>
<macAddress>c0:56:e3:5a:7d:01</macAddress>
<firmwareVersion>V5.7.15</firmwareVersion>
</DeviceInfo>"#;
        let http = FakeHttp::new().on(Method::Get, "/ISAPI/System/deviceInfo", 200, xml);
        let id = device_identity(&http, BASE, &creds()).await.unwrap();
        assert_eq!(id.mac.as_deref(), Some("C0:56:E3:5A:7D:01"));
        assert_eq!(id.serial.as_deref(), Some("DS-2CD2043G2-I20240101AAWRE00000001"));
        assert_eq!(http.requests()[0].login.as_deref(), Some("admin"));
        // Autre chose qu'un DeviceInfo : illisible.
        let http = FakeHttp::new().on(Method::Get, "/ISAPI/System/deviceInfo", 200, "<html>box</html>");
        assert!(matches!(device_identity(&http, BASE, &creds()).await, Err(VapixError::Parse(_))));
    }
}
