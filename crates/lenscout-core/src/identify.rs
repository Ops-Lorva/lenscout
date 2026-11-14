//! Identifier une caméra dont l'adresse a été saisie (Cadrage, sans passer
//! par Réseau) : ce que la découverte aurait appris d'elle, marque d'abord,
//! pour choisir l'URL du flux. La garde de sous-réseau est à l'appelant,
//! avant tout appel : un identifiant part vers l'adresse saisie.

use std::net::Ipv4Addr;

use crate::model::{Activation, Camera, Family};
use crate::transport::{CameraHttp, Credentials, HttpRequest, Method, NetError};
use crate::vapix::{self, VapixError};

#[derive(Debug, PartialEq)]
pub enum IdentifyError {
    /// Rien ne répond à cette adresse.
    Unreachable,
    /// Un appareil répond mais refuse le compte.
    AuthFailed,
    /// Un appareil répond, ce n'est ni une Axis ni une Hikvision.
    NotACamera,
}

fn camera(ip: Ipv4Addr, family: Family, brand: &str) -> Camera {
    Camera {
        ip,
        mac: None,
        family,
        brand: Some(brand.to_string()),
        model: None,
        serial: None,
        firmware: None,
        activation: Activation::Unknown,
        http_port: 80,
        sources: vec![],
    }
}

fn net_error(e: &NetError) -> Option<IdentifyError> {
    match e {
        NetError::Timeout | NetError::Unreachable(_) | NetError::Denied => Some(IdentifyError::Unreachable),
        NetError::Auth | NetError::InsecureBasic | NetError::Status(401 | 403) => Some(IdentifyError::AuthFailed),
        _ => None,
    }
}

/// Texte du premier `<tag>…</tag>` (ISAPI : pas de préfixe d'espace de noms).
fn tag(xml: &str, name: &str) -> Option<String> {
    let start = xml.find(&format!("<{name}>"))? + name.len() + 2;
    let end = start + xml[start..].find(&format!("</{name}>"))?;
    Some(xml[start..end].trim().to_string()).filter(|s| !s.is_empty())
}

/// Axis d'abord, anonyme (`basicdeviceinfo.cgi`, repli `param.cgi` des AXIS
/// OS < 8.40) ; sinon Hikvision (`/ISAPI/System/deviceInfo`, avec le compte).
pub async fn identify(http: &dyn CameraHttp, ip: Ipv4Addr, creds: &Credentials) -> Result<Camera, IdentifyError> {
    let mut cam = camera(ip, Family::Axis, "AXIS");
    let base = cam.base_url();
    match vapix::device_info(http, &base).await {
        Ok(info) => {
            cam.brand = info.brand.or(cam.brand);
            cam.model = info.model;
            cam.serial = info.serial;
            cam.firmware = info.firmware;
            return Ok(cam);
        }
        Err(VapixError::Net(e)) if net_error(&e) == Some(IdentifyError::Unreachable) => {
            return Err(IdentifyError::Unreachable);
        }
        Err(VapixError::Net(NetError::Status(404))) => {
            if let Ok(serial) = vapix::serial_from_params(http, &base, creds).await {
                cam.serial = Some(serial);
                return Ok(cam);
            }
        }
        Err(_) => {}
    }
    let req = HttpRequest {
        method: Method::Get,
        url: format!("{base}/ISAPI/System/deviceInfo"),
        body: None,
        content_type: None,
    };
    let resp = http.send(req, Some(creds)).await.map_err(|e| net_error(&e).unwrap_or(IdentifyError::NotACamera))?;
    match resp.status {
        401 | 403 => return Err(IdentifyError::AuthFailed),
        200 => {}
        _ => return Err(IdentifyError::NotACamera),
    }
    let xml = String::from_utf8_lossy(&resp.body);
    if !xml.contains("<deviceInfo") {
        return Err(IdentifyError::NotACamera);
    }
    let mut cam = camera(ip, Family::Hikvision, "Hikvision");
    cam.model = tag(&xml, "model");
    cam.serial = tag(&xml, "serialNumber");
    cam.firmware = tag(&xml, "firmwareVersion");
    cam.mac = tag(&xml, "macAddress");
    Ok(cam)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use crate::testing::FakeHttp;

    const INFO: &[u8] = include_bytes!("../tests/fixtures/vapix_basicdeviceinfo.json");
    const HIK: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<deviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<deviceName>IP CAMERA</deviceName><model>DS-2CD2143G2-I</model>
<serialNumber>DS-2CD2143G2-I20230101AAWRJ12345678</serialNumber>
<macAddress>a4:14:37:12:34:56</macAddress><firmwareVersion>V5.7.3</firmwareVersion>
</deviceInfo>"#;

    fn ip() -> Ipv4Addr {
        "192.168.1.64".parse().unwrap()
    }

    fn creds() -> Credentials {
        Credentials { login: "admin".into(), password: Secret::new("pw".into()) }
    }

    #[tokio::test]
    async fn une_axis_se_reconnait_sans_envoyer_le_compte() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO.to_vec());
        let cam = identify(&http, ip(), &creds()).await.unwrap();
        assert_eq!(cam.family, Family::Axis);
        assert_eq!(cam.ip, ip());
        assert_eq!(cam.serial.as_deref(), Some("ACCC8E123456"));
        assert!(http.requests().iter().all(|r| r.login.is_none()));
    }

    #[tokio::test]
    async fn une_ancienne_axis_se_reconnait_par_param_cgi() {
        let http = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 200, "root.Properties.System.SerialNumber=ACCC8E000001\n");
        let cam = identify(&http, ip(), &creds()).await.unwrap();
        assert_eq!((cam.family, cam.serial.as_deref()), (Family::Axis, Some("ACCC8E000001")));
    }

    #[tokio::test]
    async fn une_hikvision_se_reconnait_par_isapi_avec_le_compte() {
        let http = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 404, "")
            .on(Method::Get, "/ISAPI/System/deviceInfo", 200, HIK);
        let cam = identify(&http, ip(), &creds()).await.unwrap();
        assert_eq!(cam.family, Family::Hikvision);
        assert_eq!(cam.model.as_deref(), Some("DS-2CD2143G2-I"));
        assert_eq!(cam.firmware.as_deref(), Some("V5.7.3"));
        let isapi = http.requests().into_iter().find(|r| r.url.contains("ISAPI")).unwrap();
        assert_eq!(isapi.login.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn compte_refuse() {
        let http = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 404, "")
            .on(Method::Get, "/ISAPI/System/deviceInfo", 401, "");
        assert_eq!(identify(&http, ip(), &creds()).await, Err(IdentifyError::AuthFailed));
    }

    #[tokio::test]
    async fn rien_ne_repond() {
        // FakeHttp : route inconnue = injoignable.
        assert_eq!(identify(&FakeHttp::new(), ip(), &creds()).await, Err(IdentifyError::Unreachable));
    }

    #[tokio::test]
    async fn un_appareil_qui_n_est_pas_une_camera_geree() {
        let http = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 404, "")
            .on(Method::Get, "/ISAPI/System/deviceInfo", 404, "<html>box</html>");
        assert_eq!(identify(&http, ip(), &creds()).await, Err(IdentifyError::NotACamera));
        let http = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, "pas du json")
            .on(Method::Get, "/ISAPI/System/deviceInfo", 200, "<html>routeur</html>");
        assert_eq!(identify(&http, ip(), &creds()).await, Err(IdentifyError::NotACamera));
    }
}
