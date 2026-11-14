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
    /// L'appareil n'accepte que Basic sur HTTP : le mot de passe n'est pas
    /// envoyé en clair.
    AuthInsecure,
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
        addressing: None,
        declared_mac: None,
    }
}

fn net_error(e: &NetError) -> Option<IdentifyError> {
    match e {
        NetError::Timeout | NetError::Unreachable(_) | NetError::Denied => Some(IdentifyError::Unreachable),
        NetError::Auth | NetError::Status(401 | 403) => Some(IdentifyError::AuthFailed),
        NetError::InsecureBasic => Some(IdentifyError::AuthInsecure),
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
        Err(VapixError::Net(NetError::Status(404))) => match vapix::serial_from_params(http, &base, Some(creds)).await {
            Ok(serial) => {
                cam.serial = Some(serial);
                return Ok(cam);
            }
            // Ancienne Axis (< 8.40) qui refuse le compte : ne pas aller
            // chercher une Hikvision, qui répondrait « pas une caméra ».
            Err(VapixError::Net(e)) => {
                if let Some(refused @ (IdentifyError::AuthFailed | IdentifyError::AuthInsecure)) = net_error(&e) {
                    return Err(refused);
                }
            }
            Err(_) => {}
        },
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

/// Corps de `GET /SDK/activateStatus` d'une Hikvision : lu sans compte (la
/// page de connexion s'en sert pour proposer l'activation).
fn hik_activation(xml: &str) -> Option<Activation> {
    match tag(xml, "Activated")?.as_str() {
        "true" => Some(Activation::Activated),
        "false" => Some(Activation::New),
        _ => Some(Activation::Unknown),
    }
}

/// Identifie SANS compte ce qui répond à `ip` : rien du compte ne part, la
/// cible n'a pas encore été vue. Sert au balayage d'un réseau routé, où ni le
/// multicast ni l'ARP ne passent. Axis : `basicdeviceinfo.cgi` (repli
/// `param.cgi` anonyme des AXIS OS < 8.40). Hikvision : `deviceInfo` quand le
/// firmware le laisse lire, sinon `/SDK/activateStatus`, qui dit la marque et
/// l'état d'activation sans le modèle. `None` : rien, ou pas une caméra gérée.
pub async fn identify_anonymous(http: &dyn CameraHttp, ip: Ipv4Addr) -> Option<Camera> {
    let mut cam = camera(ip, Family::Axis, "AXIS");
    let base = cam.base_url();
    match vapix::device_info(http, &base).await {
        Ok(info) => {
            cam.brand = info.brand.or(cam.brand);
            cam.model = info.model;
            cam.serial = info.serial;
            cam.firmware = info.firmware;
            return Some(cam);
        }
        // Rien n'écoute : inutile d'essayer le reste.
        Err(VapixError::Net(e)) if net_error(&e) == Some(IdentifyError::Unreachable) => return None,
        Err(VapixError::Net(NetError::Status(404))) => {
            if let Ok(serial) = vapix::serial_from_params(http, &base, None).await {
                cam.serial = Some(serial);
                return Some(cam);
            }
        }
        Err(_) => {}
    }
    let get = |path: &str| HttpRequest { method: Method::Get, url: format!("{base}{path}"), body: None, content_type: None };
    let mut cam = camera(ip, Family::Hikvision, "Hikvision");
    if let Ok(resp) = http.send(get("/ISAPI/System/deviceInfo"), None).await {
        let xml = String::from_utf8_lossy(&resp.body);
        if resp.status == 200 && xml.contains("<deviceInfo") {
            cam.model = tag(&xml, "model");
            cam.serial = tag(&xml, "serialNumber");
            cam.firmware = tag(&xml, "firmwareVersion");
            return Some(cam);
        }
    }
    let resp = http.send(get("/SDK/activateStatus"), None).await.ok().filter(|r| r.status == 200)?;
    cam.activation = hik_activation(&String::from_utf8_lossy(&resp.body))?;
    Some(cam)
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
    async fn ancienne_axis_mauvais_mot_de_passe_refusee_sans_essayer_isapi() {
        let http = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 401, "")
            .on(Method::Get, "/ISAPI/System/deviceInfo", 404, "");
        assert_eq!(identify(&http, ip(), &creds()).await, Err(IdentifyError::AuthFailed));
        assert!(http.requests().iter().all(|r| !r.url.contains("ISAPI")));
    }

    #[tokio::test]
    async fn basic_en_clair_refuse_a_son_propre_code() {
        // L'appareil n'accepte que Basic sur HTTP : le transport refuse
        // d'envoyer le mot de passe en clair.
        struct BasicOnly;
        #[async_trait::async_trait]
        impl CameraHttp for BasicOnly {
            async fn send(&self, req: HttpRequest, creds: Option<&Credentials>) -> Result<crate::transport::HttpResponse, NetError> {
                if creds.is_some() && req.url.contains("ISAPI") {
                    return Err(NetError::InsecureBasic);
                }
                Ok(crate::transport::HttpResponse { status: 404, headers: vec![], body: vec![] })
            }
            async fn stream(
                &self,
                _: HttpRequest,
                _: Option<&Credentials>,
            ) -> Result<(crate::transport::HttpResponse, crate::transport::ByteStream), NetError> {
                Err(NetError::Cancelled)
            }
        }
        assert_eq!(identify(&BasicOnly, ip(), &creds()).await, Err(IdentifyError::AuthInsecure));
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

    /// Réponse de `/SDK/activateStatus` (forme supposée d'après la page de
    /// connexion Hikvision : à confirmer sur une vraie caméra).
    const HIK_ACTIVATED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ActivateStatus version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<Activated>true</Activated>
</ActivateStatus>"#;

    #[tokio::test]
    async fn sans_compte_une_axis_se_reconnait_par_basicdeviceinfo() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO.to_vec());
        let cam = identify_anonymous(&http, ip()).await.unwrap();
        assert_eq!((cam.family, cam.ip, cam.serial.as_deref()), (Family::Axis, ip(), Some("ACCC8E123456")));
        assert!(cam.mac.is_none(), "pas de MAC sans couche 2");
        assert!(http.requests().iter().all(|r| r.login.is_none()));
        // Ancienne Axis : param.cgi anonyme.
        let old = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 200, "root.Properties.System.SerialNumber=ACCC8E000001\n");
        let cam = identify_anonymous(&old, ip()).await.unwrap();
        assert_eq!((cam.family, cam.serial.as_deref()), (Family::Axis, Some("ACCC8E000001")));
    }

    #[tokio::test]
    async fn sans_compte_une_hikvision_se_reconnait_par_isapi_ou_activate_status() {
        let open = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 404, "")
            .on(Method::Get, "/ISAPI/System/deviceInfo", 200, HIK);
        let cam = identify_anonymous(&open, ip()).await.unwrap();
        assert_eq!((cam.family, cam.model.as_deref()), (Family::Hikvision, Some("DS-2CD2143G2-I")));
        assert_eq!(cam.serial.as_deref(), Some("DS-2CD2143G2-I20230101AAWRJ12345678"));
        // deviceInfo fermé (401) : activateStatus dit la marque et l'état.
        let closed = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 404, "")
            .on(Method::Get, "/ISAPI/System/deviceInfo", 401, "")
            .on(Method::Get, "/SDK/activateStatus", 200, HIK_ACTIVATED);
        let cam = identify_anonymous(&closed, ip()).await.unwrap();
        assert_eq!((cam.family, cam.activation, cam.serial.as_deref()), (Family::Hikvision, Activation::Activated, None));
        assert!(closed.requests().iter().all(|r| r.login.is_none()), "aucun compte ne part");
    }

    #[tokio::test]
    async fn sans_compte_rien_ou_autre_chose_ne_donne_rien() {
        assert!(identify_anonymous(&FakeHttp::new(), ip()).await.is_none());
        let other = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 404, "")
            .on(Method::Get, "/ISAPI/System/deviceInfo", 404, "<html>box</html>")
            .on(Method::Get, "/SDK/activateStatus", 200, "<html>routeur</html>");
        assert!(identify_anonymous(&other, ip()).await.is_none());
        // Rien n'écoute : une seule requête.
        let dead = FakeHttp::new();
        let _ = identify_anonymous(&dead, ip()).await;
        assert_eq!(dead.requests().len(), 1);
    }
}
