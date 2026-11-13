//! Actions de configuration sur des caméras : une caméra à la fois, dans
//! l'ordre, avec vérification de son identité juste avant d'écrire.
//!
//! Les tâches suivantes étendent `Action` (IP temporaire, SADP, lot) et
//! `ActionContext` ; `apply` reste le seul point d'entrée par caméra, donc le
//! seul endroit où la marque et l'identité sont contrôlées.

use std::net::Ipv4Addr;
use std::sync::Arc;

use serde::Serialize;

use crate::discovery::arp::ScanInterface;
use crate::model::{Camera, Family, normalize_mac};
use crate::transport::{CameraHttp, Credentials, NetError};
use crate::vapix::{self, NetworkSettings, TimeSettings, VapixError};

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Activate,
    Network(NetworkSettings),
    Time(TimeSettings),
}

/// Codes stables : le front les traduit, `detail` ne vient que de la caméra
/// (jamais d'un mot de passe).
#[derive(Serialize, thiserror::Error, Debug, PartialEq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ActionError {
    #[error("action non prise en charge")]
    Unsupported,
    #[error("ce n'est plus la même caméra")]
    IdentityMismatch,
    #[error("caméra injoignable : {ip}")]
    Unreachable { ip: Ipv4Addr },
    #[error("authentification refusée")]
    AuthFailed,
    #[error("refusé : {detail}")]
    Rejected { detail: String },
    /// Utilisé par la tâche 13 (IP temporaire du poste).
    #[error("droits refusés : {ip}")]
    ElevationRefused { ip: Ipv4Addr },
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ActionResult {
    /// MAC de la caméra, sinon son IP : la clé de la ligne côté front.
    pub key: String,
    pub ok: bool,
    pub error: Option<ActionError>,
}

/// La tâche 13 y ajoute l'élévation, la 14 le socket SADP.
pub struct ActionContext {
    pub http: Arc<dyn CameraHttp>,
    pub iface: ScanInterface,
}

/// Erreur d'un appel VAPIX → code affiché. `ip` n'est que celle de la caméra visée.
fn from_vapix(e: VapixError, ip: Ipv4Addr) -> ActionError {
    match e {
        VapixError::Net(NetError::Timeout | NetError::Unreachable(_) | NetError::Io(_)) => {
            ActionError::Unreachable { ip }
        }
        VapixError::Net(NetError::Auth | NetError::Status(401 | 403)) => ActionError::AuthFailed,
        VapixError::Net(e) => ActionError::Rejected { detail: e.to_string() },
        VapixError::Rejected(detail) | VapixError::Parse(detail) => ActionError::Rejected { detail },
    }
}

/// Lit l'identité de la caméra à son adresse actuelle et la compare à celle
/// qu'on croit viser : n° de série si on le connaît, sinon MAC (sur Axis, le
/// n° de série est la MAC sans séparateurs). Sans rien à comparer, ou si
/// l'appareil ne répond pas comme une Axis (autre appareil arrivé à cette
/// adresse), on refuse : la caméra visée n'est pas confirmée.
pub async fn verify_identity(ctx: &ActionContext, cam: &Camera) -> Result<(), ActionError> {
    if cam.family != Family::Axis {
        return Err(ActionError::Unsupported);
    }
    let info = match vapix::device_info(ctx.http.as_ref(), &cam.base_url()).await {
        Ok(info) => info,
        Err(VapixError::Parse(_) | VapixError::Rejected(_) | VapixError::Net(NetError::Status(_))) => {
            return Err(ActionError::IdentityMismatch);
        }
        Err(e) => return Err(from_vapix(e, cam.ip)),
    };
    let Some(found) = info.serial.as_deref().map(str::trim) else {
        return Err(ActionError::IdentityMismatch);
    };
    let same = match (cam.serial.as_deref(), cam.mac.as_deref()) {
        (Some(expected), _) => expected.trim().eq_ignore_ascii_case(found),
        (None, Some(mac)) => match (normalize_mac(mac), normalize_mac(found)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
        (None, None) => false,
    };
    if same { Ok(()) } else { Err(ActionError::IdentityMismatch) }
}

fn result(cam: &Camera, outcome: Result<(), ActionError>) -> ActionResult {
    ActionResult {
        key: cam.mac.clone().unwrap_or_else(|| cam.ip.to_string()),
        ok: outcome.is_ok(),
        error: outcome.err(),
    }
}

/// Seule porte d'écriture : marque, identité, puis l'écriture. Une marque sans
/// action (`Other`, Hikvision tant que la tâche 14 n'est pas faite) ne génère
/// aucune requête.
pub async fn apply(
    ctx: &ActionContext,
    cam: &Camera,
    creds: &Credentials,
    action: &Action,
) -> ActionResult {
    result(cam, apply_checked(ctx, cam, creds, action).await)
}

async fn apply_checked(
    ctx: &ActionContext,
    cam: &Camera,
    creds: &Credentials,
    action: &Action,
) -> Result<(), ActionError> {
    match cam.family {
        Family::Axis => {}
        Family::Hikvision | Family::Other => return Err(ActionError::Unsupported),
    }
    verify_identity(ctx, cam).await?;
    let http = ctx.http.as_ref();
    let base = cam.base_url();
    match action {
        Action::Activate => vapix::activate(http, &base, creds).await,
        Action::Network(net) => vapix::set_network(http, &base, creds, net).await,
        Action::Time(t) => vapix::set_time(http, &base, creds, t).await,
    }
    .map_err(|e| from_vapix(e, cam.ip))
}

/// Une caméra après l'autre, dans l'ordre de la liste ; un échec n'arrête pas
/// les suivantes. Le changement d'IP vise une seule caméra (le lot a son plan
/// d'adresses, tâche 15) : sur plusieurs, rien n'est envoyé.
pub async fn apply_all(
    ctx: &ActionContext,
    cams: &[Camera],
    creds: &Credentials,
    action: &Action,
) -> Vec<ActionResult> {
    if matches!(action, Action::Network(_)) && cams.len() > 1 {
        let refused = || ActionError::Rejected {
            detail: "une seule caméra à la fois".into(),
        };
        return cams.iter().map(|c| result(c, Err(refused()))).collect();
    }
    let mut out = Vec::with_capacity(cams.len());
    for cam in cams {
        out.push(apply(ctx, cam, creds, action).await);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Activation, Source};
    use crate::secret::Secret;
    use crate::testing::FakeHttp;
    use crate::transport::{ByteStream, HttpRequest, HttpResponse, Method};
    use async_trait::async_trait;

    const INFO: &[u8] = include_bytes!("../tests/fixtures/vapix_basicdeviceinfo.json");
    const SERIAL: &str = "ACCC8E123456";
    const MAC: &str = "AC:CC:8E:12:34:56";

    fn creds() -> Credentials {
        Credentials { login: "root".into(), password: Secret::new("S3cr3t".into()) }
    }

    fn cam(ip: &str, family: Family) -> Camera {
        Camera {
            ip: ip.parse().unwrap(),
            mac: Some(MAC.into()),
            family,
            brand: None,
            model: None,
            serial: None,
            firmware: None,
            activation: Activation::New,
            http_port: 80,
            sources: vec![Source::Mdns],
        }
    }

    fn ctx(http: Arc<dyn CameraHttp>) -> ActionContext {
        ActionContext {
            http,
            iface: ScanInterface {
                name: "eth0".into(),
                ip: "192.0.2.2".parse().unwrap(),
                mask: "255.255.255.0".parse().unwrap(),
            },
        }
    }

    /// Une Axis qui accepte tout, dont le n° de série est `SERIAL`.
    fn axis_ok() -> FakeHttp {
        FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO.to_vec())
            .on(Method::Post, "/axis-cgi/pwdgrp.cgi", 200, "Created account root.")
            .on(Method::Post, "/axis-cgi/param.cgi", 200, "OK")
            .on(Method::Post, "/axis-cgi/time.cgi", 200, r#"{"data":{}}"#)
            .on(Method::Post, "/axis-cgi/ntp.cgi", 200, r#"{"data":{}}"#)
    }

    /// Les requêtes qui modifient la caméra (tout sauf la lecture d'identité).
    fn writes(http: &FakeHttp) -> Vec<String> {
        http.requests()
            .into_iter()
            .filter(|r| !r.url.ends_with("/axis-cgi/basicdeviceinfo.cgi"))
            .map(|r| r.url)
            .collect()
    }

    fn static_net() -> Action {
        Action::Network(NetworkSettings::Static {
            ip: "192.0.2.50".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            gateway: Some("192.0.2.1".parse().unwrap()),
            dns: vec![],
        })
    }

    fn time() -> Action {
        Action::Time(TimeSettings {
            ntp_servers: vec!["pool.ntp.org".into()],
            timezone: "Europe/Paris".into(),
        })
    }

    /// Caméra qui répond à tout par `reply`, en enregistrant les URL.
    struct Scripted {
        reply: fn(&HttpRequest) -> Result<HttpResponse, NetError>,
        urls: std::sync::Mutex<Vec<String>>,
    }

    impl Scripted {
        fn new(reply: fn(&HttpRequest) -> Result<HttpResponse, NetError>) -> Self {
            Scripted { reply, urls: Default::default() }
        }
    }

    #[async_trait]
    impl CameraHttp for Scripted {
        async fn send(&self, req: HttpRequest, _: Option<&Credentials>) -> Result<HttpResponse, NetError> {
            self.urls.lock().unwrap().push(req.url.clone());
            (self.reply)(&req)
        }
        async fn stream(&self, _: HttpRequest, _: Option<&Credentials>) -> Result<(HttpResponse, ByteStream), NetError> {
            Err(NetError::Cancelled)
        }
    }

    /// Une adresse qui ne répond pas, les autres délèguent à `inner`.
    struct DeadHost {
        inner: FakeHttp,
        dead: &'static str,
    }

    #[async_trait]
    impl CameraHttp for DeadHost {
        async fn send(&self, req: HttpRequest, c: Option<&Credentials>) -> Result<HttpResponse, NetError> {
            if req.url.contains(self.dead) {
                return Err(NetError::Unreachable("hors ligne".into()));
            }
            self.inner.send(req, c).await
        }
        async fn stream(&self, req: HttpRequest, c: Option<&Credentials>) -> Result<(HttpResponse, ByteStream), NetError> {
            self.inner.stream(req, c).await
        }
    }

    #[tokio::test]
    async fn identity_mismatch_never_writes() {
        // Une autre caméra a pris l'adresse : série différente de la MAC visée.
        let other = String::from_utf8_lossy(INFO).replace(SERIAL, "ACCC8E999999");
        let http = Arc::new(
            FakeHttp::new()
                .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, other.into_bytes())
                .on(Method::Post, "/axis-cgi/pwdgrp.cgi", 200, "Created account root.")
                .on(Method::Post, "/axis-cgi/param.cgi", 200, "OK")
                .on(Method::Post, "/axis-cgi/time.cgi", 200, r#"{"data":{}}"#)
                .on(Method::Post, "/axis-cgi/ntp.cgi", 200, r#"{"data":{}}"#),
        );
        for action in [Action::Activate, static_net(), time()] {
            let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &action).await;
            assert_eq!(r.error, Some(ActionError::IdentityMismatch));
            assert!(!r.ok);
        }
        assert_eq!(writes(&http), Vec::<String>::new());
    }

    #[tokio::test]
    async fn known_serial_must_match_even_when_mac_would() {
        let http = Arc::new(axis_ok());
        let mut c = cam("192.0.2.11", Family::Axis);
        c.serial = Some("ACCC8E000001".into());
        let r = apply(&ctx(http.clone()), &c, &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::IdentityMismatch));
        assert!(writes(&http).is_empty());

        c.serial = Some(SERIAL.into());
        c.mac = None;
        assert!(apply(&ctx(http.clone()), &c, &creds(), &Action::Activate).await.ok);
    }

    #[tokio::test]
    async fn identity_needs_a_serial_or_a_mac_to_compare() {
        let http = Arc::new(axis_ok());
        let mut c = cam("192.0.2.11", Family::Axis);
        c.mac = None;
        let r = apply(&ctx(http.clone()), &c, &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::IdentityMismatch));
        assert!(writes(&http).is_empty());
        assert_eq!(r.key, "192.0.2.11");
    }

    #[tokio::test]
    async fn device_without_axis_answer_is_not_the_camera() {
        // Un autre appareil à cette adresse (page HTML, 404) : rien n'est écrit.
        for reply in [
            (|_: &HttpRequest| Ok(HttpResponse { status: 200, headers: vec![], body: b"<html>".to_vec() })) as fn(&HttpRequest) -> _,
            |_| Ok(HttpResponse { status: 404, headers: vec![], body: vec![] }),
        ] {
            let http = Arc::new(Scripted::new(reply));
            let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
            assert_eq!(r.error, Some(ActionError::IdentityMismatch));
            assert_eq!(http.urls.lock().unwrap().len(), 1, "seule la lecture d'identité est partie");
        }
    }

    #[tokio::test]
    async fn activate_two_cameras_in_order() {
        let http = Arc::new(axis_ok());
        let cams = [cam("192.0.2.12", Family::Axis), cam("192.0.2.11", Family::Axis)];
        let out = apply_all(&ctx(http.clone()), &cams, &creds(), &Action::Activate).await;
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| r.ok && r.error.is_none()));
        let order: Vec<String> = http.requests().into_iter().map(|r| r.url).collect();
        assert_eq!(
            order,
            [
                "http://192.0.2.12/axis-cgi/basicdeviceinfo.cgi",
                "http://192.0.2.12/axis-cgi/pwdgrp.cgi",
                "http://192.0.2.11/axis-cgi/basicdeviceinfo.cgi",
                "http://192.0.2.11/axis-cgi/pwdgrp.cgi",
            ]
        );
    }

    #[tokio::test]
    async fn failure_on_first_does_not_stop_second() {
        let http = Arc::new(DeadHost { inner: axis_ok(), dead: "192.0.2.11" });
        let cams = [cam("192.0.2.11", Family::Axis), cam("192.0.2.12", Family::Axis)];
        let out = apply_all(&ctx(http.clone()), &cams, &creds(), &Action::Activate).await;
        assert_eq!(out[0].error, Some(ActionError::Unreachable { ip: "192.0.2.11".parse().unwrap() }));
        assert!(out[1].ok);
        assert!(http.inner.requests().iter().any(|r| r.url == "http://192.0.2.12/axis-cgi/pwdgrp.cgi"));
    }

    #[tokio::test]
    async fn other_family_is_unsupported_without_request() {
        let http = Arc::new(axis_ok());
        for action in [Action::Activate, static_net(), time()] {
            let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Other), &creds(), &action).await;
            assert_eq!(r.error, Some(ActionError::Unsupported));
        }
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn hikvision_is_unsupported_until_its_task() {
        let http = Arc::new(axis_ok());
        let out = apply_all(
            &ctx(http.clone()),
            &[cam("192.0.2.11", Family::Hikvision)],
            &creds(),
            &Action::Activate,
        )
        .await;
        assert_eq!(out[0].error, Some(ActionError::Unsupported));
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn mixed_selection_only_touches_the_axis() {
        let http = Arc::new(axis_ok());
        let cams = [cam("192.0.2.11", Family::Other), cam("192.0.2.12", Family::Axis)];
        let out = apply_all(&ctx(http.clone()), &cams, &creds(), &time()).await;
        assert_eq!(out[0].error, Some(ActionError::Unsupported));
        assert!(out[1].ok);
        assert!(http.requests().iter().all(|r| r.url.starts_with("http://192.0.2.12/")));
    }

    #[tokio::test]
    async fn network_on_two_cameras_is_refused() {
        let http = Arc::new(axis_ok());
        let cams = [cam("192.0.2.11", Family::Axis), cam("192.0.2.12", Family::Axis)];
        let out = apply_all(&ctx(http.clone()), &cams, &creds(), &static_net()).await;
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| !r.ok && matches!(r.error, Some(ActionError::Rejected { .. }))));
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn unreachable_camera_reports_its_ip() {
        let http = Arc::new(FakeHttp::new());
        let r = apply(&ctx(http), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::Unreachable { ip: "192.0.2.11".parse().unwrap() }));
        assert_eq!(r.key, MAC);
    }

    #[tokio::test]
    async fn network_change_goes_through_with_credentials() {
        let http = Arc::new(axis_ok());
        let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &static_net()).await;
        assert!(r.ok, "{r:?}");
        let req = http.requests().into_iter().find(|r| r.url.ends_with("param.cgi")).unwrap();
        assert_eq!(req.login.as_deref(), Some("root"));
        assert!(String::from_utf8_lossy(&req.body).contains("Network.IPAddress=192.0.2.50"));
    }

    #[tokio::test]
    async fn invalid_static_network_is_rejected_without_write() {
        let http = Arc::new(axis_ok());
        let bad = Action::Network(NetworkSettings::Static {
            ip: "169.254.1.5".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            gateway: None,
            dns: vec![],
        });
        let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &bad).await;
        assert!(matches!(r.error, Some(ActionError::Rejected { .. })));
        assert!(writes(&http).is_empty());
    }

    #[tokio::test]
    async fn auth_refusal_is_reported_as_auth_failed() {
        let http = Arc::new(Scripted::new(|req| {
            if req.url.ends_with("basicdeviceinfo.cgi") {
                Ok(HttpResponse { status: 200, headers: vec![], body: INFO.to_vec() })
            } else {
                Err(NetError::Auth)
            }
        }));
        let r = apply(&ctx(http), &cam("192.0.2.11", Family::Axis), &creds(), &time()).await;
        assert_eq!(r.error, Some(ActionError::AuthFailed));
    }

    #[tokio::test]
    async fn camera_refusal_carries_its_message() {
        let http = Arc::new(
            FakeHttp::new()
                .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO.to_vec())
                .on(Method::Post, "/axis-cgi/pwdgrp.cgi", 200, "Error: invalid password."),
        );
        let r = apply(&ctx(http), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::Rejected { detail: "Error: invalid password.".into() }));
    }

    #[test]
    fn action_error_json_has_no_password() {
        let ip: Ipv4Addr = "192.0.2.11".parse().unwrap();
        let all = [
            ActionError::Unsupported,
            ActionError::IdentityMismatch,
            ActionError::Unreachable { ip },
            ActionError::AuthFailed,
            ActionError::Rejected { detail: "Error: invalid password.".into() },
            ActionError::ElevationRefused { ip },
        ];
        for e in all {
            let json = serde_json::to_string(&e).unwrap();
            assert!(!json.contains("S3cr3t"), "{json}");
            assert!(json.contains("\"code\""), "{json}");
            assert!(!e.to_string().contains("S3cr3t"));
        }
        let r = ActionResult { key: MAC.into(), ok: false, error: Some(ActionError::AuthFailed) };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"key":"AC:CC:8E:12:34:56","ok":false,"error":{"code":"auth_failed"}}"#
        );
    }
}
