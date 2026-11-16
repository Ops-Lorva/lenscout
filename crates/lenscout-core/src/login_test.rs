//! Test de login (Opérations) : les identifiants d'un compte essayés sur des
//! caméras, en lecture seule, un résultat par caméra.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::actions::{ActionContext, ActionError, direct, row_key, verify_identity};
use crate::isapi;
use crate::model::{Activation, Camera, Family, normalize_mac};
use crate::transport::{Credentials, NetError};
use crate::vapix::{self, AuthOutcome, VapixError};

/// Issue du test d'une caméra : code stable, traduit par le front.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum LoginOutcome {
    Ok,
    Denied,
    Unreachable,
    NotActivated,
    Unsupported,
    OtherDevice,
    Held,
}

/// Une ligne du résultat. `index` : la place de la caméra dans la sélection
/// reçue ; `key` : sa MAC, sinon son IP (`actions::row_key`).
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct LoginResult {
    pub index: usize,
    pub key: String,
    pub ip: Ipv4Addr,
    #[serde(flatten)]
    pub outcome: LoginOutcome,
}

/// Garde anti-verrouillage : au-delà de `max_denials` refus dans `window`,
/// la caméra n'est plus essayée.
#[derive(Clone, Copy, Debug)]
pub struct LoginGuard {
    pub max_denials: u32,
    pub window: Duration,
}

/// Refus horodatés par clé de ligne, gardés le temps de la session.
#[derive(Default, Debug)]
pub struct DenialLog {
    denials: HashMap<String, Vec<Instant>>,
}

impl DenialLog {
    /// La ligne `key` peut-elle être essayée à `now` : moins de
    /// `max_denials` refus dans la fenêtre qui finit à `now`.
    pub fn allows(&self, key: &str, now: Instant, g: LoginGuard) -> bool {
        let recent = self.denials.get(key).map_or(0, |at| at.iter().filter(|t| now.saturating_duration_since(**t) < g.window).count());
        recent < g.max_denials as usize
    }

    pub fn record(&mut self, key: &str, now: Instant) {
        let at = self.denials.entry(key.to_string()).or_default();
        at.push(now);
        // Une session longue ne garde que les refus récents d'une ligne.
        if at.len() > 16 {
            at.remove(0);
        }
    }
}

/// L'adresse s'est annoncée au dernier scan, fait sur CETTE interface : depuis
/// elle-même, au balayage routé, ou (Hikvision) par sa MAC en SADP.
fn heard(ctx: &ActionContext, cam: &Camera) -> bool {
    let mac = cam.mac.as_deref().and_then(normalize_mac);
    ctx.seen_iface.as_deref() == Some(ctx.iface.name.as_str())
        && (ctx.seen.contains(&cam.ip)
            || ctx.seen_routed.contains(&cam.ip)
            || (cam.family == Family::Hikvision && mac.is_some_and(|m| ctx.seen_sadp.contains(&m))))
}

/// Essaie le compte sur une caméra, sans rien y écrire ni rien poser sur le
/// poste. Dans l'ordre : caméra neuve (rien à essayer), marque, joignable sans
/// IP temporaire, identité confirmée AVANT tout mot de passe, puis une seule
/// lecture authentifiée :
/// - Axis : `GET pwdgrp.cgi?action=get`, lisible par un administrateur seul ;
/// - Hikvision / LTS : `GET /ISAPI/System/deviceInfo`, dont la MAC (ou le n°
///   de série) confirme l'identité dans la même réponse.
pub async fn test_login(ctx: &ActionContext, cam: &Camera, creds: &Credentials) -> LoginOutcome {
    if cam.activation == Activation::New {
        return LoginOutcome::NotActivated;
    }
    if cam.family == Family::Other {
        return LoginOutcome::Unsupported;
    }
    if !direct(ctx, cam.ip).await {
        return LoginOutcome::Unreachable;
    }
    match cam.family {
        Family::Axis => test_axis(ctx, cam, creds).await,
        Family::Hikvision => test_isapi(ctx, cam, creds).await,
        Family::Other => LoginOutcome::Unsupported,
    }
}

async fn test_axis(ctx: &ActionContext, cam: &Camera, creds: &Credentials) -> LoginOutcome {
    match verify_identity(ctx, cam, None).await {
        Ok(_) => {}
        // Lecture anonyme fermée (vieux firmware) : seulement une adresse
        // que le scan a entendue s'annoncer.
        Err(ActionError::NotNew) if heard(ctx, cam) => {}
        Err(ActionError::IdentityMismatch | ActionError::IdentityUnreadable | ActionError::BadReply) => {
            return LoginOutcome::OtherDevice;
        }
        Err(_) => return LoginOutcome::Unreachable,
    }
    let (http, base) = (ctx.http.as_ref(), cam.base_url());
    match vapix::try_auth(http, &base, creds).await {
        AuthOutcome::Ok => LoginOutcome::Ok,
        AuthOutcome::Unreachable => LoginOutcome::Unreachable,
        // Refus d'une caméra dont le scan n'a pas lu l'état : neuve, elle
        // refuse tout compte ; la question se pose sans compte.
        AuthOutcome::Denied if cam.activation == Activation::Unknown => match vapix::activation_state(http, &base).await {
            Activation::New => LoginOutcome::NotActivated,
            _ => LoginOutcome::Denied,
        },
        AuthOutcome::Denied => LoginOutcome::Denied,
    }
}

async fn test_isapi(ctx: &ActionContext, cam: &Camera, creds: &Credentials) -> LoginOutcome {
    if !heard(ctx, cam) {
        return LoginOutcome::Unreachable;
    }
    let id = match isapi::device_identity(ctx.http.as_ref(), &cam.base_url(), creds).await {
        Ok(id) => id,
        Err(VapixError::Net(NetError::Auth | NetError::Status(401 | 403))) => return LoginOutcome::Denied,
        Err(VapixError::Parse(_) | VapixError::Rejected(_)) => return LoginOutcome::OtherDevice,
        Err(_) => return LoginOutcome::Unreachable,
    };
    let mac = cam.mac.as_deref().and_then(normalize_mac);
    let same = match (&mac, &id.mac, cam.serial.as_deref(), id.serial.as_deref()) {
        (Some(a), Some(b), _, _) => a == b,
        (_, _, Some(a), Some(b)) => a.trim().eq_ignore_ascii_case(b.trim()),
        _ => false,
    };
    if same { LoginOutcome::Ok } else { LoginOutcome::OtherDevice }
}

/// Teste `cams`, au plus `parallel` à la fois (le verrouillage d'une caméra
/// ne dépend que de ses propres essais). Une ligne retenue par `log` (trop de
/// refus récents) sort `Held` sans requête ; un refus y est inscrit.
/// L'annulation laisse finir les caméras en cours et n'en lance plus.
/// Rend `true` si annulé. `on_result` reçoit chaque ligne dès qu'elle est finie.
#[allow(clippy::too_many_arguments)]
pub async fn run_login_test(
    ctx: &ActionContext,
    cams: &[Camera],
    creds: &Credentials,
    parallel: usize,
    log: &std::sync::Mutex<DenialLog>,
    guard: LoginGuard,
    cancel: CancellationToken,
    on_result: impl Fn(LoginResult),
) -> bool {
    use futures_util::StreamExt;
    let lock = || log.lock().unwrap_or_else(|e| e.into_inner());
    let mut results = futures_util::stream::iter(cams.iter().enumerate())
        .map(|(index, cam)| {
            let cancel = cancel.clone();
            async move {
                if cancel.is_cancelled() {
                    return None;
                }
                let key = row_key(cam);
                let outcome = if lock().allows(&key, Instant::now(), guard) {
                    test_login(ctx, cam, creds).await
                } else {
                    LoginOutcome::Held
                };
                if outcome == LoginOutcome::Denied {
                    lock().record(&key, Instant::now());
                }
                Some(LoginResult { index, key, ip: cam.ip, outcome })
            }
        })
        .buffer_unordered(parallel.max(1));
    while let Some(r) = results.next().await {
        if let Some(r) = r {
            on_result(r);
        }
    }
    cancel.is_cancelled()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::actions::SeenState;
    use crate::discovery::arp::ScanInterface;
    use crate::model::{Activation, Family, Source};
    use crate::route::Route;
    use crate::secret::Secret;
    use crate::testing::{FakeHttp, FakeNeighbours, FakeRoutes, PanicElevator};
    use crate::transport::{ByteStream, CameraHttp, HttpRequest, HttpResponse, Method, NetError};

    const INFO: &[u8] = include_bytes!("../tests/fixtures/vapix_basicdeviceinfo.json");
    const SERIAL: &str = "ACCC8E123456";
    const HIK_INFO: &str = "<DeviceInfo><serialNumber>DS-1</serialNumber><macAddress>44:19:b6:12:34:56</macAddress></DeviceInfo>";
    const GUARD: LoginGuard = LoginGuard { max_denials: 2, window: Duration::from_secs(30 * 60) };

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn ctx(http: Arc<dyn CameraHttp>) -> ActionContext {
        ActionContext {
            http,
            iface: ScanInterface { name: "eth0".into(), ip: ip("192.0.2.2"), mask: ip("255.255.255.0") },
            service: "eth0".into(),
            elevator: Arc::new(PanicElevator),
            journal: std::env::temp_dir().join("lenscout-login-test-jamais-cree").join("temp-ip.json"),
            seen: vec![ip("192.0.2.11"), ip("192.0.2.21")],
            seen_iface: Some("eth0".into()),
            seen_sadp: vec![],
            sadp: None,
            in_use: vec![],
            other_ifaces: vec![],
            account_network: false,
            seen_states: vec![SeenState { key: "AC:CC:8E:12:34:56".into(), ip: ip("192.0.2.11"), activation: Activation::Activated }],
            neighbours: Arc::new(FakeNeighbours::any("AC:CC:8E:12:34:56")),
            seen_routed: vec![],
            routes: Arc::new(FakeRoutes::new(Route::Unknown)),
        }
    }

    fn creds() -> Credentials {
        Credentials { login: "root".into(), password: Secret::new("S3cr3t".into()) }
    }

    fn axis(last: u8) -> Camera {
        Camera {
            ip: ip(&format!("192.0.2.{last}")),
            mac: Some("AC:CC:8E:12:34:56".into()),
            family: Family::Axis,
            brand: None,
            model: Some("M3106-L Mk II".into()),
            serial: Some(SERIAL.into()),
            firmware: None,
            activation: Activation::Activated,
            http_port: 80,
            sources: vec![Source::Mdns],
            addressing: None,
            declared_mac: None,
        }
    }

    fn hik(last: u8) -> Camera {
        Camera { family: Family::Hikvision, mac: Some("44:19:B6:12:34:56".into()), serial: None, ..axis(last) }
    }

    fn axis_http(pwdgrp: u16) -> FakeHttp {
        FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO.to_vec())
            .on(Method::Get, "/axis-cgi/pwdgrp.cgi", pwdgrp, "")
    }

    /// Requêtes qui portent l'identifiant.
    fn with_login(http: &FakeHttp) -> Vec<crate::testing::RecordedRequest> {
        http.requests().into_iter().filter(|r| r.login.is_some()).collect()
    }

    #[tokio::test]
    async fn axis_ok_reads_pwdgrp_with_get_only() {
        let http = Arc::new(axis_http(200));
        assert_eq!(test_login(&ctx(http.clone()), &axis(11), &creds()).await, LoginOutcome::Ok);
        // L'identité se lit sans compte (POST JSON de lecture) ; le compte ne
        // part que dans un GET, une seule fois.
        let authed = with_login(&http);
        assert_eq!(authed.len(), 1);
        assert_eq!(authed[0].method, Method::Get);
        assert!(authed[0].url.ends_with("/axis-cgi/pwdgrp.cgi?action=get"));
        assert!(http.requests().iter().all(|r| r.method != Method::Put));
        assert!(http.requests().iter().all(|r| r.method == Method::Get || r.url.ends_with("basicdeviceinfo.cgi")));
    }

    #[tokio::test]
    async fn axis_401_and_403_are_denied() {
        for status in [401, 403] {
            let http = Arc::new(axis_http(status));
            assert_eq!(test_login(&ctx(http), &axis(11), &creds()).await, LoginOutcome::Denied, "{status}");
        }
    }

    #[tokio::test]
    async fn axis_identity_mismatch_is_other_device_and_sends_no_password() {
        let http = Arc::new(axis_http(200));
        let mut other = axis(11);
        other.serial = Some("AUTRE".into());
        assert_eq!(test_login(&ctx(http.clone()), &other, &creds()).await, LoginOutcome::OtherDevice);
        assert!(with_login(&http).is_empty());
    }

    #[tokio::test]
    async fn axis_closed_anonymous_identity_needs_the_last_scan() {
        let closed = || {
            FakeHttp::new()
                .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
                .on(Method::Get, "/axis-cgi/param.cgi", 401, "")
                .on(Method::Get, "/axis-cgi/pwdgrp.cgi", 200, "")
        };
        // Annoncée au dernier scan (.11) : essayée.
        let http = Arc::new(closed());
        assert_eq!(test_login(&ctx(http.clone()), &axis(11), &creds()).await, LoginOutcome::Ok);
        // Jamais entendue (.12) : rien du compte ne part.
        let http = Arc::new(closed());
        assert_eq!(test_login(&ctx(http.clone()), &axis(12), &creds()).await, LoginOutcome::Unreachable);
        assert!(with_login(&http).is_empty());
    }

    #[tokio::test]
    async fn axis_unknown_activation_refused_then_systemready_new_is_not_activated() {
        let mut cam = axis(11);
        cam.activation = Activation::Unknown;
        let http = Arc::new(axis_http(401).on(Method::Post, "/axis-cgi/systemready.cgi", 200, r#"{"data":{"needsetup":"yes"}}"#));
        assert_eq!(test_login(&ctx(http), &cam, &creds()).await, LoginOutcome::NotActivated);
        let http = Arc::new(axis_http(401).on(Method::Post, "/axis-cgi/systemready.cgi", 200, r#"{"data":{"needsetup":"no"}}"#));
        assert_eq!(test_login(&ctx(http), &cam, &creds()).await, LoginOutcome::Denied);
        // Activée d'après le scan : pas de relecture.
        let http = Arc::new(axis_http(401));
        assert_eq!(test_login(&ctx(http.clone()), &axis(11), &creds()).await, LoginOutcome::Denied);
        assert!(http.requests().iter().all(|r| !r.url.contains("systemready")));
    }

    #[tokio::test]
    async fn new_camera_is_not_activated_without_any_request() {
        let http = Arc::new(axis_http(200));
        for mut cam in [axis(11), hik(21)] {
            cam.activation = Activation::New;
            assert_eq!(test_login(&ctx(http.clone()), &cam, &creds()).await, LoginOutcome::NotActivated);
        }
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn hikvision_ok_reads_device_info_and_checks_mac() {
        let http = Arc::new(FakeHttp::new().on(Method::Get, "/ISAPI/System/deviceInfo", 200, HIK_INFO));
        assert_eq!(test_login(&ctx(http.clone()), &hik(21), &creds()).await, LoginOutcome::Ok);
        let reqs = http.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!((reqs[0].method, reqs[0].login.as_deref()), (Method::Get, Some("root")));
    }

    #[tokio::test]
    async fn hikvision_401_is_denied() {
        let http = Arc::new(FakeHttp::new().on(Method::Get, "/ISAPI/System/deviceInfo", 401, ""));
        assert_eq!(test_login(&ctx(http), &hik(21), &creds()).await, LoginOutcome::Denied);
    }

    #[tokio::test]
    async fn hikvision_other_mac_is_other_device() {
        let other = HIK_INFO.replace("44:19:b6:12:34:56", "44:19:b6:99:99:99");
        let http = Arc::new(FakeHttp::new().on(Method::Get, "/ISAPI/System/deviceInfo", 200, other));
        assert_eq!(test_login(&ctx(http), &hik(21), &creds()).await, LoginOutcome::OtherDevice);
    }

    #[tokio::test]
    async fn hikvision_not_heard_at_this_address_is_unreachable_without_request() {
        let http = Arc::new(FakeHttp::new().on(Method::Get, "/ISAPI/System/deviceInfo", 200, HIK_INFO));
        assert_eq!(test_login(&ctx(http.clone()), &hik(22), &creds()).await, LoginOutcome::Unreachable);
        // Entendue par sa MAC en SADP : essayée.
        let mut c = ctx(http.clone());
        c.seen_sadp = vec!["44:19:B6:12:34:56".into()];
        assert!(http.requests().is_empty());
        assert_eq!(test_login(&c, &hik(22), &creds()).await, LoginOutcome::Ok);
    }

    #[tokio::test]
    async fn other_brand_is_unsupported_without_request() {
        let http = Arc::new(axis_http(200));
        let cam = Camera { family: Family::Other, ..axis(11) };
        assert_eq!(test_login(&ctx(http.clone()), &cam, &creds()).await, LoginOutcome::Unsupported);
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn off_subnet_without_route_is_unreachable() {
        // `PanicElevator` : aucune IP temporaire n'est posée.
        let http = Arc::new(axis_http(200));
        let mut far = axis(11);
        far.ip = ip("10.9.9.9");
        let mut c = ctx(http.clone());
        c.seen.push(far.ip);
        assert_eq!(test_login(&c, &far, &creds()).await, LoginOutcome::Unreachable);
        assert!(http.requests().is_empty());
    }

    /// Toute requête échoue avec l'erreur fabriquée par `err`.
    struct FailingHttp(fn() -> NetError);

    #[async_trait::async_trait]
    impl CameraHttp for FailingHttp {
        async fn send(&self, _r: HttpRequest, _c: Option<&Credentials>) -> Result<HttpResponse, NetError> {
            Err((self.0)())
        }
        async fn stream(&self, _r: HttpRequest, _c: Option<&Credentials>) -> Result<(HttpResponse, ByteStream), NetError> {
            Err((self.0)())
        }
    }

    #[tokio::test]
    async fn timeout_and_io_are_unreachable() {
        for err in [(|| NetError::Timeout) as fn() -> NetError, || NetError::Io("reset".into())] {
            let c = ctx(Arc::new(FailingHttp(err)));
            assert_eq!(test_login(&c, &axis(11), &creds()).await, LoginOutcome::Unreachable);
            assert_eq!(test_login(&c, &hik(21), &creds()).await, LoginOutcome::Unreachable);
        }
    }

    #[test]
    fn guard_holds_after_two_denials_within_window_and_frees_after() {
        let mut log = DenialLog::default();
        let t0 = Instant::now();
        assert!(log.allows("k", t0, GUARD));
        log.record("k", t0);
        assert!(log.allows("k", t0 + Duration::from_secs(60), GUARD));
        log.record("k", t0 + Duration::from_secs(60));
        assert!(!log.allows("k", t0 + Duration::from_secs(120), GUARD));
        assert!(log.allows("autre", t0 + Duration::from_secs(120), GUARD));
        // Le premier refus sort de la fenêtre : un seul reste.
        assert!(log.allows("k", t0 + Duration::from_secs(30 * 60 + 1), GUARD));
    }

    #[tokio::test]
    async fn run_tries_each_camera_once() {
        let http = Arc::new(axis_http(200));
        // Trois lignes (clés distinctes) ; l'identité se confirme par le n° de série.
        let mut cams: Vec<Camera> = (11..14).map(axis).collect();
        for (i, c) in cams.iter_mut().enumerate() {
            c.mac = Some(format!("AC:CC:8E:00:00:{i:02}"));
        }
        let c = ctx(http.clone());
        let got = Mutex::new(vec![]);
        let log = Mutex::new(DenialLog::default());
        let cancelled = run_login_test(&c, &cams, &creds(), 16, &log, GUARD, CancellationToken::new(), |r| got.lock().unwrap().push(r)).await;
        assert!(!cancelled);
        let mut got = got.into_inner().unwrap();
        got.sort_by_key(|r| r.index);
        assert_eq!(got.iter().map(|r| (r.index, r.outcome.clone())).collect::<Vec<_>>(), [(0, LoginOutcome::Ok), (1, LoginOutcome::Ok), (2, LoginOutcome::Ok)]);
        assert_eq!(got[1].key, "AC:CC:8E:00:00:01");
        assert_eq!(got[1].ip, ip("192.0.2.12"));
        // Un seul envoi de l'identifiant par caméra.
        let authed = with_login(&http);
        assert_eq!(authed.len(), 3);
        for last in 11..14 {
            assert_eq!(authed.iter().filter(|r| r.url.contains(&format!("192.0.2.{last}/"))).count(), 1);
        }
    }

    /// Compte les requêtes en vol ; chacune dure un peu.
    #[derive(Default)]
    struct SlowHttp {
        now: AtomicUsize,
        peak: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl CameraHttp for SlowHttp {
        async fn send(&self, req: HttpRequest, _c: Option<&Credentials>) -> Result<HttpResponse, NetError> {
            let n = self.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(n, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
            self.now.fetch_sub(1, Ordering::SeqCst);
            let body = if req.url.contains("basicdeviceinfo") { INFO.to_vec() } else { vec![] };
            Ok(HttpResponse { status: 200, headers: vec![], body })
        }
        async fn stream(&self, _r: HttpRequest, _c: Option<&Credentials>) -> Result<(HttpResponse, ByteStream), NetError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn run_respects_parallel_limit() {
        let http = Arc::new(SlowHttp::default());
        let cams: Vec<Camera> = (30..90).map(axis).collect();
        let n = AtomicUsize::new(0);
        let log = Mutex::new(DenialLog::default());
        run_login_test(&ctx(http.clone()), &cams, &creds(), 16, &log, GUARD, CancellationToken::new(), |_| {
            n.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert_eq!(n.load(Ordering::SeqCst), 60);
        let peak = http.peak.load(Ordering::SeqCst);
        assert!(peak <= 16 && peak > 1, "{peak}");
    }

    #[tokio::test]
    async fn run_cancelled_starts_no_new_camera() {
        let http = Arc::new(axis_http(200));
        let cancel = CancellationToken::new();
        cancel.cancel();
        let log = Mutex::new(DenialLog::default());
        let got = Mutex::new(vec![]);
        let cancelled = run_login_test(&ctx(http.clone()), &[axis(11), axis(11)], &creds(), 16, &log, GUARD, cancel, |r| got.lock().unwrap().push(r)).await;
        assert!(cancelled);
        assert!(got.lock().unwrap().is_empty());
        assert!(http.requests().is_empty());
        // Annulé pendant le passage : la suite ne part pas.
        let http = Arc::new(axis_http(200));
        let cancel = CancellationToken::new();
        let cams: Vec<Camera> = std::iter::repeat_n(axis(11), 5).collect();
        let n = AtomicUsize::new(0);
        let stop = cancel.clone();
        let cancelled = run_login_test(&ctx(http.clone()), &cams, &creds(), 1, &log, GUARD, cancel, |_| {
            n.fetch_add(1, Ordering::SeqCst);
            stop.cancel();
        })
        .await;
        assert!(cancelled);
        assert_eq!(n.load(Ordering::SeqCst), 1);
        assert_eq!(with_login(&http).len(), 1);
    }

    #[tokio::test]
    async fn run_records_denials_in_the_shared_log() {
        let log = Mutex::new(DenialLog::default());
        let run = |http: Arc<FakeHttp>| {
            let log = &log;
            async move {
                let got = Mutex::new(vec![]);
                run_login_test(&ctx(http), &[axis(11)], &creds(), 16, log, GUARD, CancellationToken::new(), |r| got.lock().unwrap().push(r.outcome)).await;
                got.into_inner().unwrap()
            }
        };
        assert_eq!(run(Arc::new(axis_http(401))).await, [LoginOutcome::Denied]);
        assert_eq!(run(Arc::new(axis_http(401))).await, [LoginOutcome::Denied]);
        // Deux refus : la caméra n'est plus essayée, même avec le bon compte.
        let http = Arc::new(axis_http(200));
        assert_eq!(run(http.clone()).await, [LoginOutcome::Held]);
        assert!(http.requests().is_empty());
        // Le refus d'une autre ligne ne la retient pas.
        assert!(log.lock().unwrap().allows("192.0.2.99", Instant::now(), GUARD));
    }

    #[test]
    fn results_serialize_flat_with_a_code() {
        let r = LoginResult { index: 3, key: "AC:CC:8E:12:34:56".into(), ip: ip("192.0.2.11"), outcome: LoginOutcome::OtherDevice };
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"index":3,"key":"AC:CC:8E:12:34:56","ip":"192.0.2.11","code":"other_device"}"#);
    }
}
