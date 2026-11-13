//! Actions de configuration sur des caméras : une caméra à la fois, dans
//! l'ordre, avec vérification de son identité juste avant d'écrire.
//!
//! Les tâches suivantes étendent `Action` (IP temporaire, SADP, lot) et
//! `ActionContext` ; `apply` reste le seul point d'entrée par caméra, donc le
//! seul endroit où la marque et l'identité sont contrôlées.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;

use crate::batch::{Assignment, BatchRequest};
use crate::discovery::arp::ScanInterface;
use crate::model::{Camera, Family, Source, normalize_mac};
use crate::temp_ip::{
    Elevator, TempIpError, needs_temp_ip, pick_temp_ip, reachable_with_temp_ip, read_journal, subnets_overlap,
    temp_mask, with_temp_ip,
};
use crate::discovery::sadp;
use crate::transport::{CameraHttp, Credentials, Datagram, NetError};
use std::time::Duration;
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
    /// Lecture d'identité impossible (404, 401, réponse non Axis) : l'écriture
    /// est bloquée mais on ne prétend pas que c'est une autre caméra.
    #[error("identité illisible")]
    IdentityUnreadable,
    /// Adresse hors du sous-réseau de l'interface : rien n'est envoyé.
    #[error("caméra hors du sous-réseau")]
    CameraOffSubnet,
    #[error("caméra déjà activée")]
    AlreadyActivated,
    #[error("une seule caméra à la fois")]
    NetworkNeedsOneCamera,
    #[error("caméra injoignable : {ip}")]
    Unreachable { ip: Ipv4Addr },
    #[error("authentification refusée")]
    AuthFailed,
    /// Texte de la caméra elle-même (`# Error: …`), jamais un texte de l'app.
    #[error("refusé : {detail}")]
    Rejected { detail: String },
    /// Valeur refusée avant l'envoi : `reason` est un code stable
    /// (`invalid_mask`, `gateway_out_of_subnet`, `bad_login`…).
    #[error("valeur refusée : {reason}")]
    Invalid { reason: String },
    /// Statut HTTP inattendu de la caméra.
    #[error("statut HTTP {status}")]
    HttpStatus { status: u16 },
    /// La caméra n'offre que Basic en http : le mot de passe n'est pas envoyé.
    #[error("authentification Basic refusée en HTTP")]
    AuthInsecure,
    /// Réponse que l'app ne sait pas lire (pas du JSON VAPIX, champ absent).
    #[error("réponse illisible")]
    BadReply,
    /// Invite d'élévation refusée : `ip` est celle de la caméra hors sous-réseau.
    #[error("droits refusés : {ip}")]
    ElevationRefused { ip: Ipv4Addr },
    /// L'IP temporaire n'a pas pu être posée (rien de libre, commande en échec).
    #[error("IP temporaire impossible")]
    TempIpFailed,
    /// Hikvision : sa MAC ne s'est pas annoncée en SADP, sur cette interface,
    /// au dernier scan. Rien n'est envoyé (un mot de passe SADP est diffusé en
    /// multicast sur le LAN de l'interface).
    #[error("caméra non vue en SADP")]
    CameraNotSeen,
    /// L'IP temporaire `ip` n'a pas pu être retirée du poste ; le journal
    /// reste, le démarrage suivant réessaiera.
    #[error("IP temporaire restée : {ip}")]
    TempIpLeft { ip: Ipv4Addr },
    /// Une autre instance de Lenscout tient l'IP temporaire.
    #[error("IP temporaire déjà en cours")]
    TempIpBusy,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ActionResult {
    /// MAC de la caméra, sinon son IP : la clé de la ligne côté front.
    pub key: String,
    pub ok: bool,
    pub error: Option<ActionError>,
}

pub struct ActionContext {
    pub http: Arc<dyn CameraHttp>,
    pub iface: ScanInterface,
    /// Le nom choisi dans l'app : service networksetup sur macOS (où
    /// `iface.name` est l'ifname BSD « en0 »), le même nom ailleurs.
    pub service: String,
    pub elevator: Arc<dyn Elevator>,
    /// `<app_data_dir>/temp-ip.json`.
    pub journal: PathBuf,
    /// Adresses qui se sont annoncées elles-mêmes au dernier scan (source
    /// UDP = adresse annoncée), tenues par Rust : le front ne peut pas en
    /// inventer.
    pub seen: Vec<Ipv4Addr>,
    /// Interface de ce scan (`ScanInterface::name`).
    pub seen_iface: Option<String>,
    /// MAC (normalisées) qui se sont annoncées en SADP depuis leur propre
    /// adresse au dernier scan (`seen_iface`), tenues par Rust.
    pub seen_sadp: Vec<String>,
    /// Socket SADP ouvert sur `iface` ; `None` : pas d'action SADP possible.
    pub sadp: Option<Arc<dyn Datagram>>,
    /// Autres adresses à ne pas prendre pour l'IP temporaire (voisins ARP).
    pub in_use: Vec<Ipv4Addr>,
    /// Les autres interfaces actives du poste.
    pub other_ifaces: Vec<ScanInterface>,
}

/// Erreur d'un appel VAPIX → code affiché. `ip` n'est que celle de la caméra visée.
fn from_vapix(e: VapixError, ip: Ipv4Addr) -> ActionError {
    match e {
        VapixError::Net(NetError::Timeout | NetError::Unreachable(_) | NetError::Io(_)) => {
            ActionError::Unreachable { ip }
        }
        VapixError::Net(NetError::Auth | NetError::Status(401 | 403)) => ActionError::AuthFailed,
        VapixError::Net(NetError::Status(status)) => ActionError::HttpStatus { status },
        VapixError::Net(NetError::InsecureBasic) => ActionError::AuthInsecure,
        VapixError::Net(NetError::Cancelled) => ActionError::Unreachable { ip },
        // Seul un texte de la caméra est affiché tel quel.
        VapixError::Rejected(detail) => ActionError::Rejected { detail },
        VapixError::Parse(_) => ActionError::BadReply,
        VapixError::Invalid(reason) => ActionError::Invalid { reason: reason.into() },
    }
}

/// Lit l'identité de la caméra à son adresse actuelle et la compare à celle
/// qu'on croit viser : n° de série si on le connaît, sinon MAC (sur Axis, le
/// n° de série est la MAC sans séparateurs). Sans rien à comparer, ou si
/// l'appareil ne répond pas comme une Axis (autre appareil arrivé à cette
/// adresse), on refuse : la caméra visée n'est pas confirmée.
///
/// AXIS OS < 8.40 n'a pas `basicdeviceinfo.cgi` (404) : le n° de série se lit
/// alors dans `param.cgi` (`creds` seulement si la lecture anonyme est fermée).
pub async fn verify_identity(ctx: &ActionContext, cam: &Camera, creds: &Credentials) -> Result<(), ActionError> {
    if cam.family != Family::Axis {
        return Err(ActionError::Unsupported);
    }
    let unreadable = |e: VapixError| match e {
        VapixError::Parse(_)
        | VapixError::Rejected(_)
        | VapixError::Invalid(_)
        | VapixError::Net(NetError::Status(_) | NetError::Auth) => ActionError::IdentityUnreadable,
        e => from_vapix(e, cam.ip),
    };
    let http = ctx.http.as_ref();
    let base = cam.base_url();
    let serial = match vapix::device_info(http, &base).await {
        Ok(info) => info.serial,
        Err(VapixError::Net(NetError::Status(404))) => {
            Some(vapix::serial_from_params(http, &base, creds).await.map_err(unreadable)?)
        }
        Err(e) => return Err(unreadable(e)),
    };
    let Some(found) = serial.as_deref().map(str::trim) else {
        return Err(ActionError::IdentityUnreadable);
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

/// L'adresse vient du front : elle doit être dans le sous-réseau de l'interface
/// choisie, sinon un webview compromis ferait partir un mot de passe vers un hôte
/// quelconque. Seule exception, `off_subnet_allowed`.
pub fn on_subnet(iface: &ScanInterface, ip: Ipv4Addr) -> bool {
    !needs_temp_ip(iface.ip, iface.mask, ip)
}

/// Hors sous-réseau, une IP temporaire n'est posée que si tout tient :
/// - l'adresse s'est annoncée elle-même au dernier scan, fait sur CETTE
///   interface (le front fournit la caméra, il ne peut pas inventer une cible) ;
/// - c'est une adresse de réseau local (169.254/16 ou RFC 1918) ;
/// - le réseau ouvert par l'IP temporaire (/16 ou /24) ne recouvre celui
///   d'aucune autre interface du poste (sinon le trafic partirait ailleurs).
///
/// Sinon `camera_off_subnet`, avant toute requête et toute invite.
fn off_subnet_allowed(ctx: &ActionContext, ip: Ipv4Addr) -> bool {
    let mask = temp_mask(ip);
    ctx.seen_iface.as_deref() == Some(ctx.iface.name.as_str())
        && ctx.seen.contains(&ip)
        && reachable_with_temp_ip(ip)
        && !ctx
            .other_ifaces
            .iter()
            .filter(|o| o.name != ctx.iface.name)
            .any(|o| subnets_overlap(ip, mask, o.ip, o.mask))
}

fn result(cam: &Camera, outcome: Result<(), ActionError>) -> ActionResult {
    ActionResult {
        key: cam.mac.clone().unwrap_or_else(|| cam.ip.to_string()),
        ok: outcome.is_ok(),
        error: outcome.err(),
    }
}

/// Seule porte d'écriture : marque, sous-réseau (IP temporaire au besoin),
/// identité, puis l'écriture. Une marque sans action (`Other`) ne génère aucune requête ;
/// Hikvision passe par SADP (`apply_sadp`), sans IP temporaire.
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
        Family::Hikvision => return apply_sadp(ctx, cam, creds, action).await,
        Family::Other => return Err(ActionError::Unsupported),
    }
    if on_subnet(&ctx.iface, cam.ip) {
        return verify_and_write(ctx, cam, creds, action).await;
    }
    if !off_subnet_allowed(ctx, cam.ip) {
        return Err(ActionError::CameraOffSubnet);
    }
    let avoid: Vec<Ipv4Addr> = ctx.seen.iter().chain(&ctx.in_use).copied().collect();
    let temp = pick_temp_ip(&ctx.iface.name, cam.ip, &avoid, rand::random())
        .map_err(|_| ActionError::TempIpFailed)?;
    // L'IP temporaire couvre la vérification d'identité ET l'écriture.
    let done = with_temp_ip(ctx.elevator.as_ref(), &ctx.journal, &temp, &ctx.service, || {
        verify_and_write(ctx, cam, creds, action)
    })
    .await;
    match done {
        Ok(outcome) => outcome,
        Err(TempIpError::ElevationRefused) => Err(ActionError::ElevationRefused { ip: cam.ip }),
        Err(TempIpError::Busy) => Err(ActionError::TempIpBusy),
        // Journal encore là : une adresse est restée sur le poste.
        Err(_) => Err(match read_journal(&ctx.journal) {
            Ok(Some(left)) => ActionError::TempIpLeft { ip: left.ip },
            _ => ActionError::TempIpFailed,
        }),
    }
}

/// Délai d'attente de la réponse d'une caméra à une commande SADP.
const SADP_TIMEOUT: Duration = Duration::from_secs(5);

/// Hikvision : SADP pour `Activate` et `Network`, jamais d'IP temporaire (le
/// message va au groupe multicast, la caméra n'a pas besoin d'être joignable
/// en IP). Le mot de passe sera diffusé sur le LAN de l'interface : la MAC doit
/// donc s'être annoncée en SADP, sur cette interface, au dernier scan ; le
/// front fournit la caméra, il ne peut pas inventer une cible. L'identité est
/// la MAC du message, relue dans la réponse.
async fn apply_sadp(
    ctx: &ActionContext,
    cam: &Camera,
    creds: &Credentials,
    action: &Action,
) -> Result<(), ActionError> {
    if matches!(action, Action::Time(_)) {
        return Err(ActionError::Unsupported);
    }
    let (Some(sock), Some(mac)) = (ctx.sadp.as_deref(), cam.mac.as_deref().and_then(normalize_mac)) else {
        return Err(ActionError::Unsupported);
    };
    // Une ligne qui n'a jamais été vue en SADP n'est pas une cible SADP.
    let heard = cam.sources.contains(&Source::Sadp)
        && ctx.seen_iface.as_deref() == Some(ctx.iface.name.as_str()) && ctx.seen_sadp.contains(&mac);
    if !heard {
        return Err(ActionError::CameraNotSeen);
    }
    let uuid = uuid::Uuid::new_v4();
    let msg = match action {
        Action::Activate => sadp::build_activate(uuid, &mac, &creds.password),
        Action::Network(net) => sadp::build_update(uuid, &mac, &creds.password, net),
        Action::Time(_) => None,
    };
    // Sans encodage de mot de passe documenté, rien n'est construit.
    let Some(msg) = msg else { return Err(ActionError::Unsupported) };
    sadp::send_and_wait(sock, &msg, &mac, cam.ip, SADP_TIMEOUT).await
}

async fn verify_and_write(
    ctx: &ActionContext,
    cam: &Camera,
    creds: &Credentials,
    action: &Action,
) -> Result<(), ActionError> {
    verify_identity(ctx, cam, creds).await?;
    let http = ctx.http.as_ref();
    let base = cam.base_url();
    let done = match action {
        Action::Activate => vapix::activate(http, &base, creds).await,
        Action::Network(net) => vapix::set_network(http, &base, creds, net).await,
        Action::Time(t) => vapix::set_time(http, &base, creds, t).await,
    };
    done.map_err(|e| match (action, from_vapix(e, cam.ip)) {
        // Une caméra qui a déjà un compte refuse la création du premier (401).
        (Action::Activate, ActionError::AuthFailed) => ActionError::AlreadyActivated,
        (_, err) => err,
    })
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
        return cams
            .iter()
            .map(|c| result(c, Err(ActionError::NetworkNeedsOneCamera)))
            .collect();
    }
    let mut out = Vec::with_capacity(cams.len());
    for cam in cams {
        out.push(apply(ctx, cam, creds, action).await);
    }
    out
}

/// Applique un plan d'IP en lot : `cams[i]` reçoit `rows[i].new_ip`. Chaque
/// attribution passe par `apply` (sous-réseau, IP temporaire, identité juste
/// avant l'écriture) ; une caméra refusée est sautée, les autres continuent.
/// Une seule ligne de résultat par caméra, dans l'ordre du plan. Un plan qui
/// ne correspond pas aux caméras (longueurs) n'applique rien : `Err("internal")`.
///
/// Les nouvelles adresses du plan rejoignent `in_use` : l'IP temporaire posée
/// pour une caméra hors sous-réseau ne doit pas heurter celle d'une caméra déjà
/// déplacée.
pub async fn apply_batch(
    mut ctx: ActionContext,
    cams: &[Camera],
    rows: &[Assignment],
    creds: &Credentials,
    req: &BatchRequest,
) -> Result<Vec<ActionResult>, String> {
    if cams.len() != rows.len() {
        return Err("internal".into());
    }
    ctx.in_use.extend(rows.iter().map(|r| r.new_ip));
    let mut out = Vec::with_capacity(cams.len());
    for (cam, row) in cams.iter().zip(rows) {
        let action = Action::Network(NetworkSettings::Static {
            ip: row.new_ip,
            mask: req.mask,
            gateway: req.gateway,
            dns: req.dns.clone(),
        });
        out.push(apply(&ctx, cam, creds, &action).await);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Activation, Source};
    use crate::secret::Secret;
    use crate::temp_ip::TempIpError;
    use crate::testing::{FakeElevator, FakeHttp, PanicElevator};
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

    /// Contexte sans élévation possible : un appel ferait échouer le test.
    fn ctx(http: Arc<dyn CameraHttp>) -> ActionContext {
        ctx_with(http, Arc::new(PanicElevator), vec![])
    }

    /// `seen` : adresses entendues par le dernier scan, fait sur `eth0`.
    fn ctx_with(http: Arc<dyn CameraHttp>, elevator: Arc<dyn Elevator>, seen: Vec<Ipv4Addr>) -> ActionContext {
        ActionContext {
            http,
            iface: ScanInterface {
                name: "eth0".into(),
                ip: "192.0.2.2".parse().unwrap(),
                mask: "255.255.255.0".parse().unwrap(),
            },
            service: "eth0".into(),
            elevator,
            journal: std::env::temp_dir()
                .join(format!("lenscout-test-{}", uuid::Uuid::new_v4()))
                .join("temp-ip.json"),
            seen,
            seen_iface: Some("eth0".into()),
            seen_sadp: vec![],
            sadp: None,
            in_use: vec![],
            other_ifaces: vec![],
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
    async fn unreadable_identity_blocks_the_write_with_its_own_code() {
        // Page HTML, 404 (firmware ancien), 401 (accès anonyme fermé) : l'identité
        // n'est pas lisible, rien n'est écrit, et le message ne dit pas « autre caméra ».
        for reply in [
            (|_: &HttpRequest| Ok(HttpResponse { status: 200, headers: vec![], body: b"<html>".to_vec() })) as fn(&HttpRequest) -> _,
            |_| Ok(HttpResponse { status: 404, headers: vec![], body: vec![] }),
            |_| Ok(HttpResponse { status: 401, headers: vec![], body: vec![] }),
            |_| Err(NetError::Auth),
        ] {
            let http = Arc::new(Scripted::new(reply));
            let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
            assert_eq!(r.error, Some(ActionError::IdentityUnreadable));
            // Sur 404, la lecture de repli (param.cgi, AXIS OS < 8.40) part aussi.
            let urls = http.urls.lock().unwrap().clone();
            assert!(urls.iter().all(|u| u.contains("basicdeviceinfo.cgi") || u.contains("action=list")), "{urls:?}");
        }
    }

    /// Caméra scriptée qui voit aussi si des identifiants accompagnent la requête.
    struct WithLogin {
        reply: fn(&HttpRequest, bool) -> Result<HttpResponse, NetError>,
        seen: std::sync::Mutex<Vec<(String, bool)>>,
    }

    impl WithLogin {
        fn new(reply: fn(&HttpRequest, bool) -> Result<HttpResponse, NetError>) -> Self {
            WithLogin { reply, seen: Default::default() }
        }
        fn seen(&self) -> Vec<(String, bool)> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CameraHttp for WithLogin {
        async fn send(&self, req: HttpRequest, c: Option<&Credentials>) -> Result<HttpResponse, NetError> {
            let path = req.url.trim_start_matches("http://192.0.2.11").to_string();
            self.seen.lock().unwrap().push((path, c.is_some()));
            (self.reply)(&req, c.is_some())
        }
        async fn stream(&self, _: HttpRequest, _: Option<&Credentials>) -> Result<(HttpResponse, ByteStream), NetError> {
            Err(NetError::Cancelled)
        }
    }

    fn reply(status: u16, body: &str) -> Result<HttpResponse, NetError> {
        Ok(HttpResponse { status, headers: vec![], body: body.as_bytes().to_vec() })
    }

    const SERIAL_PARAM: &str = "/axis-cgi/param.cgi?action=list&group=Properties.System.SerialNumber";

    /// AXIS OS < 8.40 : pas de basicdeviceinfo.cgi (404), le n° de série se lit
    /// dans `param.cgi`, anonyme d'abord.
    #[tokio::test]
    async fn old_firmware_identity_is_read_from_param_cgi_anonymously() {
        let http = Arc::new(WithLogin::new(|req, _| {
            if req.url.ends_with("basicdeviceinfo.cgi") {
                reply(404, "")
            } else if req.url.contains("action=list") {
                reply(200, "root.Properties.System.SerialNumber=ACCC8E123456\n")
            } else {
                reply(200, "OK")
            }
        }));
        let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
        assert!(r.ok, "{:?}", r.error);
        let seen = http.seen();
        assert_eq!(seen[0], ("/axis-cgi/basicdeviceinfo.cgi".to_string(), false));
        assert_eq!(seen[1], (SERIAL_PARAM.to_string(), false));
    }

    /// Lecture anonyme fermée (401) : la même requête repart avec le compte.
    #[tokio::test]
    async fn old_firmware_identity_retries_param_cgi_with_the_account_on_401() {
        for anonymous in [
            (|_: &HttpRequest| reply(401, "")) as fn(&HttpRequest) -> _,
            |_| Err(NetError::Auth),
        ] {
            thread_local! { static ANON: std::cell::Cell<Option<fn(&HttpRequest) -> Result<HttpResponse, NetError>>> = const { std::cell::Cell::new(None) }; }
            ANON.with(|a| a.set(Some(anonymous)));
            let http = Arc::new(WithLogin::new(|req, with_login| {
                if req.url.ends_with("basicdeviceinfo.cgi") {
                    reply(404, "")
                } else if req.url.contains("action=list") && !with_login {
                    ANON.with(|a| a.get().unwrap())(req)
                } else if req.url.contains("action=list") {
                    reply(200, "root.Properties.System.SerialNumber=ACCC8E123456")
                } else {
                    reply(200, "OK")
                }
            }));
            let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
            assert!(r.ok, "{:?}", r.error);
            let seen = http.seen();
            assert_eq!(seen[1], (SERIAL_PARAM.to_string(), false));
            assert_eq!(seen[2], (SERIAL_PARAM.to_string(), true));
        }
    }

    #[tokio::test]
    async fn old_firmware_identity_still_blocks_a_mismatch_or_an_unreadable_serial() {
        let other = Arc::new(WithLogin::new(|req, _| {
            if req.url.ends_with("basicdeviceinfo.cgi") {
                reply(404, "")
            } else if req.url.contains("action=list") {
                reply(200, "root.Properties.System.SerialNumber=ACCC8E999999")
            } else {
                reply(200, "OK")
            }
        }));
        let r = apply(&ctx(other.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &time()).await;
        assert_eq!(r.error, Some(ActionError::IdentityMismatch));
        assert_eq!(other.seen().len(), 2, "rien n'est écrit");
        for body in ["# Error: Error -1 getting param in group 'Properties.System.SerialNumber'", "", "<html>"] {
            thread_local! { static BODY: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") }; }
            BODY.with(|b| b.set(body));
            let http = Arc::new(WithLogin::new(|req, _| {
                if req.url.ends_with("basicdeviceinfo.cgi") {
                    reply(404, "")
                } else {
                    reply(200, BODY.with(|b| b.get()))
                }
            }));
            let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &time()).await;
            assert_eq!(r.error, Some(ActionError::IdentityUnreadable), "{body}");
        }
    }

    /// Seul un texte venu de la caméra part en `detail` : le reste est un code
    /// que le front traduit (aucun texte français affiché en en/es).
    #[test]
    fn local_and_transport_errors_become_codes() {
        let ip: Ipv4Addr = "192.0.2.11".parse().unwrap();
        assert_eq!(
            from_vapix(VapixError::Invalid("gateway_is_ip"), ip),
            ActionError::Invalid { reason: "gateway_is_ip".into() }
        );
        assert_eq!(from_vapix(VapixError::Net(NetError::Status(500)), ip), ActionError::HttpStatus { status: 500 });
        assert_eq!(from_vapix(VapixError::Net(NetError::InsecureBasic), ip), ActionError::AuthInsecure);
        assert_eq!(from_vapix(VapixError::Parse("expected value".into()), ip), ActionError::BadReply);
        assert_eq!(from_vapix(VapixError::Net(NetError::Cancelled), ip), ActionError::Unreachable { ip });
        assert_eq!(
            from_vapix(VapixError::Rejected("# Error: x".into()), ip),
            ActionError::Rejected { detail: "# Error: x".into() }
        );
        assert_eq!(
            serde_json::to_string(&ActionError::Invalid { reason: "too_many_dns".into() }).unwrap(),
            r#"{"code":"invalid","reason":"too_many_dns"}"#
        );
    }

    #[tokio::test]
    async fn camera_outside_the_interface_subnet_gets_no_request() {
        // Le front fournit l'adresse : une IP hors du sous-réseau de l'interface
        // ne reçoit rien, surtout pas un mot de passe.
        let http = Arc::new(axis_ok());
        for ip in ["198.51.100.5", "192.0.3.11", "10.0.0.1"] {
            for action in [Action::Activate, static_net(), time()] {
                let r = apply(&ctx(http.clone()), &cam(ip, Family::Axis), &creds(), &action).await;
                assert_eq!(r.error, Some(ActionError::CameraOffSubnet), "{ip}");
            }
        }
        assert!(http.requests().is_empty());
        // Dans le sous-réseau : accepté.
        assert!(apply(&ctx(http.clone()), &cam("192.0.2.200", Family::Axis), &creds(), &time()).await.ok);
    }

    #[tokio::test]
    async fn activate_on_an_activated_camera_says_so() {
        let http = Arc::new(Scripted::new(|req| {
            if req.url.ends_with("basicdeviceinfo.cgi") {
                Ok(HttpResponse { status: 200, headers: vec![], body: INFO.to_vec() })
            } else {
                Err(NetError::Auth)
            }
        }));
        let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::AlreadyActivated));
        // Un refus d'authentification d'une autre action reste AuthFailed.
        let r = apply(&ctx(http), &cam("192.0.2.11", Family::Axis), &creds(), &time()).await;
        assert_eq!(r.error, Some(ActionError::AuthFailed));
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
                "https://192.0.2.12/axis-cgi/pwdgrp.cgi",
                "http://192.0.2.11/axis-cgi/basicdeviceinfo.cgi",
                "https://192.0.2.11/axis-cgi/pwdgrp.cgi",
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
        assert!(http.inner.requests().iter().any(|r| r.url == "https://192.0.2.12/axis-cgi/pwdgrp.cgi"));
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

    /// Contexte Hikvision : socket SADP faux, MAC entendue en SADP sur `eth0`
    /// si `heard`. Un Elevator qui panique : jamais d'IP temporaire.
    fn sadp_ctx(http: Arc<dyn CameraHttp>, heard: bool) -> (ActionContext, Arc<crate::testing::FakeDatagram>) {
        let dg = Arc::new(crate::testing::FakeDatagram::new(vec![]));
        let mut c = ctx(http);
        c.sadp = Some(dg.clone());
        if heard {
            c.seen_sadp = vec![MAC.into()];
        }
        (c, dg)
    }

    /// Hors sous-réseau, jamais d'`with_temp_ip` : `PanicElevator` panique au premier appel.
    fn off_subnet_hik() -> Camera {
        let mut c = cam("169.254.10.20", Family::Hikvision);
        c.sources = vec![Source::Mdns, Source::Sadp];
        c
    }

    #[tokio::test]
    async fn hikvision_time_is_unsupported() {
        let http = Arc::new(axis_ok());
        let (c, dg) = sadp_ctx(http.clone(), true);
        let r = apply(&c, &cam("192.0.2.11", Family::Hikvision), &creds(), &time()).await;
        assert_eq!(r.error, Some(ActionError::Unsupported));
        assert!(http.requests().is_empty());
        assert!(dg.sent().is_empty());
    }

    #[tokio::test]
    async fn hikvision_activate_uses_sadp_not_http() {
        let http = Arc::new(axis_ok());
        let (c, _) = sadp_ctx(http.clone(), true);
        for action in [Action::Activate, static_net()] {
            let r = apply(&c, &off_subnet_hik(), &creds(), &action).await;
            // Sans encodage de mot de passe documenté : rien ne part, nulle part.
            assert_eq!(r.error, Some(ActionError::Unsupported));
        }
        assert!(http.requests().is_empty(), "ISAPI/VAPIX non utilisés");
    }

    #[tokio::test]
    async fn hikvision_not_heard_over_sadp_is_refused_before_any_send() {
        let http = Arc::new(axis_ok());
        for action in [Action::Activate, static_net()] {
            // MAC jamais entendue.
            let (c, dg) = sadp_ctx(http.clone(), false);
            let r = apply(&c, &off_subnet_hik(), &creds(), &action).await;
            assert_eq!(r.error, Some(ActionError::CameraNotSeen));
            assert!(dg.sent().is_empty());
            // Entendue, mais lors d'un scan fait sur une autre interface.
            let (mut c, dg) = sadp_ctx(http.clone(), true);
            c.seen_iface = Some("wlan0".into());
            let r = apply(&c, &off_subnet_hik(), &creds(), &action).await;
            assert_eq!(r.error, Some(ActionError::CameraNotSeen));
            assert!(dg.sent().is_empty());
        }
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn hikvision_row_never_seen_over_sadp_is_refused() {
        let (c, dg) = sadp_ctx(Arc::new(axis_ok()), true);
        let mut cam = off_subnet_hik();
        cam.sources = vec![Source::Mdns];
        let r = apply(&c, &cam, &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::CameraNotSeen));
        assert!(dg.sent().is_empty());
    }

    #[tokio::test]
    async fn hikvision_without_sadp_socket_is_unsupported() {
        let r = apply(&ctx(Arc::new(axis_ok())), &cam("192.0.2.11", Family::Hikvision), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::Unsupported));
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
        assert!(out.iter().all(|r| !r.ok && r.error == Some(ActionError::NetworkNeedsOneCamera)));
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
        assert_eq!(r.error, Some(ActionError::Invalid { reason: "ip_unusable".into() }));
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

    fn ll_cam() -> Camera {
        cam("169.254.10.20", Family::Axis)
    }

    #[tokio::test]
    async fn out_of_subnet_refused_elevation_reports_ip() {
        let http = Arc::new(axis_ok());
        let elev = Arc::new(FakeElevator::replying(vec![Err(TempIpError::ElevationRefused)]));
        let c = ctx_with(http.clone(), elev.clone(), vec![ll_cam().ip]);
        let r = apply(&c, &ll_cam(), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::ElevationRefused { ip: "169.254.10.20".parse().unwrap() }));
        assert!(http.requests().is_empty(), "aucune requête HTTP");
        assert_eq!(elev.plans().len(), 1, "l'ajout seul, refusé");
        assert!(!c.journal.exists());
    }

    #[tokio::test]
    async fn off_subnet_ip_not_seen_by_the_scan_gets_no_elevation_nor_request() {
        // Le webview fournit la caméra : une adresse que Rust n'a pas vue au
        // dernier scan ne justifie ni invite ni requête, même en 169.254.
        let http = Arc::new(axis_ok());
        let seen_other = vec!["169.254.1.1".parse().unwrap(), "192.0.2.11".parse().unwrap()];
        for ip in ["169.254.10.20", "192.168.0.90", "10.0.0.1"] {
            let c = ctx_with(http.clone(), Arc::new(PanicElevator), seen_other.clone());
            let r = apply(&c, &cam(ip, Family::Axis), &creds(), &Action::Activate).await;
            assert_eq!(r.error, Some(ActionError::CameraOffSubnet), "{ip}");
        }
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn off_subnet_public_ip_is_refused_even_when_seen() {
        let http = Arc::new(axis_ok());
        for ip in ["198.51.100.5", "8.8.8.8", "172.32.0.1"] {
            let c = ctx_with(http.clone(), Arc::new(PanicElevator), vec![ip.parse().unwrap()]);
            let r = apply(&c, &cam(ip, Family::Axis), &creds(), &Action::Activate).await;
            assert_eq!(r.error, Some(ActionError::CameraOffSubnet), "{ip}");
        }
        assert!(http.requests().is_empty());
    }

    /// Note, à chaque requête, combien de plans l'élévateur a déjà reçus.
    struct Watch {
        inner: FakeHttp,
        elev: Arc<FakeElevator>,
        plans_at: std::sync::Mutex<Vec<usize>>,
    }

    #[async_trait]
    impl CameraHttp for Watch {
        async fn send(&self, req: HttpRequest, c: Option<&Credentials>) -> Result<HttpResponse, NetError> {
            self.plans_at.lock().unwrap().push(self.elev.plans().len());
            self.inner.send(req, c).await
        }
        async fn stream(&self, req: HttpRequest, c: Option<&Credentials>) -> Result<(HttpResponse, ByteStream), NetError> {
            self.inner.stream(req, c).await
        }
    }

    #[tokio::test]
    async fn seen_link_local_camera_is_reached_through_a_temp_ip() {
        let elev = Arc::new(FakeElevator::new());
        let http = Arc::new(Watch { inner: axis_ok(), elev: elev.clone(), plans_at: Default::default() });
        let seen: Vec<Ipv4Addr> = vec![ll_cam().ip, "192.0.2.11".parse().unwrap()];
        let c = ctx_with(http.clone(), elev.clone(), seen.clone());
        let r = apply(&c, &ll_cam(), &creds(), &Action::Activate).await;
        assert!(r.ok, "{r:?}");
        // Lecture d'identité ET écriture, toutes deux entre l'ajout et le retrait.
        let urls: Vec<String> = http.inner.requests().into_iter().map(|r| r.url).collect();
        assert_eq!(
            urls,
            ["http://169.254.10.20/axis-cgi/basicdeviceinfo.cgi", "https://169.254.10.20/axis-cgi/pwdgrp.cgi"]
        );
        assert_eq!(*http.plans_at.lock().unwrap(), vec![1, 1]);
        let plans = elev.plans();
        assert_eq!(plans.len(), 2);
        assert_ne!(plans[0], plans[1], "un ajout puis un retrait");
        assert!(!c.journal.exists());
    }

    fn plan_for(ip: &str, mask: &str) -> crate::temp_ip::ElevatedPlan {
        crate::temp_ip::add_plan(
            crate::temp_ip::OsKind::current(),
            &crate::temp_ip::TempIp { iface: "eth0".into(), ip: ip.parse().unwrap(), mask: mask.parse().unwrap() },
            "eth0",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn temp_ip_avoids_the_camera_seen_addresses_and_arp_neighbours() {
        let elev = Arc::new(FakeElevator::new());
        let mut c = ctx_with(Arc::new(axis_ok()), elev.clone(), vec!["192.168.0.90".parse().unwrap(), "192.168.0.250".parse().unwrap()]);
        // Voisins ARP de l'interface : .200 à .248.
        c.in_use = (200..=248).map(|d| Ipv4Addr::new(192, 168, 0, d)).collect();
        assert!(apply(&c, &cam("192.168.0.90", Family::Axis), &creds(), &time()).await.ok);
        assert_eq!(elev.plans()[0], plan_for("192.168.0.249", "255.255.255.0"));
    }

    #[tokio::test]
    async fn seen_on_another_interface_gets_no_temp_ip() {
        let http = Arc::new(axis_ok());
        for seen_iface in [Some("wlan0".to_string()), None] {
            let mut c = ctx_with(http.clone(), Arc::new(PanicElevator), vec![ll_cam().ip]);
            c.seen_iface = seen_iface;
            let r = apply(&c, &ll_cam(), &creds(), &Action::Activate).await;
            assert_eq!(r.error, Some(ActionError::CameraOffSubnet));
        }
        assert!(http.requests().is_empty());
    }

    fn other(name: &str, ip: &str, mask: &str) -> ScanInterface {
        ScanInterface { name: name.into(), ip: ip.parse().unwrap(), mask: mask.parse().unwrap() }
    }

    #[tokio::test]
    async fn camera_subnet_overlapping_another_interface_is_refused() {
        let http = Arc::new(axis_ok());
        for (camera, iface) in [
            ("192.168.0.90", other("wlan0", "192.168.0.10", "255.255.255.0")),
            ("192.168.0.90", other("wlan0", "192.168.0.10", "255.255.0.0")),
            ("192.168.0.90", other("wlan0", "192.168.0.130", "255.255.255.128")),
            ("169.254.10.20", other("eth1", "169.254.77.1", "255.255.0.0")),
            ("169.254.10.20", other("eth1", "169.254.77.1", "255.255.255.0")),
        ] {
            let mut c = ctx_with(http.clone(), Arc::new(PanicElevator), vec![camera.parse().unwrap()]);
            c.other_ifaces = vec![other("lo", "127.0.0.1", "255.0.0.0"), iface.clone()];
            let r = apply(&c, &cam(camera, Family::Axis), &creds(), &Action::Activate).await;
            assert_eq!(r.error, Some(ActionError::CameraOffSubnet), "{camera} / {iface:?}");
        }
        assert!(http.requests().is_empty());
        // Une autre interface sans recouvrement ne gêne pas.
        let elev = Arc::new(FakeElevator::new());
        let mut c = ctx_with(Arc::new(axis_ok()), elev.clone(), vec!["192.168.0.90".parse().unwrap()]);
        c.other_ifaces = vec![other("wlan0", "192.168.1.10", "255.255.255.0")];
        assert!(apply(&c, &cam("192.168.0.90", Family::Axis), &creds(), &time()).await.ok);
        assert_eq!(elev.plans().len(), 2);
    }

    #[tokio::test]
    async fn busy_temp_ip_lock_is_reported_without_request() {
        let http = Arc::new(axis_ok());
        let c = ctx_with(http.clone(), Arc::new(PanicElevator), vec![ll_cam().ip]);
        std::fs::create_dir_all(c.journal.parent().unwrap()).unwrap();
        let held = std::fs::File::create(crate::temp_ip::lock_path(&c.journal)).unwrap();
        held.lock().unwrap();
        let r = apply(&c, &ll_cam(), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::TempIpBusy));
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn temp_ip_left_on_the_computer_is_reported() {
        let elev = Arc::new(FakeElevator::replying(vec![Ok(()), Err(TempIpError::Failed("netsh".into()))]));
        let c = ctx_with(Arc::new(axis_ok()), elev, vec![ll_cam().ip]);
        let r = apply(&c, &ll_cam(), &creds(), &Action::Activate).await;
        let Some(ActionError::TempIpLeft { ip }) = r.error else { panic!("{r:?}") };
        assert_eq!(ip.octets()[..2], [169, 254]);
        assert!(c.journal.exists(), "gardé pour le retrait au démarrage");
    }

    #[tokio::test]
    async fn temp_ip_that_cannot_be_added_is_reported_without_request() {
        let elev = Arc::new(FakeElevator::replying(vec![Err(TempIpError::Failed("x".into()))]));
        let http = Arc::new(axis_ok());
        let c = ctx_with(http.clone(), elev, vec![ll_cam().ip]);
        let r = apply(&c, &ll_cam(), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::TempIpFailed));
        assert!(http.requests().is_empty());
    }

    #[test]
    fn action_error_json_has_no_password() {
        let ip: Ipv4Addr = "192.0.2.11".parse().unwrap();
        let all = [
            ActionError::Unsupported,
            ActionError::IdentityMismatch,
            ActionError::IdentityUnreadable,
            ActionError::CameraOffSubnet,
            ActionError::CameraNotSeen,
            ActionError::AlreadyActivated,
            ActionError::NetworkNeedsOneCamera,
            ActionError::Unreachable { ip },
            ActionError::AuthFailed,
            ActionError::Rejected { detail: "Error: invalid password.".into() },
            ActionError::ElevationRefused { ip },
            ActionError::TempIpFailed,
            ActionError::TempIpLeft { ip },
            ActionError::TempIpBusy,
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

    /// Une caméra par adresse : `serials` associe l'hôte au n° de série qu'elle annonce.
    struct PerHost {
        inner: FakeHttp,
        serials: Vec<(&'static str, &'static str)>,
    }

    #[async_trait]
    impl CameraHttp for PerHost {
        async fn send(&self, req: HttpRequest, c: Option<&Credentials>) -> Result<HttpResponse, NetError> {
            if req.url.ends_with("/axis-cgi/basicdeviceinfo.cgi")
                && let Some((_, serial)) = self.serials.iter().find(|(h, _)| req.url.contains(h))
            {
                let body = String::from_utf8_lossy(INFO).replace(SERIAL, serial);
                // Passe par `inner` pour que la requête soit enregistrée.
                self.inner.send(req.clone(), c).await.ok();
                return Ok(HttpResponse { status: 200, headers: vec![], body: body.into_bytes() });
            }
            self.inner.send(req, c).await
        }
        async fn stream(&self, req: HttpRequest, c: Option<&Credentials>) -> Result<(HttpResponse, ByteStream), NetError> {
            self.inner.stream(req, c).await
        }
    }

    fn batch_cam(last: u8, mac: &str) -> Camera {
        let mut c = cam(&format!("192.0.2.{last}"), Family::Axis);
        c.mac = Some(mac.into());
        c
    }

    fn batch_plan(cams: &[Camera]) -> (BatchRequest, Vec<Assignment>) {
        let req = BatchRequest {
            start: "192.0.2.101".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            gateway: Some("192.0.2.1".parse().unwrap()),
            dns: vec![],
        };
        let rows = crate::batch::plan_batch(cams, &req, &[], &[]).unwrap();
        (req, rows)
    }

    #[tokio::test]
    async fn batch_writes_each_assignment_to_its_own_camera_only() {
        let (a, b) = (batch_cam(11, "AC:CC:8E:12:34:56"), batch_cam(12, "AC:CC:8E:12:34:57"));
        let http = Arc::new(PerHost { inner: axis_ok(), serials: vec![("192.0.2.12", "ACCC8E123457")] });
        let (req, rows) = batch_plan(&[a.clone(), b.clone()]);
        let out = apply_batch(ctx(http.clone()), &[a, b], &rows, &creds(), &req).await.unwrap();
        assert!(out.iter().all(|r| r.ok), "{out:?}");
        let hosts: Vec<String> = http.inner.requests().into_iter().map(|r| r.url).collect();
        assert!(hosts.iter().all(|u| u.contains("192.0.2.11") || u.contains("192.0.2.12")), "{hosts:?}");
        let bodies: Vec<String> = http
            .inner
            .requests()
            .into_iter()
            .filter(|r| r.url.ends_with("/axis-cgi/param.cgi"))
            .map(|r| String::from_utf8(r.body).unwrap())
            .collect();
        assert_eq!(bodies.len(), 2);
        assert!(bodies[0].contains("Network.IPAddress=192.0.2.101"), "{}", bodies[0]);
        assert!(bodies[1].contains("Network.IPAddress=192.0.2.102"), "{}", bodies[1]);
    }

    #[tokio::test]
    async fn batch_skips_camera_whose_identity_changed() {
        let (a, b) = (batch_cam(11, "AC:CC:8E:12:34:56"), batch_cam(12, "AC:CC:8E:12:34:57"));
        // B répond avec la série d'une autre caméra.
        let http = Arc::new(PerHost { inner: axis_ok(), serials: vec![("192.0.2.12", "ACCC8E999999")] });
        let (req, rows) = batch_plan(&[a.clone(), b.clone()]);
        let out = apply_batch(ctx(http.clone()), &[a, b], &rows, &creds(), &req).await.unwrap();
        assert_eq!(out.len(), 2);
        assert!(out[0].ok);
        assert_eq!(out[1].error, Some(ActionError::IdentityMismatch));
        let to_b_writes = http
            .inner
            .requests()
            .into_iter()
            .filter(|r| r.url.contains("192.0.2.12") && !r.url.ends_with("/axis-cgi/basicdeviceinfo.cgi"))
            .count();
        assert_eq!(to_b_writes, 0);
    }

    #[tokio::test]
    async fn batch_first_failure_does_not_stop_the_next() {
        // A est injoignable : B est quand même traitée.
        let (a, b) = (batch_cam(11, "AC:CC:8E:12:34:56"), batch_cam(12, "AC:CC:8E:12:34:57"));
        let http = Arc::new(DeadHost {
            inner: axis_ok(),
            dead: "192.0.2.11",
        });
        let (req, rows) = batch_plan(&[a.clone(), b.clone()]);
        let out = apply_batch(ctx(http), &[a, b], &rows, &creds(), &req).await.unwrap();
        assert!(matches!(out[0].error, Some(ActionError::Unreachable { .. })));
        // B répond avec la série de la MAC de A : l'identité de B ne correspond pas, mais elle a bien été tentée.
        assert_eq!(out[1].error, Some(ActionError::IdentityMismatch));
    }

    #[tokio::test]
    async fn batch_temp_ip_avoids_the_new_addresses_of_the_plan() {
        // Deux caméras hors sous-réseau, même /24 ; leurs nouvelles IP sont
        // .200 et .201. Les voisins occupent .203 à .250 : seule .202 convient.
        let mut a = cam("192.168.0.90", Family::Axis);
        a.mac = Some("AC:CC:8E:12:34:56".into());
        let b = a.clone();
        let mut b = Camera { ip: "192.168.0.91".parse().unwrap(), ..b };
        b.mac = Some("AC:CC:8E:12:34:56".into());
        let req = BatchRequest {
            start: "192.168.0.200".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            gateway: None,
            dns: vec![],
        };
        let rows = crate::batch::plan_batch(&[a.clone(), b.clone()], &req, &[], &[]).unwrap();
        // Le tirage est aléatoire : plusieurs essais pour qu'une collision se voie.
        for _ in 0..12 {
            let elev = Arc::new(FakeElevator::new());
            let mut c = ctx_with(Arc::new(axis_ok()), elev.clone(), vec![a.ip, b.ip]);
            c.in_use = (203..=250).map(|d| Ipv4Addr::new(192, 168, 0, d)).collect();
            let out = apply_batch(c, &[a.clone(), b.clone()], &rows, &creds(), &req).await.unwrap();
            assert!(out.iter().all(|r| r.ok), "{out:?}");
            let plans = elev.plans();
            assert_eq!(plans.len(), 4);
            assert_eq!(plans[0], plan_for("192.168.0.202", "255.255.255.0"));
            assert_eq!(plans[2], plan_for("192.168.0.202", "255.255.255.0"));
        }
    }

    #[tokio::test]
    async fn batch_length_mismatch_applies_nothing() {
        let a = batch_cam(11, "AC:CC:8E:12:34:56");
        let http = Arc::new(axis_ok());
        let (req, rows) = batch_plan(std::slice::from_ref(&a));
        let two = [a.clone(), batch_cam(12, "AC:CC:8E:12:34:57")];
        assert!(apply_batch(ctx(http.clone()), &two, &rows, &creds(), &req).await.is_err());
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn batch_camera_keeping_its_own_ip_is_still_written() {
        let a = batch_cam(11, "AC:CC:8E:12:34:56");
        let http = Arc::new(axis_ok());
        let req = BatchRequest {
            start: "192.0.2.11".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            gateway: None,
            dns: vec![],
        };
        let rows = crate::batch::plan_batch(std::slice::from_ref(&a), &req, &[], &[]).unwrap();
        let out = apply_batch(ctx(http.clone()), &[a], &rows, &creds(), &req).await.unwrap();
        assert!(out[0].ok, "{out:?}");
        let body = http.requests().into_iter().find(|r| r.url.ends_with("/axis-cgi/param.cgi")).unwrap();
        assert!(String::from_utf8(body.body).unwrap().contains("Network.IPAddress=192.0.2.11"));
    }
}
