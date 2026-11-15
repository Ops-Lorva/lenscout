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
use crate::discovery::arp::{Neighbours, ScanInterface};
use crate::model::{Activation, Camera, Family, Source, mac_from_serial, normalize_mac};
use crate::oui::camera_brand_for_mac;
use crate::temp_ip::{
    Elevator, TempIpError, needs_temp_ip, pick_temp_ip, reachable_with_temp_ip, read_journal, subnets_overlap,
    temp_mask, with_temp_ip,
};
use crate::discovery::sadp;
use crate::isapi;
use crate::route::{Route, Routes};
use crate::transport::{CameraHttp, Credentials, Datagram, NetError};
use std::time::Duration;
use crate::vapix::{self, NetworkSettings, ResetMode, TimeSettings, VapixError};

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Premier compte, en https seulement.
    Activate,
    /// `Activate` dont l'envoi en http clair, si https ne se connecte pas, a
    /// été confirmé par le technicien pour CETTE caméra (jamais un lot).
    ActivateCleartext,
    Network(NetworkSettings),
    Time(TimeSettings),
    /// Réinitialisation d'usine, avec le compte : Axis par VAPIX, Hikvision
    /// par ISAPI. Peut viser un lot.
    FactoryReset(ResetMode),
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
    /// L'IP d'un compte est posée sur le poste (écran Réseau) : elle tient
    /// l'IP temporaire. Revenir sur DHCP pour joindre cette caméra.
    #[error("réseau d'un compte en cours")]
    AccountNetworkActive,
    /// Activation : https injoignable. Rien n'est parti ; le technicien peut
    /// confirmer l'envoi en clair pour cette caméra.
    #[error("https injoignable : envoi en clair à confirmer")]
    ActivationCleartext,
    /// Activation d'un appareil que le dernier scan n'a pas lu neuf
    /// (`needsetup=yes`) : rien n'est envoyé.
    #[error("caméra pas lue neuve au scan")]
    NotNew,
    /// Activation : la MAC vue en couche 2 (table ARP) n'est pas d'un OUI
    /// Axis, ou l'adresse n'a pas d'entrée ARP. Le mot de passe ne part pas.
    #[error("MAC non Axis en couche 2")]
    MacNotAxis,
    /// Activation à travers le routeur : la MAC que la caméra déclare (son
    /// n° de série, relu à l'instant) n'a pas la forme d'une MAC ou n'est pas
    /// d'un OUI Axis. Le mot de passe ne part pas.
    #[error("MAC déclarée non Axis")]
    DeclaredMacNotAxis,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ActionResult {
    /// MAC de la caméra, sinon son IP : la clé de la ligne côté front.
    pub key: String,
    pub ok: bool,
    pub error: Option<ActionError>,
}

/// Ce que le dernier scan a lu d'une ligne : sa clé (MAC, sinon IP, comme
/// `ActionResult::key`), son adresse, son état d'activation.
#[derive(Debug, Clone, PartialEq)]
pub struct SeenState {
    pub key: String,
    pub ip: Ipv4Addr,
    pub activation: Activation,
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
    /// Une IP de compte est posée (« Se mettre dans ce réseau ») : elle
    /// tient le verrou de l'IP temporaire.
    pub account_network: bool,
    /// État d'activation de chaque ligne au dernier scan (`seen_iface`),
    /// tenu par Rust : le front ne peut pas en inventer.
    pub seen_states: Vec<SeenState>,
    /// Table ARP : la MAC de couche 2 d'une caméra avant l'envoi d'un mot de
    /// passe d'activation.
    pub neighbours: Arc<dyn Neighbours>,
    /// Adresses qui ont répondu au balayage HTTP du réseau routé, au dernier
    /// scan (`seen_iface`), tenues par Rust.
    pub seen_routed: Vec<Ipv4Addr>,
    /// Route du poste vers une caméra, demandée au moment de l'action.
    pub routes: Arc<dyn Routes>,
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
        VapixError::Net(NetError::Cancelled | NetError::Denied) => ActionError::Unreachable { ip },
        // Seul un texte de la caméra est affiché tel quel.
        VapixError::Rejected(detail) => ActionError::Rejected { detail },
        VapixError::Parse(_) => ActionError::BadReply,
        VapixError::Invalid(reason) => ActionError::Invalid { reason: reason.into() },
        VapixError::Cleartext => ActionError::ActivationCleartext,
    }
}

/// Clé de la ligne d'une caméra : sa MAC, sinon son IP.
pub fn row_key(cam: &Camera) -> String {
    cam.mac.clone().unwrap_or_else(|| cam.ip.to_string())
}

fn is_activation(action: &Action) -> bool {
    matches!(action, Action::Activate | Action::ActivateCleartext)
}

/// État de la ligne lu par le dernier scan, fait sur CETTE interface, à
/// CETTE adresse ; `None` si le scan ne l'a pas vue ainsi.
fn scan_state(ctx: &ActionContext, cam: &Camera) -> Option<Activation> {
    if ctx.seen_iface.as_deref() != Some(ctx.iface.name.as_str()) {
        return None;
    }
    let key = row_key(cam);
    ctx.seen_states.iter().find(|s| s.key == key && s.ip == cam.ip).map(|s| s.activation)
}

fn is_axis_mac(mac: &str) -> bool {
    matches!(camera_brand_for_mac(mac), Some((Family::Axis, _)))
}

/// La MAC de couche 2 de la caméra (pas celle qu'elle annonce) est d'un OUI
/// Axis ; si l'adresse figure sous plusieurs cartes, toutes ses MAC doivent
/// l'être. Relève la barre face à un faux appareil, sans plus : une MAC se change.
async fn layer2_is_axis(ctx: &ActionContext, cam: &Camera) -> bool {
    let macs = ctx.neighbours.macs_of(&ctx.iface, cam.ip).await;
    !macs.is_empty() && macs.iter().all(|mac| is_axis_mac(mac))
}

/// Lit l'identité de la caméra à son adresse actuelle et la compare à celle
/// qu'on croit viser : n° de série si on le connaît, sinon MAC (sur Axis, le
/// n° de série est la MAC sans séparateurs). Sans rien à comparer, ou si
/// l'appareil ne répond pas comme une Axis (autre appareil arrivé à cette
/// adresse), on refuse : la caméra visée n'est pas confirmée.
///
/// AXIS OS < 8.40 n'a pas `basicdeviceinfo.cgi` (404) : le n° de série se lit
/// alors dans `param.cgi` (`creds` seulement si la lecture anonyme est fermée).
///
/// `creds` à `None` (activation) : rien du compte ne part, et un refus
/// d'authentification dit que la caméra a déjà un compte : `not_new`.
///
/// Rend le n° de série lu, celui qui vient d'être confirmé.
pub async fn verify_identity(ctx: &ActionContext, cam: &Camera, creds: Option<&Credentials>) -> Result<String, ActionError> {
    if cam.family != Family::Axis {
        return Err(ActionError::Unsupported);
    }
    let unreadable = |e: VapixError| match e {
        VapixError::Net(NetError::Auth | NetError::Status(401 | 403)) if creds.is_none() => ActionError::NotNew,
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
    if same { Ok(found.to_string()) } else { Err(ActionError::IdentityMismatch) }
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

/// Mode routé : une caméra hors du sous-réseau de l'interface est jointe à
/// travers le routeur, SANS IP temporaire, si tout tient :
/// - c'est une adresse privée (RFC 1918) ;
/// - elle a répondu au balayage du réseau routé au dernier scan (`seen_routed`,
///   tenu par Rust : le front ne peut pas inventer une cible) ;
/// - la route du poste vers elle passe, À CET INSTANT, par une passerelle.
///
/// Les adresses sont vérifiées avant la route : une caméra que rien ne
/// désigne ne coûte pas une commande système.
pub async fn routed_allowed(routes: &dyn Routes, seen_routed: &[Ipv4Addr], ip: Ipv4Addr) -> bool {
    ip.is_private() && seen_routed.contains(&ip) && matches!(routes.route_to(ip).await, Route::Routed(_))
}

/// `routed_allowed` pour une action : le dernier scan doit être celui de
/// cette interface.
async fn routed_for(ctx: &ActionContext, ip: Ipv4Addr) -> bool {
    ctx.seen_iface.as_deref() == Some(ctx.iface.name.as_str()) && routed_allowed(ctx.routes.as_ref(), &ctx.seen_routed, ip).await
}

/// Jointe sans IP temporaire : dans le sous-réseau de l'interface, ou à
/// travers le routeur (`routed_for`). Seule condition pour qu'une lecture
/// avec le compte parte vers elle hors d'une action (aperçu d'une opération).
pub async fn direct(ctx: &ActionContext, ip: Ipv4Addr) -> bool {
    on_subnet(&ctx.iface, ip) || routed_for(ctx, ip).await
}

fn result(cam: &Camera, outcome: Result<(), ActionError>) -> ActionResult {
    ActionResult {
        key: row_key(cam),
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
        Family::Hikvision => {
            return match action {
                Action::FactoryReset(mode) => reset_isapi(ctx, cam, creds, *mode).await,
                _ => apply_sadp(ctx, cam, creds, action).await,
            };
        }
        Family::Other => return Err(ActionError::Unsupported),
    }
    // Le routeur joint la caméra : ni IP temporaire, ni invite ; l'identité
    // (n° de série, la MAC ne passe pas le routeur) est relue comme ailleurs.
    let on = on_subnet(&ctx.iface, cam.ip) || routed_for(ctx, cam.ip).await;
    if !on && !off_subnet_allowed(ctx, cam.ip) {
        return Err(ActionError::CameraOffSubnet);
    }
    if !on && ctx.account_network {
        return Err(ActionError::AccountNetworkActive);
    }
    // Lue activée, ou jamais vue à cette adresse : refusé avant toute requête
    // et toute invite. Inconnue (caméra hors sous-réseau que le scan n'a pas
    // pu interroger) : l'état est relu au moment de l'action.
    if is_activation(action) && !matches!(scan_state(ctx, cam), Some(Activation::New | Activation::Unknown)) {
        return Err(ActionError::NotNew);
    }
    if on {
        let routed = !on_subnet(&ctx.iface, cam.ip);
        return verify_and_write(ctx, cam, creds, action, routed).await;
    }
    let avoid: Vec<Ipv4Addr> = ctx.seen.iter().chain(&ctx.in_use).copied().collect();
    let temp = pick_temp_ip(&ctx.iface.name, cam.ip, &avoid, rand::random())
        .map_err(|_| ActionError::TempIpFailed)?;
    // L'IP temporaire couvre la vérification d'identité ET l'écriture.
    let done = with_temp_ip(ctx.elevator.as_ref(), &ctx.journal, &temp, &ctx.service, || {
        verify_and_write(ctx, cam, creds, action, false)
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
    // SADP dit l'état lui-même : seule une ligne lue neuve s'active.
    if is_activation(action) && scan_state(ctx, cam) != Some(Activation::New) {
        return Err(ActionError::NotNew);
    }
    let uuid = uuid::Uuid::new_v4();
    let msg = match action {
        Action::Activate | Action::ActivateCleartext => sadp::build_activate(uuid, &mac, &creds.password),
        Action::Network(net) => sadp::build_update(uuid, &mac, &creds.password, net),
        Action::Time(_) | Action::FactoryReset(_) => None,
    };
    // Sans encodage de mot de passe documenté, rien n'est construit.
    let Some(msg) = msg else { return Err(ActionError::Unsupported) };
    sadp::send_and_wait(sock, &msg, &mac, cam.ip, SADP_TIMEOUT).await
}

/// Hikvision, réinitialisation : ISAPI en HTTP avec le compte, donc dans le
/// sous-réseau ou à travers le routeur (`routed_allowed`), jamais par une IP
/// temporaire, et vers une caméra que le dernier scan a entendue, sur cette
/// interface : depuis son adresse, sa MAC en SADP, ou au balayage routé.
/// L'identité (MAC, sinon n° de série) est relue avec le compte juste avant
/// l'ordre.
async fn reset_isapi(ctx: &ActionContext, cam: &Camera, creds: &Credentials, mode: ResetMode) -> Result<(), ActionError> {
    let routed = !on_subnet(&ctx.iface, cam.ip) && routed_for(ctx, cam.ip).await;
    if !on_subnet(&ctx.iface, cam.ip) && !routed {
        return Err(ActionError::CameraOffSubnet);
    }
    let mac = cam.mac.as_deref().and_then(normalize_mac);
    let heard = ctx.seen_iface.as_deref() == Some(ctx.iface.name.as_str())
        && (ctx.seen.contains(&cam.ip) || routed || mac.as_ref().is_some_and(|m| ctx.seen_sadp.contains(m)));
    if !heard {
        return Err(ActionError::CameraNotSeen);
    }
    let (http, base) = (ctx.http.as_ref(), cam.base_url());
    let id = isapi::device_identity(http, &base, creds).await.map_err(|e| match e {
        VapixError::Parse(_) | VapixError::Rejected(_) => ActionError::IdentityUnreadable,
        e => from_vapix(e, cam.ip),
    })?;
    let same = match (&mac, &id.mac, cam.serial.as_deref(), id.serial.as_deref()) {
        (Some(a), Some(b), _, _) => a == b,
        (_, _, Some(a), Some(b)) => a.trim().eq_ignore_ascii_case(b.trim()),
        _ => false,
    };
    if !same {
        return Err(ActionError::IdentityMismatch);
    }
    isapi::factory_reset(http, &base, creds, mode).await.map_err(|e| from_vapix(e, cam.ip))
}

/// `routed` : la caméra est jointe à travers le routeur (`routed_for`).
async fn verify_and_write(
    ctx: &ActionContext,
    cam: &Camera,
    creds: &Credentials,
    action: &Action,
    routed: bool,
) -> Result<(), ActionError> {
    let cleartext = match action {
        Action::Activate => false,
        Action::ActivateCleartext => true,
        _ => {
            verify_identity(ctx, cam, Some(creds)).await?;
            let (http, base) = (ctx.http.as_ref(), cam.base_url());
            let done = match action {
                Action::Network(net) => vapix::set_network(http, &base, creds, net).await,
                Action::Time(t) => vapix::set_time(http, &base, creds, t).await,
                Action::FactoryReset(mode) => vapix::factory_default(http, &base, creds, *mode).await,
                Action::Activate | Action::ActivateCleartext => return Err(ActionError::Unsupported),
            };
            return done.map_err(|e| from_vapix(e, cam.ip));
        }
    };
    activate_checked(ctx, cam, creds, cleartext, routed).await
}

/// Activation : rien du compte ne part avant que tout soit vérifié.
/// 1. identité, lue sans compte (une caméra neuve n'en a aucun : un refus
///    dit qu'elle n'est pas neuve) ;
/// 2. MAC de couche 2 d'un OUI Axis ; à travers le routeur, où la couche 2
///    ne passe pas, la MAC que la caméra déclare : le n° de série relu en 1
///    (sur Axis, c'est la MAC), s'il en a exactement la forme ;
/// 3. état « neuve » relu à l'instant, sans compte (`needsetup=yes`) ;
/// 4. alors seulement le mot de passe.
async fn activate_checked(ctx: &ActionContext, cam: &Camera, creds: &Credentials, cleartext: bool, routed: bool) -> Result<(), ActionError> {
    let serial = verify_identity(ctx, cam, None).await?;
    let axis = if routed {
        mac_from_serial(&serial).is_some_and(|mac| is_axis_mac(&mac))
    } else {
        layer2_is_axis(ctx, cam).await
    };
    if !axis {
        return Err(if routed { ActionError::DeclaredMacNotAxis } else { ActionError::MacNotAxis });
    }
    let (http, base) = (ctx.http.as_ref(), cam.base_url());
    if vapix::activation_state(http, &base).await != Activation::New {
        return Err(ActionError::NotNew);
    }
    vapix::activate(http, &base, creds, cleartext).await.map_err(|e| match from_vapix(e, cam.ip) {
        // Une caméra qui a déjà un compte refuse la création du premier (401).
        ActionError::AuthFailed => ActionError::AlreadyActivated,
        err => err,
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
    // Le changement d'IP, comme l'envoi en clair (confirmé caméra par
    // caméra), ne vise qu'une caméra.
    if matches!(action, Action::Network(_) | Action::ActivateCleartext) && cams.len() > 1 {
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
    use crate::testing::{FakeElevator, FakeHttp, FakeNeighbours, FakeRoutes, PanicElevator};
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
            addressing: None,
            declared_mac: None,
        }
    }

    /// Contexte sans élévation possible : un appel ferait échouer le test.
    fn ctx(http: Arc<dyn CameraHttp>) -> TestCtx {
        ctx_with(http, Arc::new(PanicElevator), vec![])
    }

    /// `seen` : adresses entendues par le dernier scan, fait sur `eth0`.
    fn ctx_with(http: Arc<dyn CameraHttp>, elevator: Arc<dyn Elevator>, seen: Vec<Ipv4Addr>) -> TestCtx {
        let journal = crate::testing::UncreatedFile::new("lenscout-test", "temp-ip.json");
        let c = ActionContext {
            http,
            iface: ScanInterface {
                name: "eth0".into(),
                ip: "192.0.2.2".parse().unwrap(),
                mask: "255.255.255.0".parse().unwrap(),
            },
            service: "eth0".into(),
            elevator,
            journal: journal.to_path_buf(),
            seen,
            seen_iface: Some("eth0".into()),
            seen_sadp: vec![],
            sadp: None,
            in_use: vec![],
            other_ifaces: vec![],
            account_network: false,
            seen_states: scan_states(Activation::New),
            neighbours: Arc::new(FakeNeighbours::any(MAC)),
            seen_routed: vec![],
            routes: Arc::new(FakeRoutes::new(Route::Unknown)),
        };
        TestCtx { c, _journal: journal }
    }

    /// Ce que le dernier scan (sur `eth0`) a lu pour la MAC de test, aux
    /// adresses des tests, et pour la ligne sans MAC en 192.0.2.11.
    fn scan_states(activation: Activation) -> Vec<SeenState> {
        let mut out: Vec<SeenState> = ["192.0.2.11", "192.0.2.12", "192.0.2.200", "169.254.10.20", "192.168.0.90", "192.168.0.91"]
            .iter()
            .map(|ip| SeenState { key: MAC.into(), ip: ip.parse().unwrap(), activation })
            .collect();
        out.push(SeenState { key: "192.0.2.11".into(), ip: "192.0.2.11".parse().unwrap(), activation });
        out
    }

    const NEEDSETUP_YES: &str = r#"{"apiVersion":"1.1","data":{"needsetup":"yes","systemready":"yes"}}"#;
    const NEEDSETUP_NO: &str = r#"{"apiVersion":"1.1","data":{"needsetup":"no","systemready":"yes"}}"#;

    /// Le contexte d'un test ; le dossier du journal part avec lui.
    struct TestCtx {
        c: ActionContext,
        _journal: crate::testing::UncreatedFile,
    }

    impl std::ops::Deref for TestCtx {
        type Target = ActionContext;
        fn deref(&self) -> &ActionContext {
            &self.c
        }
    }

    impl std::ops::DerefMut for TestCtx {
        fn deref_mut(&mut self) -> &mut ActionContext {
            &mut self.c
        }
    }

    /// Une Axis qui accepte tout, dont le n° de série est `SERIAL`.
    fn axis_ok() -> FakeHttp {
        FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO.to_vec())
            .on(Method::Post, "/axis-cgi/systemready.cgi", 200, NEEDSETUP_YES)
            .on(Method::Post, "/axis-cgi/pwdgrp.cgi", 200, "Created account root.")
            .on(Method::Post, "/axis-cgi/param.cgi", 200, "OK")
            .on(Method::Post, "/axis-cgi/time.cgi", 200, r#"{"data":{}}"#)
            .on(Method::Post, "/axis-cgi/ntp.cgi", 200, r#"{"data":{}}"#)
    }

    /// Les requêtes qui modifient la caméra (tout sauf les lectures d'identité et d'état).
    fn writes(http: &FakeHttp) -> Vec<String> {
        http.requests()
            .into_iter()
            .filter(|r| !r.url.ends_with("/axis-cgi/basicdeviceinfo.cgi") && !r.url.ends_with("/axis-cgi/systemready.cgi"))
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
            let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &time()).await;
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

    /// Réponse de la caméra à la lecture anonyme de `param.cgi`.
    type AnonReply = fn(&HttpRequest) -> Result<HttpResponse, NetError>;

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
            thread_local! { static ANON: std::cell::Cell<Option<AnonReply>> = const { std::cell::Cell::new(None) }; }
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
            let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &static_net()).await;
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
        // Relue au moment de l'action : elle a déjà un compte (refus partout).
        let http = Arc::new(Scripted::new(|req| {
            if req.url.ends_with("basicdeviceinfo.cgi") {
                Ok(HttpResponse { status: 200, headers: vec![], body: INFO.to_vec() })
            } else {
                Err(NetError::Auth)
            }
        }));
        let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::NotNew));
        assert!(!http.urls.lock().unwrap().iter().any(|u| u.starts_with("https://")), "aucun mot de passe");
        // Lue neuve, puis le premier compte refusé (401) : déjà activée entre-temps.
        let raced = Arc::new(Scripted::new(|req| {
            if req.url.ends_with("basicdeviceinfo.cgi") {
                Ok(HttpResponse { status: 200, headers: vec![], body: INFO.to_vec() })
            } else if req.url.ends_with("systemready.cgi") {
                Ok(HttpResponse { status: 200, headers: vec![], body: NEEDSETUP_YES.as_bytes().to_vec() })
            } else {
                Err(NetError::Auth)
            }
        }));
        let r = apply(&ctx(raced), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
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
                "http://192.0.2.12/axis-cgi/systemready.cgi",
                "https://192.0.2.12/axis-cgi/pwdgrp.cgi",
                "http://192.0.2.11/axis-cgi/basicdeviceinfo.cgi",
                "http://192.0.2.11/axis-cgi/systemready.cgi",
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
    fn sadp_ctx(http: Arc<dyn CameraHttp>, heard: bool) -> (TestCtx, Arc<crate::testing::FakeDatagram>) {
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

    fn keep_ip() -> Action {
        Action::FactoryReset(ResetMode::KeepIp)
    }

    #[tokio::test]
    async fn axis_reset_checks_identity_then_sends_the_cgi_with_the_account() {
        for (mode, path) in [(ResetMode::KeepIp, "/axis-cgi/factorydefault.cgi"), (ResetMode::Full, "/axis-cgi/hardfactorydefault.cgi")] {
            let http = Arc::new(axis_ok().on(Method::Get, path, 200, "OK"));
            let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &Action::FactoryReset(mode)).await;
            assert!(r.ok, "{:?}", r.error);
            let reqs = http.requests();
            assert!(reqs[0].url.ends_with("/axis-cgi/basicdeviceinfo.cgi"), "identité d'abord");
            let reset = reqs.last().unwrap();
            assert_eq!((reset.method, reset.url.as_str()), (Method::Get, format!("http://192.0.2.11{path}").as_str()));
            assert_eq!(reset.login.as_deref(), Some("root"));
        }
    }

    #[tokio::test]
    async fn axis_reset_never_reaches_another_camera() {
        let other = String::from_utf8_lossy(INFO).replace(SERIAL, "ACCC8E999999");
        let http = Arc::new(
            FakeHttp::new()
                .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, other.into_bytes())
                .on(Method::Get, "/axis-cgi/factorydefault.cgi", 200, "OK"),
        );
        let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &keep_ip()).await;
        assert_eq!(r.error, Some(ActionError::IdentityMismatch));
        assert!(http.requests().iter().all(|r| !r.url.contains("factorydefault")));
    }

    #[tokio::test]
    async fn axis_reset_refused_or_silent_is_reported() {
        let http = Arc::new(axis_ok().on(Method::Get, "/axis-cgi/factorydefault.cgi", 401, ""));
        let r = apply(&ctx(http), &cam("192.0.2.11", Family::Axis), &creds(), &keep_ip()).await;
        assert_eq!(r.error, Some(ActionError::AuthFailed));
        let http = Arc::new(Scripted::new(|req| {
            if req.url.ends_with("basicdeviceinfo.cgi") {
                Ok(HttpResponse { status: 200, headers: vec![], body: INFO.to_vec() })
            } else {
                Err(NetError::Timeout)
            }
        }));
        let r = apply(&ctx(http), &cam("192.0.2.11", Family::Axis), &creds(), &keep_ip()).await;
        assert_eq!(r.error, Some(ActionError::Unreachable { ip: "192.0.2.11".parse().unwrap() }));
    }

    const HIK_INFO: &str = "<DeviceInfo><serialNumber>DS-1</serialNumber><macAddress>ac:cc:8e:12:34:56</macAddress></DeviceInfo>";

    #[tokio::test]
    async fn hikvision_reset_goes_through_isapi_after_its_mac_is_confirmed() {
        let http = Arc::new(
            FakeHttp::new()
                .on(Method::Get, "/ISAPI/System/deviceInfo", 200, HIK_INFO)
                .on(Method::Put, "/ISAPI/System/factoryReset", 200, "<ResponseStatus><statusCode>1</statusCode></ResponseStatus>"),
        );
        let ip: Ipv4Addr = "192.0.2.11".parse().unwrap();
        let (c, dg) = sadp_ctx(http.clone(), true);
        let r = apply(&c, &cam("192.0.2.11", Family::Hikvision), &creds(), &Action::FactoryReset(ResetMode::Full)).await;
        assert!(r.ok, "{:?}", r.error);
        let last = http.requests().pop().unwrap();
        assert_eq!((last.method, last.url.as_str()), (Method::Put, "http://192.0.2.11/ISAPI/System/factoryReset?mode=full"));
        assert_eq!(last.login.as_deref(), Some("root"));
        assert!(dg.sent().is_empty(), "rien en SADP");
        // Entendue depuis son adresse (sans SADP) : aussi une cible.
        let mut c = ctx(http.clone());
        c.seen = vec![ip];
        assert!(apply(&c, &cam("192.0.2.11", Family::Hikvision), &creds(), &keep_ip()).await.ok);
    }

    #[tokio::test]
    async fn hikvision_reset_refuses_an_unconfirmed_target() {
        let other = HIK_INFO.replace("ac:cc:8e:12:34:56", "c0:56:e3:00:00:01");
        let http = Arc::new(
            FakeHttp::new()
                .on(Method::Get, "/ISAPI/System/deviceInfo", 200, other)
                .on(Method::Put, "/ISAPI/System/factoryReset", 200, ""),
        );
        let (c, _) = sadp_ctx(http.clone(), true);
        let r = apply(&c, &cam("192.0.2.11", Family::Hikvision), &creds(), &keep_ip()).await;
        assert_eq!(r.error, Some(ActionError::IdentityMismatch));
        // Jamais vue au scan : le compte ne part pas.
        let (c, _) = sadp_ctx(http.clone(), false);
        let r = apply(&c, &cam("192.0.2.11", Family::Hikvision), &creds(), &keep_ip()).await;
        assert_eq!(r.error, Some(ActionError::CameraNotSeen));
        // Hors sous-réseau : pas d'IP temporaire pour ISAPI.
        let (c, _) = sadp_ctx(http.clone(), true);
        let r = apply(&c, &off_subnet_hik(), &creds(), &keep_ip()).await;
        assert_eq!(r.error, Some(ActionError::CameraOffSubnet));
        assert!(http.requests().iter().all(|r| r.method != Method::Put));
    }

    #[tokio::test]
    async fn a_reset_can_target_several_cameras() {
        let http = Arc::new(axis_ok().on(Method::Get, "/axis-cgi/factorydefault.cgi", 200, "OK"));
        let cams = [cam("192.0.2.11", Family::Axis), cam("192.0.2.12", Family::Axis)];
        let out = apply_all(&ctx(http.clone()), &cams, &creds(), &keep_ip()).await;
        assert!(out.iter().all(|r| r.ok), "{out:?}");
        assert_eq!(http.requests().iter().filter(|r| r.url.contains("factorydefault")).count(), 2);
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
                .on(Method::Post, "/axis-cgi/systemready.cgi", 200, NEEDSETUP_YES)
                .on(Method::Post, "/axis-cgi/pwdgrp.cgi", 200, "Error: invalid password."),
        );
        let r = apply(&ctx(http), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::Rejected { detail: "Error: invalid password.".into() }));
    }

    /// L'état lu au scan, tenu par Rust, sur CETTE interface et à CETTE
    /// adresse : « activée » ou absent → refusé avant toute requête. Le front
    /// ne peut rien y changer.
    #[tokio::test]
    async fn activate_is_refused_when_the_scan_read_it_activated_or_never_saw_it() {
        let http = Arc::new(axis_ok());
        let mut activated = ctx(http.clone());
        activated.seen_states = scan_states(Activation::Activated);
        let mut empty = ctx(http.clone());
        empty.seen_states.clear();
        let mut other_iface = ctx(http.clone());
        other_iface.seen_iface = Some("wlan0".into());
        for c in [&activated, &empty, &other_iface] {
            for action in [Action::Activate, Action::ActivateCleartext] {
                let r = apply(c, &cam("192.0.2.11", Family::Axis), &creds(), &action).await;
                assert_eq!(r.error, Some(ActionError::NotNew));
            }
        }
        // La MAC d'une caméra neuve associée par le front à une autre adresse.
        let r = apply(&ctx(http.clone()), &cam("192.0.2.77", Family::Axis), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::NotNew));
        assert!(http.requests().is_empty());
        // Les autres actions ne changent pas.
        assert!(apply(&activated, &cam("192.0.2.11", Family::Axis), &creds(), &time()).await.ok);
    }

    /// État inconnu au scan (Axis neuve hors du sous-réseau, joignable par
    /// l'IP temporaire seulement) : relu au moment de l'action, sans compte,
    /// après le contrôle MAC ; le mot de passe ne part que si `needsetup=yes`.
    #[tokio::test]
    async fn unknown_at_scan_is_activated_only_if_the_camera_says_new_now() {
        for (body, expected) in [(NEEDSETUP_YES, None), (NEEDSETUP_NO, Some(ActionError::NotNew))] {
            let http = Arc::new(
                FakeHttp::new()
                    .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO.to_vec())
                    .on(Method::Post, "/axis-cgi/systemready.cgi", 200, body)
                    .on(Method::Post, "/axis-cgi/pwdgrp.cgi", 200, "Created account root."),
            );
            let mut c = ctx(http.clone());
            c.seen_states = scan_states(Activation::Unknown);
            let mut front = cam("192.0.2.11", Family::Axis);
            front.activation = Activation::Unknown;
            let r = apply(&c, &front, &creds(), &Action::Activate).await;
            assert_eq!(r.error, expected);
            let urls: Vec<String> = http.requests().into_iter().map(|r| r.url).collect();
            assert_eq!(urls.iter().any(|u| u.ends_with("pwdgrp.cgi")), expected.is_none(), "{urls:?}");
            assert!(http.requests().iter().all(|r| r.login.is_none()), "aucune requête avec le compte");
        }
        // Un état illisible au moment de l'action ne vaut pas « neuve ».
        let http = Arc::new(FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO.to_vec()));
        let mut c = ctx(http.clone());
        c.seen_states = scan_states(Activation::Unknown);
        let r = apply(&c, &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::NotNew));
    }

    /// Faux appareil à MAC non Axis qui imite une Axis < 8.40 : 404 sur
    /// basicdeviceinfo, puis 401 Digest sur param.cgi. Rien du compte ne lui
    /// est envoyé, pas même une réponse Digest.
    #[tokio::test]
    async fn activation_never_sends_the_account_before_the_mac_check() {
        for anonymous_serial in [false, true] {
            thread_local! { static SERIAL_OK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
            SERIAL_OK.with(|s| s.set(anonymous_serial));
            let http = Arc::new(WithLogin::new(|req, with_login| {
                if req.url.ends_with("basicdeviceinfo.cgi") {
                    reply(404, "")
                } else if req.url.contains("action=list") && (with_login || SERIAL_OK.with(|s| s.get())) {
                    reply(200, "root.Properties.System.SerialNumber=ACCC8E123456")
                } else if req.url.contains("action=list") {
                    Ok(HttpResponse { status: 401, headers: vec![("WWW-Authenticate".into(), "Digest realm=\"x\", nonce=\"n\"".into())], body: vec![] })
                } else {
                    reply(200, "Created account root.")
                }
            }));
            let mut c = ctx(http.clone());
            c.neighbours = Arc::new(FakeNeighbours::table(&[("192.0.2.11", "A4:5E:60:11:22:33")]));
            for action in [Action::Activate, Action::ActivateCleartext] {
                let r = apply(&c, &cam("192.0.2.11", Family::Axis), &creds(), &action).await;
                let want = if anonymous_serial { ActionError::MacNotAxis } else { ActionError::NotNew };
                assert_eq!(r.error, Some(want));
            }
            let seen = http.seen();
            assert!(seen.iter().all(|(_, with_login)| !with_login), "{seen:?}");
            assert!(!seen.iter().any(|(p, _)| p.contains("pwdgrp") || p.contains("systemready")), "{seen:?}");
        }
    }

    /// L'envoi en clair se confirme caméra par caméra : sur une liste, rien ne part.
    #[tokio::test]
    async fn cleartext_activation_on_several_cameras_sends_nothing() {
        let http = Arc::new(axis_ok());
        let cams = [cam("192.0.2.11", Family::Axis), cam("192.0.2.12", Family::Axis)];
        let out = apply_all(&ctx(http.clone()), &cams, &creds(), &Action::ActivateCleartext).await;
        assert!(out.iter().all(|r| r.error == Some(ActionError::NetworkNeedsOneCamera)), "{out:?}");
        assert!(http.requests().is_empty());
        let one = apply_all(&ctx(http.clone()), &cams[..1], &creds(), &Action::ActivateCleartext).await;
        assert!(one[0].ok, "{one:?}");
    }

    /// Le mot de passe ne part que si la MAC vue en couche 2 (table ARP) est
    /// d'un OUI Axis ; une MAC absente de la table est refusée aussi.
    #[tokio::test]
    async fn activate_needs_an_axis_mac_in_the_arp_table() {
        for table in [
            FakeNeighbours::table(&[]),
            FakeNeighbours::table(&[("192.0.2.11", "A4:5E:60:11:22:33")]),
            FakeNeighbours::table(&[("192.0.2.12", MAC)]),
            // La même IP sous deux cartes (Windows) : toutes doivent être Axis.
            FakeNeighbours::table(&[("192.0.2.11", "A4:5E:60:11:22:33"), ("192.0.2.11", MAC)]),
            FakeNeighbours::table(&[("192.0.2.11", MAC), ("192.0.2.11", "A4:5E:60:11:22:33")]),
        ] {
            let http = Arc::new(axis_ok());
            let mut c = ctx(http.clone());
            c.neighbours = Arc::new(table);
            for action in [Action::Activate, Action::ActivateCleartext] {
                let r = apply(&c, &cam("192.0.2.11", Family::Axis), &creds(), &action).await;
                assert_eq!(r.error, Some(ActionError::MacNotAxis));
            }
            assert!(writes(&http).is_empty(), "aucun mot de passe envoyé");
            // Les autres actions ne lisent pas l'ARP.
            assert!(apply(&c, &cam("192.0.2.11", Family::Axis), &creds(), &time()).await.ok);
        }
        let http = Arc::new(axis_ok());
        let mut c = ctx(http.clone());
        c.neighbours = Arc::new(FakeNeighbours::table(&[("192.0.2.11", "00:40:8C:01:02:03")]));
        assert!(apply(&c, &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await.ok);
        let http = Arc::new(axis_ok());
        let mut c = ctx(http.clone());
        c.neighbours = Arc::new(FakeNeighbours::table(&[("192.0.2.11", "00:40:8C:01:02:03"), ("192.0.2.11", MAC)]));
        assert!(apply(&c, &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await.ok);
    }

    /// https injoignable : `activation_cleartext`, rien en clair ; seule
    /// l'action confirmée pour cette caméra repasse en http.
    #[tokio::test]
    async fn https_unreachable_activation_asks_before_sending_in_cleartext() {
        let http = Arc::new(Scripted::new(|req| {
            if req.url.starts_with("https://") {
                Err(NetError::Unreachable("443 fermé".into()))
            } else if req.url.ends_with("basicdeviceinfo.cgi") {
                Ok(HttpResponse { status: 200, headers: vec![], body: INFO.to_vec() })
            } else {
                Ok(HttpResponse { status: 200, headers: vec![], body: b"Created account root.".to_vec() })
            }
        }));
        let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::ActivationCleartext));
        let urls = http.urls.lock().unwrap().clone();
        assert!(!urls.contains(&"http://192.0.2.11/axis-cgi/pwdgrp.cgi".to_string()), "{urls:?}");
        let r = apply(&ctx(http.clone()), &cam("192.0.2.11", Family::Axis), &creds(), &Action::ActivateCleartext).await;
        assert!(r.ok, "{r:?}");
        assert!(http.urls.lock().unwrap().contains(&"http://192.0.2.11/axis-cgi/pwdgrp.cgi".to_string()));
    }

    #[test]
    fn cleartext_refusal_becomes_its_own_code() {
        let ip: Ipv4Addr = "192.0.2.11".parse().unwrap();
        assert_eq!(from_vapix(VapixError::Cleartext, ip), ActionError::ActivationCleartext);
        assert_eq!(serde_json::to_string(&ActionError::ActivationCleartext).unwrap(), r#"{"code":"activation_cleartext"}"#);
        assert_eq!(serde_json::to_string(&ActionError::NotNew).unwrap(), r#"{"code":"not_new"}"#);
        assert_eq!(serde_json::to_string(&ActionError::MacNotAxis).unwrap(), r#"{"code":"mac_not_axis"}"#);
        assert_eq!(serde_json::to_string(&ActionError::DeclaredMacNotAxis).unwrap(), r#"{"code":"declared_mac_not_axis"}"#);
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
            [
                "http://169.254.10.20/axis-cgi/basicdeviceinfo.cgi",
                "http://169.254.10.20/axis-cgi/systemready.cgi",
                "https://169.254.10.20/axis-cgi/pwdgrp.cgi"
            ]
        );
        assert_eq!(*http.plans_at.lock().unwrap(), vec![1, 1, 1]);
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
    async fn account_network_on_the_computer_has_its_own_code() {
        // L'IP d'un compte est posée (« réseau du compte ») : pas d'IP
        // temporaire, et pas le message d'une autre fenêtre.
        let http = Arc::new(axis_ok());
        let mut c = ctx_with(http.clone(), Arc::new(PanicElevator), vec![ll_cam().ip]);
        c.account_network = true;
        let r = apply(&c, &ll_cam(), &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::AccountNetworkActive));
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
            ActionError::AccountNetworkActive,
            ActionError::ActivationCleartext,
            ActionError::NotNew,
            ActionError::MacNotAxis,
            ActionError::DeclaredMacNotAxis,
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
        let rows = crate::batch::plan_batch(cams, &req, &[], &[], &Default::default()).unwrap();
        (req, rows)
    }

    #[tokio::test]
    async fn batch_writes_each_assignment_to_its_own_camera_only() {
        let (a, b) = (batch_cam(11, "AC:CC:8E:12:34:56"), batch_cam(12, "AC:CC:8E:12:34:57"));
        let http = Arc::new(PerHost { inner: axis_ok(), serials: vec![("192.0.2.12", "ACCC8E123457")] });
        let (req, rows) = batch_plan(&[a.clone(), b.clone()]);
        let out = apply_batch(ctx(http.clone()).c, &[a, b], &rows, &creds(), &req).await.unwrap();
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
        let out = apply_batch(ctx(http.clone()).c, &[a, b], &rows, &creds(), &req).await.unwrap();
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
        let out = apply_batch(ctx(http).c, &[a, b], &rows, &creds(), &req).await.unwrap();
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
        let rows = crate::batch::plan_batch(&[a.clone(), b.clone()], &req, &[], &[], &Default::default()).unwrap();
        // Le tirage est aléatoire : plusieurs essais pour qu'une collision se voie.
        for _ in 0..12 {
            let elev = Arc::new(FakeElevator::new());
            let mut c = ctx_with(Arc::new(axis_ok()), elev.clone(), vec![a.ip, b.ip]);
            c.in_use = (203..=250).map(|d| Ipv4Addr::new(192, 168, 0, d)).collect();
            let out = apply_batch(c.c, &[a.clone(), b.clone()], &rows, &creds(), &req).await.unwrap();
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
        assert!(apply_batch(ctx(http.clone()).c, &two, &rows, &creds(), &req).await.is_err());
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
        let rows = crate::batch::plan_batch(std::slice::from_ref(&a), &req, &[], &[], &Default::default()).unwrap();
        let out = apply_batch(ctx(http.clone()).c, &[a], &rows, &creds(), &req).await.unwrap();
        assert!(out[0].ok, "{out:?}");
        let body = http.requests().into_iter().find(|r| r.url.ends_with("/axis-cgi/param.cgi")).unwrap();
        assert!(String::from_utf8(body.body).unwrap().contains("Network.IPAddress=192.0.2.11"));
    }

    /// Caméra du réseau routé (10.0.20.0/24, l'interface est en 192.0.2.0/24),
    /// vue au balayage HTTP : sans MAC, avec son n° de série.
    fn routed_cam(family: Family) -> Camera {
        let mut c = cam("10.0.20.11", family);
        c.mac = None;
        c.serial = Some(if family == Family::Axis { SERIAL.into() } else { "DS-1".into() });
        c.sources = vec![Source::Http];
        c.activation = Activation::Activated;
        c
    }

    /// Contexte du mode routé : l'adresse a répondu au balayage routé et la
    /// route vers elle passe par `route`. `PanicElevator` : jamais d'IP temporaire.
    fn routed_ctx(http: Arc<dyn CameraHttp>, route: Route) -> (TestCtx, Arc<FakeRoutes>) {
        let routes = Arc::new(FakeRoutes::new(route));
        let mut c = ctx(http);
        c.seen_routed = vec!["10.0.20.11".parse().unwrap()];
        c.routes = routes.clone();
        (c, routes)
    }

    #[tokio::test]
    async fn routed_camera_is_configured_through_the_router_without_temp_ip() {
        let http = Arc::new(axis_ok());
        let (c, routes) = routed_ctx(http.clone(), Route::Routed("192.0.2.1".parse().unwrap()));
        let r = apply(&c, &routed_cam(Family::Axis), &creds(), &time()).await;
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(r.key, "10.0.20.11", "sans MAC, la clé est l'IP");
        let reqs = http.requests();
        assert!(reqs[0].url.ends_with("/axis-cgi/basicdeviceinfo.cgi"), "identité d'abord");
        assert!(reqs.iter().all(|r| r.url.starts_with("http://10.0.20.11/")));
        assert!(!writes(&http).is_empty());
        // La route est relue à l'action, pour cette adresse.
        assert_eq!(routes.asked(), vec!["10.0.20.11".parse::<Ipv4Addr>().unwrap()]);
    }

    #[tokio::test]
    async fn routed_camera_identity_is_its_serial() {
        let other = String::from_utf8_lossy(INFO).replace(SERIAL, "ACCC8E999999");
        let http = Arc::new(FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, other.into_bytes()));
        let (c, _) = routed_ctx(http.clone(), Route::Routed("192.0.2.1".parse().unwrap()));
        let r = apply(&c, &routed_cam(Family::Axis), &creds(), &time()).await;
        assert_eq!(r.error, Some(ActionError::IdentityMismatch));
        // Ni n° de série ni MAC : rien à comparer, rien n'est écrit.
        let mut blind = routed_cam(Family::Axis);
        blind.serial = None;
        let r = apply(&c, &blind, &creds(), &time()).await;
        assert_eq!(r.error, Some(ActionError::IdentityMismatch));
        assert!(writes(&http).is_empty());
    }

    #[tokio::test]
    async fn routed_needs_a_route_by_a_gateway_now_a_routed_answer_and_a_private_address() {
        let gw = Route::Routed("192.0.2.1".parse().unwrap());
        // Sur le lien, ou route illisible : comme avant (hors sous-réseau, pas vue en couche 2).
        for route in [Route::OnLink("eth0".into()), Route::Unknown] {
            let http = Arc::new(axis_ok());
            let (c, _) = routed_ctx(http.clone(), route.clone());
            let r = apply(&c, &routed_cam(Family::Axis), &creds(), &time()).await;
            assert_eq!(r.error, Some(ActionError::CameraOffSubnet), "{route:?}");
            assert!(http.requests().is_empty(), "{route:?}");
        }
        // Pas entendue au balayage routé : la route n'est même pas demandée.
        let http = Arc::new(axis_ok());
        let (mut c, routes) = routed_ctx(http.clone(), gw.clone());
        c.seen_routed.clear();
        assert_eq!(apply(&c, &routed_cam(Family::Axis), &creds(), &time()).await.error, Some(ActionError::CameraOffSubnet));
        assert!(routes.asked().is_empty());
        // Adresse publique, même « entendue » et routée.
        let (mut c, _) = routed_ctx(http.clone(), gw.clone());
        c.seen_routed = vec!["203.0.113.5".parse().unwrap()];
        let mut public = routed_cam(Family::Axis);
        public.ip = "203.0.113.5".parse().unwrap();
        assert_eq!(apply(&c, &public, &creds(), &time()).await.error, Some(ActionError::CameraOffSubnet));
        // Balayage fait sur une autre interface.
        let (mut c, _) = routed_ctx(http.clone(), gw);
        c.seen_iface = Some("wlan0".into());
        assert_eq!(apply(&c, &routed_cam(Family::Axis), &creds(), &time()).await.error, Some(ActionError::CameraOffSubnet));
        assert!(http.requests().is_empty(), "aucun compte n'est parti");
    }

    /// Contexte routé où le dernier scan a lu la caméra routée neuve (sa clé
    /// est son IP : elle n'a pas de MAC vue) ; table ARP vide, elle ne passe
    /// pas le routeur.
    fn routed_new_ctx(http: Arc<dyn CameraHttp>) -> TestCtx {
        let (mut c, _) = routed_ctx(http, Route::Routed("192.0.2.1".parse().unwrap()));
        c.seen_states.push(SeenState { key: "10.0.20.11".into(), ip: "10.0.20.11".parse().unwrap(), activation: Activation::New });
        c.neighbours = Arc::new(FakeNeighbours::table(&[]));
        c
    }

    fn routed_new_cam(serial: &str) -> Camera {
        let mut c = routed_cam(Family::Axis);
        c.serial = Some(serial.into());
        c.activation = Activation::New;
        c
    }

    fn info_with_serial(serial: &str) -> Vec<u8> {
        String::from_utf8_lossy(INFO).replace(SERIAL, serial).into_bytes()
    }

    /// À travers le routeur, la MAC ne se lit pas en couche 2 : celle que la
    /// caméra déclare (son n° de série, relu à l'instant sans compte) passe le
    /// même contrôle d'OUI Axis.
    #[tokio::test]
    async fn routed_axis_is_activated_on_the_mac_its_serial_declares() {
        let http = Arc::new(axis_ok());
        let c = routed_new_ctx(http.clone());
        let r = apply(&c, &routed_new_cam(SERIAL), &creds(), &Action::Activate).await;
        assert!(r.ok, "{:?}", r.error);
        let urls: Vec<String> = http.requests().into_iter().map(|r| r.url).collect();
        assert!(urls[0].ends_with("/axis-cgi/basicdeviceinfo.cgi"), "n° de série relu d'abord : {urls:?}");
        assert!(urls.iter().any(|u| u.ends_with("://10.0.20.11/axis-cgi/pwdgrp.cgi")), "{urls:?}");
    }

    /// N° de série absent, restreint, d'une autre forme ou d'un OUI non Axis :
    /// rien du compte ne part.
    #[tokio::test]
    async fn routed_activation_is_refused_without_an_axis_serial() {
        let no_serial = String::from_utf8_lossy(INFO).replace(&format!(r#""SerialNumber": "{SERIAL}","#), "").into_bytes();
        assert!(!String::from_utf8_lossy(&no_serial).contains("SerialNumber"));
        let cases: Vec<(FakeHttp, &str, ActionError)> = vec![
            (FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, no_serial), SERIAL, ActionError::IdentityUnreadable),
            (FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 401, ""), SERIAL, ActionError::NotNew),
            (FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, info_with_serial("ACCC8E12345")), "ACCC8E12345", ActionError::DeclaredMacNotAxis),
            (FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, info_with_serial("ACCC8E12345X")), "ACCC8E12345X", ActionError::DeclaredMacNotAxis),
            (FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, info_with_serial("A45E60112233")), "A45E60112233", ActionError::DeclaredMacNotAxis),
        ];
        for (fake, serial, want) in cases {
            let http = Arc::new(fake.on(Method::Post, "/axis-cgi/systemready.cgi", 200, NEEDSETUP_YES).on(Method::Post, "/axis-cgi/pwdgrp.cgi", 200, "Created account root."));
            let c = routed_new_ctx(http.clone());
            for action in [Action::Activate, Action::ActivateCleartext] {
                let r = apply(&c, &routed_new_cam(serial), &creds(), &action).await;
                assert_eq!(r.error.as_ref(), Some(&want), "{serial}");
            }
            assert!(writes(&http).is_empty(), "aucun mot de passe envoyé ({serial})");
            assert!(http.requests().iter().all(|r| r.login.is_none()));
        }
    }

    /// Dans le sous-réseau, la MAC déclarée ne remplace jamais la couche 2.
    #[tokio::test]
    async fn declared_mac_does_not_replace_the_arp_table_on_the_subnet() {
        let http = Arc::new(axis_ok());
        let mut c = ctx(http.clone());
        c.neighbours = Arc::new(FakeNeighbours::table(&[]));
        let mut front = cam("192.0.2.11", Family::Axis);
        front.declared_mac = Some(MAC.into());
        let r = apply(&c, &front, &creds(), &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::MacNotAxis));
        assert!(writes(&http).is_empty());
    }

    #[tokio::test]
    async fn on_subnet_camera_never_asks_for_a_route() {
        let http = Arc::new(axis_ok());
        let (c, routes) = routed_ctx(http, Route::Routed("192.0.2.1".parse().unwrap()));
        assert!(apply(&c, &cam("192.0.2.11", Family::Axis), &creds(), &time()).await.ok);
        assert!(routes.asked().is_empty());
    }

    #[tokio::test]
    async fn routed_hikvision_reset_goes_through_isapi_after_its_serial_is_confirmed() {
        let reset = "<ResponseStatus><statusCode>1</statusCode></ResponseStatus>";
        let http = Arc::new(
            FakeHttp::new()
                .on(Method::Get, "/ISAPI/System/deviceInfo", 200, HIK_INFO)
                .on(Method::Put, "/ISAPI/System/factoryReset", 200, reset),
        );
        let (c, _) = routed_ctx(http.clone(), Route::Routed("192.0.2.1".parse().unwrap()));
        let r = apply(&c, &routed_cam(Family::Hikvision), &creds(), &keep_ip()).await;
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(http.requests().pop().unwrap().url, "http://10.0.20.11/ISAPI/System/factoryReset?mode=basic");
        // Autre n° de série : pas d'ordre.
        let http = Arc::new(
            FakeHttp::new()
                .on(Method::Get, "/ISAPI/System/deviceInfo", 200, HIK_INFO.replace("DS-1", "DS-2"))
                .on(Method::Put, "/ISAPI/System/factoryReset", 200, reset),
        );
        let (c, _) = routed_ctx(http.clone(), Route::Routed("192.0.2.1".parse().unwrap()));
        assert_eq!(apply(&c, &routed_cam(Family::Hikvision), &creds(), &keep_ip()).await.error, Some(ActionError::IdentityMismatch));
        // Plus routée à l'action : refusée avant toute requête.
        let http = Arc::new(FakeHttp::new());
        let (c, _) = routed_ctx(http.clone(), Route::OnLink("eth0".into()));
        assert_eq!(apply(&c, &routed_cam(Family::Hikvision), &creds(), &keep_ip()).await.error, Some(ActionError::CameraOffSubnet));
        assert!(http.requests().is_empty());
    }
}
