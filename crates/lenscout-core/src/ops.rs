//! Opérations de masse (onglet Opérations) : garder les IP en changeant
//! masque / passerelle / DNS, renuméroter, mettre l'heure. Ici le plan (une
//! ligne par caméra, avant / après, conflits) et l'application d'une ligne ;
//! l'écriture passe par `actions::apply`, donc par la garde de sous-réseau,
//! l'IP temporaire et la vérification d'identité de chaque caméra.

use std::net::Ipv4Addr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::accounts::{Exclusions, NetworkFill};
use crate::actions::{Action, ActionContext, ActionResult, apply};
use crate::batch::{BatchError, BatchRequest, check_room, plan_rows, usable_mask};
use crate::model::{Camera, Family};
use crate::transport::{CameraHttp, Credentials, NetError};
use crate::vapix::{self, AuthOutcome, NetConfig, NetworkSettings, VapixError};

/// Ce qu'une ligne recevra : l'IP fixe et ses réglages.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NetTarget {
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

/// Conflit d'une ligne, code stable traduit par le front. Tous bloquent
/// l'application sauf `OutsideAccount`, simple avertissement : passer un site
/// de /24 à /23, ou renuméroter vers un autre réseau, sort volontairement du
/// réseau enregistré dans le compte.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Conflict {
    /// Marque sans écriture réseau ou horaire (Hikvision : SADP sans
    /// encodage de mot de passe, pas d'heure ; autres marques).
    Unsupported,
    /// Ni MAC ni n° de série : l'identité ne pourrait pas être vérifiée.
    MissingIdentity,
    /// Réglage réseau illisible (caméra muette, compte refusé, caméra hors
    /// sous-réseau joignable seulement par IP temporaire) : les champs
    /// laissés vides n'ont pas de valeur à garder.
    Unreadable,
    /// En DHCP : garder son IP la figerait en IP fixe sur un bail.
    Dhcp,
    IpInUse { ip: Ipv4Addr, mac: Option<String> },
    NetworkOrBroadcast { ip: Ipv4Addr },
    GatewayOutOfSubnet { ip: Ipv4Addr },
    /// Passerelle sur l'adresse même de la caméra.
    GatewayIsIp { ip: Ipv4Addr },
    /// Nouvelle adresse hors du réseau du compte (avertissement).
    OutsideAccount { network: String },
}

impl Conflict {
    pub fn blocking(&self) -> bool {
        !matches!(self, Conflict::OutsideAccount { .. })
    }
}

/// Une ligne de l'aperçu, dans l'ordre de la sélection. `before` : réglage lu
/// sur la caméra (absent pour l'heure, ou illisible) ; `after` : ce qu'elle
/// recevra (absent pour l'heure).
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct OpRow {
    pub key: String,
    pub ip: Ipv4Addr,
    pub before: Option<NetConfig>,
    pub after: Option<NetTarget>,
    pub conflicts: Vec<Conflict>,
}

impl OpRow {
    pub fn blocked(&self) -> bool {
        self.conflicts.iter().any(Conflict::blocking)
    }
}

/// « Garder les IP » : `None` = inchangé (la valeur lue sur la caméra).
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct KeepRequest {
    pub mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Option<Vec<Ipv4Addr>>,
}

/// L'adresse est-elle dans le réseau du compte ? `None` : compte sans réseau.
fn in_account(fill: Option<&NetworkFill>, ip: Ipv4Addr) -> Option<bool> {
    let (net, prefix) = fill?.network.split_once('/')?;
    let (net, prefix) = (net.parse::<Ipv4Addr>().ok()?, prefix.parse::<u32>().ok()?);
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    Some(u32::from(ip) & mask == u32::from(net))
}

fn outside(fill: Option<&NetworkFill>, ip: Ipv4Addr) -> Option<Conflict> {
    match in_account(fill, ip) {
        Some(false) => fill.map(|f| Conflict::OutsideAccount { network: f.network.clone() }),
        _ => None,
    }
}

/// Une marque sur laquelle l'opération écrit : Axis seulement. Hikvision n'a
/// ni lecture du réglage réseau, ni encodage SADP du mot de passe, ni heure.
fn writable(cam: &Camera) -> bool {
    cam.family == Family::Axis
}

fn has_identity(cam: &Camera) -> bool {
    let known = |f: &Option<String>| f.as_deref().is_some_and(|s| !s.trim().is_empty());
    known(&cam.mac) || known(&cam.serial)
}

/// Les refus d'une IP fixe : adresse réseau ou broadcast, passerelle hors du
/// sous-réseau ou sur l'adresse même.
fn target_conflicts(t: &NetTarget) -> Vec<Conflict> {
    let mut out = Vec::new();
    let (a, m) = (u32::from(t.ip), u32::from(t.mask));
    let net = a & m;
    if a == net || a == net | !m {
        out.push(Conflict::NetworkOrBroadcast { ip: t.ip });
    }
    if let Some(gw) = t.gateway {
        let g = u32::from(gw);
        if gw == t.ip {
            out.push(Conflict::GatewayIsIp { ip: gw });
        } else if g & m != net || g == net || g == net | !m {
            out.push(Conflict::GatewayOutOfSubnet { ip: gw });
        }
    }
    out
}

/// Plan de « Garder les IP » : chaque caméra garde son IP actuelle ; le masque,
/// la passerelle et le DNS demandés remplacent ceux lus sur elle (`before[i]`
/// pour `selection[i]`), les champs vides gardent la valeur lue. Erreurs de
/// toute la demande : sélection vide, rien à changer, masque, plus de 2 DNS.
pub fn plan_keep(
    selection: &[Camera],
    before: &[Option<NetConfig>],
    req: &KeepRequest,
    fill: Option<&NetworkFill>,
) -> Result<Vec<OpRow>, BatchError> {
    if selection.is_empty() {
        return Err(BatchError::NoSelection);
    }
    if req.mask.is_none() && req.gateway.is_none() && req.dns.is_none() {
        return Err(BatchError::NoChange);
    }
    if req.mask.is_some_and(|m| !usable_mask(m)) {
        return Err(BatchError::InvalidMask);
    }
    if req.dns.as_ref().is_some_and(|d| d.len() > 2) {
        return Err(BatchError::TooManyDns);
    }
    let rows = selection
        .iter()
        .enumerate()
        .map(|(i, cam)| {
            let read = before.get(i).cloned().flatten();
            let mut conflicts = Vec::new();
            if !writable(cam) {
                conflicts.push(Conflict::Unsupported);
            }
            if !has_identity(cam) {
                conflicts.push(Conflict::MissingIdentity);
            }
            let after = match &read {
                None => {
                    if writable(cam) {
                        conflicts.push(Conflict::Unreadable);
                    }
                    None
                }
                Some(b) => {
                    if b.addressing == crate::model::Addressing::Dhcp {
                        conflicts.push(Conflict::Dhcp);
                    }
                    let t = NetTarget {
                        ip: cam.ip,
                        mask: req.mask.unwrap_or(b.mask),
                        gateway: req.gateway.or(b.gateway),
                        dns: req.dns.clone().unwrap_or_else(|| b.dns.clone()),
                    };
                    conflicts.extend(target_conflicts(&t));
                    Some(t)
                }
            };
            conflicts.extend(outside(fill, cam.ip));
            OpRow { key: crate::actions::row_key(cam), ip: cam.ip, before: read, after, conflicts }
        })
        .collect();
    Ok(rows)
}

/// Plan de « Renuméroter » : le plan en lot (`plan_rows`, IP exclues et
/// caméras connues du compte sautées), refusé d'emblée si le réseau du compte
/// n'a pas la place (`check_room`, `fill` comptant les adresses du lot comme
/// libres) ; les refus d'adresse sont rendus sur leur ligne.
#[allow(clippy::too_many_arguments)]
pub fn plan_renumber(
    selection: &[Camera],
    before: &[Option<NetConfig>],
    req: &BatchRequest,
    others: &[Camera],
    reserved: &[Ipv4Addr],
    excluded: &Exclusions,
    fill: Option<&NetworkFill>,
) -> Result<Vec<OpRow>, BatchError> {
    if selection.is_empty() {
        return Err(BatchError::NoSelection);
    }
    check_room(selection.len(), req, fill)?;
    let planned = plan_rows(selection, req, others, reserved, excluded)?;
    let rows = selection
        .iter()
        .zip(planned)
        .enumerate()
        .map(|(i, (cam, p))| {
            let mut conflicts: Vec<Conflict> = p
                .conflicts
                .into_iter()
                .map(|e| match e {
                    BatchError::MissingMac { .. } => Conflict::MissingIdentity,
                    BatchError::NetworkOrBroadcast { ip } => Conflict::NetworkOrBroadcast { ip },
                    BatchError::IpInUse { ip, mac } => Conflict::IpInUse { ip, mac },
                    BatchError::GatewayInRange { ip } => Conflict::GatewayIsIp { ip },
                    _ => Conflict::Unsupported,
                })
                .collect();
            // `plan_rows` admet une Hikvision quand SADP saura écrire ; ici
            // l'écriture est celle d'une Axis.
            if !writable(cam) && !conflicts.contains(&Conflict::Unsupported) {
                conflicts.insert(0, Conflict::Unsupported);
            }
            conflicts.extend(outside(fill, p.new_ip));
            let after = NetTarget { ip: p.new_ip, mask: req.mask, gateway: req.gateway, dns: req.dns.clone() };
            OpRow { key: crate::actions::row_key(cam), ip: cam.ip, before: before.get(i).cloned().flatten(), after: Some(after), conflicts }
        })
        .collect();
    Ok(rows)
}

/// Plan de « Mettre l'heure » : Axis seulement, avec une identité vérifiable.
pub fn plan_time(selection: &[Camera]) -> Result<Vec<OpRow>, BatchError> {
    if selection.is_empty() {
        return Err(BatchError::NoSelection);
    }
    Ok(selection
        .iter()
        .map(|cam| {
            let mut conflicts = Vec::new();
            if !writable(cam) {
                conflicts.push(Conflict::Unsupported);
            }
            if !has_identity(cam) {
                conflicts.push(Conflict::MissingIdentity);
            }
            OpRow { key: crate::actions::row_key(cam), ip: cam.ip, before: None, after: None, conflicts }
        })
        .collect())
}

/// L'action d'une ligne : son IP fixe, sinon `time`.
pub fn row_action(row: &OpRow, time: Option<&vapix::TimeSettings>) -> Option<Action> {
    match (&row.after, time) {
        (Some(t), _) => Some(Action::Network(NetworkSettings::Static {
            ip: t.ip,
            mask: t.mask,
            gateway: t.gateway,
            dns: t.dns.clone(),
        })),
        (None, Some(t)) => Some(Action::Time(t.clone())),
        (None, None) => None,
    }
}

/// Lit le réglage réseau de chaque caméra avec le compte, au plus `parallel`
/// à la fois, pour l'aperçu. Seulement une Axis jointe sans IP temporaire
/// (dans le sous-réseau, ou à travers le routeur : `actions::direct`), et
/// après `verify_identity` : le compte ne part que vers la caméra visée.
/// `None` : non lue.
pub async fn read_before(ctx: &ActionContext, cams: &[Camera], creds: &Credentials, parallel: usize) -> Vec<Option<NetConfig>> {
    use futures_util::StreamExt;
    // Caméras possédées par le flux : un emprunt par élément ne passe pas
    // l'envoi entre fils d'une commande Tauri.
    futures_util::stream::iter(cams.to_vec())
        .map(|cam| async move {
            if cam.family != Family::Axis || !crate::actions::direct(ctx, cam.ip).await {
                return None;
            }
            crate::actions::verify_identity(ctx, &cam, Some(creds)).await.ok()?;
            vapix::network_config(ctx.http.as_ref(), &cam.base_url(), creds).await.ok()
        })
        .buffered(parallel.max(1))
        .collect()
        .await
}

/// Relecture après un changement d'adresse : attente `first`, puis jusqu'à
/// `tries` essais espacés de `pause`.
#[derive(Debug, Clone, Copy)]
pub struct Readback {
    pub first: Duration,
    pub tries: u32,
    pub pause: Duration,
}

/// La caméra répond-elle à `ip` ? Lecture anonyme de son identité : même n°
/// de série si on le connaît ; une réponse HTTP sans identité lisible (AXIS
/// OS < 8.40, 404) compte comme une réponse. Une autre caméra à cette
/// adresse, ou le silence : non.
pub async fn readback(http: &dyn CameraHttp, cam: &Camera, ip: Ipv4Addr, wait: Readback) -> bool {
    let base = Camera { ip, ..cam.clone() }.base_url();
    tokio::time::sleep(wait.first).await;
    for n in 0..wait.tries.max(1) {
        if n > 0 {
            tokio::time::sleep(wait.pause).await;
        }
        match vapix::device_info(http, &base).await {
            Ok(info) => {
                return match (cam.serial.as_deref(), info.serial.as_deref()) {
                    (Some(want), Some(got)) => want.trim().eq_ignore_ascii_case(got.trim()),
                    _ => true,
                };
            }
            Err(VapixError::Net(NetError::Timeout | NetError::Unreachable(_) | NetError::Io(_) | NetError::Cancelled | NetError::Denied)) => {}
            Err(_) => return true,
        }
    }
    false
}

/// Résultat d'une ligne appliquée. `reachable` : après un changement
/// d'adresse réussi, la caméra a-t-elle répondu à sa nouvelle adresse ?
/// (`None` : rien à relire.)
#[derive(Serialize, Debug, PartialEq)]
pub struct StepResult {
    #[serde(flatten)]
    pub result: ActionResult,
    pub reachable: Option<bool>,
}

/// Applique l'action d'une ligne par `apply`, puis, pour une IP fixe posée,
/// relit la caméra à sa nouvelle adresse par `check` (client à délai court).
pub async fn apply_step(
    ctx: &ActionContext,
    cam: &Camera,
    creds: &Credentials,
    action: &Action,
    check: &dyn CameraHttp,
    wait: Readback,
) -> StepResult {
    let result = apply(ctx, cam, creds, action).await;
    let reachable = match action {
        Action::Network(NetworkSettings::Static { ip, .. }) if result.ok => Some(readback(check, cam, *ip, wait).await),
        _ => None,
    };
    StepResult { result, reachable }
}

/// Garde anti-verrouillage de « Changer les identifiants » : les Axis récents
/// bloquent un compte après ~5 échecs rapprochés. `delay` espace deux essais
/// sur une même caméra ; `max_failures` arrête les essais après ce nombre
/// d'échecs d'authentification (401), même s'il reste des couples à essayer.
#[derive(Debug, Clone, Copy)]
pub struct CredGuard {
    pub delay: Duration,
    pub max_failures: u32,
}

/// Sort d'une caméra pour « Changer les identifiants ». Le rapport ne montre
/// que l'utilisateur qui a marché (`Posed`), jamais un mot de passe. `detail`
/// de `Rejected` ne vient que de la caméra.
#[derive(Serialize, Debug, PartialEq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum CredOutcome {
    /// Nouvel identifiant posé, après authentification par l'utilisateur `login`.
    Posed { login: String },
    /// Le nouvel identifiant visé fonctionne déjà : rien n'est posé.
    AlreadyUpToDate,
    /// Aucun des identifiants essayés n'a authentifié : rien n'est posé.
    NoCredential,
    /// Arrêté par le garde-fou après le nombre max d'échecs (risque de blocage).
    StoppedByGuard,
    /// Marque non gérée (Hikvision / autre) : aucun essai.
    Unsupported,
    /// Caméra injoignable (réseau, hors sous-réseau, identité non confirmée) :
    /// rien n'est posé, rien n'a consommé le compteur d'échecs.
    Unreachable,
    /// Authentifié, mais la caméra a refusé le changement (`detail` = son texte).
    Rejected { detail: String },
}

/// Résultat d'une ligne de « Changer les identifiants » (clé = MAC, sinon IP).
#[derive(Serialize, Debug, PartialEq)]
pub struct CredResult {
    pub key: String,
    #[serde(flatten)]
    pub outcome: CredOutcome,
}

/// Plan de « Changer les identifiants » : Axis seulement, identité vérifiable
/// (sans quoi on ne saurait pas confirmer la caméra avant d'y envoyer des mots
/// de passe). Comme « Mettre l'heure », l'aperçu n'écrit rien et surtout
/// n'essaie AUCUN identifiant : tout essai se fait à l'application, une seule
/// fois, pour ne pas doubler le risque de blocage.
pub fn plan_change_credentials(selection: &[Camera]) -> Result<Vec<OpRow>, BatchError> {
    if selection.is_empty() {
        return Err(BatchError::NoSelection);
    }
    Ok(selection
        .iter()
        .map(|cam| {
            let mut conflicts = Vec::new();
            if !writable(cam) {
                conflicts.push(Conflict::Unsupported);
            }
            if !has_identity(cam) {
                conflicts.push(Conflict::MissingIdentity);
            }
            OpRow { key: crate::actions::row_key(cam), ip: cam.ip, before: None, after: None, conflicts }
        })
        .collect())
}

/// Deux identifiants (login + mot de passe) sont-ils les mêmes ? Comparaison
/// en mémoire, jamais journalisée.
fn same_cred(a: &Credentials, b: &Credentials) -> bool {
    a.login == b.login && a.password.expose() == b.password.expose()
}

/// Ordre des identifiants à essayer : le compte sélectionné d'abord, puis les
/// couples de la liste, dans l'ordre donné. Les doublons et tout couple égal
/// au nouvel identifiant visé (déjà essayé en premier) sont retirés : un essai
/// de moins, c'est un pas de moins vers le blocage.
fn cred_order(account: Option<&Credentials>, list: &[Credentials], new: &Credentials) -> Vec<Credentials> {
    let mut out: Vec<Credentials> = Vec::new();
    for c in account.into_iter().chain(list.iter()) {
        if !same_cred(c, new) && !out.iter().any(|o| same_cred(o, c)) {
            out.push(c.clone());
        }
    }
    out
}

/// Change l'identifiant d'une caméra. Dans l'ordre : le nouvel identifiant visé
/// (déjà à jour → skip), puis le compte sélectionné, puis les couples de la
/// liste ; au premier qui authentifie, pose le nouvel identifiant. Aucun mot de
/// passe n'est envoyé avant que l'identité de la caméra ne soit confirmée.
///
/// La caméra doit être jointe sans IP temporaire (sous-réseau ou routeur) ;
/// sinon `Unreachable`. Entre deux essais, `guard.delay` ; après
/// `guard.max_failures` échecs 401 (et s'il reste des couples), `StoppedByGuard`.
/// Une erreur réseau rend `Unreachable` sans compter d'échec.
pub async fn change_credentials_step(
    ctx: &ActionContext,
    cam: &Camera,
    account: Option<&Credentials>,
    candidates: &[Credentials],
    new: &Credentials,
    guard: CredGuard,
) -> CredResult {
    CredResult { key: crate::actions::row_key(cam), outcome: change_credentials_inner(ctx, cam, account, candidates, new, guard).await }
}

async fn change_credentials_inner(
    ctx: &ActionContext,
    cam: &Camera,
    account: Option<&Credentials>,
    candidates: &[Credentials],
    new: &Credentials,
    guard: CredGuard,
) -> CredOutcome {
    if cam.family != Family::Axis {
        return CredOutcome::Unsupported;
    }
    // Jointe sans IP temporaire, et identité confirmée AVANT tout mot de passe :
    // on ne diffuse pas une liste de mots de passe vers un appareil inattendu.
    if !crate::actions::direct(ctx, cam.ip).await {
        return CredOutcome::Unreachable;
    }
    if crate::actions::verify_identity(ctx, cam, None).await.is_err() {
        return CredOutcome::Unreachable;
    }
    let http = ctx.http.as_ref();
    let base = cam.base_url();
    // 1. Le nouvel identifiant visé marche-t-il déjà ?
    match vapix::try_auth(http, &base, new).await {
        AuthOutcome::Ok => return CredOutcome::AlreadyUpToDate,
        AuthOutcome::Unreachable => return CredOutcome::Unreachable,
        AuthOutcome::Denied => {}
    }
    // 2. Le compte, puis la liste, dans l'ordre, dédoublonnés.
    let order = cred_order(account, candidates, new);
    let mut failures = 0u32;
    for (i, cred) in order.iter().enumerate() {
        tokio::time::sleep(guard.delay).await;
        match vapix::try_auth(http, &base, cred).await {
            AuthOutcome::Ok => {
                return match vapix::set_credentials(http, &base, cred, new).await {
                    Ok(()) => CredOutcome::Posed { login: cred.login.clone() },
                    Err(VapixError::Rejected(detail)) => CredOutcome::Rejected { detail },
                    // Écriture sans réponse : la caméra ne change pas d'adresse,
                    // on ne prétend pas avoir posé l'identifiant.
                    Err(_) => CredOutcome::Unreachable,
                };
            }
            AuthOutcome::Denied => {
                failures += 1;
                if failures >= guard.max_failures && i + 1 < order.len() {
                    return CredOutcome::StoppedByGuard;
                }
            }
            AuthOutcome::Unreachable => return CredOutcome::Unreachable,
        }
    }
    CredOutcome::NoCredential
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::accounts::{AccountNetwork, network_fill};
    use crate::actions::SeenState;
    use crate::discovery::arp::ScanInterface;
    use crate::model::{Activation, Addressing, Source};
    use crate::route::Route;
    use crate::secret::Secret;
    use crate::testing::{FakeHttp, FakeNeighbours, FakeRoutes, PanicElevator};
    use crate::transport::Method;
    use crate::vapix::TimeSettings;

    const INFO: &[u8] = include_bytes!("../tests/fixtures/vapix_basicdeviceinfo.json");
    const SERIAL: &str = "ACCC8E123456";

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn axis(last: u8) -> Camera {
        Camera {
            ip: ip(&format!("10.0.50.{last}")),
            mac: Some(format!("AC:CC:8E:00:00:{last:02X}")),
            family: Family::Axis,
            brand: None,
            model: None,
            serial: Some(format!("SER{last}")),
            firmware: None,
            activation: Activation::Activated,
            http_port: 80,
            sources: vec![Source::Mdns],
            addressing: None,
            declared_mac: None,
        }
    }

    fn read(last: u8, addressing: Addressing) -> Option<NetConfig> {
        Some(NetConfig {
            addressing,
            ip: ip(&format!("10.0.50.{last}")),
            mask: ip("255.255.255.0"),
            gateway: Some(ip("10.0.50.1")),
            dns: vec![ip("10.0.50.2")],
        })
    }

    fn fill(pc: &str) -> NetworkFill {
        let net = AccountNetwork { pc_ip: Some(pc.into()), ..Default::default() }.validated().unwrap();
        network_fill(&net, &[], &[]).unwrap()
    }

    #[test]
    fn keeping_the_ips_changes_only_what_is_asked() {
        let sel = [axis(11), axis(12)];
        let before = [read(11, Addressing::Static), read(12, Addressing::Static)];
        let req = KeepRequest { mask: Some(ip("255.255.254.0")), ..Default::default() };
        let rows = plan_keep(&sel, &before, &req, None).unwrap();
        assert_eq!(
            rows[0].after,
            Some(NetTarget { ip: ip("10.0.50.11"), mask: ip("255.255.254.0"), gateway: Some(ip("10.0.50.1")), dns: vec![ip("10.0.50.2")] })
        );
        assert_eq!(rows[1].after.as_ref().unwrap().ip, ip("10.0.50.12"));
        assert!(rows.iter().all(|r| r.conflicts.is_empty()));
        assert_eq!(rows[0].before, before[0]);
        assert_eq!(rows[0].key, "AC:CC:8E:00:00:0B");
        // Passerelle et DNS demandés remplacent ceux lus.
        let req = KeepRequest { gateway: Some(ip("10.0.50.254")), dns: Some(vec![ip("1.1.1.1"), ip("9.9.9.9")]), ..Default::default() };
        let t = plan_keep(&sel[..1], &before[..1], &req, None).unwrap().remove(0).after.unwrap();
        assert_eq!((t.mask, t.gateway, t.dns), (ip("255.255.255.0"), Some(ip("10.0.50.254")), vec![ip("1.1.1.1"), ip("9.9.9.9")]));
    }

    #[test]
    fn keeping_the_ips_flags_each_row() {
        let mut hik = axis(13);
        hik.family = Family::Hikvision;
        // /23 : 10.0.51.255 en devient le broadcast.
        let mut edge = axis(14);
        edge.ip = ip("10.0.51.255");
        let sel = [axis(11), axis(12), hik, edge];
        let before = [None, read(12, Addressing::Dhcp), None, read(14, Addressing::Static)];
        let req = KeepRequest { mask: Some(ip("255.255.254.0")), ..Default::default() };
        let rows = plan_keep(&sel, &before, &req, None).unwrap();
        assert_eq!(rows[0].conflicts, [Conflict::Unreadable]);
        assert_eq!(rows[1].conflicts, [Conflict::Dhcp]);
        assert_eq!(rows[2].conflicts, [Conflict::Unsupported]);
        assert_eq!(rows[3].conflicts, [Conflict::NetworkOrBroadcast { ip: ip("10.0.51.255") }]);
        assert!(rows.iter().all(OpRow::blocked));
        // Passerelle hors du nouveau sous-réseau, ou sur l'adresse même.
        let req = KeepRequest { mask: Some(ip("255.255.255.128")), gateway: Some(ip("10.0.50.200")), ..Default::default() };
        let rows = plan_keep(&[axis(11)], &[read(11, Addressing::Static)], &req, None).unwrap();
        assert_eq!(rows[0].conflicts, [Conflict::GatewayOutOfSubnet { ip: ip("10.0.50.200") }]);
        let req = KeepRequest { gateway: Some(ip("10.0.50.11")), ..Default::default() };
        let rows = plan_keep(&[axis(11)], &[read(11, Addressing::Static)], &req, None).unwrap();
        assert_eq!(rows[0].conflicts, [Conflict::GatewayIsIp { ip: ip("10.0.50.11") }]);
    }

    #[test]
    fn outside_the_account_network_is_a_warning_only() {
        let f = fill("10.0.60.5/24");
        let req = KeepRequest { mask: Some(ip("255.255.254.0")), ..Default::default() };
        let rows = plan_keep(&[axis(11)], &[read(11, Addressing::Static)], &req, Some(&f)).unwrap();
        assert_eq!(rows[0].conflicts, [Conflict::OutsideAccount { network: "10.0.60.0/24".into() }]);
        assert!(!rows[0].blocked());
        let rows = plan_keep(&[axis(11)], &[read(11, Addressing::Static)], &req, Some(&fill("10.0.50.5/24"))).unwrap();
        assert!(rows[0].conflicts.is_empty());
        assert_eq!(serde_json::to_value(&rows[0]).unwrap()["key"], "AC:CC:8E:00:00:0B");
        assert_eq!(serde_json::to_value(Conflict::Dhcp).unwrap()["code"], "dhcp");
    }

    #[test]
    fn keeping_the_ips_refuses_a_request_that_changes_nothing_or_is_invalid() {
        let sel = [axis(11)];
        let before = [read(11, Addressing::Static)];
        assert_eq!(plan_keep(&[], &[], &KeepRequest { mask: Some(ip("255.255.0.0")), ..Default::default() }, None), Err(BatchError::NoSelection));
        assert_eq!(plan_keep(&sel, &before, &KeepRequest::default(), None), Err(BatchError::NoChange));
        let bad = KeepRequest { mask: Some(ip("255.0.255.0")), ..Default::default() };
        assert_eq!(plan_keep(&sel, &before, &bad, None), Err(BatchError::InvalidMask));
        let dns = KeepRequest { dns: Some(vec![ip("1.1.1.1"), ip("1.0.0.1"), ip("9.9.9.9")]), ..Default::default() };
        assert_eq!(plan_keep(&sel, &before, &dns, None), Err(BatchError::TooManyDns));
    }

    fn req(start: &str) -> BatchRequest {
        BatchRequest { start: ip(start), mask: ip("255.255.255.0"), gateway: Some(ip("10.0.50.1")), dns: vec![] }
    }

    #[test]
    fn renumbering_shows_before_after_and_conflicts_per_row() {
        let sel = [axis(200), axis(201)];
        let before = [read(200, Addressing::Dhcp), None];
        let others = [axis(12)];
        let rows = plan_renumber(&sel, &before, &req("10.0.50.11"), &others, &[], &Exclusions::default(), None).unwrap();
        assert_eq!(rows[0].before, before[0]);
        assert_eq!(rows[0].after.as_ref().unwrap().ip, ip("10.0.50.11"));
        assert_eq!(rows[0].after.as_ref().unwrap().gateway, Some(ip("10.0.50.1")));
        assert!(rows[0].conflicts.is_empty(), "DHCP ou illisible n'empêche pas de renuméroter");
        assert_eq!(rows[1].conflicts, [Conflict::IpInUse { ip: ip("10.0.50.12"), mac: Some("AC:CC:8E:00:00:0C".into()) }]);
        // Plus de caméras que d'adresses libres dans le réseau du compte : refus de toute la demande.
        let f = fill("10.0.50.6/29");
        let mut r = req("10.0.50.1");
        r.mask = ip("255.255.255.248");
        r.gateway = None;
        let many: Vec<Camera> = (100..106).map(axis).collect();
        assert_eq!(
            plan_renumber(&many, &[], &r, &[], &[], &Exclusions::default(), Some(&f)),
            Err(BatchError::NotEnoughFree { needed: 6, free: 5 })
        );
        // Vers un autre réseau que celui du compte : avertissement par ligne.
        let rows = plan_renumber(&sel, &[], &req("10.0.50.11"), &[], &[], &Exclusions::default(), Some(&fill("10.0.60.5/24"))).unwrap();
        assert_eq!(rows[0].conflicts, [Conflict::OutsideAccount { network: "10.0.60.0/24".into() }]);
    }

    #[test]
    fn renumbering_accepts_a_routed_axis_and_refuses_hikvision() {
        let mut routed = axis(30);
        routed.mac = None;
        let mut hik = axis(31);
        hik.family = Family::Hikvision;
        let rows = plan_renumber(&[routed, hik], &[], &req("10.0.50.11"), &[], &[], &Exclusions::default(), None).unwrap();
        assert!(rows[0].conflicts.is_empty());
        assert_eq!(rows[0].key, "10.0.50.30");
        assert_eq!(rows[1].conflicts, [Conflict::Unsupported]);
    }

    #[test]
    fn setting_the_time_is_for_axis_only() {
        let mut hik = axis(31);
        hik.family = Family::Hikvision;
        let rows = plan_time(&[axis(11), hik]).unwrap();
        assert!(rows[0].conflicts.is_empty() && rows[0].after.is_none());
        assert_eq!(rows[1].conflicts, [Conflict::Unsupported]);
        assert_eq!(plan_time(&[]), Err(BatchError::NoSelection));
        let t = TimeSettings { ntp_servers: vec![], timezone: "UTC".into() };
        assert_eq!(row_action(&rows[0], Some(&t)), Some(Action::Time(t.clone())));
    }

    #[test]
    fn the_action_of_a_network_row_is_its_fixed_ip() {
        let rows = plan_keep(&[axis(11)], &[read(11, Addressing::Static)], &KeepRequest { mask: Some(ip("255.255.254.0")), ..Default::default() }, None).unwrap();
        assert_eq!(
            row_action(&rows[0], None),
            Some(Action::Network(NetworkSettings::Static {
                ip: ip("10.0.50.11"),
                mask: ip("255.255.254.0"),
                gateway: Some(ip("10.0.50.1")),
                dns: vec![ip("10.0.50.2")],
            }))
        );
    }

    const NOW: Readback = Readback { first: Duration::ZERO, tries: 2, pause: Duration::ZERO };

    fn known(serial: &str) -> Camera {
        Camera { ip: ip("192.0.2.11"), serial: Some(serial.into()), ..axis(11) }
    }

    #[tokio::test]
    async fn the_readback_wants_the_same_camera_at_the_new_address() {
        let up = FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO.to_vec());
        assert!(readback(&up, &known(SERIAL), ip("192.0.2.40"), NOW).await);
        assert_eq!(up.requests()[0].url, "http://192.0.2.40/axis-cgi/basicdeviceinfo.cgi");
        assert!(!readback(&up, &known("AUTRE"), ip("192.0.2.40"), NOW).await, "une autre caméra à cette adresse");
        // Personne : deux essais, puis non.
        let down = FakeHttp::new();
        assert!(!readback(&down, &known(SERIAL), ip("192.0.2.40"), NOW).await);
        assert_eq!(down.requests().len(), 2);
        // Une ancienne Axis sans basicdeviceinfo répond quand même.
        let old = FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "");
        assert!(readback(&old, &known(SERIAL), ip("192.0.2.40"), NOW).await);
    }

    fn ctx(http: Arc<dyn CameraHttp>) -> ActionContext {
        ActionContext {
            http,
            iface: ScanInterface { name: "eth0".into(), ip: ip("192.0.2.2"), mask: ip("255.255.255.0") },
            service: "eth0".into(),
            elevator: Arc::new(PanicElevator),
            journal: std::env::temp_dir().join("lenscout-ops-test-jamais-cree").join("temp-ip.json"),
            seen: vec![ip("192.0.2.11")],
            seen_iface: Some("eth0".into()),
            seen_sadp: vec![],
            sadp: None,
            in_use: vec![],
            other_ifaces: vec![],
            account_network: false,
            seen_states: vec![SeenState { key: "AC:CC:8E:00:00:0B".into(), ip: ip("192.0.2.11"), activation: Activation::Activated }],
            neighbours: Arc::new(FakeNeighbours::any("AC:CC:8E:12:34:56")),
            seen_routed: vec![],
            routes: Arc::new(FakeRoutes::new(Route::Unknown)),
        }
    }

    fn creds() -> Credentials {
        Credentials { login: "root".into(), password: Secret::new("S3cr3t".into()) }
    }

    fn axis_ok() -> FakeHttp {
        FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, INFO.to_vec())
            .on(Method::Post, "/axis-cgi/param.cgi", 200, "OK")
            .on(Method::Post, "/axis-cgi/time.cgi", 200, r#"{"data":{}}"#)
            .on(
                Method::Get,
                "/axis-cgi/param.cgi",
                200,
                "root.Network.BootProto=none\nroot.Network.IPAddress=192.0.2.11\nroot.Network.SubnetMask=255.255.255.0\n",
            )
    }

    #[tokio::test]
    async fn a_step_writes_then_reads_the_camera_back_at_its_new_address() {
        let http = Arc::new(axis_ok());
        let c = ctx(http.clone());
        let to = |a: &str| Action::Network(NetworkSettings::Static { ip: ip(a), mask: ip("255.255.255.0"), gateway: None, dns: vec![] });
        let step = apply_step(&c, &known(SERIAL), &creds(), &to("192.0.2.40"), &axis_ok(), NOW).await;
        assert!(step.result.ok, "{:?}", step.result.error);
        assert_eq!(step.reachable, Some(true));
        assert!(http.requests().iter().any(|r| r.method == Method::Post && r.url.ends_with("/axis-cgi/param.cgi")));
        // Écrite, mais muette à sa nouvelle adresse.
        let step = apply_step(&c, &known(SERIAL), &creds(), &to("192.0.2.41"), &FakeHttp::new(), NOW).await;
        assert_eq!((step.result.ok, step.reachable), (true, Some(false)));
        let j = serde_json::to_value(&step).unwrap();
        assert_eq!((j["ok"].as_bool(), j["reachable"].as_bool()), (Some(true), Some(false)));
        // Refusée : rien à relire.
        let step = apply_step(&c, &known("AUTRE"), &creds(), &to("192.0.2.42"), &axis_ok(), NOW).await;
        assert_eq!((step.result.ok, step.reachable), (false, None));
        // L'heure : rien à relire.
        let t = Action::Time(TimeSettings { ntp_servers: vec![], timezone: "UTC".into() });
        let step = apply_step(&c, &known(SERIAL), &creds(), &t, &FakeHttp::new(), NOW).await;
        assert_eq!((step.result.ok, step.reachable), (true, None));
    }

    #[tokio::test]
    async fn the_preview_reads_only_an_axis_it_reaches_without_a_temporary_ip() {
        let http = Arc::new(axis_ok());
        let c = ctx(http.clone());
        let mut far = known(SERIAL);
        far.ip = ip("10.9.9.9");
        let mut hik = known(SERIAL);
        hik.family = Family::Hikvision;
        let got = read_before(&c, &[known(SERIAL), far, hik, known("AUTRE")], &creds(), 4).await;
        assert_eq!(got.iter().map(Option::is_some).collect::<Vec<_>>(), [true, false, false, false]);
        assert_eq!(got[0].as_ref().unwrap().ip, ip("192.0.2.11"));
        // Le compte n'est parti que vers la caméra confirmée.
        let with_account: Vec<String> = http.requests().into_iter().filter(|r| r.login.is_some()).map(|r| r.url).collect();
        assert_eq!(with_account.len(), 1);
        assert!(with_account[0].starts_with("http://192.0.2.11/axis-cgi/param.cgi?action=list"));
    }

    // --- Changer les identifiants ---

    use std::sync::Mutex;

    /// Caméra Axis dont l'authentification dépend du mot de passe : seuls les
    /// mots de passe de `accept` passent (200) sur la sonde `pwdgrp.cgi?action=get`,
    /// les autres rendent 401. `basicdeviceinfo.cgi` donne le n° de série
    /// (identité). `set_ok` : la pose de l'identifiant réussit ou non.
    struct CredHttp {
        accept: Vec<&'static str>,
        set_ok: bool,
        posts: Mutex<usize>,
    }

    impl CredHttp {
        fn new(accept: &[&'static str]) -> Self {
            CredHttp { accept: accept.to_vec(), set_ok: true, posts: Mutex::new(0) }
        }
        fn sets(&self) -> usize {
            *self.posts.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl CameraHttp for CredHttp {
        async fn send(&self, req: crate::transport::HttpRequest, creds: Option<&Credentials>) -> Result<crate::transport::HttpResponse, NetError> {
            use crate::transport::HttpResponse;
            let ok = |body: &[u8]| Ok(HttpResponse { status: 200, headers: vec![], body: body.to_vec() });
            if req.url.ends_with("/axis-cgi/basicdeviceinfo.cgi") {
                return ok(INFO);
            }
            if req.url.contains("/axis-cgi/pwdgrp.cgi") {
                return match req.method {
                    // La pose de l'identifiant (POST) : réussit si `set_ok`.
                    Method::Post => {
                        *self.posts.lock().unwrap() += 1;
                        if self.set_ok { ok(b"OK") } else { ok(b"# Error: password policy") }
                    }
                    // La sonde (GET action=get) : 200 si le mot de passe passe.
                    _ => {
                        let pw = creds.map(|c| c.password.expose()).unwrap_or("");
                        if self.accept.iter().any(|a| *a == pw) { ok(b"admin=\"root\"") } else { Ok(HttpResponse { status: 401, headers: vec![], body: vec![] }) }
                    }
                };
            }
            Err(NetError::Unreachable(format!("route inconnue : {}", req.url)))
        }
        async fn stream(&self, _r: crate::transport::HttpRequest, _c: Option<&Credentials>) -> Result<(crate::transport::HttpResponse, crate::transport::ByteStream), NetError> {
            unimplemented!()
        }
    }

    const GUARD: CredGuard = CredGuard { delay: Duration::ZERO, max_failures: 4 };

    fn cred(login: &str, pw: &str) -> Credentials {
        Credentials { login: login.into(), password: Secret::new(pw.into()) }
    }

    #[test]
    fn the_credentials_plan_is_axis_with_an_identity() {
        let mut hik = axis(11);
        hik.family = Family::Hikvision;
        let mut bare = axis(12);
        (bare.mac, bare.serial) = (None, None);
        let rows = plan_change_credentials(&[axis(13), hik, bare]).unwrap();
        assert!(rows[0].conflicts.is_empty() && rows[0].after.is_none() && rows[0].before.is_none());
        assert_eq!(rows[1].conflicts, [Conflict::Unsupported]);
        assert_eq!(rows[2].conflicts, [Conflict::MissingIdentity]);
        assert_eq!(plan_change_credentials(&[]), Err(BatchError::NoSelection));
    }

    #[test]
    fn the_try_order_puts_the_account_first_dedups_and_skips_the_new_one() {
        let new = cred("root", "new");
        let account = cred("root", "a");
        let list = [cred("root", "a"), cred("installer", "b"), cred("root", "new"), cred("installer", "b")];
        let order = cred_order(Some(&account), &list, &new);
        let shown: Vec<(&str, &str)> = order.iter().map(|c| (c.login.as_str(), c.password.expose())).collect();
        assert_eq!(shown, [("root", "a"), ("installer", "b")]);
        // Sans compte : seulement la liste.
        assert_eq!(cred_order(None, &[cred("x", "y")], &new).len(), 1);
    }

    #[tokio::test]
    async fn the_new_credential_already_in_place_is_a_skip() {
        let http = Arc::new(CredHttp::new(&["new"]));
        let c = ctx(http.clone());
        let r = change_credentials_step(&c, &known(SERIAL), Some(&cred("root", "acc")), &[cred("x", "y")], &cred("root", "new"), GUARD).await;
        assert_eq!(r.outcome, CredOutcome::AlreadyUpToDate);
        assert_eq!(http.sets(), 0, "rien n'est posé");
        assert_eq!(r.key, "AC:CC:8E:00:00:0B");
    }

    #[tokio::test]
    async fn the_account_then_the_list_credential_sets_the_new_one() {
        // Le compte marche : posé, authentifié par le compte.
        let http = Arc::new(CredHttp::new(&["acc"]));
        let c = ctx(http.clone());
        let r = change_credentials_step(&c, &known(SERIAL), Some(&cred("root", "acc")), &[], &cred("root", "new"), GUARD).await;
        assert_eq!(r.outcome, CredOutcome::Posed { login: "root".into() });
        assert_eq!(http.sets(), 1);
        // Le compte échoue, un couple de la liste marche : posé par ce couple.
        let http = Arc::new(CredHttp::new(&["old2"]));
        let c = ctx(http.clone());
        let list = [cred("installer", "old1"), cred("tech", "old2")];
        let r = change_credentials_step(&c, &known(SERIAL), Some(&cred("root", "acc")), &list, &cred("root", "new"), GUARD).await;
        assert_eq!(r.outcome, CredOutcome::Posed { login: "tech".into() });
    }

    #[tokio::test]
    async fn no_credential_found_posts_nothing() {
        let http = Arc::new(CredHttp::new(&["none-match"]));
        let c = ctx(http.clone());
        let list = [cred("a", "1"), cred("b", "2")];
        let r = change_credentials_step(&c, &known(SERIAL), Some(&cred("root", "acc")), &list, &cred("root", "new"), GUARD).await;
        assert_eq!(r.outcome, CredOutcome::NoCredential);
        assert_eq!(http.sets(), 0);
    }

    #[tokio::test]
    async fn the_guard_stops_after_the_max_failures_when_couples_remain() {
        let http = Arc::new(CredHttp::new(&["never"]));
        let c = ctx(http.clone());
        let guard = CredGuard { delay: Duration::ZERO, max_failures: 2 };
        let list = [cred("a", "1"), cred("b", "2"), cred("c", "3"), cred("d", "4")];
        let r = change_credentials_step(&c, &known(SERIAL), None, &list, &cred("root", "new"), guard).await;
        assert_eq!(r.outcome, CredOutcome::StoppedByGuard);
    }

    #[tokio::test]
    async fn an_unsupported_brand_or_an_unreachable_camera_posts_nothing() {
        let http = Arc::new(CredHttp::new(&["acc"]));
        let c = ctx(http.clone());
        let mut hik = known(SERIAL);
        hik.family = Family::Hikvision;
        let r = change_credentials_step(&c, &hik, None, &[], &cred("root", "new"), GUARD).await;
        assert_eq!(r.outcome, CredOutcome::Unsupported);
        // Hors sous-réseau, sans IP temporaire : injoignable, aucun mot de passe.
        let mut far = known(SERIAL);
        far.ip = ip("10.9.9.9");
        let r = change_credentials_step(&c, &far, None, &[cred("a", "1")], &cred("root", "new"), GUARD).await;
        assert_eq!(r.outcome, CredOutcome::Unreachable);
        assert_eq!(http.sets(), 0);
    }

    #[tokio::test]
    async fn the_report_never_shows_a_password() {
        let http = Arc::new(CredHttp::new(&["s3cr3t-match"]));
        let c = ctx(http.clone());
        let r = change_credentials_step(&c, &known(SERIAL), Some(&cred("root", "s3cr3t-match")), &[], &cred("root", "new"), GUARD).await;
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("s3cr3t-match") && !json.contains("new"));
        assert!(json.contains("\"code\":\"posed\"") && json.contains("\"login\":\"root\""));
    }
}
