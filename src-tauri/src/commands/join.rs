use std::net::Ipv4Addr;
use std::sync::Mutex;

use lenscout_core::accounts::{AccountBook, AccountNetwork};
use lenscout_core::discovery::arp::{ScanInterface, read_neighbours};
use lenscout_core::interfaces::{get_interface_details, list_interfaces_up};
use lenscout_core::free_ips::{FreeProbe, Reply, SystemProbe};
use lenscout_core::presence;
use lenscout_core::route::{Route, Routes, SystemRoutes, probe_address};
use lenscout_core::temp_ip::{
    HeldTempIp, SwitchFailure, SystemElevator, TempIp, TempIpError, hold_temp_ip, joined_scope, needs_temp_ip,
    subnets_overlap, switch_held,
};
use serde::Serialize;
use tauri::State;

use super::configure::TempIpJournal;

/// « Se mettre dans ce réseau » : l'IP du PC d'un compte, posée sur une
/// interface par le mécanisme de l'IP temporaire et gardée jusqu'au retour
/// sur DHCP, au changement de compte ou à la sortie de l'app. L'adresse
/// principale, la route par défaut et la configuration de l'interface ne
/// sont jamais touchées ; la passerelle du compte n'est pas posée sur le PC.
#[derive(Default)]
pub struct JoinState {
    current: Mutex<Option<Joined>>,
    /// Mode routé : le réseau du compte est joint par le routeur, rien n'est
    /// posé sur le poste. Exclusif de `current`.
    routed: Mutex<Option<RoutedJoin>>,
    /// Une pose, un retrait ou une lecture de l'état à la fois.
    op: tokio::sync::Mutex<()>,
}

struct Joined {
    held: HeldTempIp,
    account_id: String,
    /// Passerelle du compte : écartée des adresses libres.
    gateway: Option<Ipv4Addr>,
    /// Interface telle que le front la nomme (service networksetup sur macOS).
    service: String,
    /// L'interface avant la pose (adresse principale) : c'est elle, jamais
    /// l'adresse posée, qui sert aux contrôles d'une pose suivante.
    primary: ScanInterface,
}

/// Le réseau d'un compte joint à travers le routeur (un autre VLAN).
#[derive(Clone, Debug, PartialEq)]
pub struct RoutedJoin {
    pub account_id: String,
    /// Interface telle que le front la nomme.
    pub service: String,
    /// `ScanInterface::name` de l'interface.
    pub iface: String,
    /// Réseau du compte (adresse du PC et masque du compte).
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    /// L'adresse dont la route a été demandée (passerelle du compte, sinon
    /// premier hôte) : elle a répondu à travers le routeur.
    pub probe: Ipv4Addr,
    /// La passerelle du poste par laquelle passe la route.
    pub via: Ipv4Addr,
}

impl JoinState {
    fn routed_lock(&self) -> std::sync::MutexGuard<'_, Option<RoutedJoin>> {
        self.routed.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Le réseau routé du compte retenu sur `iface` (`ScanInterface::name`).
    pub fn routed_on(&self, iface: &str) -> Option<RoutedJoin> {
        self.routed_lock().clone().filter(|r| r.iface == iface)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Joined>> {
        self.current.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// L'adresse posée, s'il y en a une.
    pub fn temp(&self) -> Option<TempIp> {
        self.lock().as_ref().map(|j| j.held.temp().clone())
    }

    /// L'interface vue par le scan, les actions et les adresses libres.
    pub fn scope(&self, base: ScanInterface) -> ScanInterface {
        joined_scope(base, self.temp().as_ref())
    }

    /// Passerelle du compte posé sur `iface` (`ScanInterface::name`).
    pub fn gateway_on(&self, iface: &str) -> Option<Ipv4Addr> {
        self.lock().as_ref().filter(|j| j.held.temp().iface == iface).and_then(|j| j.gateway)
    }

    /// Sortie de l'app : le verrou est lâché, le journal reste ;
    /// `cleanup_before_exit` retire l'adresse juste après.
    pub fn let_go(&self) {
        self.lock().take();
        self.routed_lock().take();
    }

    fn out(&self) -> Option<JoinedOut> {
        self.lock().as_ref().map(JoinedOut::new).or_else(|| self.routed_lock().as_ref().map(JoinedOut::routed))
    }
}

/// Miroir côté front : `src/lib/api/net.ts`.
#[derive(Serialize, Debug, PartialEq)]
pub struct JoinedOut {
    pub account_id: String,
    /// Interface telle que le front la nomme.
    pub iface: String,
    pub ip: String,
    pub mask: String,
    /// `192.168.1.250/24`.
    pub cidr: String,
    /// Mode routé : la passerelle du poste par laquelle passe le réseau du
    /// compte ; `ip`, `mask` et `cidr` sont alors ceux de ce réseau, rien
    /// n'est posé.
    pub via: Option<String>,
}

impl JoinedOut {
    fn new(j: &Joined) -> Self {
        let t = j.held.temp();
        JoinedOut {
            account_id: j.account_id.clone(),
            iface: j.service.clone(),
            ip: t.ip.to_string(),
            mask: t.mask.to_string(),
            cidr: format!("{}/{}", t.ip, u32::from(t.mask).count_ones()),
            via: None,
        }
    }

    fn routed(r: &RoutedJoin) -> Self {
        let net = Ipv4Addr::from(u32::from(r.ip) & u32::from(r.mask));
        JoinedOut {
            account_id: r.account_id.clone(),
            iface: r.service.clone(),
            ip: net.to_string(),
            mask: r.mask.to_string(),
            cidr: format!("{net}/{}", u32::from(r.mask).count_ones()),
            via: Some(r.via.to_string()),
        }
    }
}

/// Le réseau du compte est-il joint par un routeur ? Oui si la route vers
/// `probe` passe par une passerelle ET que `probe` répond au ping par là.
/// La route seule ne suffit pas : un réseau inconnu du poste (caméras neuves
/// en 192.168.0.x sur le même câble) part aussi par la route par défaut ;
/// seule une réponse dit que le routeur le connaît. Rend la passerelle.
/// ⚠️ À demander AVANT de poser une adresse (la route deviendrait connectée).
pub(crate) async fn routed_via(routes: &dyn Routes, ping: &dyn FreeProbe, probe: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
    let probe = probe?;
    let Route::Routed(via) = routes.route_to(probe).await else {
        return None;
    };
    // Deux tirs : un écho perdu ne doit pas faire poser une adresse qui coupe le routage.
    for _ in 0..2 {
        if ping.ping(probe).await == Reply::Alive {
            return Some(via);
        }
    }
    None
}

/// Les interfaces que les contrôles d'une pose doivent voir : l'adresse
/// principale (relevée avant la pose en cours) à la place de l'adresse
/// posée, et jamais l'adresse posée elle-même (service « Lenscout » de
/// macOS, qui apparaît comme une interface de plus).
pub(crate) fn join_inputs(
    fresh: ScanInterface,
    others: Vec<ScanInterface>,
    current: Option<(&TempIp, &ScanInterface)>,
) -> (ScanInterface, Vec<ScanInterface>) {
    let Some((temp, primary)) = current else {
        return (fresh, others);
    };
    // Relue à chaque pose ; la relevée à la pose précédente ne sert que si
    // la lecture rend l'adresse posée (bail DHCP changé entre-temps : la
    // nouvelle adresse principale compte).
    let primary_for = |i: ScanInterface| if i.name == temp.iface && i.ip == temp.ip { primary.clone() } else { i };
    let base = primary_for(fresh);
    let mut seen = vec![base.name.clone()];
    let others = others
        .into_iter()
        .map(primary_for)
        .filter(|i| i.ip != temp.ip)
        .filter(|i| {
            let new = !seen.contains(&i.name);
            seen.push(i.name.clone());
            new
        })
        .collect();
    (base, others)
}

/// L'adresse à poser pour le compte sur `iface` (adresse principale), les
/// autres interfaces actives étant `others`. Codes : `account_no_pc_ip`,
/// `pc_ip_prefix_unsupported` (compte d'avant les bornes /8 à /30),
/// `already_in_network` (l'interface est déjà dans ce réseau),
/// `network_overlaps_other_iface` (le réseau du compte recouvre celui d'une
/// autre interface : le poste ne saurait plus par où joindre ces adresses).
pub(crate) fn join_target(net: &AccountNetwork, iface: &ScanInterface, others: &[ScanInterface]) -> Result<TempIp, String> {
    let pc_ip = net.pc_ip.as_deref().ok_or("account_no_pc_ip")?;
    let (ip, prefix) = pc_ip
        .split_once('/')
        .and_then(|(ip, p)| Some((ip.parse::<Ipv4Addr>().ok()?, p.parse::<u32>().ok()?)))
        .ok_or("account_no_pc_ip")?;
    if !(8..=30).contains(&prefix) {
        return Err("pc_ip_prefix_unsupported".into());
    }
    let mask = Ipv4Addr::from(!0u32 << (32 - prefix));
    if !needs_temp_ip(iface.ip, iface.mask, ip) || !needs_temp_ip(ip, mask, iface.ip) {
        return Err("already_in_network".into());
    }
    if others.iter().any(|o| subnets_overlap(ip, mask, o.ip, o.mask)) {
        return Err("network_overlaps_other_iface".into());
    }
    Ok(TempIp { iface: iface.name.clone(), ip, mask })
}

fn temp_ip_code(e: TempIpError) -> String {
    match e {
        TempIpError::ElevationRefused => "elevation_refused",
        TempIpError::Busy => "temp_ip_busy",
        _ => "temp_ip_failed",
    }
    .to_string()
}

/// L'adresse en place n'a pas pu être retirée (refus compris) : elle reste.
fn kept_code(e: TempIpError) -> String {
    match e {
        TempIpError::ElevationRefused | TempIpError::Busy | TempIpError::Invalid(_) => temp_ip_code(e),
        _ => "temp_ip_left".to_string(),
    }
}

/// L'interface d'une adresse posée a disparu (adaptateur USB débranché) :
/// sous Linux l'adresse est partie avec elle, il n'y a rien à retirer.
/// Ailleurs on tente le retrait normal (le service macOS, lui, survit).
/// Présence, pas état du lien : câble débranché, l'adresse est toujours là.
async fn interface_gone(service: &str) -> bool {
    cfg!(target_os = "linux") && interface_gone_under(std::path::Path::new("/sys/class/net"), service)
}

/// `name` absent de `sys_net` (`/sys/class/net`). Nom douteux : `false`.
fn interface_gone_under(sys_net: &std::path::Path, name: &str) -> bool {
    let plain = !name.is_empty() && name != "." && name != ".." && !name.contains('/');
    plain && !sys_net.join(name).exists()
}

/// Retire l'adresse posée, s'il y en a une. Échec ou refus : elle reste
/// tenue (`temp_ip_left`, `elevation_refused`), l'écran reste sur le compte.
async fn release_current(state: &JoinState) -> Result<(), String> {
    state.routed_lock().take();
    let Some(j) = state.lock().take() else {
        return Ok(());
    };
    if interface_gone(&j.service).await {
        j.held.abandon();
        return Ok(());
    }
    let Joined { held, account_id, gateway, service, primary } = j;
    match held.release(&SystemElevator) {
        Ok(()) => Ok(()),
        Err((held, e)) => {
            *state.lock() = Some(Joined { held: *held, account_id, gateway, service, primary });
            Err(kept_code(e))
        }
    }
}

/// Erreurs : codes stables (`not_found`, `account_no_pc_ip`,
/// `pc_ip_prefix_unsupported`, `iface_unknown`,
/// `iface_no_ipv4`, `already_in_network`, `network_overlaps_other_iface`,
/// `pc_ip_in_use`, `elevation_refused`, `temp_ip_busy`, `temp_ip_failed`,
/// `temp_ip_left`, `join_lost`, `internal`), traduits par le front.
///
/// Tous les contrôles passent AVANT de toucher l'adresse déjà posée. Puis
/// A est remplacée par B (une seule invite sous Windows et Linux) ; refus
/// ou échec : A reste ou est reposée, sinon `join_lost` (plus rien de posé).
#[tauri::command]
pub async fn cmd_join_network(
    account_id: String,
    iface: String,
    accounts: State<'_, Mutex<AccountBook>>,
    journal: State<'_, TempIpJournal>,
    state: State<'_, JoinState>,
) -> Result<JoinedOut, String> {
    let _one = state.op.lock().await;
    let account = accounts
        .lock()
        .map_err(|_| "internal".to_string())?
        .list()
        .into_iter()
        .find(|a| a.id == account_id)
        .ok_or("not_found")?;
    let name = iface.clone();
    let (fresh, others) = tauri::async_runtime::spawn_blocking(move || {
        let up = list_interfaces_up();
        if !up.contains(&name) {
            return Err("iface_unknown".to_string());
        }
        let fresh = ScanInterface::from_details(&name, &get_interface_details(&name))
            .ok_or_else(|| "iface_no_ipv4".to_string())?;
        let others: Vec<ScanInterface> = up
            .iter()
            .filter(|n| **n != name)
            .filter_map(|n| ScanInterface::from_details(n, &get_interface_details(n)))
            .collect();
        Ok((fresh, others))
    })
    .await
    .map_err(|_| "internal".to_string())??;
    let current = {
        let guard = state.lock();
        guard.as_ref().map(|j| (j.held.temp().clone(), j.primary.clone(), j.account_id.clone(), j.service.clone()))
    };
    let (base, others) = join_inputs(fresh, others, current.as_ref().map(|(t, p, _, _)| (t, p)));
    let target = join_target(&account.net, &base, &others)?;
    if let Some((t, _, id, service)) = &current
        && *t == target
        && *id == account_id
        && *service == iface
    {
        return state.out().ok_or_else(|| "internal".to_string());
    }
    // Le routeur joint-il déjà ce réseau ? Demandé avant toute pose. Alors
    // rien n'est posé : l'adresse du compte couperait l'accès routé.
    let gateway: Option<Ipv4Addr> = account.net.gateway.as_deref().and_then(|g| g.parse().ok());
    let probe = probe_address(target.ip, target.mask, gateway);
    let via = routed_via(&SystemRoutes, &SystemProbe { iface: base.clone() }, probe).await;
    lenscout_core::debug_log::log(&match via {
        Some(v) => format!("compte : {probe:?} joint par le routeur {v}, rien n'est posé"),
        None => format!("compte : {probe:?} ni routé ni joignable, l'adresse est posée"),
    });
    if let (Some(via), Some(probe)) = (via, probe) {
        release_current(&state).await?;
        *state.routed_lock() = Some(RoutedJoin {
            account_id,
            service: iface,
            iface: base.name.clone(),
            ip: target.ip,
            mask: target.mask,
            probe,
            via,
        });
        return state.out().ok_or_else(|| "internal".to_string());
    }
    // Une adresse déjà vue dans la table ARP appartient à un autre appareil.
    let ours = current.as_ref().is_some_and(|(t, ..)| t.ip == target.ip);
    if !ours && read_neighbours(&base).await.contains_key(&target.ip) {
        return Err("pc_ip_in_use".into());
    }
    state.routed_lock().take();
    let previous = state.lock().take();
    let previous = match previous {
        Some(j) if interface_gone(&j.service).await => {
            j.held.abandon();
            None
        }
        other => other,
    };
    let held = match previous {
        None => hold_temp_ip(&SystemElevator, &journal.0, &target, &iface).await.map_err(temp_ip_code)?,
        Some(j) => {
            let Joined { held, account_id: id_a, gateway: gw_a, service: svc_a, primary: prim_a } = j;
            let back = |held| Joined { held, account_id: id_a.clone(), gateway: gw_a, service: svc_a.clone(), primary: prim_a.clone() };
            match switch_held(&SystemElevator, &journal.0, held, &target, &iface).await {
                Ok(held) => held,
                Err(SwitchFailure::Kept(held, e)) => {
                    *state.lock() = Some(back(*held));
                    return Err(kept_code(e));
                }
                Err(SwitchFailure::Restored(held, e)) => {
                    *state.lock() = Some(back(*held));
                    return Err(temp_ip_code(e));
                }
                Err(SwitchFailure::Lost(_)) => return Err("join_lost".into()),
            }
        }
    };
    *state.lock() = Some(Joined { held, account_id, gateway, service: iface, primary: base });
    state.out().ok_or_else(|| "internal".to_string())
}

/// Retour sur DHCP : l'adresse posée est retirée (rien d'autre n'est
/// touché, aucun client DHCP n'est lancé). Codes : `temp_ip_left`,
/// `elevation_refused` (l'adresse reste posée).
#[tauri::command]
pub async fn cmd_leave_network(state: State<'_, JoinState>) -> Result<(), String> {
    let _one = state.op.lock().await;
    release_current(&state).await
}

/// Délai laissé au système pour faire apparaître l'adresse posée.
const PRESENCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const PRESENCE_EVERY: std::time::Duration = std::time::Duration::from_millis(200);

/// Attend que l'adresse posée soit utilisable (`present`), au plus
/// `PRESENCE_TIMEOUT`. Code : `pc_ip_not_present`.
async fn wait_present(t: &TempIp, mut present: impl FnMut(Ipv4Addr) -> bool) -> Result<(), String> {
    let ip = t.ip;
    if presence::wait_until(|| present(ip), PRESENCE_TIMEOUT, PRESENCE_EVERY).await {
        Ok(())
    } else {
        Err("pc_ip_not_present".to_string())
    }
}

/// Après une pose, avant le scan qui suit : l'adresse du compte est-elle
/// bien sur le poste ? (macOS : le service dupliqué la fait apparaître un
/// peu après la fin de `networksetup`.) Rien de posé : tout de suite `Ok`.
/// Code : `pc_ip_not_present`. L'adresse reste tenue dans tous les cas.
#[tauri::command]
pub async fn cmd_join_ready(state: State<'_, JoinState>) -> Result<(), String> {
    let Some(t) = state.temp() else {
        return Ok(());
    };
    let r = wait_present(&t, presence::address_present).await;
    // Journal de mise au point : où le système a mis l'adresse (sous macOS,
    // le service dupliqué pourrait la poser sur un autre nom BSD).
    let service = state.lock().as_ref().map(|j| j.service.clone()).unwrap_or_default();
    // Windows : lu par PowerShell, donc hors du runtime.
    let ip = t.ip;
    let on = tauri::async_runtime::spawn_blocking(move || presence::interface_of(ip)).await.ok().flatten();
    lenscout_core::debug_log::log(&ready_log_line(&t, &service, on.as_deref(), &r));
    r
}

/// Ligne de journal d'une pose : adresse, service choisi à l'écran et
/// interface visée (`TempIp::iface` : nom BSD sous macOS, alias sous
/// Windows), puis interface qui la porte vraiment.
fn ready_log_line(t: &TempIp, service: &str, on: Option<&str>, r: &Result<(), String>) -> String {
    let head = format!("pose : {}/{} via « {service} » ({})", t.ip, t.mask, t.iface);
    match (on, r) {
        (Some(i), _) if i == t.iface => format!("{head} : présente sur {i}"),
        (Some(i), _) => format!("{head} : présente sur {i}, PAS sur l'interface attendue"),
        (None, Ok(())) => format!("{head} : présente, interface non lue"),
        (None, Err(code)) => format!("{head} : absente du poste ({code})"),
    }
}

/// Lu après la pose ou le retrait en cours : jamais un état intermédiaire.
#[tauri::command]
pub async fn cmd_joined_network(state: State<'_, JoinState>) -> Result<Option<JoinedOut>, String> {
    let _one = state.op.lock().await;
    Ok(state.out())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, mask: &str) -> ScanInterface {
        ScanInterface { name: name.into(), ip: ip.parse().unwrap(), mask: mask.parse().unwrap() }
    }

    fn en0(ip: &str, mask: &str) -> ScanInterface {
        iface("en0", ip, mask)
    }

    #[tokio::test(start_paused = true)]
    async fn l_adresse_posee_est_attendue_avant_le_scan() {
        let t = TempIp { iface: "en0".into(), ip: "192.168.1.10".parse().unwrap(), mask: "255.255.255.0".parse().unwrap() };
        let mut seen = 0;
        let r = wait_present(&t, |ip| {
            assert_eq!(ip, t.ip);
            seen += 1;
            seen >= 3
        })
        .await;
        assert_eq!(r, Ok(()));
        assert_eq!(seen, 3);
        // Jamais là : erreur claire au bout du délai.
        let start = tokio::time::Instant::now();
        assert_eq!(wait_present(&t, |_| false).await, Err("pc_ip_not_present".to_string()));
        assert!(start.elapsed() <= PRESENCE_TIMEOUT);
    }

    #[test]
    fn la_ligne_de_journal_de_la_pose_se_lit_sans_decoder() {
        let t = temp("en0", "192.168.1.10", "255.255.255.0");
        let ok: Result<(), String> = Ok(());
        let late: Result<(), String> = Err("pc_ip_not_present".into());
        assert_eq!(
            ready_log_line(&t, "Wi-Fi", Some("en0"), &ok),
            "pose : 192.168.1.10/255.255.255.0 via « Wi-Fi » (en0) : présente sur en0"
        );
        assert_eq!(
            ready_log_line(&t, "Wi-Fi", Some("en1"), &ok),
            "pose : 192.168.1.10/255.255.255.0 via « Wi-Fi » (en0) : présente sur en1, PAS sur l'interface attendue"
        );
        assert_eq!(
            ready_log_line(&t, "Wi-Fi", None, &late),
            "pose : 192.168.1.10/255.255.255.0 via « Wi-Fi » (en0) : absente du poste (pc_ip_not_present)"
        );
    }

    fn net(pc_ip: Option<&str>) -> AccountNetwork {
        AccountNetwork { pc_ip: pc_ip.map(str::to_string), ..Default::default() }
    }

    fn temp(name: &str, ip: &str, mask: &str) -> TempIp {
        TempIp { iface: name.into(), ip: ip.parse().unwrap(), mask: mask.parse().unwrap() }
    }

    #[test]
    fn target_is_the_pc_ip_of_the_account_on_the_resolved_interface() {
        let t = join_target(&net(Some("192.168.1.250/24")), &en0("10.0.0.5", "255.255.0.0"), &[]).unwrap();
        assert_eq!(t, temp("en0", "192.168.1.250", "255.255.255.0"));
    }

    #[test]
    fn account_without_pc_ip_cannot_join() {
        let i = en0("10.0.0.5", "255.255.0.0");
        for bad in [None, Some("x"), Some("192.168.1.250")] {
            assert_eq!(join_target(&net(bad), &i, &[]).unwrap_err(), "account_no_pc_ip", "{bad:?}");
        }
    }

    #[test]
    fn old_account_with_a_prefix_out_of_bounds_has_its_own_code() {
        let i = en0("10.0.0.5", "255.255.0.0");
        for bad in ["192.168.1.250/31", "10.0.0.250/7", "192.168.1.250/32", "192.168.1.250/0"] {
            assert_eq!(join_target(&net(Some(bad)), &i, &[]).unwrap_err(), "pc_ip_prefix_unsupported", "{bad}");
        }
    }

    #[test]
    fn interface_already_in_the_network_is_refused() {
        let i = en0("192.168.1.20", "255.255.255.0");
        assert_eq!(join_target(&net(Some("192.168.1.250/24")), &i, &[]).unwrap_err(), "already_in_network");
        // Réseaux qui se recouvrent, dans un sens ou dans l'autre.
        assert_eq!(join_target(&net(Some("192.168.1.250/16")), &i, &[]).unwrap_err(), "already_in_network");
        let wide = en0("192.168.5.5", "255.255.0.0");
        assert_eq!(join_target(&net(Some("192.168.1.250/24")), &wide, &[]).unwrap_err(), "already_in_network");
    }

    #[test]
    fn network_of_another_active_interface_is_refused() {
        let i = en0("10.0.0.5", "255.255.255.0");
        let wifi = iface("en1", "192.168.1.30", "255.255.255.0");
        let r = join_target(&net(Some("192.168.1.250/24")), &i, std::slice::from_ref(&wifi));
        assert_eq!(r.unwrap_err(), "network_overlaps_other_iface");
        // Recouvrement partiel : /16 du compte contre /24 du Wi-Fi.
        let r = join_target(&net(Some("192.168.7.250/16")), &i, std::slice::from_ref(&wifi));
        assert_eq!(r.unwrap_err(), "network_overlaps_other_iface");
        assert!(join_target(&net(Some("172.16.0.250/24")), &i, &[wifi]).is_ok());
    }

    #[test]
    fn checks_use_the_primary_address_never_the_posed_one() {
        // A posée sur en0 (192.168.1.250/24) ; Linux rapporte parfois l'adresse
        // posée comme celle de l'interface. Le compte B vise 192.168.1.0/24
        // aussi : il faut comparer à l'adresse principale (10.0.0.5).
        let a = temp("en0", "192.168.1.250", "255.255.255.0");
        let primary = en0("10.0.0.5", "255.255.255.0");
        let fresh = en0("192.168.1.250", "255.255.255.0");
        let (base, others) = join_inputs(fresh, vec![], Some((&a, &primary)));
        assert_eq!(base, primary);
        assert!(join_target(&net(Some("192.168.1.240/24")), &base, &others).is_ok());
    }

    #[test]
    fn the_posed_address_never_counts_as_another_interface() {
        // macOS : le service « Lenscout » apparaît comme une interface de plus.
        let a = temp("en0", "192.168.1.250", "255.255.255.0");
        let primary = en0("10.0.0.5", "255.255.255.0");
        let lenscout = en0("192.168.1.250", "255.255.255.0");
        let wifi = iface("en1", "172.16.0.9", "255.255.255.0");
        let (base, others) = join_inputs(primary.clone(), vec![lenscout, wifi.clone()], Some((&a, &primary)));
        assert_eq!(base, primary);
        assert_eq!(others, vec![wifi]);
        // Changement d'interface : l'ancienne compte par son adresse principale.
        let fresh_en1 = iface("en1", "172.16.0.9", "255.255.255.0");
        let posed_en0 = en0("192.168.1.250", "255.255.255.0");
        let (base, others) = join_inputs(fresh_en1.clone(), vec![posed_en0], Some((&a, &primary)));
        assert_eq!(base, fresh_en1);
        assert_eq!(others, vec![primary.clone()], "en0 compte par son adresse principale, jamais la posée");
        let (_, others) = join_inputs(fresh_en1, vec![primary.clone()], Some((&a, &primary)));
        assert_eq!(others, vec![primary]);
    }

    #[test]
    fn primary_is_read_again_at_each_switch() {
        // Le bail DHCP d'en0 a changé depuis la pose : l'adresse relue sert,
        // la relevée à la pose seulement si la lecture rend l'adresse posée.
        let a = temp("en0", "192.168.1.250", "255.255.255.0");
        let at_pose = en0("10.0.0.5", "255.255.255.0");
        let now = en0("10.0.0.77", "255.255.255.0");
        let (base, _) = join_inputs(now.clone(), vec![], Some((&a, &at_pose)));
        assert_eq!(base, now);
        let (_, others) = join_inputs(iface("en1", "172.16.0.9", "255.255.255.0"), vec![now.clone()], Some((&a, &at_pose)));
        assert_eq!(others, vec![now]);
    }

    #[test]
    fn unplugged_interface_is_gone_but_a_cable_out_is_not() {
        let sys = lenscout_core::testing::TmpDir::new("lenscout-join");
        std::fs::create_dir(sys.join("enx001122")).unwrap();
        // Présente (câble débranché ou non) : on tente le retrait normal.
        assert!(!interface_gone_under(&sys, "enx001122"));
        assert!(interface_gone_under(&sys, "enx334455"));
        // Nom douteux : jamais « disparue » (le retrait normal est tenté).
        for bad in ["", ".", "..", "a/b"] {
            assert!(!interface_gone_under(&sys, bad), "{bad}");
        }
    }

    #[test]
    fn nothing_held_means_no_scope_change() {
        let state = JoinState::default();
        let base = en0("10.0.0.5", "255.255.0.0");
        assert_eq!(state.scope(base.clone()), base);
        assert_eq!(state.gateway_on("en0"), None);
        assert!(state.out().is_none());
    }

    #[test]
    fn removal_failures_keep_the_address_with_their_code() {
        assert_eq!(kept_code(TempIpError::ElevationRefused), "elevation_refused");
        assert_eq!(kept_code(TempIpError::Failed("x".into())), "temp_ip_left");
        assert_eq!(kept_code(TempIpError::Busy), "temp_ip_busy");
    }

    struct Ping(Vec<Reply>, std::sync::Mutex<usize>);

    #[async_trait::async_trait]
    impl FreeProbe for Ping {
        async fn ping(&self, _: Ipv4Addr) -> Reply {
            let mut n = self.1.lock().unwrap();
            *n += 1;
            self.0.get(*n - 1).copied().unwrap_or(Reply::Silent)
        }
        async fn neighbours(&self) -> std::collections::HashSet<Ipv4Addr> {
            Default::default()
        }
    }

    fn ping(replies: &[Reply]) -> Ping {
        Ping(replies.to_vec(), std::sync::Mutex::new(0))
    }

    #[tokio::test]
    async fn un_reseau_route_qui_repond_ne_pose_rien() {
        use lenscout_core::testing::FakeRoutes;
        let gw: Ipv4Addr = "10.0.20.1".parse().unwrap();
        let routed = FakeRoutes::routed("10.0.8.1");
        assert_eq!(routed_via(&routed, &ping(&[Reply::Alive]), Some(gw)).await, Some("10.0.8.1".parse().unwrap()));
        assert_eq!(routed.asked(), vec![gw]);
        // Un écho perdu : second tir.
        assert!(routed_via(&routed, &ping(&[Reply::Silent, Reply::Alive]), Some(gw)).await.is_some());
    }

    #[tokio::test]
    async fn sur_le_lien_inconnu_ou_muet_le_comportement_reste() {
        use lenscout_core::testing::FakeRoutes;
        let gw: Ipv4Addr = "192.168.0.1".parse().unwrap();
        // Route par défaut vers un réseau que le routeur ignore (caméras neuves
        // sur le même câble) : personne ne répond, on pose comme avant.
        assert_eq!(routed_via(&FakeRoutes::routed("10.0.8.1"), &ping(&[]), Some(gw)).await, None);
        for route in [Route::OnLink("en0".into()), Route::Unknown] {
            let r = FakeRoutes::new(route);
            assert_eq!(routed_via(&r, &ping(&[Reply::Alive]), Some(gw)).await, None);
        }
        assert_eq!(routed_via(&FakeRoutes::routed("10.0.8.1"), &ping(&[Reply::Alive]), None).await, None);
    }

    #[test]
    fn le_mode_route_se_lit_comme_le_reseau_du_compte_avec_sa_passerelle() {
        let state = JoinState::default();
        let r = RoutedJoin {
            account_id: "galleria".into(),
            service: "Wi-Fi".into(),
            iface: "en0".into(),
            ip: "10.0.20.2".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            probe: "10.0.20.1".parse().unwrap(),
            via: "10.0.8.1".parse().unwrap(),
        };
        *state.routed_lock() = Some(r.clone());
        let out = state.out().unwrap();
        assert_eq!((out.ip.as_str(), out.cidr.as_str(), out.via.as_deref()), ("10.0.20.0", "10.0.20.0/24", Some("10.0.8.1")));
        assert_eq!(out.iface, "Wi-Fi");
        // Rien de posé : le scan et les actions gardent l'adresse de l'interface.
        assert!(state.temp().is_none());
        let base = en0("10.0.8.235", "255.255.255.0");
        assert_eq!(state.scope(base.clone()), base);
        assert_eq!(state.routed_on("en0"), Some(r));
        assert_eq!(state.routed_on("en1"), None);
        state.let_go();
        assert!(state.out().is_none());
    }
}
