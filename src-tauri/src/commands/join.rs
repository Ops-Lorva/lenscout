use std::net::Ipv4Addr;
use std::sync::Mutex;

use lenscout_core::accounts::{AccountBook, AccountNetwork};
use lenscout_core::discovery::arp::{ScanInterface, read_neighbours};
use lenscout_core::interfaces::{get_interface_details, list_interfaces_up};
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

impl JoinState {
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
    }

    fn out(&self) -> Option<JoinedOut> {
        self.lock().as_ref().map(JoinedOut::new)
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
        }
    }
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
    let primary_for = |i: ScanInterface| if i.name == temp.iface { primary.clone() } else { i };
    let base = primary_for(fresh);
    let mut seen = vec![base.name.clone()];
    let others = others
        .into_iter()
        .filter(|i| i.ip != temp.ip)
        .map(primary_for)
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
/// `already_in_network` (l'interface est déjà dans ce réseau),
/// `network_overlaps_other_iface` (le réseau du compte recouvre celui d'une
/// autre interface : le poste ne saurait plus par où joindre ces adresses).
pub(crate) fn join_target(net: &AccountNetwork, iface: &ScanInterface, others: &[ScanInterface]) -> Result<TempIp, String> {
    let pc_ip = net.pc_ip.as_deref().ok_or("account_no_pc_ip")?;
    let (ip, prefix) = pc_ip
        .split_once('/')
        .and_then(|(ip, p)| Some((ip.parse::<Ipv4Addr>().ok()?, p.parse::<u32>().ok()?)))
        .filter(|(_, p)| (8..=30).contains(p))
        .ok_or("account_no_pc_ip")?;
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
async fn interface_gone(service: &str) -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let name = service.to_string();
    tauri::async_runtime::spawn_blocking(move || !list_interfaces_up().contains(&name))
        .await
        .unwrap_or(false)
}

/// Retire l'adresse posée, s'il y en a une. Échec ou refus : elle reste
/// tenue (`temp_ip_left`, `elevation_refused`), l'écran reste sur le compte.
async fn release_current(state: &JoinState) -> Result<(), String> {
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

/// Erreurs : codes stables (`not_found`, `account_no_pc_ip`, `iface_unknown`,
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
    // Une adresse déjà vue dans la table ARP appartient à un autre appareil.
    let ours = current.as_ref().is_some_and(|(t, ..)| t.ip == target.ip);
    if !ours && read_neighbours(&base).await.contains_key(&target.ip) {
        return Err("pc_ip_in_use".into());
    }
    let gateway = account.net.gateway.as_deref().and_then(|g| g.parse().ok());
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
        for bad in [None, Some("x"), Some("192.168.1.250/31"), Some("10.0.0.250/7")] {
            assert_eq!(join_target(&net(bad), &i, &[]).unwrap_err(), "account_no_pc_ip", "{bad:?}");
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
        assert!(others.is_empty(), "l'adresse posée sur en0 est écartée");
        let (_, others) = join_inputs(fresh_en1, vec![primary.clone()], Some((&a, &primary)));
        assert_eq!(others, vec![primary]);
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
}
