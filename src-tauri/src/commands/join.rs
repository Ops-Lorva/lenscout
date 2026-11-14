use std::net::Ipv4Addr;
use std::sync::Mutex;

use lenscout_core::accounts::{AccountBook, AccountNetwork};
use lenscout_core::discovery::arp::{ScanInterface, read_neighbours};
use lenscout_core::interfaces::{get_interface_details, list_interfaces_up};
use lenscout_core::temp_ip::{
    HeldTempIp, SystemElevator, TempIp, TempIpError, hold_temp_ip, joined_scope, needs_temp_ip,
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
    /// Une pose ou un retrait à la fois.
    op: tokio::sync::Mutex<()>,
}

struct Joined {
    held: HeldTempIp,
    account_id: String,
    /// Passerelle du compte : écartée des adresses libres.
    gateway: Option<Ipv4Addr>,
    /// Interface telle que le front la nomme (service networksetup sur macOS).
    service: String,
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

/// Miroir côté front : `src/lib/api/join.ts`.
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

/// L'adresse à poser pour le compte sur l'interface `iface` (adresse
/// principale `iface.ip`). Codes : `account_no_pc_ip` (compte sans IP du
/// PC), `already_in_network` (l'interface est déjà dans ce réseau).
pub(crate) fn join_target(net: &AccountNetwork, iface: &ScanInterface) -> Result<TempIp, String> {
    let pc_ip = net.pc_ip.as_deref().ok_or("account_no_pc_ip")?;
    let (ip, prefix) = pc_ip
        .split_once('/')
        .and_then(|(ip, p)| Some((ip.parse::<Ipv4Addr>().ok()?, p.parse::<u32>().ok()?)))
        .filter(|(_, p)| (1..=32).contains(p))
        .ok_or("account_no_pc_ip")?;
    let mask = Ipv4Addr::from(!0u32 << (32 - prefix));
    if !needs_temp_ip(iface.ip, iface.mask, ip) || !needs_temp_ip(ip, mask, iface.ip) {
        return Err("already_in_network".into());
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

/// Retire l'adresse posée, s'il y en a une. Échec : `temp_ip_left` (le
/// journal reste, le démarrage ou la sortie suivants la retireront).
fn release_current(state: &JoinState) -> Result<(), String> {
    let Some(j) = state.lock().take() else {
        return Ok(());
    };
    j.held.release(&SystemElevator).map_err(|_| "temp_ip_left".to_string())
}

/// Erreurs : codes stables (`not_found`, `account_no_pc_ip`, `iface_unknown`,
/// `iface_no_ipv4`, `already_in_network`, `pc_ip_in_use`, `elevation_refused`,
/// `temp_ip_busy`, `temp_ip_failed`, `temp_ip_left`, `internal`), traduits
/// par le front. Une adresse déjà posée (autre compte) est retirée d'abord.
#[tauri::command]
pub async fn cmd_join_network(
    account_id: String,
    iface: String,
    accounts: State<'_, Mutex<AccountBook>>,
    journal: State<'_, TempIpJournal>,
    state: State<'_, JoinState>,
) -> Result<JoinedOut, String> {
    let account = accounts
        .lock()
        .map_err(|_| "internal".to_string())?
        .list()
        .into_iter()
        .find(|a| a.id == account_id)
        .ok_or("not_found")?;
    let name = iface.clone();
    let base = tauri::async_runtime::spawn_blocking(move || {
        if !list_interfaces_up().contains(&name) {
            return Err("iface_unknown".to_string());
        }
        ScanInterface::from_details(&name, &get_interface_details(&name)).ok_or_else(|| "iface_no_ipv4".to_string())
    })
    .await
    .map_err(|_| "internal".to_string())??;
    let target = join_target(&account.net, &base)?;
    let _one = state.op.lock().await;
    release_current(&state)?;
    // Une adresse déjà vue dans la table ARP appartient à un autre appareil.
    if read_neighbours(&base).await.contains_key(&target.ip) {
        return Err("pc_ip_in_use".into());
    }
    let held = hold_temp_ip(&SystemElevator, &journal.0, &target, &iface).await.map_err(temp_ip_code)?;
    let gateway = account.net.gateway.as_deref().and_then(|g| g.parse().ok());
    *state.lock() = Some(Joined { held, account_id, gateway, service: iface });
    state.out().ok_or_else(|| "internal".to_string())
}

/// Retour sur DHCP : l'adresse posée est retirée (rien d'autre n'est
/// touché, aucun client DHCP n'est lancé). Code : `temp_ip_left`.
#[tauri::command]
pub async fn cmd_leave_network(state: State<'_, JoinState>) -> Result<(), String> {
    let _one = state.op.lock().await;
    release_current(&state)
}

#[tauri::command]
pub fn cmd_joined_network(state: State<'_, JoinState>) -> Option<JoinedOut> {
    state.out()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(ip: &str, mask: &str) -> ScanInterface {
        ScanInterface { name: "en0".into(), ip: ip.parse().unwrap(), mask: mask.parse().unwrap() }
    }

    fn net(pc_ip: Option<&str>) -> AccountNetwork {
        AccountNetwork { pc_ip: pc_ip.map(str::to_string), ..Default::default() }
    }

    #[test]
    fn target_is_the_pc_ip_of_the_account_on_the_resolved_interface() {
        let t = join_target(&net(Some("192.168.1.250/24")), &iface("10.0.0.5", "255.255.0.0")).unwrap();
        assert_eq!(t, TempIp { iface: "en0".into(), ip: "192.168.1.250".parse().unwrap(), mask: "255.255.255.0".parse().unwrap() });
    }

    #[test]
    fn account_without_pc_ip_cannot_join() {
        assert_eq!(join_target(&net(None), &iface("10.0.0.5", "255.255.0.0")).unwrap_err(), "account_no_pc_ip");
        assert_eq!(join_target(&net(Some("x")), &iface("10.0.0.5", "255.255.0.0")).unwrap_err(), "account_no_pc_ip");
    }

    #[test]
    fn interface_already_in_the_network_is_refused() {
        let i = iface("192.168.1.20", "255.255.255.0");
        assert_eq!(join_target(&net(Some("192.168.1.250/24")), &i).unwrap_err(), "already_in_network");
        // Réseaux qui se recouvrent, dans un sens ou dans l'autre.
        assert_eq!(join_target(&net(Some("192.168.1.250/16")), &i).unwrap_err(), "already_in_network");
        let wide = iface("192.168.5.5", "255.255.0.0");
        assert_eq!(join_target(&net(Some("192.168.1.250/24")), &wide).unwrap_err(), "already_in_network");
    }

    #[test]
    fn nothing_held_means_no_scope_change() {
        let state = JoinState::default();
        let base = iface("10.0.0.5", "255.255.0.0");
        assert_eq!(state.scope(base.clone()), base);
        assert_eq!(state.gateway_on("en0"), None);
        assert!(state.out().is_none());
        assert_eq!(release_current(&state), Ok(()));
    }
}
