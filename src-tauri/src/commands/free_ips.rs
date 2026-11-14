use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use lenscout_core::discovery::arp::ScanInterface;
use lenscout_core::free_ips::{FreeError, FreeRange, SystemProbe, scan};
use lenscout_core::interfaces::{get_interface_details, list_interfaces_up};
use serde::Serialize;
use tauri::State;
use tauri::ipc::Channel;
use tokio_util::sync::CancellationToken;

use super::discovery::{ScanState, SeenSnapshot};

/// Le balayage d'adresses libres en cours : un seul à la fois, remplacé au
/// démarrage du suivant. Le front numérote ses balayages : une annulation vise
/// un balayage précis, et celle qui arrive avant son démarrage est retenue.
#[derive(Default)]
pub struct FreeIpsState {
    inner: Mutex<Runs>,
}

#[derive(Default)]
struct Runs {
    current: Option<(u64, CancellationToken)>,
    /// Annulations reçues avant le démarrage de leur balayage.
    early: HashSet<u64>,
}

/// Plus d'annulations en avance que cela : le front n'en produit pas autant.
const MAX_EARLY: usize = 64;

impl FreeIpsState {
    /// Le jeton du balayage `id` (déjà annulé s'il l'a été avant de démarrer) ;
    /// le balayage précédent est annulé.
    fn begin(&self, id: u64) -> CancellationToken {
        let mut runs = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let token = CancellationToken::new();
        if runs.early.remove(&id) {
            token.cancel();
        }
        if let Some((_, old)) = runs.current.replace((id, token.clone())) {
            old.cancel();
        }
        token
    }

    /// Annule le balayage `id` ; un autre balayage n'est pas touché.
    fn cancel(&self, id: u64) {
        let mut runs = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cur, token)) = &runs.current
            && *cur == id
        {
            token.cancel();
            runs.current = None;
        } else {
            if runs.early.len() >= MAX_EARLY {
                runs.early.clear();
            }
            runs.early.insert(id);
        }
    }
}

/// Miroir côté front : `src/lib/api/freeIps.ts`.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum FreeIpsEvent {
    Progress { done: usize, total: usize },
    Done { ranges: Vec<FreeRange>, truncated: bool },
}

/// Ce que le balayage ne doit pas proposer : les caméras entendues au dernier
/// scan de cette interface, la passerelle de l'interface. (L'adresse du poste
/// est écartée par le balayage lui-même.)
fn exclusions(iface: &ScanInterface, seen: &SeenSnapshot, gateway: Option<&str>) -> HashSet<Ipv4Addr> {
    let mut out: HashSet<Ipv4Addr> = HashSet::new();
    if seen.iface.as_deref() == Some(iface.name.as_str()) {
        out.extend(seen.ips.iter().copied());
    }
    out.extend(gateway.and_then(|g| g.trim().parse::<Ipv4Addr>().ok()));
    out
}

/// Erreurs : codes stables (`iface_unknown`, `iface_no_ipv4`, `ping_unavailable`,
/// `internal`), traduits par le front.
///
/// Balaie le sous-réseau de l'interface et envoie `Progress` puis `Done`. Un
/// balayage annulé (`cmd_free_ips_cancel`, feuille fermée, balayage remplacé)
/// rend `Ok` sans `Done` : plus rien ne doit viser la feuille disparue.
#[tauri::command]
pub async fn cmd_free_ips(
    id: u64,
    interface: String,
    channel: Channel<FreeIpsEvent>,
    state: State<'_, FreeIpsState>,
    scan_state: State<'_, ScanState>,
    join: State<'_, super::join::JoinState>,
) -> Result<(), String> {
    let token = state.begin(id);

    let name = interface.clone();
    let (iface, gateway) = tauri::async_runtime::spawn_blocking(move || {
        if !list_interfaces_up().contains(&name) {
            return Err("iface_unknown".to_string());
        }
        let details = get_interface_details(&name);
        let iface = ScanInterface::from_details(&name, &details).ok_or_else(|| "iface_no_ipv4".to_string())?;
        Ok((iface, details.gateway))
    })
    .await
    .map_err(|_| "internal".to_string())??;

    // Dans le réseau d'un compte : ce réseau-là, et la passerelle du compte.
    let (iface, gateway) = match join.gateway_on(&iface.name) {
        Some(g) => (join.scope(iface), Some(g.to_string())),
        None if join.temp().is_some_and(|t| t.iface == iface.name) => (join.scope(iface), None),
        None => (iface, gateway),
    };
    let exclude = exclusions(&iface, &scan_state.seen(), gateway.as_deref());
    let probe = Arc::new(SystemProbe { iface: iface.clone() });
    let sender = channel.clone();
    let result = scan(&iface, exclude, probe, progress_to(token.clone(), move |e| sender.send(e).is_ok()), token.clone()).await;
    match result {
        Ok(found) if !token.is_cancelled() => {
            let _ = channel.send(FreeIpsEvent::Done { ranges: found.ranges, truncated: found.truncated });
            Ok(())
        }
        Ok(_) | Err(FreeError::Cancelled) => Ok(()),
        Err(FreeError::PingUnavailable) => Err("ping_unavailable".to_string()),
    }
}

/// La progression envoyée par `send` (qui rend `false` quand le webview n'est
/// plus là : le balayage est annulé). Après l'annulation, rien n'est envoyé.
fn progress_to(token: CancellationToken, send: impl Fn(FreeIpsEvent) -> bool) -> impl Fn(usize, usize) {
    move |done, total| {
        if !token.is_cancelled() && !send(FreeIpsEvent::Progress { done, total }) {
            token.cancel();
        }
    }
}

#[tauri::command]
pub fn cmd_free_ips_cancel(id: u64, state: State<'_, FreeIpsState>) {
    state.cancel(id);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth0() -> ScanInterface {
        ScanInterface { name: "eth0".into(), ip: "10.0.50.2".parse().unwrap(), mask: "255.255.255.0".parse().unwrap() }
    }

    fn seen(iface: &str, ips: &[&str]) -> SeenSnapshot {
        SeenSnapshot { iface: Some(iface.into()), ips: ips.iter().map(|s| s.parse().unwrap()).collect(), sadp_macs: vec![], states: vec![] }
    }

    #[test]
    fn exclusions_hold_seen_cameras_and_the_gateway() {
        let out = exclusions(&eth0(), &seen("eth0", &["10.0.50.31"]), Some("10.0.50.1"));
        let want: HashSet<Ipv4Addr> = ["10.0.50.31", "10.0.50.1"].iter().map(|s| s.parse().unwrap()).collect();
        assert_eq!(out, want);
    }

    #[test]
    fn cameras_heard_on_another_interface_are_not_excluded() {
        let out = exclusions(&eth0(), &seen("wlan0", &["10.0.50.31"]), None);
        assert!(out.is_empty());
        assert!(exclusions(&eth0(), &seen("eth0", &[]), Some("pas une ip")).is_empty());
    }

    #[test]
    fn a_cancel_only_reaches_its_own_run() {
        let state = FreeIpsState::default();
        let a = state.begin(1);
        state.cancel(2);
        assert!(!a.is_cancelled());
        state.cancel(1);
        assert!(a.is_cancelled());
    }

    #[test]
    fn a_cancel_received_before_the_start_is_kept() {
        let state = FreeIpsState::default();
        state.cancel(7);
        let t = state.begin(7);
        assert!(t.is_cancelled(), "le balayage démarre déjà annulé");
        assert!(!state.begin(8).is_cancelled(), "et l'annulation ne vaut que pour lui");
    }

    #[test]
    fn a_new_run_cancels_the_previous_one() {
        let state = FreeIpsState::default();
        let a = state.begin(1);
        let b = state.begin(2);
        assert!(a.is_cancelled() && !b.is_cancelled());
    }

    #[test]
    fn no_event_is_sent_after_cancellation() {
        use std::cell::RefCell;
        let token = CancellationToken::new();
        let sent = RefCell::new(vec![]);
        let progress = progress_to(token.clone(), |e| {
            sent.borrow_mut().push(e);
            true
        });
        progress(1, 3);
        token.cancel();
        progress(2, 3);
        progress(3, 3);
        assert_eq!(*sent.borrow(), vec![FreeIpsEvent::Progress { done: 1, total: 3 }]);
    }

    #[test]
    fn a_closed_webview_cancels_the_run() {
        let token = CancellationToken::new();
        progress_to(token.clone(), |_| false)(1, 3);
        assert!(token.is_cancelled());
    }

    #[test]
    fn events_serialize_with_a_lowercase_kind() {
        let p = serde_json::to_string(&FreeIpsEvent::Progress { done: 137, total: 254 }).unwrap();
        assert_eq!(p, r#"{"kind":"progress","done":137,"total":254}"#);
        let d = FreeIpsEvent::Done {
            ranges: vec![FreeRange { first: "10.0.50.20".parse().unwrap(), last: "10.0.50.22".parse().unwrap(), count: 3 }],
            truncated: false,
        };
        assert_eq!(
            serde_json::to_string(&d).unwrap(),
            r#"{"kind":"done","ranges":[{"first":"10.0.50.20","last":"10.0.50.22","count":3}],"truncated":false}"#
        );
    }
}
