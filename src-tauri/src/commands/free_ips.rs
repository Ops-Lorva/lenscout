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
/// démarrage du suivant.
#[derive(Default)]
pub struct FreeIpsState {
    cancel: Mutex<Option<CancellationToken>>,
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
    interface: String,
    channel: Channel<FreeIpsEvent>,
    state: State<'_, FreeIpsState>,
    scan_state: State<'_, ScanState>,
) -> Result<(), String> {
    let token = CancellationToken::new();
    if let Some(old) = state.cancel.lock().unwrap_or_else(|e| e.into_inner()).replace(token.clone()) {
        old.cancel();
    }

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

    let exclude = exclusions(&iface, &scan_state.seen(), gateway.as_deref());
    let probe = Arc::new(SystemProbe { iface: iface.clone() });
    let (sender, cancel) = (channel.clone(), token.clone());
    let result = scan(
        &iface,
        exclude,
        probe,
        move |done, total| {
            // Feuille fermée ou balayage remplacé : rien n'est envoyé.
            if !cancel.is_cancelled() && sender.send(FreeIpsEvent::Progress { done, total }).is_err() {
                cancel.cancel();
            }
        },
        token.clone(),
    )
    .await;
    match result {
        Ok(found) if !token.is_cancelled() => {
            let _ = channel.send(FreeIpsEvent::Done { ranges: found.ranges, truncated: found.truncated });
            Ok(())
        }
        Ok(_) | Err(FreeError::Cancelled) => Ok(()),
        Err(FreeError::PingUnavailable) => Err("ping_unavailable".to_string()),
    }
}

#[tauri::command]
pub fn cmd_free_ips_cancel(state: State<'_, FreeIpsState>) {
    if let Some(t) = state.cancel.lock().unwrap_or_else(|e| e.into_inner()).take() {
        t.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth0() -> ScanInterface {
        ScanInterface { name: "eth0".into(), ip: "10.0.50.2".parse().unwrap(), mask: "255.255.255.0".parse().unwrap() }
    }

    fn seen(iface: &str, ips: &[&str]) -> SeenSnapshot {
        SeenSnapshot { iface: Some(iface.into()), ips: ips.iter().map(|s| s.parse().unwrap()).collect(), sadp_macs: vec![] }
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
