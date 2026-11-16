//! Relevé du réseau d'un compte : commande Tauri, progression en flux et annulation.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lenscout_core::accounts::{AccountBook, NetworkFill, unix_now};
use lenscout_core::discovery::arp::ScanInterface;
use lenscout_core::discovery::socket::open_ephemeral;
use lenscout_core::free_ips::{FreeError, SystemProbe};
use lenscout_core::model::Camera;
use lenscout_core::oui::vendor_for_mac;
use lenscout_core::site_survey::device::{Clues, SeenDevice, guess_kind};
use lenscout_core::site_survey::names::{NameSource, resolve_names};
use lenscout_core::site_survey::sweep::{HostSeen, sweep};
use serde::Serialize;
use tauri::State;
use tauri::ipc::Channel;
use tokio_util::sync::CancellationToken;

use super::free_ips::{SweepScope, sweep_scope};
use super::join::JoinState;

/// Attente des réponses NetBIOS et mDNS, toutes adresses ensemble.
const NAMES_WAIT: Duration = Duration::from_millis(1500);

/// Le relevé en cours : un seul à la fois, remplacé au démarrage du suivant.
#[derive(Default)]
pub struct SiteSurveyState {
    inner: Mutex<Runs>,
}

#[derive(Default)]
struct Runs {
    current: Option<(u64, CancellationToken)>,
    /// Annulations reçues avant le démarrage de leur relevé.
    early: HashSet<u64>,
}

/// Plus d'annulations en avance que cela : le front n'en produit pas autant.
const MAX_EARLY: usize = 64;

// Même mécanisme que `FreeIpsState` (commands/free_ips.rs).
impl SiteSurveyState {
    /// Le jeton du relevé `id` (déjà annulé s'il l'a été avant de démarrer) ;
    /// le relevé précédent est annulé.
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

    /// Annule le relevé `id` ; un autre relevé n'est pas touché.
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

/// Miroir côté front : `src/lib/api/siteNet.ts`.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SurveyEvent {
    Progress { done: usize, total: usize },
    Done { devices: Vec<SeenDevice>, surveyed_at: u64, fill: Option<NetworkFill>, truncated: bool },
}

/// Garde « sur place » : l'adresse balayée (celle de l'interface, du compte
/// posé, ou du routeur en mode routé) est dans le réseau de l'IP du PC du
/// compte. Codes : `account_no_pc_ip`, `not_on_account_network`.
fn on_account_network(pc_ip: Option<&str>, scope: &ScanInterface) -> Result<(), String> {
    let (ip, prefix) = pc_ip.and_then(|p| p.trim().split_once('/')).ok_or("account_no_pc_ip")?;
    let (Ok(ip), Ok(prefix)) = (ip.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else {
        return Err("account_no_pc_ip".into());
    };
    if prefix > 32 {
        return Err("account_no_pc_ip".into());
    }
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    if u32::from(ip) & mask == u32::from(scope.ip) & mask {
        Ok(())
    } else {
        Err("not_on_account_network".into())
    }
}

/// Les appareils d'un relevé, datés `at` : constructeur de la MAC, nom
/// (NetBIOS sinon mDNS), modèle d'une caméra connue à cette adresse, type
/// deviné. `cameras` : adresse → modèle des caméras vues ou connues.
fn devices_of(
    hosts: &[HostSeen],
    names: &HashMap<Ipv4Addr, (String, NameSource)>,
    cameras: &HashMap<Ipv4Addr, Option<String>>,
    gateway: Option<Ipv4Addr>,
    pc: Option<Ipv4Addr>,
    at: u64,
) -> Vec<SeenDevice> {
    hosts
        .iter()
        .map(|h| {
            let vendor = h.mac.as_deref().and_then(vendor_for_mac);
            let name = names.get(&h.ip);
            let model = cameras.get(&h.ip).cloned().flatten();
            let kind = guess_kind(&Clues {
                ip: h.ip,
                mac: h.mac.as_deref(),
                vendor: vendor.as_deref(),
                camera_model: model.as_deref(),
                is_camera: cameras.contains_key(&h.ip),
                netbios: name.is_some_and(|(_, s)| *s == NameSource::NetBios),
                gateway,
                pc,
            });
            SeenDevice {
                ip: h.ip,
                mac: h.mac.clone(),
                vendor,
                kind,
                name: name.map(|(n, _)| n.clone()),
                model,
                first_seen: at,
                last_seen: at,
            }
        })
        .collect()
}

/// Erreurs : codes stables (`iface_unknown`, `iface_no_ipv4`,
/// `ping_unavailable`, `not_found`, `account_no_pc_ip`,
/// `not_on_account_network`, `internal`), traduits par le front.
///
/// Balaie le réseau du compte (ping puis ARP), demande les noms, devine les
/// types, retient le relevé dans le compte, puis envoie `Done`. En mode
/// routé, ni MAC ni constructeur : l'ARP ne passe pas le routeur.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_site_survey(
    id: u64,
    account_id: String,
    interface: String,
    cameras: Vec<Camera>,
    channel: Channel<SurveyEvent>,
    state: State<'_, SiteSurveyState>,
    join: State<'_, JoinState>,
    accounts: State<'_, Mutex<AccountBook>>,
) -> Result<(), String> {
    let token = state.begin(id);
    let (net, known) = {
        let book = accounts.lock().map_err(|_| "internal".to_string())?;
        let net = book.list().into_iter().find(|a| a.id == account_id).ok_or("not_found")?.net;
        (net, book.known_cameras(&account_id).map_err(|_| "not_found".to_string())?)
    };
    let SweepScope { iface, gateway, routed, probe } = sweep_scope(interface, &join).await?;
    on_account_network(net.pc_ip.as_deref(), &iface)?;

    let sender = channel.clone();
    let stop = token.clone();
    let progress = move |done, total| {
        if !stop.is_cancelled() && sender.send(SurveyEvent::Progress { done, total }).is_err() {
            stop.cancel();
        }
    };
    let ping = Arc::new(SystemProbe { iface: probe.clone() });
    let (hosts, truncated) = match sweep(&iface, ping, progress, token.clone()).await {
        Ok(found) => found,
        Err(FreeError::Cancelled) => return Ok(()),
        Err(FreeError::PingUnavailable) => return Err("ping_unavailable".into()),
    };
    if token.is_cancelled() {
        return Ok(());
    }

    let ips: Vec<Ipv4Addr> = hosts.iter().map(|h| h.ip).collect();
    let names = match (open_ephemeral(&probe), open_ephemeral(&probe)) {
        (Ok(nb), Ok(md)) => resolve_names(&ips, Arc::new(nb), Arc::new(md), NAMES_WAIT).await,
        // Sans socket : le relevé reste, sans noms.
        _ => HashMap::new(),
    };
    if token.is_cancelled() {
        return Ok(());
    }

    let mut models: HashMap<Ipv4Addr, Option<String>> = known.into_iter().map(|c| (c.ip, c.model)).collect();
    models.extend(cameras.into_iter().map(|c| (c.ip, c.model)));
    let gateway = net.gateway.as_deref().and_then(|g| g.trim().parse().ok()).or(gateway);
    let pc = (!routed).then_some(iface.ip);
    let at = unix_now();
    let seen = devices_of(&hosts, &names, &models, gateway, pc, at);

    let (devices, fill) = {
        let mut book = accounts.lock().map_err(|_| "internal".to_string())?;
        book.record_survey(&account_id, seen, at).map_err(|_| "not_found".to_string())?;
        let (devices, _) = book.devices(&account_id).map_err(|_| "not_found".to_string())?;
        (devices, book.fill(&account_id, &[]).ok().flatten())
    };
    let _ = channel.send(SurveyEvent::Done { devices, surveyed_at: at, fill, truncated });
    Ok(())
}

#[tauri::command]
pub fn cmd_site_survey_cancel(id: u64, state: State<'_, SiteSurveyState>) {
    state.cancel(id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenscout_core::site_survey::device::DeviceKind;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn scope(addr: &str, mask: &str) -> ScanInterface {
        ScanInterface { name: "eth0".into(), ip: ip(addr), mask: ip(mask) }
    }

    #[test]
    fn survey_refused_off_the_account_network() {
        let pc = Some("192.168.1.250/24");
        assert_eq!(on_account_network(pc, &scope("192.168.1.7", "255.255.255.0")), Ok(()));
        // Interface sur un /16 qui couvre le réseau du compte : son adresse y est.
        assert_eq!(on_account_network(pc, &scope("192.168.1.7", "255.255.0.0")), Ok(()));
        assert_eq!(on_account_network(pc, &scope("10.0.50.2", "255.255.255.0")), Err("not_on_account_network".into()));
        assert_eq!(on_account_network(pc, &scope("192.168.2.7", "255.255.255.0")), Err("not_on_account_network".into()));
        assert_eq!(on_account_network(None, &scope("192.168.1.7", "255.255.255.0")), Err("account_no_pc_ip".into()));
        assert_eq!(on_account_network(Some("x"), &scope("192.168.1.7", "255.255.255.0")), Err("account_no_pc_ip".into()));
    }

    #[test]
    fn survey_events_serialize_as_the_front_reads_them() {
        let p = serde_json::to_string(&SurveyEvent::Progress { done: 3, total: 253 }).unwrap();
        assert_eq!(p, r#"{"kind":"progress","done":3,"total":253}"#);
        let d = serde_json::to_value(SurveyEvent::Done { devices: vec![], surveyed_at: 9, fill: None, truncated: false }).unwrap();
        assert_eq!(d, serde_json::json!({"kind": "done", "devices": [], "surveyed_at": 9, "fill": null, "truncated": false}));
    }

    #[test]
    fn cancel_before_start_is_kept() {
        let state = SiteSurveyState::default();
        state.cancel(7);
        assert!(state.begin(7).is_cancelled(), "le relevé démarre déjà annulé");
        assert!(!state.begin(8).is_cancelled(), "et l'annulation ne vaut que pour lui");
        let a = state.begin(9);
        state.cancel(10);
        assert!(!a.is_cancelled());
        state.cancel(9);
        assert!(a.is_cancelled());
    }

    #[test]
    fn devices_carry_vendor_name_model_and_guessed_kind() {
        let hosts = [
            HostSeen { ip: ip("192.168.1.1"), mac: None, replied: true },
            HostSeen { ip: ip("192.168.1.20"), mac: Some("AC:CC:8E:00:00:20".into()), replied: true },
            HostSeen { ip: ip("192.168.1.30"), mac: None, replied: true },
            HostSeen { ip: ip("192.168.1.40"), mac: None, replied: false },
            HostSeen { ip: ip("192.168.1.50"), mac: None, replied: true },
        ];
        let names = HashMap::from([
            (ip("192.168.1.40"), ("POSTE-ACCUEIL".to_string(), NameSource::NetBios)),
            (ip("192.168.1.50"), ("imprimante".to_string(), NameSource::Mdns)),
        ]);
        let cams = HashMap::from([(ip("192.168.1.30"), Some("DS-7608NI-K2".to_string())), (ip("192.168.1.20"), None)]);
        let d = devices_of(&hosts, &names, &cams, Some(ip("192.168.1.1")), Some(ip("192.168.1.250")), 42);
        let got: Vec<_> = d.iter().map(|d| (d.kind, d.name.as_deref(), d.model.as_deref())).collect();
        assert_eq!(
            got,
            [
                (DeviceKind::Gateway, None, None),
                (DeviceKind::Camera, None, None),
                (DeviceKind::Nvr, None, Some("DS-7608NI-K2")),
                (DeviceKind::Pc, Some("POSTE-ACCUEIL"), None),
                (DeviceKind::Unknown, Some("imprimante"), None),
            ]
        );
        assert!(d[1].vendor.as_deref().is_some_and(|v| v.to_lowercase().contains("axis")));
        assert!(d.iter().all(|d| d.first_seen == 42 && d.last_seen == 42));
    }
}
