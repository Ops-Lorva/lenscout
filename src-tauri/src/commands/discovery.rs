use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lenscout_core::discovery::arp::{ScanInterface, SystemArp};
use lenscout_core::discovery::scanner::{
    open_probe_socket, routed_targets, run_scan, MdnsProbe, Probe, RoutedSweep, ScanConfig, ScanEvent, WsdProbe,
};
use lenscout_core::discovery::sadp::SadpProbe;
use lenscout_core::http_client::ReqwestCameraHttp;
use lenscout_core::actions::{SeenState, row_key};
use lenscout_core::interfaces::{get_interface_details, list_interfaces_up};
use lenscout_core::model::{Activation, Addressing, Camera, Family};
use lenscout_core::presence;
use lenscout_core::transport::Datagram;
use tauri::ipc::Channel;
use tauri::{AppHandle, State};
use tauri_plugin_opener::OpenerExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Durée d'écoute des sondes.
const LISTEN: Duration = Duration::from_secs(6);
/// Délai d'une requête HTTP vers une caméra pendant l'enrichissement.
const HTTP_TIMEOUT: Duration = Duration::from_secs(4);
/// Délai d'une requête du balayage routé : la plupart des adresses ne
/// répondent pas, le balayage doit tenir dans le temps d'écoute.
const ROUTED_TIMEOUT: Duration = Duration::from_millis(1500);

/// Le scan en cours, s'il y en a un : un seul à la fois.
#[derive(Default)]
pub struct ScanState {
    pub cancel: Mutex<Option<CancellationToken>>,
    /// Ce que le dernier scan a entendu, tenu par Rust : seule une adresse de
    /// cette liste, sur cette interface, peut justifier une IP temporaire (le
    /// front fournit la caméra, il ne doit pas pouvoir inventer une cible).
    pub last_seen: Mutex<LastSeen>,
}

#[derive(Default, Clone, Debug)]
pub struct LastSeen {
    /// Numéro du scan : un scan remplacé qui finit de se vider ne doit pas
    /// écrire dans celui qui l'a remplacé.
    pub generation: u64,
    /// `ScanInterface::name` du scan.
    pub iface: Option<String>,
    /// Adresses qui se sont annoncées elles-mêmes (`ScanEvent::Heard`).
    pub ips: HashSet<Ipv4Addr>,
    /// MAC (normalisées) annoncées en SADP depuis leur propre adresse
    /// (`ScanEvent::HeardSadp`) : seules celles-ci peuvent recevoir une action
    /// SADP, qui diffuse le mot de passe sur le LAN de l'interface.
    pub sadp_macs: HashSet<String>,
    /// Par clé de ligne (MAC, sinon IP) : adresse et état d'activation de sa
    /// dernière annonce. Seule une ligne lue neuve (ou inconnue, relue à
    /// l'action) à cette adresse peut être activée.
    pub states: HashMap<String, (Ipv4Addr, Activation)>,
    /// Adresses qui ont répondu au balayage HTTP du réseau routé
    /// (`ScanEvent::HeardRouted`) : seules celles-ci peuvent être jointes à
    /// travers le routeur, sans IP temporaire.
    pub routed: HashSet<Ipv4Addr>,
}

/// Instantané de `LastSeen`, adresses triées.
pub struct SeenSnapshot {
    pub iface: Option<String>,
    pub ips: Vec<Ipv4Addr>,
    pub sadp_macs: Vec<String>,
    /// Triés par clé.
    pub states: Vec<SeenState>,
    /// Triées.
    pub routed: Vec<Ipv4Addr>,
}

impl ScanState {
    pub fn seen(&self) -> SeenSnapshot {
        let last = self.last_seen.lock().unwrap();
        let mut ips: Vec<Ipv4Addr> = last.ips.iter().copied().collect();
        ips.sort();
        let mut sadp_macs: Vec<String> = last.sadp_macs.iter().cloned().collect();
        sadp_macs.sort();
        let mut states: Vec<SeenState> = last
            .states
            .iter()
            .map(|(key, (ip, activation))| SeenState { key: key.clone(), ip: *ip, activation: *activation })
            .collect();
        states.sort_by(|a, b| a.key.cmp(&b.key));
        let mut routed: Vec<Ipv4Addr> = last.routed.iter().copied().collect();
        routed.sort();
        SeenSnapshot { iface: last.iface.clone(), ips, sadp_macs, states, routed }
    }

    /// Un nouveau scan repart de zéro, sur son interface ; rend son numéro.
    fn begin(&self, iface: &ScanInterface) -> u64 {
        let mut last = self.last_seen.lock().unwrap();
        let generation = last.generation.wrapping_add(1);
        *last = LastSeen { generation, iface: Some(iface.name.clone()), ..Default::default() };
        generation
    }

    /// N'écrit que si `generation` est encore le scan en cours.
    fn record(&self, generation: u64, ev: &ScanEvent) {
        let mut last = self.last_seen.lock().unwrap();
        if last.generation != generation {
            return;
        }
        match ev {
            ScanEvent::Heard { ip } => {
                last.ips.insert(*ip);
            }
            ScanEvent::HeardSadp { mac } => {
                last.sadp_macs.insert(mac.clone());
            }
            ScanEvent::HeardRouted { ip } => {
                last.routed.insert(*ip);
            }
            ScanEvent::Upsert { camera } => {
                last.states.insert(row_key(camera), (camera.ip, camera.activation));
            }
            _ => {}
        }
    }
}

type ProbeSocket = (Arc<dyn Probe>, Arc<dyn Datagram>);

/// La liste des sondes de la découverte. Une sonde dont le socket ne s'ouvre pas est ignorée (port déjà
/// pris par un autre programme, adresse pas encore là) : les autres sources
/// suffisent à remplir la liste, et l'ARP complète le reste.
fn probes(iface: &ScanInterface) -> Vec<ProbeSocket> {
    let all: Vec<Arc<dyn Probe>> = vec![Arc::new(MdnsProbe), Arc::new(WsdProbe), Arc::new(SadpProbe)];
    let opened = all
        .into_iter()
        .map(|p| (format!("{:?}", p.source()), open_probe_socket(p.as_ref(), iface).map(|dg| (p, dg))))
        .collect();
    keep_opened(opened, lenscout_core::debug_log::log)
}

/// Les sockets ouverts ; chaque échec est une ligne de journal, sans arrêter les autres.
fn keep_opened<T>(opened: Vec<(impl std::fmt::Display, std::io::Result<T>)>, log: impl FnMut(&str)) -> Vec<T> {
    let mut log = log;
    opened
        .into_iter()
        .filter_map(|(name, r)| match r {
            Ok(v) => Some(v),
            Err(e) => {
                log(&format!("scan : socket {name} non lié : {e}"));
                None
            }
        })
        .collect()
}

/// Envoi témoin d'un scan refusé : depuis l'adresse principale vers sa
/// passerelle, seulement si le scan partait de l'adresse d'un compte.
fn control_target(base: &ScanInterface, scanned: &ScanInterface, gateway: Option<Ipv4Addr>) -> Option<(Ipv4Addr, Ipv4Addr)> {
    (scanned.ip != base.ip).then_some(())?;
    Some((base.ip, gateway?))
}

/// Erreurs : codes stables (`iface_unknown`, `iface_no_ipv4`, `no_socket`,
/// `local_network_denied` — tous les envois de découverte refusés par le
/// système, permission « Réseau local » de macOS —, `account_address_denied`
/// — refusés depuis l'adresse du compte seulement, l'envoi témoin depuis
/// l'adresse principale passant (voir `presence::denial_code`) —,
/// `internal`), traduits par le front.
///
/// Lance un scan et rend la main à sa fin. Un scan déjà en cours est annulé
/// d'abord. L'interface vient du front : elle doit figurer parmi les liens
/// actifs.
#[tauri::command]
pub async fn cmd_scan_start(
    iface: String,
    on_event: Channel<ScanEvent>,
    state: State<'_, ScanState>,
    join: State<'_, super::join::JoinState>,
) -> Result<(), String> {
    let token = CancellationToken::new();
    if let Some(old) = state.cancel.lock().unwrap().replace(token.clone()) {
        old.cancel();
    }

    let name = iface.clone();
    let (base, gateway) = tauri::async_runtime::spawn_blocking(move || {
        if !list_interfaces_up().contains(&name) {
            return Err("iface_unknown".to_string());
        }
        let details = get_interface_details(&name);
        let gateway = details.gateway.as_deref().and_then(|g| g.trim().parse::<Ipv4Addr>().ok());
        ScanInterface::from_details(&name, &details)
            .map(|i| (i, gateway))
            .ok_or_else(|| "iface_no_ipv4".to_string())
    })
    .await
    .map_err(|_| "internal".to_string())??;
    // Dans le réseau d'un compte : le scan part de l'adresse posée.
    let scan_iface = join.scope(base.clone());
    let control = control_target(&base, &scan_iface, gateway);

    // Les sockets s'ouvrent ici, dans le runtime, pas dans un thread bloquant :
    // tokio doit les enregistrer.
    let probes = probes(&scan_iface);
    if probes.is_empty() {
        return Err("no_socket".to_string());
    }

    let generation = state.begin(&scan_iface);
    let (tx, mut rx) = mpsc::channel(256);
    // Mode routé : le réseau du compte, balayé en HTTP à travers le routeur.
    let routed = join.routed_on(&base.name).map(|r| RoutedSweep {
        targets: routed_targets(r.probe, r.mask),
        http: Arc::new(ReqwestCameraHttp::new(ROUTED_TIMEOUT)),
    });
    let cfg = ScanConfig { iface: scan_iface, listen: LISTEN, routed };
    let http = Arc::new(ReqwestCameraHttp::new(HTTP_TIMEOUT));
    let scan = tokio::spawn(run_scan(probes, http, Arc::new(SystemArp), cfg, tx, token.clone()));
    while let Some(ev) = rx.recv().await {
        state.record(generation, &ev);
        // Interne : l'adresse entendue ne part pas au webview.
        if matches!(ev, ScanEvent::Heard { .. } | ScanEvent::HeardSadp { .. } | ScanEvent::HeardRouted { .. }) {
            continue;
        }
        // Webview disparue : plus personne n'écoute, on arrête le scan.
        if on_event.send(ev).is_err() {
            token.cancel();
            break;
        }
    }
    let summary = scan.await.unwrap_or_default();
    let witness = match control.filter(|_| summary.local_network_denied) {
        Some((from, gw)) => tauri::async_runtime::spawn_blocking(move || presence::control_send(from, gw)).await.ok(),
        None => None,
    };
    match presence::denial_code(summary.local_network_denied, witness.as_ref()) {
        Some(code) => {
            lenscout_core::debug_log::log(&format!("scan : envois refusés, témoin {witness:?} → {code}"));
            Err(code.to_string())
        }
        None => Ok(()),
    }
}

#[tauri::command]
pub fn cmd_scan_cancel(state: State<'_, ScanState>) {
    if let Some(t) = state.cancel.lock().unwrap().take() {
        t.cancel();
    }
}

/// Lectures `Network.BootProto` en même temps, au plus.
const ADDRESSING_PARALLEL: usize = 8;

/// Les Axis dont on peut lire l'adressage avec le compte : activées selon le
/// dernier scan (état tenu par Rust, pas celui du front), entendues depuis
/// leur adresse, et seules sur cette adresse (sinon on ne saurait pas qui
/// répond). Le compte ne part vers rien d'autre.
fn addressing_targets(cameras: &[Camera], seen: &SeenSnapshot) -> Vec<(Ipv4Addr, String)> {
    let shared = |ip: Ipv4Addr| seen.states.iter().filter(|s| s.ip == ip).count() > 1;
    cameras
        .iter()
        .filter(|c| c.family == Family::Axis && seen.ips.contains(&c.ip) && !shared(c.ip))
        .filter(|c| {
            let key = row_key(c);
            seen.states.iter().any(|s| s.key == key && s.ip == c.ip && s.activation == Activation::Activated)
        })
        .map(|c| (c.ip, c.base_url()))
        .collect()
}

/// Une adressage lu (`dhcp` | `static`), par adresse.
#[derive(serde::Serialize, Debug, PartialEq)]
pub struct AddressingOut {
    pub ip: Ipv4Addr,
    pub addressing: Addressing,
}

/// Erreurs : `not_found`, `secret_missing`, `keyring` (compte).
///
/// Après un scan : lit `Network.BootProto` des Axis activées avec le compte
/// retenu, en parallèle borné. Le scan n'attend pas ces lectures ; une
/// caméra qui ne répond pas, ou refuse le compte, n'a pas de ligne (« — »).
#[tauri::command]
pub async fn cmd_read_addressing(
    cameras: Vec<Camera>,
    account_id: String,
    scan: State<'_, ScanState>,
    accounts: State<'_, Mutex<lenscout_core::accounts::AccountBook>>,
) -> Result<Vec<AddressingOut>, String> {
    let creds = super::accounts::credentials_for(&accounts, &account_id)?;
    let targets = addressing_targets(&cameras, &scan.seen());
    let http = ReqwestCameraHttp::new(HTTP_TIMEOUT);
    let read = lenscout_core::vapix::addressing_of_all(&http, targets, &creds, ADDRESSING_PARALLEL).await;
    Ok(read.into_iter().map(|(ip, addressing)| AddressingOut { ip, addressing }).collect())
}

/// L'URL est reconstruite ici : le front ne fournit qu'une IPv4 et un port,
/// jamais un schéma ni un hôte qui ouvrirait autre chose qu'une caméra.
fn camera_web_url(ip: &str, port: u16) -> Result<String, String> {
    let ip: Ipv4Addr = ip.trim().parse().map_err(|_| "bad_ip".to_string())?;
    if port == 0 {
        return Err("bad_port".to_string());
    }
    Ok(match port {
        80 => format!("http://{ip}/"),
        443 => format!("https://{ip}/"),
        p => format!("http://{ip}:{p}/"),
    })
}

#[tauri::command]
pub fn cmd_open_camera_web(app: AppHandle, ip: String, port: u16) -> Result<(), String> {
    let url = camera_web_url(&ip, port)?;
    app.opener().open_url(url, None::<&str>).map_err(|_| "open_failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth0() -> ScanInterface {
        ScanInterface { name: "eth0".into(), ip: "10.0.50.2".parse().unwrap(), mask: "255.255.255.0".parse().unwrap() }
    }

    #[test]
    fn un_socket_lie_suffit_les_echecs_sont_journalises() {
        let mut logged = Vec::new();
        let kept = keep_opened(
            vec![
                ("mdns", Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))),
                ("wsd", Ok(2)),
                ("sadp", Err(std::io::Error::from(std::io::ErrorKind::AddrInUse))),
            ],
            |l| logged.push(l.to_string()),
        );
        assert_eq!(kept, vec![2]);
        assert_eq!(logged.len(), 2);
        assert!(logged[0].contains("mdns") && logged[1].contains("sadp"), "{logged:?}");
        assert!(keep_opened::<u8>(vec![("mdns", Err(std::io::Error::other("x")))], |_| {}).is_empty());
    }

    #[test]
    fn le_temoin_ne_part_que_d_une_adresse_de_compte_avec_passerelle() {
        let base = eth0();
        let joined = ScanInterface { ip: "192.168.1.10".parse().unwrap(), ..eth0() };
        let gw: Ipv4Addr = "10.0.50.1".parse().unwrap();
        assert_eq!(control_target(&base, &joined, Some(gw)), Some((base.ip, gw)));
        // Scan sur l'adresse principale : pas de témoin, le refus vaut pour l'app.
        assert_eq!(control_target(&base, &base, Some(gw)), None);
        assert_eq!(control_target(&base, &joined, None), None);
    }

    #[test]
    fn seules_les_adresses_entendues_sont_retenues_avec_leur_interface() {
        let state = ScanState::default();
        let cam = Camera {
            ip: "169.254.10.20".parse().unwrap(),
            mac: None,
            family: Family::Axis,
            brand: None,
            model: None,
            serial: None,
            firmware: None,
            activation: Activation::New,
            http_port: 80,
            sources: vec![],
            addressing: None,
        };
        let g = state.begin(&eth0());
        state.record(g, &ScanEvent::Done);
        state.record(g, &ScanEvent::Upsert { camera: cam });
        assert!(state.seen().ips.is_empty(), "une annonce ne suffit pas");
        let ip: Ipv4Addr = "169.254.10.20".parse().unwrap();
        state.record(g, &ScanEvent::Heard { ip });
        state.record(g, &ScanEvent::Heard { ip });
        let seen = state.seen();
        assert_eq!(seen.ips, vec![ip]);
        assert_eq!(seen.iface.as_deref(), Some("eth0"));
        // Un nouveau scan repart de zéro, sur sa propre interface.
        state.begin(&ScanInterface { name: "wlan0".into(), ..eth0() });
        assert!(state.seen().ips.is_empty());
        assert_eq!(state.seen().iface.as_deref(), Some("wlan0"));
    }

    /// L'état d'activation lu au scan est tenu par Rust, par clé de ligne avec
    /// son adresse : la dernière annonce d'une ligne fait foi.
    #[test]
    fn l_etat_lu_au_scan_est_retenu_par_ligne_avec_son_adresse() {
        use lenscout_core::actions::SeenState;
        let state = ScanState::default();
        let cam = |mac: Option<&str>, activation| Camera {
            ip: "192.0.2.11".parse().unwrap(),
            mac: mac.map(String::from),
            family: Family::Axis,
            brand: None,
            model: None,
            serial: None,
            firmware: None,
            activation,
            http_port: 80,
            sources: vec![],
            addressing: None,
        };
        let st = |key: &str, ip: &str, activation| SeenState { key: key.into(), ip: ip.parse().unwrap(), activation };
        let g = state.begin(&eth0());
        state.record(g, &ScanEvent::Upsert { camera: cam(Some("AC:CC:8E:12:34:56"), Activation::Unknown) });
        assert_eq!(state.seen().states, vec![st("AC:CC:8E:12:34:56", "192.0.2.11", Activation::Unknown)]);
        state.record(g, &ScanEvent::Upsert { camera: cam(Some("AC:CC:8E:12:34:56"), Activation::New) });
        state.record(g, &ScanEvent::Upsert { camera: cam(None, Activation::New) });
        assert_eq!(
            state.seen().states,
            vec![st("192.0.2.11", "192.0.2.11", Activation::New), st("AC:CC:8E:12:34:56", "192.0.2.11", Activation::New)]
        );
        // Relue activée, puis déplacée (DHCP) : la dernière annonce fait foi.
        state.record(g, &ScanEvent::Upsert { camera: cam(Some("AC:CC:8E:12:34:56"), Activation::Activated) });
        let mut moved = cam(Some("AC:CC:8E:12:34:56"), Activation::Activated);
        moved.ip = "192.0.2.12".parse().unwrap();
        state.record(g, &ScanEvent::Upsert { camera: moved });
        assert_eq!(state.seen().states[1], st("AC:CC:8E:12:34:56", "192.0.2.12", Activation::Activated));
        state.begin(&eth0());
        assert!(state.seen().states.is_empty(), "un nouveau scan repart de zéro");
    }

    /// Un scan remplacé qui finit de se vider n'écrit pas dans le nouveau.
    #[test]
    fn un_ancien_scan_n_ecrit_pas_dans_le_nouveau() {
        let state = ScanState::default();
        let old = state.begin(&eth0());
        let new = state.begin(&ScanInterface { name: "wlan0".into(), ..eth0() });
        assert_ne!(old, new);
        state.record(old, &ScanEvent::Heard { ip: "192.0.2.31".parse().unwrap() });
        state.record(old, &ScanEvent::HeardSadp { mac: "C0:56:E3:5A:7D:01".into() });
        assert!(state.seen().ips.is_empty());
        assert!(state.seen().sadp_macs.is_empty());
        state.record(new, &ScanEvent::Heard { ip: "192.0.2.32".parse().unwrap() });
        assert_eq!(state.seen().ips, vec!["192.0.2.32".parse::<Ipv4Addr>().unwrap()]);
    }

    #[test]
    fn les_adresses_du_balayage_route_sont_retenues_a_part() {
        let state = ScanState::default();
        let g = state.begin(&eth0());
        let ip: Ipv4Addr = "10.0.20.11".parse().unwrap();
        state.record(g, &ScanEvent::HeardRouted { ip });
        let seen = state.seen();
        assert_eq!(seen.routed, vec![ip]);
        assert!(seen.ips.is_empty(), "une réponse routée n'est pas une annonce de couche 2");
        state.begin(&eth0());
        assert!(state.seen().routed.is_empty());
    }

    #[test]
    fn seules_les_mac_entendues_en_sadp_sont_retenues_avec_leur_interface() {
        let state = ScanState::default();
        let g = state.begin(&eth0());
        state.record(g, &ScanEvent::Heard { ip: "192.0.2.31".parse().unwrap() });
        assert!(state.seen().sadp_macs.is_empty(), "une adresse entendue ne vaut pas une MAC SADP");
        state.record(g, &ScanEvent::HeardSadp { mac: "C0:56:E3:5A:7D:01".into() });
        state.record(g, &ScanEvent::HeardSadp { mac: "C0:56:E3:5A:7D:01".into() });
        assert_eq!(state.seen().sadp_macs, vec!["C0:56:E3:5A:7D:01".to_string()]);
        state.begin(&ScanInterface { name: "wlan0".into(), ..eth0() });
        assert!(state.seen().sadp_macs.is_empty());
    }

    /// Un paquet SADP dont l'adresse annoncée n'est pas sa source ne prouve rien.
    #[tokio::test]
    async fn sadp_heard_requires_source_equal_announced_address() {
        use lenscout_core::discovery::scanner::run_scan_with_capture;
        use lenscout_core::testing::{FakeDatagram, FakeHttp};
        let xml = include_str!("../../../crates/lenscout-core/tests/fixtures/sadp_inquiry_response_activated.xml");
        for (src, heard) in [("192.0.2.31:37020", true), ("192.0.2.77:37020", false)] {
            let dg = Arc::new(FakeDatagram::new(vec![(xml.as_bytes().to_vec(), src.parse().unwrap())]));
            let probes: Vec<(Arc<dyn Probe>, Arc<dyn Datagram>)> = vec![(Arc::new(SadpProbe), dg)];
            let state = ScanState::default();
            let g = state.begin(&eth0());
            let (tx, mut rx) = mpsc::channel(64);
            let cfg = ScanConfig { iface: eth0(), listen: Duration::from_millis(200), routed: None };
            run_scan_with_capture(probes, Arc::new(FakeHttp::new()), Arc::new(NoArp), cfg, tx, CancellationToken::new(), None).await;
            while let Ok(ev) = rx.try_recv() {
                state.record(g, &ev);
            }
            assert_eq!(!state.seen().sadp_macs.is_empty(), heard, "{src}");
        }
    }

    use lenscout_core::discovery::arp::ArpSource;

    struct NoArp;

    #[async_trait::async_trait]
    impl ArpSource for NoArp {
        async fn sweep_and_read(&self, _: &ScanInterface) -> std::collections::HashMap<Ipv4Addr, String> {
            Default::default()
        }
    }

    #[tokio::test]
    async fn reponse_wsd_qui_annonce_une_autre_adresse_hors_sous_reseau_refusee_sans_elevation() {
        use lenscout_core::actions::{Action, ActionContext, ActionError, apply};
        use lenscout_core::discovery::scanner::{Probe, ScanConfig, WsdProbe, run_scan_with_capture};
        use lenscout_core::secret::Secret;
        use lenscout_core::testing::{FakeDatagram, FakeHttp, PanicElevator};
        use lenscout_core::transport::Credentials;

        let xml = include_str!("../../../crates/lenscout-core/tests/fixtures/wsd_axis_probematch.xml")
            .replace("192.0.2.11", "10.66.66.66");
        let dg = Arc::new(FakeDatagram::new(vec![(xml.into_bytes(), "10.0.50.9:3702".parse().unwrap())]));
        let probes: Vec<(Arc<dyn Probe>, Arc<dyn Datagram>)> = vec![(Arc::new(WsdProbe), dg)];
        let state = ScanState::default();
        let g = state.begin(&eth0());
        let (tx, mut rx) = mpsc::channel(64);
        let cfg = ScanConfig { iface: eth0(), listen: Duration::from_millis(200), routed: None };
        run_scan_with_capture(probes, Arc::new(FakeHttp::new()), Arc::new(NoArp), cfg, tx, CancellationToken::new(), None).await;
        let mut listed = false;
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Upsert { camera } = &ev {
                listed |= camera.ip == "10.66.66.66".parse::<Ipv4Addr>().unwrap();
            }
            state.record(g, &ev);
        }
        assert!(listed, "la caméra reste listée");

        let seen = state.seen();
        let ctx = ActionContext {
            http: Arc::new(FakeHttp::new()),
            iface: eth0(),
            service: "eth0".into(),
            elevator: Arc::new(PanicElevator),
            journal: std::env::temp_dir().join("lenscout-test-jamais-cree").join("temp-ip.json"),
            seen: seen.ips,
            seen_iface: seen.iface,
            seen_sadp: seen.sadp_macs,
            sadp: None,
            in_use: vec![],
            other_ifaces: vec![],
            account_network: false,
            seen_states: seen.states,
            neighbours: Arc::new(lenscout_core::testing::FakeNeighbours::any("AC:CC:8E:12:34:56")),
            seen_routed: seen.routed,
            routes: Arc::new(lenscout_core::testing::FakeRoutes::routed("10.0.50.1")),
        };
        let cam = Camera {
            ip: "10.66.66.66".parse().unwrap(),
            mac: Some("AC:CC:8E:12:34:56".into()),
            family: Family::Axis,
            brand: None,
            model: None,
            serial: None,
            firmware: None,
            activation: Activation::New,
            http_port: 80,
            sources: vec![],
            addressing: None,
        };
        let creds = Credentials { login: "root".into(), password: Secret::new("x".into()) };
        let time = Action::Time(lenscout_core::vapix::TimeSettings { ntp_servers: vec![], timezone: "UTC".into() });
        for action in [Action::Activate, time] {
            let r = apply(&ctx, &cam, &creds, &action).await;
            assert_eq!(r.error, Some(ActionError::CameraOffSubnet));
        }
    }

    #[test]
    fn url_reconstruite_depuis_une_ipv4() {
        assert_eq!(camera_web_url("10.0.50.7", 80).unwrap(), "http://10.0.50.7/");
        assert_eq!(camera_web_url("10.0.50.7", 443).unwrap(), "https://10.0.50.7/");
        assert_eq!(camera_web_url("10.0.50.7", 8080).unwrap(), "http://10.0.50.7:8080/");
    }

    #[test]
    fn tout_ce_qui_nest_pas_une_ipv4_est_refuse() {
        for bad in ["file:///etc/passwd", "cam.local", "http://10.0.0.1", "::1", "10.0.0.1/x", "", "10.0.0.1@evil.example"] {
            assert!(camera_web_url(bad, 80).is_err(), "{bad}");
        }
        assert_eq!(camera_web_url("nope", 80).unwrap_err(), "bad_ip");
        assert_eq!(camera_web_url("10.0.50.7", 0).unwrap_err(), "bad_port");
    }

    fn axis(ip: &str, mac: &str, activation: Activation) -> Camera {
        Camera {
            ip: ip.parse().unwrap(),
            mac: Some(mac.into()),
            family: Family::Axis,
            brand: None,
            model: None,
            serial: None,
            firmware: None,
            activation,
            http_port: 80,
            sources: vec![],
            addressing: None,
        }
    }

    /// Le compte ne part que vers une Axis activée que le dernier scan a
    /// entendue à cette adresse, seule sur son adresse ; l'état vient de Rust.
    #[test]
    fn la_lecture_dhcp_ne_vise_que_les_axis_activees_entendues() {
        let state = ScanState::default();
        let g = state.begin(&eth0());
        let a = axis("10.0.50.11", "AC:CC:8E:00:00:11", Activation::Activated);
        let neuve = axis("10.0.50.12", "AC:CC:8E:00:00:12", Activation::New);
        let muette = axis("10.0.50.13", "AC:CC:8E:00:00:13", Activation::Activated);
        let partage1 = axis("10.0.50.14", "AC:CC:8E:00:00:14", Activation::Activated);
        let partage2 = axis("10.0.50.14", "AC:CC:8E:00:00:24", Activation::Activated);
        let mut hik = axis("10.0.50.15", "C0:56:E3:00:00:15", Activation::Activated);
        hik.family = Family::Hikvision;
        for c in [&a, &neuve, &muette, &partage1, &partage2, &hik] {
            state.record(g, &ScanEvent::Upsert { camera: c.clone() });
        }
        for ip in ["10.0.50.11", "10.0.50.12", "10.0.50.14", "10.0.50.15"] {
            state.record(g, &ScanEvent::Heard { ip: ip.parse().unwrap() });
        }
        // Le front dit « activée » pour la neuve : Rust ne le croit pas.
        let mut menteuse = neuve.clone();
        menteuse.activation = Activation::Activated;
        let all = [a.clone(), menteuse, muette, partage1, partage2, hik];
        let got = addressing_targets(&all, &state.seen());
        assert_eq!(got, vec![("10.0.50.11".parse().unwrap(), "http://10.0.50.11".to_string())]);
    }
}
