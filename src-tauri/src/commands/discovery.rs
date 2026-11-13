use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lenscout_core::discovery::arp::{ScanInterface, SystemArp};
use lenscout_core::discovery::scanner::{
    open_probe_socket, run_scan, MdnsProbe, Probe, ScanConfig, ScanEvent, WsdProbe,
};
use lenscout_core::http_client::ReqwestCameraHttp;
use lenscout_core::interfaces::{get_interface_details, list_interfaces_up};
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
    /// `ScanInterface::name` du scan.
    pub iface: Option<String>,
    /// Adresses qui se sont annoncées elles-mêmes (`ScanEvent::Heard`).
    pub ips: HashSet<Ipv4Addr>,
}

/// Instantané de `LastSeen`, adresses triées.
pub struct SeenSnapshot {
    pub iface: Option<String>,
    pub ips: Vec<Ipv4Addr>,
}

impl ScanState {
    pub fn seen(&self) -> SeenSnapshot {
        let last = self.last_seen.lock().unwrap();
        let mut ips: Vec<Ipv4Addr> = last.ips.iter().copied().collect();
        ips.sort();
        SeenSnapshot { iface: last.iface.clone(), ips }
    }

    /// Un nouveau scan repart de zéro, sur son interface.
    fn begin(&self, iface: &ScanInterface) {
        *self.last_seen.lock().unwrap() = LastSeen { iface: Some(iface.name.clone()), ips: HashSet::new() };
    }

    fn record(&self, ev: &ScanEvent) {
        if let ScanEvent::Heard { ip } = ev {
            self.last_seen.lock().unwrap().ips.insert(*ip);
        }
    }
}

type ProbeSocket = (Arc<dyn Probe>, Arc<dyn Datagram>);

/// La liste des sondes de la découverte : c'est ici que SADP s'ajoutera
/// (tâche 14). Une sonde dont le socket ne s'ouvre pas est ignorée (port déjà
/// pris par un autre programme) : les autres sources suffisent à remplir la
/// liste, et l'ARP complète le reste.
fn probes(iface: &ScanInterface) -> Vec<ProbeSocket> {
    let all: Vec<Arc<dyn Probe>> = vec![Arc::new(MdnsProbe), Arc::new(WsdProbe)];
    all.into_iter()
        .filter_map(|p| match open_probe_socket(p.as_ref(), iface) {
            Ok(dg) => Some((p, dg)),
            Err(_) => None,
        })
        .collect()
}

/// Erreurs : codes stables (`iface_unknown`, `iface_no_ipv4`, `no_socket`,
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
) -> Result<(), String> {
    let token = CancellationToken::new();
    if let Some(old) = state.cancel.lock().unwrap().replace(token.clone()) {
        old.cancel();
    }

    let name = iface.clone();
    let scan_iface = tauri::async_runtime::spawn_blocking(move || {
        if !list_interfaces_up().contains(&name) {
            return Err("iface_unknown".to_string());
        }
        ScanInterface::from_details(&name, &get_interface_details(&name))
            .ok_or_else(|| "iface_no_ipv4".to_string())
    })
    .await
    .map_err(|_| "internal".to_string())??;

    // Les sockets s'ouvrent ici, dans le runtime, pas dans un thread bloquant :
    // tokio doit les enregistrer.
    let probes = probes(&scan_iface);
    if probes.is_empty() {
        return Err("no_socket".to_string());
    }

    state.begin(&scan_iface);
    let (tx, mut rx) = mpsc::channel(256);
    let cfg = ScanConfig { iface: scan_iface, listen: LISTEN };
    let http = Arc::new(ReqwestCameraHttp::new(HTTP_TIMEOUT));
    let scan = tokio::spawn(run_scan(probes, http, Arc::new(SystemArp), cfg, tx, token.clone()));
    while let Some(ev) = rx.recv().await {
        state.record(&ev);
        // Interne : l'adresse entendue ne part pas au webview.
        if matches!(ev, ScanEvent::Heard { .. }) {
            continue;
        }
        // Webview disparue : plus personne n'écoute, on arrête le scan.
        if on_event.send(ev).is_err() {
            token.cancel();
            break;
        }
    }
    let _ = scan.await;
    Ok(())
}

#[tauri::command]
pub fn cmd_scan_cancel(state: State<'_, ScanState>) {
    if let Some(t) = state.cancel.lock().unwrap().take() {
        t.cancel();
    }
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
    use lenscout_core::model::{Activation, Camera, Family};

    fn eth0() -> ScanInterface {
        ScanInterface { name: "eth0".into(), ip: "10.0.50.2".parse().unwrap(), mask: "255.255.255.0".parse().unwrap() }
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
        };
        state.begin(&eth0());
        state.record(&ScanEvent::Done);
        state.record(&ScanEvent::Upsert { camera: cam });
        assert!(state.seen().ips.is_empty(), "une annonce ne suffit pas");
        let ip: Ipv4Addr = "169.254.10.20".parse().unwrap();
        state.record(&ScanEvent::Heard { ip });
        state.record(&ScanEvent::Heard { ip });
        let seen = state.seen();
        assert_eq!(seen.ips, vec![ip]);
        assert_eq!(seen.iface.as_deref(), Some("eth0"));
        // Un nouveau scan repart de zéro, sur sa propre interface.
        state.begin(&ScanInterface { name: "wlan0".into(), ..eth0() });
        assert!(state.seen().ips.is_empty());
        assert_eq!(state.seen().iface.as_deref(), Some("wlan0"));
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
        state.begin(&eth0());
        let (tx, mut rx) = mpsc::channel(64);
        let cfg = ScanConfig { iface: eth0(), listen: Duration::from_millis(200) };
        run_scan_with_capture(probes, Arc::new(FakeHttp::new()), Arc::new(NoArp), cfg, tx, CancellationToken::new(), None).await;
        let mut listed = false;
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Upsert { camera } = &ev {
                listed |= camera.ip == "10.66.66.66".parse::<Ipv4Addr>().unwrap();
            }
            state.record(&ev);
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
            in_use: vec![],
            other_ifaces: vec![],
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
        };
        let creds = Credentials { login: "root".into(), password: Secret::new("x".into()) };
        let r = apply(&ctx, &cam, &creds, &Action::Activate).await;
        assert_eq!(r.error, Some(ActionError::CameraOffSubnet));
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
}
