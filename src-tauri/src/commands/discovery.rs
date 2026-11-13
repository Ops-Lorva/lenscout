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

    let (tx, mut rx) = mpsc::channel(256);
    let cfg = ScanConfig { iface: scan_iface, listen: LISTEN };
    let http = Arc::new(ReqwestCameraHttp::new(HTTP_TIMEOUT));
    let scan = tokio::spawn(run_scan(probes, http, Arc::new(SystemArp), cfg, tx, token.clone()));
    while let Some(ev) = rx.recv().await {
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
