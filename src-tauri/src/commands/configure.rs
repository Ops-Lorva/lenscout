use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lenscout_core::accounts::AccountBook;
use lenscout_core::actions::{Action, ActionContext, ActionResult, apply_all, apply_batch, on_subnet};
use lenscout_core::batch::{Assignment, BatchError, BatchRequest, plan_batch};
use lenscout_core::discovery::arp::{ScanInterface, read_neighbours};
use lenscout_core::discovery::sadp;
use lenscout_core::discovery::socket::open_multicast;
use lenscout_core::transport::Datagram;
use lenscout_core::http_client::ReqwestCameraHttp;
use lenscout_core::interfaces::{get_interface_details, list_interfaces_up};
use lenscout_core::model::{Camera, Family};
use lenscout_core::temp_ip::SystemElevator;
use lenscout_core::vapix::{NetworkSettings, TimeSettings};
use serde::{Deserialize, Serialize};
use tauri::State;

use super::accounts::credentials_for;
use super::discovery::ScanState;

/// `<app_data_dir>/temp-ip.json` : l'IP temporaire en cours, à retirer au
/// démarrage si l'app a été tuée.
pub struct TempIpJournal(pub PathBuf);

/// Délai d'une requête d'écriture vers une caméra.
const HTTP_TIMEOUT: Duration = Duration::from_secs(8);

/// Ce que le front peut demander : des adresses déjà typées (`Ipv4Addr` refuse
/// toute autre chaîne), jamais de mot de passe.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionDto {
    Activate,
    NetworkDhcp,
    NetworkStatic {
        ip: Ipv4Addr,
        mask: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        #[serde(default)]
        dns: Vec<Ipv4Addr>,
    },
    Time {
        #[serde(default)]
        ntp_servers: Vec<String>,
        timezone: String,
    },
}

/// Erreurs : codes stables (`bad_action`, `iface_unknown`, `iface_no_ipv4`,
/// `not_found`, `secret_missing`, `internal`), traduits par le front. Les
/// erreurs par caméra sont dans les `ActionResult`.
pub(crate) fn to_action(dto: ActionDto) -> Result<Action, String> {
    Ok(match dto {
        ActionDto::Activate => Action::Activate,
        ActionDto::NetworkDhcp => Action::Network(NetworkSettings::Dhcp),
        ActionDto::NetworkStatic { ip, mask, gateway, dns } => {
            Action::Network(NetworkSettings::Static { ip, mask, gateway, dns })
        }
        ActionDto::Time { ntp_servers, timezone } => {
            let ntp_servers: Vec<String> = ntp_servers
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let timezone = timezone.trim().to_string();
            // Un nom de fuseau ou de serveur part tel quel dans une requête :
            // seuls les caractères d'un nom (IANA ou DNS) sont admis.
            let ok = |s: &str| {
                s.len() <= 253
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._+/:".contains(&b))
            };
            if timezone.is_empty() || !ok(&timezone) || ntp_servers.iter().any(|s| !ok(s)) {
                return Err("bad_action".into());
            }
            Action::Time(TimeSettings { ntp_servers, timezone })
        }
    })
}

/// Le contexte d'écriture, identique pour une action et pour un lot : sous-réseau
/// de l'interface choisie, ce que le dernier scan a entendu, SADP pour une
/// sélection Hikvision.
async fn build_context(
    iface: String,
    cameras: &[Camera],
    scan: &ScanState,
    journal: &std::path::Path,
) -> Result<ActionContext, String> {
    let service = iface.clone();
    let targets: Vec<Ipv4Addr> = cameras.iter().map(|c| c.ip).collect();
    let (scan_iface, any_off_subnet, other_ifaces) = tauri::async_runtime::spawn_blocking(move || {
        let up = list_interfaces_up();
        if !up.contains(&iface) {
            return Err("iface_unknown".to_string());
        }
        let scan_iface = ScanInterface::from_details(&iface, &get_interface_details(&iface))
            .ok_or_else(|| "iface_no_ipv4".to_string())?;
        // Les autres interfaces ne servent qu'au chemin hors sous-réseau :
        // leurs détails coûtent un processus chacune, on ne les lit qu'alors.
        let any_off_subnet = targets.iter().any(|ip| !on_subnet(&scan_iface, *ip));
        let others = if any_off_subnet {
            up.iter()
                .filter(|name| **name != iface)
                .filter_map(|name| ScanInterface::from_details(name, &get_interface_details(name)))
                .collect()
        } else {
            vec![]
        };
        Ok((scan_iface, any_off_subnet, others))
    })
    .await
    .map_err(|_| "internal".to_string())??;
    // Voisins ARP : jamais pris pour l'IP temporaire.
    let in_use = if any_off_subnet { read_neighbours(&scan_iface).await.into_keys().collect() } else { vec![] };
    let seen = scan.seen();
    // Le socket SADP ne s'ouvre que pour une sélection Hikvision ; un port
    // déjà pris ne bloque rien : l'action rendra `unsupported`.
    let sadp: Option<Arc<dyn Datagram>> = if cameras.iter().any(|c| c.family == Family::Hikvision) {
        open_multicast(&scan_iface, sadp::GROUP).ok().map(|d| Arc::new(d) as Arc<dyn Datagram>)
    } else {
        None
    };
    Ok(ActionContext {
        http: Arc::new(ReqwestCameraHttp::new(HTTP_TIMEOUT)),
        iface: scan_iface,
        service,
        elevator: Arc::new(SystemElevator),
        journal: journal.to_path_buf(),
        seen: seen.ips,
        seen_iface: seen.iface,
        seen_sadp: seen.sadp_macs,
        sadp,
        in_use,
        other_ifaces,
    })
}

/// Applique une action aux seules caméras reçues, dans l'ordre. Le front passe
/// la sélection visible ; le cœur revérifie la marque et l'identité de chaque
/// caméra avant d'écrire. Hors du sous-réseau de l'interface, une IP
/// temporaire est posée sur le poste pour une caméra vue au dernier scan.
#[tauri::command]
pub async fn cmd_apply_action(
    cameras: Vec<Camera>,
    account_id: String,
    action: ActionDto,
    iface: String,
    accounts: State<'_, Mutex<AccountBook>>,
    scan: State<'_, ScanState>,
    journal: State<'_, TempIpJournal>,
) -> Result<Vec<ActionResult>, String> {
    let action = to_action(action)?;
    let creds = credentials_for(&accounts, &account_id)?;
    let ctx = build_context(iface, &cameras, &scan, &journal.0).await?;
    Ok(apply_all(&ctx, &cameras, &creds, &action).await)
}

/// Durée de vie d'un aperçu : passé ce délai le réseau a pu changer.
const PREVIEW_TTL: Duration = Duration::from_secs(10 * 60);
/// Aperçus gardés en même temps ; le plus ancien part au-delà.
const PREVIEW_MAX: usize = 8;

/// Un aperçu validé, tel que Rust l'a calculé : c'est lui, et lui seul, que
/// `cmd_batch_apply` applique.
struct StoredPreview {
    cameras: Vec<Camera>,
    rows: Vec<Assignment>,
    req: BatchRequest,
    iface: String,
    created: Instant,
}

/// Aperçus en attente, par identifiant à usage unique.
#[derive(Default)]
pub struct PreviewStore(Mutex<HashMap<String, StoredPreview>>);

impl PreviewStore {
    fn put(&self, p: StoredPreview) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut m = self.0.lock().unwrap();
        m.retain(|_, o| p.created.saturating_duration_since(o.created) <= PREVIEW_TTL);
        while m.len() >= PREVIEW_MAX {
            let Some(oldest) = m.iter().min_by_key(|(_, o)| o.created).map(|(k, _)| k.clone()) else { break };
            m.remove(&oldest);
        }
        m.insert(id.clone(), p);
        id
    }

    /// Sort l'aperçu du magasin dans tous les cas : un identifiant ne sert
    /// qu'une fois, même si l'application a échoué en partie ou si l'aperçu est
    /// refusé. `scan_iface` : interface du dernier scan.
    fn take(&self, id: &str, iface: &str, scan_iface: Option<&str>, now: Instant) -> Result<StoredPreview, String> {
        let p = self.0.lock().unwrap().remove(id).ok_or("preview_unknown")?;
        if now.saturating_duration_since(p.created) > PREVIEW_TTL
            || p.iface != iface
            || scan_iface != Some(p.iface.as_str())
        {
            return Err("preview_expired".into());
        }
        Ok(p)
    }
}

#[derive(Serialize)]
pub struct BatchPreview {
    pub id: String,
    pub rows: Vec<Assignment>,
}

/// Ce que le front peut demander pour un lot : des adresses déjà typées.
#[derive(Deserialize, Debug)]
pub struct BatchRequestDto {
    pub start: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    #[serde(default)]
    pub dns: Vec<Ipv4Addr>,
}

impl From<BatchRequestDto> for BatchRequest {
    fn from(d: BatchRequestDto) -> Self {
        BatchRequest { start: d.start, mask: d.mask, gateway: d.gateway, dns: d.dns }
    }
}

/// Calcule et valide le plan, sans rien envoyer à aucune caméra, et le garde
/// côté Rust sous un identifiant. `selection` est dans l'ordre affiché ;
/// `others` : les autres caméras connues.
#[tauri::command]
pub fn cmd_batch_preview(
    selection: Vec<Camera>,
    others: Vec<Camera>,
    req: BatchRequestDto,
    iface: String,
    store: State<'_, PreviewStore>,
) -> Result<BatchPreview, BatchError> {
    let req: BatchRequest = req.into();
    let rows = plan_batch(&selection, &req, &others)?;
    let id = store.put(StoredPreview { cameras: selection, rows: rows.clone(), req, iface, created: Instant::now() });
    Ok(BatchPreview { id, rows })
}

/// Applique exactement l'aperçu gardé, caméra par caméra, par `apply` : sous-
/// réseau, IP temporaire et identité (MAC / série) vérifiés avant chaque
/// écriture. Erreurs : `preview_unknown` (inconnu ou déjà appliqué),
/// `preview_expired` (plus de 10 min, ou interface différente du scan).
#[tauri::command]
pub async fn cmd_batch_apply(
    preview_id: String,
    account_id: String,
    iface: String,
    accounts: State<'_, Mutex<AccountBook>>,
    scan: State<'_, ScanState>,
    journal: State<'_, TempIpJournal>,
    store: State<'_, PreviewStore>,
) -> Result<Vec<ActionResult>, String> {
    let preview = store.take(&preview_id, &iface, scan.seen().iface.as_deref(), Instant::now())?;
    let creds = credentials_for(&accounts, &account_id)?;
    let ctx = build_context(iface, &preview.cameras, &scan, &journal.0).await?;
    Ok(apply_batch(&ctx, &preview.cameras, &preview.rows, &creds, &preview.req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<Action, String> {
        to_action(serde_json::from_str::<ActionDto>(json).map_err(|_| "bad_action".to_string())?)
    }

    #[test]
    fn les_trois_actions_se_convertissent() {
        assert_eq!(parse(r#"{"kind":"activate"}"#).unwrap(), Action::Activate);
        assert_eq!(
            parse(r#"{"kind":"network_dhcp"}"#).unwrap(),
            Action::Network(NetworkSettings::Dhcp)
        );
        let net = parse(
            r#"{"kind":"network_static","ip":"192.0.2.50","mask":"255.255.255.0","gateway":null,"dns":["192.0.2.1"]}"#,
        )
        .unwrap();
        assert_eq!(
            net,
            Action::Network(NetworkSettings::Static {
                ip: "192.0.2.50".parse().unwrap(),
                mask: "255.255.255.0".parse().unwrap(),
                gateway: None,
                dns: vec!["192.0.2.1".parse().unwrap()],
            })
        );
        let t = parse(r#"{"kind":"time","ntp_servers":[" pool.ntp.org ",""],"timezone":"Europe/Paris"}"#).unwrap();
        assert_eq!(
            t,
            Action::Time(TimeSettings { ntp_servers: vec!["pool.ntp.org".into()], timezone: "Europe/Paris".into() })
        );
    }

    #[test]
    fn une_adresse_invalide_ou_un_nom_louche_est_refuse() {
        assert_eq!(
            parse(r#"{"kind":"network_static","ip":"pas-une-ip","mask":"255.255.255.0"}"#).unwrap_err(),
            "bad_action"
        );
        for bad in [
            r#"{"kind":"time","timezone":""}"#,
            r#"{"kind":"time","timezone":"Europe/Paris\"}"}"#,
            r#"{"kind":"time","timezone":"UTC","ntp_servers":["a b"]}"#,
            r#"{"kind":"time","timezone":"UTC","ntp_servers":["x&y=z"]}"#,
        ] {
            assert_eq!(parse(bad).unwrap_err(), "bad_action", "{bad}");
        }
    }

    fn stored(iface: &str, created: Instant) -> StoredPreview {
        StoredPreview {
            cameras: vec![],
            rows: vec![],
            req: BatchRequest {
                start: "10.0.50.11".parse().unwrap(),
                mask: "255.255.255.0".parse().unwrap(),
                gateway: None,
                dns: vec![],
            },
            iface: iface.into(),
            created,
        }
    }

    #[test]
    fn un_apercu_ne_sert_qu_une_fois() {
        let store = PreviewStore::default();
        let now = Instant::now();
        let id = store.put(stored("eth0", now));
        assert!(store.take(&id, "eth0", Some("eth0"), now).is_ok());
        assert_eq!(store.take(&id, "eth0", Some("eth0"), now).err().as_deref(), Some("preview_unknown"));
        assert_eq!(store.take("inconnu", "eth0", Some("eth0"), now).err().as_deref(), Some("preview_unknown"));
    }

    #[test]
    fn un_apercu_refuse_est_quand_meme_consomme() {
        let store = PreviewStore::default();
        let now = Instant::now();
        let id = store.put(stored("eth0", now));
        // Autre interface que le scan en cours.
        assert_eq!(store.take(&id, "eth0", Some("wlan0"), now).err().as_deref(), Some("preview_expired"));
        assert_eq!(store.take(&id, "eth0", Some("eth0"), now).err().as_deref(), Some("preview_unknown"));
    }

    #[test]
    fn un_apercu_expire_apres_dix_minutes_ou_sur_une_autre_interface() {
        let store = PreviewStore::default();
        let t0 = Instant::now();
        let id = store.put(stored("eth0", t0));
        assert!(store.take(&id, "eth0", Some("eth0"), t0 + PREVIEW_TTL).is_ok());
        let id = store.put(stored("eth0", t0));
        let late = t0 + PREVIEW_TTL + Duration::from_secs(1);
        assert_eq!(store.take(&id, "eth0", Some("eth0"), late).err().as_deref(), Some("preview_expired"));
        let id = store.put(stored("eth0", t0));
        assert_eq!(store.take(&id, "wlan0", Some("wlan0"), t0).err().as_deref(), Some("preview_expired"));
        let id = store.put(stored("eth0", t0));
        assert_eq!(store.take(&id, "eth0", None, t0).err().as_deref(), Some("preview_expired"));
    }

    #[test]
    fn le_magasin_est_borne() {
        let store = PreviewStore::default();
        let t0 = Instant::now();
        let first = store.put(stored("eth0", t0));
        for i in 1..=PREVIEW_MAX as u64 {
            store.put(stored("eth0", t0 + Duration::from_millis(i)));
        }
        assert_eq!(store.0.lock().unwrap().len(), PREVIEW_MAX);
        assert_eq!(store.take(&first, "eth0", Some("eth0"), t0).err().as_deref(), Some("preview_unknown"));
    }
}
