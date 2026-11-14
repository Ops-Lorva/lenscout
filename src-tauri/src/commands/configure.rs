use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lenscout_core::accounts::AccountBook;
use lenscout_core::actions::{Action, ActionContext, ActionResult, apply_all, apply_batch, on_subnet};
use lenscout_core::batch::{Assignment, BatchError, BatchRequest, plan_batch};
use lenscout_core::discovery::arp::{ScanInterface, SystemNeighbours, read_neighbours};
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
    /// `allow_cleartext` : envoi en http clair confirmé pour cette caméra.
    Activate {
        #[serde(default)]
        allow_cleartext: bool,
    },
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
        ActionDto::Activate { allow_cleartext: false } => Action::Activate,
        ActionDto::Activate { allow_cleartext: true } => Action::ActivateCleartext,
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

/// L'envoi en clair d'un mot de passe d'activation se confirme pour une
/// caméra à la fois : une liste de plusieurs (ou aucune) est refusée.
pub(crate) fn one_camera_for_cleartext(action: &Action, cameras: usize) -> Result<(), String> {
    if *action == Action::ActivateCleartext && cameras != 1 {
        return Err("bad_action".into());
    }
    Ok(())
}

/// Le contexte d'écriture, identique pour une action et pour un lot : sous-réseau
/// de l'interface choisie, ce que le dernier scan a entendu, SADP pour une
/// sélection Hikvision.
async fn build_context(
    iface: String,
    cameras: &[Camera],
    scan: &ScanState,
    journal: &std::path::Path,
    join: &super::join::JoinState,
) -> Result<ActionContext, String> {
    let service = iface.clone();
    let targets: Vec<Ipv4Addr> = cameras.iter().map(|c| c.ip).collect();
    // Dans le réseau d'un compte : l'adresse posée fait l'interface.
    let held = join.temp();
    let account_network = held.is_some();
    let (scan_iface, any_off_subnet, other_ifaces) = tauri::async_runtime::spawn_blocking(move || {
        let up = list_interfaces_up();
        if !up.contains(&iface) {
            return Err("iface_unknown".to_string());
        }
        let scan_iface = ScanInterface::from_details(&iface, &get_interface_details(&iface))
            .ok_or_else(|| "iface_no_ipv4".to_string())?;
        let scan_iface = lenscout_core::temp_ip::joined_scope(scan_iface, held.as_ref());
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
        account_network,
        seen_states: seen.states,
        neighbours: Arc::new(SystemNeighbours),
    })
}

/// Applique une action aux seules caméras reçues, dans l'ordre. Le front passe
/// la sélection visible ; le cœur revérifie la marque et l'identité de chaque
/// caméra avant d'écrire. Hors du sous-réseau de l'interface, une IP
/// temporaire est posée sur le poste pour une caméra vue au dernier scan.
#[tauri::command]
// Un argument par état Tauri : les regrouper ne servirait qu'à ce lint.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_apply_action(
    cameras: Vec<Camera>,
    account_id: String,
    action: ActionDto,
    iface: String,
    accounts: State<'_, Mutex<AccountBook>>,
    scan: State<'_, ScanState>,
    journal: State<'_, TempIpJournal>,
    join: State<'_, super::join::JoinState>,
) -> Result<Vec<ActionResult>, String> {
    let action = to_action(action)?;
    one_camera_for_cleartext(&action, cameras.len())?;
    let creds = credentials_for(&accounts, &account_id)?;
    let ctx = build_context(iface, &cameras, &scan, &journal.0, &join).await?;
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

    /// Les caméras d'un aperçu, sans le consommer : le contexte d'écriture
    /// s'en construit avant que l'identifiant ne soit pris.
    fn cameras_of(&self, id: &str) -> Result<Vec<Camera>, String> {
        self.0.lock().unwrap().get(id).map(|p| p.cameras.clone()).ok_or_else(|| "preview_unknown".to_string())
    }

    /// Sort l'aperçu du magasin dans tous les cas : un identifiant ne sert
    /// qu'une fois, même si l'application a échoué en partie ou si l'aperçu est
    /// refusé. `iface` : `ScanInterface::name` de l'application ; `scan_iface` :
    /// celui du dernier scan.
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

/// Échec d'un aperçu : erreur de plan (objet à code) ou code de commande.
#[derive(Serialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum PreviewError {
    Plan(BatchError),
    Code(String),
}

impl From<BatchError> for PreviewError {
    fn from(e: BatchError) -> Self {
        PreviewError::Plan(e)
    }
}

/// Calcule et valide le plan, sans rien envoyer à aucune caméra, et le garde
/// côté Rust sous un identifiant. `selection` est dans l'ordre affiché ;
/// `others` : les autres caméras connues. L'adresse du poste sur l'interface
/// vient d'ici, pas du front : elle n'est jamais attribuée. Les IP exclues du
/// compte retenu (`account_id`) sont sautées.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_batch_preview(
    selection: Vec<Camera>,
    others: Vec<Camera>,
    req: BatchRequestDto,
    iface: String,
    account_id: Option<String>,
    store: State<'_, PreviewStore>,
    join: State<'_, super::join::JoinState>,
    accounts: State<'_, Mutex<AccountBook>>,
) -> Result<BatchPreview, PreviewError> {
    let req: BatchRequest = req.into();
    let name = iface;
    let host = tauri::async_runtime::spawn_blocking(move || {
        if !list_interfaces_up().contains(&name) {
            return Err("iface_unknown".to_string());
        }
        ScanInterface::from_details(&name, &get_interface_details(&name))
            .ok_or_else(|| "iface_no_ipv4".to_string())
    })
    .await
    .map_err(|_| PreviewError::Code("internal".into()))?
    .map_err(PreviewError::Code)?;
    // Les deux adresses du poste sont réservées : la principale et celle d'un compte.
    let primary = host.ip;
    let host = join.scope(host);
    let excluded = super::accounts::exclusions_for(&accounts, account_id.as_deref());
    let rows = plan_batch(&selection, &req, &others, &[primary, host.ip], &excluded)?;
    let id = remember_preview(&store, selection, rows.clone(), req, &host, Instant::now());
    Ok(BatchPreview { id, rows })
}

/// Garde un aperçu sous l'interface telle que le scan et l'application la
/// nomment (`ScanInterface::name`) : sur macOS le front choisit un service
/// networksetup (« Ethernet ») mais le scan retient l'ifname système (« en0 »).
fn remember_preview(
    store: &PreviewStore,
    cameras: Vec<Camera>,
    rows: Vec<Assignment>,
    req: BatchRequest,
    resolved: &ScanInterface,
    created: Instant,
) -> String {
    store.put(StoredPreview { cameras, rows, req, iface: resolved.name.clone(), created })
}

/// Applique exactement l'aperçu gardé, caméra par caméra, par `apply` : sous-
/// réseau, IP temporaire et identité (MAC / série) vérifiés avant chaque
/// écriture. Erreurs : `preview_unknown` (inconnu ou déjà appliqué),
/// `preview_expired` (plus de 10 min, ou interface différente du scan).
/// Compte et contexte d'abord : un échec passager ne consomme pas l'identifiant.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_batch_apply(
    preview_id: String,
    account_id: String,
    iface: String,
    accounts: State<'_, Mutex<AccountBook>>,
    scan: State<'_, ScanState>,
    journal: State<'_, TempIpJournal>,
    join: State<'_, super::join::JoinState>,
    store: State<'_, PreviewStore>,
) -> Result<Vec<ActionResult>, String> {
    let cameras = store.cameras_of(&preview_id)?;
    let creds = credentials_for(&accounts, &account_id)?;
    let ctx = build_context(iface, &cameras, &scan, &journal.0, &join).await?;
    // Noms système des deux côtés : celui du contexte, celui du dernier scan.
    let preview = store.take(&preview_id, &ctx.iface.name, scan.seen().iface.as_deref(), Instant::now())?;
    apply_batch(ctx, &preview.cameras, &preview.rows, &creds, &preview.req).await
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

    /// L'envoi en clair se confirme caméra par caméra : jamais pour un lot.
    #[test]
    fn l_activation_en_clair_ne_vise_qu_une_camera() {
        assert_eq!(parse(r#"{"kind":"activate","allow_cleartext":false}"#).unwrap(), Action::Activate);
        let clear = parse(r#"{"kind":"activate","allow_cleartext":true}"#).unwrap();
        assert_eq!(clear, Action::ActivateCleartext);
        assert_eq!(one_camera_for_cleartext(&clear, 1), Ok(()));
        for n in [0, 2, 5] {
            assert_eq!(one_camera_for_cleartext(&clear, n), Err("bad_action".to_string()), "{n}");
        }
        assert_eq!(one_camera_for_cleartext(&Action::Activate, 5), Ok(()));
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

    /// macOS : le front choisit un service networksetup (« Ethernet »), le scan
    /// et le contexte d'écriture nomment l'interface système (« en0 »).
    #[test]
    fn un_apercu_macos_se_reprend_sous_le_nom_systeme() {
        use lenscout_core::interfaces::InterfaceDetails;
        let details = InterfaceDetails {
            ip: Some("10.0.50.2".into()),
            subnet: Some("255.255.255.0".into()),
            bsd_name: Some("en0".into()),
            ..Default::default()
        };
        let resolved = ScanInterface::from_details("Ethernet", &details).unwrap();
        assert_eq!(resolved.name, "en0");
        let store = PreviewStore::default();
        let now = Instant::now();
        let s = stored("", now);
        let id = remember_preview(&store, s.cameras, s.rows, s.req, &resolved, now);
        // Ce que cmd_batch_apply passe : le nom du contexte, celui du scan.
        assert!(store.take(&id, &resolved.name, Some("en0"), now).is_ok());
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

    #[test]
    fn les_cameras_d_un_apercu_se_lisent_sans_le_consommer() {
        let store = PreviewStore::default();
        let id = store.put(stored("eth0", Instant::now()));
        assert!(store.cameras_of(&id).is_ok());
        assert!(store.cameras_of(&id).is_ok());
        assert!(store.take(&id, "eth0", Some("eth0"), Instant::now()).is_ok());
        assert_eq!(store.cameras_of(&id).err().as_deref(), Some("preview_unknown"));
    }

    #[test]
    fn une_erreur_d_apercu_se_serialise_en_objet_ou_en_chaine() {
        let plan: PreviewError = BatchError::TooManyDns.into();
        assert_eq!(serde_json::to_string(&plan).unwrap(), r#"{"code":"too_many_dns"}"#);
        assert_eq!(serde_json::to_string(&PreviewError::Code("iface_unknown".into())).unwrap(), r#""iface_unknown""#);
    }
}
