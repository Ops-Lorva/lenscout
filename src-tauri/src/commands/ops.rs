//! Onglet Opérations : aperçu d'une opération de masse, puis application
//! ligne par ligne. Le front appelle `cmd_ops_step` caméra après caméra ;
//! « Arrêter » n'appelle simplement pas la suivante.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lenscout_core::accounts::{AccountBook, KnownCamera, unix_now};
use lenscout_core::actions::Action;
use lenscout_core::batch::BatchRequest;
use lenscout_core::http_client::ReqwestCameraHttp;
use lenscout_core::model::Camera;
use lenscout_core::ops::{KeepRequest, OpRow, Readback, StepResult, apply_step, plan_keep, plan_renumber, plan_time, read_before, row_action};
use lenscout_core::vapix::NetworkSettings;
use serde::{Deserialize, Serialize};
use tauri::State;

use super::accounts::{credentials_for, fill_for, remember_cameras, reserved_for};
use super::configure::{ActionDto, PREVIEW_MAX, PREVIEW_TTL, PreviewError, TempIpJournal, build_context, host_addresses, to_action};
use super::discovery::ScanState;

/// Lectures du réglage réseau en même temps, à l'aperçu.
const READ_PARALLEL: usize = 8;
/// Relecture à la nouvelle adresse : une Axis applique son réglage réseau en
/// quelques secondes. Au pire ~19 s par caméra muette. // À VÉRIFIER sur vraie Axis
const READBACK: Readback = Readback { first: Duration::from_secs(3), tries: 4, pause: Duration::from_secs(2) };
/// Délai d'une requête de relecture : la caméra est sur le réseau proche.
const READBACK_TIMEOUT: Duration = Duration::from_secs(2);

/// Ce que le front peut demander : des adresses déjà typées. `keep_ip` : un
/// champ `null` est inchangé.
#[derive(Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OpRequestDto {
    KeepIp {
        mask: Option<Ipv4Addr>,
        gateway: Option<Ipv4Addr>,
        dns: Option<Vec<Ipv4Addr>>,
    },
    Renumber {
        start: Ipv4Addr,
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

/// Une opération validée, telle que Rust l'a calculée : c'est elle, et elle
/// seule, que `cmd_ops_step` applique, une ligne à la fois et une seule fois.
struct StoredOp {
    cameras: Vec<Camera>,
    actions: Vec<Action>,
    done: Vec<bool>,
    iface: String,
    /// Dernier usage : l'opération expire après `PREVIEW_TTL` sans pas (une
    /// longue application, caméra après caméra, ne l'interrompt pas).
    touched: Instant,
}

impl StoredOp {
    /// Les IP fixes du plan : l'IP temporaire d'une caméra hors sous-réseau ne
    /// doit pas heurter celle d'une caméra déjà déplacée.
    fn planned_ips(&self) -> Vec<Ipv4Addr> {
        self.actions
            .iter()
            .filter_map(|a| match a {
                Action::Network(NetworkSettings::Static { ip, .. }) => Some(*ip),
                _ => None,
            })
            .collect()
    }
}

#[derive(Default)]
pub struct OpsStore(Mutex<HashMap<String, StoredOp>>);

impl OpsStore {
    fn put(&self, op: StoredOp) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut m = self.0.lock().unwrap();
        m.retain(|_, o| op.touched.saturating_duration_since(o.touched) <= PREVIEW_TTL);
        while m.len() >= PREVIEW_MAX {
            let Some(oldest) = m.iter().min_by_key(|(_, o)| o.touched).map(|(k, _)| k.clone()) else { break };
            m.remove(&oldest);
        }
        m.insert(id.clone(), op);
        id
    }

    /// La caméra d'une ligne, sans la consommer : le contexte d'écriture s'en
    /// construit avant que la ligne ne soit prise.
    fn camera_of(&self, id: &str, index: usize) -> Result<Camera, String> {
        let m = self.0.lock().unwrap();
        let op = m.get(id).ok_or("preview_unknown")?;
        op.cameras.get(index).cloned().ok_or_else(|| "bad_action".to_string())
    }

    /// Prend la ligne `index` : une seule fois, sur l'interface de l'aperçu
    /// (`iface`, nom système) qui doit être celle du dernier scan, avant
    /// l'expiration. Rend sa caméra, son action et les IP du plan. La
    /// dernière ligne prise retire l'opération.
    fn claim(
        &self,
        id: &str,
        index: usize,
        iface: &str,
        scan_iface: Option<&str>,
        now: Instant,
    ) -> Result<(Camera, Action, Vec<Ipv4Addr>), String> {
        let mut m = self.0.lock().unwrap();
        let op = m.get_mut(id).ok_or("preview_unknown")?;
        if now.saturating_duration_since(op.touched) > PREVIEW_TTL || op.iface != iface || scan_iface != Some(op.iface.as_str()) {
            m.remove(id);
            return Err("preview_expired".into());
        }
        if op.done.get(index) != Some(&false) {
            return Err("bad_action".into());
        }
        op.done[index] = true;
        op.touched = now;
        let out = (op.cameras[index].clone(), op.actions[index].clone(), op.planned_ips());
        if op.done.iter().all(|d| *d) {
            m.remove(id);
        }
        Ok(out)
    }

    fn close(&self, id: &str) {
        self.0.lock().unwrap().remove(id);
    }
}

/// `id` : absent tant qu'une ligne porte un conflit bloquant (rien n'est
/// gardé, Appliquer reste impossible).
#[derive(Serialize)]
pub struct OpsPreview {
    pub id: Option<String>,
    pub rows: Vec<OpRow>,
}

/// Les actions d'un plan sans conflit bloquant ; `None` sinon.
fn actions_of(rows: &[OpRow], time: Option<&lenscout_core::vapix::TimeSettings>) -> Option<Vec<Action>> {
    if rows.iter().any(OpRow::blocked) {
        return None;
    }
    rows.iter().map(|r| row_action(r, time)).collect()
}

/// Calcule l'aperçu d'une opération : réglage réseau lu sur chaque caméra
/// (garder les IP, renuméroter), avant / après et conflits par ligne. Rien
/// n'est écrit. Sans conflit bloquant, l'opération est gardée côté Rust sous
/// un identifiant. `selection` dans l'ordre affiché ; `others` : les autres
/// caméras connues.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_ops_preview(
    selection: Vec<Camera>,
    others: Vec<Camera>,
    req: OpRequestDto,
    iface: String,
    account_id: String,
    store: State<'_, OpsStore>,
    scan: State<'_, ScanState>,
    journal: State<'_, TempIpJournal>,
    join: State<'_, super::join::JoinState>,
    accounts: State<'_, Mutex<AccountBook>>,
) -> Result<OpsPreview, PreviewError> {
    let code = PreviewError::Code;
    let creds = credentials_for(&accounts, &account_id).map_err(code)?;
    let ctx = build_context(iface.clone(), &selection, &scan, &journal.0, &join).await.map_err(code)?;
    let own: Vec<Ipv4Addr> = selection.iter().map(|c| c.ip).collect();
    let fill = fill_for(&accounts, Some(&account_id), &own);
    let (rows, time) = match req {
        OpRequestDto::Time { ntp_servers, timezone } => {
            let Action::Time(t) = to_action(ActionDto::Time { ntp_servers, timezone }).map_err(code)? else {
                return Err(code("bad_action".into()));
            };
            (plan_time(&selection)?, Some(t))
        }
        OpRequestDto::KeepIp { mask, gateway, dns } => {
            let req = KeepRequest { mask, gateway, dns };
            let before = read_before(&ctx, &selection, &creds, READ_PARALLEL).await;
            (plan_keep(&selection, &before, &req, fill.as_ref())?, None)
        }
        OpRequestDto::Renumber { start, mask, gateway, dns } => {
            let req = BatchRequest { start, mask, gateway, dns };
            let (primary, host) = host_addresses(iface, &join).await.map_err(code)?;
            let excluded = reserved_for(&accounts, Some(&account_id), &own);
            let before = read_before(&ctx, &selection, &creds, READ_PARALLEL).await;
            (plan_renumber(&selection, &before, &req, &others, &[primary, host.ip], &excluded, fill.as_ref())?, None)
        }
    };
    let id = actions_of(&rows, time.as_ref()).map(|actions| {
        let done = vec![false; actions.len()];
        store.put(StoredOp { cameras: selection, actions, done, iface: ctx.iface.name.clone(), touched: Instant::now() })
    });
    Ok(OpsPreview { id, rows })
}

/// Applique la ligne `index` de l'opération `op_id` par `apply` (sous-réseau,
/// IP temporaire, identité vérifiés juste avant l'écriture), puis relit la
/// caméra à sa nouvelle adresse. Une IP posée entre dans la mémoire du
/// compte. Erreurs : `preview_unknown`, `preview_expired`, `bad_action`
/// (ligne inconnue ou déjà appliquée), et celles du compte et de l'interface.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_ops_step(
    op_id: String,
    index: usize,
    account_id: String,
    iface: String,
    store: State<'_, OpsStore>,
    accounts: State<'_, Mutex<AccountBook>>,
    scan: State<'_, ScanState>,
    journal: State<'_, TempIpJournal>,
    join: State<'_, super::join::JoinState>,
) -> Result<StepResult, String> {
    let cam = store.camera_of(&op_id, index)?;
    let creds = credentials_for(&accounts, &account_id)?;
    let mut ctx = build_context(iface, std::slice::from_ref(&cam), &scan, &journal.0, &join).await?;
    let (cam, action, planned) = store.claim(&op_id, index, &ctx.iface.name, scan.seen().iface.as_deref(), Instant::now())?;
    ctx.in_use.extend(planned);
    let check = ReqwestCameraHttp::new(READBACK_TIMEOUT);
    let step = apply_step(&ctx, &cam, &creds, &action, &check, READBACK).await;
    if let (true, Action::Network(NetworkSettings::Static { ip, .. })) = (step.result.ok, &action) {
        remember_cameras(&accounts, &account_id, vec![KnownCamera::of(&cam, *ip, unix_now())], false);
    }
    Ok(step)
}

/// Arrêt ou abandon : l'opération est oubliée, ses lignes restantes ne
/// partiront plus.
#[tauri::command]
pub fn cmd_ops_close(op_id: String, store: State<'_, OpsStore>) {
    store.close(&op_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenscout_core::model::{Activation, Family};
    use lenscout_core::ops::Conflict;

    fn camera(last: u8) -> Camera {
        Camera {
            ip: format!("10.0.50.{last}").parse().unwrap(),
            mac: Some(format!("AC:CC:8E:00:00:{last:02X}")),
            family: Family::Axis,
            brand: None,
            model: None,
            serial: None,
            firmware: None,
            activation: Activation::Activated,
            http_port: 80,
            sources: vec![],
            addressing: None,
            declared_mac: None,
        }
    }

    fn to(ip: &str) -> Action {
        Action::Network(NetworkSettings::Static { ip: ip.parse().unwrap(), mask: "255.255.255.0".parse().unwrap(), gateway: None, dns: vec![] })
    }

    fn stored(now: Instant) -> StoredOp {
        StoredOp {
            cameras: vec![camera(11), camera(12)],
            actions: vec![to("10.0.50.21"), to("10.0.50.22")],
            done: vec![false, false],
            iface: "eth0".into(),
            touched: now,
        }
    }

    #[test]
    fn chaque_ligne_ne_s_applique_qu_une_fois_puis_l_operation_part() {
        let store = OpsStore::default();
        let now = Instant::now();
        let id = store.put(stored(now));
        let (cam, action, planned) = store.claim(&id, 1, "eth0", Some("eth0"), now).unwrap();
        assert_eq!((cam.ip.to_string(), action), ("10.0.50.12".to_string(), to("10.0.50.22")));
        assert_eq!(planned.len(), 2);
        assert_eq!(store.claim(&id, 1, "eth0", Some("eth0"), now).err().as_deref(), Some("bad_action"));
        assert_eq!(store.claim(&id, 7, "eth0", Some("eth0"), now).err().as_deref(), Some("bad_action"));
        assert!(store.camera_of(&id, 0).is_ok());
        assert!(store.claim(&id, 0, "eth0", Some("eth0"), now).is_ok());
        assert_eq!(store.camera_of(&id, 0).err().as_deref(), Some("preview_unknown"));
    }

    #[test]
    fn une_operation_expire_sans_pas_ou_sur_une_autre_interface() {
        let store = OpsStore::default();
        let t0 = Instant::now();
        let id = store.put(stored(t0));
        // Chaque pas repousse l'expiration : une longue application va au bout.
        let t1 = t0 + PREVIEW_TTL;
        assert!(store.claim(&id, 0, "eth0", Some("eth0"), t1).is_ok());
        let late = t1 + PREVIEW_TTL + Duration::from_secs(1);
        assert_eq!(store.claim(&id, 1, "eth0", Some("eth0"), late).err().as_deref(), Some("preview_expired"));
        assert_eq!(store.claim(&id, 1, "eth0", Some("eth0"), t1).err().as_deref(), Some("preview_unknown"));
        let id = store.put(stored(t0));
        assert_eq!(store.claim(&id, 0, "eth0", Some("wlan0"), t0).err().as_deref(), Some("preview_expired"));
        let id = store.put(stored(t0));
        assert_eq!(store.claim(&id, 0, "wlan0", Some("wlan0"), t0).err().as_deref(), Some("preview_expired"));
    }

    #[test]
    fn arreter_oublie_l_operation() {
        let store = OpsStore::default();
        let id = store.put(stored(Instant::now()));
        store.close(&id);
        assert_eq!(store.claim(&id, 0, "eth0", Some("eth0"), Instant::now()).err().as_deref(), Some("preview_unknown"));
    }

    #[test]
    fn un_plan_avec_un_conflit_bloquant_n_est_pas_garde() {
        let row = |conflicts: Vec<Conflict>| OpRow {
            key: "k".into(),
            ip: "10.0.50.11".parse().unwrap(),
            before: None,
            after: Some(lenscout_core::ops::NetTarget {
                ip: "10.0.50.21".parse().unwrap(),
                mask: "255.255.255.0".parse().unwrap(),
                gateway: None,
                dns: vec![],
            }),
            conflicts,
        };
        assert_eq!(actions_of(&[row(vec![])], None), Some(vec![to("10.0.50.21")]));
        assert!(actions_of(&[row(vec![]), row(vec![Conflict::Dhcp])], None).is_none());
        // Un avertissement n'empêche rien.
        assert!(actions_of(&[row(vec![Conflict::OutsideAccount { network: "10.0.60.0/24".into() }])], None).is_some());
    }

    #[test]
    fn les_trois_operations_se_lisent() {
        let keep: OpRequestDto = serde_json::from_str(r#"{"kind":"keep_ip","mask":"255.255.254.0","gateway":null,"dns":null}"#).unwrap();
        assert!(matches!(keep, OpRequestDto::KeepIp { mask: Some(_), gateway: None, dns: None }));
        let ren: OpRequestDto =
            serde_json::from_str(r#"{"kind":"renumber","start":"10.0.50.11","mask":"255.255.255.0","gateway":"10.0.50.1"}"#).unwrap();
        assert!(matches!(ren, OpRequestDto::Renumber { gateway: Some(_), .. }));
        let time: OpRequestDto = serde_json::from_str(r#"{"kind":"time","timezone":"Europe/Paris"}"#).unwrap();
        assert!(matches!(time, OpRequestDto::Time { .. }));
        assert!(serde_json::from_str::<OpRequestDto>(r#"{"kind":"keep_ip","mask":"pas-une-ip"}"#).is_err());
    }
}
