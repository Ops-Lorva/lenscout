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
use lenscout_core::ops::{
    CredGuard, CredResult, KeepRequest, OpRow, Readback, StepResult, apply_step, change_credentials_step, plan_change_credentials,
    plan_keep, plan_renumber, plan_time, read_before, row_action,
};
use lenscout_core::secret::Secret;
use lenscout_core::transport::Credentials;
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
/// Garde anti-verrouillage de « Changer les identifiants » : les Axis récentes
/// bloquent un compte après ~5 échecs rapprochés. Délai entre deux essais sur
/// une caméra, et arrêt après ce nombre d'échecs 401. // À VÉRIFIER sur vraie Axis
const CRED_GUARD: CredGuard = CredGuard { delay: Duration::from_secs(1), max_failures: 4 };

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
    /// Changer les identifiants : le nouvel identifiant visé, et une liste de
    /// couples à essayer. Les mots de passe (`Secret`) ne sont jamais
    /// resérialisés : ils ne vivent qu'en mémoire, le temps de l'opération.
    ChangeCredentials {
        new_login: String,
        new_password: Secret,
        #[serde(default)]
        candidates: Vec<CredentialPairDto>,
    },
}

/// Un couple identifiant / mot de passe à essayer. `Secret` : jamais écrit sur
/// disque ni dans le trousseau, jamais resérialisé.
#[derive(Deserialize, Debug)]
pub struct CredentialPairDto {
    pub login: String,
    pub password: Secret,
}

impl From<CredentialPairDto> for Credentials {
    fn from(d: CredentialPairDto) -> Self {
        Credentials { login: d.login, password: d.password }
    }
}

/// Le plan gardé d'une opération, selon sa nature : des actions réseau/heure
/// (une par caméra), ou le changement d'identifiants (nouvel identifiant visé
/// et couples à essayer, communs à toutes les caméras).
enum Plan {
    Actions(Vec<Action>),
    Credentials { new: Credentials, candidates: Vec<Credentials> },
}

/// Une ligne prise (`claim`) : son action réseau/heure, ou le plan
/// d'identifiants à lui appliquer.
enum Claimed {
    Action { cam: Camera, action: Action, planned: Vec<Ipv4Addr> },
    Credentials { cam: Camera, new: Credentials, candidates: Vec<Credentials> },
}

/// Une opération validée, telle que Rust l'a calculée : c'est elle, et elle
/// seule, que `cmd_ops_step` applique, une ligne à la fois et une seule fois.
struct StoredOp {
    cameras: Vec<Camera>,
    plan: Plan,
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
        match &self.plan {
            Plan::Actions(actions) => actions
                .iter()
                .filter_map(|a| match a {
                    Action::Network(NetworkSettings::Static { ip, .. }) => Some(*ip),
                    _ => None,
                })
                .collect(),
            Plan::Credentials { .. } => vec![],
        }
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
    ) -> Result<Claimed, String> {
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
        let cam = op.cameras[index].clone();
        let out = match &op.plan {
            Plan::Actions(actions) => Claimed::Action { cam, action: actions[index].clone(), planned: op.planned_ips() },
            Plan::Credentials { new, candidates } => Claimed::Credentials { cam, new: new.clone(), candidates: candidates.clone() },
        };
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
    // Chaque branche rend l'aperçu et, s'il n'est pas bloqué, le plan à garder.
    let (rows, plan): (Vec<OpRow>, Option<Plan>) = match req {
        OpRequestDto::Time { ntp_servers, timezone } => {
            let Action::Time(t) = to_action(ActionDto::Time { ntp_servers, timezone }).map_err(code)? else {
                return Err(code("bad_action".into()));
            };
            let rows = plan_time(&selection)?;
            let plan = actions_of(&rows, Some(&t)).map(Plan::Actions);
            (rows, plan)
        }
        OpRequestDto::KeepIp { mask, gateway, dns } => {
            let req = KeepRequest { mask, gateway, dns };
            let before = read_before(&ctx, &selection, &creds, READ_PARALLEL).await;
            let rows = plan_keep(&selection, &before, &req, fill.as_ref())?;
            let plan = actions_of(&rows, None).map(Plan::Actions);
            (rows, plan)
        }
        OpRequestDto::Renumber { start, mask, gateway, dns } => {
            let req = BatchRequest { start, mask, gateway, dns };
            let (primary, host) = host_addresses(iface, &join).await.map_err(code)?;
            let excluded = reserved_for(&accounts, Some(&account_id), &own);
            let before = read_before(&ctx, &selection, &creds, READ_PARALLEL).await;
            let rows = plan_renumber(&selection, &before, &req, &others, &[primary, host.ip], &excluded, fill.as_ref())?;
            let plan = actions_of(&rows, None).map(Plan::Actions);
            (rows, plan)
        }
        OpRequestDto::ChangeCredentials { new_login, new_password, candidates } => {
            // L'aperçu N'ESSAIE AUCUN identifiant (pour ne pas doubler le risque
            // de blocage) : il n'annonce que l'intention, le test se fait à
            // l'application. Les mots de passe ne vivent que dans le plan gardé.
            let rows = plan_change_credentials(&selection)?;
            let new = Credentials { login: new_login, password: new_password };
            let candidates: Vec<Credentials> = candidates.into_iter().map(Into::into).collect();
            let plan = (!rows.iter().any(OpRow::blocked)).then_some(Plan::Credentials { new, candidates });
            (rows, plan)
        }
    };
    let id = plan.map(|plan| {
        let done = vec![false; rows.len()];
        store.put(StoredOp { cameras: selection, plan, done, iface: ctx.iface.name.clone(), touched: Instant::now() })
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
    let Claimed::Action { cam, action, planned } = store.claim(&op_id, index, &ctx.iface.name, scan.seen().iface.as_deref(), Instant::now())?
    else {
        // Opération de changement d'identifiants : ce n'est pas la bonne commande.
        return Err("bad_action".into());
    };
    ctx.in_use.extend(planned);
    let check = ReqwestCameraHttp::new(READBACK_TIMEOUT);
    let step = apply_step(&ctx, &cam, &creds, &action, &check, READBACK).await;
    if let (true, Action::Network(NetworkSettings::Static { ip, .. })) = (step.result.ok, &action) {
        remember_cameras(&accounts, &account_id, vec![KnownCamera::of(&cam, *ip, unix_now())], false);
    }
    Ok(step)
}

/// Applique la ligne `index` d'une opération « Changer les identifiants » :
/// essaie le nouvel identifiant visé, puis le compte, puis les couples de la
/// liste (garde anti-verrouillage), et pose le nouvel identifiant au premier
/// qui authentifie. Le rapport ne porte jamais de mot de passe. Erreurs comme
/// `cmd_ops_step` ; `bad_action` si l'opération n'est pas un changement
/// d'identifiants.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_ops_creds_step(
    op_id: String,
    index: usize,
    account_id: String,
    iface: String,
    store: State<'_, OpsStore>,
    accounts: State<'_, Mutex<AccountBook>>,
    scan: State<'_, ScanState>,
    journal: State<'_, TempIpJournal>,
    join: State<'_, super::join::JoinState>,
) -> Result<CredResult, String> {
    let cam = store.camera_of(&op_id, index)?;
    // Le compte sélectionné sert d'identifiant à essayer (en premier après le
    // nouvel identifiant visé) ; s'il n'a pas de secret, on s'en passe.
    let account = credentials_for(&accounts, &account_id).ok();
    let ctx = build_context(iface, std::slice::from_ref(&cam), &scan, &journal.0, &join).await?;
    let Claimed::Credentials { cam, new, candidates } =
        store.claim(&op_id, index, &ctx.iface.name, scan.seen().iface.as_deref(), Instant::now())?
    else {
        return Err("bad_action".into());
    };
    Ok(change_credentials_step(&ctx, &cam, account.as_ref(), &candidates, &new, CRED_GUARD).await)
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
            plan: Plan::Actions(vec![to("10.0.50.21"), to("10.0.50.22")]),
            done: vec![false, false],
            iface: "eth0".into(),
            touched: now,
        }
    }

    /// L'action d'une ligne prise ; échoue si c'est un plan d'identifiants.
    fn action_of(claimed: Claimed) -> (Camera, Action, Vec<Ipv4Addr>) {
        match claimed {
            Claimed::Action { cam, action, planned } => (cam, action, planned),
            Claimed::Credentials { .. } => panic!("plan d'identifiants inattendu"),
        }
    }

    #[test]
    fn chaque_ligne_ne_s_applique_qu_une_fois_puis_l_operation_part() {
        let store = OpsStore::default();
        let now = Instant::now();
        let id = store.put(stored(now));
        let (cam, action, planned) = action_of(store.claim(&id, 1, "eth0", Some("eth0"), now).unwrap());
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
    fn les_operations_se_lisent() {
        let keep: OpRequestDto = serde_json::from_str(r#"{"kind":"keep_ip","mask":"255.255.254.0","gateway":null,"dns":null}"#).unwrap();
        assert!(matches!(keep, OpRequestDto::KeepIp { mask: Some(_), gateway: None, dns: None }));
        let ren: OpRequestDto =
            serde_json::from_str(r#"{"kind":"renumber","start":"10.0.50.11","mask":"255.255.255.0","gateway":"10.0.50.1"}"#).unwrap();
        assert!(matches!(ren, OpRequestDto::Renumber { gateway: Some(_), .. }));
        let time: OpRequestDto = serde_json::from_str(r#"{"kind":"time","timezone":"Europe/Paris"}"#).unwrap();
        assert!(matches!(time, OpRequestDto::Time { .. }));
        assert!(serde_json::from_str::<OpRequestDto>(r#"{"kind":"keep_ip","mask":"pas-une-ip"}"#).is_err());
        // Changer les identifiants : nouvel identifiant visé + couples à essayer.
        let creds: OpRequestDto = serde_json::from_str(
            r#"{"kind":"change_credentials","new_login":"root","new_password":"N3w","candidates":[{"login":"installer","password":"old"}]}"#,
        )
        .unwrap();
        let OpRequestDto::ChangeCredentials { new_login, new_password, candidates } = creds else { panic!() };
        assert_eq!((new_login.as_str(), new_password.expose()), ("root", "N3w"));
        assert_eq!((candidates[0].login.as_str(), candidates[0].password.expose()), ("installer", "old"));
        // La liste des couples est facultative.
        assert!(serde_json::from_str::<OpRequestDto>(r#"{"kind":"change_credentials","new_login":"root","new_password":"x"}"#).is_ok());
    }

    /// Une opération « changer les identifiants » se garde comme un plan
    /// d'identifiants, et `cmd_ops_step` (action) la refuse.
    #[test]
    fn une_operation_d_identifiants_se_prend_comme_telle() {
        let store = OpsStore::default();
        let now = Instant::now();
        let op = StoredOp {
            cameras: vec![camera(11)],
            plan: Plan::Credentials {
                new: Credentials { login: "root".into(), password: Secret::new("N3w".into()) },
                candidates: vec![Credentials { login: "installer".into(), password: Secret::new("old".into()) }],
            },
            done: vec![false],
            iface: "eth0".into(),
            touched: now,
        };
        let id = store.put(op);
        // Pas d'IP fixe dans ce plan : rien à réserver.
        let claimed = store.claim(&id, 0, "eth0", Some("eth0"), now).unwrap();
        match claimed {
            Claimed::Credentials { cam, new, candidates } => {
                assert_eq!(cam.ip.to_string(), "10.0.50.11");
                assert_eq!(new.login, "root");
                assert_eq!(candidates.len(), 1);
            }
            Claimed::Action { .. } => panic!("plan d'identifiants attendu"),
        }
    }
}
