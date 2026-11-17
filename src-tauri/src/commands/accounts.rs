use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;

use lenscout_core::accounts::{
    Account, AccountBook, AccountError, AccountNetwork, Choice, Exclusions, ImportKind, ImportPlan, ImportSummary,
    KnownCamera, NetworkFill, ReservedIp, Startup, current_devices, unix_now, write_file_private,
};
use lenscout_core::secret::Secret;
use lenscout_core::transport::Credentials;
use serde::{Deserialize, Serialize};
use tauri::State;

/// Erreurs : codes stables (`empty_field`, `duplicate_name`, `not_found`,
/// `secret_missing`, `io`, `import_invalid`, `file_unwritable`,
/// `file_unreadable`, `invalid_pc_ip`, `missing_mask`, `invalid_gateway`,
/// `gateway_outside_network`, `invalid_exclusions`), traduits par le front. Le message de
/// l'OS n'est pas renvoyé.
fn code(e: AccountError) -> String {
    match e {
        AccountError::EmptyField => "empty_field",
        AccountError::DuplicateName => "duplicate_name",
        AccountError::NotFound => "not_found",
        AccountError::SecretMissing => "secret_missing",
        AccountError::Io(_) => "io",
        AccountError::ImportInvalid => "import_invalid",
        AccountError::InvalidPcIp => "invalid_pc_ip",
        AccountError::MaskMissing => "missing_mask",
        AccountError::InvalidGateway => "invalid_gateway",
        AccountError::GatewayOutsideNetwork => "gateway_outside_network",
        AccountError::InvalidExclusions => "invalid_exclusions",
    }
    .to_string()
}

fn lock(state: &Mutex<AccountBook>) -> Result<std::sync::MutexGuard<'_, AccountBook>, String> {
    state.lock().map_err(|_| "internal".to_string())
}

// Les fonctions pures portent la logique ; les commandes ne font que
// verrouiller l'état. Aucune ne renvoie de mot de passe, sauf
// `cmd_account_password`, à la demande, pour un seul compte.

/// Entrée de liste : le compte et un booléen disant s'il a un mot de passe
/// (jamais le mot de passe) ; sinon il est à ressaisir.
#[derive(Serialize, Debug, PartialEq)]
pub struct AccountEntry {
    pub id: String,
    pub name: String,
    pub login: String,
    #[serde(flatten)]
    pub net: AccountNetwork,
    pub has_secret: bool,
}

pub(crate) fn accounts_list(book: &AccountBook) -> Vec<AccountEntry> {
    book.list()
        .into_iter()
        .map(|a| AccountEntry {
            has_secret: book.has_secret(&a.id),
            id: a.id,
            name: a.name,
            login: a.login,
            net: a.net,
        })
        .collect()
}

/// Un fichier d'import fait quelques ko ; au-delà, ce n'est pas le nôtre.
const IMPORT_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Plan d'import à plat pour l'écran : `kind` = `new` | `identical` | `differs`.
/// Aucun secret.
#[derive(Serialize, Debug, PartialEq)]
pub struct ImportItemOut {
    pub name: String,
    pub kind: &'static str,
    pub login_differs: bool,
    pub password_differs: bool,
    pub network_differs: bool,
    pub gateway_dropped: bool,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ImportPlanOut {
    pub items: Vec<ImportItemOut>,
}

impl From<ImportPlan> for ImportPlanOut {
    fn from(plan: ImportPlan) -> Self {
        let items = plan
            .items
            .into_iter()
            .map(|i| {
                let (kind, login_differs, password_differs, network_differs) = match i.kind {
                    ImportKind::New => ("new", false, false, false),
                    ImportKind::Identical => ("identical", false, false, false),
                    ImportKind::Differs { login_differs, password_differs, network_differs } => {
                        ("differs", login_differs, password_differs, network_differs)
                    }
                };
                ImportItemOut {
                    name: i.name,
                    kind,
                    login_differs,
                    password_differs,
                    network_differs,
                    gateway_dropped: i.gateway_dropped,
                }
            })
            .collect();
        Self { items }
    }
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ImportSummaryOut {
    pub added: usize,
    pub identical: usize,
    pub replaced: usize,
    pub kept_both: usize,
    pub skipped: usize,
}

impl From<ImportSummary> for ImportSummaryOut {
    fn from(s: ImportSummary) -> Self {
        Self {
            added: s.added,
            identical: s.identical,
            replaced: s.replaced,
            kept_both: s.kept_both,
            skipped: s.skipped,
        }
    }
}

/// Choix du front pour un nom déjà présent qui diffère.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChoiceIn {
    Replace,
    KeepBoth,
    Skip,
}

impl From<ChoiceIn> for Choice {
    fn from(c: ChoiceIn) -> Self {
        match c {
            ChoiceIn::Replace => Choice::Replace,
            ChoiceIn::KeepBoth => Choice::KeepBoth,
            ChoiceIn::Skip => Choice::Skip,
        }
    }
}

/// Le fichier d'export porte l'extension `.lenscout` (la boîte Enregistrer
/// peut la laisser de côté).
pub(crate) fn with_lenscout_ext(path: &Path) -> std::path::PathBuf {
    match path.extension() {
        Some(e) if e.eq_ignore_ascii_case("lenscout") => path.to_path_buf(),
        _ => {
            let mut p = path.as_os_str().to_owned();
            p.push(".lenscout");
            p.into()
        }
    }
}

/// Écriture atomique en 0600 (mécanisme du core). Rend le nombre de comptes.
pub(crate) fn accounts_export(book: &AccountBook, path: &Path) -> Result<usize, String> {
    write_file_private(&with_lenscout_ext(path), book.export().as_bytes())
        .map_err(|_| "file_unwritable".to_string())?;
    Ok(book.list().len())
}

/// Fichier absent ou inaccessible : `file_unreadable` ; trop gros ou pas du texte :
/// `import_invalid`, comme tout fichier qui n'est pas un export.
fn read_import(path: &Path) -> Result<String, String> {
    let unreadable = |_| "file_unreadable".to_string();
    let meta = std::fs::metadata(path).map_err(unreadable)?;
    if meta.len() > IMPORT_MAX_BYTES {
        return Err("import_invalid".to_string());
    }
    let bytes = std::fs::read(path).map_err(unreadable)?;
    String::from_utf8(bytes).map_err(|_| "import_invalid".to_string())
}

pub(crate) fn accounts_import_plan(book: &AccountBook, path: &Path) -> Result<ImportPlanOut, String> {
    let data = read_import(path)?;
    book.import_plan(&data).map(Into::into).map_err(code)
}

pub(crate) fn accounts_import_apply(
    book: &mut AccountBook,
    path: &Path,
    choices: HashMap<String, ChoiceIn>,
) -> Result<ImportSummaryOut, String> {
    let data = read_import(path)?;
    let choices: HashMap<String, Choice> = choices.into_iter().map(|(k, v)| (k, v.into())).collect();
    book.import_apply(&data, &choices).map(Into::into).map_err(code)
}

/// Signalement unique au front d'un démarrage dégradé (`quarantined`,
/// `unwritable`), pris par la page Comptes à son premier affichage.
pub struct StartupNotice(pub Mutex<Option<&'static str>>);

pub(crate) fn startup_code(startup: &Startup) -> Option<&'static str> {
    match startup {
        Startup::Clean => None,
        Startup::Quarantined(_) => Some("quarantined"),
        Startup::Unwritable => Some("unwritable"),
    }
}

/// L'avis du démarrage : un problème du carnet d'abord, sinon une
/// migration de l'ancien identifiant restée incomplète (réessayée au
/// prochain lancement).
pub(crate) fn notice_code(startup: &Startup, migration_incomplete: bool) -> Option<&'static str> {
    startup_code(startup).or(migration_incomplete.then_some("migration_incomplete"))
}

/// Comptes de l'ancien identifiant posés à côté du carnet par la migration
/// (les deux carnets existaient) : fusionnés par id, puis le fichier est
/// renommé `.merged-<horodatage>`. `false` (avis au démarrage) si la fusion
/// a échoué : écriture impossible → le fichier reste, retentée au prochain
/// lancement ; fichier illisible → mis de côté `.corrupt-<horodatage>`
/// (jamais effacé), donc signalé une seule fois.
pub(crate) fn absorb_old_accounts(book: &mut AccountBook, aside: &Path) -> bool {
    if !aside.exists() {
        return true;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let renamed = |suffix: &str| {
        let mut to = aside.as_os_str().to_owned();
        to.push(format!(".{suffix}-{stamp}"));
        std::fs::rename(aside, to).is_ok()
    };
    match book.absorb(aside) {
        Ok(_) => renamed("merged"),
        Err(AccountError::ImportInvalid) => {
            renamed("corrupt");
            false
        }
        Err(_) => false,
    }
}

pub(crate) fn take_notice(notice: &StartupNotice) -> Option<String> {
    notice.0.lock().ok()?.take().map(str::to_string)
}

pub(crate) fn account_create(
    book: &mut AccountBook,
    name: &str,
    login: &str,
    password: Secret,
    net: AccountNetwork,
) -> Result<Account, String> {
    book.create(name, login, password, net).map_err(code)
}

pub(crate) fn account_update(
    book: &mut AccountBook,
    id: &str,
    name: &str,
    login: &str,
    password: Option<Secret>,
    net: AccountNetwork,
) -> Result<Account, String> {
    book.update(id, name, login, password, net).map_err(code)
}

/// Mot de passe montré dans la fiche Modifier. Sérialisé tel quel pour le
/// front, jamais affiché par `Debug` (journaux).
/// Effacé de la mémoire après l'envoi (c'est un `Secret`).
pub struct RevealedPassword(Secret);

impl Serialize for RevealedPassword {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.expose())
    }
}

impl zeroize::ZeroizeOnDrop for RevealedPassword {}

impl std::fmt::Debug for RevealedPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// `None` : compte à ressaisir (champ vide dans la fiche).
pub(crate) fn account_password(book: &AccountBook, id: &str) -> Result<Option<RevealedPassword>, String> {
    Ok(book.password(id).map_err(code)?.map(RevealedPassword))
}

pub(crate) fn account_remove(book: &mut AccountBook, id: &str) -> Result<(), String> {
    book.remove(id).map_err(code)
}

/// Identifiants d'un compte pour les commandes authentifiées (cadrage,
/// configuration) : le mot de passe reste côté Rust.
/// Pour une action ou un flux. Codes possibles (affichés par les pages
/// Configuration et Cadrage) : `not_found`, `secret_missing`, `internal`.
/// `AccountBook::credentials` ne rend rien d'autre.
pub(crate) fn credentials_for(state: &Mutex<AccountBook>, id: &str) -> Result<Credentials, String> {
    lock(state)?.credentials(id).map_err(|e| match e {
        AccountError::NotFound => "not_found".to_string(),
        AccountError::SecretMissing => "secret_missing".to_string(),
        _ => "internal".to_string(),
    })
}

/// IP exclues du compte retenu par une feuille. Sans compte (ou compte
/// supprimé entre-temps) : rien d'exclu, la feuille reste utilisable.
pub(crate) fn exclusions_for(state: &Mutex<AccountBook>, id: Option<&str>) -> Exclusions {
    let Some(id) = id else { return Exclusions::default() };
    let Ok(book) = lock(state) else { return Exclusions::default() };
    book.list().into_iter().find(|a| a.id == id).map(|a| a.net.excluded()).unwrap_or_default()
}

/// Ce qu'une feuille ne doit pas proposer pour le compte retenu : ses IP
/// exclues, ses IP réservées, les adresses de ses caméras connues et des
/// appareils relevés sur son réseau (même absents du dernier relevé, tant
/// qu'ils ont répondu depuis moins de six mois), sauf `own` (les adresses
/// actuelles des caméras qu'on réadresse, libres pour elles — jamais une
/// réservée, comme une exclue). Sans compte : rien, la feuille reste utilisable.
pub(crate) fn reserved_for(state: &Mutex<AccountBook>, id: Option<&str>, own: &[Ipv4Addr]) -> Exclusions {
    let excluded = exclusions_for(state, id);
    let Some(id) = id else { return excluded };
    let Ok((held, taken)) = lock(state).and_then(|b| {
        let cameras = b.known_cameras(id).map_err(code)?;
        let (devices, _) = b.devices(id).map_err(code)?;
        let held: Vec<Ipv4Addr> = b.reservations(id).map_err(code)?.into_iter().map(|r| r.ip).collect();
        let devices = current_devices(&devices, unix_now());
        Ok((held, cameras.into_iter().map(|c| c.ip).chain(devices.into_iter().map(|d| d.ip)).collect::<Vec<_>>()))
    }) else {
        return excluded;
    };
    excluded.with_addresses(held).with_addresses(taken.into_iter().filter(|a| !own.contains(a)))
}

/// Remplissage du réseau du compte retenu, `own` comptées libres ; `None` sans
/// compte, compte disparu ou sans réseau.
pub(crate) fn fill_for(state: &Mutex<AccountBook>, id: Option<&str>, own: &[Ipv4Addr]) -> Option<NetworkFill> {
    lock(state).ok()?.fill(id?, own).ok().flatten()
}

pub(crate) fn account_cameras(book: &AccountBook, id: &str) -> Result<Vec<KnownCamera>, String> {
    book.known_cameras(id).map_err(code)
}

pub(crate) fn account_fill(book: &AccountBook, id: &str) -> Result<Option<NetworkFill>, String> {
    book.fill(id, &[]).map_err(code)
}

/// Inventaire relevé d'un compte et date du dernier relevé.
#[derive(Serialize, Debug, PartialEq)]
pub struct AccountDevices {
    pub devices: Vec<lenscout_core::site_survey::device::SeenDevice>,
    pub surveyed_at: Option<u64>,
}

pub(crate) fn account_devices(book: &AccountBook, id: &str) -> Result<AccountDevices, String> {
    let (devices, surveyed_at) = book.devices(id).map_err(code)?;
    Ok(AccountDevices { devices, surveyed_at })
}

pub(crate) fn account_forget_device(book: &mut AccountBook, id: &str, key: &str) -> Result<(), String> {
    book.forget_device(id, key).map_err(code)
}

pub(crate) fn account_reservations(book: &AccountBook, id: &str) -> Result<Vec<ReservedIp>, String> {
    book.reservations(id).map_err(code)
}

/// Réserve une adresse (libellé facultatif), datée de maintenant. Adresse
/// illisible : `invalid_ip`.
pub(crate) fn account_reserve(book: &mut AccountBook, id: &str, ip: &str, label: Option<String>) -> Result<(), String> {
    let ip: Ipv4Addr = ip.trim().parse().map_err(|_| "invalid_ip".to_string())?;
    book.reserve(id, ip, label.as_deref(), unix_now()).map_err(code)
}

pub(crate) fn account_release(book: &mut AccountBook, id: &str, ip: &str) -> Result<(), String> {
    let ip: Ipv4Addr = ip.trim().parse().map_err(|_| "not_found".to_string())?;
    book.release(id, ip).map_err(code)
}

pub(crate) fn account_forget_camera(book: &mut AccountBook, id: &str, key: &str) -> Result<(), String> {
    book.forget_camera(id, key).map_err(code)
}

/// Caméras posées ou vues avec un compte, retenues dans sa mémoire. Un
/// échec (compte supprimé entre-temps, carnet en lecture seule) ne fait pas
/// échouer l'action ni le scan : c'est une mémoire, elle se rattrapera.
/// `seen_only` : un scan, qui ne retient que les caméras du réseau du compte.
pub(crate) fn remember_cameras(state: &Mutex<AccountBook>, id: &str, cameras: Vec<KnownCamera>, seen_only: bool) {
    if cameras.is_empty() {
        return;
    }
    let Ok(mut book) = lock(state) else { return };
    let r = match seen_only {
        true => book.remember_seen(id, cameras).map(|_| ()),
        false => book.remember(id, cameras),
    };
    if let Err(e) = r {
        lenscout_core::debug_log::log(&format!("caméras connues non retenues : {e}"));
    }
}

// `async` : l'écriture du fichier des comptes ne doit pas geler le thread
// principal.

#[tauri::command]
pub fn cmd_accounts_startup(notice: State<'_, StartupNotice>) -> Option<String> {
    take_notice(&notice)
}

#[tauri::command]
pub async fn cmd_accounts_list(
    state: State<'_, Mutex<AccountBook>>,
) -> Result<Vec<AccountEntry>, String> {
    let book = lock(&state)?;
    Ok(accounts_list(&book))
}

#[tauri::command]
pub async fn cmd_account_create(
    name: String,
    login: String,
    password: Secret,
    // Absent (ancien front) : aucun champ réseau.
    net: Option<AccountNetwork>,
    state: State<'_, Mutex<AccountBook>>,
) -> Result<Account, String> {
    let mut book = lock(&state)?;
    account_create(&mut book, &name, &login, password, net.unwrap_or_default())
}

#[tauri::command]
pub async fn cmd_account_update(
    id: String,
    name: String,
    login: String,
    password: Option<Secret>,
    net: Option<AccountNetwork>,
    state: State<'_, Mutex<AccountBook>>,
) -> Result<Account, String> {
    let mut book = lock(&state)?;
    account_update(&mut book, &id, &name, &login, password, net.unwrap_or_default())
}

/// Déchiffre le mot de passe d'UN compte, à l'ouverture de sa fiche.
#[tauri::command]
pub async fn cmd_account_password(
    id: String,
    state: State<'_, Mutex<AccountBook>>,
) -> Result<Option<RevealedPassword>, String> {
    let book = lock(&state)?;
    account_password(&book, &id)
}

#[tauri::command]
pub async fn cmd_account_remove(
    id: String,
    state: State<'_, Mutex<AccountBook>>,
) -> Result<(), String> {
    let mut book = lock(&state)?;
    account_remove(&mut book, &id)
}

/// Caméras connues du compte (jamais de secret : adresse, identité, modèle, date).
#[tauri::command]
pub async fn cmd_account_cameras(id: String, state: State<'_, Mutex<AccountBook>>) -> Result<Vec<KnownCamera>, String> {
    let book = lock(&state)?;
    account_cameras(&book, &id)
}

/// Remplissage du réseau du compte ; `null` sans IP du PC.
#[tauri::command]
pub async fn cmd_account_fill(id: String, state: State<'_, Mutex<AccountBook>>) -> Result<Option<NetworkFill>, String> {
    let book = lock(&state)?;
    account_fill(&book, &id)
}

/// Inventaire relevé du compte et date du dernier relevé (jamais de secret).
#[tauri::command]
pub async fn cmd_account_devices(id: String, state: State<'_, Mutex<AccountBook>>) -> Result<AccountDevices, String> {
    let book = lock(&state)?;
    account_devices(&book, &id)
}

/// Oublie un appareil relevé (`key` : MAC, sinon IP).
#[tauri::command]
pub async fn cmd_account_forget_device(id: String, key: String, state: State<'_, Mutex<AccountBook>>) -> Result<(), String> {
    let mut book = lock(&state)?;
    account_forget_device(&mut book, &id, &key)
}

/// Adresses réservées à la main dans le réseau du compte.
#[tauri::command]
pub async fn cmd_account_reservations(id: String, state: State<'_, Mutex<AccountBook>>) -> Result<Vec<ReservedIp>, String> {
    let book = lock(&state)?;
    account_reservations(&book, &id)
}

/// Réserve une adresse libre (une caméra posée là, pas encore joignable).
#[tauri::command]
pub async fn cmd_account_reserve(id: String, ip: String, label: Option<String>, state: State<'_, Mutex<AccountBook>>) -> Result<(), String> {
    let mut book = lock(&state)?;
    account_reserve(&mut book, &id, &ip, label)
}

/// Libère une adresse réservée.
#[tauri::command]
pub async fn cmd_account_release(id: String, ip: String, state: State<'_, Mutex<AccountBook>>) -> Result<(), String> {
    let mut book = lock(&state)?;
    account_release(&mut book, &id, &ip)
}

/// Oublie une caméra connue (`key` : n° de série, sinon MAC).
#[tauri::command]
pub async fn cmd_account_forget_camera(id: String, key: String, state: State<'_, Mutex<AccountBook>>) -> Result<(), String> {
    let mut book = lock(&state)?;
    account_forget_camera(&mut book, &id, &key)
}

// Le chemin vient de la boîte Enregistrer / Ouvrir du plugin dialog, jamais
// d'un champ de saisie.

#[tauri::command]
pub async fn cmd_accounts_export(path: String, state: State<'_, Mutex<AccountBook>>) -> Result<usize, String> {
    let book = lock(&state)?;
    accounts_export(&book, Path::new(&path))
}

#[tauri::command]
pub async fn cmd_accounts_import_plan(
    path: String,
    state: State<'_, Mutex<AccountBook>>,
) -> Result<ImportPlanOut, String> {
    let book = lock(&state)?;
    accounts_import_plan(&book, Path::new(&path))
}

#[tauri::command]
pub async fn cmd_accounts_import_apply(
    path: String,
    choices: HashMap<String, ChoiceIn>,
    state: State<'_, Mutex<AccountBook>>,
) -> Result<ImportSummaryOut, String> {
    let mut book = lock(&state)?;
    accounts_import_apply(&mut book, Path::new(&path), choices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenscout_core::site_survey::device::{DeviceKind, SeenDevice};

    /// Dossier temporaire d'un test, retiré à sa fin (même en cas d'échec).
    struct TmpDir(std::path::PathBuf);

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmp_dir() -> TmpDir {
        let dir = std::env::temp_dir().join(format!("lenscout-cmd-accounts-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        TmpDir(dir)
    }

    fn book() -> (AccountBook, TmpDir) {
        let dir = tmp_dir();
        let book = AccountBook::load(dir.0.join("accounts.json")).unwrap();
        (book, dir)
    }

    fn book_at(path: &std::path::Path) -> AccountBook {
        AccountBook::load(path.to_path_buf()).unwrap()
    }

    fn no_net() -> AccountNetwork {
        AccountNetwork::default()
    }

    #[test]
    fn password_is_revealed_for_one_account_only_never_in_debug() {
        let (mut book, _g_book) = book();
        let acc = account_create(&mut book, "A", "r", Secret::new("Unique-Pw-9".into()), no_net()).unwrap();
        fn wiped<T: zeroize::ZeroizeOnDrop>() {}
        wiped::<RevealedPassword>();
        let shown = account_password(&book, &acc.id).unwrap().unwrap();
        assert_eq!(serde_json::to_value(&shown).unwrap(), "Unique-Pw-9");
        assert!(!format!("{shown:?}").contains("Unique"));
        assert_eq!(account_password(&book, "zzz").unwrap_err(), "not_found");
    }

    #[test]
    fn network_errors_are_stable_codes() {
        let (mut book, _g_book) = book();
        let pwd = || Secret::new("x".into());
        let net = |pc: &str, n: &str, g: &str| AccountNetwork {
            pc_ip: Some(pc.into()),
            network: Some(n.into()),
            gateway: Some(g.into()),
            exclusions: None,
        };
        let cases = [
            (net("x/24", "", ""), "invalid_pc_ip"),
            (net("10.0.1.5", "", ""), "missing_mask"),
            (net("", "", "x"), "invalid_gateway"),
            (net("10.0.1.5/24", "10.0.0.0/16", "10.0.2.1"), "gateway_outside_network"),
            (AccountNetwork { exclusions: Some("10.0.1.9-10.0.1.2".into()), ..no_net() }, "invalid_exclusions"),
        ];
        for (n, want) in cases {
            assert_eq!(account_create(&mut book, "A", "r", pwd(), n).unwrap_err(), want);
        }
        assert!(book.list().is_empty());
    }

    #[test]
    fn list_and_plan_carry_network_fields() {
        let (mut src, _g_src) = book();
        let full = AccountNetwork {
            pc_ip: Some("192.168.1.250/24".into()),
            network: Some("192.168.1.0/24".into()),
            gateway: Some("192.168.1.1".into()),
            exclusions: Some("192.168.1.2-192.168.1.9".into()),
        };
        account_create(&mut src, "Mairie", "root", Secret::new("x".into()), full).unwrap();
        let json = serde_json::to_value(accounts_list(&src)).unwrap();
        assert_eq!(json[0]["pc_ip"], "192.168.1.250/24");
        assert_eq!(json[0]["network"], "192.168.1.0/24");
        assert_eq!(json[0]["gateway"], "192.168.1.1");
        assert_eq!(json[0]["exclusions"], "192.168.1.2-9");
        let (path, _g_path) = temp_file("n.lenscout");
        accounts_export(&src, &path).unwrap();
        let (mut dst, _g_dst) = book();
        account_create(&mut dst, "Mairie", "root", Secret::new("x".into()), no_net()).unwrap();
        let plan = serde_json::to_value(accounts_import_plan(&dst, &path).unwrap()).unwrap();
        assert_eq!(plan["items"][0]["kind"], "differs");
        assert_eq!(plan["items"][0]["network_differs"], true);
        assert_eq!(plan["items"][0]["gateway_dropped"], false);
        assert_eq!(plan["items"][0]["login_differs"], false);
    }

    #[test]
    fn exclusions_of_the_chosen_account_only() {
        let (mut book, _g_book) = book();
        let n = AccountNetwork { exclusions: Some("10.0.0.5".into()), ..no_net() };
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into()), n).unwrap();
        let state = Mutex::new(book);
        assert!(exclusions_for(&state, Some(&acc.id)).contains("10.0.0.5".parse().unwrap()));
        // Aucun compte, ou un compte disparu : rien d'exclu, la recherche continue.
        assert_eq!(exclusions_for(&state, None), Exclusions::default());
        assert_eq!(exclusions_for(&state, Some("zzz")), Exclusions::default());
    }

    fn site() -> AccountNetwork {
        AccountNetwork { pc_ip: Some("10.0.8.250/24".into()), gateway: Some("10.0.8.1".into()), ..no_net() }
    }

    fn cam(ip: &str, serial: &str) -> KnownCamera {
        KnownCamera { ip: ip.parse().unwrap(), serial: Some(serial.into()), mac: None, model: None, last_seen: 1 }
    }

    #[test]
    fn known_cameras_are_reserved_except_the_ones_being_moved() {
        let (mut book, _g_book) = book();
        let n = AccountNetwork { exclusions: Some("10.0.8.5".into()), ..site() };
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into()), n).unwrap();
        book.remember(&acc.id, vec![cam("10.0.8.20", "S1"), cam("10.0.8.21", "S2")]).unwrap();
        let state = Mutex::new(book);
        let ip = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        let r = reserved_for(&state, Some(&acc.id), &[ip("10.0.8.21")]);
        assert!(r.contains(ip("10.0.8.5")) && r.contains(ip("10.0.8.20")));
        // La caméra qu'on réadresse : son adresse actuelle reste libre pour elle.
        assert!(!r.contains(ip("10.0.8.21")));
        assert_eq!(reserved_for(&state, None, &[]), Exclusions::default());
        assert_eq!(reserved_for(&state, Some("zzz"), &[]), Exclusions::default());
        // Le remplissage compte de même.
        let f = fill_for(&state, Some(&acc.id), &[ip("10.0.8.21")]).unwrap();
        assert_eq!((f.cameras, f.free), (1, 254 - 4));
        assert!(fill_for(&state, None, &[]).is_none());
    }

    // Vu à l'instant : un appareil vu il y a plus de six mois ne compte plus pris.
    fn seen_device(ip: &str, mac: Option<&str>) -> SeenDevice {
        let now = lenscout_core::accounts::unix_now();
        SeenDevice { ip: ip.parse().unwrap(), mac: mac.map(str::to_string), vendor: None, kind: DeviceKind::Switch, name: None, model: None, first_seen: now, last_seen: now }
    }

    #[test]
    fn reserved_ips_are_held_even_for_the_cameras_being_moved() {
        let (mut book, _g_book) = book();
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into()), site()).unwrap();
        let ip = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        account_reserve(&mut book, &acc.id, "10.0.8.60", Some("Cam 110".into())).unwrap();
        let state = Mutex::new(book);
        assert!(reserved_for(&state, Some(&acc.id), &[ip("10.0.8.60")]).contains(ip("10.0.8.60")));
        assert_eq!(fill_for(&state, Some(&acc.id), &[]).unwrap().reserved, 1);
    }

    #[test]
    fn a_device_unseen_for_six_months_is_not_held() {
        let (mut book, _g_book) = book();
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into()), site()).unwrap();
        let old = lenscout_core::accounts::unix_now() - 181 * 24 * 3600;
        let stale = SeenDevice { first_seen: old, last_seen: old, ..seen_device("10.0.8.40", None) };
        book.record_survey(&acc.id, vec![stale, seen_device("10.0.8.41", None)], old).unwrap();
        let state = Mutex::new(book);
        let ip = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        let r = reserved_for(&state, Some(&acc.id), &[]);
        assert!(!r.contains(ip("10.0.8.40")) && r.contains(ip("10.0.8.41")));
    }

    #[test]
    fn reservations_are_listed_made_and_released_with_stable_codes() {
        let (mut book, _g_book) = book();
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into()), site()).unwrap();
        assert_eq!(account_reserve(&mut book, &acc.id, "pas une ip", None).unwrap_err(), "invalid_ip");
        account_reserve(&mut book, &acc.id, " 10.0.8.60 ", Some("Cam 110".into())).unwrap();
        let json = serde_json::to_value(account_reservations(&book, &acc.id).unwrap()).unwrap();
        assert_eq!((json[0]["ip"].as_str(), json[0]["label"].as_str()), (Some("10.0.8.60"), Some("Cam 110")));
        assert!(json[0]["at"].as_u64().unwrap() > 0);
        assert_eq!(account_release(&mut book, &acc.id, "10.0.8.61").unwrap_err(), "not_found");
        account_release(&mut book, &acc.id, "10.0.8.60").unwrap();
        assert!(account_reservations(&book, &acc.id).unwrap().is_empty());
        assert_eq!(account_reservations(&book, "zzz").unwrap_err(), "not_found");
    }

    #[test]
    fn reserved_holds_surveyed_devices_but_not_own() {
        let (mut book, _g_book) = book();
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into()), site()).unwrap();
        book.record_survey(&acc.id, vec![seen_device("10.0.8.30", Some("AA:BB:CC:00:00:30")), seen_device("10.0.8.31", None)], 5).unwrap();
        let state = Mutex::new(book);
        let ip = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        let r = reserved_for(&state, Some(&acc.id), &[ip("10.0.8.31")]);
        assert!(r.contains(ip("10.0.8.30")));
        assert!(!r.contains(ip("10.0.8.31")));
        let f = fill_for(&state, Some(&acc.id), &[]).unwrap();
        assert_eq!(f.devices, 2);
    }

    #[test]
    fn devices_of_an_account_are_listed_with_their_date_and_forgotten_by_key() {
        let (mut book, _g_book) = book();
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into()), site()).unwrap();
        let json = serde_json::to_value(account_devices(&book, &acc.id).unwrap()).unwrap();
        assert_eq!(json, serde_json::json!({"devices": [], "surveyed_at": null}));
        book.record_survey(&acc.id, vec![seen_device("10.0.8.30", Some("AA:BB:CC:00:00:30"))], 5).unwrap();
        let json = serde_json::to_value(account_devices(&book, &acc.id).unwrap()).unwrap();
        assert_eq!((json["devices"][0]["kind"].as_str(), json["surveyed_at"].as_u64()), (Some("switch"), Some(5)));
        assert_eq!(account_forget_device(&mut book, &acc.id, "10.0.8.99").unwrap_err(), "not_found");
        account_forget_device(&mut book, &acc.id, "AA:BB:CC:00:00:30").unwrap();
        assert!(account_devices(&book, &acc.id).unwrap().devices.is_empty());
        assert_eq!(account_devices(&book, "zzz").unwrap_err(), "not_found");
    }

    #[test]
    fn cameras_of_an_account_are_listed_and_forgotten_by_key() {
        let (mut book, _g_book) = book();
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into()), site()).unwrap();
        book.remember(&acc.id, vec![cam("10.0.8.20", "S1")]).unwrap();
        let json = serde_json::to_value(account_cameras(&book, &acc.id).unwrap()).unwrap();
        assert_eq!(json[0]["ip"], "10.0.8.20");
        assert_eq!(json[0]["serial"], "S1");
        assert_eq!(json[0]["last_seen"], 1);
        assert_eq!(account_forget_camera(&mut book, &acc.id, "S2").unwrap_err(), "not_found");
        account_forget_camera(&mut book, &acc.id, "S1").unwrap();
        assert!(account_cameras(&book, &acc.id).unwrap().is_empty());
        assert_eq!(account_cameras(&book, "zzz").unwrap_err(), "not_found");
        let fill = serde_json::to_value(account_fill(&book, &acc.id).unwrap()).unwrap();
        assert_eq!(fill["free"], 252);
        assert_eq!(fill["segments"][0]["kind"], "gateway");
    }

    fn uuid_like() -> String {
        format!(
            "{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[test]
    fn list_never_contains_password() {
        let (mut book, _g_book) = book();
        account_create(
            &mut book,
            "Défaut LORVA",
            "root",
            Secret::new("S3cr3t-Unique!".into()),
            no_net(),
        )
        .unwrap();
        let json = serde_json::to_string(&accounts_list(&book)).unwrap();
        assert!(!json.contains("S3cr3t"));
        assert!(json.contains("Défaut LORVA"));
    }

    #[test]
    fn list_flags_accounts_without_secret() {
        // Ancien format : mots de passe hors du fichier, à ressaisir.
        let _dir = tmp_dir();
        let path = _dir.0.join("accounts.json");
        std::fs::write(&path, r#"[{"id":"lost","name":"B","login":"r"}]"#).unwrap();
        let mut book = AccountBook::load(path).unwrap();
        let ok = account_create(&mut book, "A", "r", Secret::new("x".into()), no_net()).unwrap();
        let entries = accounts_list(&book);
        let flag = |id: &str| entries.iter().find(|e| e.id == id).unwrap().has_secret;
        assert!(flag(&ok.id));
        assert!(!flag("lost"));
        let json = serde_json::to_string(&entries).unwrap();
        assert!(json.contains("\"has_secret\":false"));
    }

    #[test]
    fn a_failed_migration_is_announced_after_an_accounts_problem() {
        use lenscout_core::accounts::Startup;
        assert_eq!(notice_code(&Startup::Clean, false), None);
        assert_eq!(notice_code(&Startup::Clean, true), Some("migration_incomplete"));
        assert_eq!(notice_code(&Startup::Unwritable, true), Some("unwritable"));
    }

    #[test]
    fn old_accounts_set_aside_are_merged_once() {
        let (mut book, dir) = book();
        let aside = dir.0.join("accounts.json.io.lenscout.app");
        // Rien de posé à côté : rien à faire.
        assert!(absorb_old_accounts(&mut book, &aside));
        let mut old = book_at(&aside);
        account_create(&mut old, "Gare", "root", Secret::new("x".into()), no_net()).unwrap();
        assert!(absorb_old_accounts(&mut book, &aside));
        assert_eq!(book.list().len(), 1);
        // Le fichier fusionné est renommé (jamais effacé) : pas de seconde fusion.
        assert!(!aside.exists());
        let kept = std::fs::read_dir(&dir.0).unwrap().filter_map(|e| e.ok()).any(|e| {
            e.file_name().to_string_lossy().starts_with("accounts.json.io.lenscout.app.merged-")
        });
        assert!(kept);
        // Illisible : mis de côté (`.corrupt-*`, jamais effacé), signalé une
        // seule fois — le lancement suivant n'a plus rien à fusionner.
        std::fs::write(&aside, b"pas du json").unwrap();
        assert!(!absorb_old_accounts(&mut book, &aside));
        assert!(!aside.exists());
        let corrupt = std::fs::read_dir(&dir.0).unwrap().filter_map(|e| e.ok()).any(|e| {
            e.file_name().to_string_lossy().starts_with("accounts.json.io.lenscout.app.corrupt-")
        });
        assert!(corrupt);
        assert!(absorb_old_accounts(&mut book, &aside));
    }

    #[test]
    fn startup_codes() {
        use lenscout_core::accounts::Startup;
        assert_eq!(startup_code(&Startup::Clean), None);
        assert_eq!(
            startup_code(&Startup::Quarantined("x".into())),
            Some("quarantined")
        );
        assert_eq!(startup_code(&Startup::Unwritable), Some("unwritable"));
    }

    #[test]
    fn notice_is_given_once() {
        let notice = StartupNotice(Mutex::new(Some("quarantined")));
        assert_eq!(take_notice(&notice), Some("quarantined".to_string()));
        assert_eq!(take_notice(&notice), None);
    }

    #[test]
    fn errors_are_stable_codes() {
        let (mut book, _g_book) = book();
        let pwd = || Secret::new("x".into());
        assert_eq!(
            account_create(&mut book, " ", "r", pwd(), no_net()).unwrap_err(),
            "empty_field"
        );
        account_create(&mut book, "A", "r", pwd(), no_net()).unwrap();
        assert_eq!(
            account_create(&mut book, "a", "r", pwd(), no_net()).unwrap_err(),
            "duplicate_name"
        );
        assert_eq!(account_remove(&mut book, "nope").unwrap_err(), "not_found");
    }

    #[test]
    fn missing_secret_has_its_own_code() {
        let _dir = tmp_dir();
        let path = _dir.0.join("accounts.json");
        std::fs::write(&path, r#"[{"id":"a","name":"A","login":"r"}]"#).unwrap();
        // Ancien format : compte repris « à ressaisir ».
        let book = Mutex::new(AccountBook::load(path).unwrap());
        assert_eq!(credentials_for(&book, "a").unwrap_err(), "secret_missing");
        assert_eq!(credentials_for(&book, "nope").unwrap_err(), "not_found");
    }

    #[test]
    fn update_without_password_keeps_it() {
        let (mut book, _g_book) = book();
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into()), no_net()).unwrap();
        let upd = account_update(&mut book, &acc.id, "B", "r2", None, no_net()).unwrap();
        assert_eq!((upd.name.as_str(), upd.login.as_str()), ("B", "r2"));
        assert_eq!(book.credentials(&acc.id).unwrap().password.expose(), "x");
    }

    fn temp_file(name: &str) -> (std::path::PathBuf, TmpDir) {
        let dir = tmp_dir();
        (dir.0.join(name), dir)
    }

    #[test]
    fn export_writes_the_sealed_file_and_counts() {
        let (mut src, _g_src) = book();
        account_create(&mut src, "Mairie Arles", "root-unique", Secret::new("S3cr3t-Unique!".into()), no_net()).unwrap();
        account_create(&mut src, "Gare", "admin", Secret::new("x".into()), no_net()).unwrap();
        let (path, _g_path) = temp_file("lenscout-comptes.lenscout");
        assert_eq!(accounts_export(&src, &path).unwrap(), 2);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("Mairie Arles") && !raw.contains("root-unique") && !raw.contains("S3cr3t"));
        // Pas de temporaire laissé à côté.
        assert!(!path.with_extension("lenscout.tmp").exists());
        // Le fichier se réimporte sur un carnet neuf.
        let (mut dst, _g_dst) = book();
        let summary = accounts_import_apply(&mut dst, &path, HashMap::new()).unwrap();
        assert_eq!(summary.added, 2);
        assert_eq!(dst.list().len(), 2);
    }

    #[test]
    fn import_plan_has_flat_kinds_and_no_secret() {
        let (mut src, _g_src) = book();
        account_create(&mut src, "Mairie Arles", "root-unique", Secret::new("S3cr3t-Unique!".into()), no_net()).unwrap();
        account_create(&mut src, "Gare", "admin", Secret::new("x".into()), no_net()).unwrap();
        let (path, _g_path) = temp_file("a.lenscout");
        accounts_export(&src, &path).unwrap();
        let (mut dst, _g_dst) = book();
        account_create(&mut dst, "Mairie Arles", "autre", Secret::new("S3cr3t-Unique!".into()), no_net()).unwrap();
        let plan = accounts_import_plan(&dst, &path).unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        assert!(!json.contains("S3cr3t") && !json.contains("root-unique"));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let items = v["items"].as_array().unwrap();
        let mairie = items.iter().find(|i| i["name"] == "Mairie Arles").unwrap();
        assert_eq!(mairie["kind"], "differs");
        assert_eq!(mairie["login_differs"], true);
        assert_eq!(mairie["password_differs"], false);
        let gare = items.iter().find(|i| i["name"] == "Gare").unwrap();
        assert_eq!(gare["kind"], "new");
    }

    #[test]
    fn keep_both_choice_is_applied() {
        let (mut src, _g_src) = book();
        account_create(&mut src, "Mairie", "root", Secret::new("a".into()), no_net()).unwrap();
        let (path, _g_path) = temp_file("a.lenscout");
        accounts_export(&src, &path).unwrap();
        let (mut dst, _g_dst) = book();
        account_create(&mut dst, "Mairie", "autre", Secret::new("b".into()), no_net()).unwrap();
        // Les choix arrivent du front en JSON : on passe par la vraie désérialisation.
        let choices: HashMap<String, ChoiceIn> = serde_json::from_str(r#"{"Mairie":"keep_both"}"#).unwrap();
        let summary = accounts_import_apply(&mut dst, &path, choices).unwrap();
        assert_eq!(summary.kept_both, 1);
        assert!(dst.list().iter().any(|a| a.name == "Mairie 2"));
    }

    #[test]
    fn unreadable_import_is_import_invalid_and_changes_nothing() {
        let (mut dst, _g_dst) = book();
        account_create(&mut dst, "A", "r", Secret::new("x".into()), no_net()).unwrap();
        let (path, _g_path) = temp_file("junk.lenscout");
        std::fs::write(&path, b"{\"format\":\"autre\"}").unwrap();
        assert_eq!(accounts_import_plan(&dst, &path).unwrap_err(), "import_invalid");
        assert_eq!(accounts_import_apply(&mut dst, &path, HashMap::new()).unwrap_err(), "import_invalid");
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(accounts_import_plan(&dst, &path).unwrap_err(), "import_invalid");
        assert_eq!(dst.list().len(), 1);
        // Fichier absent : erreur d'accès, pas « illisible ».
        let (gone, _g_gone) = temp_file("absent.lenscout");
        assert_eq!(accounts_import_plan(&dst, &gone).unwrap_err(), "file_unreadable");
    }

    #[test]
    fn export_adds_the_extension_when_missing() {
        let (mut src, _g_src) = book();
        account_create(&mut src, "A", "r", Secret::new("x".into()), no_net()).unwrap();
        let (bare, _g_bare) = temp_file("sauvegarde");
        accounts_export(&src, &bare).unwrap();
        assert!(bare.with_extension("lenscout").exists() && !bare.exists());
        let (named, _g_named) = temp_file("b.lenscout");
        accounts_export(&src, &named).unwrap();
        assert!(named.exists());
    }

    #[cfg(unix)]
    #[test]
    fn export_is_private_even_over_a_stale_temp() {
        use std::os::unix::fs::PermissionsExt;
        let (mut src, _g_src) = book();
        account_create(&mut src, "A", "r", Secret::new("x".into()), no_net()).unwrap();
        let (path, _g_path) = temp_file("c.lenscout");
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        std::fs::write(&tmp, b"vieux").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        accounts_export(&src, &path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// Indépendant de l'utilisateur (root contourne les droits) : le chemin choisi
    /// a pour « dossier » un fichier ordinaire, le système refuse quoi qu'on soit.
    #[test]
    fn io_errors_on_the_chosen_file_have_their_own_codes() {
        let (mut src, _g_src) = book();
        account_create(&mut src, "A", "r", Secret::new("x".into()), no_net()).unwrap();
        let (plain, _g_plain) = temp_file("ordinaire");
        std::fs::write(&plain, b"x").unwrap();
        let path = plain.join("d.lenscout");
        assert_eq!(accounts_export(&src, &path).unwrap_err(), "file_unwritable");
        assert!(!path.exists() && !path.with_extension("lenscout.tmp").exists());
        assert_eq!(accounts_import_plan(&src, &path).unwrap_err(), "file_unreadable");
    }
}
