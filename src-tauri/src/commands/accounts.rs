use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use lenscout_core::accounts::{
    Account, AccountBook, AccountError, AccountNetwork, Choice, ImportKind, ImportPlan, ImportSummary, Startup,
    write_file_private,
};
use lenscout_core::secret::Secret;
use lenscout_core::transport::Credentials;
use serde::{Deserialize, Serialize};
use tauri::State;

/// Erreurs : codes stables (`empty_field`, `duplicate_name`, `not_found`,
/// `secret_missing`, `keyring`, `io`, `import_invalid`, `file_unwritable`,
/// `file_unreadable`, `invalid_pc_ip`, `missing_mask`, `invalid_gateway`,
/// `gateway_outside_network`), traduits par le front. Le message de
/// l'OS n'est pas renvoyé.
fn code(e: AccountError) -> String {
    match e {
        AccountError::EmptyField => "empty_field",
        AccountError::DuplicateName => "duplicate_name",
        AccountError::NotFound => "not_found",
        AccountError::SecretMissing => "secret_missing",
        AccountError::Keyring(_) => "keyring",
        AccountError::Io(_) => "io",
        AccountError::ImportInvalid => "import_invalid",
        AccountError::InvalidPcIp => "invalid_pc_ip",
        AccountError::MaskMissing => "missing_mask",
        AccountError::InvalidGateway => "invalid_gateway",
        AccountError::GatewayOutsideNetwork => "gateway_outside_network",
    }
    .to_string()
}

fn lock(state: &Mutex<AccountBook>) -> Result<std::sync::MutexGuard<'_, AccountBook>, String> {
    state.lock().map_err(|_| "internal".to_string())
}

// Les fonctions pures portent la logique ; les commandes ne font que
// verrouiller l'état. Aucune ne renvoie de mot de passe.

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
                ImportItemOut { name: i.name, kind, login_differs, password_differs, network_differs }
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

pub(crate) fn account_remove(book: &mut AccountBook, id: &str) -> Result<(), String> {
    book.remove(id).map_err(code)
}

/// Identifiants d'un compte pour les commandes authentifiées (cadrage,
/// configuration) : le mot de passe reste côté Rust.
/// Pour une action ou un flux. Codes possibles (affichés par les pages
/// Configuration et Cadrage) : `not_found`, `secret_missing`, `keyring`,
/// `internal`. `AccountBook::credentials` ne rend rien d'autre.
pub(crate) fn credentials_for(state: &Mutex<AccountBook>, id: &str) -> Result<Credentials, String> {
    lock(state)?.credentials(id).map_err(|e| match e {
        AccountError::NotFound => "not_found".to_string(),
        AccountError::SecretMissing => "secret_missing".to_string(),
        _ => "keyring".to_string(),
    })
}

// `async` : le trousseau peut bloquer (D-Bus, invite de l'OS), ce qui ne doit
// pas geler le thread principal.

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

#[tauri::command]
pub async fn cmd_account_remove(
    id: String,
    state: State<'_, Mutex<AccountBook>>,
) -> Result<(), String> {
    let mut book = lock(&state)?;
    account_remove(&mut book, &id)
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
    use lenscout_core::accounts::{MemoryStore, SecretStore};
    use std::sync::Arc;

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
        let book = AccountBook::load(dir.0.join("accounts.json"), Arc::new(MemoryStore::default())).unwrap();
        (book, dir)
    }

    fn no_net() -> AccountNetwork {
        AccountNetwork::default()
    }

    #[test]
    fn network_errors_are_stable_codes() {
        let (mut book, _g_book) = book();
        let pwd = || Secret::new("x".into());
        let net = |pc: &str, n: &str, g: &str| AccountNetwork {
            pc_ip: Some(pc.into()),
            network: Some(n.into()),
            gateway: Some(g.into()),
        };
        let cases = [
            (net("x/24", "", ""), "invalid_pc_ip"),
            (net("10.0.1.5", "", ""), "missing_mask"),
            (net("", "", "x"), "invalid_gateway"),
            (net("10.0.1.5/24", "10.0.0.0/16", "10.0.2.1"), "gateway_outside_network"),
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
        };
        account_create(&mut src, "Mairie", "root", Secret::new("x".into()), full).unwrap();
        let json = serde_json::to_value(accounts_list(&src)).unwrap();
        assert_eq!(json[0]["pc_ip"], "192.168.1.250/24");
        assert_eq!(json[0]["network"], "192.168.1.0/24");
        assert_eq!(json[0]["gateway"], "192.168.1.1");
        let (path, _g_path) = temp_file("n.lenscout");
        accounts_export(&src, &path).unwrap();
        let (mut dst, _g_dst) = book();
        account_create(&mut dst, "Mairie", "root", Secret::new("x".into()), no_net()).unwrap();
        let plan = serde_json::to_value(accounts_import_plan(&dst, &path).unwrap()).unwrap();
        assert_eq!(plan["items"][0]["kind"], "differs");
        assert_eq!(plan["items"][0]["network_differs"], true);
        assert_eq!(plan["items"][0]["login_differs"], false);
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
        // Ancien format dont le trousseau a perdu un secret.
        let store = Arc::new(MemoryStore::default());
        let _dir = tmp_dir();
        let path = _dir.0.join("accounts.json");
        std::fs::write(
            &path,
            r#"[{"id":"ok","name":"A","login":"r"},{"id":"lost","name":"B","login":"r"}]"#,
        )
        .unwrap();
        store.set("ok", &Secret::new("x".into())).unwrap();
        let book = AccountBook::load(path, store).unwrap();
        let entries = accounts_list(&book);
        let flag = |id: &str| entries.iter().find(|e| e.id == id).unwrap().has_secret;
        assert!(flag("ok"));
        assert!(!flag("lost"));
        let json = serde_json::to_string(&entries).unwrap();
        assert!(json.contains("\"has_secret\":false"));
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
        let store = Arc::new(MemoryStore::default());
        let _dir = tmp_dir();
        let path = _dir.0.join("accounts.json");
        std::fs::write(&path, r#"[{"id":"a","name":"A","login":"r"}]"#).unwrap();
        // Trousseau sans le secret : compte repris « à ressaisir ».
        let book = Mutex::new(AccountBook::load(path, store).unwrap());
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
