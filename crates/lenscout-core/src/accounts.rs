use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::seal;
use crate::secret::Secret;
use crate::transport::Credentials;

/// Métadonnées d'un compte. Le mot de passe n'y figure pas : il vit dans le
/// carnet, scellé dans le fichier (voir `seal`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub login: String,
}

#[derive(thiserror::Error, Debug)]
pub enum AccountError {
    #[error("compte introuvable")]
    NotFound,
    // Le compte existe mais n'a pas de mot de passe (reprise d'un trousseau
    // inaccessible) : à ressaisir.
    #[error("mot de passe absent")]
    SecretMissing,
    #[error("nom déjà utilisé")]
    DuplicateName,
    #[error("champ vide")]
    EmptyField,
    // Message de l'OS, jamais le mot de passe.
    #[error("trousseau : {0}")]
    Keyring(String),
    #[error("fichier : {0}")]
    Io(String),
    // Fichier d'import illisible, tronqué ou d'un autre logiciel.
    #[error("fichier d'import invalide")]
    ImportInvalid,
}

/// Ancien trousseau : ne sert plus qu'à la reprise des comptes du format 1.
pub trait SecretStore: Send + Sync {
    fn set(&self, id: &str, password: &Secret) -> Result<(), AccountError>;
    fn get(&self, id: &str) -> Result<Secret, AccountError>;
    fn delete(&self, id: &str) -> Result<(), AccountError>;
}

/// Trousseau du système : Keychain (macOS), Credential Manager (Windows),
/// Secret Service (Linux).
pub struct KeyringStore;

const SERVICE: &str = "io.lenscout.app";

impl KeyringStore {
    fn entry(id: &str) -> Result<keyring::Entry, AccountError> {
        keyring::Entry::new(SERVICE, id).map_err(keyring_error)
    }
}

fn keyring_error(e: keyring::Error) -> AccountError {
    match e {
        keyring::Error::NoEntry => AccountError::NotFound,
        other => AccountError::Keyring(other.to_string()),
    }
}

impl SecretStore for KeyringStore {
    fn set(&self, id: &str, password: &Secret) -> Result<(), AccountError> {
        Self::entry(id)?
            .set_password(password.expose())
            .map_err(keyring_error)
    }

    fn get(&self, id: &str) -> Result<Secret, AccountError> {
        Self::entry(id)?
            .get_password()
            .map(Secret::new)
            .map_err(keyring_error)
    }

    fn delete(&self, id: &str) -> Result<(), AccountError> {
        Self::entry(id)?.delete_credential().map_err(keyring_error)
    }
}

/// Trousseau en mémoire, pour les tests.
#[derive(Default)]
pub struct MemoryStore {
    secrets: Mutex<HashMap<String, Secret>>,
}

impl SecretStore for MemoryStore {
    fn set(&self, id: &str, password: &Secret) -> Result<(), AccountError> {
        self.secrets
            .lock()
            .unwrap()
            .insert(id.to_string(), password.clone());
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Secret, AccountError> {
        self.secrets
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(AccountError::NotFound)
    }

    fn delete(&self, id: &str) -> Result<(), AccountError> {
        self.secrets
            .lock()
            .unwrap()
            .remove(id)
            .map(|_| ())
            .ok_or(AccountError::NotFound)
    }
}

#[derive(Clone)]
struct Entry {
    account: Account,
    // Absent : compte à ressaisir (« Mot de passe à ressaisir »).
    password: Option<Secret>,
}

pub struct AccountBook {
    path: PathBuf,
    entries: Vec<Entry>,
    // Carnet en mémoire seule : toute écriture échoue (voir `load_or_quarantine`).
    read_only: bool,
}

/// Issue du chargement au démarrage.
#[derive(Debug)]
pub enum Startup {
    Clean,
    /// Fichier illisible renommé ; chemin du fichier mis de côté.
    Quarantined(PathBuf),
    /// Fichier illisible et renommage impossible : carnet vide, sans écriture.
    Unwritable,
}

/// Un `accounts.json` illisible ne doit ni bloquer le démarrage ni être
/// écrasé : on le renomme (jamais supprimé) et on repart d'un carnet vide.
/// Si même le renommage échoue, le carnet reste en mémoire seule.
pub fn load_or_quarantine(path: PathBuf, store: Arc<dyn SecretStore>) -> (AccountBook, Startup) {
    if let Ok(book) = AccountBook::load(path.clone(), store) {
        return (book, Startup::Clean);
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".corrupt-{stamp}"));
    let moved = path.with_file_name(name);
    let mut book = AccountBook {
        path: path.clone(),
        entries: Vec::new(),
        read_only: false,
    };
    if std::fs::rename(&path, &moved).is_ok() {
        (book, Startup::Quarantined(moved))
    } else {
        book.read_only = true;
        (book, Startup::Unwritable)
    }
}

impl fmt::Debug for AccountBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountBook")
            .field("path", &self.path)
            .field("accounts", &self.list())
            .finish_non_exhaustive()
    }
}

/// Résultat d'un import, par compte du fichier.
#[derive(Debug, Clone, PartialEq)]
pub enum ImportKind {
    New,
    Identical,
    Differs {
        login_differs: bool,
        password_differs: bool,
    },
}

/// Aucun secret ici : le plan part tel quel vers l'écran.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportItem {
    pub name: String,
    pub kind: ImportKind,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImportPlan {
    pub items: Vec<ImportItem>,
}

/// Choix pour un nom déjà présent qui diffère.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Choice {
    Replace,
    KeepBoth,
    Skip,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImportSummary {
    pub added: usize,
    pub identical: usize,
    pub replaced: usize,
    pub kept_both: usize,
    pub skipped: usize,
}

// Compte lu dans un fichier d'import, secrets déjà ouverts.
struct Imported {
    name: String,
    login: String,
    password: Option<Secret>,
}

const EXPORT_FORMAT: &str = "lenscout-accounts";

fn open_text(sealed: &str) -> Option<String> {
    String::from_utf8(seal::open(sealed).ok()?).ok()
}

fn parse_import(data: &str) -> Result<Vec<Imported>, AccountError> {
    let invalid = || AccountError::ImportInvalid;
    let v: serde_json::Value = serde_json::from_str(data).map_err(|_| invalid())?;
    if v["format"] != EXPORT_FORMAT || v["version"] != 1 {
        return Err(invalid());
    }
    let mut out = Vec::new();
    for a in v["accounts"].as_array().ok_or_else(invalid)? {
        let name = a["name"].as_str().ok_or_else(invalid)?.trim().to_string();
        let login = open_text(a["login"].as_str().ok_or_else(invalid)?).ok_or_else(invalid)?;
        let password = match a.get("password") {
            None | Some(serde_json::Value::Null) => None,
            Some(p) => Some(Secret::new(
                open_text(p.as_str().ok_or_else(invalid)?).ok_or_else(invalid)?,
            )),
        };
        if name.is_empty() || login.is_empty() {
            return Err(invalid());
        }
        out.push(Imported {
            name,
            login,
            password: password.filter(|p| !p.expose().is_empty()),
        });
    }
    Ok(out)
}

fn classify(existing: &Entry, imported: &Imported) -> ImportKind {
    let login_differs = existing.account.login != imported.login;
    // Un import sans mot de passe n'efface jamais celui du carnet.
    let password_differs = imported
        .password
        .as_ref()
        .is_some_and(|p| Some(p.expose()) != existing.password.as_ref().map(Secret::expose));
    if login_differs || password_differs {
        ImportKind::Differs {
            login_differs,
            password_differs,
        }
    } else {
        ImportKind::Identical
    }
}

fn position_of(entries: &[Entry], name: &str) -> Option<usize> {
    let wanted = name.to_lowercase();
    entries
        .iter()
        .position(|e| e.account.name.to_lowercase() == wanted)
}

impl AccountBook {
    /// Lit le fichier : format 2 (scellé) ou ancien format (tableau, login en
    /// clair, secret au trousseau), repris puis réécrit en format 2. Les
    /// entrées du trousseau ne sont jamais supprimées. Si un secret manque
    /// (trousseau inaccessible, entrée perdue), le compte reste listé « à
    /// ressaisir » et le fichier d'origine n'est pas réécrit : la reprise sera
    /// retentée au prochain lancement.
    pub fn load(path: PathBuf, store: Arc<dyn SecretStore>) -> Result<Self, AccountError> {
        let io = |e: String| AccountError::Io(e);
        let mut book = AccountBook {
            path,
            entries: Vec::new(),
            read_only: false,
        };
        let raw = match std::fs::read(&book.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(book),
            Err(e) => return Err(io(e.to_string())),
        };
        let v: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| io(e.to_string()))?;
        if v.is_array() {
            let legacy: Vec<Account> = serde_json::from_value(v).map_err(|e| io(e.to_string()))?;
            let mut complete = true;
            for account in legacy {
                let password = store
                    .get(&account.id)
                    .ok()
                    .filter(|p| !p.expose().is_empty());
                complete &= password.is_some();
                book.entries.push(Entry { account, password });
            }
            if complete {
                // Réécriture ratée (dossier en lecture seule) : on garde le carnet en mémoire.
                let _ = book.write(&book.entries);
            }
            return Ok(book);
        }
        if v["version"] != 2 {
            return Err(io("version de fichier inconnue".into()));
        }
        for a in v["accounts"]
            .as_array()
            .ok_or_else(|| io("comptes absents".into()))?
        {
            let text = |key: &str| {
                a[key]
                    .as_str()
                    .and_then(open_text)
                    .ok_or_else(|| io(format!("{key} illisible")))
            };
            let field = |key: &str| {
                a[key]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| io(format!("{key} absent")))
            };
            book.entries.push(Entry {
                account: Account {
                    id: field("id")?,
                    name: field("name")?,
                    login: text("login")?,
                },
                password: Some(Secret::new(text("password")?)).filter(|p| !p.expose().is_empty()),
            });
        }
        Ok(book)
    }

    /// Vrai si le compte a un mot de passe ; faux : à ressaisir.
    pub fn has_secret(&self, id: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.account.id == id && e.password.is_some())
    }

    pub fn list(&self) -> Vec<Account> {
        self.entries.iter().map(|e| e.account.clone()).collect()
    }

    pub fn create(
        &mut self,
        name: &str,
        login: &str,
        password: Secret,
    ) -> Result<Account, AccountError> {
        let (name, login) = (name.trim(), login.trim());
        if name.is_empty() || login.is_empty() || password.expose().is_empty() {
            return Err(AccountError::EmptyField);
        }
        if self.name_taken(name, None) {
            return Err(AccountError::DuplicateName);
        }
        let account = Account {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            login: login.to_string(),
        };
        let mut next = self.entries.clone();
        next.push(Entry {
            account: account.clone(),
            password: Some(password),
        });
        self.write(&next)?;
        self.entries = next;
        Ok(account)
    }

    pub fn update(
        &mut self,
        id: &str,
        name: &str,
        login: &str,
        password: Option<Secret>,
    ) -> Result<Account, AccountError> {
        let (name, login) = (name.trim(), login.trim());
        let index = self.index_of(id)?;
        if name.is_empty() || login.is_empty() {
            return Err(AccountError::EmptyField);
        }
        if password.as_ref().is_some_and(|p| p.expose().is_empty()) {
            return Err(AccountError::EmptyField);
        }
        if self.name_taken(name, Some(id)) {
            return Err(AccountError::DuplicateName);
        }
        // Compte sans mot de passe : l'enregistrer sans en fournir un laisserait
        // croire qu'il est réparé.
        if password.is_none() && self.entries[index].password.is_none() {
            return Err(AccountError::SecretMissing);
        }
        let account = Account {
            id: id.to_string(),
            name: name.to_string(),
            login: login.to_string(),
        };
        let mut next = self.entries.clone();
        next[index].account = account.clone();
        if password.is_some() {
            next[index].password = password;
        }
        self.write(&next)?;
        self.entries = next;
        Ok(account)
    }

    pub fn remove(&mut self, id: &str) -> Result<(), AccountError> {
        let index = self.index_of(id)?;
        let mut next = self.entries.clone();
        next.remove(index);
        self.write(&next)?;
        self.entries = next;
        Ok(())
    }

    pub fn credentials(&self, id: &str) -> Result<Credentials, AccountError> {
        let entry = &self.entries[self.index_of(id)?];
        Ok(Credentials {
            login: entry.account.login.clone(),
            password: entry.password.clone().ok_or(AccountError::SecretMissing)?,
        })
    }

    /// Fichier d'export : sans ids, identifiant et mot de passe scellés, sans
    /// `password` pour un compte à ressaisir.
    pub fn export(&self) -> String {
        let accounts: Vec<_> = self
            .entries
            .iter()
            .map(|e| {
                let mut a = serde_json::json!({
                    "name": e.account.name,
                    "login": seal::seal(e.account.login.as_bytes()),
                });
                if let Some(p) = &e.password {
                    a["password"] = seal::seal(p.expose().as_bytes()).into();
                }
                a
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "format": EXPORT_FORMAT,
            "version": 1,
            "accounts": accounts,
        }))
        .expect("json")
    }

    /// Premier temps : ce que l'import ferait, sans rien modifier.
    pub fn import_plan(&self, data: &str) -> Result<ImportPlan, AccountError> {
        let items = parse_import(data)?
            .into_iter()
            .map(|imp| ImportItem {
                kind: match position_of(&self.entries, &imp.name) {
                    None => ImportKind::New,
                    Some(i) => classify(&self.entries[i], &imp),
                },
                name: imp.name,
            })
            .collect();
        Ok(ImportPlan { items })
    }

    /// Second temps : le fichier est relu et le plan recalculé. `choices` est
    /// indexé par nom du fichier ; absent ⇒ `Replace`. Tout ou rien : un
    /// échec d'écriture laisse le carnet intact.
    pub fn import_apply(
        &mut self,
        data: &str,
        choices: &HashMap<String, Choice>,
    ) -> Result<ImportSummary, AccountError> {
        let imports = parse_import(data)?;
        let mut next = self.entries.clone();
        let mut summary = ImportSummary::default();
        for imp in imports {
            let fresh = |name: String, imp: Imported| Entry {
                account: Account {
                    id: uuid::Uuid::new_v4().to_string(),
                    name,
                    login: imp.login,
                },
                password: imp.password,
            };
            let Some(i) = position_of(&next, &imp.name) else {
                next.push(fresh(imp.name.clone(), imp));
                summary.added += 1;
                continue;
            };
            if classify(&next[i], &imp) == ImportKind::Identical {
                summary.identical += 1;
                continue;
            }
            match choices.get(&imp.name).copied().unwrap_or(Choice::Replace) {
                Choice::Replace => {
                    next[i].account.name = imp.name;
                    next[i].account.login = imp.login;
                    if imp.password.is_some() {
                        next[i].password = imp.password;
                    }
                    summary.replaced += 1;
                }
                Choice::KeepBoth => {
                    let name = (2..)
                        .map(|n| format!("{} {n}", imp.name))
                        .find(|candidate| position_of(&next, candidate).is_none())
                        .expect("suffixe libre");
                    next.push(fresh(name, imp));
                    summary.kept_both += 1;
                }
                Choice::Skip => summary.skipped += 1,
            }
        }
        if summary.added + summary.replaced + summary.kept_both > 0 {
            self.write(&next)?;
            self.entries = next;
        }
        Ok(summary)
    }

    fn index_of(&self, id: &str) -> Result<usize, AccountError> {
        self.entries
            .iter()
            .position(|e| e.account.id == id)
            .ok_or(AccountError::NotFound)
    }

    fn name_taken(&self, name: &str, except: Option<&str>) -> bool {
        let wanted = name.to_lowercase();
        self.entries.iter().any(|e| {
            Some(e.account.id.as_str()) != except && e.account.name.to_lowercase() == wanted
        })
    }

    /// Écriture atomique : fichier temporaire voisin puis `rename`. Format 2 :
    /// identifiant et mot de passe scellés (un compte à ressaisir porte un
    /// mot de passe scellé vide).
    fn write(&self, entries: &[Entry]) -> Result<(), AccountError> {
        let io = |e: std::io::Error| AccountError::Io(e.to_string());
        if self.read_only {
            return Err(AccountError::Io("lecture seule".into()));
        }
        let accounts: Vec<_> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.account.id,
                    "name": e.account.name,
                    "login": seal::seal(e.account.login.as_bytes()),
                    "password": seal::seal(e.password.as_ref().map_or("", Secret::expose).as_bytes()),
                })
            })
            .collect();
        let json = serde_json::to_vec_pretty(&serde_json::json!({
            "version": 2,
            "accounts": accounts,
        }))
        .map_err(|e| AccountError::Io(e.to_string()))?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            io(e)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PWD: &str = "S3cr3t-Unique!";

    struct Fixture {
        dir: PathBuf,
        store: Arc<MemoryStore>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("lenscout-accounts-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Fixture {
                dir,
                store: Arc::new(MemoryStore::default()),
            }
        }
        fn path(&self) -> PathBuf {
            self.dir.join("accounts.json")
        }
        fn book(&self) -> AccountBook {
            AccountBook::load(self.path(), self.store.clone()).unwrap()
        }
        fn raw(&self) -> String {
            String::from_utf8(std::fs::read(self.path()).unwrap()).unwrap()
        }
        /// Fichier de l'ancien format : tableau sans `version`, login en clair.
        fn write_v1(&self, accounts: &[(&str, &str, &str)]) {
            let list: Vec<_> = accounts
                .iter()
                .map(
                    |(id, name, login)| serde_json::json!({"id": id, "name": name, "login": login}),
                )
                .collect();
            std::fs::write(self.path(), serde_json::to_vec(&list).unwrap()).unwrap();
        }
    }

    fn pwd(p: &str) -> Secret {
        Secret::new(p.into())
    }

    fn empty_book() -> AccountBook {
        Fixture::new().book()
    }

    #[test]
    fn file_never_contains_login_or_password_in_clear() {
        let fx = Fixture::new();
        let mut book = fx.book();
        book.create("Défaut LORVA", "root-unique", pwd(PWD))
            .unwrap();
        let raw = fx.raw();
        assert!(!raw.contains("S3cr3t"));
        assert!(!raw.contains("root-unique"));
        assert!(raw.contains("Défaut LORVA"));
        assert!(raw.contains("\"version\": 2"));
    }

    #[test]
    fn credentials_after_reload() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("Défaut LORVA", "root", pwd(PWD)).unwrap();
        let creds = fx.book().credentials(&acc.id).unwrap();
        assert_eq!(creds.login, "root");
        assert_eq!(creds.password.expose(), PWD);
        assert!(fx.book().has_secret(&acc.id));
    }

    #[test]
    fn reload_keeps_accounts() {
        let fx = Fixture::new();
        let mut book = fx.book();
        book.create("A", "root", pwd(PWD)).unwrap();
        book.create("B", "admin", pwd(PWD)).unwrap();
        assert_eq!(fx.book().list(), book.list());
        assert_eq!(fx.book().list().len(), 2);
    }

    #[test]
    fn missing_file_is_empty_book() {
        assert!(empty_book().list().is_empty());
    }

    #[test]
    fn duplicate_name_rejected() {
        let fx = Fixture::new();
        let mut book = fx.book();
        book.create("Client X", "root", pwd(PWD)).unwrap();
        let err = book.create("client x", "root", pwd(PWD)).unwrap_err();
        assert!(matches!(err, AccountError::DuplicateName));
        assert_eq!(book.list().len(), 1);
    }

    #[test]
    fn update_rejects_name_of_another_account() {
        let mut book = empty_book();
        book.create("A", "root", pwd(PWD)).unwrap();
        let b = book.create("B", "root", pwd(PWD)).unwrap();
        let err = book.update(&b.id, "a", "root", None).unwrap_err();
        assert!(matches!(err, AccountError::DuplicateName));
        // Garder son propre nom (casse changée) reste permis.
        assert!(book.update(&b.id, "b", "root", None).is_ok());
    }

    #[test]
    fn empty_fields_rejected() {
        let mut book = empty_book();
        assert!(matches!(
            book.create(" ", "root", pwd(PWD)).unwrap_err(),
            AccountError::EmptyField
        ));
        assert!(matches!(
            book.create("A", "", pwd(PWD)).unwrap_err(),
            AccountError::EmptyField
        ));
        assert!(matches!(
            book.create("A", "root", pwd("")).unwrap_err(),
            AccountError::EmptyField
        ));
        assert!(book.list().is_empty());
    }

    #[test]
    fn update_without_password_keeps_secret() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("A", "root", pwd(PWD)).unwrap();
        let upd = book.update(&acc.id, "A2", "admin", None).unwrap();
        assert_eq!((upd.name.as_str(), upd.login.as_str()), ("A2", "admin"));
        assert_eq!(upd.id, acc.id);
        assert_eq!(book.credentials(&acc.id).unwrap().password.expose(), PWD);
        assert_eq!(fx.book().list()[0].name, "A2");
        assert_eq!(
            fx.book().credentials(&acc.id).unwrap().password.expose(),
            PWD
        );
    }

    #[test]
    fn update_with_password_replaces_secret() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("A", "root", pwd(PWD)).unwrap();
        book.update(&acc.id, "A", "root", Some(pwd("Autre-1")))
            .unwrap();
        assert_eq!(
            fx.book().credentials(&acc.id).unwrap().password.expose(),
            "Autre-1"
        );
    }

    #[test]
    fn remove_deletes_account() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("A", "root", pwd(PWD)).unwrap();
        book.remove(&acc.id).unwrap();
        assert!(book.list().is_empty());
        assert!(fx.book().list().is_empty());
        assert!(matches!(book.remove(&acc.id), Err(AccountError::NotFound)));
    }

    #[test]
    fn unknown_id_is_not_found() {
        let mut book = empty_book();
        assert!(matches!(book.credentials("x"), Err(AccountError::NotFound)));
        assert!(matches!(
            book.update("x", "A", "r", None),
            Err(AccountError::NotFound)
        ));
    }

    #[test]
    fn account_debug_has_no_password() {
        let mut book = empty_book();
        let acc = book.create("A", "root", pwd(PWD)).unwrap();
        assert!(!format!("{book:?} {acc:?}").contains("S3cr3t"));
    }

    #[test]
    fn write_failure_leaves_book_unchanged() {
        let fx = Fixture::new();
        // Le chemin du fichier est un dossier : le `rename` final échoue.
        std::fs::create_dir_all(fx.path()).unwrap();
        let mut book = AccountBook::load(fx.dir.join("absent.json"), fx.store.clone()).unwrap();
        book.path = fx.path();
        let err = book.create("A", "root", pwd(PWD)).unwrap_err();
        assert!(matches!(err, AccountError::Io(_)));
        assert!(book.list().is_empty());
    }

    #[test]
    fn corrupt_file_is_quarantined_not_deleted() {
        let fx = Fixture::new();
        std::fs::write(fx.path(), b"{ pas du json").unwrap();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(book.list().is_empty());
        let Startup::Quarantined(moved) = startup else {
            panic!("attendu Quarantined, reçu {startup:?}");
        };
        assert!(!fx.path().exists());
        assert!(
            moved
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("accounts.json.corrupt-")
        );
        assert_eq!(std::fs::read(&moved).unwrap(), b"{ pas du json");
        // Le carnet vide reste utilisable.
        let mut book = book;
        assert!(book.create("A", "root", pwd(PWD)).is_ok());
    }

    #[test]
    fn unsealable_v2_file_is_quarantined() {
        let fx = Fixture::new();
        std::fs::write(
            fx.path(),
            br#"{"version":2,"accounts":[{"id":"1","name":"A","login":"AAAA","password":"AAAA"}]}"#,
        )
        .unwrap();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(book.list().is_empty());
        assert!(matches!(startup, Startup::Quarantined(_)));
    }

    #[test]
    fn absent_file_is_clean_start() {
        let fx = Fixture::new();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(book.list().is_empty());
        assert!(matches!(startup, Startup::Clean));
        assert!(std::fs::read_dir(&fx.dir).unwrap().next().is_none());
    }

    #[test]
    fn valid_file_is_clean_start() {
        let fx = Fixture::new();
        fx.book().create("A", "root", pwd(PWD)).unwrap();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert_eq!(book.list().len(), 1);
        assert!(matches!(startup, Startup::Clean));
    }

    #[cfg(unix)]
    #[test]
    fn failed_rename_gives_unwritable_memory_book() {
        use std::os::unix::fs::PermissionsExt;
        let fx = Fixture::new();
        std::fs::write(fx.path(), b"{ pas du json").unwrap();
        // Dossier en lecture seule : le rename échoue.
        std::fs::set_permissions(&fx.dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let (mut book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        std::fs::set_permissions(&fx.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(startup, Startup::Unwritable));
        assert!(book.list().is_empty());
        let err = book.create("A", "root", pwd(PWD)).unwrap_err();
        assert!(matches!(err, AccountError::Io(_)));
        assert!(book.list().is_empty());
        // Le fichier d'origine n'a pas été touché.
        assert_eq!(std::fs::read(fx.path()).unwrap(), b"{ pas du json");
    }

    // ---- Reprise de l'ancien format ----

    #[test]
    fn migrates_v1_file_from_store() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root-unique")]);
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(matches!(startup, Startup::Clean));
        let creds = book.credentials("id-1").unwrap();
        assert_eq!(
            (creds.login.as_str(), creds.password.expose()),
            ("root-unique", PWD)
        );
        assert!(book.has_secret("id-1"));
        // Le fichier est réécrit en v2, sans rien en clair.
        let raw = fx.raw();
        assert!(raw.contains("\"version\": 2"));
        assert!(!raw.contains("root-unique") && !raw.contains("S3cr3t"));
        // Rechargé sans trousseau : le fichier se suffit.
        let alone = AccountBook::load(fx.path(), Arc::new(MemoryStore::default())).unwrap();
        assert_eq!(alone.credentials("id-1").unwrap().password.expose(), PWD);
    }

    #[test]
    fn migration_missing_secret_keeps_account_needing_password() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root"), ("id-2", "Gare", "admin")]);
        fx.store.set("id-2", &pwd(PWD)).unwrap();
        let (mut book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(matches!(startup, Startup::Clean));
        assert_eq!(book.list().len(), 2);
        assert!(!book.has_secret("id-1"));
        assert!(book.has_secret("id-2"));
        assert!(matches!(
            book.credentials("id-1"),
            Err(AccountError::SecretMissing)
        ));
        assert!(matches!(
            book.update("id-1", "Mairie", "root", None),
            Err(AccountError::SecretMissing)
        ));
        // Ressaisir le mot de passe répare le compte.
        book.update("id-1", "Mairie", "root", Some(pwd("Neuf-1")))
            .unwrap();
        assert_eq!(
            book.credentials("id-1").unwrap().password.expose(),
            "Neuf-1"
        );
        assert_eq!(book.credentials("id-2").unwrap().password.expose(), PWD);
    }

    #[test]
    fn migration_with_missing_secret_does_not_rewrite_file() {
        // Trousseau inaccessible : le fichier d'origine reste tel quel, la
        // reprise sera retentée au lancement suivant.
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        let before = std::fs::read(fx.path()).unwrap();
        let (book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        assert_eq!(book.list().len(), 1);
        assert_eq!(std::fs::read(fx.path()).unwrap(), before);
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        let (book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        assert_eq!(book.credentials("id-1").unwrap().password.expose(), PWD);
        assert!(fx.raw().contains("\"version\": 2"));
    }

    #[test]
    fn migration_keeps_store_entries() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        let _ = load_or_quarantine(fx.path(), fx.store.clone());
        assert_eq!(fx.store.get("id-1").unwrap().expose(), PWD);
    }

    // ---- Export / import ----

    fn sample_book() -> AccountBook {
        let mut book = empty_book();
        book.create("Mairie Arles", "root-unique", pwd(PWD))
            .unwrap();
        book.create("Gare", "admin", pwd("Autre-1")).unwrap();
        book
    }

    #[test]
    fn export_has_no_ids_no_clear_and_no_needs_password() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Sans secret", "root")]);
        let (mut book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        book.create("Mairie Arles", "root-unique", pwd(PWD))
            .unwrap();
        let out = book.export();
        assert!(!out.contains("root-unique") && !out.contains("S3cr3t"));
        assert!(!out.contains("needs_password") && !out.contains("\"id\""));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["format"], "lenscout-accounts");
        assert_eq!(v["version"], 1);
        let accounts = v["accounts"].as_array().unwrap();
        let sans = accounts
            .iter()
            .find(|a| a["name"] == "Sans secret")
            .unwrap();
        assert!(sans.get("password").is_none());
        assert!(sans.get("login").is_some());
    }

    #[test]
    fn export_then_import_on_empty_book_restores_all() {
        let src = sample_book();
        let data = src.export();
        let mut dst = empty_book();
        let plan = dst.import_plan(&data).unwrap();
        assert!(plan.items.iter().all(|i| i.kind == ImportKind::New));
        let summary = dst.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(summary.added, 2);
        let find = |book: &AccountBook, name: &str| {
            let a = book.list().into_iter().find(|a| a.name == name).unwrap();
            book.credentials(&a.id).unwrap()
        };
        let c = find(&dst, "Mairie Arles");
        assert_eq!(
            (c.login.as_str(), c.password.expose()),
            ("root-unique", PWD)
        );
        assert_eq!(find(&dst, "Gare").password.expose(), "Autre-1");
    }

    #[test]
    fn import_survives_a_reload() {
        let fx = Fixture::new();
        let data = sample_book().export();
        fx.book().import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(fx.book().list().len(), 2);
    }

    #[test]
    fn import_identical_is_untouched() {
        let mut book = sample_book();
        let data = book.export();
        let before = book.list();
        let plan = book.import_plan(&data).unwrap();
        assert!(plan.items.iter().all(|i| i.kind == ImportKind::Identical));
        let summary = book.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(
            (summary.added, summary.replaced, summary.identical),
            (0, 0, 2)
        );
        assert_eq!(book.list(), before);
    }

    fn differing() -> (AccountBook, String) {
        let src = sample_book();
        let mut dst = empty_book();
        dst.create("Mairie Arles", "autre-login", pwd(PWD)).unwrap();
        (dst, src.export())
    }

    #[test]
    fn import_plan_reports_what_differs_without_secrets() {
        let (dst, data) = differing();
        let plan = dst.import_plan(&data).unwrap();
        let mairie = plan
            .items
            .iter()
            .find(|i| i.name == "Mairie Arles")
            .unwrap();
        assert_eq!(
            mairie.kind,
            ImportKind::Differs {
                login_differs: true,
                password_differs: false
            }
        );
        let gare = plan.items.iter().find(|i| i.name == "Gare").unwrap();
        assert_eq!(gare.kind, ImportKind::New);
    }

    #[test]
    fn import_differs_default_replace() {
        let (mut dst, data) = differing();
        let id = dst.list()[0].id.clone();
        let summary = dst.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!((summary.added, summary.replaced), (1, 1));
        assert_eq!(dst.list().len(), 2);
        // Remplacé en gardant l'id.
        assert_eq!(dst.credentials(&id).unwrap().login, "root-unique");
    }

    #[test]
    fn import_keep_both_picks_next_free_suffix() {
        let (mut dst, data) = differing();
        dst.create("Mairie Arles 2", "x", pwd("y")).unwrap();
        let choices = HashMap::from([("Mairie Arles".to_string(), Choice::KeepBoth)]);
        let summary = dst.import_apply(&data, &choices).unwrap();
        assert_eq!(summary.kept_both, 1);
        let names: Vec<_> = dst.list().into_iter().map(|a| a.name).collect();
        assert!(names.contains(&"Mairie Arles".to_string()));
        assert!(names.contains(&"Mairie Arles 2".to_string()));
        assert!(names.contains(&"Mairie Arles 3".to_string()));
        let a3 = dst
            .list()
            .into_iter()
            .find(|a| a.name == "Mairie Arles 3")
            .unwrap();
        assert_eq!(dst.credentials(&a3.id).unwrap().login, "root-unique");
        // L'original n'a pas bougé.
        let a1 = dst
            .list()
            .into_iter()
            .find(|a| a.name == "Mairie Arles")
            .unwrap();
        assert_eq!(dst.credentials(&a1.id).unwrap().login, "autre-login");
    }

    #[test]
    fn import_skip_changes_nothing() {
        let (mut dst, data) = differing();
        let choices = HashMap::from([("Mairie Arles".to_string(), Choice::Skip)]);
        let summary = dst.import_apply(&data, &choices).unwrap();
        assert_eq!((summary.skipped, summary.replaced), (1, 0));
        let a = dst
            .list()
            .into_iter()
            .find(|a| a.name == "Mairie Arles")
            .unwrap();
        assert_eq!(dst.credentials(&a.id).unwrap().login, "autre-login");
    }

    #[test]
    fn import_rejects_garbage_and_foreign_json() {
        let mut book = sample_book();
        let before = book.list();
        let bad = [
            "",
            "pas du json",
            "{\"format\":\"lenscout-accounts\",\"version\":1,\"accounts\":[",
            "[]",
            "{\"hello\":1}",
            "{\"format\":\"autre\",\"version\":1,\"accounts\":[]}",
            "{\"format\":\"lenscout-accounts\",\"version\":9,\"accounts\":[]}",
            "{\"format\":\"lenscout-accounts\",\"version\":1,\"accounts\":[{\"name\":\"A\",\"login\":\"AAAA\"}]}",
        ];
        for data in bad {
            assert!(
                matches!(book.import_plan(data), Err(AccountError::ImportInvalid)),
                "{data}"
            );
            assert!(
                matches!(
                    book.import_apply(data, &HashMap::new()),
                    Err(AccountError::ImportInvalid)
                ),
                "{data}"
            );
        }
        // Tronqué.
        let good = sample_book().export();
        let cut = &good[..good.len() / 2];
        assert!(matches!(
            book.import_apply(cut, &HashMap::new()),
            Err(AccountError::ImportInvalid)
        ));
        assert_eq!(book.list(), before);
    }

    #[test]
    fn import_without_password_keeps_existing_password() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Sans secret", "root")]);
        let (nopass, _) = load_or_quarantine(fx.path(), fx.store.clone());
        let data = nopass.export();
        let mut dst = empty_book();
        dst.create("Sans secret", "root", pwd(PWD)).unwrap();
        let plan = dst.import_plan(&data).unwrap();
        assert_eq!(plan.items[0].kind, ImportKind::Identical);
        // Sur un carnet vide : ajouté, à ressaisir.
        let mut empty = empty_book();
        empty.import_apply(&data, &HashMap::new()).unwrap();
        assert!(!empty.has_secret(&empty.list()[0].id));
    }

    #[test]
    fn import_apply_is_atomic_on_write_failure() {
        let fx = Fixture::new();
        std::fs::create_dir_all(fx.path()).unwrap();
        let mut book = AccountBook::load(fx.dir.join("absent.json"), fx.store.clone()).unwrap();
        book.path = fx.path();
        let data = sample_book().export();
        assert!(matches!(
            book.import_apply(&data, &HashMap::new()),
            Err(AccountError::Io(_))
        ));
        assert!(book.list().is_empty());
    }
}
