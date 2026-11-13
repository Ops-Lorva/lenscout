use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::secret::Secret;
use crate::transport::Credentials;

/// Métadonnées d'un compte. Le mot de passe n'y figure pas : il vit dans le
/// trousseau du système, sous l'identifiant du compte.
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
    #[error("nom déjà utilisé")]
    DuplicateName,
    #[error("champ vide")]
    EmptyField,
    // Message de l'OS, jamais le mot de passe.
    #[error("trousseau : {0}")]
    Keyring(String),
    #[error("fichier : {0}")]
    Io(String),
}

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

pub struct AccountBook {
    path: PathBuf,
    accounts: Vec<Account>,
    store: Arc<dyn SecretStore>,
}

impl fmt::Debug for AccountBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountBook")
            .field("path", &self.path)
            .field("accounts", &self.accounts)
            .finish_non_exhaustive()
    }
}

impl AccountBook {
    pub fn load(path: PathBuf, store: Arc<dyn SecretStore>) -> Result<Self, AccountError> {
        let accounts = match std::fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|e| AccountError::Io(e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(AccountError::Io(e.to_string())),
        };
        Ok(AccountBook {
            path,
            accounts,
            store,
        })
    }

    pub fn list(&self) -> Vec<Account> {
        self.accounts.clone()
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
        // Le secret d'abord : un JSON ne doit jamais désigner un compte sans mot de passe.
        self.store.set(&account.id, &password)?;
        let mut next = self.accounts.clone();
        next.push(account.clone());
        if let Err(e) = self.write(&next) {
            let _ = self.store.delete(&account.id);
            return Err(e);
        }
        self.accounts = next;
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
        let account = Account {
            id: id.to_string(),
            name: name.to_string(),
            login: login.to_string(),
        };
        // Ancien secret gardé pour le rétablir si l'écriture du JSON échoue.
        let previous = match &password {
            Some(new) => {
                let old = self.store.get(id).ok();
                self.store.set(id, new)?;
                old
            }
            None => None,
        };
        let mut next = self.accounts.clone();
        next[index] = account.clone();
        if let Err(e) = self.write(&next) {
            if let Some(old) = previous {
                let _ = self.store.set(id, &old);
            }
            return Err(e);
        }
        self.accounts = next;
        Ok(account)
    }

    pub fn remove(&mut self, id: &str) -> Result<(), AccountError> {
        let index = self.index_of(id)?;
        let mut next = self.accounts.clone();
        next.remove(index);
        self.write(&next)?;
        self.accounts = next;
        // Un secret déjà absent du trousseau n'est pas une erreur.
        match self.store.delete(id) {
            Ok(()) | Err(AccountError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn credentials(&self, id: &str) -> Result<Credentials, AccountError> {
        let index = self.index_of(id)?;
        Ok(Credentials {
            login: self.accounts[index].login.clone(),
            password: self.store.get(id)?,
        })
    }

    fn index_of(&self, id: &str) -> Result<usize, AccountError> {
        self.accounts
            .iter()
            .position(|a| a.id == id)
            .ok_or(AccountError::NotFound)
    }

    fn name_taken(&self, name: &str, except: Option<&str>) -> bool {
        let wanted = name.to_lowercase();
        self.accounts
            .iter()
            .any(|a| Some(a.id.as_str()) != except && a.name.to_lowercase() == wanted)
    }

    /// Écriture atomique : fichier temporaire voisin puis `rename`.
    fn write(&self, accounts: &[Account]) -> Result<(), AccountError> {
        let io = |e: std::io::Error| AccountError::Io(e.to_string());
        let json =
            serde_json::to_vec_pretty(accounts).map_err(|e| AccountError::Io(e.to_string()))?;
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
    }

    #[test]
    fn json_never_contains_password() {
        let fx = Fixture::new();
        let mut book = fx.book();
        book.create("Défaut LORVA", "root", Secret::new(PWD.into()))
            .unwrap();
        let raw = String::from_utf8(std::fs::read(fx.path()).unwrap()).unwrap();
        assert!(!raw.contains("S3cr3t"));
        assert!(raw.contains("root"));
    }

    #[test]
    fn credentials_come_from_store() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book
            .create("Défaut LORVA", "root", Secret::new(PWD.into()))
            .unwrap();
        let creds = book.credentials(&acc.id).unwrap();
        assert_eq!(creds.login, "root");
        assert_eq!(creds.password.expose(), PWD);
    }

    #[test]
    fn reload_keeps_accounts() {
        let fx = Fixture::new();
        let mut book = fx.book();
        book.create("A", "root", Secret::new(PWD.into())).unwrap();
        book.create("B", "admin", Secret::new(PWD.into())).unwrap();
        assert_eq!(fx.book().list(), book.list());
        assert_eq!(fx.book().list().len(), 2);
    }

    #[test]
    fn missing_file_is_empty_book() {
        assert!(Fixture::new().book().list().is_empty());
    }

    #[test]
    fn duplicate_name_rejected() {
        let fx = Fixture::new();
        let mut book = fx.book();
        book.create("Client X", "root", Secret::new(PWD.into()))
            .unwrap();
        let err = book
            .create("client x", "root", Secret::new(PWD.into()))
            .unwrap_err();
        assert!(matches!(err, AccountError::DuplicateName));
        assert_eq!(book.list().len(), 1);
    }

    #[test]
    fn update_rejects_name_of_another_account() {
        let fx = Fixture::new();
        let mut book = fx.book();
        book.create("A", "root", Secret::new(PWD.into())).unwrap();
        let b = book.create("B", "root", Secret::new(PWD.into())).unwrap();
        let err = book.update(&b.id, "a", "root", None).unwrap_err();
        assert!(matches!(err, AccountError::DuplicateName));
        // Garder son propre nom (casse changée) reste permis.
        assert!(book.update(&b.id, "b", "root", None).is_ok());
    }

    #[test]
    fn empty_fields_rejected() {
        let fx = Fixture::new();
        let mut book = fx.book();
        assert!(matches!(
            book.create(" ", "root", Secret::new(PWD.into()))
                .unwrap_err(),
            AccountError::EmptyField
        ));
        assert!(matches!(
            book.create("A", "", Secret::new(PWD.into())).unwrap_err(),
            AccountError::EmptyField
        ));
        assert!(matches!(
            book.create("A", "root", Secret::new(String::new()))
                .unwrap_err(),
            AccountError::EmptyField
        ));
        assert!(book.list().is_empty());
    }

    #[test]
    fn update_without_password_keeps_secret() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("A", "root", Secret::new(PWD.into())).unwrap();
        let upd = book.update(&acc.id, "A2", "admin", None).unwrap();
        assert_eq!((upd.name.as_str(), upd.login.as_str()), ("A2", "admin"));
        assert_eq!(upd.id, acc.id);
        assert_eq!(book.credentials(&acc.id).unwrap().password.expose(), PWD);
        assert_eq!(fx.book().list()[0].name, "A2");
    }

    #[test]
    fn update_with_password_replaces_secret() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("A", "root", Secret::new(PWD.into())).unwrap();
        book.update(&acc.id, "A", "root", Some(Secret::new("Autre-1".into())))
            .unwrap();
        assert_eq!(
            book.credentials(&acc.id).unwrap().password.expose(),
            "Autre-1"
        );
    }

    #[test]
    fn remove_deletes_secret() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("A", "root", Secret::new(PWD.into())).unwrap();
        book.remove(&acc.id).unwrap();
        assert!(matches!(fx.store.get(&acc.id), Err(AccountError::NotFound)));
        assert!(book.list().is_empty());
        assert!(fx.book().list().is_empty());
        assert!(matches!(book.remove(&acc.id), Err(AccountError::NotFound)));
    }

    #[test]
    fn unknown_id_is_not_found() {
        let fx = Fixture::new();
        let mut book = fx.book();
        assert!(matches!(book.credentials("x"), Err(AccountError::NotFound)));
        assert!(matches!(
            book.update("x", "A", "r", None),
            Err(AccountError::NotFound)
        ));
    }

    #[test]
    fn account_debug_has_no_password() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("A", "root", Secret::new(PWD.into())).unwrap();
        assert!(!format!("{book:?} {acc:?}").contains("S3cr3t"));
    }

    // Le JSON ne doit pas rester en place si le trousseau échoue, ni l'inverse.
    struct FailingStore;
    impl SecretStore for FailingStore {
        fn set(&self, _: &str, _: &Secret) -> Result<(), AccountError> {
            Err(AccountError::Keyring("verrouillé".into()))
        }
        fn get(&self, _: &str) -> Result<Secret, AccountError> {
            Err(AccountError::NotFound)
        }
        fn delete(&self, _: &str) -> Result<(), AccountError> {
            Ok(())
        }
    }

    #[test]
    fn keyring_failure_leaves_no_json_entry() {
        let fx = Fixture::new();
        let mut book = AccountBook::load(fx.path(), Arc::new(FailingStore)).unwrap();
        let err = book
            .create("A", "root", Secret::new(PWD.into()))
            .unwrap_err();
        assert!(matches!(err, AccountError::Keyring(_)));
        assert!(book.list().is_empty());
        assert!(!fx.path().exists());
    }

    #[test]
    fn json_failure_removes_secret() {
        let fx = Fixture::new();
        // Le chemin du fichier est un dossier : le `rename` final échoue.
        std::fs::create_dir_all(fx.path()).unwrap();
        let mut book = AccountBook::load(fx.dir.join("absent.json"), fx.store.clone()).unwrap();
        book.path = fx.path();
        let err = book
            .create("A", "root", Secret::new(PWD.into()))
            .unwrap_err();
        assert!(matches!(err, AccountError::Io(_)));
        assert!(book.list().is_empty());
        assert!(fx.store.secrets.lock().unwrap().is_empty());
    }
}
