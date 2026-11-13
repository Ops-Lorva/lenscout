use std::sync::Mutex;

use lenscout_core::accounts::{Account, AccountBook, AccountError};
use lenscout_core::secret::Secret;
use lenscout_core::transport::Credentials;
use tauri::State;

/// Erreurs : codes stables (`empty_field`, `duplicate_name`, `not_found`,
/// `secret_missing`, `keyring`, `io`), traduits par le front. Le message de
/// l'OS n'est pas renvoyé.
fn code(e: AccountError) -> String {
    match e {
        AccountError::EmptyField => "empty_field",
        AccountError::DuplicateName => "duplicate_name",
        AccountError::NotFound => "not_found",
        AccountError::SecretMissing => "secret_missing",
        AccountError::Keyring(_) => "keyring",
        AccountError::Io(_) => "io",
    }
    .to_string()
}

fn lock(state: &Mutex<AccountBook>) -> Result<std::sync::MutexGuard<'_, AccountBook>, String> {
    state.lock().map_err(|_| "internal".to_string())
}

// Les fonctions pures portent la logique ; les commandes ne font que
// verrouiller l'état. Aucune ne renvoie de mot de passe.

pub(crate) fn accounts_list(book: &AccountBook) -> Vec<Account> {
    book.list()
}

pub(crate) fn account_create(
    book: &mut AccountBook,
    name: &str,
    login: &str,
    password: Secret,
) -> Result<Account, String> {
    book.create(name, login, password).map_err(code)
}

pub(crate) fn account_update(
    book: &mut AccountBook,
    id: &str,
    name: &str,
    login: &str,
    password: Option<Secret>,
) -> Result<Account, String> {
    book.update(id, name, login, password).map_err(code)
}

pub(crate) fn account_remove(book: &mut AccountBook, id: &str) -> Result<(), String> {
    book.remove(id).map_err(code)
}

/// Identifiants d'un compte pour les commandes authentifiées (cadrage,
/// configuration) : le mot de passe reste côté Rust.
#[allow(dead_code)] // premier appelant : tâche 11
pub(crate) fn credentials_for(state: &Mutex<AccountBook>, id: &str) -> Result<Credentials, String> {
    lock(state)?.credentials(id).map_err(code)
}

// `async` : le trousseau peut bloquer (D-Bus, invite de l'OS), ce qui ne doit
// pas geler le thread principal.

#[tauri::command]
pub async fn cmd_accounts_list(
    state: State<'_, Mutex<AccountBook>>,
) -> Result<Vec<Account>, String> {
    let book = lock(&state)?;
    Ok(accounts_list(&book))
}

#[tauri::command]
pub async fn cmd_account_create(
    name: String,
    login: String,
    password: Secret,
    state: State<'_, Mutex<AccountBook>>,
) -> Result<Account, String> {
    let mut book = lock(&state)?;
    account_create(&mut book, &name, &login, password)
}

#[tauri::command]
pub async fn cmd_account_update(
    id: String,
    name: String,
    login: String,
    password: Option<Secret>,
    state: State<'_, Mutex<AccountBook>>,
) -> Result<Account, String> {
    let mut book = lock(&state)?;
    account_update(&mut book, &id, &name, &login, password)
}

#[tauri::command]
pub async fn cmd_account_remove(
    id: String,
    state: State<'_, Mutex<AccountBook>>,
) -> Result<(), String> {
    let mut book = lock(&state)?;
    account_remove(&mut book, &id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenscout_core::accounts::MemoryStore;
    use std::sync::Arc;

    fn book() -> AccountBook {
        let path = std::env::temp_dir()
            .join(format!("lenscout-cmd-accounts-{}", uuid_like()))
            .join("accounts.json");
        AccountBook::load(path, Arc::new(MemoryStore::default())).unwrap()
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
        let mut book = book();
        account_create(
            &mut book,
            "Défaut LORVA",
            "root",
            Secret::new("S3cr3t-Unique!".into()),
        )
        .unwrap();
        let json = serde_json::to_string(&accounts_list(&book)).unwrap();
        assert!(!json.contains("S3cr3t"));
        assert!(json.contains("Défaut LORVA"));
    }

    #[test]
    fn errors_are_stable_codes() {
        let mut book = book();
        let pwd = || Secret::new("x".into());
        assert_eq!(
            account_create(&mut book, " ", "r", pwd()).unwrap_err(),
            "empty_field"
        );
        account_create(&mut book, "A", "r", pwd()).unwrap();
        assert_eq!(
            account_create(&mut book, "a", "r", pwd()).unwrap_err(),
            "duplicate_name"
        );
        assert_eq!(account_remove(&mut book, "nope").unwrap_err(), "not_found");
    }

    #[test]
    fn missing_secret_has_its_own_code() {
        let store = Arc::new(MemoryStore::default());
        let path = std::env::temp_dir()
            .join(format!("lenscout-cmd-accounts-{}", uuid_like()))
            .join("accounts.json");
        let mut book = AccountBook::load(path.clone(), store).unwrap();
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into())).unwrap();
        // Même fichier, autre trousseau : le cas d'un accounts.json copié ailleurs.
        let other = Mutex::new(AccountBook::load(path, Arc::new(MemoryStore::default())).unwrap());
        assert_eq!(
            credentials_for(&other, &acc.id).unwrap_err(),
            "secret_missing"
        );
        assert_eq!(credentials_for(&other, "nope").unwrap_err(), "not_found");
    }

    #[test]
    fn update_without_password_keeps_it() {
        let mut book = book();
        let acc = account_create(&mut book, "A", "r", Secret::new("x".into())).unwrap();
        let upd = account_update(&mut book, &acc.id, "B", "r2", None).unwrap();
        assert_eq!((upd.name.as_str(), upd.login.as_str()), ("B", "r2"));
        assert_eq!(book.credentials(&acc.id).unwrap().password.expose(), "x");
    }
}
