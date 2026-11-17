//! Test de login : commande Tauri, résultats en flux et annulation.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lenscout_core::accounts::AccountBook;
use lenscout_core::http_client::ReqwestCameraHttp;
use lenscout_core::login_test::{DenialLog, LoginGuard, LoginResult, run_login_test};
use lenscout_core::model::Camera;
use serde::Serialize;
use tauri::State;
use tauri::ipc::Channel;
use tokio_util::sync::CancellationToken;

use super::accounts::credentials_for;
use super::configure::{TempIpJournal, build_context};
use super::discovery::ScanState;
use super::join::JoinState;

/// Délai d'une requête du test : une caméra muette ne retient pas le passage.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(3);
/// Caméras testées en même temps.
const LOGIN_PARALLEL: usize = 16;
/// Au-delà de 2 refus en 30 min, une caméra n'est plus essayée : Hikvision
/// verrouille après 5 à 7 échecs (30 min) et Cadrage / Opérations consomment
/// aussi des essais. Vu sur DS-2CD2132F-IWS (17/11/2026) : verrouillage actif,
/// nombre d'essais non réglable (`/ISAPI/Security/illegalLoginLock` ne rend
/// que `<enabled>`), donc le seuil fixe du firmware. LTS non vérifiée.
const LOGIN_GUARD: LoginGuard = LoginGuard { max_denials: 2, window: Duration::from_secs(30 * 60) };

/// Le test en cours (un seul, remplacé au démarrage du suivant) et les refus
/// de la session, partagés entre passages.
#[derive(Default)]
pub struct LoginTestState {
    runs: Mutex<Runs>,
    denials: Mutex<DenialLog>,
}

#[derive(Default)]
struct Runs {
    current: Option<(u64, CancellationToken)>,
    /// Annulations reçues avant le démarrage de leur passage.
    early: HashSet<u64>,
}

/// Plus d'annulations en avance que cela : le front n'en produit pas autant.
const MAX_EARLY: usize = 64;

// Même mécanisme que `FreeIpsState` (commands/free_ips.rs).
impl LoginTestState {
    /// Le jeton du passage `id` (déjà annulé s'il l'a été avant de démarrer) ;
    /// le passage précédent est annulé.
    fn begin(&self, id: u64) -> CancellationToken {
        let mut runs = self.runs.lock().unwrap_or_else(|e| e.into_inner());
        let token = CancellationToken::new();
        if runs.early.remove(&id) {
            token.cancel();
        }
        if let Some((_, old)) = runs.current.replace((id, token.clone())) {
            old.cancel();
        }
        token
    }

    /// Annule le passage `id` ; un autre passage n'est pas touché.
    fn cancel(&self, id: u64) {
        let mut runs = self.runs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cur, token)) = &runs.current
            && *cur == id
        {
            token.cancel();
            runs.current = None;
        } else {
            if runs.early.len() >= MAX_EARLY {
                runs.early.clear();
            }
            runs.early.insert(id);
        }
    }
}

/// Miroir côté front : `src/lib/api/loginTest.ts`.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoginEvent {
    Result(LoginResult),
    Done { cancelled: bool },
}

fn check_selection(cameras: &[Camera]) -> Result<(), String> {
    if cameras.is_empty() { Err("no_cameras".to_string()) } else { Ok(()) }
}

/// Erreurs : codes stables (`no_cameras`, `not_found`, `secret_missing`,
/// `iface_unknown`, `iface_no_ipv4`, `internal`), traduits par le front.
///
/// Essaie le compte sur chaque caméra reçue, en lecture seule, et envoie un
/// `Result` par caméra dès qu'il est connu, puis `Done`. Le front visible ou
/// pas : un `Channel` fermé annule le passage.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_login_test(
    id: u64,
    cameras: Vec<Camera>,
    account_id: String,
    iface: String,
    channel: Channel<LoginEvent>,
    state: State<'_, LoginTestState>,
    scan: State<'_, ScanState>,
    journal: State<'_, TempIpJournal>,
    join: State<'_, JoinState>,
    accounts: State<'_, Mutex<AccountBook>>,
) -> Result<(), String> {
    check_selection(&cameras)?;
    let token = state.begin(id);
    let creds = credentials_for(&accounts, &account_id)?;
    let mut ctx = build_context(iface, &cameras, &scan, &journal.0, &join).await?;
    ctx.http = Arc::new(ReqwestCameraHttp::new(LOGIN_TIMEOUT));
    let stop = token.clone();
    let cancelled = run_login_test(&ctx, &cameras, &creds, LOGIN_PARALLEL, &state.denials, LOGIN_GUARD, token, |r| {
        if channel.send(LoginEvent::Result(r)).is_err() {
            stop.cancel();
        }
    })
    .await;
    let _ = channel.send(LoginEvent::Done { cancelled });
    Ok(())
}

#[tauri::command]
pub fn cmd_login_test_cancel(id: u64, state: State<'_, LoginTestState>) {
    state.cancel(id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenscout_core::login_test::LoginOutcome;

    #[test]
    fn events_serialize_as_the_front_reads_them() {
        let r = LoginEvent::Result(LoginResult {
            index: 0,
            key: "AC:CC:8E:12:34:56".into(),
            ip: "10.0.50.11".parse().unwrap(),
            outcome: LoginOutcome::Ok,
        });
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"kind":"result","index":0,"key":"AC:CC:8E:12:34:56","ip":"10.0.50.11","code":"ok"}"#
        );
        assert_eq!(serde_json::to_string(&LoginEvent::Done { cancelled: false }).unwrap(), r#"{"kind":"done","cancelled":false}"#);
    }

    #[test]
    fn cancel_before_start_is_kept() {
        let state = LoginTestState::default();
        state.cancel(7);
        assert!(state.begin(7).is_cancelled(), "le passage démarre déjà annulé");
        assert!(!state.begin(8).is_cancelled(), "et l'annulation ne vaut que pour lui");
        let a = state.begin(9);
        state.cancel(10);
        assert!(!a.is_cancelled());
        state.cancel(9);
        assert!(a.is_cancelled());
    }

    #[test]
    fn new_run_cancels_the_previous() {
        let state = LoginTestState::default();
        let a = state.begin(1);
        let b = state.begin(2);
        assert!(a.is_cancelled() && !b.is_cancelled());
    }

    #[test]
    fn empty_selection_is_no_cameras() {
        assert_eq!(check_selection(&[]), Err("no_cameras".to_string()));
    }
}
