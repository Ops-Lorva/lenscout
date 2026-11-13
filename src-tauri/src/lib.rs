mod commands;

use commands::accounts::{
    StartupNotice, cmd_account_create, cmd_account_remove, cmd_account_update, cmd_accounts_list,
    cmd_accounts_startup, startup_code,
};
use commands::configure::{TempIpJournal, cmd_apply_action};
use commands::stream::{StreamState, cmd_stream_ack, cmd_stream_start, cmd_stream_stop};
use commands::app::{cmd_app_version, cmd_interface_details, cmd_list_interfaces};
use commands::discovery::{ScanState, cmd_open_camera_web, cmd_scan_cancel, cmd_scan_start};
use lenscout_core::accounts::{KeyringStore, load_or_quarantine};
use lenscout_core::temp_ip::{SystemElevator, cleanup_leftover};
use std::sync::{Arc, Mutex};
use tauri::{Manager, RunEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(ScanState::default())
        .manage(StreamState::default())
        .setup(|app| {
            // Un accounts.json illisible est mis de côté, jamais écrasé ni bloquant.
            let path = app.path().app_config_dir()?.join("accounts.json");
            let (book, startup) = load_or_quarantine(path, Arc::new(KeyringStore));
            app.manage(StartupNotice(Mutex::new(startup_code(&startup))));
            app.manage(Mutex::new(book));
            // IP temporaire laissée par une session tuée : retirée avant toute
            // action. Un échec est journalisé et n'empêche pas le démarrage ;
            // le journal reste pour la prochaine fois.
            let journal = app.path().app_data_dir()?.join("temp-ip.json");
            if let Err(e) = cleanup_leftover(&SystemElevator, &journal) {
                eprintln!("Lenscout : IP temporaire non retirée au démarrage : {e}");
            }
            app.manage(TempIpJournal(journal));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            cmd_app_version,
            cmd_list_interfaces,
            cmd_interface_details,
            cmd_scan_start,
            cmd_scan_cancel,
            cmd_open_camera_web,
            cmd_accounts_list,
            cmd_accounts_startup,
            cmd_account_create,
            cmd_account_update,
            cmd_account_remove,
            cmd_apply_action,
            cmd_stream_start,
            cmd_stream_stop,
            cmd_stream_ack,
        ])
        .build(tauri::generate_context!())
        .expect("erreur au lancement de Lenscout")
        .run(|app, event| {
            // Filet de sortie : une IP temporaire encore journalisée est
            // retirée avant de quitter. Verrou tenu (action en cours, autre
            // instance) : rien n'est fait, le démarrage suivant s'en charge.
            if let RunEvent::Exit = event
                && let Some(journal) = app.try_state::<TempIpJournal>()
                && let Err(e) = cleanup_leftover(&SystemElevator, &journal.0)
            {
                eprintln!("Lenscout : IP temporaire non retirée à la sortie : {e}");
            }
        });
}
