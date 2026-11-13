mod commands;

use commands::accounts::{
    StartupNotice, cmd_account_create, cmd_account_remove, cmd_account_update, cmd_accounts_list,
    cmd_accounts_startup, startup_code,
};
use commands::configure::cmd_apply_action;
use commands::stream::{StreamState, cmd_stream_ack, cmd_stream_start, cmd_stream_stop};
use commands::app::{cmd_app_version, cmd_interface_details, cmd_list_interfaces};
use commands::discovery::{ScanState, cmd_open_camera_web, cmd_scan_cancel, cmd_scan_start};
use lenscout_core::accounts::{KeyringStore, load_or_quarantine};
use std::sync::{Arc, Mutex};
use tauri::Manager;

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
        .run(tauri::generate_context!())
        .expect("erreur au lancement de Lenscout");
}
