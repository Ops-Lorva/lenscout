mod commands;

use commands::accounts::{
    cmd_account_create, cmd_account_remove, cmd_account_update, cmd_accounts_list,
};
use commands::app::{cmd_app_version, cmd_interface_details, cmd_list_interfaces};
use commands::discovery::{ScanState, cmd_open_camera_web, cmd_scan_cancel, cmd_scan_start};
use lenscout_core::accounts::{AccountBook, KeyringStore};
use std::sync::{Arc, Mutex};
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(ScanState::default())
        .setup(|app| {
            // Un accounts.json illisible arrête le démarrage plutôt que d'être
            // écrasé par un carnet vide au premier enregistrement.
            let path = app.path().app_config_dir()?.join("accounts.json");
            let book = AccountBook::load(path, Arc::new(KeyringStore))?;
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
            cmd_account_create,
            cmd_account_update,
            cmd_account_remove,
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de Lenscout");
}
