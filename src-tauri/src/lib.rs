mod commands;

use commands::app::{cmd_app_version, cmd_interface_details, cmd_list_interfaces};
use commands::discovery::{cmd_open_camera_web, cmd_scan_cancel, cmd_scan_start, ScanState};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(ScanState::default())
        .invoke_handler(tauri::generate_handler![
            cmd_app_version,
            cmd_list_interfaces,
            cmd_interface_details,
            cmd_scan_start,
            cmd_scan_cancel,
            cmd_open_camera_web,
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de Lenscout");
}
