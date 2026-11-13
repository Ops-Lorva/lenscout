mod commands;

use commands::app::{cmd_app_version, cmd_interface_details, cmd_list_interfaces};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            cmd_app_version,
            cmd_list_interfaces,
            cmd_interface_details,
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de Lenscout");
}
