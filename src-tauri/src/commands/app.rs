use lenscout_core::interfaces::{get_interface_details, list_interfaces_up, InterfaceDetails};

#[tauri::command]
pub fn cmd_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Seulement les liens actifs : voir `list_interfaces_up`.
#[tauri::command]
pub async fn cmd_list_interfaces() -> Vec<String> {
    tauri::async_runtime::spawn_blocking(list_interfaces_up)
        .await
        .unwrap_or_default()
}

#[tauri::command]
pub async fn cmd_interface_details(name: String) -> InterfaceDetails {
    tauri::async_runtime::spawn_blocking(move || get_interface_details(&name))
        .await
        .unwrap_or_default()
}
