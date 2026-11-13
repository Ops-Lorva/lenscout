use lenscout_core::interfaces::{get_interface_details, list_interfaces_up, InterfaceDetails};

#[tauri::command]
pub fn cmd_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Seulement les liens actifs : voir `list_interfaces_up`.
#[tauri::command]
pub async fn cmd_list_interfaces() -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(list_interfaces_up)
        .await
        .map_err(|_| "internal".to_string())
}

/// Un nom qui ne figure pas dans `list_interfaces_up()` est refusé : il
/// atteint des commandes système, il ne vient donc jamais tel quel du front.
#[tauri::command]
pub async fn cmd_interface_details(name: String) -> Result<InterfaceDetails, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if !list_interfaces_up().contains(&name) {
            return Err("iface_unknown".to_string());
        }
        Ok(get_interface_details(&name))
    })
    .await
    .map_err(|_| "internal".to_string())?
}
