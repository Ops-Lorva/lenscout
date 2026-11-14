use lenscout_core::interfaces::{get_interface_details, list_interfaces_up, InterfaceDetails};
use tauri::Manager;

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

/// Journal de diagnostic actif ? Lu depuis l'état en mémoire, pas depuis le
/// fichier : `LENSCOUT_DEBUG=1` l'allume sans fichier.
#[tauri::command]
pub fn cmd_debug_get() -> bool {
    lenscout_core::debug_log::capture_dir().is_some()
}

/// Pose ou retire le fichier `debug` dans `app_data_dir`, puis allume ou
/// éteint le journal sur-le-champ : pas besoin de relancer.
#[tauri::command]
pub fn cmd_debug_set(app: tauri::AppHandle, on: bool) -> Result<(), String> {
    let data_dir = app.path().app_data_dir().map_err(|_| "internal".to_string())?;
    lenscout_core::debug_log::set_switch(&data_dir, on).map_err(|_| "internal".to_string())?;
    if on {
        lenscout_core::debug_log::install(&data_dir);
    } else {
        lenscout_core::debug_log::uninstall();
    }
    Ok(())
}
