use crate::updater::{self, UpdateInfo};

#[tauri::command]
pub async fn cmd_check_update() -> Result<UpdateInfo, String> {
    updater::check_update_impl().await
}

/// `url` vient du front : `apply_update_impl` la refuse hors de GitHub
/// Releases et vérifie la signature minisign avant d'écrire ou de lancer.
#[tauri::command]
pub async fn cmd_apply_update(url: String, asset_name: String) -> Result<String, String> {
    updater::apply_update_impl(url, asset_name).await
}
