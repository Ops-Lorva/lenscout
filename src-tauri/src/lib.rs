mod commands;
mod updater;

use commands::accounts::{
    StartupNotice, absorb_old_accounts, cmd_account_cameras, cmd_account_create, cmd_account_devices, cmd_account_forget_device, cmd_account_forget_all_devices, cmd_account_fill, cmd_account_release, cmd_account_reservations, cmd_account_reserve, cmd_account_forget_camera, cmd_account_password, cmd_account_remove, cmd_accounts_export, cmd_accounts_import_apply,
    cmd_accounts_import_plan, cmd_account_update, cmd_accounts_list,
    cmd_accounts_startup, notice_code,
};
use commands::configure::{PreviewStore, TempIpJournal, cmd_apply_action, cmd_batch_apply, cmd_batch_preview};
use commands::report::{cmd_save_report, cmd_save_xlsx};
use commands::login_test::{LoginTestState, cmd_login_test, cmd_login_test_cancel};
use commands::site_survey::{SiteSurveyState, cmd_site_survey, cmd_site_survey_cancel};
use commands::ops::{OpsStore, cmd_ops_close, cmd_ops_creds_step, cmd_ops_preview, cmd_ops_step};
use commands::stream::{StreamState, cmd_identify_camera, cmd_stream_ack, cmd_stream_start, cmd_stream_stop, cmd_stream_views};
use commands::update::{cmd_apply_update, cmd_check_update};
use commands::app::{cmd_app_version, cmd_debug_get, cmd_debug_set, cmd_interface_details, cmd_list_interfaces};
use commands::imaging::{cmd_image_settings, cmd_optics, cmd_set_bdc, cmd_set_rotation};
use commands::free_ips::{FreeIpsState, cmd_free_ips, cmd_free_ips_cancel};
use commands::join::{JoinState, cmd_join_network, cmd_join_ready, cmd_joined_network, cmd_leave_network};
use commands::discovery::{ScanState, cmd_open_camera_web, cmd_read_addressing, cmd_read_link_local, cmd_scan_cancel, cmd_scan_start};
use lenscout_core::accounts::load_or_quarantine;
use lenscout_core::permissions::set_data_dir;
use lenscout_core::temp_ip::{SystemElevator, cleanup_before_exit, cleanup_leftover};
use std::time::Duration;
use std::sync::Mutex;
use tauri::{Manager, RunEvent};

/// Attente maximale, à la sortie, d'une IP temporaire en cours de retrait.
const EXIT_WAIT: Duration = Duration::from_secs(10);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Nouvel identifiant : les dossiers de l'ancien sont recopiés AVANT tout
    // chargement (comptes, IP temporaire d'une session tuée) et avant que le
    // webview ouvre son profil. L'ancien reste en place. Un échec est
    // réessayé au prochain lancement et annoncé à l'écran des comptes.
    let failed = lenscout_core::migrate::migrate_identifier();
    for (dir, e) in &failed {
        eprintln!("Lenscout : {} non repris : {e}", dir.display());
    }
    let mut migration_incomplete = !failed.is_empty();
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanState::default())
        .manage(StreamState::default())
        .manage(FreeIpsState::default())
        .manage(LoginTestState::default())
        .manage(SiteSurveyState::default())
        .manage(PreviewStore::default())
        .manage(OpsStore::default())
        .manage(JoinState::default())
        .setup(move |app| {
            // Installeurs laissés par une mise à jour précédente.
            updater::cleanup_old_updates();
            // Un accounts.json illisible est mis de côté, jamais écrasé ni bloquant.
            let config_dir = app.path().app_config_dir()?;
            let (mut book, startup) = load_or_quarantine(config_dir.join("accounts.json"));
            // Reprise d'une migration : les comptes de l'ancien carnet, posés à côté.
            let aside = config_dir.join(lenscout_core::migrate::set_aside_name("accounts.json"));
            migration_incomplete |= !absorb_old_accounts(&mut book, &aside);
            app.manage(StartupNotice(Mutex::new(notice_code(&startup, migration_incomplete))));
            app.manage(Mutex::new(book));
            // IP temporaire laissée par une session tuée : retirée avant toute
            // action. Un échec est journalisé et n'empêche pas le démarrage ;
            // le journal reste pour la prochaine fois.
            let data_dir = app.path().app_data_dir()?;
            // Journal de mise au point : `LENSCOUT_DEBUG=1` ou un fichier
            // `debug` dans ce dossier (lancement depuis le Finder).
            if lenscout_core::debug_log::enabled(std::env::var_os("LENSCOUT_DEBUG").as_deref(), &data_dir) {
                lenscout_core::debug_log::install(&data_dir);
            }
            // Le marqueur de la règle sudoers macOS y vit.
            set_data_dir(&data_dir);
            let journal = data_dir.join("temp-ip.json");
            if let Err(e) = cleanup_leftover(&SystemElevator, &journal) {
                eprintln!("Lenscout : IP temporaire non retirée au démarrage : {e}");
            }
            app.manage(TempIpJournal(journal));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            cmd_app_version,
            cmd_free_ips,
            cmd_free_ips_cancel,
            cmd_site_survey,
            cmd_site_survey_cancel,
            cmd_login_test,
            cmd_login_test_cancel,
            cmd_list_interfaces,
            cmd_interface_details,
            cmd_debug_get,
            cmd_debug_set,
            cmd_scan_start,
            cmd_read_addressing,
            cmd_read_link_local,
            cmd_scan_cancel,
            cmd_open_camera_web,
            cmd_accounts_list,
            cmd_accounts_startup,
            cmd_account_create,
            cmd_account_update,
            cmd_account_password,
            cmd_account_remove,
            cmd_account_cameras,
            cmd_account_fill,
            cmd_account_forget_camera,
            cmd_account_devices,
            cmd_account_forget_device,
            cmd_account_forget_all_devices,
            cmd_account_reservations,
            cmd_account_reserve,
            cmd_account_release,
            cmd_accounts_export,
            cmd_accounts_import_plan,
            cmd_accounts_import_apply,
            cmd_save_report,
            cmd_save_xlsx,
            cmd_join_network,
            cmd_join_ready,
            cmd_leave_network,
            cmd_joined_network,
            cmd_apply_action,
            cmd_batch_preview,
            cmd_batch_apply,
            cmd_ops_preview,
            cmd_ops_step,
            cmd_ops_creds_step,
            cmd_ops_close,
            cmd_stream_start,
            cmd_stream_views,
            cmd_image_settings,
            cmd_optics,
            cmd_set_rotation,
            cmd_set_bdc,
            cmd_identify_camera,
            cmd_stream_stop,
            cmd_stream_ack,
            cmd_check_update,
            cmd_apply_update,
        ])
        .build(tauri::generate_context!())
        .expect("erreur au lancement de Lenscout")
        .run(|app, event| {
            // Filet de sortie : une action en cours tient le verrou ; on
            // attend qu'elle ait retiré son IP (10 s au plus), puis on retire
            // ce que le journal porte encore. Au-delà, on quitte : le
            // démarrage suivant s'en charge.
            //
            // `Exit` arrive quand la boucle d'événements se termine, fenêtres
            // déjà fermées : attendre ici ne fige aucune fenêtre, et l'action
            // en cours tourne sur le runtime async, pas sur ce fil. Plus
            // simple et plus sûr que `ExitRequested` + `prevent_exit` + une
            // seconde sortie, qui ne couvre pas tous les chemins de sortie.
            //
            // L'IP posée par « Se mettre dans ce réseau » est lâchée d'abord
            // (son journal reste) : le filet ci-dessous la retire.
            if let RunEvent::Exit = event
                && let Some(join) = app.try_state::<JoinState>()
            {
                join.let_go();
            }
            if let RunEvent::Exit = event
                && let Some(journal) = app.try_state::<TempIpJournal>()
                && let Err(e) = cleanup_before_exit(&SystemElevator, &journal.0, EXIT_WAIT)
            {
                eprintln!("Lenscout : IP temporaire non retirée à la sortie : {e}");
            }
        });
}
