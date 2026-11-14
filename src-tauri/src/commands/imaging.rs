use std::sync::Mutex;
use std::time::Duration;

use lenscout_core::accounts::AccountBook;
use lenscout_core::http_client::ReqwestCameraHttp;
use lenscout_core::imaging::{
    self, ImageSettings, MAX_VIEW_INDEX, Optics, OpticsCommand, error_code, view_sensor,
};
use lenscout_core::model::{Camera, Family};
use lenscout_core::route::SystemRoutes;
use lenscout_core::transport::Credentials;
use tauri::State;

use super::accounts::credentials_for;
use super::discovery::ScanState;
use super::join::JoinState;
use super::stream::{guard_interfaces_now, reachable};

/// Délai d'une requête de réglage ; un autofocus, lui, se suit par sondage.
const HTTP_TIMEOUT: Duration = Duration::from_secs(8);
/// Sondage de l'optique après une commande : 30 lectures toutes les 400 ms
/// au plus (12 s), le temps d'un autofocus.
const SETTLE_TRIES: usize = 30;
const SETTLE_EVERY: Duration = Duration::from_millis(400);

/// Indice `Image.I<i>` de la vue choisie (`camera=n`, à partir de 1) ; sans
/// vue (caméra à une seule vue), la première. Code : `bad_value`.
fn view_index(view: Option<u32>) -> Result<u32, String> {
    match view {
        None => Ok(0),
        Some(n) if (1..=MAX_VIEW_INDEX + 1).contains(&n) => Ok(n - 1),
        Some(_) => Err("bad_value".into()),
    }
}

/// Seules les Axis ont ce panneau. Code : `unsupported_brand`.
fn axis_only(camera: &Camera) -> Result<(), String> {
    if camera.family == Family::Axis { Ok(()) } else { Err("unsupported_brand".into()) }
}

/// La garde du cadrage, avant toute requête : une Axis, joignable dans le
/// sous-réseau d'une interface ou à travers le routeur (même règle que les
/// actions) ; alors seulement le compte est lu. Codes : `unsupported_brand`,
/// `bad_value`, `camera_off_subnet`, ceux de `credentials_for`.
async fn guarded(
    camera: &Camera,
    account_id: &str,
    view: Option<u32>,
    accounts: &Mutex<AccountBook>,
    join: &JoinState,
    scan: &ScanState,
) -> Result<(Credentials, u32), String> {
    axis_only(camera)?;
    let i = view_index(view)?;
    let held = join.temp();
    let ifaces = tauri::async_runtime::spawn_blocking(move || guard_interfaces_now(held))
        .await
        .map_err(|_| "internal".to_string())?;
    if !reachable(&ifaces, &scan.seen().routed, &SystemRoutes, camera.ip).await {
        return Err("camera_off_subnet".into());
    }
    Ok((credentials_for(accounts, account_id)?, i))
}

/// Ce que le panneau de réglages montre pour la vue choisie. Codes : ceux de `guarded`.
#[tauri::command]
pub async fn cmd_image_settings(
    camera: Camera,
    account_id: String,
    view: Option<u32>,
    accounts: State<'_, Mutex<AccountBook>>,
    join: State<'_, JoinState>,
    scan: State<'_, ScanState>,
) -> Result<ImageSettings, String> {
    let (creds, i) = guarded(&camera, &account_id, view, &accounts, &join, &scan).await?;
    let http = ReqwestCameraHttp::new(HTTP_TIMEOUT);
    Ok(imaging::image_settings(&http, &camera.base_url(), &creds, i).await)
}

/// Le capteur de la vue, relu sur la caméra (jamais fourni par le front) ;
/// une vue groupée n'en a pas. Code : `unsupported`.
async fn sensor(http: &ReqwestCameraHttp, base: &str, creds: &Credentials, i: u32) -> Result<u32, String> {
    let params = imaging::read_view(http, base, creds, i).await;
    view_sensor(&params, i).ok_or_else(|| "unsupported".to_string())
}

/// Une commande d'optique, puis l'état relu à la fin du mouvement (sondage
/// borné). Codes : ceux de `guarded`, `unsupported`, `bad_value`,
/// `auth_failed`, `unreachable`, `setting_failed`.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_optics(
    camera: Camera,
    account_id: String,
    view: Option<u32>,
    command: OpticsCommand,
    accounts: State<'_, Mutex<AccountBook>>,
    join: State<'_, JoinState>,
    scan: State<'_, ScanState>,
) -> Result<Option<Optics>, String> {
    let (creds, i) = guarded(&camera, &account_id, view, &accounts, &join, &scan).await?;
    let http = ReqwestCameraHttp::new(HTTP_TIMEOUT);
    let base = camera.base_url();
    let id = sensor(&http, &base, &creds, i).await?.to_string();
    imaging::send_optics(&http, &base, &creds, &id, &command).await.map_err(|e| error_code(&e).to_string())?;
    Ok(imaging::settle_optics(&http, &base, &creds, &id, SETTLE_TRIES, SETTLE_EVERY).await)
}

/// Rotation de la vue, parmi celles que la caméra permet (relues avant
/// l'écriture). Le front relance le flux ensuite.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_set_rotation(
    camera: Camera,
    account_id: String,
    view: Option<u32>,
    degrees: u32,
    accounts: State<'_, Mutex<AccountBook>>,
    join: State<'_, JoinState>,
    scan: State<'_, ScanState>,
) -> Result<(), String> {
    let (creds, i) = guarded(&camera, &account_id, view, &accounts, &join, &scan).await?;
    let http = ReqwestCameraHttp::new(HTTP_TIMEOUT);
    imaging::set_rotation(&http, &camera.base_url(), &creds, i, degrees).await.map_err(|e| error_code(&e).to_string())
}

/// Correction de distorsion du capteur de la vue ; rend l'état relu (`None` :
/// plus réglable). Un échec rend son code : le front remet l'interrupteur à
/// la dernière valeur lue.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_set_bdc(
    camera: Camera,
    account_id: String,
    view: Option<u32>,
    on: bool,
    accounts: State<'_, Mutex<AccountBook>>,
    join: State<'_, JoinState>,
    scan: State<'_, ScanState>,
) -> Result<Option<bool>, String> {
    let (creds, i) = guarded(&camera, &account_id, view, &accounts, &join, &scan).await?;
    let http = ReqwestCameraHttp::new(HTTP_TIMEOUT);
    let base = camera.base_url();
    let s = sensor(&http, &base, &creds, i).await?;
    imaging::set_bdc(&http, &base, &creds, s, on).await.map_err(|e| error_code(&e).to_string())?;
    Ok(imaging::read_bdc(&http, &base, &creds, s).await.map(|b| b.on))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenscout_core::model::Activation;

    #[test]
    fn la_vue_se_ramene_a_son_indice_image_i() {
        assert_eq!(view_index(None), Ok(0));
        assert_eq!(view_index(Some(1)), Ok(0));
        assert_eq!(view_index(Some(3)), Ok(2));
        for bad in [0, MAX_VIEW_INDEX + 2, u32::MAX] {
            assert_eq!(view_index(Some(bad)), Err("bad_value".to_string()), "{bad}");
        }
    }

    #[test]
    fn seules_les_axis_ont_un_panneau() {
        let mut cam = Camera {
            ip: "192.0.2.11".parse().unwrap(),
            mac: None,
            family: Family::Axis,
            brand: None,
            model: None,
            serial: None,
            firmware: None,
            activation: Activation::Activated,
            http_port: 80,
            sources: vec![],
            addressing: None,
        };
        assert!(axis_only(&cam).is_ok());
        for f in [Family::Hikvision, Family::Other] {
            cam.family = f;
            assert_eq!(axis_only(&cam), Err("unsupported_brand".to_string()));
        }
    }
}
