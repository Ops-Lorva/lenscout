use std::sync::{Arc, Mutex};
use std::time::Duration;

use lenscout_core::accounts::AccountBook;
use lenscout_core::actions::on_subnet;
use lenscout_core::discovery::arp::ScanInterface;
use lenscout_core::http_client::ReqwestCameraHttp;
use lenscout_core::interfaces::{get_interface_details, list_interfaces_up};
use lenscout_core::mjpeg::{run_stream, stream_url};
use lenscout_core::model::Camera;
use lenscout_core::transport::{CameraHttp, Credentials, NetError};
use tauri::State;
use tauri::ipc::{Channel, InvokeResponseBody};
use tokio_util::sync::CancellationToken;

use super::accounts::credentials_for;

/// Délai d'établissement de la connexion ; le flux, lui, n'a pas de durée.
const HTTP_TIMEOUT: Duration = Duration::from_secs(8);

/// Le flux en cours : un seul jeton actif, remplacé à chaque démarrage.
#[derive(Default)]
pub struct StreamState {
    cancel: Mutex<Option<CancellationToken>>,
}

impl StreamState {
    /// Arrête le flux précédent et rend le jeton du nouveau.
    fn replace(&self) -> CancellationToken {
        let token = CancellationToken::new();
        let old = self.cancel.lock().unwrap_or_else(|e| e.into_inner()).replace(token.clone());
        if let Some(old) = old {
            old.cancel();
        }
        token
    }

    fn stop(&self) {
        if let Some(old) = self.cancel.lock().unwrap_or_else(|e| e.into_inner()).take() {
            old.cancel();
        }
    }
}

/// L'adresse vient du front, et un mot de passe part vers elle : elle doit
/// être dans le sous-réseau d'au moins une interface active, avant toute
/// requête. Puis l'URL du flux ; `unsupported_brand` si la marque n'en a pas.
pub(crate) fn guarded_url(cam: &Camera, ifaces: &[ScanInterface]) -> Result<String, String> {
    if !ifaces.iter().any(|i| on_subnet(i, cam.ip)) {
        return Err("camera_off_subnet".into());
    }
    stream_url(cam).ok_or_else(|| "unsupported_brand".to_string())
}

/// Code stable d'une fin de flux sur erreur ; jamais le texte de l'erreur
/// (l'URL de la caméra n'a pas à remonter).
fn net_code(e: &NetError) -> &'static str {
    match e {
        NetError::Auth | NetError::InsecureBasic | NetError::Status(401 | 403) => "auth_failed",
        NetError::Timeout | NetError::Unreachable(_) | NetError::Io(_) => "unreachable",
        NetError::Status(_) => "stream_failed",
        NetError::Cancelled => "stream_failed",
    }
}

/// Lance la boucle de flux. `Ok(())` à l'arrêt demandé, sinon un code stable.
pub(crate) fn spawn_stream(
    state: &StreamState,
    http: Arc<dyn CameraHttp>,
    url: String,
    creds: Credentials,
    mut on_frame: impl FnMut(Vec<u8>) + Send + 'static,
) -> tauri::async_runtime::JoinHandle<Result<(), String>> {
    let cancel = state.replace();
    tauri::async_runtime::spawn(async move {
        run_stream(http.as_ref(), url, &creds, cancel, move |f| on_frame(f.to_vec()))
            .await
            .map_err(|e| net_code(&e).to_string())
    })
}

/// Seule porte de démarrage : la garde de sous-réseau d'abord, le transport
/// ensuite. Un refus ne touche ni le transport ni le flux en cours.
pub(crate) fn start_guarded(
    state: &StreamState,
    http: Arc<dyn CameraHttp>,
    cam: &Camera,
    ifaces: &[ScanInterface],
    creds: Credentials,
    on_frame: impl FnMut(Vec<u8>) + Send + 'static,
) -> Result<tauri::async_runtime::JoinHandle<Result<(), String>>, String> {
    let url = guarded_url(cam, ifaces)?;
    Ok(spawn_stream(state, http, url, creds, on_frame))
}

/// Interfaces actives avec une adresse IPv4 exploitable.
fn active_interfaces() -> Vec<ScanInterface> {
    list_interfaces_up()
        .into_iter()
        .filter_map(|n| ScanInterface::from_details(&n, &get_interface_details(&n)))
        .collect()
}

/// Démarre le flux et ne rend la main qu'à sa fin : `Ok` à l'arrêt (ou au
/// remplacement par un autre flux), un code stable sinon. Les images partent
/// en octets bruts sur le canal ; le mot de passe ne quitte jamais Rust.
#[tauri::command]
pub async fn cmd_stream_start(
    camera: Camera,
    account_id: String,
    on_frame: Channel<InvokeResponseBody>,
    accounts: State<'_, Mutex<AccountBook>>,
    stream: State<'_, StreamState>,
) -> Result<(), String> {
    stream.stop();
    let ifaces = tauri::async_runtime::spawn_blocking(active_interfaces)
        .await
        .map_err(|_| "internal".to_string())?;
    let creds = credentials_for(&accounts, &account_id)?;
    let handle = start_guarded(
        &stream,
        Arc::new(ReqwestCameraHttp::new(HTTP_TIMEOUT)),
        &camera,
        &ifaces,
        creds,
        move |frame| {
            let _ = on_frame.send(InvokeResponseBody::Raw(frame));
        },
    )?;
    handle.await.map_err(|_| "internal".to_string())?
}

#[tauri::command]
pub fn cmd_stream_stop(stream: State<'_, StreamState>) {
    stream.stop();
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    use lenscout_core::model::{Activation, Family};
    use lenscout_core::secret::Secret;
    use lenscout_core::testing::FakeHttp;
    use lenscout_core::transport::{ByteStream, HttpRequest, HttpResponse};

    const CT: &str = "multipart/x-mixed-replace; boundary=b";

    fn cam(ip: &str, family: Family) -> Camera {
        Camera {
            ip: ip.parse().unwrap(),
            mac: None,
            family,
            brand: None,
            model: None,
            serial: None,
            firmware: None,
            activation: Activation::Unknown,
            http_port: 80,
            sources: vec![],
        }
    }

    fn iface() -> ScanInterface {
        ScanInterface { name: "eth0".into(), ip: "192.0.2.10".parse().unwrap(), mask: "255.255.255.0".parse().unwrap() }
    }

    fn creds() -> Credentials {
        Credentials { login: "root".into(), password: Secret::new("pw".into()) }
    }

    /// Une caméra dont le flux ne finit jamais : seule l'annulation y met fin.
    struct Endless;

    #[async_trait]
    impl CameraHttp for Endless {
        async fn send(&self, _: HttpRequest, _: Option<&Credentials>) -> Result<HttpResponse, NetError> {
            Err(NetError::Unreachable("non".into()))
        }
        async fn stream(&self, _: HttpRequest, _: Option<&Credentials>) -> Result<(HttpResponse, ByteStream), NetError> {
            let resp = HttpResponse { status: 200, headers: vec![("Content-Type".into(), CT.into())], body: vec![] };
            let body: ByteStream = Box::pin(futures_util::stream::pending::<Result<Bytes, NetError>>());
            Ok((resp, body))
        }
    }

    #[test]
    fn hors_sous_reseau_refuse_avant_toute_requete() {
        let http = Arc::new(FakeHttp::new().on_stream("/axis-cgi/mjpg", CT, vec![]));
        let state = StreamState::default();
        for (ip, ifaces) in [("198.51.100.7", vec![iface()]), ("192.0.3.7", vec![iface()]), ("192.0.2.20", vec![])] {
            let r = start_guarded(&state, http.clone(), &cam(ip, Family::Axis), &ifaces, creds(), |_| {});
            assert_eq!(r.err().as_deref(), Some("camera_off_subnet"), "{ip}");
        }
        // Le refus ne touche ni le transport (aucun identifiant envoyé) ni l'état.
        assert!(http.requests().is_empty());
        assert!(state.cancel.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn dans_le_sous_reseau_la_requete_part_avec_le_login_sans_secret() {
        let http = Arc::new(FakeHttp::new().on_stream("/axis-cgi/mjpg", CT, vec![]));
        let state = StreamState::default();
        let h = start_guarded(&state, http.clone(), &cam("192.0.2.20", Family::Axis), &[iface()], creds(), |_| {})
            .unwrap();
        let _ = h.await;
        let reqs = http.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].login.as_deref(), Some("root"));
        assert!(!reqs[0].url.contains("pw"));
    }

    #[test]
    fn marque_sans_flux_et_url_dans_le_sous_reseau() {
        assert_eq!(guarded_url(&cam("192.0.2.20", Family::Other), &[iface()]).unwrap_err(), "unsupported_brand");
        let url = guarded_url(&cam("192.0.2.20", Family::Axis), &[iface()]).unwrap();
        assert!(url.starts_with("http://192.0.2.20/axis-cgi/mjpg/video.cgi"));
    }

    #[tokio::test]
    async fn les_images_sont_poussees_puis_le_flux_se_ferme() {
        let jpeg = [vec![0xFF, 0xD8, 1, 2, 3, 0xFF, 0xD9]].concat();
        let mut body = b"--b\r\nContent-Type: image/jpeg\r\n".to_vec();
        body.extend(format!("Content-Length: {}\r\n\r\n", jpeg.len()).as_bytes());
        body.extend(&jpeg);
        body.extend(b"\r\n--b\r\n");
        let http = Arc::new(FakeHttp::new().on_stream("/axis-cgi/mjpg", CT, vec![body]));
        let state = StreamState::default();
        let frames = Arc::new(Mutex::new(Vec::new()));
        let sink = frames.clone();
        let h = spawn_stream(&state, http.clone(), "http://192.0.2.20/axis-cgi/mjpg/video.cgi".into(), creds(), move |f| {
            sink.lock().unwrap().push(f)
        });
        // Le faux flux est fini : la fin du corps est une erreur réseau, pas un arrêt.
        assert_eq!(h.await.unwrap(), Err("unreachable".to_string()));
        assert_eq!(frames.lock().unwrap().as_slice(), &[jpeg]);
        let reqs = http.requests();
        assert_eq!(reqs.len(), 1);
        assert!(!reqs[0].url.contains("pw"), "aucun secret dans l'URL");
    }

    #[tokio::test]
    async fn l_arret_termine_la_tache_et_un_second_start_remplace_le_premier() {
        let state = StreamState::default();
        let http: Arc<dyn CameraHttp> = Arc::new(Endless);
        let url = "http://192.0.2.20/axis-cgi/mjpg/video.cgi".to_string();

        let first = spawn_stream(&state, http.clone(), url.clone(), creds(), |_| {});
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!first.inner().is_finished(), "le flux tourne");
        state.stop();
        assert_eq!(first.await.unwrap(), Ok(()));
        assert!(state.cancel.lock().unwrap().is_none());

        let first = spawn_stream(&state, http.clone(), url.clone(), creds(), |_| {});
        tokio::time::sleep(Duration::from_millis(30)).await;
        let second = spawn_stream(&state, http, url, creds(), |_| {});
        // Remplacé : le premier se termine tout seul, le second tourne, un seul jeton reste.
        assert_eq!(first.await.unwrap(), Ok(()));
        assert!(!second.inner().is_finished());
        assert!(state.cancel.lock().unwrap().is_some());
        state.stop();
        assert_eq!(second.await.unwrap(), Ok(()));
    }
}
