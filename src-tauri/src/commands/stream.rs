use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

/// Images envoyées au webview mais pas encore acquittées (`cmd_stream_ack`) :
/// au-delà, les nouvelles images sont abandonnées côté Rust. La file du canal
/// Tauri, elle, n'a pas de plafond.
const MAX_IN_FLIGHT: usize = 2;

/// Un démarrage de flux : son jeton d'annulation, son numéro, et son compteur
/// d'images en vol (neuf à chaque démarrage).
pub(crate) struct Run {
    id: u64,
    token: CancellationToken,
    in_flight: Arc<AtomicUsize>,
}

/// Le flux en cours : un seul actif, remplacé à chaque démarrage.
#[derive(Default)]
pub struct StreamState {
    cancel: Mutex<Option<Run>>,
    next_id: AtomicU64,
}

impl StreamState {
    /// Arrête le flux précédent et rend le démarrage du nouveau. À appeler au
    /// tout début de la commande, avant le moindre `await` : un `stop` qui
    /// arrive ensuite l'annule.
    pub(crate) fn replace(&self) -> Run {
        let run = Run {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            token: CancellationToken::new(),
            in_flight: Arc::new(AtomicUsize::new(0)),
        };
        let current = Run { id: run.id, token: run.token.clone(), in_flight: run.in_flight.clone() };
        let old = self.cancel.lock().unwrap_or_else(|e| e.into_inner()).replace(current);
        if let Some(old) = old {
            old.token.cancel();
        }
        run
    }

    pub(crate) fn stop(&self) {
        if let Some(old) = self.cancel.lock().unwrap_or_else(|e| e.into_inner()).take() {
            old.token.cancel();
        }
    }

    /// Libère le démarrage `id` (refusé avant d'avoir commencé), sans toucher
    /// à un démarrage plus récent qui l'aurait remplacé.
    pub(crate) fn release(&self, id: u64) {
        let mut cur = self.cancel.lock().unwrap_or_else(|e| e.into_inner());
        if cur.as_ref().is_some_and(|r| r.id == id)
            && let Some(r) = cur.take()
        {
            r.token.cancel();
        }
    }

    /// Le webview a traité une image : une place se libère (jamais sous zéro).
    pub(crate) fn ack(&self) {
        if let Some(r) = self.cancel.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let _ = r.in_flight.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
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
/// (l'URL de la caméra n'a pas à remonter). `Io` n'est pas forcément le
/// réseau (flux non multipart, flux fermé) : `stream_failed`.
fn net_code(e: &NetError) -> &'static str {
    match e {
        NetError::InsecureBasic => "auth_insecure",
        NetError::Auth | NetError::Status(401 | 403) => "auth_failed",
        NetError::Timeout | NetError::Unreachable(_) | NetError::Denied => "unreachable",
        NetError::Io(_) | NetError::Status(_) | NetError::Cancelled => "stream_failed",
    }
}

/// Lance la boucle de flux. `Ok(())` à l'arrêt demandé, sinon un code stable.
/// `send` rend `Err` quand le webview n'est plus là : le flux est annulé.
/// Les images au-delà de `MAX_IN_FLIGHT` non acquittées sont abandonnées.
pub(crate) fn spawn_stream(
    run: Run,
    http: Arc<dyn CameraHttp>,
    url: String,
    creds: Credentials,
    mut send: impl FnMut(Vec<u8>) -> Result<(), ()> + Send + 'static,
) -> tauri::async_runtime::JoinHandle<Result<(), String>> {
    let Run { token, in_flight, .. } = run;
    let cancel = token.clone();
    tauri::async_runtime::spawn(async move {
        run_stream(http.as_ref(), url, &creds, cancel, move |f| {
            if token.is_cancelled() || in_flight.load(Ordering::SeqCst) >= MAX_IN_FLIGHT {
                return;
            }
            in_flight.fetch_add(1, Ordering::SeqCst);
            if send(f.to_vec()).is_err() {
                token.cancel();
            }
        })
        .await
        .map_err(|e| net_code(&e).to_string())
    })
}

/// Seule porte de démarrage : la garde de sous-réseau d'abord, le transport
/// ensuite. Un refus libère le démarrage `run` (donc arrête le flux précédent,
/// déjà remplacé au début de la commande) sans toucher au transport.
pub(crate) fn start_guarded(
    state: &StreamState,
    run: Run,
    http: Arc<dyn CameraHttp>,
    cam: &Camera,
    ifaces: &[ScanInterface],
    creds: Credentials,
    send: impl FnMut(Vec<u8>) -> Result<(), ()> + Send + 'static,
) -> Result<tauri::async_runtime::JoinHandle<Result<(), String>>, String> {
    match guarded_url(cam, ifaces) {
        Ok(url) => Ok(spawn_stream(run, http, url, creds, send)),
        Err(e) => {
            state.release(run.id);
            Err(e)
        }
    }
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
    // Avant tout await : un stop reçu pendant les étapes suivantes annule ce jeton.
    let run = stream.replace();
    let id = run.id;
    let prepared = async {
        let ifaces = tauri::async_runtime::spawn_blocking(active_interfaces)
            .await
            .map_err(|_| "internal".to_string())?;
        let creds = credentials_for(&accounts, &account_id)?;
        Ok::<_, String>((ifaces, creds))
    }
    .await;
    let (ifaces, creds) = match prepared {
        Ok(p) => p,
        Err(e) => {
            stream.release(id);
            return Err(e);
        }
    };
    let handle = start_guarded(
        &stream,
        run,
        Arc::new(ReqwestCameraHttp::new(HTTP_TIMEOUT)),
        &camera,
        &ifaces,
        creds,
        move |frame| on_frame.send(InvokeResponseBody::Raw(frame)).map_err(|_| ()),
    )?;
    handle.await.map_err(|_| "internal".to_string())?
}

#[tauri::command]
pub fn cmd_stream_stop(stream: State<'_, StreamState>) {
    stream.stop();
}

/// Le front a traité une image (affichée ou abandonnée).
#[tauri::command]
pub fn cmd_stream_ack(stream: State<'_, StreamState>) {
    stream.ack();
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
    use std::sync::atomic::Ordering;

    const CT: &str = "multipart/x-mixed-replace; boundary=b";
    const URL: &str = "http://192.0.2.20/axis-cgi/mjpg/video.cgi";

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

    fn jpeg(n: u8) -> Vec<u8> {
        vec![0xFF, 0xD8, n, 0xFF, 0xD9]
    }

    /// `n` images dans un seul corps multipart.
    fn body(n: u8) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..n {
            let j = jpeg(i);
            out.extend(format!("--b\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", j.len()).as_bytes());
            out.extend(&j);
            out.extend(b"\r\n");
        }
        out.extend(b"--b\r\n");
        out
    }

    fn fake(n: u8) -> Arc<FakeHttp> {
        Arc::new(FakeHttp::new().on_stream("/axis-cgi/mjpg", CT, vec![body(n)]))
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

    fn active(state: &StreamState) -> bool {
        state.cancel.lock().unwrap().is_some()
    }

    #[test]
    fn hors_sous_reseau_refuse_avant_toute_requete() {
        let http = fake(1);
        let state = StreamState::default();
        for (ip, ifaces) in [("198.51.100.7", vec![iface()]), ("192.0.3.7", vec![iface()]), ("192.0.2.20", vec![])] {
            let run = state.replace();
            let r = start_guarded(&state, run, http.clone(), &cam(ip, Family::Axis), &ifaces, creds(), |_| Ok(()));
            assert_eq!(r.err().as_deref(), Some("camera_off_subnet"), "{ip}");
            // Le refus libère le jeton posé au départ.
            assert!(!active(&state), "{ip}");
        }
        assert!(http.requests().is_empty(), "aucun identifiant envoye");
    }

    #[test]
    fn un_refus_ne_libere_pas_le_flux_d_un_demarrage_plus_recent() {
        let state = StreamState::default();
        let old = state.replace();
        let newer = state.replace();
        state.release(old.id);
        assert!(active(&state));
        assert!(!newer.token.is_cancelled());
        state.release(newer.id);
        assert!(!active(&state));
    }

    #[test]
    fn marque_sans_flux() {
        let state = StreamState::default();
        let run = state.replace();
        let r = start_guarded(&state, run, fake(1), &cam("192.0.2.20", Family::Other), &[iface()], creds(), |_| Ok(()));
        assert_eq!(r.err().as_deref(), Some("unsupported_brand"));
        assert!(!active(&state));
    }

    #[tokio::test]
    async fn dans_le_sous_reseau_la_requete_part_avec_le_login_sans_secret() {
        let http = fake(0);
        let state = StreamState::default();
        let run = state.replace();
        let h = start_guarded(&state, run, http.clone(), &cam("192.0.2.20", Family::Axis), &[iface()], creds(), |_| Ok(()))
            .unwrap();
        let _ = h.await;
        let reqs = http.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].login.as_deref(), Some("root"));
        assert!(reqs[0].url.starts_with("http://192.0.2.20/axis-cgi/mjpg/video.cgi"));
        assert!(!reqs[0].url.contains("pw"));
    }

    #[tokio::test]
    async fn un_stop_entre_la_garde_et_le_lancement_n_ouvre_aucun_flux() {
        let http = fake(3);
        let state = StreamState::default();
        let run = state.replace(); // debut de cmd_stream_start
        state.stop(); // le front arrete pendant les await
        let h = start_guarded(&state, run, http.clone(), &cam("192.0.2.20", Family::Axis), &[iface()], creds(), |_| Ok(()))
            .unwrap();
        assert_eq!(h.await.unwrap(), Ok(()));
        assert!(http.requests().is_empty(), "le flux annule n'a rien demande a la camera");
    }

    #[tokio::test]
    async fn les_images_sont_poussees_puis_la_fin_du_corps_est_un_flux_interrompu() {
        let http = fake(1);
        let state = StreamState::default();
        let frames = Arc::new(Mutex::new(Vec::new()));
        let sink = frames.clone();
        let h = spawn_stream(state.replace(), http, URL.into(), creds(), move |f| {
            sink.lock().unwrap().push(f);
            Ok(())
        });
        assert_eq!(h.await.unwrap(), Err("stream_failed".to_string()));
        assert_eq!(frames.lock().unwrap().as_slice(), &[jpeg(0)]);
    }

    #[test]
    fn codes_d_erreur_reseau() {
        assert_eq!(net_code(&NetError::InsecureBasic), "auth_insecure");
        assert_eq!(net_code(&NetError::Auth), "auth_failed");
        assert_eq!(net_code(&NetError::Status(403)), "auth_failed");
        assert_eq!(net_code(&NetError::Timeout), "unreachable");
        assert_eq!(net_code(&NetError::Unreachable("x".into())), "unreachable");
        assert_eq!(net_code(&NetError::Io("flux fermé".into())), "stream_failed");
        assert_eq!(net_code(&NetError::Status(500)), "stream_failed");
    }

    #[tokio::test]
    async fn sans_acquittement_deux_images_au_plus_partent() {
        let state = StreamState::default();
        let run = state.replace();
        let in_flight = run.in_flight.clone();
        let sent = Arc::new(Mutex::new(0usize));
        let n = sent.clone();
        let h = spawn_stream(run, fake(5), URL.into(), creds(), move |_| {
            *n.lock().unwrap() += 1;
            Ok(())
        });
        let _ = h.await;
        assert_eq!(*sent.lock().unwrap(), MAX_IN_FLIGHT);
        assert_eq!(in_flight.load(Ordering::SeqCst), MAX_IN_FLIGHT);
        // Un acquittement libere une place ; jamais en dessous de zero.
        state.ack();
        assert_eq!(in_flight.load(Ordering::SeqCst), MAX_IN_FLIGHT - 1);
        for _ in 0..5 {
            state.ack();
        }
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn un_nouveau_demarrage_remet_le_compteur_a_zero() {
        let state = StreamState::default();
        let first = state.replace();
        first.in_flight.store(2, Ordering::SeqCst);
        let second = state.replace();
        assert_eq!(second.in_flight.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn un_canal_ferme_annule_le_flux() {
        let state = StreamState::default();
        let run = state.replace();
        let token = run.token.clone();
        let calls = Arc::new(Mutex::new(0usize));
        let c = calls.clone();
        let h = spawn_stream(run, fake(4), URL.into(), creds(), move |_| {
            *c.lock().unwrap() += 1;
            Err(())
        });
        // Annule par l'envoi en echec : fin propre, pas une erreur de flux.
        assert_eq!(h.await.unwrap(), Ok(()));
        assert!(token.is_cancelled());
        assert_eq!(*calls.lock().unwrap(), 1, "plus rien n'est envoye apres l'echec");
    }

    #[tokio::test]
    async fn l_arret_termine_la_tache_et_un_second_start_remplace_le_premier() {
        let state = StreamState::default();
        let http: Arc<dyn CameraHttp> = Arc::new(Endless);

        let first = spawn_stream(state.replace(), http.clone(), URL.into(), creds(), |_| Ok(()));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!first.inner().is_finished(), "le flux tourne");
        state.stop();
        assert_eq!(first.await.unwrap(), Ok(()));
        assert!(!active(&state));

        let first = spawn_stream(state.replace(), http.clone(), URL.into(), creds(), |_| Ok(()));
        tokio::time::sleep(Duration::from_millis(30)).await;
        let second = spawn_stream(state.replace(), http, URL.into(), creds(), |_| Ok(()));
        assert_eq!(first.await.unwrap(), Ok(()));
        assert!(!second.inner().is_finished());
        assert!(active(&state));
        state.stop();
        assert_eq!(second.await.unwrap(), Ok(()));
    }
}
