use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lenscout_core::accounts::AccountBook;
use lenscout_core::actions::on_subnet;
use lenscout_core::discovery::arp::ScanInterface;
use lenscout_core::http_client::ReqwestCameraHttp;
use lenscout_core::identify::{IdentifyError, identify};
use lenscout_core::interfaces::{get_interface_details, list_interfaces_up};
use lenscout_core::mjpeg::{run_stream, stream_url_for_view};
use lenscout_core::model::Family;
use lenscout_core::vapix::{self, View};
use lenscout_core::model::Camera;
use lenscout_core::presence;
use lenscout_core::temp_ip::TempIp;
use lenscout_core::transport::{CameraHttp, Credentials, NetError};
use tauri::State;
use tauri::ipc::{Channel, InvokeResponseBody};
use tokio_util::sync::CancellationToken;

use super::accounts::credentials_for;
use super::join::JoinState;

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
/// requête. Puis l'URL du flux, sur la vue `view` d'une Axis multicapteur
/// (`camera=N`) ; `unsupported_brand` si la marque n'en a pas.
pub(crate) fn guarded_view_url(cam: &Camera, view: Option<u32>, ifaces: &[ScanInterface]) -> Result<String, String> {
    if !ifaces.iter().any(|i| on_subnet(i, cam.ip)) {
        return Err("camera_off_subnet".into());
    }
    stream_url_for_view(cam, view).ok_or_else(|| "unsupported_brand".to_string())
}

/// Vues d'une Axis, sous la même garde de sous-réseau que le flux, avant
/// toute requête et avant de lire le compte. Une autre marque : une vue,
/// sans requête (Hikvision est hors périmètre).
pub(crate) async fn views_guarded(
    http: &dyn CameraHttp,
    cam: &Camera,
    ifaces: &[ScanInterface],
    creds: impl FnOnce() -> Result<Credentials, String>,
) -> Result<Vec<View>, String> {
    if !ifaces.iter().any(|i| on_subnet(i, cam.ip)) {
        return Err("camera_off_subnet".into());
    }
    if cam.family != Family::Axis {
        return Ok(vec![View { n: 1, name: None }]);
    }
    Ok(vapix::views(http, &cam.base_url(), &creds()?).await)
}

/// Adresse saisie dans Cadrage : lisible (`bad_ip`, l'adresse du poste
/// comprise), puis la même garde de sous-réseau que le flux AVANT toute
/// requête (`camera_off_subnet`), puis l'identification (`unreachable`,
/// `auth_failed`, `not_a_camera`). `creds` n'est lu qu'après la garde.
pub(crate) async fn identify_guarded(
    http: &dyn CameraHttp,
    ip: &str,
    ifaces: &[ScanInterface],
    creds: impl FnOnce() -> Result<Credentials, String>,
) -> Result<Camera, String> {
    let ip: Ipv4Addr = ip.trim().parse().map_err(|_| "bad_ip".to_string())?;
    if ifaces.iter().any(|i| i.ip == ip) {
        return Err("bad_ip".into());
    }
    if !ifaces.iter().any(|i| on_subnet(i, ip)) {
        return Err("camera_off_subnet".into());
    }
    identify(http, ip, &creds()?).await.map_err(|e| {
        match e {
            IdentifyError::Unreachable => "unreachable",
            IdentifyError::AuthFailed => "auth_failed",
            IdentifyError::AuthInsecure => "auth_insecure",
            IdentifyError::NotACamera => "not_a_camera",
        }
        .to_string()
    })
}

/// Identifie la caméra d'une adresse saisie, pour la cadrer sans passer par
/// Réseau. Codes : ceux de `identify_guarded` et de `credentials_for`.
#[tauri::command]
pub async fn cmd_identify_camera(
    ip: String,
    account_id: String,
    accounts: State<'_, Mutex<AccountBook>>,
    join: State<'_, JoinState>,
) -> Result<Camera, String> {
    let held = join.temp();
    let ifaces = tauri::async_runtime::spawn_blocking(move || guard_interfaces_now(held))
        .await
        .map_err(|_| "internal".to_string())?;
    let http = ReqwestCameraHttp::new(HTTP_TIMEOUT);
    identify_guarded(&http, &ip, &ifaces, || credentials_for(&accounts, &account_id)).await
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
    view: Option<u32>,
    ifaces: &[ScanInterface],
    creds: Credentials,
    send: impl FnMut(Vec<u8>) -> Result<(), ()> + Send + 'static,
) -> Result<tauri::async_runtime::JoinHandle<Result<(), String>>, String> {
    match guarded_view_url(cam, view, ifaces) {
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

/// Les adresses vues par la garde de sous-réseau : celles des interfaces
/// actives, plus les autres adresses de CES cartes (une carte en porte deux
/// pendant la pose d'un compte ; les détails système n'en rendent qu'une),
/// et celle que Lenscout tient si `present` la trouve sur le poste (pose
/// ratée : jamais). Une carte que le scan ne propose pas (VPN, pont, docker,
/// débranchée) ne compte pas : un identifiant ne part jamais hors réseau.
/// Sans boucle locale ni doublon.
pub(crate) fn guard_interfaces(
    active: &[ScanInterface],
    local: &[ScanInterface],
    held: Option<&TempIp>,
    present: impl Fn(Ipv4Addr) -> bool,
) -> Vec<ScanInterface> {
    // `eth0:1` (adresse étiquetée, Linux) appartient à `eth0`.
    let card = |n: &str| n.split(':').next().unwrap_or(n).to_string();
    let on_active = |i: &&ScanInterface| active.iter().any(|a| card(&a.name) == card(&i.name));
    let held = held.filter(|t| present(t.ip) && active.iter().any(|a| card(&a.name) == card(&t.iface))).map(|t| ScanInterface { name: t.iface.clone(), ip: t.ip, mask: t.mask });
    let mut out: Vec<ScanInterface> = Vec::new();
    for i in active.iter().chain(local.iter().filter(on_active)).chain(held.as_ref()) {
        if !i.ip.is_loopback() && !out.iter().any(|o| o.ip == i.ip) {
            out.push(i.clone());
        }
    }
    out
}

/// `guard_interfaces` sur l'état réel du poste (bloquant : à lancer hors du
/// runtime).
fn guard_interfaces_now(held: Option<TempIp>) -> Vec<ScanInterface> {
    guard_interfaces(&active_interfaces(), &presence::local_addresses(), held.as_ref(), presence::address_present)
}

/// Démarre le flux et ne rend la main qu'à sa fin : `Ok` à l'arrêt (ou au
/// remplacement par un autre flux), un code stable sinon. Les images partent
/// en octets bruts sur le canal ; le mot de passe ne quitte jamais Rust.
///
/// `view` : la vue d'une Axis multicapteur (`camera=N`, à partir de 1) ;
/// absente, la vue par défaut.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn cmd_stream_start(
    camera: Camera,
    account_id: String,
    view: Option<u32>,
    on_frame: Channel<InvokeResponseBody>,
    accounts: State<'_, Mutex<AccountBook>>,
    stream: State<'_, StreamState>,
    join: State<'_, JoinState>,
) -> Result<(), String> {
    // Avant tout await : un stop reçu pendant les étapes suivantes annule ce jeton.
    let run = stream.replace();
    let id = run.id;
    let prepared = async {
        let held = join.temp();
        let ifaces = tauri::async_runtime::spawn_blocking(move || guard_interfaces_now(held))
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
        view.filter(|n| *n >= 1),
        &ifaces,
        creds,
        move |frame| on_frame.send(InvokeResponseBody::Raw(frame)).map_err(|_| ()),
    )?;
    handle.await.map_err(|_| "internal".to_string())?
}

/// Vues de la caméra à cadrer (Axis multicapteur), pour le sélecteur de la
/// page Cadrage. Codes : `camera_off_subnet`, ceux de `credentials_for`.
#[tauri::command]
pub async fn cmd_stream_views(
    camera: Camera,
    account_id: String,
    accounts: State<'_, Mutex<AccountBook>>,
    join: State<'_, JoinState>,
) -> Result<Vec<View>, String> {
    let held = join.temp();
    let ifaces = tauri::async_runtime::spawn_blocking(move || guard_interfaces_now(held))
        .await
        .map_err(|_| "internal".to_string())?;
    let http = ReqwestCameraHttp::new(HTTP_TIMEOUT);
    views_guarded(&http, &camera, &ifaces, || credentials_for(&accounts, &account_id)).await
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

    /// `guarded_view_url` sur la vue par défaut.
    fn guarded_url(cam: &Camera, ifaces: &[ScanInterface]) -> Result<String, String> {
        guarded_view_url(cam, None, ifaces)
    }
    use async_trait::async_trait;
    use bytes::Bytes;
    use lenscout_core::model::{Activation, Family};
    use lenscout_core::secret::Secret;
    use lenscout_core::testing::FakeHttp;
    use lenscout_core::transport::{ByteStream, HttpRequest, HttpResponse, Method};
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
            addressing: None,
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

    #[tokio::test]
    async fn ip_saisie_hors_sous_reseau_ou_illisible_refusee_avant_toute_requete() {
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, "{}");
        for (ip, want) in [("198.51.100.7", "camera_off_subnet"), ("192.0.2", "bad_ip"), ("x", "bad_ip"), ("192.0.2.10", "bad_ip")] {
            assert_eq!(identify_guarded(&http, ip, &[iface()], || Ok(creds())).await.err().as_deref(), Some(want), "{ip}");
        }
        assert!(http.requests().is_empty(), "aucune requete");
    }

    #[tokio::test]
    async fn ip_saisie_identifiee_par_la_meme_garde_puis_codes_clairs() {
        let info = br#"{"apiVersion":"1.0","data":{"propertyList":{"Brand":"AXIS","ProdNbr":"M3106","SerialNumber":"ACCC8E000002"}}}"#;
        let http = FakeHttp::new().on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, info.to_vec());
        let cam = identify_guarded(&http, " 192.0.2.20 ", &[iface()], || Ok(creds())).await.unwrap();
        assert_eq!((cam.family, cam.ip), (Family::Axis, "192.0.2.20".parse().unwrap()));
        // La garde de flux accepte la caméra identifiée.
        assert!(guarded_url(&cam, &[iface()]).is_ok());
        assert_eq!(identify_guarded(&FakeHttp::new(), "192.0.2.20", &[iface()], || Ok(creds())).await.err().as_deref(), Some("unreachable"));
        let refused = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 404, "")
            .on(Method::Get, "/ISAPI/System/deviceInfo", 401, "");
        assert_eq!(identify_guarded(&refused, "192.0.2.20", &[iface()], || Ok(creds())).await.err().as_deref(), Some("auth_failed"));
        let other = FakeHttp::new()
            .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 404, "")
            .on(Method::Get, "/axis-cgi/param.cgi", 404, "")
            .on(Method::Get, "/ISAPI/System/deviceInfo", 404, "");
        assert_eq!(identify_guarded(&other, "192.0.2.20", &[iface()], || Ok(creds())).await.err().as_deref(), Some("not_a_camera"));
        // Compte introuvable : le code du compte remonte.
        assert_eq!(identify_guarded(&other, "192.0.2.20", &[iface()], || Err("not_found".into())).await.err().as_deref(), Some("not_found"));
    }

    fn si(name: &str, ip: &str, mask: &str) -> ScanInterface {
        ScanInterface { name: name.into(), ip: ip.parse().unwrap(), mask: mask.parse().unwrap() }
    }

    #[test]
    fn la_garde_voit_toutes_les_adresses_du_poste_et_celle_du_compte() {
        let m = "255.255.255.0";
        let here = |_: Ipv4Addr| true;
        // Détails système : une seule adresse par carte (la principale sous
        // macOS, l'une ou l'autre ailleurs).
        let active = [si("en0", "10.0.8.235", m)];
        let local = [si("en0", "10.0.8.235", m), si("en0", "192.168.1.10", m), si("lo0", "127.0.0.1", "255.0.0.0")];
        let held = TempIp { iface: "en0".into(), ip: "192.168.1.10".parse().unwrap(), mask: m.parse().unwrap() };
        let got = guard_interfaces(&active, &local, Some(&held), here);
        let ips: Vec<String> = got.iter().map(|i| i.ip.to_string()).collect();
        assert_eq!(ips, ["10.0.8.235", "192.168.1.10"]);
        // Les deux réseaux sont cadrables pendant la pose.
        for ip in ["10.0.8.64", "192.168.1.64"] {
            assert!(guarded_url(&cam(ip, Family::Axis), &got).is_ok(), "{ip}");
        }
        // Énumération ratée : l'adresse tenue par Lenscout compte quand même…
        let got = guard_interfaces(&active, &[], Some(&held), here);
        assert!(guarded_url(&cam("192.168.1.64", Family::Axis), &got).is_ok());
        // …si elle est vraiment sur le poste.
        let got = guard_interfaces(&active, &[], Some(&held), |_| false);
        assert!(guarded_url(&cam("192.168.1.64", Family::Axis), &got).is_err());
        // …et sur une carte active.
        let got = guard_interfaces(&[], &[], Some(&held), here);
        assert!(got.is_empty());
        // Rien de posé : les adresses des cartes actives, sans la boucle locale.
        let got = guard_interfaces(&active, &local, None, here);
        assert_eq!(got.len(), 2);
        assert!(guarded_url(&cam("127.0.0.2", Family::Axis), &got).is_err());
    }

    #[test]
    fn la_garde_ignore_les_cartes_que_le_scan_ne_propose_pas() {
        let here = |_: Ipv4Addr| true;
        let active = [si("en0", "10.0.8.235", "255.255.255.0")];
        // Tunnel VPN, pont de partage, docker, carte débranchée : jamais cadrables.
        let local = [
            si("en0", "10.0.8.235", "255.255.255.0"),
            si("utun3", "100.64.0.2", "255.192.0.0"),
            si("bridge100", "192.168.2.1", "255.255.255.0"),
            si("docker0", "172.17.0.1", "255.255.0.0"),
            si("en7", "192.168.50.10", "255.255.255.0"),
        ];
        let got = guard_interfaces(&active, &local, None, here);
        for ip in ["100.64.0.9", "192.168.2.9", "172.17.0.9", "192.168.50.64"] {
            assert!(guarded_url(&cam(ip, Family::Axis), &got).is_err(), "{ip}");
        }
        // Linux : une adresse étiquetée (`eth0:1`) appartient à `eth0`.
        let active = [si("eth0", "10.0.8.235", "255.255.255.0")];
        let local = [si("eth0:1", "192.168.1.10", "255.255.255.0")];
        let got = guard_interfaces(&active, &local, None, here);
        assert!(guarded_url(&cam("192.168.1.64", Family::Axis), &got).is_ok());
    }

    #[test]
    fn hors_sous_reseau_refuse_avant_toute_requete() {
        let http = fake(1);
        let state = StreamState::default();
        for (ip, ifaces) in [("198.51.100.7", vec![iface()]), ("192.0.3.7", vec![iface()]), ("192.0.2.20", vec![])] {
            let run = state.replace();
            let r = start_guarded(&state, run, http.clone(), &cam(ip, Family::Axis), None, &ifaces, creds(), |_| Ok(()));
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
        let r = start_guarded(&state, run, fake(1), &cam("192.0.2.20", Family::Other), None, &[iface()], creds(), |_| Ok(()));
        assert_eq!(r.err().as_deref(), Some("unsupported_brand"));
        assert!(!active(&state));
    }

    #[tokio::test]
    async fn dans_le_sous_reseau_la_requete_part_avec_le_login_sans_secret() {
        let http = fake(0);
        let state = StreamState::default();
        let run = state.replace();
        let h = start_guarded(&state, run, http.clone(), &cam("192.0.2.20", Family::Axis), None, &[iface()], creds(), |_| Ok(()))
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
        let h = start_guarded(&state, run, http.clone(), &cam("192.0.2.20", Family::Axis), None, &[iface()], creds(), |_| Ok(()))
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

    #[tokio::test]
    async fn la_vue_choisie_part_dans_l_url_du_flux() {
        let http = fake(0);
        let state = StreamState::default();
        let run = state.replace();
        let h = start_guarded(&state, run, http.clone(), &cam("192.0.2.20", Family::Axis), Some(3), &[iface()], creds(), |_| Ok(()))
            .unwrap();
        let _ = h.await;
        assert!(http.requests()[0].url.ends_with("&camera=3"), "{}", http.requests()[0].url);
    }

    #[tokio::test]
    async fn les_vues_se_lisent_sous_la_meme_garde_et_seulement_sur_axis() {
        let http = FakeHttp::new()
            .on(Method::Get, "/axis-cgi/param.cgi?action=list&group=Properties.Image.NbrOfViews", 200, "root.Properties.Image.NbrOfViews=3\n")
            .on(Method::Get, "/axis-cgi/param.cgi?action=list&group=Image", 200, "");
        let v = views_guarded(&http, &cam("192.0.2.20", Family::Axis), &[iface()], || Ok(creds())).await.unwrap();
        assert_eq!(v.len(), 3);
        // Hors sous-réseau : refusé avant toute requête, le compte n'est pas lu.
        let silent = FakeHttp::new();
        let r = views_guarded(&silent, &cam("198.51.100.7", Family::Axis), &[iface()], || panic!("compte lu")).await;
        assert_eq!(r.err().as_deref(), Some("camera_off_subnet"));
        // Hikvision : une vue, aucune requête.
        let v = views_guarded(&silent, &cam("192.0.2.21", Family::Hikvision), &[iface()], || Ok(creds())).await.unwrap();
        assert_eq!(v.len(), 1);
        assert!(silent.requests().is_empty());
    }
}
