//! Orchestration de la découverte : une ligne par caméra, émise au fil de l'eau.
//!
//! Point d'extension : une nouvelle source (SADP, tâche 14) est un `Probe` de
//! plus dans la liste `probes` de `run_scan`, avec son propre `Datagram` ;
//! l'orchestration ne connaît aucun protocole.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::arp::{ArpSource, ScanInterface};
use super::{mdns, wsd};
use crate::model::{Activation, Camera, Family, Sighting, Source};
use crate::oui::camera_brand_for_mac;
use crate::transport::{CameraHttp, Datagram, NetError};
use crate::vapix;

/// Instants d'envoi de la requête, depuis le début de l'écoute : un paquet
/// multicast se perd, on le renvoie.
const SEND_AT: [Duration; 3] = [Duration::ZERO, Duration::from_secs(1), Duration::from_secs(3)];
/// Plus grand datagramme lu (taille maximale d'un paquet mDNS).
const RECV_BUF: usize = 9216;
/// Capacité du canal interne des événements.
const EVENTS: usize = 1024;

/// Une source de découverte : ce qu'elle envoie, où, et comment lire la réponse.
pub trait Probe: Send + Sync {
    fn source(&self) -> Source;
    fn group(&self) -> SocketAddrV4;
    fn build(&self) -> Vec<u8>;
    fn parse(&self, packet: &[u8], src: Ipv4Addr) -> Vec<Sighting>;
    /// Le socket se lie-t-il au port du groupe ? Non pour un protocole dont la
    /// réponse revient en unicast sur le port source.
    fn bind_group_port(&self) -> bool {
        true
    }
}

pub struct MdnsProbe;
pub struct WsdProbe;

/// Ouvre le socket qui convient à la sonde sur l'interface choisie.
pub fn open_probe_socket(probe: &dyn Probe, iface: &ScanInterface) -> std::io::Result<Arc<dyn Datagram>> {
    Ok(if probe.bind_group_port() {
        Arc::new(super::socket::open_multicast(iface, probe.group())?)
    } else {
        Arc::new(super::socket::open_ephemeral(iface)?)
    })
}

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ScanEvent {
    Upsert { camera: Camera },
    Done,
}

#[derive(Clone)]
pub struct ScanConfig {
    pub iface: ScanInterface,
    /// Durée d'écoute des sondes (6 s en usage normal).
    pub listen: Duration,
}

/// Ce que les tâches de fond rapportent à la boucle principale.
enum Event {
    Seen(Sighting),
    Enriched { idx: usize, ip: Ipv4Addr, info: Option<vapix::DeviceInfo>, activation: Activation },
}

fn source_name(s: Source) -> &'static str {
    match s {
        Source::Mdns => "mdns",
        Source::Wsd => "wsd",
        Source::Sadp => "sadp",
        Source::Oui => "oui",
    }
}

/// Écrit le datagramme en `<source>-<ip>-<n>.bin` ; ne remplace jamais un
/// fichier existant. Les erreurs d'écriture sont ignorées : la capture ne doit
/// pas gêner la découverte.
fn capture(dir: &std::path::Path, source: Source, ip: Ipv4Addr, packet: &[u8]) {
    use std::io::Write;
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    for n in 0.. {
        let path = dir.join(format!("{}-{ip}-{n}.bin", source_name(source)));
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                let _ = f.write_all(packet);
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return,
        }
    }
}

/// Envoie la requête de la sonde aux instants `SEND_AT`.
async fn send_loop(probe: Arc<dyn Probe>, dg: Arc<dyn Datagram>, start: Instant) {
    let query = probe.build();
    let dest = SocketAddr::V4(probe.group());
    for at in SEND_AT {
        tokio::time::sleep_until(start + at).await;
        // Un envoi perdu est repris au tour suivant.
        let _ = dg.send_to(&query, dest).await;
    }
}

/// Erreurs de lecture consécutives après lesquelles on abandonne la sonde.
const MAX_RECV_ERRORS: usize = 20;

/// Lit les réponses. Une erreur de lecture n'arrête pas la sonde : sous
/// Windows, un ICMP « port inaccessible » en réponse à un de nos envois
/// remonte en `WSAECONNRESET` sur le prochain `recv`. `Timeout` (le faux n'a
/// plus rien à rejouer ; le vrai socket n'en rend pas) et `Cancelled` y mettent
/// fin, de même qu'une panne persistante (`MAX_RECV_ERRORS` de suite).
async fn recv_loop(
    probe: Arc<dyn Probe>,
    dg: Arc<dyn Datagram>,
    events: mpsc::Sender<Event>,
    capture_dir: Option<PathBuf>,
) {
    let mut buf = vec![0u8; RECV_BUF];
    let mut errors = 0;
    loop {
        let (n, from) = match dg.recv_from(&mut buf).await {
            Ok(r) => {
                errors = 0;
                r
            }
            Err(NetError::Timeout | NetError::Cancelled) => return,
            Err(_) => {
                errors += 1;
                if errors >= MAX_RECV_ERRORS {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let IpAddr::V4(src) = from.ip() else { continue };
        let packet = &buf[..n];
        if let Some(dir) = &capture_dir {
            capture(dir, probe.source(), src, packet);
        }
        for sighting in probe.parse(packet, src) {
            if events.send(Event::Seen(sighting)).await.is_err() {
                return;
            }
        }
    }
}

/// Résultat de `Scan::find`.
enum Target {
    Row(usize),
    New,
    Ignore,
}

struct Scan {
    cameras: Vec<Camera>,
    /// IP dont l'enrichissement VAPIX est déjà parti.
    enriching: HashSet<Ipv4Addr>,
    /// Lignes enrichies par VAPIX ; `true` si le modèle vient de VAPIX.
    enriched: HashMap<usize, bool>,
    pending: usize,
    http: Arc<dyn CameraHttp>,
    events: mpsc::Sender<Event>,
    out: mpsc::Sender<ScanEvent>,
    cancel: CancellationToken,
    tasks: JoinSet<()>,
}

impl Scan {
    /// Où va une observation. Avec MAC : la caméra de même MAC, ou à défaut la
    /// caméra de même IP qui n'a pas encore de MAC. Sans MAC : la caméra de
    /// même IP, à condition qu'elle soit seule — sur une IP partagée (plusieurs
    /// Axis neuves en 192.168.0.90) on ne sait pas qui parle.
    fn find(&self, s: &Sighting) -> Target {
        match &s.mac {
            Some(mac) => self
                .cameras
                .iter()
                .position(|c| c.mac.as_ref() == Some(mac))
                .or_else(|| self.cameras.iter().position(|c| c.ip == s.ip && c.mac.is_none()))
                .map_or(Target::New, Target::Row),
            None => {
                let mut at_ip = self.cameras.iter().enumerate().filter(|(_, c)| c.ip == s.ip);
                match (at_ip.next(), at_ip.next()) {
                    (None, _) => Target::New,
                    (Some((i, _)), None) => Target::Row(i),
                    _ => Target::Ignore,
                }
            }
        }
    }

    /// Plusieurs caméras de MAC différentes sur la même IP.
    fn ip_is_shared(&self, ip: Ipv4Addr) -> bool {
        self.cameras.iter().filter(|c| c.ip == ip && c.mac.is_some()).count() > 1
    }

    /// Émet la caméra `idx` ; un récepteur disparu arrête le balayage.
    async fn emit(&self, idx: usize) {
        let camera = self.cameras[idx].clone();
        if self.out.send(ScanEvent::Upsert { camera }).await.is_err() {
            self.cancel.cancel();
        }
    }

    async fn on_sighting(&mut self, s: Sighting) {
        let idx = match self.find(&s) {
            Target::Ignore => return,
            Target::Row(i) => {
                let before = self.cameras[i].clone();
                self.cameras[i].merge(&s);
                // Une observation avec MAC dit où est la caméra maintenant
                // (DHCP, autre installateur) ; ce qu'on savait de l'ancienne
                // adresse ne vaut plus.
                if s.model.is_some() {
                    self.enriched.entry(i).and_modify(|m| *m = false);
                }
                if s.mac.is_some() && self.cameras[i].ip != s.ip {
                    self.enriching.remove(&self.cameras[i].ip);
                    self.cameras[i].ip = s.ip;
                }
                if self.cameras[i] == before {
                    return;
                }
                i
            }
            Target::New => {
                self.cameras.push(Camera::from_sighting(&s));
                self.cameras.len() - 1
            }
        };
        self.drop_vapix_if_shared(idx).await;
        self.enrich_if_axis(idx);
        self.emit(idx).await;
    }

    /// Si l'IP de `idx` vient de devenir partagée, ce que VAPIX a dit des
    /// autres lignes de cette IP peut venir de n'importe quelle caméra : on
    /// l'oublie (le modèle seulement s'il vient de VAPIX, pas de l'annonce).
    async fn drop_vapix_if_shared(&mut self, idx: usize) {
        let ip = self.cameras[idx].ip;
        if !self.ip_is_shared(ip) {
            return;
        }
        for i in 0..self.cameras.len() {
            if i == idx || self.cameras[i].ip != ip {
                continue;
            }
            let Some(model_from_vapix) = self.enriched.remove(&i) else { continue };
            let cam = &mut self.cameras[i];
            cam.serial = None;
            cam.firmware = None;
            cam.activation = Activation::Unknown;
            if model_from_vapix {
                cam.model = None;
            }
            self.emit(i).await;
        }
    }

    /// Une seule fois par IP : identité et état d'activation par VAPIX. Jamais
    /// sur une IP partagée : on ne saurait pas quelle caméra répond.
    fn enrich_if_axis(&mut self, idx: usize) {
        let cam = &self.cameras[idx];
        if cam.family != Family::Axis || self.ip_is_shared(cam.ip) || !self.enriching.insert(cam.ip) {
            return;
        }
        let (ip, base) = (cam.ip, cam.base_url());
        let (http, events) = (self.http.clone(), self.events.clone());
        self.pending += 1;
        self.tasks.spawn(async move {
            let (info, activation) =
                tokio::join!(vapix::device_info(&*http, &base), vapix::activation_state(&*http, &base));
            let _ = events.send(Event::Enriched { idx, ip, info: info.ok(), activation }).await;
        });
    }

    /// `idx` désigne la ligne (les lignes ne sont jamais retirées). La réponse
    /// est jetée si la caméra a changé d'IP depuis, ou si l'IP est devenue
    /// partagée : elle peut venir d'une autre caméra.
    async fn on_enriched(
        &mut self,
        idx: usize,
        ip: Ipv4Addr,
        info: Option<vapix::DeviceInfo>,
        activation: Activation,
    ) {
        self.pending -= 1;
        if self.cameras[idx].ip != ip || self.ip_is_shared(ip) {
            return;
        }
        let before = self.cameras[idx].clone();
        let cam = &mut self.cameras[idx];
        let mut model_from_vapix = false;
        if let Some(info) = info {
            // La marque et le modèle déjà connus (annonce de la caméra) restent.
            if cam.model.is_none() {
                model_from_vapix = info.model.is_some();
                cam.model = info.model;
            }
            if cam.brand.is_none() {
                cam.brand = info.brand;
            }
            cam.serial = info.serial.or(cam.serial.take());
            cam.firmware = info.firmware.or(cam.firmware.take());
        }
        if activation != Activation::Unknown {
            cam.activation = activation;
        }
        if self.cameras[idx] != before {
            self.enriched.insert(idx, model_from_vapix);
            self.emit(idx).await;
        }
    }

    async fn handle(&mut self, ev: Event) {
        match ev {
            Event::Seen(s) => self.on_sighting(s).await,
            Event::Enriched { idx, ip, info, activation } => self.on_enriched(idx, ip, info, activation).await,
        }
    }

    /// Traite ce qui reste en file puis attend les enrichissements en cours.
    async fn settle(&mut self, irx: &mut mpsc::Receiver<Event>) {
        loop {
            if let Ok(ev) = irx.try_recv() {
                self.handle(ev).await;
                continue;
            }
            if self.pending == 0 {
                return;
            }
            let cancel = self.cancel.clone();
            tokio::select! {
                _ = cancel.cancelled() => return,
                Some(ev) = irx.recv() => self.handle(ev).await,
            }
        }
    }

    /// Voisins ARP : une MAC de marque caméra inconnue jusque-là devient une
    /// ligne (source `Oui`) ; une caméra connue par son IP sans MAC reçoit la
    /// sienne.
    async fn on_arp(&mut self, table: HashMap<Ipv4Addr, String>) {
        let mut entries: Vec<_> = table.into_iter().collect();
        entries.sort();
        for (ip, mac) in entries {
            let brand = camera_brand_for_mac(&mac);
            let known = self.cameras.iter().position(|c| c.ip == ip && c.mac.is_none());
            if self.cameras.iter().any(|c| c.mac.as_deref() == Some(mac.as_str())) {
                continue;
            }
            let sighting = Sighting {
                source: Source::Oui,
                ip,
                mac: Some(mac.clone()),
                family: brand.as_ref().map(|(f, _)| *f),
                brand: brand.map(|(_, b)| b),
                model: None,
                serial: None,
                firmware: None,
                activation: Activation::Unknown,
                http_port: None,
            };
            match known {
                Some(i) if sighting.family.is_none() => {
                    self.cameras[i].mac = Some(mac);
                    self.emit(i).await;
                }
                Some(_) => self.on_sighting(sighting).await,
                None if sighting.family.is_some() => self.on_sighting(sighting).await,
                None => {}
            }
        }
    }
}

pub async fn run_scan(
    probes: Vec<(Arc<dyn Probe>, Arc<dyn Datagram>)>,
    http: Arc<dyn CameraHttp>,
    arp: Arc<dyn ArpSource>,
    cfg: ScanConfig,
    tx: mpsc::Sender<ScanEvent>,
    cancel: CancellationToken,
) {
    let capture_dir = std::env::var_os("LENSCOUT_CAPTURE_DIR").map(PathBuf::from);
    run_scan_with_capture(probes, http, arp, cfg, tx, cancel, capture_dir).await;
}

/// `run_scan` avec le dossier de capture en paramètre (testable sans toucher
/// l'environnement du processus). Émet toujours `Done` à la fin, même annulé.
#[allow(clippy::too_many_arguments)]
pub async fn run_scan_with_capture(
    probes: Vec<(Arc<dyn Probe>, Arc<dyn Datagram>)>,
    http: Arc<dyn CameraHttp>,
    arp: Arc<dyn ArpSource>,
    cfg: ScanConfig,
    tx: mpsc::Sender<ScanEvent>,
    cancel: CancellationToken,
    capture_dir: Option<PathBuf>,
) {
    let (etx, mut erx) = mpsc::channel(EVENTS);
    // Jeton enfant : un récepteur disparu arrête le balayage sans annuler
    // le jeton de l'appelant.
    let cancel = cancel.child_token();
    let mut scan = Scan {
        cameras: vec![],
        enriching: HashSet::new(),
        enriched: HashMap::new(),
        pending: 0,
        http,
        events: etx.clone(),
        out: tx.clone(),
        cancel: cancel.clone(),
        tasks: JoinSet::new(),
    };

    let start = Instant::now();
    let mut probe_tasks = JoinSet::new();
    for (probe, dg) in probes {
        probe_tasks.spawn(send_loop(probe.clone(), dg.clone(), start));
        probe_tasks.spawn(recv_loop(probe, dg, etx.clone(), capture_dir.clone()));
    }

    let deadline = start + cfg.listen;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep_until(deadline) => break,
            Some(ev) = erx.recv() => scan.handle(ev).await,
        }
    }
    // Fin d'écoute : les envois et lectures restants sont abandonnés.
    drop(probe_tasks);

    if !cancel.is_cancelled() {
        scan.settle(&mut erx).await;
    }
    if !cancel.is_cancelled() {
        let table = tokio::select! {
            _ = cancel.cancelled() => None,
            t = arp.sweep_and_read(&cfg.iface) => Some(t),
        };
        if let Some(table) = table {
            scan.on_arp(table).await;
            scan.settle(&mut erx).await;
        }
    }
    let _ = tx.send(ScanEvent::Done).await;
}

impl Probe for MdnsProbe {
    fn source(&self) -> Source { Source::Mdns }
    fn group(&self) -> SocketAddrV4 { mdns::GROUP }
    fn build(&self) -> Vec<u8> { mdns::build_query() }
    fn parse(&self, packet: &[u8], src: Ipv4Addr) -> Vec<Sighting> { mdns::parse_response(packet, src) }
}

impl Probe for WsdProbe {
    fn source(&self) -> Source { Source::Wsd }
    fn group(&self) -> SocketAddrV4 { wsd::GROUP }
    fn build(&self) -> Vec<u8> { wsd::build_probe(uuid::Uuid::new_v4()) }
    // Les ProbeMatches reviennent en unicast sur notre port source : partir du
    // 3702 les ferait prendre par le service WSD du système (Windows).
    fn bind_group_port(&self) -> bool { false }
    fn parse(&self, packet: &[u8], src: Ipv4Addr) -> Vec<Sighting> {
        wsd::parse_probe_match(packet, src).into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::SocketAddr;

    use async_trait::async_trait;
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::rdata::{A, PTR, SRV, TXT};
    use hickory_proto::rr::{Name, RData, Record};

    use crate::model::{Activation, Family};
    use crate::testing::{FakeDatagram, FakeHttp};
    use crate::transport::{Method, NetError};

    const INSTANCE: &str = "AXIS M3106-L Mk II - ACCC8E123456._axis-video._tcp.local.";
    const WSD_AXIS: &str = include_str!("../../tests/fixtures/wsd_axis_probematch.xml");
    const DEVICE_INFO: &[u8] = include_bytes!("../../tests/fixtures/vapix_basicdeviceinfo.json");

    fn name(s: &str) -> Name {
        let labels: Vec<&[u8]> = s.split('.').filter(|l| !l.is_empty()).map(str::as_bytes).collect();
        let mut n = Name::from_labels(labels).unwrap();
        n.set_fqdn(true);
        n
    }

    fn record(owner: &str, data: RData) -> Record {
        Record::from_rdata(name(owner), 120, data)
    }

    /// Réponse mDNS d'une Axis fictive en 192.0.2.21.
    fn axis_response_packet() -> Vec<u8> {
        let mut m = Message::response(0, OpCode::Query);
        m.metadata.message_type = MessageType::Response;
        m.metadata.authoritative = true;
        for r in [
            record("_axis-video._tcp.local.", RData::PTR(PTR(name(INSTANCE)))),
            record(INSTANCE, RData::SRV(SRV::new(0, 0, 80, name("axis-accc8e123456.local.")))),
            record(
                INSTANCE,
                RData::TXT(TXT::new(vec![
                    "macaddress=AC:CC:8E:12:34:56".to_string(),
                    "model=M3106-L Mk II".to_string(),
                ])),
            ),
            record("axis-accc8e123456.local.", RData::A(A("192.0.2.21".parse().unwrap()))),
        ] {
            m.add_answer(r);
        }
        m.to_vec().unwrap()
    }

    /// Même caméra vue par WS-Discovery, sans MAC dans les scopes.
    fn wsd_without_mac(ip: &str) -> Vec<u8> {
        WSD_AXIS
            .replace("192.0.2.11", ip)
            .replace(" onvif://www.onvif.org/MAC/AC:CC:8E:12:34:56", "")
            .into_bytes()
    }

    fn from(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    struct FakeArp(HashMap<Ipv4Addr, String>);

    #[async_trait]
    impl ArpSource for FakeArp {
        async fn sweep_and_read(&self, _iface: &ScanInterface) -> HashMap<Ipv4Addr, String> {
            self.0.clone()
        }
    }

    fn arp(entries: &[(&str, &str)]) -> Arc<FakeArp> {
        Arc::new(FakeArp(entries.iter().map(|(ip, mac)| (ip.parse().unwrap(), mac.to_string())).collect()))
    }

    fn axis_http() -> Arc<FakeHttp> {
        Arc::new(
            FakeHttp::new()
                .on(Method::Post, "/axis-cgi/basicdeviceinfo.cgi", 200, DEVICE_INFO)
                .on(Method::Get, "/axis-cgi/pwdgrp.cgi", 200, "root"),
        )
    }

    fn cfg() -> ScanConfig {
        ScanConfig {
            iface: ScanInterface {
                name: "eth0".into(),
                ip: "192.0.2.2".parse().unwrap(),
                mask: "255.255.255.0".parse().unwrap(),
            },
            listen: Duration::from_secs(6),
        }
    }

    type Pair = (Arc<dyn Probe>, Arc<dyn Datagram>);

    fn probe_pair(
        p: Arc<dyn Probe>,
        replies: Vec<(Vec<u8>, SocketAddr)>,
    ) -> (Pair, Arc<FakeDatagram>) {
        let dg = Arc::new(FakeDatagram::new(replies));
        ((p, dg.clone() as Arc<dyn Datagram>), dg)
    }

    async fn scan(
        probes: Vec<(Arc<dyn Probe>, Arc<dyn Datagram>)>,
        http: Arc<dyn CameraHttp>,
        arp: Arc<dyn ArpSource>,
    ) -> Vec<ScanEvent> {
        let (tx, mut rx) = mpsc::channel(256);
        run_scan(probes, http, arp, cfg(), tx, CancellationToken::new()).await;
        let mut out = vec![];
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    fn cameras(events: &[ScanEvent]) -> Vec<&Camera> {
        events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Upsert { camera } => Some(camera),
                ScanEvent::Done => None,
            })
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn mdns_reply_emits_axis_then_enriched() {
        let (p, _) = probe_pair(Arc::new(MdnsProbe), vec![(axis_response_packet(), from("192.0.2.21", 5353))]);
        let events = scan(vec![p], axis_http(), arp(&[])).await;
        let cams = cameras(&events);
        assert!(cams.len() >= 2, "une ligne brute puis une ligne enrichie");
        assert_eq!(cams[0].serial, None);
        let last = cams.last().unwrap();
        assert_eq!(last.mac.as_deref(), Some("AC:CC:8E:12:34:56"));
        assert_eq!(last.family, Family::Axis);
        assert_eq!(last.serial.as_deref(), Some("ACCC8E123456"));
        assert_eq!(last.firmware.as_deref(), Some("11.11.73"));
        assert_eq!(last.activation, Activation::New);
    }

    #[tokio::test(start_paused = true)]
    async fn same_camera_from_mdns_and_wsd_is_one_row() {
        let (m, _) = probe_pair(Arc::new(MdnsProbe), vec![(axis_response_packet(), from("192.0.2.21", 5353))]);
        let (w, _) = probe_pair(Arc::new(WsdProbe), vec![(wsd_without_mac("192.0.2.21"), from("192.0.2.21", 3702))]);
        let events = scan(vec![m, w], axis_http(), arp(&[])).await;
        let cams = cameras(&events);
        // Chaque Upsert porte l'état complet : la clé de la ligne, c'est l'IP ici
        // (mDNS donne la MAC, WSD seulement l'IP) et il n'y en a qu'une.
        assert!(cams.iter().all(|c| c.ip == "192.0.2.21".parse::<Ipv4Addr>().unwrap()));
        let last = cams.last().unwrap();
        assert_eq!(last.mac.as_deref(), Some("AC:CC:8E:12:34:56"));
        assert!(last.sources.contains(&Source::Mdns) && last.sources.contains(&Source::Wsd));
        assert_eq!(last.sources.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn wsd_without_mac_gets_its_mac_from_arp_on_the_same_row() {
        let (w, _) = probe_pair(Arc::new(WsdProbe), vec![(wsd_without_mac("192.0.2.21"), from("192.0.2.21", 3702))]);
        let events = scan(vec![w], axis_http(), arp(&[("192.0.2.21", "AC:CC:8E:12:34:56")])).await;
        let cams = cameras(&events);
        assert!(cams.iter().all(|c| c.ip == "192.0.2.21".parse::<Ipv4Addr>().unwrap()));
        let last = cams.last().unwrap();
        // la MAC vient de l'ARP, sur la ligne déjà connue
        assert_eq!(last.mac.as_deref(), Some("AC:CC:8E:12:34:56"));
        assert_eq!(last.sources, vec![Source::Wsd, Source::Oui]);
    }

    #[tokio::test(start_paused = true)]
    async fn two_cameras_with_different_macs_stay_two_rows() {
        let wsd_a = WSD_AXIS.replace("192.0.2.11", "192.0.2.31").into_bytes();
        let wsd_b = WSD_AXIS.replace("192.0.2.11", "192.0.2.32").replace("AC:CC:8E:12:34:56", "AC:CC:8E:65:43:21").into_bytes();
        let (w, _) = probe_pair(
            Arc::new(WsdProbe),
            vec![(wsd_a, from("192.0.2.31", 3702)), (wsd_b, from("192.0.2.32", 3702))],
        );
        let events = scan(vec![w], axis_http(), arp(&[])).await;
        let ips: std::collections::HashSet<_> = cameras(&events).iter().map(|c| c.ip).collect();
        assert_eq!(ips.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn oui_only_device_appears() {
        let events = scan(vec![], axis_http(), arp(&[("192.0.2.30", "00:BC:99:11:22:33")])).await;
        let cams = cameras(&events);
        assert_eq!(cams.len(), 1);
        assert_eq!(cams[0].family, Family::Hikvision);
        assert_eq!(cams[0].sources, vec![Source::Oui]);
        assert_eq!(cams[0].mac.as_deref(), Some("00:BC:99:11:22:33"));
    }

    #[tokio::test(start_paused = true)]
    async fn non_camera_arp_entries_ignored() {
        let events = scan(vec![], axis_http(), arp(&[("192.0.2.40", "A4:5E:60:11:22:33")])).await;
        assert!(cameras(&events).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn axis_known_by_oui_is_enriched_too() {
        let events = scan(vec![], axis_http(), arp(&[("192.0.2.50", "AC:CC:8E:12:34:56")])).await;
        let last = *cameras(&events).last().unwrap();
        assert_eq!(last.family, Family::Axis);
        assert_eq!(last.serial.as_deref(), Some("ACCC8E123456"));
    }

    #[tokio::test(start_paused = true)]
    async fn unreachable_axis_stays_listed_without_enrichment() {
        let (p, _) = probe_pair(Arc::new(MdnsProbe), vec![(axis_response_packet(), from("192.0.2.21", 5353))]);
        let events = scan(vec![p], Arc::new(FakeHttp::new()), arp(&[])).await;
        let last = *cameras(&events).last().unwrap();
        assert_eq!(last.serial, None);
        assert_eq!(last.activation, Activation::Unknown);
        assert!(matches!(events.last(), Some(ScanEvent::Done)));
    }

    #[tokio::test(start_paused = true)]
    async fn garbage_packets_are_ignored() {
        let (p, _) = probe_pair(
            Arc::new(MdnsProbe),
            vec![(vec![0xff; 40], from("192.0.2.21", 5353)), (vec![], from("192.0.2.22", 5353))],
        );
        let events = scan(vec![p], axis_http(), arp(&[])).await;
        assert!(cameras(&events).is_empty());
        assert!(matches!(events.last(), Some(ScanEvent::Done)));
    }

    #[tokio::test(start_paused = true)]
    async fn ends_with_done() {
        let events = scan(vec![], axis_http(), arp(&[])).await;
        assert!(matches!(events.as_slice(), [ScanEvent::Done]));
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_stops_quickly() {
        let (p, _) = probe_pair(Arc::new(MdnsProbe), vec![]);
        let (tx, mut rx) = mpsc::channel(256);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let t = tokio::time::Instant::now();
        run_scan(vec![p], axis_http(), arp(&[]), cfg(), tx, cancel).await;
        assert!(t.elapsed() < Duration::from_millis(500));
        let mut last = None;
        while let Ok(ev) = rx.try_recv() {
            last = Some(ev);
        }
        assert!(matches!(last, Some(ScanEvent::Done)));
    }

    #[tokio::test(start_paused = true)]
    async fn probes_are_sent_three_times() {
        let (m, mdg) = probe_pair(Arc::new(MdnsProbe), vec![]);
        let (w, wdg) = probe_pair(Arc::new(WsdProbe), vec![]);
        let t = tokio::time::Instant::now();
        scan(vec![m, w], axis_http(), arp(&[])).await;
        assert_eq!(mdg.sent().len(), 3);
        assert_eq!(wdg.sent().len(), 3);
        assert!(mdg.sent().iter().all(|(_, to)| *to == SocketAddr::V4(mdns::GROUP)));
        assert!(wdg.sent().iter().all(|(_, to)| *to == SocketAddr::V4(wsd::GROUP)));
        assert!(t.elapsed() >= Duration::from_secs(6));
    }

    #[tokio::test(start_paused = true)]
    async fn captures_received_datagrams_when_a_directory_is_given() {
        let dir = std::env::temp_dir().join(format!("lenscout-capture-{}", uuid::Uuid::new_v4()));
        let (p, _) = probe_pair(Arc::new(MdnsProbe), vec![(axis_response_packet(), from("192.0.2.21", 5353))]);
        let (tx, _rx) = mpsc::channel(256);
        run_scan_with_capture(vec![p], axis_http(), arp(&[]), cfg(), tx, CancellationToken::new(), Some(dir.clone())).await;
        let written = std::fs::read(dir.join("mdns-192.0.2.21-0.bin")).unwrap();
        assert_eq!(written, axis_response_packet());
    }

    fn wsd_at(ip: &str, mac: &str) -> Vec<u8> {
        WSD_AXIS.replace("192.0.2.11", ip).replace("AC:CC:8E:12:34:56", mac).into_bytes()
    }

    /// Dernier état émis pour chaque MAC.
    fn last_by_mac(events: &[ScanEvent]) -> HashMap<String, &Camera> {
        let mut out = HashMap::new();
        for c in cameras(events) {
            if let Some(m) = &c.mac {
                out.insert(m.clone(), c);
            }
        }
        out
    }

    #[tokio::test(start_paused = true)]
    async fn factory_ip_shared_by_two_macs_is_neither_enriched_nor_mixed() {
        let http = axis_http();
        let (w, _) = probe_pair(
            Arc::new(WsdProbe),
            vec![
                (wsd_at("192.0.2.90", "AC:CC:8E:00:00:01"), from("192.0.2.90", 3702)),
                (wsd_at("192.0.2.90", "AC:CC:8E:00:00:02"), from("192.0.2.90", 3702)),
                // sans MAC, sur une IP partagée : on ne sait pas qui parle
                (wsd_without_mac("192.0.2.90"), from("192.0.2.90", 3702)),
            ],
        );
        let events = scan(vec![w], http.clone(), arp(&[])).await;
        let rows = last_by_mac(&events);
        assert_eq!(rows.len(), 2);
        for cam in rows.values() {
            assert_eq!(cam.serial, None);
            assert_eq!(cam.firmware, None);
            assert_eq!(cam.activation, Activation::Unknown);
        }
        assert!(cameras(&events).iter().all(|c| c.mac.is_some()), "aucune ligne sans MAC");
    }

    #[tokio::test(start_paused = true)]
    async fn camera_changing_ip_keeps_one_row_on_the_new_ip() {
        let http = axis_http();
        let moved = WSD_AXIS.replace("192.0.2.11:80", "192.0.2.22:8080").into_bytes();
        let (w, _) = probe_pair(
            Arc::new(WsdProbe),
            vec![
                (wsd_at("192.0.2.21", "AC:CC:8E:12:34:56"), from("192.0.2.21", 3702)),
                (moved, from("192.0.2.22", 3702)),
            ],
        );
        let events = scan(vec![w], http.clone(), arp(&[])).await;
        assert!(cameras(&events).iter().all(|c| c.mac.as_deref() == Some("AC:CC:8E:12:34:56")));
        let last = *cameras(&events).last().unwrap();
        assert_eq!(last.ip, "192.0.2.22".parse::<Ipv4Addr>().unwrap());
        assert_eq!(last.http_port, 8080);
        // l'enrichissement se refait à la nouvelle adresse
        assert_eq!(last.serial.as_deref(), Some("ACCC8E123456"));
        assert!(http.requests().iter().any(|r| r.url.contains("192.0.2.22:8080")));
    }

    #[test]
    fn wsd_sends_from_an_ephemeral_port_and_mdns_from_its_own() {
        assert!(!WsdProbe.bind_group_port());
        assert!(MdnsProbe.bind_group_port());
    }

    /// Rejoue un scénario d'erreurs et de paquets ; `Timeout` une fois vide.
    type Recv = Result<(Vec<u8>, SocketAddr), NetError>;

    struct Scripted {
        script: std::sync::Mutex<std::collections::VecDeque<Recv>>,
        forever_err: bool,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl Datagram for Scripted {
        async fn send_to(&self, _buf: &[u8], _dest: SocketAddr) -> Result<(), NetError> {
            Ok(())
        }
        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.forever_err {
                return Err(NetError::Io("connection reset".into()));
            }
            match self.script.lock().unwrap().pop_front() {
                Some(Ok((data, from))) => {
                    buf[..data.len()].copy_from_slice(&data);
                    Ok((data.len(), from))
                }
                Some(Err(e)) => Err(e),
                None => Err(NetError::Timeout),
            }
        }
    }

    fn scripted(items: Vec<Recv>, forever_err: bool) -> Arc<Scripted> {
        Arc::new(Scripted {
            script: std::sync::Mutex::new(items.into()),
            forever_err,
            calls: Default::default(),
        })
    }

    #[tokio::test(start_paused = true)]
    async fn receive_loop_survives_transient_errors() {
        let dg = scripted(
            vec![
                Err(NetError::Io("connection reset".into())),
                Err(NetError::Io("connection reset".into())),
                Ok((axis_response_packet(), from("192.0.2.21", 5353))),
            ],
            false,
        );
        let events = scan(vec![(Arc::new(MdnsProbe), dg as Arc<dyn Datagram>)], axis_http(), arp(&[])).await;
        assert_eq!(cameras(&events).first().map(|c| c.ip), Some("192.0.2.21".parse().unwrap()));
    }

    #[tokio::test(start_paused = true)]
    async fn receive_loop_gives_up_on_a_permanent_error() {
        let dg = scripted(vec![], true);
        let events = scan(vec![(Arc::new(MdnsProbe), dg.clone() as Arc<dyn Datagram>)], axis_http(), arp(&[])).await;
        assert!(matches!(events.last(), Some(ScanEvent::Done)));
        assert!(dg.calls.load(std::sync::atomic::Ordering::Relaxed) < 100);
    }

    #[tokio::test(start_paused = true)]
    async fn camera_outside_the_interface_subnet_is_listed() {
        for iface_ip in ["10.0.50.7", "192.0.2.7"] {
            let mut c = cfg();
            c.iface.ip = iface_ip.parse().unwrap();
            let (w, _) = probe_pair(
                Arc::new(WsdProbe),
                vec![(wsd_at("192.168.0.90", "AC:CC:8E:12:34:56"), from("192.168.0.90", 3702))],
            );
            let (tx, mut rx) = mpsc::channel(256);
            run_scan(vec![w], axis_http(), arp(&[]), c, tx, CancellationToken::new()).await;
            let mut found = false;
            while let Ok(ev) = rx.try_recv() {
                found |= matches!(ev, ScanEvent::Upsert { camera } if camera.ip == "192.168.0.90".parse::<Ipv4Addr>().unwrap());
            }
            assert!(found, "interface {iface_ip}");
        }
    }

    /// Rejoue des datagrammes, chacun après son délai.
    struct Delayed(std::sync::Mutex<std::collections::VecDeque<(Duration, Vec<u8>, SocketAddr)>>);

    #[async_trait]
    impl Datagram for Delayed {
        async fn send_to(&self, _buf: &[u8], _dest: SocketAddr) -> Result<(), NetError> {
            Ok(())
        }
        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
            let next = self.0.lock().unwrap().pop_front();
            let (delay, data, from) = next.ok_or(NetError::Timeout)?;
            tokio::time::sleep(delay).await;
            buf[..data.len()].copy_from_slice(&data);
            Ok((data.len(), from))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn identity_from_vapix_is_dropped_when_the_ip_becomes_shared() {
        let (m, _) = probe_pair(Arc::new(MdnsProbe), vec![(axis_response_packet(), from("192.0.2.21", 5353))]);
        // une seconde MAC apparaît sur la même IP, bien après l'enrichissement
        let late = Arc::new(Delayed(std::sync::Mutex::new(
            vec![(Duration::from_secs(2), wsd_at("192.0.2.21", "AC:CC:8E:00:00:02"), from("192.0.2.21", 3702))].into(),
        )));
        let events = scan(vec![m, (Arc::new(WsdProbe), late as Arc<dyn Datagram>)], axis_http(), arp(&[])).await;
        assert!(
            cameras(&events).iter().any(|c| c.serial.is_some()),
            "la ligne a bien été enrichie avant"
        );
        let rows = last_by_mac(&events);
        assert_eq!(rows.len(), 2);
        for cam in rows.values() {
            assert_eq!(cam.serial, None);
            assert_eq!(cam.firmware, None);
            assert_eq!(cam.activation, Activation::Unknown);
        }
        // le modèle annoncé par la caméra elle-même (mDNS) reste
        assert_eq!(rows["AC:CC:8E:12:34:56"].model.as_deref(), Some("AXIS M3106-L Mk II"));
    }

    #[test]
    fn scan_event_serializes_with_a_kind_tag() {
        assert_eq!(serde_json::to_string(&ScanEvent::Done).unwrap(), r#"{"kind":"done"}"#);
    }
}
