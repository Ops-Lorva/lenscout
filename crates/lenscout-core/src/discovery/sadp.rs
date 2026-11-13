// NON VÉRIFIÉ sur une vraie caméra LTS — écrit d'après :
//   cameronnewman/hikvision-tooling (MIT), internal/sadp/{scanner,commands}.go,
//   https://github.com/cameronnewman/hikvision-tooling
//   commit afa00e3db11bb47914e1f0d724c6975e0a41e218 (HEAD du 2026-11-13),
// pour le groupe 239.255.255.250:37020, le message `inquiry`, les noms de
// champs de `ProbeMatch` et la forme des messages `activate` / `update`.
//
// ENCODAGE DU MOT DE PASSE — AUCUNE SOURCE FIABLE. Cet outil met le mot de
// passe en clair dans `<Password>` ; rien dans ses sources ni dans ses tests
// n'établit qu'un firmware récent l'accepte (le SADP officiel passe par un
// échange `getencryptstring` / `exchangecode` dont aucune description publique
// de l'encodage n'a été trouvée : hiktools et hikvision-tooling ne décrivent
// que le code de réinitialisation, pas le mot de passe). `encode_password`
// refuse donc d'en inventer un : il rend `None`, et activer / changer l'IP
// d'une Hikvision par SADP rend `unsupported`. Le jour où une source publique
// décrit l'encodage, seule cette fonction change.
//
// GARDE-FOU : `encode_password` ne doit JAMAIS devenir la fonction identité
// (ni un simple base64) : le mot de passe partirait alors en clair dans un
// message multicast. Tant qu'il rend `None`, aucun message n'est construit.
//
// Aucun réseau ici : les sockets sont dans `socket.rs`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use quick_xml::Reader;
use quick_xml::events::Event;
use uuid::Uuid;

use crate::actions::ActionError;
use crate::discovery::arp::ScanInterface;
use crate::discovery::scanner::Probe;
use crate::model::{Activation, Family, Sighting, Source, normalize_mac};
use crate::secret::Secret;
use crate::transport::{Datagram, NetError};
use crate::vapix::NetworkSettings;

pub const GROUP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 37020);

/// Au-delà, ce n'est pas une réponse SADP : le datagramme est ignoré sans
/// être analysé.
const MAX_XML: usize = 64 * 1024;
/// Plus grand datagramme lu en attendant une réponse à une commande.
const RECV_BUF: usize = 9216;
/// Port de commande des messages `update` : valeur par défaut de l'outil de
/// référence, la caméra visée n'a pas annoncé le sien dans notre `Sighting`.
const DEFAULT_COMMAND_PORT: u16 = 8000;
/// Longueur maximale du texte d'un refus repris de la caméra.
const MAX_DETAIL: usize = 120;

pub struct SadpProbe;

impl Probe for SadpProbe {
    fn source(&self) -> Source {
        Source::Sadp
    }
    fn group(&self) -> SocketAddrV4 {
        GROUP
    }
    fn build(&self) -> Vec<u8> {
        build_inquiry(Uuid::new_v4())
    }
    fn parse(&self, packet: &[u8], src: Ipv4Addr, _iface: &ScanInterface) -> Vec<Sighting> {
        parse_inquiry_response(packet, src).into_iter().collect()
    }
}

pub fn build_inquiry(uuid: Uuid) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>{}</Uuid><Types>inquiry</Types></Probe>"#,
        uuid.hyphenated().to_string().to_ascii_uppercase()
    )
    .into_bytes()
}

/// Éléments feuilles d'un message (nom local → texte) et nom de la racine.
/// Un message dont la racine n'est pas refermée (coupé) ou mal formé est rejeté.
struct Fields {
    root: String,
    map: HashMap<String, String>,
}

impl Fields {
    fn get(&self, name: &str) -> Option<&str> {
        self.map.get(name).map(|s| s.trim())
    }
}

fn read_fields(xml: &[u8]) -> Option<Fields> {
    if xml.len() > MAX_XML {
        return None;
    }
    let mut reader = Reader::from_reader(xml);
    let mut root = None;
    let mut map = HashMap::new();
    let mut cur: Option<String> = None;
    let mut text = String::new();
    let (mut depth, mut closed) = (0usize, false);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.local_name().as_ref().to_string();
                if root.is_none() {
                    root = Some(name.clone());
                }
                depth += 1;
                cur = Some(name);
                text.clear();
            }
            Ok(Event::Text(t)) => {
                if cur.is_some() && text.len() <= MAX_XML {
                    text.push_str(&t.into_inner());
                }
            }
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
                closed = depth == 0;
                if let Some(name) = cur.take() {
                    map.entry(name).or_insert_with(|| std::mem::take(&mut text));
                }
            }
            // Une entité (ou une DTD qui en déclarerait) n'a rien à faire dans SADP.
            Ok(Event::GeneralRef(_) | Event::DocType(_)) => return None,
            Ok(Event::Eof) | Err(_) => break,
            Ok(_) => {}
        }
    }
    // Un message coupé avant la fermeture de sa racine est rejeté en entier.
    if !closed {
        return None;
    }
    Some(Fields { root: root?, map })
}

/// Lit un `ProbeMatch`. `None` si ce n'en est pas un, ou sans MAC valide. Une
/// adresse annoncée mais illisible fait rejeter le message ; absente, la
/// source du paquet la remplace.
pub fn parse_inquiry_response(xml: &[u8], src: Ipv4Addr) -> Option<Sighting> {
    let f = read_fields(xml)?;
    if f.root != "ProbeMatch" {
        return None;
    }
    let mac = normalize_mac(f.get("MAC")?)?;
    let ip = match f.get("IPv4Address") {
        Some(s) => s.parse().ok()?,
        None => src,
    };
    let text = |k: &str| f.get(k).filter(|s| !s.is_empty()).map(str::to_string);
    let model = text("DeviceDescription");
    let serial = text("DeviceSN");
    // Règle à corriger sur la première vraie LTS.
    let is_lts = [text("DeviceType"), model.clone(), serial.clone()]
        .iter()
        .flatten()
        .any(|s| s.to_ascii_uppercase().contains("LTS"));
    let activation = match f.get("Activated").map(str::to_ascii_lowercase).as_deref() {
        Some("true") => Activation::Activated,
        Some("false") => Activation::New,
        _ => Activation::Unknown,
    };
    Some(Sighting {
        source: Source::Sadp,
        ip,
        mac: Some(mac),
        family: Some(Family::Hikvision),
        brand: Some(if is_lts { "LTS" } else { "Hikvision" }.to_string()),
        model,
        serial,
        firmware: text("SoftwareVersion"),
        activation,
        http_port: f.get("HttpPort").and_then(|s| s.parse().ok()).filter(|p| *p != 0),
    })
}

/// Mot de passe tel que le firmware l'exige dans `<Password>`. `None` : aucune
/// source publique fiable de l'encodage (voir l'en-tête), on n'en invente pas.
pub fn encode_password(_password: &Secret) -> Option<Secret> {
    None
}

/// Le cœur sait-il configurer une Hikvision ? Suit `encode_password` : le jour
/// où l'encodage existe, le lot (`batch::plan_batch`) suit sans autre changement.
pub fn can_configure() -> bool {
    encode_password(&Secret::new(String::new())).is_some()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// `C0:56:E3:5A:7D:01` → `c0-56-e3-5a-7d-01`, la forme du message.
fn wire_mac(mac: &str) -> Option<String> {
    normalize_mac(mac).map(|m| m.to_ascii_lowercase().replace(':', "-"))
}

fn uuid_text(uuid: Uuid) -> String {
    uuid.hyphenated().to_string().to_ascii_uppercase()
}

/// Message `activate` avec un mot de passe DÉJÀ encodé.
pub(crate) fn build_activate_with(uuid: Uuid, mac: &str, encoded: &Secret) -> Option<Vec<u8>> {
    Some(
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>{}</Uuid><MAC>{}</MAC><Types>activate</Types><Password>{}</Password></Probe>"#,
            uuid_text(uuid),
            wire_mac(mac)?,
            xml_escape(encoded.expose())
        )
        .into_bytes(),
    )
}

/// Message `update` (adresse) avec un mot de passe DÉJÀ encodé.
pub(crate) fn build_update_with(uuid: Uuid, mac: &str, encoded: &Secret, net: &NetworkSettings) -> Option<Vec<u8>> {
    let addressing = match net {
        NetworkSettings::Dhcp => "<DHCP>true</DHCP>".to_string(),
        NetworkSettings::Static { ip, mask, gateway, .. } => format!(
            "<IPv4Address>{ip}</IPv4Address><CommandPort>{DEFAULT_COMMAND_PORT}</CommandPort><IPv4SubnetMask>{mask}</IPv4SubnetMask><IPv4Gateway>{}</IPv4Gateway><DHCP>false</DHCP>",
            gateway.unwrap_or(Ipv4Addr::UNSPECIFIED)
        ),
    };
    Some(
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>{}</Uuid><Types>update</Types><PWErrorParse>true</PWErrorParse><MAC>{}</MAC><Password>{}</Password>{addressing}</Probe>"#,
            uuid_text(uuid),
            wire_mac(mac)?,
            xml_escape(encoded.expose())
        )
        .into_bytes(),
    )
}

/// `None` tant que `encode_password` n'a pas de source : rien n'est construit.
pub fn build_activate(uuid: Uuid, mac: &str, password: &Secret) -> Option<Vec<u8>> {
    build_activate_with(uuid, mac, &encode_password(password)?)
}

pub fn build_update(uuid: Uuid, mac: &str, password: &Secret, net: &NetworkSettings) -> Option<Vec<u8>> {
    build_update_with(uuid, mac, &encode_password(password)?, net)
}

/// `<Result>success</Result>` → `Ok`, tout autre texte → `Err(texte)`.
/// Sans `<Result>` (écho de notre propre message, autre type de paquet) :
/// `Err` vide, que `send_and_wait` ne prend pas pour une réponse.
pub fn parse_result(xml: &[u8]) -> Result<(), String> {
    let Some(f) = read_fields(xml) else { return Err(String::new()) };
    match f.get("Result") {
        Some(r) if r.eq_ignore_ascii_case("success") => Ok(()),
        Some(r) => Err(r.chars().take(MAX_DETAIL).collect()),
        None => Err(String::new()),
    }
}

/// Envoie `msg` au groupe SADP et attend la réponse de la caméra de MAC `mac`
/// (toutes répondent en multicast ; les autres MAC, les autres UUID et notre
/// propre écho sont ignorés). `ip` n'est que celle annoncée dans l'erreur d'injoignabilité.
pub async fn send_and_wait(
    sock: &dyn Datagram,
    msg: &[u8],
    mac: &str,
    ip: Ipv4Addr,
    timeout: Duration,
) -> Result<(), ActionError> {
    let want = normalize_mac(mac).ok_or(ActionError::IdentityUnreadable)?;
    // Seule une réponse qui reprend l'UUID du message envoyé est la nôtre.
    let sent_uuid = read_fields(msg)
        .and_then(|f| f.get("Uuid").map(str::to_ascii_uppercase))
        .ok_or(ActionError::IdentityUnreadable)?;
    sock.send_to(msg, SocketAddr::V4(GROUP)).await.map_err(|_| ActionError::Unreachable { ip })?;
    let wait = async {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            let n = match sock.recv_from(&mut buf).await {
                Ok((n, _)) => n,
                Err(NetError::Timeout | NetError::Cancelled) => return Err(ActionError::Unreachable { ip }),
                // Une erreur de lecture passagère (ICMP sous Windows) ne tranche rien.
                Err(_) => continue,
            };
            let packet = &buf[..n];
            let Some(f) = read_fields(packet) else { continue };
            let same_uuid = f.get("Uuid").map(str::to_ascii_uppercase).as_deref() == Some(sent_uuid.as_str());
            if !same_uuid || f.get("Result").is_none() || f.get("MAC").and_then(normalize_mac) != Some(want.clone()) {
                continue;
            }
            return parse_result(packet).map_err(|detail| ActionError::Rejected { detail });
        }
    };
    tokio::time::timeout(timeout, wait).await.unwrap_or(Err(ActionError::Unreachable { ip }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeDatagram;

    const ACTIVATED: &[u8] = include_bytes!("../../tests/fixtures/sadp_inquiry_response_activated.xml");
    const NEW: &[u8] = include_bytes!("../../tests/fixtures/sadp_inquiry_response_new.xml");
    const MAC: &str = "C0:56:E3:5A:7D:01";

    fn src() -> Ipv4Addr {
        "192.0.2.31".parse().unwrap()
    }

    fn uuid() -> Uuid {
        Uuid::parse_str("7b2d9c10-1a2b-4c3d-9e8f-001122334455").unwrap()
    }

    #[test]
    fn inquiry_xml_exact() {
        assert_eq!(
            String::from_utf8(build_inquiry(uuid())).unwrap(),
            r#"<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>7B2D9C10-1A2B-4C3D-9E8F-001122334455</Uuid><Types>inquiry</Types></Probe>"#
        );
    }

    #[test]
    fn parses_activated_response() {
        let s = parse_inquiry_response(ACTIVATED, src()).unwrap();
        assert_eq!(s.source, Source::Sadp);
        assert_eq!(s.mac.as_deref(), Some(MAC));
        assert_eq!(s.ip, src());
        assert_eq!(s.serial.as_deref(), Some("DS-2CD2043G2-I20240101AAWRE00000001"));
        assert_eq!(s.model.as_deref(), Some("DS-2CD2043G2-I"));
        assert_eq!(s.firmware.as_deref(), Some("V5.7.15build 240101"));
        assert_eq!(s.activation, Activation::Activated);
        assert_eq!(s.family, Some(Family::Hikvision));
        assert_eq!(s.brand.as_deref(), Some("Hikvision"));
        assert_eq!(s.http_port, Some(80));
    }

    #[test]
    fn parses_new_response_and_lts_brand() {
        let s = parse_inquiry_response(NEW, "192.0.2.32".parse().unwrap()).unwrap();
        assert_eq!(s.activation, Activation::New);
        assert_eq!(s.brand.as_deref(), Some("LTS"));
        assert_eq!(s.family, Some(Family::Hikvision));
    }

    #[test]
    fn malformed_or_truncated_is_none() {
        for n in 0..ACTIVATED.len() {
            let _ = parse_inquiry_response(&ACTIVATED[..n], src());
            let _ = parse_result(&ACTIVATED[..n]);
        }
        assert!(parse_inquiry_response(b"", src()).is_none());
        assert!(parse_inquiry_response(b"<ProbeMatch><MAC>zz</MAC></ProbeMatch>", src()).is_none());
        assert!(parse_inquiry_response(b"\xff\xfe<<<>>>", src()).is_none());
        // Coupé au milieu de l'adresse : rejeté, pas d'adresse tronquée ni de repli sur la source.
        let cut = &ACTIVATED[..String::from_utf8_lossy(ACTIVATED).find("2.31").unwrap() + 2];
        assert!(parse_inquiry_response(cut, src()).is_none());
    }

    #[test]
    fn oversized_message_is_ignored() {
        let mut big = b"<ProbeMatch><MAC>c0-56-e3-5a-7d-01</MAC><X>".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_XML));
        big.extend_from_slice(b"</X></ProbeMatch>");
        assert!(parse_inquiry_response(&big, src()).is_none());
    }

    #[test]
    fn an_echoed_probe_or_unannounced_address_is_handled() {
        // Notre propre requête reçue en retour n'est pas un ProbeMatch.
        assert!(parse_inquiry_response(&build_inquiry(uuid()), src()).is_none());
        let no_ip = b"<ProbeMatch><MAC>c0-56-e3-5a-7d-01</MAC></ProbeMatch>";
        assert_eq!(parse_inquiry_response(no_ip, src()).unwrap().ip, src());
    }

    #[test]
    fn activate_message_targets_mac_and_hides_password_in_debug() {
        let encoded = Secret::new("ENC-Unique-Value".into());
        let msg = String::from_utf8(build_activate_with(uuid(), MAC, &encoded).unwrap()).unwrap();
        assert!(msg.contains("<MAC>c0-56-e3-5a-7d-01</MAC>"));
        assert!(msg.contains("<Types>activate</Types>"));
        assert!(msg.contains("<Password>ENC-Unique-Value</Password>"));
        assert!(!format!("{encoded:?} {encoded}").contains("Unique"));
        let net = NetworkSettings::Static {
            ip: "192.0.2.50".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            gateway: None,
            dns: vec![],
        };
        let upd = String::from_utf8(build_update_with(uuid(), MAC, &encoded, &net).unwrap()).unwrap();
        assert!(upd.contains("<IPv4Address>192.0.2.50</IPv4Address>"));
        assert!(upd.contains("<MAC>c0-56-e3-5a-7d-01</MAC>"));
        // Un mot de passe ne sort pas du XML.
        let evil = Secret::new("a</Password><X>&".into());
        let m = String::from_utf8(build_activate_with(uuid(), MAC, &evil).unwrap()).unwrap();
        assert!(m.contains("a&lt;/Password&gt;&lt;X&gt;&amp;"));
        assert!(build_activate_with(uuid(), "pas-une-mac", &encoded).is_none());
    }

    #[test]
    fn without_a_documented_encoding_nothing_is_built() {
        let pw = Secret::new("S3cr3t".into());
        assert!(encode_password(&pw).is_none());
        assert!(build_activate(uuid(), MAC, &pw).is_none());
        assert!(build_update(uuid(), MAC, &pw, &NetworkSettings::Dhcp).is_none());
    }

    const SENT: &[u8] = b"<Probe><Uuid>AAAA-1</Uuid><MAC>c0-56-e3-5a-7d-01</MAC></Probe>";

    fn reply(mac: &str, result: &str) -> (Vec<u8>, SocketAddr) {
        reply_uuid("AAAA-1", mac, result)
    }

    fn reply_uuid(uuid: &str, mac: &str, result: &str) -> (Vec<u8>, SocketAddr) {
        (
            format!("<ProbeMatch><Uuid>{uuid}</Uuid><MAC>{mac}</MAC><Types>activate</Types><Result>{result}</Result></ProbeMatch>")
                .into_bytes(),
            "192.0.2.31:37020".parse().unwrap(),
        )
    }

    fn ip() -> Ipv4Addr {
        "192.0.2.31".parse().unwrap()
    }

    #[tokio::test]
    async fn send_and_wait_ignores_other_macs() {
        let echo = (b"<Probe><MAC>c0-56-e3-5a-7d-01</MAC></Probe>".to_vec(), "192.0.2.2:37020".parse().unwrap());
        let dg = FakeDatagram::new(vec![echo, reply("c0-56-e3-5a-7d-99", "failed"), reply("c0-56-e3-5a-7d-01", "success")]);
        send_and_wait(&dg, SENT, MAC, ip(), Duration::from_secs(1)).await.unwrap();
        assert_eq!(dg.sent()[0].1, SocketAddr::V4(GROUP));
    }

    #[tokio::test]
    async fn send_and_wait_ignores_other_uuids() {
        let dg = FakeDatagram::new(vec![reply_uuid("BBBB-2", "c0-56-e3-5a-7d-01", "failed"), reply_uuid("aaaa-1", "c0-56-e3-5a-7d-01", "success")]);
        send_and_wait(&dg, SENT, MAC, ip(), Duration::from_secs(1)).await.unwrap();
        // Seule une réponse d'un autre UUID : on attend en vain.
        let dg = FakeDatagram::new(vec![reply_uuid("BBBB-2", "c0-56-e3-5a-7d-01", "success")]);
        let e = send_and_wait(&dg, SENT, MAC, ip(), Duration::from_millis(50)).await.unwrap_err();
        assert_eq!(e, ActionError::Unreachable { ip: ip() });
    }

    #[test]
    fn entity_references_and_doctype_are_rejected() {
        let xml = b"<ProbeMatch><MAC>c0-56-e3-5a-7d-01</MAC><DeviceSN>a&amp;b</DeviceSN></ProbeMatch>";
        assert!(parse_inquiry_response(xml, src()).is_none());
        let dtd = b"<!DOCTYPE x [<!ENTITY e \"v\">]><ProbeMatch><MAC>c0-56-e3-5a-7d-01</MAC></ProbeMatch>";
        assert!(parse_inquiry_response(dtd, src()).is_none());
        assert!(parse_result(b"<ProbeMatch><Result>a&lt;b</Result></ProbeMatch>").is_err());
    }

    #[tokio::test]
    async fn send_and_wait_reports_the_camera_refusal() {
        let dg = FakeDatagram::new(vec![reply("c0-56-e3-5a-7d-01", "denied")]);
        let e = send_and_wait(&dg, SENT, MAC, ip(), Duration::from_secs(1)).await.unwrap_err();
        assert_eq!(e, ActionError::Rejected { detail: "denied".into() });
    }

    #[tokio::test]
    async fn send_and_wait_timeout_is_unreachable() {
        let dg = FakeDatagram::new(vec![reply("c0-56-e3-5a-7d-99", "success")]);
        let e = send_and_wait(&dg, SENT, MAC, ip(), Duration::from_millis(50)).await.unwrap_err();
        assert_eq!(e, ActionError::Unreachable { ip: ip() });
    }
}
