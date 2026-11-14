//! mDNS (RFC 6762) : question PTR sur `_axis-video._tcp` et lecture des
//! réponses. Aucun réseau ici — les sockets sont dans `socket.rs`.

use std::net::{Ipv4Addr, SocketAddrV4};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};

use super::arp::ScanInterface;
use super::pick_address;
use crate::model::{Activation, Family, Sighting, Source, normalize_mac};

pub const GROUP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
pub const AXIS_SERVICE: &str = "_axis-video._tcp.local.";

/// Question PTR sur le service Axis : id 0 et bit QU à 0 (RFC 6762 §18), la
/// réponse revient donc en multicast comme pour n'importe quel écouteur.
pub fn build_query() -> Vec<u8> {
    let labels: Vec<&[u8]> = AXIS_SERVICE
        .split('.')
        .filter(|l| !l.is_empty())
        .map(str::as_bytes)
        .collect();
    let mut name = Name::from_labels(labels).expect("AXIS_SERVICE est un nom valide");
    name.set_fqdn(true);
    let mut m = Message::new(0, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(name, RecordType::PTR));
    m.to_vec().expect("une question PTR tient en un paquet")
}

/// Nom en minuscules, étiquettes brutes jointes par `.` (un nom d'instance
/// contient des espaces, que `to_ascii` échapperait).
fn key(name: &Name) -> String {
    name.iter()
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(".")
}

/// Un paquet tronqué ou hostile donne une liste vide, jamais une panique :
/// `Message::from_vec` renvoie une erreur et rien ici n'indexe ni ne `unwrap`.
pub fn parse_response(packet: &[u8], src: Ipv4Addr, iface: Option<&ScanInterface>) -> Vec<Sighting> {
    let Ok(msg) = Message::from_vec(packet) else {
        return Vec::new();
    };
    if msg.metadata.message_type != MessageType::Response {
        return Vec::new();
    }
    let service = AXIS_SERVICE.trim_end_matches('.').to_ascii_lowercase();

    // Instances annoncées par un PTR sur le service Axis, sans doublon.
    let mut instances: Vec<&Name> = Vec::new();
    for r in msg.all_sections() {
        if let RData::PTR(ptr) = &r.data
            && key(&r.name) == service
            && !instances.iter().any(|n| key(n) == key(&ptr.0))
        {
            instances.push(&ptr.0);
        }
    }

    let mut out = Vec::new();
    for instance in instances {
        let k = key(instance);
        let label = instance
            .iter()
            .next()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .unwrap_or_default();
        // « AXIS M3106-L Mk II - ACCC8E123456 » : modèle puis MAC en suffixe.
        let (model, suffix_mac) = match label.rsplit_once(" - ") {
            Some((m, mac)) => (m.trim(), normalize_mac(mac)),
            None => (label.trim(), None),
        };

        let mut port = None;
        let mut target = None;
        let mut txt_mac = None;
        for r in msg.all_sections().filter(|r| key(&r.name) == k) {
            match &r.data {
                RData::SRV(srv) => {
                    port = Some(srv.port);
                    target = Some(key(&srv.target));
                }
                RData::TXT(txt) => {
                    for item in txt.txt_data.iter() {
                        let item = String::from_utf8_lossy(item);
                        if let Some((k, v)) = item.split_once('=')
                            && k.trim().eq_ignore_ascii_case("macaddress")
                        {
                            txt_mac = normalize_mac(v);
                        }
                    }
                }
                _ => {}
            }
        }
        let addresses: Vec<Ipv4Addr> = target
            .map(|t| {
                msg.all_sections()
                    .filter_map(|r| match &r.data {
                        RData::A(a) if key(&r.name) == t => Some(a.0),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let ip = pick_address(&addresses, src, iface).unwrap_or(src);

        out.push(Sighting {
            source: Source::Mdns,
            ip,
            mac: txt_mac.or(suffix_mac),
            family: Some(Family::Axis),
            brand: Some("Axis".to_string()),
            model: (!model.is_empty()).then(|| model.to_string()),
            serial: None,
            firmware: None,
            activation: Activation::Unknown,
            http_port: port,
            addressing: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Activation, Family, Source};
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::rdata::{A, PTR, SRV, TXT};
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    const INSTANCE: &str = "AXIS M3106-L Mk II - ACCC8E123456._axis-video._tcp.local.";

    fn ip() -> Ipv4Addr {
        "169.254.10.20".parse().unwrap()
    }

    /// `Name::from_utf8` refuse l'espace, que les noms d'instance DNS-SD
    /// contiennent (RFC 6763 §4.1.1) : on construit depuis les étiquettes brutes.
    fn name(s: &str) -> Name {
        let labels: Vec<&[u8]> = s.split('.').filter(|l| !l.is_empty()).map(str::as_bytes).collect();
        let mut n = Name::from_labels(labels).unwrap();
        n.set_fqdn(true);
        n
    }

    fn record(owner: &str, data: RData) -> Record {
        Record::from_rdata(name(owner), 120, data)
    }

    fn response(answers: Vec<Record>) -> Vec<u8> {
        let mut m = Message::response(0, OpCode::Query);
        m.metadata.message_type = MessageType::Response;
        m.metadata.authoritative = true;
        for r in answers {
            m.add_answer(r);
        }
        m.to_vec().unwrap()
    }

    /// Réponse complète d'une caméra fictive : PTR + SRV + TXT + A.
    fn axis_response_packet() -> Vec<u8> {
        response(vec![
            record(AXIS_SERVICE, RData::PTR(PTR(name(INSTANCE)))),
            record(
                INSTANCE,
                RData::SRV(SRV::new(0, 0, 80, name("axis-accc8e123456.local."))),
            ),
            record(
                INSTANCE,
                RData::TXT(TXT::new(vec![
                    "macaddress=AC:CC:8E:12:34:56".to_string(),
                    "model=M3106-L Mk II".to_string(),
                ])),
            ),
            record(
                "axis-accc8e123456.local.",
                RData::A(A("192.0.2.21".parse().unwrap())),
            ),
        ])
    }

    #[test]
    fn mdns_axis_response_gives_model_mac_ip() {
        let s = parse_response(&axis_response_packet(), ip(), None);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].source, Source::Mdns);
        assert_eq!(s[0].model.as_deref(), Some("AXIS M3106-L Mk II"));
        assert_eq!(s[0].mac.as_deref(), Some("AC:CC:8E:12:34:56"));
        // l'enregistrement A l'emporte sur l'adresse source
        assert_eq!(s[0].ip, "192.0.2.21".parse::<Ipv4Addr>().unwrap());
        assert_eq!(s[0].http_port, Some(80));
        assert_eq!(s[0].family, Some(Family::Axis));
        assert_eq!(s[0].brand.as_deref(), Some("Axis"));
        assert_eq!(s[0].activation, Activation::Unknown);
    }

    #[test]
    fn mdns_without_a_record_or_txt_falls_back_to_src_and_name_suffix() {
        let pkt = response(vec![record(AXIS_SERVICE, RData::PTR(PTR(name(INSTANCE))))]);
        let s = parse_response(&pkt, ip(), None);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].ip, ip());
        assert_eq!(s[0].mac.as_deref(), Some("AC:CC:8E:12:34:56"));
        assert_eq!(s[0].http_port, None);
        assert_eq!(s[0].model.as_deref(), Some("AXIS M3106-L Mk II"));
    }

    /// Une Axis annonce souvent aussi son adresse de lien local, parfois en
    /// premier : on garde la source UDP, sinon une adresse du sous-réseau.
    #[test]
    fn mdns_prefers_the_udp_source_then_the_interface_subnet_over_link_local() {
        let pkt = response(vec![
            record(AXIS_SERVICE, RData::PTR(PTR(name(INSTANCE)))),
            record(INSTANCE, RData::SRV(SRV::new(0, 0, 80, name("axis-accc8e123456.local.")))),
            record("axis-accc8e123456.local.", RData::A(A("169.254.77.88".parse().unwrap()))),
            record("axis-accc8e123456.local.", RData::A(A("192.0.2.21".parse().unwrap()))),
        ]);
        let src: Ipv4Addr = "192.0.2.21".parse().unwrap();
        assert_eq!(parse_response(&pkt, src, None)[0].ip, src);
        let iface = ScanInterface {
            name: "en0".into(),
            ip: "192.0.2.2".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
        };
        let other: Ipv4Addr = "198.51.100.9".parse().unwrap();
        assert_eq!(parse_response(&pkt, other, Some(&iface))[0].ip, src);
        // Sans source ni sous-réseau qui tranche : la première.
        assert_eq!(parse_response(&pkt, other, None)[0].ip, "169.254.77.88".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn mdns_query_asks_axis_ptr() {
        let m = Message::from_vec(&build_query()).unwrap();
        assert_eq!(m.queries.len(), 1);
        let q = &m.queries[0];
        assert_eq!(q.query_type(), RecordType::PTR);
        assert_eq!(q.name().to_ascii().to_ascii_lowercase(), AXIS_SERVICE);
        // bit QU (poids fort de la classe, dernier mot du paquet) à 0, classe IN
        let raw = build_query();
        assert_eq!(&raw[raw.len() - 2..], &[0x00, 0x01]);
        assert_eq!(m.metadata.message_type, MessageType::Query);
    }

    #[test]
    fn mdns_truncated_or_garbage_never_panics() {
        let pkt = axis_response_packet();
        for n in 0..pkt.len() {
            let _ = parse_response(&pkt[..n], ip(), None);
        }
        let _ = parse_response(&[0xff; 64], ip(), None);
        let _ = parse_response(&[], ip(), None);
        // en-tête annonçant des milliers d'enregistrements absents
        let mut hostile = vec![0u8; 12];
        hostile[2] = 0x84;
        hostile[4..12].copy_from_slice(&[0xff; 8]);
        let _ = parse_response(&hostile, ip(), None);
        // chaque octet du paquet retourné, un par un
        for i in 0..pkt.len() {
            let mut p = pkt.clone();
            p[i] ^= 0xff;
            let _ = parse_response(&p, ip(), None);
        }
    }

    #[test]
    fn mdns_ignores_other_services() {
        let pkt = response(vec![
            record(
                "_http._tcp.local.",
                RData::PTR(PTR(name("Printer - ACCC8E123456._http._tcp.local."))),
            ),
            record(
                "Printer - ACCC8E123456._http._tcp.local.",
                RData::SRV(SRV::new(0, 0, 80, name("printer.local."))),
            ),
        ]);
        assert!(parse_response(&pkt, ip(), None).is_empty());
    }

    #[test]
    fn mdns_query_packet_is_not_a_response() {
        assert!(parse_response(&build_query(), ip(), None).is_empty());
    }
}
