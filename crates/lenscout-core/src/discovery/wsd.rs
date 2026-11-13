//! ONVIF WS-Discovery : `Probe` SOAP 1.2 et lecture des `ProbeMatch`.
//! Aucun réseau ici — les sockets sont dans `socket.rs`.

use std::net::{Ipv4Addr, SocketAddrV4};

use quick_xml::Reader;
use quick_xml::events::Event;
use uuid::Uuid;

use crate::model::{Activation, Family, Sighting, Source, normalize_mac};

pub const GROUP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 3702);

/// Au-delà, ce n'est pas un ProbeMatch (un vrai tient en quelques Ko) : on
/// ignore le datagramme plutôt que de l'analyser.
const MAX_XML: usize = 64 * 1024;

/// `Probe` SOAP 1.2 (WS-Discovery 1.1) pour `dn:NetworkVideoTransmitter`.
pub fn build_probe(message_id: Uuid) -> Vec<u8> {
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" "#,
            r#"xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" "#,
            r#"xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" "#,
            r#"xmlns:dn="http://www.onvif.org/ver10/network/wsdl">"#,
            r#"<e:Header>"#,
            r#"<w:MessageID>urn:uuid:{id}</w:MessageID>"#,
            r#"<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"#,
            r#"<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"#,
            r#"</e:Header>"#,
            r#"<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>"#,
            r#"</e:Envelope>"#,
        ),
        id = message_id.hyphenated()
    )
    .into_bytes()
}

/// Décodage des `%XX` d'un scope ; une séquence invalide est gardée telle
/// quelle, les octets non UTF-8 deviennent `\u{fffd}`.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(h) = b.get(i + 1..i + 3)
            && let Some(v) = std::str::from_utf8(h).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `http://192.0.2.11:80/onvif/device_service` → (IP, port). `None` pour
/// tout ce qui n'est pas une adresse IPv4 littérale (IPv6, nom d'hôte).
fn parse_xaddr(url: &str) -> Option<(Ipv4Addr, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => (authority, if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 }),
    };
    Some((host.parse().ok()?, port))
}

/// Texte des éléments `XAddrs` et `Scopes`, quel que soit le préfixe de
/// namespace (on ne compare que le nom local). Une erreur de syntaxe arrête
/// la lecture : ce qui a déjà été lu reste utilisable.
fn read_fields(xml: &[u8]) -> (String, String) {
    #[derive(Clone, Copy, PartialEq)]
    enum In {
        Nothing,
        XAddrs,
        Scopes,
    }
    let mut reader = Reader::from_reader(xml);
    let (mut xaddrs, mut scopes) = (String::new(), String::new());
    let mut cur = In::Nothing;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                cur = match e.local_name().as_ref() {
                    "XAddrs" => In::XAddrs,
                    "Scopes" => In::Scopes,
                    _ => In::Nothing,
                }
            }
            Ok(Event::Text(t)) => {
                let text = t.into_inner();
                match cur {
                    In::XAddrs => {
                        xaddrs.push(' ');
                        xaddrs.push_str(&text);
                    }
                    In::Scopes => {
                        scopes.push(' ');
                        scopes.push_str(&text);
                    }
                    In::Nothing => {}
                }
            }
            Ok(Event::End(_)) => cur = In::Nothing,
            Ok(Event::Eof) | Err(_) => break,
            Ok(_) => {}
        }
    }
    (xaddrs, scopes)
}

/// Lit un `ProbeMatch` ONVIF. `None` s'il ne porte aucun `XAddrs` IPv4 :
/// sans adresse de service, rien à montrer (`_src` n'est donc pas utilisé,
/// l'adresse annoncée fait foi — elle peut différer de la source du paquet).
pub fn parse_probe_match(xml: &[u8], _src: Ipv4Addr) -> Option<Sighting> {
    if xml.len() > MAX_XML {
        return None;
    }
    let (xaddrs, scopes) = read_fields(xml);
    let (ip, port) = xaddrs.split_whitespace().find_map(parse_xaddr)?;

    let (mut model, mut name, mut mac) = (None, None, None);
    for scope in scopes.split_whitespace() {
        let Some(rest) = scope.strip_prefix("onvif://www.onvif.org/") else {
            continue;
        };
        let Some((kind, value)) = rest.split_once('/') else {
            continue;
        };
        let value = percent_decode(value);
        if value.is_empty() {
            continue;
        }
        match kind.to_ascii_lowercase().as_str() {
            "hardware" => model = model.or(Some(value)),
            "name" => name = name.or(Some(value)),
            "mac" => mac = mac.or_else(|| normalize_mac(&value)),
            _ => {}
        }
    }

    let upper = name.as_deref().unwrap_or("").to_ascii_uppercase();
    let (family, brand) = if upper.contains("AXIS") {
        (Family::Axis, Some("Axis".to_string()))
    } else if upper.contains("HIKVISION") {
        (Family::Hikvision, Some("Hikvision".to_string()))
    } else {
        (Family::Other, name)
    };

    Some(Sighting {
        source: Source::Wsd,
        ip,
        mac,
        family: Some(family),
        brand,
        model,
        serial: None,
        firmware: None,
        activation: Activation::Unknown,
        http_port: Some(port),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Activation, Family, Source};

    const AXIS: &[u8] = include_bytes!("../../tests/fixtures/wsd_axis_probematch.xml");
    const HIKVISION: &[u8] = include_bytes!("../../tests/fixtures/wsd_hikvision_probematch.xml");
    const GENERIC: &[u8] = include_bytes!("../../tests/fixtures/wsd_generic_probematch.xml");

    fn src() -> Ipv4Addr {
        "169.254.10.20".parse().unwrap()
    }

    #[test]
    fn wsd_axis_probematch() {
        let s = parse_probe_match(AXIS, src()).unwrap();
        assert_eq!(s.source, Source::Wsd);
        assert_eq!(s.family, Some(Family::Axis));
        assert_eq!(s.brand.as_deref(), Some("Axis"));
        assert_eq!(s.model.as_deref(), Some("M3106-L Mk II"));
        assert_eq!(s.ip, "192.0.2.11".parse::<Ipv4Addr>().unwrap());
        assert_eq!(s.http_port, Some(80));
        assert_eq!(s.mac.as_deref(), Some("AC:CC:8E:12:34:56"));
        assert_eq!(s.activation, Activation::Unknown);
    }

    #[test]
    fn wsd_hikvision_probematch_has_mac() {
        let s = parse_probe_match(HIKVISION, src()).unwrap();
        assert_eq!(s.family, Some(Family::Hikvision));
        assert_eq!(s.brand.as_deref(), Some("Hikvision"));
        assert_eq!(s.mac.as_deref(), Some("A4:14:6B:0A:1B:2C"));
        assert_eq!(s.model.as_deref(), Some("DS-2CD2043G2-I"));
        assert_eq!(s.ip, "192.0.2.12".parse::<Ipv4Addr>().unwrap());
        assert_eq!(s.http_port, Some(8080));
    }

    #[test]
    fn wsd_generic_is_other() {
        let s = parse_probe_match(GENERIC, src()).unwrap();
        assert_eq!(s.family, Some(Family::Other));
        assert_eq!(s.brand.as_deref(), Some("Example Cam"));
        assert_eq!(s.model.as_deref(), Some("EX-100"));
        assert_eq!(s.mac, None);
        // le premier XAddrs IPv4 : l'adresse IPv6 qui précède est sautée
        assert_eq!(s.ip, "192.0.2.13".parse::<Ipv4Addr>().unwrap());
        assert_eq!(s.http_port, Some(8000));
    }

    #[test]
    fn wsd_malformed_xml_is_none() {
        assert!(parse_probe_match(b"<Envelope><Body>", src()).is_none());
        assert!(parse_probe_match(b"", src()).is_none());
        assert!(parse_probe_match(b"not xml at all", src()).is_none());
    }

    #[test]
    fn wsd_without_ipv4_xaddrs_is_none() {
        let xml = b"<Envelope><Body><ProbeMatches><ProbeMatch><XAddrs>http://[2001:db8::1]/onvif</XAddrs></ProbeMatch></ProbeMatches></Body></Envelope>";
        assert!(parse_probe_match(xml, src()).is_none());
    }

    #[test]
    fn wsd_truncated_or_hostile_never_panics() {
        for fixture in [AXIS, HIKVISION, GENERIC] {
            for n in 0..fixture.len() {
                let _ = parse_probe_match(&fixture[..n], src());
            }
        }
        let _ = parse_probe_match(&[0xff, 0xfe, 0x00, 0x3c, 0xc3, 0x28], src());
        // imbrication profonde
        let deep = "<a>".repeat(20_000);
        let _ = parse_probe_match(deep.as_bytes(), src());
        // XAddrs géant, port hors plage, scopes percent-encodés invalides
        let long = format!("<XAddrs>http://192.0.2.1:99999/{}</XAddrs>", "x".repeat(60_000));
        assert!(parse_probe_match(long.as_bytes(), src()).is_none());
        let huge = format!("<XAddrs>http://192.0.2.1/{}</XAddrs>", "x".repeat(2_000_000));
        assert!(parse_probe_match(huge.as_bytes(), src()).is_none());
        let bad = b"<X><XAddrs>http://192.0.2.1/</XAddrs><Scopes>onvif://www.onvif.org/name/%ZZ%F0%9 onvif://www.onvif.org/MAC/%</Scopes></X>";
        let s = parse_probe_match(bad, src()).unwrap();
        assert_eq!(s.mac, None);
    }

    #[test]
    fn wsd_probe_contains_message_id_and_type() {
        let id = Uuid::parse_str("3f1c7a52-9d0e-4b8a-8f4e-0a1b2c3d4e5f").unwrap();
        let xml = String::from_utf8(build_probe(id)).unwrap();
        assert!(xml.contains("urn:uuid:3f1c7a52-9d0e-4b8a-8f4e-0a1b2c3d4e5f"));
        assert!(xml.contains("NetworkVideoTransmitter"));
        assert!(xml.contains("http://www.onvif.org/ver10/network/wsdl"));
        assert!(xml.contains("http://www.w3.org/2003/05/soap-envelope"));
        assert!(xml.contains("/discovery/Probe"));
    }
}
