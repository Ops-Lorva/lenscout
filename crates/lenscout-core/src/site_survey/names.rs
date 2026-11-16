//! Noms des appareils relevés : NetBIOS « node status » et mDNS inverse, en unicast.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use serde::Serialize;

use crate::transport::{Datagram, NetError};

/// D'où vient un nom.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameSource {
    NetBios,
    Mdns,
}

/// Port NetBIOS « name service ».
const NETBIOS_PORT: u16 = 137;
/// Port mDNS ; la question part d'un port éphémère (« legacy unicast »).
const MDNS_PORT: u16 = 5353;
/// Nom `*` encodé (RFC 1001 §14.1) : `*` puis 15 octets nuls, chaque demi-octet + `A`.
const WILDCARD: &[u8; 32] = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// Type NBSTAT.
const NBSTAT: u16 = 0x0021;

/// Question « node status » sur le nom `*` (RFC 1002 §4.2.17), unicast.
pub fn nbstat_query(txid: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(50);
    p.extend_from_slice(&txid.to_be_bytes());
    // Drapeaux nuls, une question.
    p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    p.push(0x20);
    p.extend_from_slice(WILDCARD);
    p.push(0);
    p.extend_from_slice(&NBSTAT.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p
}

/// Le premier nom unique de type 0x00 (poste) ou 0x20 (serveur) d'une
/// réponse « node status », espaces de fin ôtés. Un paquet tronqué, une
/// question, un nom de groupe ou non imprimable : `None`, jamais une panique.
pub fn parse_nbstat(packet: &[u8]) -> Option<String> {
    let be16 = |at: usize| -> Option<u16> { Some(u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?])) };
    // Réponse (bit QR), au moins une réponse.
    if packet.get(2)? & 0x80 == 0 || be16(6)? == 0 {
        return None;
    }
    // Nom de la réponse : étiquettes jusqu'au zéro, ou un pointeur.
    let mut at = 12;
    loop {
        let len = *packet.get(at)? as usize;
        if len == 0 {
            at += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            at += 2;
            break;
        }
        at += 1 + len;
    }
    if be16(at)? != NBSTAT {
        return None;
    }
    // Type, classe, TTL, longueur des données.
    let rdlen = be16(at + 8)? as usize;
    let data = packet.get(at + 10..at + 10 + rdlen)?;
    let count = *data.first()? as usize;
    let table = data.get(1..1 + count * 18)?;
    table.chunks_exact(18).find_map(|e| {
        let (name, suffix, flags) = (&e[..15], e[15], u16::from_be_bytes([e[16], e[17]]));
        let group = flags & 0x8000 != 0;
        if group || (suffix != 0x00 && suffix != 0x20) {
            return None;
        }
        let name = std::str::from_utf8(name).ok()?.trim_end_matches([' ', '\0']);
        (!name.is_empty() && name.bytes().all(|b| b.is_ascii_graphic())).then(|| name.to_string())
    })
}

/// `d.c.b.a.in-addr.arpa.` de `a.b.c.d`.
fn reverse_name(ip: Ipv4Addr) -> Option<Name> {
    let [a, b, c, d] = ip.octets();
    Name::from_ascii(format!("{d}.{c}.{b}.{a}.in-addr.arpa.")).ok()
}

/// Question PTR inverse, classe IN sans le bit « unicast response » : elle
/// part d'un port éphémère vers `ip:5353`, et l'appareil répond en unicast à
/// ce port (RFC 6762 §6.7).
pub fn mdns_reverse_query(ip: Ipv4Addr) -> Vec<u8> {
    let Some(name) = reverse_name(ip) else { return vec![] };
    // Un identifiant non nul : la réponse « legacy unicast » le reprend.
    let mut m = Message::new(0x4C53, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(name, RecordType::PTR));
    m.to_vec().unwrap_or_default()
}

/// Le nom d'hôte d'une réponse PTR sur l'adresse demandée (sans `.local`).
/// Une réponse sur une autre adresse, ou illisible : `None`.
pub fn parse_mdns_reverse(packet: &[u8], ip: Ipv4Addr) -> Option<String> {
    let msg = Message::from_vec(packet).ok()?;
    if msg.metadata.message_type != MessageType::Response {
        return None;
    }
    let asked = reverse_name(ip)?;
    msg.all_sections().find_map(|r| match &r.data {
        // L'égalité des noms ignore la casse.
        RData::PTR(ptr) if r.name == asked => {
            let host = ptr.0.to_utf8();
            let host = host.trim_end_matches('.');
            let host = host.strip_suffix(".local").unwrap_or(host);
            (!host.is_empty() && host.chars().all(|c| !c.is_control())).then(|| host.to_string())
        }
        _ => None,
    })
}

/// Lit les réponses de `sock` jusqu'à `deadline` et garde le nom de chaque
/// adresse demandée. Une réponse d'une autre adresse est ignorée.
async fn collect(
    sock: &dyn Datagram,
    asked: &[Ipv4Addr],
    deadline: tokio::time::Instant,
    parse: impl Fn(&[u8], Ipv4Addr) -> Option<String>,
) -> HashMap<Ipv4Addr, String> {
    let mut out = HashMap::new();
    let mut buf = vec![0u8; 1500];
    // Windows rend une erreur sur un port fermé (ICMP) : on continue, borné.
    let mut errors = 0;
    while out.len() < asked.len() && errors < 1000 {
        match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
            Err(_) | Ok(Err(NetError::Timeout)) => break,
            Ok(Err(_)) => errors += 1,
            Ok(Ok((n, from))) => {
                let IpAddr::V4(src) = from.ip() else { continue };
                if asked.contains(&src)
                    && let Some(name) = parse(&buf[..n], src)
                {
                    out.entry(src).or_insert(name);
                }
            }
        }
    }
    out
}

/// Nom de chaque adresse, en un aller-retour borné par `wait` : un paquet
/// NetBIOS et un paquet mDNS par adresse, puis les réponses des deux sockets
/// en même temps. Le nom NetBIOS passe devant le nom mDNS.
pub async fn resolve_names(
    ips: &[Ipv4Addr],
    netbios: Arc<dyn Datagram>,
    mdns: Arc<dyn Datagram>,
    wait: Duration,
) -> HashMap<Ipv4Addr, (String, NameSource)> {
    let deadline = tokio::time::Instant::now() + wait;
    for (i, ip) in ips.iter().enumerate() {
        let _ = netbios.send_to(&nbstat_query(i as u16), SocketAddr::new((*ip).into(), NETBIOS_PORT)).await;
        let _ = mdns.send_to(&mdns_reverse_query(*ip), SocketAddr::new((*ip).into(), MDNS_PORT)).await;
    }
    let (nb, md) = tokio::join!(
        collect(netbios.as_ref(), ips, deadline, |p, _| parse_nbstat(p)),
        collect(mdns.as_ref(), ips, deadline, parse_mdns_reverse),
    );
    let mut out: HashMap<Ipv4Addr, (String, NameSource)> = md.into_iter().map(|(ip, n)| (ip, (n, NameSource::Mdns))).collect();
    out.extend(nb.into_iter().map(|(ip, n)| (ip, (n, NameSource::NetBios))));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::PTR;

    use crate::testing::FakeDatagram;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// Réponse « node status » telle qu'un poste Windows l'envoie (RFC 1002
    /// §4.2.18) : en-tête, nom `*` encodé, NBSTAT, puis la table des noms
    /// (15 octets + suffixe + drapeaux) et les statistiques.
    fn nbstat_reply(txid: u16, names: &[(&str, u8, bool)]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&txid.to_be_bytes());
        p.extend_from_slice(&[0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
        p.push(0x20);
        p.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        p.push(0);
        p.extend_from_slice(&[0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0]);
        let rdata_len = 1 + names.len() * 18 + 46;
        p.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        p.push(names.len() as u8);
        for (n, suffix, group) in names {
            let mut field = [b' '; 15];
            field[..n.len()].copy_from_slice(n.as_bytes());
            p.extend_from_slice(&field);
            p.push(*suffix);
            p.extend_from_slice(&(if *group { 0x8400u16 } else { 0x0400 }).to_be_bytes());
        }
        p.extend_from_slice(&[0x00, 0x15, 0x5d, 0x01, 0x02, 0x03]);
        p.extend_from_slice(&[0u8; 40]);
        p
    }

    const WORKSTATION: &[(&str, u8, bool)] = &[("WORKGROUP", 0x00, true), ("POSTE-ACCUEIL", 0x00, false), ("POSTE-ACCUEIL", 0x20, false), ("WORKGROUP", 0x1e, true)];

    fn mdns_reply(owner: &str, target: &str) -> Vec<u8> {
        let mut m = Message::response(0x1234, OpCode::Query);
        m.metadata.message_type = MessageType::Response;
        m.add_answer(Record::from_rdata(Name::from_ascii(owner).unwrap(), 120, RData::PTR(PTR(Name::from_ascii(target).unwrap()))));
        m.to_vec().unwrap()
    }

    #[test]
    fn nbstat_query_is_the_rfc1002_wildcard_node_status() {
        let q = nbstat_query(0xBEEF);
        let mut want = vec![0xBE, 0xEF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20];
        want.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        want.extend_from_slice(&[0x00, 0x00, 0x21, 0x00, 0x01]);
        assert_eq!(q, want);
    }

    #[test]
    fn parse_nbstat_takes_the_unique_workstation_name() {
        assert_eq!(parse_nbstat(&nbstat_reply(1, WORKSTATION)).as_deref(), Some("POSTE-ACCUEIL"));
        // Un NVR qui n'annonce que son service serveur (0x20).
        assert_eq!(parse_nbstat(&nbstat_reply(1, &[("NVR-HALL", 0x20, false)])).as_deref(), Some("NVR-HALL"));
        // Que des groupes : pas de nom.
        assert_eq!(parse_nbstat(&nbstat_reply(1, &[("WORKGROUP", 0x00, true)])), None);
    }

    #[test]
    fn parse_nbstat_truncated_or_hostile_is_none() {
        let full = nbstat_reply(1, WORKSTATION);
        for n in 0..full.len() - 46 {
            assert_eq!(parse_nbstat(&full[..n]), None, "tronqué à {n}");
        }
        // Une question, pas une réponse.
        assert_eq!(parse_nbstat(&nbstat_query(1)), None);
        // Nombre de noms qui déborde du paquet.
        let mut lying = nbstat_reply(1, WORKSTATION);
        lying[12 + 34 + 10] = 200;
        assert_eq!(parse_nbstat(&lying), None);
        // Nom non imprimable.
        assert_eq!(parse_nbstat(&nbstat_reply(1, &[("A\u{7}B", 0x00, false)])), None);
    }

    #[test]
    fn mdns_reverse_query_asks_ptr_in_addr_arpa_without_qu() {
        let q = Message::from_vec(&mdns_reverse_query(ip("192.168.1.42"))).unwrap();
        assert_eq!(q.metadata.message_type, MessageType::Query);
        assert_eq!(q.queries.len(), 1);
        assert_eq!(q.queries[0].name().to_ascii(), "42.1.168.192.in-addr.arpa.");
        assert_eq!(q.queries[0].query_type(), RecordType::PTR);
        // Classe IN sans le bit « unicast response » : la question est
        // déjà unicast, depuis un port éphémère (RFC 6762 §6.7).
        let raw = mdns_reverse_query(ip("192.168.1.42"));
        assert_eq!(&raw[raw.len() - 2..], &[0x00, 0x01]);
    }

    #[test]
    fn parse_mdns_reverse_matches_the_asked_ip_only() {
        let r = mdns_reply("42.1.168.192.in-addr.arpa.", "imprimante-rdc.local.");
        assert_eq!(parse_mdns_reverse(&r, ip("192.168.1.42")).as_deref(), Some("imprimante-rdc"));
        assert_eq!(parse_mdns_reverse(&r, ip("192.168.1.43")), None);
        assert_eq!(parse_mdns_reverse(b"\x00\x01garbage", ip("192.168.1.42")), None);
    }

    /// Ne répond jamais ; garde ce qui est envoyé.
    #[derive(Default)]
    struct Silent(Mutex<Vec<(Vec<u8>, SocketAddr)>>);

    #[async_trait]
    impl Datagram for Silent {
        async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> Result<(), NetError> {
            self.0.lock().unwrap().push((buf.to_vec(), dest));
            Ok(())
        }
        async fn recv_from(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn resolve_sends_one_packet_per_ip_per_protocol_and_stops_at_wait() {
        let (nb, md) = (Arc::new(Silent::default()), Arc::new(Silent::default()));
        let ips = [ip("192.168.1.10"), ip("192.168.1.11")];
        let start = tokio::time::Instant::now();
        let got = resolve_names(&ips, nb.clone(), md.clone(), Duration::from_millis(1500)).await;
        assert!(got.is_empty());
        assert_eq!(start.elapsed(), Duration::from_millis(1500));
        let nb = nb.0.lock().unwrap();
        assert_eq!(nb.iter().map(|(_, a)| *a).collect::<Vec<_>>(), ["192.168.1.10:137".parse::<SocketAddr>().unwrap(), "192.168.1.11:137".parse().unwrap()]);
        let md = md.0.lock().unwrap();
        assert_eq!(md.iter().map(|(_, a)| *a).collect::<Vec<_>>(), ["192.168.1.10:5353".parse::<SocketAddr>().unwrap(), "192.168.1.11:5353".parse().unwrap()]);
        assert_eq!(md[1].0, mdns_reverse_query(ip("192.168.1.11")));
    }

    #[tokio::test]
    async fn resolve_prefers_netbios_then_mdns() {
        let from = |s: &str, port| SocketAddr::new(ip(s).into(), port);
        let nb = Arc::new(FakeDatagram::new(vec![(nbstat_reply(0, WORKSTATION), from("192.168.1.10", 137))]));
        let md = Arc::new(FakeDatagram::new(vec![
            (mdns_reply("10.1.168.192.in-addr.arpa.", "poste.local."), from("192.168.1.10", 5353)),
            (mdns_reply("11.1.168.192.in-addr.arpa.", "cam-entree.local."), from("192.168.1.11", 5353)),
        ]));
        let got = resolve_names(&[ip("192.168.1.10"), ip("192.168.1.11")], nb, md, Duration::from_millis(200)).await;
        assert_eq!(got.get(&ip("192.168.1.10")), Some(&("POSTE-ACCUEIL".to_string(), NameSource::NetBios)));
        assert_eq!(got.get(&ip("192.168.1.11")), Some(&("cam-entree".to_string(), NameSource::Mdns)));
    }

    #[tokio::test]
    async fn reply_from_an_unasked_ip_is_ignored() {
        let from = |s: &str, port| SocketAddr::new(ip(s).into(), port);
        let nb = Arc::new(FakeDatagram::new(vec![(nbstat_reply(0, WORKSTATION), from("192.168.1.99", 137))]));
        let md = Arc::new(FakeDatagram::new(vec![(mdns_reply("99.1.168.192.in-addr.arpa.", "x.local."), from("192.168.1.99", 5353))]));
        let got = resolve_names(&[ip("192.168.1.10")], nb, md, Duration::from_millis(200)).await;
        assert!(got.is_empty());
    }

    #[test]
    fn random_packets_never_panic() {
        // xorshift : pas de dépendance, suite reproductible.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let base = nbstat_reply(1, WORKSTATION);
        for i in 0..1000 {
            let len = (next() % 400) as usize;
            let mut p: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            // Une partie garde un en-tête plausible, pour aller plus loin dans l'analyse.
            if i % 2 == 0 && p.len() > 60 {
                p[..57].copy_from_slice(&base[..57]);
            }
            let _ = parse_nbstat(&p);
            let _ = parse_mdns_reverse(&p, ip("192.168.1.42"));
        }
    }
}
