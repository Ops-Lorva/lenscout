// Repris de LanProbe crates/lanprobe-core/src/discovery.rs le 2026-11-13, nettoyé
//! Balayage ARP : réveille chaque hôte du sous-réseau par un datagramme UDP
//! vers le port 9 (discard), puis lit la table ARP du système. Les arguments
//! des commandes système vont toujours dans `args`, jamais dans une chaîne de
//! shell.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use async_trait::async_trait;

use crate::interfaces::{InterfaceDetails, mask_to_prefix};
use crate::model::normalize_mac;
use crate::proc::async_cmd;

/// Plus grand réseau balayé : un /22 (1022 hôtes). Au-delà on ne balaie que le
/// /22 qui contient l'adresse du poste.
const MAX_SWEEP_PREFIX: u32 = 22;

/// L'interface par laquelle un balayage doit voir le réseau.
///
/// Le nom sert à `ip neigh show dev …` et `arp -i …` ; l'IP sert à Windows,
/// dont `arp -a` désigne les interfaces par leur adresse, pas par leur nom,
/// et à borner le balayage avec le masque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanInterface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl ScanInterface {
    /// `None` si l'interface n'a pas d'adresse IPv4 ou de masque exploitable.
    ///
    /// Sur macOS le nom sélectionné est un service networksetup (« Wi-Fi ») :
    /// `arp -i` et `ip neigh dev` attendent l'ifname système (« en0 »).
    pub fn from_details(selected: &str, details: &InterfaceDetails) -> Option<ScanInterface> {
        let ip: Ipv4Addr = details.ip.as_deref()?.trim().parse().ok()?;
        let subnet = details.subnet.as_deref()?;
        mask_to_prefix(subnet)?;
        let mask: Ipv4Addr = subnet.trim().parse().ok()?;
        Some(ScanInterface {
            name: details.bsd_name.clone().unwrap_or_else(|| selected.to_string()),
            ip,
            mask,
        })
    }
}

/// Hôtes à réveiller : le sous-réseau de l'interface (plafonné à un /22), sans
/// l'adresse réseau, la diffusion ni l'adresse du poste.
pub fn sweep_hosts(iface: &ScanInterface) -> Vec<Ipv4Addr> {
    let prefix = mask_to_prefix(&iface.mask.to_string())
        .unwrap_or(32)
        .max(MAX_SWEEP_PREFIX);
    if prefix >= 31 {
        return vec![];
    }
    let mask = !0u32 << (32 - prefix);
    let network = u32::from(iface.ip) & mask;
    let broadcast = network | !mask;
    (network + 1..broadcast)
        .map(Ipv4Addr::from)
        .filter(|ip| *ip != iface.ip)
        .collect()
}

/// Source des voisins ARP ; le faux des tests rend une table fixe.
#[async_trait]
pub trait ArpSource: Send + Sync {
    /// Réveille le sous-réseau puis rend la table ARP : IP → MAC normalisée.
    async fn sweep_and_read(&self, iface: &ScanInterface) -> HashMap<Ipv4Addr, String>;
}

pub struct SystemArp;

#[async_trait]
impl ArpSource for SystemArp {
    async fn sweep_and_read(&self, iface: &ScanInterface) -> HashMap<Ipv4Addr, String> {
        if let Ok(sock) = tokio::net::UdpSocket::bind((iface.ip, 0)).await {
            for (n, host) in sweep_hosts(iface).into_iter().enumerate() {
                // Une erreur d'envoi (tampon plein, hôte injoignable) n'arrête pas le balayage.
                let _ = sock.send_to(&[0u8], (host, 9)).await;
                // Laisse au noyau le temps de résoudre : sa file d'attente ARP est courte.
                if n % 128 == 127 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        }
        read_neighbours(iface).await
    }
}

/// La table ARP de l'interface telle quelle, sans balayage : IP → MAC
/// normalisée. Sert aussi à écarter les voisins du choix d'une IP temporaire.
pub async fn read_neighbours(iface: &ScanInterface) -> HashMap<Ipv4Addr, String> {
    let mut out = HashMap::new();
    for (ip, mac) in read_arp_table(iface).await {
        if let (Ok(ip), Some(mac)) = (ip.parse::<Ipv4Addr>(), normalize_mac(&mac)) {
            out.insert(ip, mac);
        }
    }
    out
}

/// La MAC d'un voisin telle que la couche 2 la voit (table ARP du système),
/// pas telle que l'appareil l'annonce ; le faux des tests rend une table fixe.
#[async_trait]
pub trait Neighbours: Send + Sync {
    /// MAC normalisées de `ip` dans la table ARP de `iface`, vide sans entrée.
    /// Plusieurs sous Windows si l'adresse figure sous plusieurs cartes.
    async fn macs_of(&self, iface: &ScanInterface, ip: Ipv4Addr) -> Vec<String>;
}

pub struct SystemNeighbours;

#[async_trait]
impl Neighbours for SystemNeighbours {
    async fn macs_of(&self, iface: &ScanInterface, ip: Ipv4Addr) -> Vec<String> {
        // Windows titre chaque bloc de `arp -a` par l'adresse principale de
        // la carte, pas forcément `iface.ip` (IP d'un compte posée en alias) :
        // l'adresse de la caméra se cherche dans toute la table.
        #[cfg(target_os = "windows")]
        {
            let _ = iface;
            let Ok(o) = async_cmd("arp").arg("-a").output().await else { return Vec::new() };
            windows_macs_of(&String::from_utf8_lossy(&o.stdout), ip)
        }
        #[cfg(not(target_os = "windows"))]
        {
            read_neighbours(iface).await.remove(&ip).into_iter().collect()
        }
    }
}

/// MAC normalisées de `ip` dans la sortie de `arp -a` (Windows), sous
/// n'importe quel en-tête d'interface : toutes, dans l'ordre de la table, si
/// l'adresse figure sous plusieurs cartes.
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
fn windows_macs_of(text: &str, ip: Ipv4Addr) -> Vec<String> {
    let ip = ip.to_string();
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some(a), Some(mac)) if a == ip && mac.contains('-') => normalize_mac(&mac.replace('-', ":")),
                _ => None,
            }
        })
        .collect()
}

/// Arguments de `ip neigh`, restreints à l'interface choisie.
#[allow(dead_code)]
fn neigh_args(iface: &ScanInterface) -> Vec<&str> {
    vec!["neigh", "show", "dev", iface.name.as_str()]
}

/// Arguments de `arp` (BSD / net-tools), restreints à l'interface choisie.
#[allow(dead_code)]
fn bsd_arp_args(iface: &ScanInterface) -> Vec<&str> {
    vec!["-an", "-i", iface.name.as_str()]
}

/// Lit la table ARP : ip -> mac.
///
/// **Toujours restreinte à l'interface choisie.** Un Wi-Fi de technicien en
/// 192.168.1.0/24 et un VLAN client dans le même plan, c'est banal : sans
/// filtre, le balayage du VLAN afficherait des machines que l'interface
/// choisie n'a jamais vues.
///
/// - Windows : `arp -a`, filtré sur le bloc de l'IP de l'interface (`arp`
///   n'accepte pas de nom d'interface, seulement l'adresse locale).
/// - macOS   : `arp -an -i <iface>`, plus filtrage du `on <iface>` de la
///   sortie — la restriction ne dépend donc pas du support de `-i`.
/// - Linux   : `ip neigh show dev <iface>` (iproute2, toujours installé)
///   avec repli `arp -an -i <iface>` — `net-tools` n'est plus installé par
///   défaut sur Debian/Ubuntu récents, donc `arp` peut être absent.
#[allow(unused_variables, unused_mut)]
async fn read_arp_table(iface: &ScanInterface) -> HashMap<String, String> {
    let mut map = HashMap::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(o) = async_cmd("arp").arg("-a").output().await {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            parse_windows_arp(&text, &mut map, Some(iface.ip));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = async_cmd("arp").args(bsd_arp_args(iface)).output().await {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            parse_bsd_arp(&text, &mut map, Some(iface.name.as_str()));
        }
    }

    #[cfg(target_os = "linux")]
    {
        // `ip neigh show dev eth0` — format :
        // "192.0.2.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        if let Ok(o) = async_cmd("ip").args(neigh_args(iface)).output().await {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            parse_ip_neigh(&text, &mut map, Some(iface.name.as_str()));
        }
        if map.is_empty()
            && let Ok(o) = async_cmd("arp").args(bsd_arp_args(iface)).output().await
        {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            parse_bsd_arp(&text, &mut map, Some(iface.name.as_str()));
        }
    }

    map
}

/// Parse `ip neigh show`. Le filtre est redondant avec `dev <iface>` mais
/// couvre les sorties où la restriction n'a pas été appliquée.
#[allow(dead_code)]
fn parse_ip_neigh(text: &str, map: &mut HashMap<String, String>, iface: Option<&str>) {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(ip) = parts.first().filter(|p| p.contains('.')) else { continue };
        if let Some(want) = iface {
            let dev = parts
                .iter()
                .position(|p| *p == "dev")
                .and_then(|i| parts.get(i + 1));
            if dev != Some(&want) {
                continue;
            }
        }
        let mac = parts
            .iter()
            .position(|p| *p == "lladdr")
            .and_then(|i| parts.get(i + 1));
        if let Some(mac) = mac
            && mac.contains(':')
            && mac.len() == 17
        {
            map.insert(ip.to_string(), mac.to_string());
        }
    }
}

/// Parse `arp -a` de Windows, bloc par bloc. Chaque bloc est introduit par
/// `Interface: <ip locale> --- 0x…` : c'est le seul moyen de rattacher une
/// entrée à une interface, `arp` ne prenant pas de nom d'interface.
#[allow(dead_code)]
fn parse_windows_arp(text: &str, map: &mut HashMap<String, String>, iface_ip: Option<Ipv4Addr>) {
    let mut dans_le_bon_bloc = iface_ip.is_none();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Interface:") {
            let bloc_ip = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<Ipv4Addr>().ok());
            dans_le_bon_bloc = match iface_ip {
                None => true,
                Some(want) => bloc_ip == Some(want),
            };
            continue;
        }
        if !dans_le_bon_bloc {
            continue;
        }
        // "  192.0.2.1   11-22-33-44-55-66   dynamic"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0].contains('.') && parts[1].contains('-') {
            map.insert(parts[0].to_string(), parts[1].replace('-', ":"));
        }
    }
}

#[allow(dead_code)]
fn parse_bsd_arp(text: &str, map: &mut HashMap<String, String>, iface: Option<&str>) {
    // Format BSD / macOS : "? (192.0.2.1) at 11:22:33:44:55:66 on en0 [ethernet]"
    for line in text.lines() {
        let Some(ip_start) = line.find('(') else { continue };
        let Some(ip_end) = line.find(')') else { continue };
        if ip_end < ip_start {
            continue;
        }
        let ip = line[ip_start + 1..ip_end].to_string();
        if !ip.contains('.') {
            continue;
        }
        // Après `)` on a `" at <mac> on <iface>..."` : on cherche le jeton qui
        // suit directement `at`.
        let mut toks = line[ip_end + 1..].split_whitespace();
        let mac = loop {
            match toks.next() {
                Some("at") => break toks.next().unwrap_or("").to_string(),
                Some(_) => continue,
                None => break String::new(),
            }
        };
        // `on <iface>` : on ne garde que les voisins vus par l'interface
        // choisie, même si `arp -i` n'a pas restreint la sortie.
        if let Some(want) = iface {
            let mut reste = line[ip_end + 1..].split_whitespace();
            let dev = loop {
                match reste.next() {
                    Some("on") => break reste.next(),
                    Some(_) => continue,
                    None => break None,
                }
            };
            if dev != Some(want) {
                continue;
            }
        }
        if mac.contains(':') && mac != "(incomplete)" && mac.len() >= 11 {
            // Normalise en "aa:bb:cc:dd:ee:ff" — BSD arp raccourcit les octets
            // à 0 : "1:2:3:4:5:6" au lieu de "01:02:03:04:05:06".
            let normalized: Vec<String> = mac
                .split(':')
                .map(|b| if b.len() == 1 { format!("0{b}") } else { b.to_string() })
                .collect();
            if normalized.len() == 6 {
                map.insert(ip, normalized.join(":"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(name: &str) -> ScanInterface {
        ScanInterface {
            name: name.to_string(),
            ip: Ipv4Addr::new(192, 0, 2, 10),
            mask: Ipv4Addr::new(255, 255, 255, 0),
        }
    }

    #[test]
    fn le_balayage_utilise_le_nom_bsd_car_c_est_lui_que_arp_connait() {
        // Sur macOS l'interface sélectionnée est un service networksetup
        // (« Wi-Fi ») ; `arp -i` attend « en0 ».
        let details = InterfaceDetails {
            name: "Wi-Fi".to_string(),
            ip: Some("192.0.2.10".to_string()),
            subnet: Some("255.255.255.0".to_string()),
            bsd_name: Some("en0".to_string()),
            ..Default::default()
        };
        assert_eq!(ScanInterface::from_details("Wi-Fi", &details), Some(ScanInterface {
            name: "en0".to_string(),
            ip: Ipv4Addr::new(192, 0, 2, 10),
            mask: Ipv4Addr::new(255, 255, 255, 0),
        }));
    }

    #[test]
    fn sans_nom_bsd_on_garde_le_nom_selectionne_et_sans_masque_on_refuse() {
        let mut details = InterfaceDetails {
            name: "eth0".to_string(),
            ip: Some("192.0.2.10".to_string()),
            subnet: Some("255.255.255.0".to_string()),
            ..Default::default()
        };
        assert_eq!(ScanInterface::from_details("eth0", &details).unwrap().name, "eth0");
        details.subnet = Some("255.0.255.0".to_string());
        assert_eq!(ScanInterface::from_details("eth0", &details), None);
        details.subnet = None;
        assert_eq!(ScanInterface::from_details("eth0", &details), None);
    }

    #[test]
    fn le_balayage_d_un_24_exclut_reseau_diffusion_et_poste() {
        let hosts = sweep_hosts(&scope("eth0"));
        assert_eq!(hosts.len(), 253);
        assert!(!hosts.contains(&Ipv4Addr::new(192, 0, 2, 0)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 0, 2, 255)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 0, 2, 10)));
        assert!(hosts.contains(&Ipv4Addr::new(192, 0, 2, 11)));
    }

    #[test]
    fn le_balayage_est_plafonne_a_un_22() {
        let mut big = scope("eth0");
        big.ip = Ipv4Addr::new(10, 1, 2, 3);
        big.mask = Ipv4Addr::new(255, 0, 0, 0);
        let hosts = sweep_hosts(&big);
        assert_eq!(hosts.len(), 1021);
        assert!(hosts.iter().all(|h| h.octets()[..2] == [10, 1] && h.octets()[2] < 4));
    }

    #[test]
    fn un_31_ou_un_32_n_a_rien_a_balayer() {
        let mut p2p = scope("eth0");
        p2p.mask = Ipv4Addr::new(255, 255, 255, 254);
        assert!(sweep_hosts(&p2p).is_empty());
    }

    #[test]
    fn ip_neigh_est_restreint_a_l_interface_choisie() {
        assert_eq!(neigh_args(&scope("eth0")), vec!["neigh", "show", "dev", "eth0"]);
    }

    #[test]
    fn arp_bsd_est_restreint_a_l_interface_choisie() {
        assert_eq!(bsd_arp_args(&scope("en0")), vec!["-an", "-i", "en0"]);
    }

    #[test]
    fn la_table_bsd_ecarte_les_voisins_d_une_autre_interface() {
        // Le Wi-Fi du technicien et le VLAN client sont tous deux en
        // 192.0.2.0/24 : sans filtre, les machines du Wi-Fi s'affichent
        // comme des hôtes découverts du VLAN.
        let text = "? (192.0.2.1) at 11:22:33:44:55:66 on en0 [ethernet]\n\
                    ? (192.0.2.2) at aa:bb:cc:dd:ee:ff on en1 [ethernet]\n";
        let mut map = HashMap::new();
        parse_bsd_arp(text, &mut map, Some("en0"));
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("192.0.2.1").map(String::as_str), Some("11:22:33:44:55:66"));
    }

    #[test]
    fn sans_filtre_la_table_bsd_garde_toutes_les_interfaces() {
        let text = "? (192.0.2.1) at 11:22:33:44:55:66 on en0 [ethernet]\n\
                    ? (192.0.2.2) at aa:bb:cc:dd:ee:ff on en1 [ethernet]\n";
        let mut map = HashMap::new();
        parse_bsd_arp(text, &mut map, None);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn la_table_bsd_complete_les_octets_courts_et_ignore_les_incompletes() {
        let text = "? (192.0.2.3) at 1:2:3:4:5:6 on en0 [ethernet]\n\
                    ? (192.0.2.4) at (incomplete) on en0 [ethernet]\n\
                    ) mal formé (\n";
        let mut map = HashMap::new();
        parse_bsd_arp(text, &mut map, Some("en0"));
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("192.0.2.3").map(String::as_str), Some("01:02:03:04:05:06"));
    }

    #[test]
    fn ip_neigh_ecarte_les_voisins_d_une_autre_interface() {
        // `ip neigh show dev eth0` filtre déjà côté noyau, mais le repli
        // `arp -an` et les sorties non filtrées doivent l'être aussi.
        let text = "192.0.2.1 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n\
                    192.0.2.2 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n";
        let mut map = HashMap::new();
        parse_ip_neigh(text, &mut map, Some("eth0"));
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("192.0.2.1"));
    }

    #[test]
    fn la_table_windows_ne_garde_que_le_bloc_de_l_interface() {
        // `arp -a` liste un bloc par interface, en tête son IP locale.
        let text = "\r\nInterface: 192.0.2.10 --- 0x5\r\n\
                    Internet Address      Physical Address      Type\r\n\
                    192.0.2.1             11-22-33-44-55-66     dynamic\r\n\
                    \r\nInterface: 198.51.100.5 --- 0x9\r\n\
                    Internet Address      Physical Address      Type\r\n\
                    192.0.2.2             aa-bb-cc-dd-ee-ff     dynamic\r\n";
        let mut map = HashMap::new();
        parse_windows_arp(text, &mut map, Some(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("192.0.2.1").map(String::as_str), Some("11:22:33:44:55:66"));
    }

    /// Contrôle MAC d'une activation sous Windows : l'adresse de la caméra est
    /// cherchée dans toute la table, quel que soit l'en-tête du bloc (l'IP d'un
    /// compte posée en alias n'est pas celle qui titre le bloc de la carte).
    #[test]
    fn windows_la_mac_d_une_camera_se_cherche_dans_tous_les_blocs() {
        let text = "\r\nInterface: 10.0.50.2 --- 0x5\r\n\
                    Internet Address      Physical Address      Type\r\n\
                    192.168.1.90          ac-cc-8e-12-34-56     dynamic\r\n\
                    \r\nInterface: 198.51.100.5 --- 0x9\r\n\
                    192.0.2.2             aa-bb-cc-dd-ee-ff     dynamic\r\n";
        assert_eq!(windows_macs_of(text, Ipv4Addr::new(192, 168, 1, 90)), ["AC:CC:8E:12:34:56"]);
        assert_eq!(windows_macs_of(text, Ipv4Addr::new(192, 0, 2, 2)), ["AA:BB:CC:DD:EE:FF"]);
        assert!(windows_macs_of(text, Ipv4Addr::new(192, 0, 2, 3)).is_empty());
    }

    /// La même IP sous deux cartes (une carte USB sur un autre réseau) : toutes
    /// les MAC trouvées sont rendues, pas la dernière seulement.
    #[test]
    fn windows_une_ip_sous_deux_cartes_rend_toutes_ses_mac() {
        let text = "\r\nInterface: 192.168.0.10 --- 0x5\r\n\
                    192.168.0.90          aa-bb-cc-dd-ee-ff     dynamic\r\n\
                    \r\nInterface: 192.168.0.20 --- 0x9\r\n\
                    192.168.0.90          ac-cc-8e-12-34-56     dynamic\r\n";
        assert_eq!(windows_macs_of(text, Ipv4Addr::new(192, 168, 0, 90)), ["AA:BB:CC:DD:EE:FF", "AC:CC:8E:12:34:56"]);
    }

    #[test]
    fn sans_filtre_la_table_windows_garde_tous_les_blocs() {
        let text = "\r\nInterface: 192.0.2.10 --- 0x5\r\n\
                    192.0.2.1             11-22-33-44-55-66     dynamic\r\n\
                    \r\nInterface: 198.51.100.5 --- 0x9\r\n\
                    192.0.2.2             aa-bb-cc-dd-ee-ff     dynamic\r\n";
        let mut map = HashMap::new();
        parse_windows_arp(text, &mut map, None);
        assert_eq!(map.len(), 2);
    }
}
