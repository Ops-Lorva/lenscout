//! Appareils relevés sur le réseau d'un compte et leur type deviné.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::oui::camera_brand_for_mac;

/// Type deviné d'un appareil relevé. Le constructeur (OUI) reste affiché à
/// côté : l'installateur corrige de tête un `Unknown`.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Camera,
    Nvr,
    Switch,
    Pc,
    Printer,
    Gateway,
    ThisPc,
    Unknown,
}

/// Un appareil relevé. Rien de secret : adresse, MAC, constructeur, nom
/// annoncé, dates (secondes depuis l'époque Unix).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SeenDevice {
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    pub kind: DeviceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Ce que le relevé sait d'une adresse pour deviner son type.
pub struct Clues<'a> {
    pub ip: Ipv4Addr,
    pub mac: Option<&'a str>,
    /// Constructeur lu dans l'OUI de la MAC.
    pub vendor: Option<&'a str>,
    /// Modèle d'une caméra vue au scan ou connue du compte.
    pub camera_model: Option<&'a str>,
    /// Vue au scan, ou connue du compte, à cette adresse.
    pub is_camera: bool,
    /// A répondu au NetBIOS « node status ».
    pub netbios: bool,
    pub gateway: Option<Ipv4Addr>,
    /// L'adresse du poste.
    pub pc: Option<Ipv4Addr>,
}

/// Préfixes de modèles d'enregistreurs (Hikvision DS-76/77/78/96, iDS-7,
/// LTS LTN, génériques NVR). À VÉRIFIER sur le chantier.
const NVR_PREFIXES: &[&str] = &["DS-76", "DS-77", "DS-78", "DS-96", "IDS-7", "LTN", "NVR"];

/// Fabricants d'imprimantes : sous-chaîne (minuscules) du nom IEEE.
const PRINTER_VENDORS: &[&str] = &["brother", "canon", "epson", "kyocera document", "lexmark", "ricoh", "xerox", "konica minolta"];

/// Fabricants de commutateurs : sous-chaîne (minuscules) du nom IEEE.
const SWITCH_VENDORS: &[&str] = &[
    "cisco", "netgear", "ubiquiti", "aruba", "hewlett packard enterprise", "d-link", "zyxel", "routerboard", "mikrotik",
    "juniper", "allied telesis", "planet technology", "ruckus", "extreme networks",
];

/// Le modèle est-il celui d'un enregistreur ?
pub fn is_nvr_model(model: &str) -> bool {
    let m = model.trim().to_ascii_uppercase();
    NVR_PREFIXES.iter().any(|p| m.starts_with(p))
}

fn vendor_in(vendor: Option<&str>, list: &[&str]) -> bool {
    vendor.is_some_and(|v| {
        let v = v.to_lowercase();
        list.iter().any(|needle| v.contains(needle))
    })
}

/// Type deviné, dans cet ordre : le poste, la passerelle, une caméra vue au
/// scan ou connue du compte (NVR d'après son modèle), un OUI de caméra,
/// d'imprimante, de commutateur, une réponse NetBIOS (PC), sinon inconnu.
pub fn guess_kind(c: &Clues) -> DeviceKind {
    if c.pc == Some(c.ip) {
        return DeviceKind::ThisPc;
    }
    if c.gateway == Some(c.ip) {
        return DeviceKind::Gateway;
    }
    if c.is_camera {
        return if c.camera_model.is_some_and(is_nvr_model) { DeviceKind::Nvr } else { DeviceKind::Camera };
    }
    if c.mac.and_then(camera_brand_for_mac).is_some() {
        return DeviceKind::Camera;
    }
    if vendor_in(c.vendor, PRINTER_VENDORS) {
        return DeviceKind::Printer;
    }
    if vendor_in(c.vendor, SWITCH_VENDORS) {
        return DeviceKind::Switch;
    }
    if c.netbios {
        return DeviceKind::Pc;
    }
    DeviceKind::Unknown
}

/// Clé d'un appareil : sa MAC (majuscules), sinon son IP.
pub fn device_key(d: &SeenDevice) -> String {
    d.mac.as_deref().map(str::to_uppercase).unwrap_or_else(|| d.ip.to_string())
}

/// Fusionne un relevé dans l'inventaire, par clé. Une ligne connue garde sa
/// première vue, prend la dernière, l'adresse, et ce que le relevé dit de
/// neuf (nom, modèle, constructeur, type sauf `Unknown`). Une adresse ne porte
/// qu'un appareil : celui du relevé remplace une autre ligne à la même IP (une
/// MAC qui change d'IP libère l'ancienne). Rend `true` si l'inventaire change.
pub fn merge_devices(list: &mut Vec<SeenDevice>, seen: Vec<SeenDevice>) -> bool {
    let mut changed = false;
    for mut d in seen {
        d.mac = d.mac.map(|m| m.to_uppercase());
        let key = device_key(&d);
        let before = list.len();
        list.retain(|o| o.ip != d.ip || device_key(o) == key);
        changed |= list.len() != before;
        match list.iter_mut().find(|o| device_key(o) == key) {
            None => {
                list.push(d);
                changed = true;
            }
            Some(mine) => {
                let merged = SeenDevice {
                    ip: d.ip,
                    mac: d.mac.or_else(|| mine.mac.clone()),
                    vendor: d.vendor.or_else(|| mine.vendor.clone()),
                    kind: if d.kind == DeviceKind::Unknown { mine.kind } else { d.kind },
                    name: d.name.or_else(|| mine.name.clone()),
                    model: d.model.or_else(|| mine.model.clone()),
                    first_seen: mine.first_seen.min(d.first_seen),
                    last_seen: mine.last_seen.max(d.last_seen),
                };
                changed |= *mine != merged;
                *mine = merged;
            }
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn clues(last: u8) -> Clues<'static> {
        Clues {
            ip: Ipv4Addr::new(192, 168, 1, last),
            mac: None,
            vendor: None,
            camera_model: None,
            is_camera: false,
            netbios: false,
            gateway: Some(ip("192.168.1.1")),
            pc: Some(ip("192.168.1.250")),
        }
    }

    fn dev(ip_s: &str, mac: Option<&str>, kind: DeviceKind, at: u64) -> SeenDevice {
        SeenDevice { ip: ip(ip_s), mac: mac.map(str::to_string), vendor: None, kind, name: None, model: None, first_seen: at, last_seen: at }
    }

    #[test]
    fn pc_and_gateway_win_over_everything() {
        let all = |last| Clues { is_camera: true, netbios: true, mac: Some("00:40:8C:00:00:01"), ..clues(last) };
        assert_eq!(guess_kind(&all(250)), DeviceKind::ThisPc);
        assert_eq!(guess_kind(&all(1)), DeviceKind::Gateway);
        assert_eq!(guess_kind(&all(2)), DeviceKind::Camera);
    }

    #[test]
    fn scanned_hikvision_nvr_model_is_nvr_and_camera_model_is_camera() {
        let seen = |m: &'static str| Clues { is_camera: true, camera_model: Some(m), ..clues(20) };
        assert_eq!(guess_kind(&seen("DS-7608NI-K2")), DeviceKind::Nvr);
        assert_eq!(guess_kind(&seen("DS-2CD2043G2-I")), DeviceKind::Camera);
        assert_eq!(guess_kind(&seen("LTN8708K-P8")), DeviceKind::Nvr);
        assert!(is_nvr_model("ids-7204HQHI-M1/S") && is_nvr_model(" DS-9632NI-I16 ") && is_nvr_model("NVR-16"));
        assert!(!is_nvr_model("P3268-LVE") && !is_nvr_model(""));
        // Sans modèle : caméra.
        assert_eq!(guess_kind(&Clues { is_camera: true, ..clues(20) }), DeviceKind::Camera);
    }

    #[test]
    fn camera_oui_without_scan_is_camera() {
        assert_eq!(guess_kind(&Clues { mac: Some("00:40:8C:12:34:56"), vendor: Some("Axis Communications AB"), ..clues(30) }), DeviceKind::Camera);
        assert_eq!(guess_kind(&Clues { mac: Some("00:BC:99:12:34:56"), ..clues(30) }), DeviceKind::Camera);
    }

    #[test]
    fn printer_oui_is_printer() {
        for v in ["Brother industries, LTD.", "CANON INC.", "Seiko Epson Corporation", "KYOCERA Document Solutions Inc.", "LEXMARK INTERNATIONAL, INC.", "RICOH COMPANY LTD.", "XEROX CORPORATION", "KONICA MINOLTA HOLDINGS, INC."] {
            assert_eq!(guess_kind(&Clues { vendor: Some(v), mac: Some("02:00:00:00:00:01"), ..clues(40) }), DeviceKind::Printer, "{v}");
        }
    }

    #[test]
    fn switch_oui_is_switch() {
        for v in ["Cisco Systems, Inc", "NETGEAR", "Ubiquiti Inc", "Hewlett Packard Enterprise", "D-LINK SYSTEMS, INC.", "Zyxel Communications Corporation", "Routerboard.com", "Juniper Networks", "Allied Telesis Labs Ltd", "PLANET Technology Corporation", "Ruckus Wireless", "Extreme Networks Headquarters"] {
            assert_eq!(guess_kind(&Clues { vendor: Some(v), mac: Some("02:00:00:00:00:01"), ..clues(50) }), DeviceKind::Switch, "{v}");
        }
    }

    #[test]
    fn netbios_reply_alone_is_pc() {
        assert_eq!(guess_kind(&Clues { netbios: true, vendor: Some("Intel Corporate"), ..clues(60) }), DeviceKind::Pc);
    }

    #[test]
    fn nothing_is_unknown() {
        assert_eq!(guess_kind(&clues(70)), DeviceKind::Unknown);
        assert_eq!(guess_kind(&Clues { vendor: Some("Intel Corporate"), ..clues(70) }), DeviceKind::Unknown);
    }

    #[test]
    fn merge_keeps_first_seen_updates_last_seen_and_name() {
        let mut list = vec![SeenDevice { name: Some("ANCIEN".into()), vendor: Some("Intel Corporate".into()), ..dev("192.168.1.60", Some("aa:bb:cc:00:00:01"), DeviceKind::Pc, 100) }];
        let again = SeenDevice { name: Some("POSTE-ACCUEIL".into()), ..dev("192.168.1.60", Some("AA:BB:CC:00:00:01"), DeviceKind::Pc, 200) };
        assert!(merge_devices(&mut list, vec![again]));
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].first_seen, list[0].last_seen), (100, 200));
        assert_eq!(list[0].name.as_deref(), Some("POSTE-ACCUEIL"));
        // Ce que le relevé ne dit pas reste.
        assert_eq!(list[0].vendor.as_deref(), Some("Intel Corporate"));
        // Rien de neuf : pas de changement.
        let same = list[0].clone();
        assert!(!merge_devices(&mut list, vec![same]));
        // Un nouvel appareil s'ajoute.
        assert!(merge_devices(&mut list, vec![dev("192.168.1.61", Some("aa:bb:cc:00:00:02"), DeviceKind::Unknown, 200)]));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn merge_by_mac_frees_old_ip() {
        let mut list = vec![dev("192.168.1.60", Some("AA:BB:CC:00:00:01"), DeviceKind::Pc, 100), dev("192.168.1.70", None, DeviceKind::Unknown, 100)];
        // La MAC passe en .70 : l'ancienne adresse est libérée, l'entrée sans MAC de .70 aussi.
        assert!(merge_devices(&mut list, vec![dev("192.168.1.70", Some("AA:BB:CC:00:00:01"), DeviceKind::Pc, 200)]));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].ip, ip("192.168.1.70"));
        assert_eq!(list[0].first_seen, 100);
    }

    #[test]
    fn merge_without_mac_keys_by_ip() {
        let mut list = vec![dev("10.0.20.5", None, DeviceKind::Unknown, 100)];
        assert!(merge_devices(&mut list, vec![dev("10.0.20.5", None, DeviceKind::Unknown, 200), dev("10.0.20.6", None, DeviceKind::Unknown, 200)]));
        assert_eq!(list.iter().map(|d| (d.ip, d.first_seen, d.last_seen)).collect::<Vec<_>>(), [(ip("10.0.20.5"), 100, 200), (ip("10.0.20.6"), 200, 200)]);
        assert_eq!(device_key(&list[0]), "10.0.20.5");
        assert_eq!(device_key(&dev("10.0.20.5", Some("aa:bb:cc:00:00:01"), DeviceKind::Pc, 1)), "AA:BB:CC:00:00:01");
    }

    #[test]
    fn unknown_kind_never_overwrites_a_known_kind() {
        let mut list = vec![dev("192.168.1.80", Some("AA:BB:CC:00:00:08"), DeviceKind::Nvr, 100)];
        merge_devices(&mut list, vec![dev("192.168.1.80", Some("AA:BB:CC:00:00:08"), DeviceKind::Unknown, 200)]);
        assert_eq!(list[0].kind, DeviceKind::Nvr);
        merge_devices(&mut list, vec![dev("192.168.1.80", Some("AA:BB:CC:00:00:08"), DeviceKind::Camera, 300)]);
        assert_eq!(list[0].kind, DeviceKind::Camera);
    }

    #[test]
    fn serde_round_trip_snake_case() {
        let d = SeenDevice { vendor: Some("Brother".into()), model: None, ..dev("192.168.1.9", Some("AA:BB:CC:00:00:09"), DeviceKind::ThisPc, 5) };
        let j = serde_json::to_string(&d).unwrap();
        assert_eq!(j, r#"{"ip":"192.168.1.9","mac":"AA:BB:CC:00:00:09","vendor":"Brother","kind":"this_pc","first_seen":5,"last_seen":5}"#);
        assert_eq!(serde_json::from_str::<SeenDevice>(&j).unwrap(), d);
    }
}
