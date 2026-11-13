// Repris de LanProbe crates/lanprobe-core/src/oui.rs le 2026-11-13
use crate::model::Family;
use std::collections::HashMap;
use std::sync::OnceLock;

const OUI_TSV: &str = include_str!("../data/oui.tsv");

struct OuiDb {
    p24: HashMap<u32, &'static str>,
    p28: HashMap<u32, &'static str>,
    p36: HashMap<u64, &'static str>,
}

fn db() -> &'static OuiDb {
    static DB: OnceLock<OuiDb> = OnceLock::new();
    DB.get_or_init(|| {
        let mut p24 = HashMap::new();
        let mut p28 = HashMap::new();
        let mut p36 = HashMap::new();
        for line in OUI_TSV.lines() {
            let mut it = line.splitn(3, '\t');
            let (Some(prefix), Some(bits), Some(vendor)) = (it.next(), it.next(), it.next()) else { continue };
            let bits: u8 = match bits.parse() { Ok(b) => b, Err(_) => continue };
            // Le préfixe est en hex ; on le ramène à sa valeur entière.
            match bits {
                24 => { if let Ok(v) = u32::from_str_radix(prefix, 16) { p24.insert(v, vendor); } }
                28 => { if let Ok(v) = u32::from_str_radix(prefix, 16) { p28.insert(v, vendor); } }
                36 => { if let Ok(v) = u64::from_str_radix(prefix, 16) { p36.insert(v, vendor); } }
                _ => {}
            }
        }
        OuiDb { p24, p28, p36 }
    })
}

/// Résout le fabricant à partir d'une adresse MAC (accepte `:` ou `-`, casse libre).
/// Teste le préfixe le plus long d'abord (36 → 28 → 24 bits).
pub fn vendor_for_mac(mac: &str) -> Option<String> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 12 {
        return None;
    }
    let mac48 = u64::from_str_radix(&hex[..12], 16).ok()?;
    let db = db();
    let key36 = mac48 >> 12;                    // 36 bits de poids fort
    if let Some(v) = db.p36.get(&key36) { return Some((*v).to_string()); }
    let key28 = (mac48 >> 20) as u32;          // 28 bits
    if let Some(v) = db.p28.get(&key28) { return Some((*v).to_string()); }
    let key24 = (mac48 >> 24) as u32;          // 24 bits
    if let Some(v) = db.p24.get(&key24) { return Some((*v).to_string()); }
    None
}


/// Fabricants de caméras reconnus : sous-chaîne (minuscules) du nom IEEE → (famille, marque).
/// Tout autre fabricant n'est pas une caméra et n'est pas affiché.
const CAMERA_BRANDS: &[(&str, Family, &str)] = &[
    ("axis communications", Family::Axis, "Axis"),
    ("hikvision", Family::Hikvision, "Hikvision"),
    ("dahua technology", Family::Other, "Dahua"),
    ("uniview", Family::Other, "Uniview"),
    ("hanwha vision", Family::Other, "Hanwha"),
    ("hanwha techwin", Family::Other, "Hanwha"),
    ("vivotek", Family::Other, "Vivotek"),
    ("mobotix", Family::Other, "Mobotix"),
    ("avigilon", Family::Other, "Avigilon"),
    ("bosch security", Family::Other, "Bosch"),
];

/// Marque de caméra déduite du préfixe MAC, `None` si le fabricant n'en fait pas.
pub fn camera_brand_for_mac(mac: &str) -> Option<(Family, String)> {
    let vendor = vendor_for_mac(mac)?.to_lowercase();
    CAMERA_BRANDS
        .iter()
        .find(|(needle, _, _)| vendor.contains(needle))
        .map(|(_, family, brand)| (*family, (*brand).to_string()))
}

#[cfg(test)]
mod tests {
    use super::{camera_brand_for_mac, vendor_for_mac};
    use crate::model::Family;

    #[test]
    fn resolves_known_ma_l_apple() {
        assert!(vendor_for_mac("a4:5e:60:11:22:33").unwrap().to_lowercase().contains("apple"));
    }

    #[test]
    fn accepts_dash_and_uppercase() {
        let v1 = vendor_for_mac("A4-5E-60-AA-BB-CC");
        let v2 = vendor_for_mac("a4:5e:60:aa:bb:cc");
        assert_eq!(v1, v2);
        assert!(v1.is_some());
    }

    #[test]
    fn unknown_or_invalid_is_none() {
        // Préfixe non assigné (locally administered) + format invalide
        assert_eq!(vendor_for_mac("zz:zz:zz:zz:zz:zz"), None);
        assert_eq!(vendor_for_mac("02:00:00:00:00:01"), None);
        assert_eq!(vendor_for_mac("a4:5e"), None);
    }

    /// Vérifie que la règle « préfixe le plus long gagne » s'applique correctement.
    ///
    /// Données réelles (oui.tsv) :
    ///   006967   24  IEEE Registration Authority
    ///   0069670  28  Annapurna labs
    ///   …        28  (0069671 … 006967E existent)
    ///   006967F  28  (ABSENT du fichier)
    ///
    /// → 00:69:67:0A:xx:xx → clé 28 bits = 0069670 → "Annapurna labs"
    /// → 00:69:67:FA:xx:xx → clé 28 bits = 006967F (absent) → repli 24 bits → "IEEE Registration Authority"
    #[test]
    fn longest_prefix_wins() {
        // Le préfixe 28 bits 0069670 est présent : il doit primer sur le 24 bits.
        let specific = vendor_for_mac("00:69:67:0A:BB:CC")
            .expect("0069670 (28-bit) doit être résolu");
        assert!(
            specific.to_lowercase().contains("annapurna"),
            "attendu 'Annapurna labs', obtenu: {specific}"
        );

        // Le préfixe 28 bits 006967F est absent : on doit retomber sur le 24 bits.
        let fallback = vendor_for_mac("00:69:67:FA:BB:CC")
            .expect("006967 (24-bit) doit être résolu en fallback");
        assert!(
            fallback.to_lowercase().contains("ieee"),
            "attendu 'IEEE Registration Authority', obtenu: {fallback}"
        );

        // Les deux résultats doivent être différents.
        assert_ne!(specific, fallback, "le 28 bits et le 24 bits fallback doivent différer");
    }

    #[test]
    fn axis_ouis_are_axis() {
        for m in ["00:40:8C:01:02:03", "AC:CC:8E:01:02:03", "B8:A4:4F:01:02:03", "E8:27:25:01:02:03"] {
            assert_eq!(camera_brand_for_mac(m), Some((Family::Axis, "Axis".to_string())));
        }
    }

    #[test]
    fn hikvision_oui_is_hikvision() {
        assert_eq!(camera_brand_for_mac("00:BC:99:01:02:03").unwrap().0, Family::Hikvision);
    }

    #[test]
    fn dahua_is_other_brand() {
        assert_eq!(camera_brand_for_mac("08:ED:ED:01:02:03"), Some((Family::Other, "Dahua".to_string())));
    }

    #[test]
    fn dahua_scale_factory_is_not_a_camera() {
        // 402C761 (28 bits) = « Shanghai Dahua Scale Factory », une balance.
        assert!(vendor_for_mac("40:2C:76:1A:BB:CC").unwrap().contains("Scale"));
        assert!(camera_brand_for_mac("40:2C:76:1A:BB:CC").is_none());
    }

    #[test]
    fn apple_is_not_a_camera() {
        assert!(camera_brand_for_mac("a4:5e:60:11:22:33").is_none());
    }

    #[test]
    fn invalid_mac_is_not_a_camera() {
        assert!(camera_brand_for_mac("zz").is_none());
    }
}
