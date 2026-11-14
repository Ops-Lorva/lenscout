use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Marque reconnue d'une caméra. `Other` = ONVIF ou préfixe MAC seuls : liste
/// et « Ouvrir la page web », aucune action de configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Axis,
    Hikvision,
    Other,
}

/// État d'activation. `Unknown` = le protocole ne le dit pas (mDNS, WSD) ;
/// seul SADP le sait, et `merge` ne laisse jamais `Unknown` effacer une valeur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Activation {
    New,
    Activated,
    Unknown,
}

/// Adressage IPv4 de la caméra : `Static` = adresse fixe. « Inconnu » est
/// `None` (le protocole ne le dit pas, ou la lecture authentifiée n'a pas eu
/// lieu) : on ne devine jamais.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Addressing {
    Dhcp,
    Static,
}

/// Protocole qui a vu la caméra (`Oui` = simple préfixe MAC vu dans l'ARP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Mdns,
    Wsd,
    Sadp,
    Oui,
}

/// Une observation brute, produite par un parser de découverte.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sighting {
    pub source: Source,
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub family: Option<Family>,
    pub brand: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware: Option<String>,
    pub activation: Activation,
    pub http_port: Option<u16>,
    #[serde(default)]
    pub addressing: Option<Addressing>,
}

/// Une caméra, fusion de toutes ses observations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Camera {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub family: Family,
    pub brand: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware: Option<String>,
    pub activation: Activation,
    pub http_port: u16,
    pub sources: Vec<Source>,
    /// Absent des caméras renvoyées par un ancien front : inconnu.
    #[serde(default)]
    pub addressing: Option<Addressing>,
}

impl Camera {
    pub fn from_sighting(s: &Sighting) -> Camera {
        Camera {
            ip: s.ip,
            mac: s.mac.clone(),
            family: s.family.unwrap_or(Family::Other),
            brand: s.brand.clone(),
            model: s.model.clone(),
            serial: s.serial.clone(),
            firmware: s.firmware.clone(),
            activation: s.activation,
            http_port: s.http_port.unwrap_or(80),
            sources: vec![s.source],
            addressing: s.addressing,
        }
    }

    /// Un champ `None` est rempli ; un champ connu n'est écrasé que par un
    /// `Some`. `Unknown` ne remplace jamais `New`/`Activated`, la marque connue (`Axis`/`Hikvision`)
    /// ne change plus.
    pub fn merge(&mut self, s: &Sighting) {
        fn fill<T: Clone>(slot: &mut Option<T>, new: &Option<T>) {
            if let Some(v) = new {
                *slot = Some(v.clone());
            }
        }
        fill(&mut self.mac, &s.mac);
        fill(&mut self.brand, &s.brand);
        fill(&mut self.model, &s.model);
        fill(&mut self.serial, &s.serial);
        fill(&mut self.firmware, &s.firmware);
        fill(&mut self.addressing, &s.addressing);
        // La première marque connue reste : une autre marque sur la même MAC
        // ne fait pas passer une Axis en Hikvision (ni l'inverse).
        if let Some(f) = s.family
            && self.family == Family::Other
        {
            self.family = f;
        }
        if s.activation != Activation::Unknown {
            self.activation = s.activation;
        }
        if let Some(p) = s.http_port {
            self.http_port = p;
        }
        if !self.sources.contains(&s.source) {
            self.sources.push(s.source);
        }
    }

    /// Adresse de la page web de la caméra (port 80 omis).
    pub fn web_url(&self) -> String {
        if self.http_port == 80 {
            format!("http://{}", self.ip)
        } else {
            format!("http://{}:{}", self.ip, self.http_port)
        }
    }

    /// Base des appels HTTP vers la caméra.
    pub fn base_url(&self) -> String {
        self.web_url()
    }
}

/// Adresse MAC → `AC:CC:8E:12:34:56`. Accepte `:`, `-`, `.` ou rien comme
/// séparateur ; `None` si ce n'est pas exactement 12 chiffres hexadécimaux.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let hex: String = raw
        .trim()
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let up = hex.to_ascii_uppercase();
    Some(
        up.as_bytes()
            .chunks(2)
            .map(|p| std::str::from_utf8(p).unwrap())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sighting(source: Source) -> Sighting {
        Sighting {
            source,
            ip: "10.0.50.11".parse().unwrap(),
            mac: None,
            family: None,
            brand: None,
            model: None,
            serial: None,
            firmware: None,
            activation: Activation::Unknown,
            http_port: None,
            addressing: None,
        }
    }

    #[test]
    fn normalize_mac_accepts_common_formats() {
        for raw in ["AC:CC:8E:12:34:56", "ACCC8E123456", "ac-cc-8e-12-34-56", "accc.8e12.3456"] {
            assert_eq!(normalize_mac(raw).as_deref(), Some("AC:CC:8E:12:34:56"));
        }
        assert_eq!(normalize_mac("ACCC8E1234"), None);
        assert_eq!(normalize_mac("ZZCC8E123456"), None);
    }

    #[test]
    fn merge_fills_missing_fields_and_dedups_sources() {
        let mut a = sighting(Source::Mdns);
        a.mac = Some("AC:CC:8E:12:34:56".into());
        a.model = Some("P3245-V".into());
        a.family = Some(Family::Axis);
        let mut b = sighting(Source::Wsd);
        b.firmware = Some("11.11.65".into());

        let mut cam = Camera::from_sighting(&a);
        cam.merge(&b);
        assert_eq!(cam.mac.as_deref(), Some("AC:CC:8E:12:34:56"));
        assert_eq!(cam.model.as_deref(), Some("P3245-V"));
        assert_eq!(cam.firmware.as_deref(), Some("11.11.65"));
        assert_eq!(cam.sources, vec![Source::Mdns, Source::Wsd]);

        cam.merge(&b);
        assert_eq!(cam.sources, vec![Source::Mdns, Source::Wsd]);
    }

    #[test]
    fn merge_unknown_activation_never_overrides() {
        let mut a = sighting(Source::Sadp);
        a.activation = Activation::New;
        let mut cam = Camera::from_sighting(&a);
        cam.merge(&sighting(Source::Mdns));
        assert_eq!(cam.activation, Activation::New);
    }

    #[test]
    fn merge_other_family_is_replaced_and_known_values_need_some() {
        let mut a = sighting(Source::Oui);
        a.family = Some(Family::Other);
        a.model = Some("A".into());
        let mut cam = Camera::from_sighting(&a);
        let mut b = sighting(Source::Mdns);
        b.family = Some(Family::Axis);
        cam.merge(&b);
        assert_eq!(cam.family, Family::Axis);
        // un None ne remplace rien
        assert_eq!(cam.model.as_deref(), Some("A"));
        // un Some différent d'un autre protocole écrase
        let mut c = sighting(Source::Wsd);
        c.model = Some("B".into());
        cam.merge(&c);
        assert_eq!(cam.model.as_deref(), Some("B"));
        // Axis n'est pas rétrogradé en Other
        let mut d = sighting(Source::Oui);
        d.family = Some(Family::Other);
        cam.merge(&d);
        assert_eq!(cam.family, Family::Axis);
    }

    #[test]
    fn a_known_family_never_switches_between_axis_and_hikvision() {
        let mut a = sighting(Source::Mdns);
        a.mac = Some("AC:CC:8E:12:34:56".into());
        a.family = Some(Family::Axis);
        let mut cam = Camera::from_sighting(&a);
        let mut h = sighting(Source::Sadp);
        h.mac = a.mac.clone();
        h.family = Some(Family::Hikvision);
        cam.merge(&h);
        assert_eq!(cam.family, Family::Axis);
        let mut cam = Camera::from_sighting(&h);
        cam.merge(&a);
        assert_eq!(cam.family, Family::Hikvision);
    }

    #[test]
    fn merge_addressing_known_is_only_replaced_by_some() {
        let mut a = sighting(Source::Sadp);
        a.addressing = Some(Addressing::Static);
        let mut cam = Camera::from_sighting(&a);
        assert_eq!(cam.addressing, Some(Addressing::Static));
        // Un protocole qui ne sait pas (mDNS, WSD) ne l'efface pas.
        cam.merge(&sighting(Source::Mdns));
        assert_eq!(cam.addressing, Some(Addressing::Static));
        let mut b = sighting(Source::Sadp);
        b.addressing = Some(Addressing::Dhcp);
        cam.merge(&b);
        assert_eq!(cam.addressing, Some(Addressing::Dhcp));
    }

    #[test]
    fn addressing_serializes_lowercase_and_is_optional_from_the_front() {
        assert_eq!(serde_json::to_value(Addressing::Dhcp).unwrap(), "dhcp");
        assert_eq!(serde_json::to_value(Addressing::Static).unwrap(), "static");
        // Le front renvoie des caméras sans le champ (anciennes listes) : il reste inconnu.
        let cam: Camera = serde_json::from_value(serde_json::json!({
            "ip": "10.0.50.11", "mac": null, "family": "axis", "brand": null, "model": null,
            "serial": null, "firmware": null, "activation": "new", "http_port": 80, "sources": [],
        }))
        .unwrap();
        assert_eq!(cam.addressing, None);
    }

    #[test]
    fn web_url_omits_port_80() {
        let mut s = sighting(Source::Mdns);
        let mut cam = Camera::from_sighting(&s);
        assert_eq!(cam.http_port, 80);
        assert_eq!(cam.web_url(), "http://10.0.50.11");
        s.http_port = Some(8080);
        cam = Camera::from_sighting(&s);
        assert_eq!(cam.web_url(), "http://10.0.50.11:8080");
        assert_eq!(cam.base_url(), "http://10.0.50.11:8080");
    }
}
