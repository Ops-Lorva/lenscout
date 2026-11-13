//! Plan d'adresses d'un changement d'IP en lot : `start + i` pour la i-ème
//! caméra de la sélection (ordre affiché). Aucune écriture ici ; l'application
//! passe par `actions::apply_batch`, donc par la garde de sous-réseau,
//! l'IP temporaire et la vérification d'identité de chaque caméra.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::discovery::sadp;
use crate::model::{Camera, Family};

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BatchRequest {
    pub start: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    #[serde(default)]
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Assignment {
    pub mac: String,
    pub serial: Option<String>,
    pub family: Family,
    pub current_ip: Ipv4Addr,
    pub new_ip: Ipv4Addr,
}

/// Codes stables, traduits par le front.
#[derive(Serialize, thiserror::Error, Debug, PartialEq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum BatchError {
    #[error("aucune caméra sélectionnée")]
    NoSelection,
    #[error("caméra sans MAC : {ip}")]
    MissingMac { ip: Ipv4Addr },
    #[error("caméra non prise en charge : {ip}")]
    Unsupported { ip: Ipv4Addr },
    #[error("masque invalide")]
    InvalidMask,
    #[error("la plage dépasse le sous-réseau")]
    RangeOverflow,
    #[error("adresse réseau ou broadcast : {ip}")]
    NetworkOrBroadcast { ip: Ipv4Addr },
    #[error("passerelle dans la plage : {ip}")]
    GatewayInRange { ip: Ipv4Addr },
    #[error("adresse déjà utilisée : {ip}")]
    IpInUse { ip: Ipv4Addr, mac: Option<String> },
}

/// `selection` : les caméras cochées, dans l'ordre affiché ; `others` : toutes
/// les autres connues (aucune ne doit voir son adresse prise).
pub fn plan_batch(
    selection: &[Camera],
    req: &BatchRequest,
    others: &[Camera],
) -> Result<Vec<Assignment>, BatchError> {
    if selection.is_empty() {
        return Err(BatchError::NoSelection);
    }
    let m = u32::from(req.mask);
    // Contigu, ni /0 ni /31 ni /32 : même règle que `vapix::validate_static`.
    if m.leading_ones() + m.trailing_zeros() != 32 || m.leading_ones() == 0 || m.leading_ones() >= 31 {
        return Err(BatchError::InvalidMask);
    }
    // Marque, puis MAC, avant tout calcul d'adresse.
    let mut macs = Vec::with_capacity(selection.len());
    for cam in selection {
        let supported = match cam.family {
            Family::Axis => true,
            Family::Hikvision => sadp::can_configure(),
            Family::Other => false,
        };
        if !supported {
            return Err(BatchError::Unsupported { ip: cam.ip });
        }
        match cam.mac.as_ref().filter(|m| !m.trim().is_empty()) {
            Some(mac) => macs.push(mac.clone()),
            None => return Err(BatchError::MissingMac { ip: cam.ip }),
        }
    }
    let start = u32::from(req.start);
    let net = start & m;
    // Toute la plage doit tenir dans le sous-réseau de `start`.
    let last = start.checked_add(selection.len() as u32 - 1).ok_or(BatchError::RangeOverflow)?;
    if last & m != net {
        return Err(BatchError::RangeOverflow);
    }
    let mut out: Vec<Assignment> = Vec::with_capacity(selection.len());
    for (i, (cam, mac)) in selection.iter().zip(macs).enumerate() {
        let a = start + i as u32;
        let new_ip = Ipv4Addr::from(a);
        if a == net || a == net | !m {
            return Err(BatchError::NetworkOrBroadcast { ip: new_ip });
        }
        // L'adresse d'une autre caméra de la sélection collisionnerait pendant
        // l'application (échange, chevauchement) ; la sienne est permise.
        let taken = selection
            .iter()
            .enumerate()
            .filter(|(j, o)| *j != i && o.ip == new_ip)
            .map(|(_, o)| o)
            .chain(others.iter().filter(|o| o.ip == new_ip))
            .next();
        if let Some(o) = taken {
            return Err(BatchError::IpInUse { ip: new_ip, mac: o.mac.clone() });
        }
        out.push(Assignment {
            mac,
            serial: cam.serial.clone(),
            family: cam.family,
            current_ip: cam.ip,
            new_ip,
        });
    }
    if let Some(gw) = req.gateway
        && out.iter().any(|a| a.new_ip == gw)
    {
        return Err(BatchError::GatewayInRange { ip: gw });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Activation, Source};

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn cam(last: u8, mac: Option<&str>, family: Family) -> Camera {
        Camera {
            ip: ip(&format!("10.0.50.{last}")),
            mac: mac.map(Into::into),
            family,
            brand: None,
            model: None,
            serial: Some(format!("SER{last}")),
            firmware: None,
            activation: Activation::Activated,
            http_port: 80,
            sources: vec![Source::Mdns],
        }
    }

    fn axis(last: u8) -> Camera {
        cam(last, Some(&format!("AC:CC:8E:00:00:{last:02X}")), Family::Axis)
    }

    fn req(start: &str) -> BatchRequest {
        BatchRequest { start: ip(start), mask: ip("255.255.255.0"), gateway: None, dns: vec![] }
    }

    #[test]
    fn assigns_in_display_order() {
        let sel = [axis(200), axis(150), axis(180)];
        let rows = plan_batch(&sel, &req("10.0.50.11"), &[]).unwrap();
        let ips: Vec<_> = rows.iter().map(|r| r.new_ip).collect();
        assert_eq!(ips, [ip("10.0.50.11"), ip("10.0.50.12"), ip("10.0.50.13")]);
        assert_eq!(rows[0].current_ip, ip("10.0.50.200"));
        assert_eq!(rows[1].mac, "AC:CC:8E:00:00:96");
        assert_eq!(rows[2].serial.as_deref(), Some("SER180"));
    }

    #[test]
    fn overflow_past_254_is_error() {
        let sel = [axis(1), axis(2), axis(3)];
        // .253 .254 .255 : la dernière est le broadcast.
        assert_eq!(
            plan_batch(&sel, &req("10.0.50.253"), &[]),
            Err(BatchError::NetworkOrBroadcast { ip: ip("10.0.50.255") })
        );
        // Une quatrième sort du /24.
        let sel = [axis(1), axis(2), axis(3), axis(4)];
        assert_eq!(plan_batch(&sel, &req("10.0.50.253"), &[]), Err(BatchError::RangeOverflow));
        // Dernière adresse de l'espace IPv4 : pas de débordement de u32, une erreur.
        let sel = [axis(1), axis(2)];
        let mut r = req("255.255.255.255");
        assert_eq!(plan_batch(&sel, &r, &[]), Err(BatchError::RangeOverflow));
        r.start = ip("10.0.50.0");
        assert_eq!(
            plan_batch(&sel, &r, &[]),
            Err(BatchError::NetworkOrBroadcast { ip: ip("10.0.50.0") })
        );
    }

    #[test]
    fn gateway_in_range_is_error() {
        let sel = [axis(1), axis(2), axis(3)];
        let mut r = req("10.0.50.11");
        r.gateway = Some(ip("10.0.50.12"));
        assert_eq!(plan_batch(&sel, &r, &[]), Err(BatchError::GatewayInRange { ip: ip("10.0.50.12") }));
        r.gateway = Some(ip("10.0.50.1"));
        assert!(plan_batch(&sel, &r, &[]).is_ok());
    }

    #[test]
    fn ip_of_unselected_camera_is_error() {
        let sel = [axis(1), axis(2)];
        let others = [axis(12)];
        assert_eq!(
            plan_batch(&sel, &req("10.0.50.11"), &others),
            Err(BatchError::IpInUse { ip: ip("10.0.50.12"), mac: Some("AC:CC:8E:00:00:0C".into()) })
        );
    }

    #[test]
    fn swap_inside_the_selection_is_ip_in_use_but_own_ip_is_fine() {
        // A (.12) reçoit .11 que porte B (.11) : collision pendant l'application.
        let sel = [axis(12), axis(11)];
        assert_eq!(
            plan_batch(&sel, &req("10.0.50.11"), &[]),
            Err(BatchError::IpInUse { ip: ip("10.0.50.11"), mac: Some("AC:CC:8E:00:00:0B".into()) })
        );
        // Une caméra qui garde sa propre adresse n'est pas sautée.
        let sel = [axis(11), axis(13)];
        let rows = plan_batch(&sel, &req("10.0.50.11"), &[]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].new_ip, rows[0].current_ip);
        assert_eq!(rows[1].new_ip, ip("10.0.50.12"));
    }

    #[test]
    fn camera_without_mac_is_error() {
        let sel = [axis(1), cam(2, None, Family::Axis)];
        assert_eq!(plan_batch(&sel, &req("10.0.50.11"), &[]), Err(BatchError::MissingMac { ip: ip("10.0.50.2") }));
    }

    #[test]
    fn other_brand_is_unsupported() {
        let sel = [axis(1), cam(2, Some("AA:BB:CC:00:00:02"), Family::Other)];
        assert_eq!(plan_batch(&sel, &req("10.0.50.11"), &[]), Err(BatchError::Unsupported { ip: ip("10.0.50.2") }));
    }

    #[test]
    fn hikvision_is_unsupported_while_sadp_cannot_configure() {
        assert!(!sadp::can_configure());
        let sel = [cam(2, Some("AA:BB:CC:00:00:02"), Family::Hikvision)];
        assert_eq!(plan_batch(&sel, &req("10.0.50.11"), &[]), Err(BatchError::Unsupported { ip: ip("10.0.50.2") }));
    }

    #[test]
    fn non_contiguous_mask_is_invalid() {
        let mut r = req("10.0.50.11");
        for bad in ["255.0.255.0", "0.0.0.0", "255.255.255.254", "255.255.255.255"] {
            r.mask = ip(bad);
            assert_eq!(plan_batch(&[axis(1)], &r, &[]), Err(BatchError::InvalidMask), "{bad}");
        }
    }

    #[test]
    fn empty_selection_is_error() {
        assert_eq!(plan_batch(&[], &req("10.0.50.11"), &[]), Err(BatchError::NoSelection));
    }

    #[test]
    fn error_codes_are_snake_case() {
        let j = serde_json::to_value(BatchError::IpInUse { ip: ip("10.0.50.12"), mac: None }).unwrap();
        assert_eq!(j["code"], "ip_in_use");
        assert_eq!(serde_json::to_value(BatchError::NoSelection).unwrap()["code"], "no_selection");
    }
}
