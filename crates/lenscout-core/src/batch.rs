//! Plan d'adresses d'un changement d'IP en lot : `start + i` pour la i-ème
//! caméra de la sélection (ordre affiché). Aucune écriture ici ; l'application
//! passe par `actions::apply_batch`, donc par la garde de sous-réseau,
//! l'IP temporaire et la vérification d'identité de chaque caméra.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::accounts::{Exclusions, NetworkFill};
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
#[derive(Serialize, thiserror::Error, Debug, Clone, PartialEq)]
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
    #[error("passerelle hors du sous-réseau : {ip}")]
    GatewayOutOfSubnet { ip: Ipv4Addr },
    #[error("plus de 2 serveurs DNS")]
    TooManyDns,
    #[error("passerelle dans la plage : {ip}")]
    GatewayInRange { ip: Ipv4Addr },
    #[error("adresse déjà utilisée : {ip}")]
    IpInUse { ip: Ipv4Addr, mac: Option<String> },
    #[error("{needed} caméras pour {free} adresses libres")]
    NotEnoughFree { needed: usize, free: u32 },
    /// « Garder les IP » sans masque, passerelle ni DNS : rien à écrire.
    #[error("rien à changer")]
    NoChange,
}

/// Le lot tient-il dans les adresses libres du réseau du compte ? Refusé
/// avant tout plan : sans quoi l'erreur viendrait d'une adresse prise ou d'un
/// débordement, sans dire que le réseau est plein. `fill` doit compter les
/// adresses actuelles du lot comme libres (`own`). Un lot vers un autre
/// réseau, ou un compte sans réseau, n'est pas jugé ici.
pub fn check_room(needed: usize, req: &BatchRequest, fill: Option<&NetworkFill>) -> Result<(), BatchError> {
    let Some(fill) = fill else { return Ok(()) };
    let Some((net, prefix)) = fill.network.split_once('/') else { return Ok(()) };
    let (Ok(net), Ok(prefix)) = (net.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else { return Ok(()) };
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    if u32::from(req.start) & mask != u32::from(net) || needed <= fill.free as usize {
        return Ok(());
    }
    Err(BatchError::NotEnoughFree { needed, free: fill.free })
}

/// `selection` : les caméras cochées, dans l'ordre affiché ; `others` : toutes
/// les autres connues (aucune ne doit voir son adresse prise) ; `reserved` :
/// adresses du poste (jamais attribuées), `IpInUse` sans MAC ; `excluded` :
/// IP exclues du compte, sautées (la plage s'allonge d'autant).
pub fn plan_batch(
    selection: &[Camera],
    req: &BatchRequest,
    others: &[Camera],
    reserved: &[Ipv4Addr],
    excluded: &Exclusions,
) -> Result<Vec<Assignment>, BatchError> {
    if selection.is_empty() {
        return Err(BatchError::NoSelection);
    }
    check_request(req)?;
    let m = u32::from(req.mask);
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
    let net = u32::from(req.start) & m;
    let addrs = addresses(selection, req, excluded)?;
    if let Some(&a) = addrs.iter().find(|&&a| a == net || a == net | !m) {
        return Err(BatchError::NetworkOrBroadcast { ip: Ipv4Addr::from(a) });
    }
    // Passerelle : dans le sous-réseau, ni adresse réseau ni broadcast.
    if let Some(gw) = req.gateway {
        let g = u32::from(gw);
        if g & m != net || g == net || g == net | !m {
            return Err(BatchError::GatewayOutOfSubnet { ip: gw });
        }
    }
    let mut out: Vec<Assignment> = Vec::with_capacity(selection.len());
    for (i, ((cam, mac), a)) in selection.iter().zip(macs).zip(addrs).enumerate() {
        let new_ip = Ipv4Addr::from(a);
        // L'adresse d'une autre caméra de la sélection collisionnerait pendant
        // l'application (échange, chevauchement) ; la sienne est permise. Le
        // partage ci-dessus l'évite ; reste le cas de deux caméras de la
        // sélection vues à la même adresse.
        let taken = selection
            .iter()
            .enumerate()
            .filter(|(j, o)| *j != i && o.ip == new_ip)
            .map(|(_, o)| o)
            .chain(others.iter().filter(|o| o.ip == new_ip))
            .next();
        if reserved.contains(&new_ip) {
            return Err(BatchError::IpInUse { ip: new_ip, mac: None });
        }
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

/// Masque et DNS de la demande, avant toute adresse.
fn check_request(req: &BatchRequest) -> Result<(), BatchError> {
    if !usable_mask(req.mask) {
        return Err(BatchError::InvalidMask);
    }
    // La caméra n'a que deux emplacements DNS.
    if req.dns.len() > 2 {
        return Err(BatchError::TooManyDns);
    }
    Ok(())
}

/// Contigu, ni /0 ni /31 ni /32 : même règle que `vapix::validate_static`.
pub fn usable_mask(mask: Ipv4Addr) -> bool {
    let m = u32::from(mask);
    m.leading_ones() + m.trailing_zeros() == 32 && m.leading_ones() != 0 && m.leading_ones() < 31
}

/// Les adresses du plan, une par caméra de `selection` (ordre affiché) : la
/// plage à partir de `start`, IP exclues sautées, tenue dans le sous-réseau.
fn addresses(selection: &[Camera], req: &BatchRequest, excluded: &Exclusions) -> Result<Vec<u32>, BatchError> {
    let m = u32::from(req.mask);
    let start = u32::from(req.start);
    let net = start & m;
    // Les adresses de la plage, à partir de `start`, exclusions sautées ; toute
    // la plage doit tenir dans le sous-réseau de `start`.
    let mut addrs = Vec::with_capacity(selection.len());
    let mut next = Some(start);
    for _ in selection {
        let a = next.and_then(|n| excluded.next_free(n)).ok_or(BatchError::RangeOverflow)?;
        if a & m != net {
            return Err(BatchError::RangeOverflow);
        }
        addrs.push(a);
        next = a.checked_add(1);
    }
    // Une caméra dont l'adresse actuelle tombe dans la plage la garde ; les
    // autres prennent les adresses restantes, dans l'ordre affiché. Aucune ne
    // reçoit donc l'adresse actuelle d'une autre caméra du lot : un échange
    // ou une chaîne dépendrait de l'ordre d'application et de la réussite de
    // la caméra précédente (une caméra refusée est sautée, les autres
    // continuent), et laisserait deux caméras sur la même adresse.
    let mut left: Vec<Option<u32>> = addrs.iter().copied().map(Some).collect();
    let mut chosen: Vec<Option<u32>> = selection
        .iter()
        .map(|cam| {
            let own = u32::from(cam.ip);
            let slot = left.iter_mut().find(|a| **a == Some(own))?;
            slot.take()
        })
        .collect();
    let mut rest = left.into_iter().flatten();
    for c in chosen.iter_mut().filter(|c| c.is_none()) {
        *c = rest.next();
    }
    Ok(chosen.into_iter().map(|c| c.expect("autant d'adresses que de caméras")).collect())
}

/// Une ligne du plan et ses refus : l'aperçu d'une opération de masse les
/// montre tous, ligne par ligne, au lieu de s'arrêter au premier.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedRow {
    pub new_ip: Ipv4Addr,
    pub conflicts: Vec<BatchError>,
}

/// `plan_batch` ligne par ligne. Restent des erreurs de toute la demande :
/// sélection vide, masque, DNS, plage hors du sous-réseau, passerelle hors du
/// sous-réseau. Le reste est rendu sur sa ligne : marque sans écriture,
/// identité absente (ni MAC ni n° de série : une caméra vue à travers le
/// routeur n'a pas de MAC, son n° de série suffit à `verify_identity`),
/// adresse réseau ou broadcast, adresse prise (poste ou autre caméra),
/// passerelle sur l'adresse de la ligne.
pub fn plan_rows(
    selection: &[Camera],
    req: &BatchRequest,
    others: &[Camera],
    reserved: &[Ipv4Addr],
    excluded: &Exclusions,
) -> Result<Vec<PlannedRow>, BatchError> {
    if selection.is_empty() {
        return Err(BatchError::NoSelection);
    }
    check_request(req)?;
    let m = u32::from(req.mask);
    let net = u32::from(req.start) & m;
    let addrs = addresses(selection, req, excluded)?;
    if let Some(gw) = req.gateway {
        let g = u32::from(gw);
        if g & m != net || g == net || g == net | !m {
            return Err(BatchError::GatewayOutOfSubnet { ip: gw });
        }
    }
    let rows = selection
        .iter()
        .zip(addrs)
        .enumerate()
        .map(|(i, (cam, a))| {
            let new_ip = Ipv4Addr::from(a);
            let mut conflicts = Vec::new();
            let supported = match cam.family {
                Family::Axis => true,
                Family::Hikvision => sadp::can_configure(),
                Family::Other => false,
            };
            if !supported {
                conflicts.push(BatchError::Unsupported { ip: cam.ip });
            }
            let known = |f: &Option<String>| f.as_deref().is_some_and(|s| !s.trim().is_empty());
            if !known(&cam.mac) && !known(&cam.serial) {
                conflicts.push(BatchError::MissingMac { ip: cam.ip });
            }
            if a == net || a == net | !m {
                conflicts.push(BatchError::NetworkOrBroadcast { ip: new_ip });
            }
            let taken = selection
                .iter()
                .enumerate()
                .filter(|(j, o)| *j != i && o.ip == new_ip)
                .map(|(_, o)| o)
                .chain(others.iter().filter(|o| o.ip == new_ip))
                .next();
            if reserved.contains(&new_ip) {
                conflicts.push(BatchError::IpInUse { ip: new_ip, mac: None });
            } else if let Some(o) = taken {
                conflicts.push(BatchError::IpInUse { ip: new_ip, mac: o.mac.clone() });
            }
            if req.gateway == Some(new_ip) {
                conflicts.push(BatchError::GatewayInRange { ip: new_ip });
            }
            PlannedRow { new_ip, conflicts }
        })
        .collect();
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{AccountNetwork, KnownCamera, network_fill};
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
            addressing: None,
            declared_mac: None,
        }
    }

    fn axis(last: u8) -> Camera {
        cam(last, Some(&format!("AC:CC:8E:00:00:{last:02X}")), Family::Axis)
    }

    fn none() -> Exclusions {
        Exclusions::default()
    }

    fn req(start: &str) -> BatchRequest {
        BatchRequest { start: ip(start), mask: ip("255.255.255.0"), gateway: None, dns: vec![] }
    }

    #[test]
    fn assigns_in_display_order() {
        let sel = [axis(200), axis(150), axis(180)];
        let rows = plan_batch(&sel, &req("10.0.50.11"), &[], &[], &none()).unwrap();
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
            plan_batch(&sel, &req("10.0.50.253"), &[], &[], &none()),
            Err(BatchError::NetworkOrBroadcast { ip: ip("10.0.50.255") })
        );
        // Une quatrième sort du /24.
        let sel = [axis(1), axis(2), axis(3), axis(4)];
        assert_eq!(plan_batch(&sel, &req("10.0.50.253"), &[], &[], &none()), Err(BatchError::RangeOverflow));
        // Dernière adresse de l'espace IPv4 : pas de débordement de u32, une erreur.
        let sel = [axis(1), axis(2)];
        let mut r = req("255.255.255.255");
        assert_eq!(plan_batch(&sel, &r, &[], &[], &none()), Err(BatchError::RangeOverflow));
        r.start = ip("10.0.50.0");
        assert_eq!(
            plan_batch(&sel, &r, &[], &[], &none()),
            Err(BatchError::NetworkOrBroadcast { ip: ip("10.0.50.0") })
        );
    }

    #[test]
    fn gateway_in_range_is_error() {
        let sel = [axis(1), axis(2), axis(3)];
        let mut r = req("10.0.50.11");
        r.gateway = Some(ip("10.0.50.12"));
        assert_eq!(plan_batch(&sel, &r, &[], &[], &none()), Err(BatchError::GatewayInRange { ip: ip("10.0.50.12") }));
        r.gateway = Some(ip("10.0.50.1"));
        assert!(plan_batch(&sel, &r, &[], &[], &none()).is_ok());
    }

    #[test]
    fn ip_of_unselected_camera_is_error() {
        let sel = [axis(1), axis(2)];
        let others = [axis(12)];
        assert_eq!(
            plan_batch(&sel, &req("10.0.50.11"), &others, &[], &none()),
            Err(BatchError::IpInUse { ip: ip("10.0.50.12"), mac: Some("AC:CC:8E:00:00:0C".into()) })
        );
    }

    #[test]
    fn a_camera_whose_address_is_in_the_range_keeps_it() {
        // A (.12) et B (.11) sur .11–.12 : chacune garde la sienne, jamais
        // d'échange (B serait encore en .11 quand A y arrive).
        let sel = [axis(12), axis(11)];
        let rows = plan_batch(&sel, &req("10.0.50.11"), &[], &[], &none()).unwrap();
        assert!(rows.iter().all(|r| r.new_ip == r.current_ip));
        // Une caméra qui garde sa propre adresse n'est pas sautée.
        let sel = [axis(11), axis(13)];
        let rows = plan_batch(&sel, &req("10.0.50.11"), &[], &[], &none()).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].new_ip, rows[0].current_ip);
        assert_eq!(rows[1].new_ip, ip("10.0.50.12"));
    }

    #[test]
    fn the_others_fill_the_addresses_left_in_display_order() {
        // .11–.13 : B (.13) garde la sienne, A et C prennent .11 et .12 dans l'ordre.
        let sel = [axis(200), axis(13), axis(150)];
        let rows = plan_batch(&sel, &req("10.0.50.11"), &[], &[], &none()).unwrap();
        let ips: Vec<_> = rows.iter().map(|r| r.new_ip).collect();
        assert_eq!(ips, [ip("10.0.50.11"), ip("10.0.50.13"), ip("10.0.50.12")]);
        // A (.12) n'est plus « déplacée sur .11 puis B sur .12 » : A garde .12, B prend .11.
        let sel = [axis(12), axis(200)];
        let rows = plan_batch(&sel, &req("10.0.50.11"), &[], &[], &none()).unwrap();
        assert_eq!(rows.iter().map(|r| r.new_ip).collect::<Vec<_>>(), [ip("10.0.50.12"), ip("10.0.50.11")]);
    }

    #[test]
    fn no_camera_ever_receives_the_current_address_of_another_of_the_lot() {
        for start in 1..=20u8 {
            let sel = [axis(5), axis(7), axis(8), axis(30), axis(6)];
            let Ok(rows) = plan_batch(&sel, &req(&format!("10.0.50.{start}")), &[], &[], &none()) else { continue };
            let mut seen = std::collections::HashSet::new();
            for r in &rows {
                assert!(seen.insert(r.new_ip), "doublon {start}");
                assert!(
                    r.new_ip == r.current_ip || sel.iter().all(|c| c.ip != r.new_ip),
                    "{} reçoit l'adresse d'une autre caméra du lot (départ .{start})",
                    r.new_ip
                );
            }
        }
    }

    #[test]
    fn an_excluded_own_address_is_left() {
        // .12 exclue : A (.12) ne la garde pas, la plage devient .11 et .13.
        let ex = Exclusions::parse("10.0.50.12").unwrap();
        let sel = [axis(12), axis(200)];
        let rows = plan_batch(&sel, &req("10.0.50.11"), &[], &[], &ex).unwrap();
        assert_eq!(rows.iter().map(|r| r.new_ip).collect::<Vec<_>>(), [ip("10.0.50.11"), ip("10.0.50.13")]);
    }

    #[test]
    fn camera_without_mac_is_error() {
        let sel = [axis(1), cam(2, None, Family::Axis)];
        assert_eq!(plan_batch(&sel, &req("10.0.50.11"), &[], &[], &none()), Err(BatchError::MissingMac { ip: ip("10.0.50.2") }));
    }

    #[test]
    fn other_brand_is_unsupported() {
        let sel = [axis(1), cam(2, Some("AA:BB:CC:00:00:02"), Family::Other)];
        assert_eq!(plan_batch(&sel, &req("10.0.50.11"), &[], &[], &none()), Err(BatchError::Unsupported { ip: ip("10.0.50.2") }));
    }

    #[test]
    fn hikvision_is_unsupported_while_sadp_cannot_configure() {
        assert!(!sadp::can_configure());
        let sel = [cam(2, Some("AA:BB:CC:00:00:02"), Family::Hikvision)];
        assert_eq!(plan_batch(&sel, &req("10.0.50.11"), &[], &[], &none()), Err(BatchError::Unsupported { ip: ip("10.0.50.2") }));
    }

    #[test]
    fn non_contiguous_mask_is_invalid() {
        let mut r = req("10.0.50.11");
        for bad in ["255.0.255.0", "0.0.0.0", "255.255.255.254", "255.255.255.255"] {
            r.mask = ip(bad);
            assert_eq!(plan_batch(&[axis(1)], &r, &[], &[], &none()), Err(BatchError::InvalidMask), "{bad}");
        }
    }

    #[test]
    fn empty_selection_is_error() {
        assert_eq!(plan_batch(&[], &req("10.0.50.11"), &[], &[], &none()), Err(BatchError::NoSelection));
    }

    #[test]
    fn error_codes_are_snake_case() {
        let j = serde_json::to_value(BatchError::IpInUse { ip: ip("10.0.50.12"), mac: None }).unwrap();
        assert_eq!(j["code"], "ip_in_use");
        assert_eq!(serde_json::to_value(BatchError::NoSelection).unwrap()["code"], "no_selection");
    }

    #[test]
    fn gateway_must_be_a_host_of_the_subnet() {
        let sel = [axis(1), axis(2)];
        let mut r = req("10.0.50.11");
        for bad in ["10.0.51.1", "10.0.50.0", "10.0.50.255"] {
            r.gateway = Some(ip(bad));
            assert_eq!(plan_batch(&sel, &r, &[], &[], &none()), Err(BatchError::GatewayOutOfSubnet { ip: ip(bad) }), "{bad}");
        }
        r.gateway = Some(ip("10.0.50.1"));
        assert!(plan_batch(&sel, &r, &[], &[], &none()).is_ok());
    }

    #[test]
    fn more_than_two_dns_is_refused() {
        let mut r = req("10.0.50.11");
        r.dns = vec![ip("10.0.50.1"), ip("10.0.50.2")];
        assert!(plan_batch(&[axis(1)], &r, &[], &[], &none()).is_ok());
        r.dns.push(ip("10.0.50.3"));
        assert_eq!(plan_batch(&[axis(1)], &r, &[], &[], &none()), Err(BatchError::TooManyDns));
        assert_eq!(serde_json::to_value(BatchError::TooManyDns).unwrap()["code"], "too_many_dns");
        assert_eq!(
            serde_json::to_value(BatchError::GatewayOutOfSubnet { ip: ip("1.2.3.4") }).unwrap()["code"],
            "gateway_out_of_subnet"
        );
    }

    #[test]
    fn the_pc_address_is_never_assigned() {
        let sel = [axis(1), axis(2)];
        assert_eq!(
            plan_batch(&sel, &req("10.0.50.11"), &[], &[ip("10.0.50.12")], &none()),
            Err(BatchError::IpInUse { ip: ip("10.0.50.12"), mac: None })
        );
        assert!(plan_batch(&sel, &req("10.0.50.11"), &[], &[ip("10.0.50.99")], &none()).is_ok());
    }

    #[test]
    fn a_slash_16_is_crossed_by_octet_but_not_by_subnet() {
        let mut r = req("10.1.255.250");
        r.mask = ip("255.255.0.0");
        let many: Vec<Camera> = (1..=10).map(axis).collect();
        // 10.1.255.250 + 10 : 10.2.0.3, autre /16.
        assert_eq!(plan_batch(&many, &r, &[], &[], &none()), Err(BatchError::RangeOverflow));
        // Six adresses finissent sur le broadcast 10.1.255.255.
        assert_eq!(
            plan_batch(&many[..6], &r, &[], &[], &none()),
            Err(BatchError::NetworkOrBroadcast { ip: ip("10.1.255.255") })
        );
        // x.y.254.255 n'est pas un broadcast en /16 : on passe de .254 à .255.
        r.start = ip("10.1.254.255");
        let rows = plan_batch(&many[..3], &r, &[], &[], &none()).unwrap();
        let ips: Vec<_> = rows.iter().map(|a| a.new_ip).collect();
        assert_eq!(ips, [ip("10.1.254.255"), ip("10.1.255.0"), ip("10.1.255.1")]);
    }

    #[test]
    fn a_slash_30_has_two_hosts() {
        let mut r = req("10.0.50.5");
        r.mask = ip("255.255.255.252");
        let sel = [axis(1), axis(2), axis(3)];
        assert_eq!(plan_batch(&sel[..2], &r, &[], &[], &none()).unwrap()[1].new_ip, ip("10.0.50.6"));
        assert_eq!(plan_batch(&sel, &r, &[], &[], &none()), Err(BatchError::NetworkOrBroadcast { ip: ip("10.0.50.7") }));
        r.start = ip("10.0.50.4");
        assert_eq!(plan_batch(&sel[..1], &r, &[], &[], &none()), Err(BatchError::NetworkOrBroadcast { ip: ip("10.0.50.4") }));
        r.start = ip("10.0.50.6");
        assert_eq!(plan_batch(&sel[..2], &r, &[], &[], &none()), Err(BatchError::NetworkOrBroadcast { ip: ip("10.0.50.7") }));
    }

    #[test]
    fn excluded_addresses_are_skipped() {
        let sel = [axis(200), axis(201), axis(202)];
        let ex = Exclusions::parse("10.0.50.12, 10.0.50.14-10.0.50.15").unwrap();
        let rows = plan_batch(&sel, &req("10.0.50.11"), &[], &[], &ex).unwrap();
        let ips: Vec<_> = rows.iter().map(|r| r.new_ip).collect();
        assert_eq!(ips, [ip("10.0.50.11"), ip("10.0.50.13"), ip("10.0.50.16")]);
        // Une IP de départ exclue n'est pas proposée non plus.
        let rows = plan_batch(&sel[..1], &req("10.0.50.12"), &[], &[], &ex).unwrap();
        assert_eq!(rows[0].new_ip, ip("10.0.50.13"));
    }

    fn fill_of(pc: &str, cams: &[&str], own: &[Ipv4Addr]) -> NetworkFill {
        let net = AccountNetwork { pc_ip: Some(pc.into()), ..Default::default() }.validated().unwrap();
        let cams: Vec<KnownCamera> = cams
            .iter()
            .map(|a| KnownCamera { ip: ip(a), serial: Some(a.to_string()), mac: None, model: None, last_seen: 1 })
            .collect();
        network_fill(&net, &cams, own).unwrap()
    }

    #[test]
    fn a_lot_larger_than_the_free_addresses_is_refused() {
        // /29 : .1 à .6, PC en .6, caméras connues en .1, .2, .3 → 2 libres.
        let fill = fill_of("10.0.50.6/29", &["10.0.50.1", "10.0.50.2", "10.0.50.3"], &[]);
        let mut r = req("10.0.50.4");
        r.mask = ip("255.255.255.248");
        assert_eq!(check_room(2, &r, Some(&fill)), Ok(()));
        assert_eq!(check_room(3, &r, Some(&fill)), Err(BatchError::NotEnoughFree { needed: 3, free: 2 }));
        assert_eq!(serde_json::to_value(BatchError::NotEnoughFree { needed: 3, free: 2 }).unwrap()["code"], "not_enough_free");
        // Lot vers un autre réseau que celui du compte, ou compte sans réseau : rien à dire ici.
        assert_eq!(check_room(3, &req("192.168.0.10"), Some(&fill)), Ok(()));
        assert_eq!(check_room(3, &r, None), Ok(()));
    }

    #[test]
    fn known_cameras_are_skipped_like_exclusions() {
        let ex = Exclusions::default().with_addresses([ip("10.0.50.12")]);
        let rows = plan_batch(&[axis(200), axis(201)], &req("10.0.50.11"), &[], &[], &ex).unwrap();
        assert_eq!(rows.iter().map(|r| r.new_ip).collect::<Vec<_>>(), [ip("10.0.50.11"), ip("10.0.50.13")]);
    }

    #[test]
    fn plan_rows_lists_each_conflict_on_its_row_without_stopping() {
        // .11 (prise par une autre caméra) et .12 (le poste) : deux lignes en
        // conflit, la troisième propre.
        let sel = [axis(200), axis(201), axis(202)];
        let others = [axis(11)];
        let rows = plan_rows(&sel, &req("10.0.50.11"), &others, &[ip("10.0.50.12")], &none()).unwrap();
        assert_eq!(rows.iter().map(|r| r.new_ip).collect::<Vec<_>>(), [ip("10.0.50.11"), ip("10.0.50.12"), ip("10.0.50.13")]);
        assert_eq!(rows[0].conflicts, [BatchError::IpInUse { ip: ip("10.0.50.11"), mac: Some("AC:CC:8E:00:00:0B".into()) }]);
        assert_eq!(rows[1].conflicts, [BatchError::IpInUse { ip: ip("10.0.50.12"), mac: None }]);
        assert!(rows[2].conflicts.is_empty());
    }

    #[test]
    fn plan_rows_flags_brand_identity_broadcast_and_gateway_per_row() {
        let mut hik = cam(3, Some("AA:BB:CC:00:00:03"), Family::Hikvision);
        hik.serial = None;
        let mut nothing = cam(4, None, Family::Axis);
        nothing.serial = None;
        // Vue à travers le routeur : pas de MAC, mais un n° de série. Elle passe.
        let routed = cam(5, None, Family::Axis);
        let sel = [routed, hik, nothing];
        let mut r = req("10.0.50.253");
        r.gateway = Some(ip("10.0.50.254"));
        let rows = plan_rows(&sel, &r, &[], &[], &none()).unwrap();
        assert!(rows[0].conflicts.is_empty());
        assert_eq!(rows[1].conflicts, [BatchError::Unsupported { ip: ip("10.0.50.3") }, BatchError::GatewayInRange { ip: ip("10.0.50.254") }]);
        assert_eq!(
            rows[2].conflicts,
            [BatchError::MissingMac { ip: ip("10.0.50.4") }, BatchError::NetworkOrBroadcast { ip: ip("10.0.50.255") }]
        );
    }

    #[test]
    fn plan_rows_keeps_the_errors_of_the_whole_request() {
        let sel = [axis(1), axis(2)];
        assert_eq!(plan_rows(&[], &req("10.0.50.11"), &[], &[], &none()), Err(BatchError::NoSelection));
        let mut r = req("10.0.50.11");
        r.mask = ip("255.0.255.0");
        assert_eq!(plan_rows(&sel, &r, &[], &[], &none()), Err(BatchError::InvalidMask));
        let mut r = req("10.0.50.11");
        r.gateway = Some(ip("10.0.51.1"));
        assert_eq!(plan_rows(&sel, &r, &[], &[], &none()), Err(BatchError::GatewayOutOfSubnet { ip: ip("10.0.51.1") }));
        let sel: Vec<Camera> = (1..=4).map(axis).collect();
        assert_eq!(plan_rows(&sel, &req("10.0.50.253"), &[], &[], &none()), Err(BatchError::RangeOverflow));
    }

    #[test]
    fn exclusions_that_push_the_range_out_are_an_overflow() {
        let sel = [axis(1), axis(2)];
        let ex = Exclusions::parse("10.0.50.253").unwrap();
        // .252, puis .254 ; une troisième tomberait sur le broadcast.
        let rows = plan_batch(&sel, &req("10.0.50.252"), &[], &[], &ex).unwrap();
        assert_eq!(rows[1].new_ip, ip("10.0.50.254"));
        let sel = [axis(1), axis(2), axis(3)];
        assert_eq!(
            plan_batch(&sel, &req("10.0.50.252"), &[], &[], &ex),
            Err(BatchError::NetworkOrBroadcast { ip: ip("10.0.50.255") })
        );
        // Tout le reste du sous-réseau exclu : plus rien à proposer.
        let ex = Exclusions::parse("10.0.50.200-10.0.51.255").unwrap();
        assert_eq!(plan_batch(&sel[..1], &req("10.0.50.200"), &[], &[], &ex), Err(BatchError::RangeOverflow));
    }
}
