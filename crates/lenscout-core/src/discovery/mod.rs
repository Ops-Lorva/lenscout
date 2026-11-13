pub mod mdns;
pub mod wsd;
pub mod sadp;
pub mod arp;
pub mod socket;
pub mod scanner;

use std::net::Ipv4Addr;

use arp::ScanInterface;

/// Adresse dans le sous-réseau de l'interface du scan.
pub fn in_subnet(iface: &ScanInterface, ip: Ipv4Addr) -> bool {
    !crate::temp_ip::needs_temp_ip(iface.ip, iface.mask, ip)
}

/// L'adresse à retenir parmi celles qu'une réponse annonce (une Axis porte
/// souvent aussi une 169.254.x.y) : celle qui est la source UDP du paquet,
/// sinon une du sous-réseau de l'interface, sinon la première.
pub fn pick_address(candidates: &[Ipv4Addr], src: Ipv4Addr, iface: Option<&ScanInterface>) -> Option<Ipv4Addr> {
    candidates
        .iter()
        .find(|a| **a == src)
        .or_else(|| iface.and_then(|i| candidates.iter().find(|a| in_subnet(i, **a))))
        .or(candidates.first())
        .copied()
}
