//! Sockets UDP multicast réels. L'envoi et la réception ne se testent pas sans
//! réseau : les tests du scanner passent par `FakeDatagram`. Seul le filtre de
//! source (`source_allowed`) est une fonction pure testée ici.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use super::arp::ScanInterface;
use crate::transport::{Datagram, NetError};

pub struct UdpDatagram {
    socket: UdpSocket,
    /// Interface choisie : les datagrammes d'ailleurs sont écartés.
    iface: ScanInterface,
}

impl UdpDatagram {
    /// Port local du socket (utile quand il a été tiré au hasard).
    pub fn local_port(&self) -> std::io::Result<u16> {
        Ok(self.socket.local_addr()?.port())
    }
}

/// Faut-il garder un datagramme venu de `src` ?
///
/// Le socket multicast est lié à `0.0.0.0` : sur macOS et Windows il reçoit
/// les datagrammes de **toutes** les interfaces, et sous Linux ceux de tout
/// groupe joint par le système. On ne garde donc que les sources du
/// sous-réseau de l'interface choisie. **Exception** : `169.254.0.0/16`
/// reste toujours visible — une caméra neuve sans DHCP s'y annonce, hors du
/// sous-réseau du poste, et c'est le cas que la tâche 13 sait traiter.
/// (`IP_PKTINFO`/`IP_RECVIF` diraient l'interface d'arrivée exacte, mais
/// demandent un `recvmsg` propre à chaque OS ; le sous-réseau suffit ici.)
pub fn source_allowed(src: Ipv4Addr, iface: &ScanInterface) -> bool {
    if src.octets()[..2] == [169, 254] {
        return true;
    }
    let mask = u32::from(iface.mask);
    (u32::from(src) ^ u32::from(iface.ip)) & mask == 0
}

#[async_trait]
impl Datagram for UdpDatagram {
    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> Result<(), NetError> {
        self.socket
            .send_to(buf, dest)
            .await
            .map(|_| ())
            .map_err(|e| NetError::Io(e.to_string()))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        loop {
            let (n, from) = self
                .socket
                .recv_from(buf)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
            match from {
                SocketAddr::V4(v4) if !source_allowed(*v4.ip(), &self.iface) => continue,
                _ => return Ok((n, from)),
            }
        }
    }
}

/// Socket lié au port du groupe, abonné au groupe sur l'interface choisie
/// et émettant par elle. L'adresse et le port sont partagés (`SO_REUSEADDR`,
/// et `SO_REUSEPORT` hors Windows) : un démon mDNS du poste écoute déjà le
/// 5353. On se lie à `0.0.0.0` et non au groupe, seul portable sous Windows.
pub fn open_multicast(iface: &ScanInterface, group: SocketAddrV4) -> std::io::Result<UdpDatagram> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))))]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, group.port()).into())?;
    // Linux : sans cela le socket reçoit aussi les groupes joints par les
    // autres sockets du système, sur toutes les interfaces.
    #[cfg(target_os = "linux")]
    socket.set_multicast_all_v4(false)?;
    socket.join_multicast_v4(group.ip(), &iface.ip)?;
    socket.set_multicast_if_v4(&iface.ip)?;
    socket.set_nonblocking(true)?;
    finish(socket, iface)
}

/// Socket à port éphémère, émettant par l'interface choisie, sans abonnement.
/// Pour les protocoles dont la réponse revient en unicast sur le port source
/// (WS-Discovery) : partir du port 3702 ferait récupérer la réponse par le
/// service WSD du système (Windows) qui y écoute déjà.
pub fn open_ephemeral(iface: &ScanInterface) -> std::io::Result<UdpDatagram> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    socket.set_multicast_if_v4(&iface.ip)?;
    socket.set_nonblocking(true)?;
    finish(socket, iface)
}

fn finish(socket: Socket, iface: &ScanInterface) -> std::io::Result<UdpDatagram> {
    Ok(UdpDatagram { socket: UdpSocket::from_std(socket.into())?, iface: iface.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface() -> ScanInterface {
        ScanInterface {
            name: "eth0".into(),
            ip: "192.0.2.10".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
        }
    }

    #[test]
    fn only_the_chosen_subnet_and_link_local_are_kept() {
        let i = iface();
        assert!(source_allowed("192.0.2.77".parse().unwrap(), &i));
        assert!(!source_allowed("198.51.100.5".parse().unwrap(), &i));
        assert!(!source_allowed("192.0.3.1".parse().unwrap(), &i));
        // caméra sans DHCP, hors du sous-réseau du poste
        assert!(source_allowed("169.254.3.4".parse().unwrap(), &i));
    }

    #[tokio::test]
    async fn ephemeral_socket_does_not_use_the_wsd_port() {
        let mut i = iface();
        i.ip = Ipv4Addr::LOCALHOST;
        let dg = open_ephemeral(&i).unwrap();
        let port = dg.local_port().unwrap();
        assert_ne!(port, 0);
        assert_ne!(port, 3702);
    }
}
