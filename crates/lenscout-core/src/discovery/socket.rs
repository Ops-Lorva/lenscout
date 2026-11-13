//! Sockets UDP multicast réels. L'envoi et la réception ne se testent pas sans
//! réseau : les tests du scanner passent par `FakeDatagram`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use super::arp::ScanInterface;
use crate::transport::{Datagram, NetError};

pub struct UdpDatagram {
    socket: UdpSocket,
}

impl UdpDatagram {
    /// Port local du socket (utile quand il a été tiré au hasard).
    pub fn local_port(&self) -> std::io::Result<u16> {
        Ok(self.socket.local_addr()?.port())
    }
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
        self.socket
            .recv_from(buf)
            .await
            .map_err(|e| NetError::Io(e.to_string()))
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
    // autres sockets du système, sur toutes les interfaces. Sous macOS et
    // Windows aucun filtre de source : perdre une caméra hors du sous-réseau
    // du poste (ancienne Axis en 192.168.0.90) est pire que voir un appareil
    // d'une autre carte.
    #[cfg(target_os = "linux")]
    socket.set_multicast_all_v4(false)?;
    socket.join_multicast_v4(group.ip(), &iface.ip)?;
    socket.set_multicast_if_v4(&iface.ip)?;
    socket.set_nonblocking(true)?;
    finish(socket)
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
    finish(socket)
}

fn finish(socket: Socket) -> std::io::Result<UdpDatagram> {
    Ok(UdpDatagram { socket: UdpSocket::from_std(socket.into())? })
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

    /// Une caméra hors du sous-réseau du poste (ancienne Axis en 192.168.0.90,
    /// poste en 10.0.50.x) doit rester visible : ici l'expéditeur 127.1.0.1 est
    /// hors du /24 de l'interface (127.0.0.1/24).
    #[tokio::test]
    async fn datagram_from_outside_the_interface_subnet_is_received() {
        let mut i = iface();
        i.ip = Ipv4Addr::LOCALHOST;
        i.mask = "255.255.255.0".parse().unwrap();
        let dg = open_ephemeral(&i).unwrap();
        let port = dg.local_port().unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::new(127, 1, 0, 1), 0)).await.unwrap();
        sender.send_to(b"hello", (Ipv4Addr::LOCALHOST, port)).await.unwrap();
        let mut buf = [0u8; 16];
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), dg.recv_from(&mut buf)).await;
        let (n, from) = got.expect("datagramme écarté").unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from.ip(), Ipv4Addr::new(127, 1, 0, 1));
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
