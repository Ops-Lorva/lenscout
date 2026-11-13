//! Sockets UDP multicast réels. Rien ici ne se teste sans réseau : les tests
//! passent par `FakeDatagram`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::transport::{Datagram, NetError};

pub struct UdpDatagram {
    socket: UdpSocket,
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

/// Socket lié au port du groupe, abonné au groupe sur l'interface `iface_ip`
/// et émettant par elle. L'adresse et le port sont partagés (`SO_REUSEADDR`,
/// et `SO_REUSEPORT` hors Windows) : un démon mDNS du poste écoute déjà le
/// 5353. On se lie à `0.0.0.0` et non au groupe, seul portable sous Windows.
pub fn open_multicast(iface_ip: Ipv4Addr, group: SocketAddrV4) -> std::io::Result<UdpDatagram> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))))]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, group.port()).into())?;
    socket.join_multicast_v4(group.ip(), &iface_ip)?;
    socket.set_multicast_if_v4(&iface_ip)?;
    socket.set_nonblocking(true)?;
    Ok(UdpDatagram { socket: UdpSocket::from_std(socket.into())? })
}
