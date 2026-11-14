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
    /// Groupes multicast : socket d'envoi lié à l'adresse du scan (voir
    /// `open_multicast`). `None` : on envoie par `socket`.
    sender: Option<UdpSocket>,
    /// Repli de `sender` déjà journalisé (une ligne par socket, pas par envoi).
    fallback_logged: std::sync::atomic::AtomicBool,
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
        if let Some(sender) = &self.sender {
            match sender.send_to(buf, dest).await {
                Ok(_) => return Ok(()),
                // Refusé depuis l'adresse du scan : on envoie quand même, par
                // le socket d'écoute (source = adresse principale).
                Err(e) => {
                    if !self.fallback_logged.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        crate::debug_log::log(&format!(
                            "envoi vers {dest} refusé depuis {:?} ({e}) : repli sur le socket d'écoute",
                            sender.local_addr().ok()
                        ));
                    }
                }
            }
        }
        self.socket
            .send_to(buf, dest)
            .await
            .map(|_| ())
            .map_err(send_error)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        let io = |e: std::io::Error| NetError::Io(e.to_string());
        let Some(sender) = &self.sender else {
            return self.socket.recv_from(buf).await.map_err(io);
        };
        // Réponses au groupe sur `socket`, réponses unicast vers l'adresse
        // source sur `sender` : le premier prêt.
        loop {
            let ready = tokio::select! {
                r = self.socket.readable() => r.map(|()| &self.socket),
                r = sender.readable() => r.map(|()| sender),
            };
            match ready.map_err(io)?.try_recv_from(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                r => return r.map_err(io),
            }
        }
    }
}

/// Erreur d'envoi → `NetError`. Sous macOS, EPERM et EHOSTUNREACH sur un
/// envoi multicast, c'est le système qui refuse (NECP : permission « Réseau
/// local », mais aussi tout autre filtre NECP — d'où l'envoi témoin de
/// `presence::denial_code`) : `Denied`. Ailleurs ces codes disent un pare-feu
/// ou une absence de route, jamais cette permission : `Io`.
pub(crate) fn send_error(e: std::io::Error) -> NetError {
    send_error_on(e, cfg!(target_os = "macos"))
}

fn send_error_on(e: std::io::Error, macos: bool) -> NetError {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::HostUnreachable if macos => NetError::Denied,
        _ => NetError::Io(e.to_string()),
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
    let mut dg = finish(socket)?;
    dg.sender = multicast_sender(iface, group.port()).ok();
    Ok(dg)
}

/// Socket d'envoi d'un groupe : lié à `iface.ip` sur le port du groupe. Lié
/// à `0.0.0.0`, macOS et Windows choisiraient l'adresse principale de la
/// carte comme source, pas celle du compte posée en plus (comme pour
/// `open_ephemeral`). Échec (port refusé par le système) : l'envoi passe par
/// le socket d'écoute, comme avant.
fn multicast_sender(iface: &ScanInterface, port: u16) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))))]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(iface.ip, port).into())?;
    socket.set_multicast_if_v4(&iface.ip)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Socket à port éphémère, émettant par l'interface choisie, sans abonnement.
/// Pour les protocoles dont la réponse revient en unicast sur le port source
/// (WS-Discovery) : partir du port 3702 ferait récupérer la réponse par le
/// service WSD du système (Windows) qui y écoute déjà. Lié à l'adresse du
/// scan : la réponse revient à l'adresse source, qui doit être celle du
/// compte quand elle est posée en plus de l'adresse principale (sinon macOS
/// et Windows prennent la première adresse de l'interface, et la caméra
/// répond vers un réseau qu'elle ne joint pas).
pub fn open_ephemeral(iface: &ScanInterface) -> std::io::Result<UdpDatagram> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind(&SocketAddrV4::new(iface.ip, 0).into())?;
    socket.set_multicast_if_v4(&iface.ip)?;
    socket.set_nonblocking(true)?;
    finish(socket)
}

fn finish(socket: Socket) -> std::io::Result<UdpDatagram> {
    Ok(UdpDatagram { socket: UdpSocket::from_std(socket.into())?, sender: None, fallback_logged: Default::default() })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_send_refused_by_the_system_is_denied_only_on_macos() {
        use std::io::{Error, ErrorKind};
        for kind in [ErrorKind::PermissionDenied, ErrorKind::HostUnreachable] {
            assert!(matches!(send_error_on(Error::from(kind), true), NetError::Denied), "{kind:?}");
            // Linux, Windows : pare-feu, absence de route — pas une permission « Réseau local ».
            assert!(matches!(send_error_on(Error::from(kind), false), NetError::Io(_)), "{kind:?}");
        }
        assert!(matches!(send_error_on(Error::from(ErrorKind::WouldBlock), true), NetError::Io(_)));
        assert!(matches!(send_error_on(Error::from(ErrorKind::AddrNotAvailable), true), NetError::Io(_)));
    }

    /// Le WS-Discovery répond en unicast à l'adresse source : elle doit être
    /// l'IP du scan (celle d'un compte posée en plus), pas l'adresse principale.
    #[tokio::test]
    async fn ephemeral_socket_sends_from_the_scan_address() {
        let mut i = iface();
        i.ip = Ipv4Addr::new(127, 0, 0, 1);
        let dg = open_ephemeral(&i).unwrap();
        assert_eq!(dg.socket.local_addr().unwrap().ip(), std::net::IpAddr::V4(i.ip));
        // Adresse absente du poste : le socket ne s'ouvre pas (pas d'envoi depuis une autre).
        i.ip = Ipv4Addr::new(192, 0, 2, 123);
        assert!(open_ephemeral(&i).is_err());
    }

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

    /// mDNS, SADP : le socket du groupe écoute sur `0.0.0.0`, mais les envois
    /// partent de l'adresse du scan (celle d'un compte posée en plus), sur le
    /// port du groupe ; une réponse unicast vers elle est reçue aussi.
    #[tokio::test]
    async fn multicast_socket_sends_from_the_scan_address() {
        let mut i = iface();
        i.ip = Ipv4Addr::LOCALHOST;
        let port = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port();
        let group = SocketAddrV4::new(Ipv4Addr::new(239, 255, 42, 99), port);
        let dg = open_multicast(&i, group).unwrap();
        let from = dg.sender.as_ref().expect("socket d'envoi").local_addr().unwrap();
        assert_eq!(from, SocketAddr::V4(SocketAddrV4::new(i.ip, port)));
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        dg.send_to(b"q", peer.local_addr().unwrap()).await.unwrap();
        let mut buf = [0u8; 16];
        let (_, seen) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(seen, from);
        peer.send_to(b"r", seen).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), dg.recv_from(&mut buf)).await;
        let (n, _) = got.expect("réponse unicast perdue").unwrap();
        assert_eq!(&buf[..n], b"r");
    }

    /// Envoi refusé depuis l'adresse du scan (macOS : EHOSTUNREACH depuis
    /// l'alias) : repli sur le socket d'écoute plutôt qu'aucun envoi. Ici le
    /// socket d'envoi est lié à la boucle locale, qui ne joint pas 192.0.2.1.
    #[tokio::test]
    async fn a_refused_send_from_the_scan_address_falls_back() {
        let listen = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let dest: SocketAddr = (Ipv4Addr::new(192, 0, 2, 1), 9).into();
        assert!(sender.send_to(b"x", dest).await.is_err(), "boucle locale vers l'extérieur");
        let dg = UdpDatagram { socket: listen, sender: Some(sender), fallback_logged: Default::default() };
        dg.send_to(b"x", dest).await.unwrap();
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
