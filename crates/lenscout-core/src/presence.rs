//! Présence d'une adresse posée, et classement d'un refus d'envoi.
//!
//! Sous macOS l'IP d'un compte passe par le service dupliqué « Lenscout » :
//! `networksetup` rend la main avant que l'adresse soit sur l'interface. Un
//! scan lancé tout de suite ne lie aucun socket (`EADDRNOTAVAIL` sur
//! l'abonnement multicast, qui cherche l'interface par son adresse) :
//! « Aucun socket de découverte ». On attend donc l'adresse avant de scanner.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crate::transport::NetError;

/// L'adresse est-elle utilisable par le poste ? Le test est celui dont les
/// sockets de découverte ont besoin : s'y lier. Rien n'est envoyé.
pub fn address_present(ip: Ipv4Addr) -> bool {
    UdpSocket::bind(SocketAddrV4::new(ip, 0)).is_ok()
}

/// Interroge `check` toutes les `every` jusqu'à `true`, au plus `timeout`.
/// Rend le dernier verdict.
pub async fn wait_until(mut check: impl FnMut() -> bool, timeout: Duration, every: Duration) -> bool {
    let end = tokio::time::Instant::now() + timeout;
    loop {
        if check() {
            return true;
        }
        if tokio::time::Instant::now() + every > end {
            return false;
        }
        tokio::time::sleep(every).await;
    }
}

/// Nom de l'interface qui porte `ip` (`getifaddrs`), pour le journal : le
/// service dupliqué de macOS peut la faire apparaître sous un autre nom BSD.
#[cfg(unix)]
pub fn interface_of(ip: Ipv4Addr) -> Option<String> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY : `getifaddrs` remplit `head` ; la liste est parcourue en lecture
    // puis rendue par `freeifaddrs`, une seule fois.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return None;
        }
        let mut found = None;
        let mut cur = head;
        while !cur.is_null() {
            let a = &*cur;
            if !a.ifa_addr.is_null() && i32::from((*a.ifa_addr).sa_family) == libc::AF_INET {
                let sin = &*(a.ifa_addr as *const libc::sockaddr_in);
                if Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)) == ip {
                    found = Some(std::ffi::CStr::from_ptr(a.ifa_name).to_string_lossy().into_owned());
                    break;
                }
            }
            cur = a.ifa_next;
        }
        libc::freeifaddrs(head);
        found
    }
}

#[cfg(not(unix))]
pub fn interface_of(_ip: Ipv4Addr) -> Option<String> {
    None
}

/// Code d'erreur d'un scan dont tous les envois ont été refusés.
///
/// macOS rend `EHOSTUNREACH` (« No route to host ») quand la permission
/// « Réseau local » manque — ou n'a pas encore reçu de réponse : l'invite
/// s'affiche au premier envoi, et ceux d'avant la réponse échouent. Mais ce
/// code peut aussi venir d'un envoi depuis l'adresse du compte seule. D'où
/// l'envoi témoin, depuis l'adresse principale de l'interface vers sa
/// passerelle : refusé aussi → refus de toute l'app ; passé → le refus
/// tient à l'adresse du compte.
///
/// `control` : `None` quand il n'y a pas eu de témoin (scan sur l'adresse
/// principale, ou pas de passerelle connue).
pub fn denial_code(all_denied: bool, control: Option<&Result<(), NetError>>) -> Option<&'static str> {
    if !all_denied {
        return None;
    }
    Some(match control {
        Some(Ok(())) => "account_address_denied",
        _ => "local_network_denied",
    })
}

/// Envoi témoin : un octet vers le port « discard » (9/UDP) de `gateway`,
/// depuis `from`. Classé comme les envois du scan.
pub fn control_send(from: Ipv4Addr, gateway: Ipv4Addr) -> Result<(), NetError> {
    let socket = UdpSocket::bind(SocketAddrV4::new(from, 0)).map_err(|e| NetError::Io(e.to_string()))?;
    socket
        .send_to(&[0], SocketAddrV4::new(gateway, 9))
        .map(|_| ())
        .map_err(crate::discovery::socket::send_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn present_only_when_the_address_is_on_the_machine() {
        assert!(address_present(Ipv4Addr::LOCALHOST));
        // TEST-NET-1 : jamais posée sur un poste.
        assert!(!address_present(Ipv4Addr::new(192, 0, 2, 123)));
    }

    #[cfg(unix)]
    #[test]
    fn the_interface_carrying_an_address_is_named() {
        let lo = interface_of(Ipv4Addr::LOCALHOST).unwrap();
        assert!(lo.starts_with("lo"), "{lo}");
        assert_eq!(interface_of(Ipv4Addr::new(192, 0, 2, 123)), None);
    }

    #[tokio::test(start_paused = true)]
    async fn waits_until_the_address_shows_up() {
        let calls = Cell::new(0);
        let start = tokio::time::Instant::now();
        let ok = wait_until(
            || {
                calls.set(calls.get() + 1);
                calls.get() == 4
            },
            Duration::from_secs(5),
            Duration::from_millis(200),
        )
        .await;
        assert!(ok);
        assert_eq!(calls.get(), 4);
        assert_eq!(start.elapsed(), Duration::from_millis(600));
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_the_timeout() {
        let calls = Cell::new(0);
        let start = tokio::time::Instant::now();
        let ok = wait_until(
            || {
                calls.set(calls.get() + 1);
                false
            },
            Duration::from_secs(1),
            Duration::from_millis(250),
        )
        .await;
        assert!(!ok);
        assert_eq!(calls.get(), 5);
        assert!(start.elapsed() <= Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn already_there_means_no_wait() {
        let start = tokio::time::Instant::now();
        assert!(wait_until(|| true, Duration::from_secs(5), Duration::from_millis(200)).await);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[test]
    fn a_refusal_is_classified_by_the_control_send() {
        // Des envois passent : pas de refus.
        assert_eq!(denial_code(false, None), None);
        assert_eq!(denial_code(false, Some(&Err(NetError::Denied))), None);
        // Pas de témoin (scan sur l'adresse principale) : toute l'app.
        assert_eq!(denial_code(true, None), Some("local_network_denied"));
        // Témoin refusé aussi : toute l'app.
        assert_eq!(denial_code(true, Some(&Err(NetError::Denied))), Some("local_network_denied"));
        // Témoin passé : seule l'adresse du compte est refusée.
        assert_eq!(denial_code(true, Some(&Ok(()))), Some("account_address_denied"));
        // Témoin en échec pour une autre raison : on ne sait pas, le message prudent reste.
        assert_eq!(denial_code(true, Some(&Err(NetError::Io("x".into())))), Some("local_network_denied"));
    }

    #[test]
    fn control_send_from_an_absent_address_fails_without_denial() {
        let r = control_send(Ipv4Addr::new(192, 0, 2, 123), Ipv4Addr::new(192, 0, 2, 1));
        assert!(matches!(r, Err(NetError::Io(_))));
        assert!(control_send(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST).is_ok());
    }
}
