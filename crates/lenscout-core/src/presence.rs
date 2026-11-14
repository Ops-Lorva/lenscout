//! Présence d'une adresse posée, et classement d'un refus d'envoi.
//!
//! Sous macOS l'IP d'un compte passe par le service dupliqué « Lenscout » :
//! `networksetup` rend la main avant que l'adresse soit sur l'interface. Un
//! scan lancé tout de suite ne lie aucun socket (`EADDRNOTAVAIL` sur
//! l'abonnement multicast, qui cherche l'interface par son adresse) :
//! « Aucun socket de découverte ». On attend donc l'adresse avant de scanner.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crate::discovery::arp::ScanInterface;
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

/// Nom de l'interface qui porte `ip`, pour le journal : le service dupliqué
/// de macOS peut la faire apparaître sous un autre nom BSD.
pub fn interface_of(ip: Ipv4Addr) -> Option<String> {
    local_addresses().into_iter().find(|a| a.ip == ip).map(|a| a.name)
}

/// Les adresses IPv4 des liens en service, avec leur masque : une carte peut
/// en porter plusieurs (l'adresse principale et celle d'un compte). Nom = nom
/// BSD / ifname (macOS, Linux), alias d'interface (Windows : cartes
/// matérielles connectées, adresses `Preferred` seulement). Le tri entre
/// cartes (VPN, pont, docker) reste à l'appelant.
#[cfg(unix)]
pub fn local_addresses() -> Vec<ScanInterface> {
    fn v4(sa: *const libc::sockaddr) -> Option<Ipv4Addr> {
        // SAFETY : `sa` vient de `getifaddrs` ; lu seulement s'il est non nul
        // et de famille AF_INET, donc un `sockaddr_in`.
        unsafe {
            if sa.is_null() || i32::from((*sa).sa_family) != libc::AF_INET {
                return None;
            }
            let sin = &*(sa as *const libc::sockaddr_in);
            Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
        }
    }
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    let mut out = Vec::new();
    // SAFETY : `getifaddrs` remplit `head` ; la liste est parcourue en lecture
    // puis rendue par `freeifaddrs`, une seule fois.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let a = &*cur;
            if let (true, Some(ip), Some(mask)) = (link_usable(a.ifa_flags), v4(a.ifa_addr), v4(a.ifa_netmask)) {
                let name = std::ffi::CStr::from_ptr(a.ifa_name).to_string_lossy().into_owned();
                out.push(ScanInterface { name, ip, mask });
            }
            cur = a.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    out
}

/// Lien administrativement levé ET opérationnel (`IFF_UP` + `IFF_RUNNING`).
#[cfg(unix)]
fn link_usable(flags: u32) -> bool {
    let want = (libc::IFF_UP | libc::IFF_RUNNING) as u32;
    flags & want == want
}

/// Windows : une ligne `alias|adresse|longueur de préfixe` par adresse.
#[cfg(target_os = "windows")]
pub fn local_addresses() -> Vec<ScanInterface> {
    const SCRIPT: &str = r#"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
$up = Get-NetAdapter | Where-Object { $_.HardwareInterface -eq $true -and $_.Status -eq 'Up' } | Select-Object -ExpandProperty ifIndex;
Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue | Where-Object { $up -contains $_.InterfaceIndex } | ForEach-Object { "$($_.InterfaceAlias)|$($_.IPAddress)|$($_.PrefixLength)" }"#;
    crate::proc::sync_cmd("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .output()
        .map(|o| parse_windows_addresses(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn local_addresses() -> Vec<ScanInterface> {
    Vec::new()
}

/// Sortie du script de `local_addresses` (Windows) ; les lignes mal formées
/// sont ignorées.
#[cfg(any(target_os = "windows", test))]
fn parse_windows_addresses(text: &str) -> Vec<ScanInterface> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.trim().rsplitn(3, '|');
            let prefix: u32 = f.next()?.parse().ok().filter(|p| *p <= 32)?;
            let ip: Ipv4Addr = f.next()?.parse().ok()?;
            let name = f.next().filter(|n| !n.is_empty())?.to_string();
            let mask = Ipv4Addr::from(u32::MAX.checked_shl(32 - prefix).unwrap_or(0));
            Some(ScanInterface { name, ip, mask })
        })
        .collect()
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

    #[cfg(unix)]
    #[test]
    fn every_ipv4_address_of_the_machine_is_listed_with_its_mask() {
        let all = local_addresses();
        let lo = all.iter().find(|a| a.ip == Ipv4Addr::LOCALHOST).expect("127.0.0.1");
        assert!(lo.name.starts_with("lo"), "{}", lo.name);
        assert_eq!(lo.mask, Ipv4Addr::new(255, 0, 0, 0));
    }

    #[cfg(unix)]
    #[test]
    fn only_running_links_count() {
        let (up, run) = (libc::IFF_UP as u32, libc::IFF_RUNNING as u32);
        assert!(link_usable(up | run));
        assert!(!link_usable(up));
        assert!(!link_usable(run));
        assert!(!link_usable(0));
    }

    #[test]
    fn windows_addresses_are_read_one_per_line() {
        let text = "Wi-Fi|10.0.8.235|24\r\nWi-Fi|192.168.1.10|24\r\nCâble|172.16.0.2|16\r\n|x|\r\nWi-Fi|10.0.0|24\r\nWi-Fi|10.0.0.9|33\r\n";
        let got = parse_windows_addresses(text);
        let want = [
            ("Wi-Fi", "10.0.8.235", "255.255.255.0"),
            ("Wi-Fi", "192.168.1.10", "255.255.255.0"),
            ("Câble", "172.16.0.2", "255.255.0.0"),
        ];
        assert_eq!(got.len(), want.len(), "{got:?}");
        for (g, (n, ip, mask)) in got.iter().zip(want) {
            assert_eq!((g.name.as_str(), g.ip, g.mask), (n, ip.parse().unwrap(), mask.parse().unwrap()));
        }
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
