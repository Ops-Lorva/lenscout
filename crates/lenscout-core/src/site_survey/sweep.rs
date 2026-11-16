//! Balayage du sous-réseau : ping de masse puis table ARP, MAC comprises.

use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::discovery::arp::ScanInterface;
use crate::free_ips::{FreeError, FreeProbe, candidates, ping_all};
use crate::interfaces::mask_to_prefix;

/// Un hôte entendu : a répondu au ping (`replied`) ou figure dans la table
/// ARP ; `mac` vient de l'ARP (aucune à travers un routeur).
#[derive(Debug, Clone, PartialEq)]
pub struct HostSeen {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub replied: bool,
}

/// Balaie le sous-réseau de `iface` comme la recherche d'IP libres (mêmes
/// candidats, 1 024 au plus autour du poste ; même ping de masse ; même
/// règle `PingUnavailable`), puis lit la table ARP. Rend les hôtes entendus,
/// triés par adresse, sans celle du poste ; le booléen dit que le
/// sous-réseau n'a été balayé qu'en partie.
pub async fn sweep(
    iface: &ScanInterface,
    probe: Arc<dyn FreeProbe>,
    progress: impl Fn(usize, usize),
    cancel: CancellationToken,
) -> Result<(Vec<HostSeen>, bool), FreeError> {
    let prefix = mask_to_prefix(&iface.mask.to_string()).unwrap_or(32) as u8;
    let (all, truncated) = candidates(iface.ip, prefix);
    let targets: Vec<Ipv4Addr> = all.into_iter().filter(|a| *a != iface.ip).collect();
    let pinged = ping_all(&targets, probe.as_ref(), progress, &cancel).await?;
    let arp = probe.neighbours().await;
    let hosts = targets
        .into_iter()
        .filter(|a| pinged.alive.contains(a) || arp.contains_key(a))
        .map(|ip| HostSeen { ip, mac: arp.get(&ip).cloned(), replied: pinged.alive.contains(&ip) })
        .collect();
    Ok((hosts, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::free_ips::Reply;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    struct Fake {
        alive: HashSet<Ipv4Addr>,
        arp: HashMap<Ipv4Addr, String>,
        unsent: bool,
        pinged: Mutex<Vec<Ipv4Addr>>,
    }

    impl Fake {
        fn new(alive: &[&str], arp: &[(&str, &str)]) -> Fake {
            Fake {
                alive: alive.iter().map(|s| ip(s)).collect(),
                arp: arp.iter().map(|(a, m)| (ip(a), m.to_string())).collect(),
                unsent: false,
                pinged: Mutex::new(vec![]),
            }
        }
    }

    #[async_trait]
    impl FreeProbe for Fake {
        async fn ping(&self, a: Ipv4Addr) -> Reply {
            self.pinged.lock().unwrap().push(a);
            if self.unsent {
                Reply::Unsent
            } else if self.alive.contains(&a) {
                Reply::Alive
            } else {
                Reply::Silent
            }
        }
        async fn neighbours(&self) -> HashMap<Ipv4Addr, String> {
            self.arp.clone()
        }
    }

    /// 192.0.2.8/29 : hôtes .9 à .14 ; le poste est .10.
    fn iface() -> ScanInterface {
        ScanInterface { name: "eth0".into(), ip: ip("192.0.2.10"), mask: ip("255.255.255.248") }
    }

    #[tokio::test]
    async fn sweep_lists_ping_replies_and_arp_only_hosts_with_their_mac() {
        let fake = Arc::new(Fake::new(&["192.0.2.9", "192.0.2.12"], &[("192.0.2.12", "AA:BB:CC:00:00:12"), ("192.0.2.13", "AA:BB:CC:00:00:13")]));
        let calls = Mutex::new(vec![]);
        let (hosts, truncated) = sweep(&iface(), fake, |d, t| calls.lock().unwrap().push((d, t)), CancellationToken::new()).await.unwrap();
        assert!(!truncated);
        assert_eq!(
            hosts,
            vec![
                HostSeen { ip: ip("192.0.2.9"), mac: None, replied: true },
                HostSeen { ip: ip("192.0.2.12"), mac: Some("AA:BB:CC:00:00:12".into()), replied: true },
                HostSeen { ip: ip("192.0.2.13"), mac: Some("AA:BB:CC:00:00:13".into()), replied: false },
            ]
        );
        assert_eq!(calls.lock().unwrap().last(), Some(&(5, 5)));
    }

    #[tokio::test]
    async fn sweep_never_lists_silent_hosts_absent_from_arp() {
        let (hosts, _) = sweep(&iface(), Arc::new(Fake::new(&[], &[])), |_, _| {}, CancellationToken::new()).await.unwrap();
        assert!(hosts.is_empty());
    }

    #[tokio::test]
    async fn sweep_excludes_the_pc_address() {
        let fake = Arc::new(Fake::new(&["192.0.2.10"], &[("192.0.2.10", "AA:BB:CC:00:00:10")]));
        let (hosts, _) = sweep(&iface(), fake.clone(), |_, _| {}, CancellationToken::new()).await.unwrap();
        assert!(hosts.is_empty());
        assert!(!fake.pinged.lock().unwrap().contains(&ip("192.0.2.10")));
        // Une entrée ARP hors du sous-réseau balayé n'est pas un hôte de ce réseau.
        let fake = Arc::new(Fake::new(&[], &[("10.9.9.9", "AA:BB:CC:00:00:99")]));
        assert!(sweep(&iface(), fake, |_, _| {}, CancellationToken::new()).await.unwrap().0.is_empty());
    }

    #[tokio::test]
    async fn sweep_is_capped_like_free_ips_and_says_truncated() {
        let big = ScanInterface { name: "eth0".into(), ip: ip("10.1.2.3"), mask: ip("255.255.0.0") };
        let fake = Arc::new(Fake::new(&[], &[]));
        let (_, truncated) = sweep(&big, fake.clone(), |_, _| {}, CancellationToken::new()).await.unwrap();
        assert!(truncated);
        assert_eq!(fake.pinged.lock().unwrap().len(), 1023);
    }

    #[tokio::test]
    async fn sweep_cancelled() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let r = sweep(&iface(), Arc::new(Fake::new(&[], &[])), |_, _| {}, cancel).await;
        assert_eq!(r, Err(FreeError::Cancelled));
    }

    #[tokio::test]
    async fn sweep_ping_unavailable() {
        let mut fake = Fake::new(&[], &[]);
        fake.unsent = true;
        let r = sweep(&iface(), Arc::new(fake), |_, _| {}, CancellationToken::new()).await;
        assert_eq!(r, Err(FreeError::PingUnavailable));
    }
}
