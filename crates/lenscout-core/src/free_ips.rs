//! Adresses libres du sous-réseau d'une interface : ping puis table ARP, les
//! adresses sans réponse sont regroupées en plages.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use ping_async::{IcmpEchoRequestor, IcmpEchoStatus};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::discovery::arp::{ScanInterface, read_neighbours};
use crate::interfaces::mask_to_prefix;
use crate::proc::async_cmd;

/// Délai d'attente d'un ping : court, le réseau est local.
const PING_TIMEOUT_MS: u64 = 600;
/// Pings en vol en même temps.
const CONCURRENCY: usize = 64;
/// Plus grand nombre d'adresses balayées ; au-delà, celles du poste d'abord.
const MAX_CANDIDATES: usize = 1024;

/// Une suite d'adresses libres consécutives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FreeRange {
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
    pub count: usize,
}

/// Fusionne les adresses libres consécutives en plages, triées par adresse.
pub fn ranges(free: &[Ipv4Addr]) -> Vec<FreeRange> {
    let mut sorted: Vec<u32> = free.iter().map(|a| u32::from(*a)).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out: Vec<FreeRange> = Vec::new();
    for n in sorted {
        match out.last_mut() {
            Some(r) if u32::from(r.last).checked_add(1) == Some(n) => {
                r.last = Ipv4Addr::from(n);
                r.count += 1;
            }
            _ => out.push(FreeRange { first: Ipv4Addr::from(n), last: Ipv4Addr::from(n), count: 1 }),
        }
    }
    out
}

/// Les hôtes du sous-réseau, sans adresse réseau ni diffusion. Au-delà de
/// `MAX_CANDIDATES`, les plus proches de l'adresse du poste ; le second
/// élément dit que la liste est tronquée.
pub fn candidates(iface_ip: Ipv4Addr, prefix: u8) -> (Vec<Ipv4Addr>, bool) {
    if prefix >= 31 {
        return (vec![], false);
    }
    let mask = u64::from(u32::MAX) << (32 - u32::from(prefix)) & u64::from(u32::MAX);
    let network = u64::from(u32::from(iface_ip)) & mask;
    let broadcast = network | (!mask & u64::from(u32::MAX));
    let (first, last) = (network + 1, broadcast - 1);
    let total = (last - first + 1) as usize;
    if total <= MAX_CANDIDATES {
        return ((first..=last).map(|n| Ipv4Addr::from(n as u32)).collect(), false);
    }
    // Fenêtre de MAX_CANDIDATES adresses centrée sur le poste, ramenée dans le sous-réseau.
    let host = u64::from(u32::from(iface_ip)).clamp(first, last);
    let start = host.saturating_sub((MAX_CANDIDATES / 2) as u64).clamp(first, last + 1 - MAX_CANDIDATES as u64);
    ((start..start + MAX_CANDIDATES as u64).map(|n| Ipv4Addr::from(n as u32)).collect(), true)
}

/// La première adresse d'une plage d'au moins `n` adresses.
pub fn first_fit(ranges: &[FreeRange], n: usize) -> Option<Ipv4Addr> {
    if n == 0 {
        return None;
    }
    ranges.iter().find(|r| r.count >= n).map(|r| r.first)
}

/// Ce qu'un tir de ping apprend de l'hôte visé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Alive,
    /// Le tir est parti, rien n'est revenu : une adresse peut quand même être prise.
    Silent,
    /// Le poste n'a pas pu émettre : rien n'est appris sur l'hôte.
    Unsent,
}

/// Les deux sources du balayage ; les faux des tests n'ouvrent aucun socket.
#[async_trait]
pub trait FreeProbe: Send + Sync {
    async fn ping(&self, ip: Ipv4Addr) -> Reply;
    /// Voisins ARP de l'interface, lus après les pings.
    async fn neighbours(&self) -> HashSet<Ipv4Addr>;
}

/// Ping ICMP non privilégié (`ping-async`) depuis l'adresse de l'interface,
/// repli sur le ping du système si le socket ne s'ouvre pas, puis table ARP.
pub struct SystemProbe {
    pub iface: ScanInterface,
}

#[async_trait]
impl FreeProbe for SystemProbe {
    async fn ping(&self, ip: Ipv4Addr) -> Reply {
        // macOS : /sbin/ping (setuid) est plus fiable que le socket ICMP non privilégié.
        #[cfg(target_os = "macos")]
        if let Some(r) = system_ping(ip, self.iface.ip).await {
            return r;
        }
        match icmp_attempt(ip, self.iface.ip).await {
            Reply::Unsent => system_ping(ip, self.iface.ip).await.unwrap_or(Reply::Unsent),
            r => r,
        }
    }

    async fn neighbours(&self) -> HashSet<Ipv4Addr> {
        read_neighbours(&self.iface).await.into_keys().collect()
    }
}

// Repris de LanProbe crates/lanprobe-core/src/ping.rs le 2026-11-14, réduit à un tir ICMP
// (le sondage TCP de repli n'a pas de sens ici : la table ARP complète).
async fn icmp_attempt(ip: Ipv4Addr, src: Ipv4Addr) -> Reply {
    // ⚠️ Échouer ici, c'est ne pas avoir de socket : un fait sur NOUS, pas sur l'hôte.
    let Ok(requestor) = IcmpEchoRequestor::new(
        IpAddr::V4(ip),
        Some(IpAddr::V4(src)),
        None,
        Some(Duration::from_millis(PING_TIMEOUT_MS)),
    ) else {
        return Reply::Unsent;
    };
    let Ok(reply) = requestor.send().await else {
        return Reply::Unsent;
    };
    match reply.status() {
        IcmpEchoStatus::Success => Reply::Alive,
        _ => Reply::Silent,
    }
}

/// Ping du système, source forcée sur l'interface choisie. `None` si le
/// programme n'a pas pu être lancé.
async fn system_ping(ip: Ipv4Addr, src: Ipv4Addr) -> Option<Reply> {
    let (ip, src) = (ip.to_string(), src.to_string());
    let timeout = PING_TIMEOUT_MS.to_string();
    let mut cmd;
    #[cfg(target_os = "windows")]
    {
        cmd = async_cmd("ping");
        cmd.args(["-n", "1", "-w", &timeout, "-S", &src, &ip]);
    }
    #[cfg(target_os = "macos")]
    {
        cmd = async_cmd("/sbin/ping");
        cmd.args(["-c", "1", "-n", "-W", &timeout, "-S", &src, &ip]);
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        cmd = async_cmd("ping");
        // -W en secondes sous Linux.
        cmd.args(["-c", "1", "-n", "-W", "1", "-I", &src, &ip]);
        let _ = &timeout;
    }
    let out = cmd.output().await.ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    // Windows rend 0 même pour « hôte injoignable » : on exige un TTL.
    let ok = out.status.success() && (cfg!(not(target_os = "windows")) || text.contains("ttl="));
    Some(if ok { Reply::Alive } else { Reply::Silent })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FreeScan {
    pub ranges: Vec<FreeRange>,
    /// Le sous-réseau dépasse ce qui est balayé : seules les adresses proches du poste l'ont été.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FreeError {
    #[error("cancelled")]
    Cancelled,
    /// Aucun ping n'a pu partir : un résultat « tout est libre » serait faux.
    #[error("ping_unavailable")]
    PingUnavailable,
}

/// Balaie le sous-réseau de `iface` : ce qui répond au ping, figure dans la
/// table ARP, est dans `exclude` ou est l'adresse du poste n'est pas libre.
/// `progress(faits, total)` est appelé à chaque ping terminé.
pub async fn scan(
    iface: &ScanInterface,
    exclude: HashSet<Ipv4Addr>,
    probe: Arc<dyn FreeProbe>,
    progress: impl Fn(usize, usize),
    cancel: CancellationToken,
) -> Result<FreeScan, FreeError> {
    let prefix = mask_to_prefix(&iface.mask.to_string()).unwrap_or(32) as u8;
    let (all, truncated) = candidates(iface.ip, prefix);
    let targets: Vec<Ipv4Addr> = all.into_iter().filter(|a| *a != iface.ip && !exclude.contains(a)).collect();
    let total = targets.len();
    if cancel.is_cancelled() {
        return Err(FreeError::Cancelled);
    }
    progress(0, total);

    let mut taken: HashSet<Ipv4Addr> = HashSet::new();
    let mut sent = 0usize;
    let mut done = 0usize;
    let mut replies = futures_util::stream::iter(targets.clone())
        .map(|a| {
            let probe = probe.clone();
            async move { (a, probe.ping(a).await) }
        })
        .buffer_unordered(CONCURRENCY);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(FreeError::Cancelled),
            next = replies.next() => match next {
                None => break,
                Some((a, r)) => {
                    done += 1;
                    match r {
                        Reply::Alive => { sent += 1; taken.insert(a); }
                        Reply::Silent => sent += 1,
                        Reply::Unsent => {}
                    }
                    progress(done, total);
                }
            },
        }
    }
    if total > 0 && sent == 0 {
        return Err(FreeError::PingUnavailable);
    }
    taken.extend(probe.neighbours().await);
    let free: Vec<Ipv4Addr> = targets.into_iter().filter(|a| !taken.contains(a)).collect();
    Ok(FreeScan { ranges: ranges(&free), truncated })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn ranges_merges_consecutive() {
        let free = [ip("10.0.0.9"), ip("10.0.0.2"), ip("10.0.0.3"), ip("10.0.0.4"), ip("10.0.0.2"), ip("10.0.0.20")];
        assert_eq!(
            ranges(&free),
            vec![
                FreeRange { first: ip("10.0.0.2"), last: ip("10.0.0.4"), count: 3 },
                FreeRange { first: ip("10.0.0.9"), last: ip("10.0.0.9"), count: 1 },
                FreeRange { first: ip("10.0.0.20"), last: ip("10.0.0.20"), count: 1 },
            ]
        );
    }

    #[test]
    fn ranges_empty() {
        assert!(ranges(&[]).is_empty());
    }

    #[test]
    fn candidates_excludes_network_and_broadcast() {
        let (c, truncated) = candidates(ip("192.0.2.10"), 24);
        assert!(!truncated);
        assert_eq!(c.len(), 254);
        assert_eq!(c[0], ip("192.0.2.1"));
        assert_eq!(*c.last().unwrap(), ip("192.0.2.254"));
        assert!(candidates(ip("192.0.2.10"), 31).0.is_empty());
    }

    #[test]
    fn candidates_caps_large_subnet_around_host() {
        let (c, truncated) = candidates(ip("10.1.2.3"), 16);
        assert!(truncated);
        assert_eq!(c.len(), 1024);
        // Les adresses les plus proches du poste, sans sortir du sous-réseau.
        assert_eq!(c[0], ip("10.1.0.3"));
        assert_eq!(*c.last().unwrap(), ip("10.1.4.2"));
        let (c, _) = candidates(ip("10.1.100.0"), 16);
        assert_eq!(c.len(), 1024);
        assert!(c.contains(&ip("10.1.100.0")) && c.contains(&ip("10.1.98.0")) && c.contains(&ip("10.1.101.255")));
        let (c, truncated) = candidates(ip("10.1.255.200"), 16);
        assert!(truncated);
        assert_eq!(*c.last().unwrap(), ip("10.1.255.254"));
    }

    #[test]
    fn first_fit_skips_small_ranges() {
        let r = ranges(&[ip("10.0.0.5"), ip("10.0.0.6"), ip("10.0.0.20"), ip("10.0.0.21"), ip("10.0.0.22")]);
        assert_eq!(first_fit(&r, 1), Some(ip("10.0.0.5")));
        assert_eq!(first_fit(&r, 3), Some(ip("10.0.0.20")));
        assert_eq!(first_fit(&r, 4), None);
        assert_eq!(first_fit(&r, 0), None);
    }

    struct Fake {
        alive: HashSet<Ipv4Addr>,
        neigh: HashSet<Ipv4Addr>,
        unsent: bool,
        pinged: Mutex<Vec<Ipv4Addr>>,
    }

    impl Fake {
        fn new(alive: &[&str], neigh: &[&str]) -> Fake {
            Fake {
                alive: alive.iter().map(|s| ip(s)).collect(),
                neigh: neigh.iter().map(|s| ip(s)).collect(),
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
        async fn neighbours(&self) -> HashSet<Ipv4Addr> {
            self.neigh.clone()
        }
    }

    fn iface() -> ScanInterface {
        ScanInterface { name: "eth0".into(), ip: ip("192.0.2.10"), mask: ip("255.255.255.248") }
    }

    // 192.0.2.8/29 : hôtes .9 à .14 ; le poste est .10.
    #[tokio::test]
    async fn scan_excludes_given_addresses() {
        let fake = Arc::new(Fake::new(&["192.0.2.9"], &["192.0.2.11"]));
        let exclude: HashSet<Ipv4Addr> = [ip("192.0.2.12")].into();
        let calls = Mutex::new(vec![]);
        let out = scan(&iface(), exclude, fake.clone(), |d, t| calls.lock().unwrap().push((d, t)), CancellationToken::new())
            .await
            .unwrap();
        // .9 répond au ping, .10 est le poste, .11 est en ARP, .12 est exclue : restent .13 et .14.
        assert_eq!(out.ranges, vec![FreeRange { first: ip("192.0.2.13"), last: ip("192.0.2.14"), count: 2 }]);
        assert!(!out.truncated);
        let pinged = fake.pinged.lock().unwrap();
        assert!(!pinged.contains(&ip("192.0.2.10")) && !pinged.contains(&ip("192.0.2.12")));
        let calls = calls.lock().unwrap();
        assert_eq!(calls.last(), Some(&(4, 4)));
    }

    #[tokio::test]
    async fn scan_stops_when_cancelled() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let r = scan(&iface(), HashSet::new(), Arc::new(Fake::new(&[], &[])), |_, _| {}, cancel).await;
        assert_eq!(r, Err(FreeError::Cancelled));
    }

    #[tokio::test]
    async fn scan_without_any_sendable_ping_is_an_error_not_an_empty_network() {
        let mut fake = Fake::new(&[], &[]);
        fake.unsent = true;
        let r = scan(&iface(), HashSet::new(), Arc::new(fake), |_, _| {}, CancellationToken::new()).await;
        assert_eq!(r, Err(FreeError::PingUnavailable));
    }
}
