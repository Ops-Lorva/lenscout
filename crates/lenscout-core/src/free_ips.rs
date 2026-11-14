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

use crate::accounts::Exclusions;
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

/// Les IP exclues d'un compte qui tombent dans ce que `scan` balaierait : à
/// joindre à `exclude`. Lues sur les candidats (1 024 au plus), jamais en
/// dépliant les plages, qui peuvent couvrir un /8.
pub fn excluded_in(iface: &ScanInterface, excluded: &Exclusions) -> HashSet<Ipv4Addr> {
    let prefix = mask_to_prefix(&iface.mask.to_string()).unwrap_or(32) as u8;
    candidates(iface.ip, prefix).0.into_iter().filter(|a| excluded.contains(*a)).collect()
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

/// Le système dont on lit la sortie de `ping`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PingOs {
    Linux,
    Mac,
    Windows,
}

impl PingOs {
    fn current() -> PingOs {
        if cfg!(target_os = "windows") {
            PingOs::Windows
        } else if cfg!(target_os = "macos") {
            PingOs::Mac
        } else {
            PingOs::Linux
        }
    }
}

/// Fragments ASCII (sans accent : la sortie de ping.exe arrive en page de code
/// OEM) des échecs d'envoi de ping.exe, en minuscules : anglais, français, espagnol.
const WINDOWS_SEND_FAILED: [&str; 4] = ["transmit failed", "chec de la transmission", "error en la transmis", "general failure"];

/// Nombre d'échos envoyés d'après la ligne de statistiques de ping.exe
/// (« Sent = 1, Received = 0… », « envoyés = 1, reçus = 0… » : seul le premier
/// nombre après un `=` compte, aucun mot n'est lu). La ligne des temps
/// (« Minimum = … ») vient après et n'est pas regardée.
fn windows_echoes_sent(text: &str) -> Option<u32> {
    let line = text.lines().find(|l| l.matches('=').count() >= 3)?;
    let after = &line[line.find('=')? + 1..];
    let digits: String = after.trim_start().chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Ce que dit un `ping` système. ⚠️ Seul un écho parti sans réponse est
/// `Silent` : toute autre erreur (socket refusé, adresse source disparue…)
/// est `Unsent`, sans quoi une panne locale ferait passer le réseau pour vide.
/// `output` mêle stdout et stderr.
/// Linux : 0 réponse, 1 silence, autre erreur. macOS : 0 réponse, 2 silence,
/// mais un envoi refusé (« sendto: No route to host » quand l'accès au réseau
/// local est refusé) sort aussi en 2 : on lit le texte.
/// Windows rend 0 même pour un hôte injoignable et localise son texte en page
/// de code OEM : `TTL=` pour une réponse, sinon la ligne de statistiques.
fn classify_ping(os: PingOs, code: Option<i32>, output: &str) -> Reply {
    let Some(code) = code else {
        return Reply::Unsent;
    };
    match os {
        PingOs::Linux => match code {
            0 => Reply::Alive,
            1 => Reply::Silent,
            _ => Reply::Unsent,
        },
        PingOs::Mac => {
            let text = output.to_lowercase();
            // « Host is down » (EHOSTDOWN) = ARP sans réponse : un vrai silence,
            // donc candidat libre. Seul « No route to host » trahit le refus local.
            if text.contains("no route to host") {
                return Reply::Unsent;
            }
            match code {
                0 => Reply::Alive,
                2 => Reply::Silent,
                _ => Reply::Unsent,
            }
        }
        PingOs::Windows => {
            let text = output.to_lowercase();
            if text.contains("ttl=") {
                Reply::Alive
            } else if WINDOWS_SEND_FAILED.iter().any(|m| text.contains(m)) {
                Reply::Unsent
            } else if windows_echoes_sent(&text).is_some_and(|sent| sent >= 1) {
                Reply::Silent
            } else {
                Reply::Unsent
            }
        }
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
    let text = format!("{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    Some(classify_ping(PingOs::current(), out.status.code(), &text))
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
    let mut silent: HashSet<Ipv4Addr> = HashSet::new();
    let mut unsent = 0usize;
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
                        Reply::Alive => { taken.insert(a); }
                        Reply::Silent => { silent.insert(a); }
                        Reply::Unsent => unsent += 1,
                    }
                    progress(done, total);
                }
            },
        }
    }
    // Plus d'un tir sur dix qui n'a pas pu partir : le résultat ne dirait rien du réseau.
    if unsent * 10 > total {
        return Err(FreeError::PingUnavailable);
    }
    taken.extend(probe.neighbours().await);
    // Libre = a reçu un ping resté sans réponse ET n'est pas dans l'ARP. Un tir
    // isolé qui n'a pas pu partir n'est jamais libre.
    let free: Vec<Ipv4Addr> = targets.into_iter().filter(|a| silent.contains(a) && !taken.contains(a)).collect();
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
        unsent_for: HashSet<Ipv4Addr>,
        pinged: Mutex<Vec<Ipv4Addr>>,
        /// Nombre de pings attendus avant la lecture ARP ; `None` : pas de contrôle.
        pings_before_arp: Option<usize>,
    }

    impl Fake {
        fn new(alive: &[&str], neigh: &[&str]) -> Fake {
            Fake {
                alive: alive.iter().map(|s| ip(s)).collect(),
                neigh: neigh.iter().map(|s| ip(s)).collect(),
                unsent: false,
                unsent_for: HashSet::new(),
                pinged: Mutex::new(vec![]),
                pings_before_arp: None,
            }
        }
    }

    #[async_trait]
    impl FreeProbe for Fake {
        async fn ping(&self, a: Ipv4Addr) -> Reply {
            self.pinged.lock().unwrap().push(a);
            if self.unsent || self.unsent_for.contains(&a) {
                Reply::Unsent
            } else if self.alive.contains(&a) {
                Reply::Alive
            } else {
                Reply::Silent
            }
        }
        async fn neighbours(&self) -> HashSet<Ipv4Addr> {
            if let Some(n) = self.pings_before_arp {
                assert_eq!(self.pinged.lock().unwrap().len(), n, "l'ARP se lit après tous les pings");
            }
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

    #[test]
    fn account_exclusions_are_read_within_the_scanned_subnet_only() {
        let ex = Exclusions::parse("192.0.2.12-192.0.2.13, 10.0.0.0-10.255.255.255").unwrap();
        let want: HashSet<Ipv4Addr> = [ip("192.0.2.12"), ip("192.0.2.13")].into();
        assert_eq!(excluded_in(&iface(), &ex), want);
        assert!(excluded_in(&iface(), &Exclusions::default()).is_empty());
    }

    #[tokio::test]
    async fn excluded_addresses_are_never_free_nor_first_fit() {
        // /29 : .9 à .14, le poste en .10. Exclues : .12 et .13.
        let ex = Exclusions::parse("192.0.2.12 - 192.0.2.13").unwrap();
        let fake = Arc::new(Fake::new(&[], &[]));
        let out = scan(&iface(), excluded_in(&iface(), &ex), fake.clone(), |_, _| {}, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            out.ranges,
            vec![
                FreeRange { first: ip("192.0.2.9"), last: ip("192.0.2.9"), count: 1 },
                FreeRange { first: ip("192.0.2.11"), last: ip("192.0.2.11"), count: 1 },
                FreeRange { first: ip("192.0.2.14"), last: ip("192.0.2.14"), count: 1 },
            ]
        );
        // Pas même pinguées.
        assert!(!fake.pinged.lock().unwrap().contains(&ip("192.0.2.12")));
        // Deux adresses de suite : aucune plage, l'exclusion coupe .11–.14.
        assert_eq!(first_fit(&out.ranges, 2), None);
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

    fn lan() -> ScanInterface {
        ScanInterface { name: "eth0".into(), ip: ip("192.0.2.10"), mask: ip("255.255.255.0") }
    }

    #[tokio::test]
    async fn scan_reads_arp_only_after_every_ping() {
        let mut fake = Fake::new(&[], &["192.0.2.11"]);
        fake.pings_before_arp = Some(4); // /29 : 5 hôtes sans le poste .10 → .9 .11 .12 .13 .14, moins .12 exclue
        let exclude: HashSet<Ipv4Addr> = [ip("192.0.2.12")].into();
        scan(&iface(), exclude, Arc::new(fake), |_, _| {}, CancellationToken::new()).await.unwrap();
    }

    #[tokio::test]
    async fn scan_reports_a_truncated_big_subnet() {
        let big = ScanInterface { name: "eth0".into(), ip: ip("10.1.2.3"), mask: ip("255.255.0.0") };
        let fake = Arc::new(Fake::new(&[], &[]));
        let out = scan(&big, HashSet::new(), fake.clone(), |_, _| {}, CancellationToken::new()).await.unwrap();
        assert!(out.truncated);
        // 1024 adresses, moins celle du poste.
        assert_eq!(fake.pinged.lock().unwrap().len(), 1023);
        let n: usize = out.ranges.iter().map(|r| r.count).sum();
        assert_eq!(n, 1023);
        let small = scan(&iface(), HashSet::new(), Arc::new(Fake::new(&[], &[])), |_, _| {}, CancellationToken::new())
            .await
            .unwrap();
        assert!(!small.truncated);
    }

    #[tokio::test]
    async fn an_address_that_could_not_be_pinged_is_never_free() {
        let mut fake = Fake::new(&[], &[]);
        fake.unsent_for = [ip("192.0.2.77")].into();
        let out = scan(&lan(), HashSet::new(), Arc::new(fake), |_, _| {}, CancellationToken::new()).await.unwrap();
        assert!(out.ranges.iter().all(|r| !(r.first..=r.last).contains(&ip("192.0.2.77"))));
        // Le poste (.10) et .77 coupent les plages : trois.
        assert_eq!(out.ranges.len(), 3);
        assert_eq!(out.ranges.iter().map(|r| r.count).sum::<usize>(), 252);
    }

    #[tokio::test]
    async fn too_many_unsent_pings_is_an_error() {
        let mut fake = Fake::new(&[], &[]);
        // 26 sur 253 : plus de 10 %.
        fake.unsent_for = (100..126).map(|n| Ipv4Addr::new(192, 0, 2, n)).collect();
        let r = scan(&lan(), HashSet::new(), Arc::new(fake), |_, _| {}, CancellationToken::new()).await;
        assert_eq!(r, Err(FreeError::PingUnavailable));
    }

    // Sorties de ping.exe localisées : les accents arrivent en page de code OEM
    // (ici U+FFFD), seuls les fragments ASCII et les nombres sont fiables.
    #[test]
    fn windows_ping_in_oem_code_page_is_read_without_accents() {
        let cases: &[(Option<i32>, &str, Reply)] = &[
            // Français.
            (Some(0), "R\u{FFFD}ponse de 192.0.2.1 : octets=32 temps<1ms TTL=64\r\nStatistiques Ping pour 192.0.2.1:\r\n    Paquets : envoy\u{FFFD}s = 1, re\u{FFFD}us = 1, perdus = 0 (perte 0%),", Reply::Alive),
            (Some(1), "D\u{FFFD}lai d'attente de la demande d\u{FFFD}pass\u{FFFD}.\r\n\r\nStatistiques Ping pour 192.0.2.10:\r\n    Paquets : envoy\u{FFFD}s = 1, re\u{FFFD}us = 0, perdus = 1 (perte 100%),", Reply::Silent),
            (Some(0), "R\u{FFFD}ponse de 192.0.2.5 : H\u{FFFD}te de destination inaccessible.\r\n\r\nStatistiques Ping pour 192.0.2.10:\r\n    Paquets : envoy\u{FFFD}s = 1, re\u{FFFD}us = 1, perdus = 0 (perte 0%),\r\nDur\u{FFFD}e approximative des boucles en millisecondes :\r\n    Minimum = 0ms, Maximum = 0ms, Moyenne = 0ms", Reply::Silent),
            (Some(1), "PING : \u{FFFD}chec de la transmission. D\u{FFFD}faillance g\u{FFFD}n\u{FFFD}rale.\r\n\r\nStatistiques Ping pour 192.0.2.10:\r\n    Paquets : envoy\u{FFFD}s = 1, re\u{FFFD}us = 0, perdus = 1 (perte 100%),", Reply::Unsent),
            // Espagnol.
            (Some(0), "Respuesta desde 192.0.2.1: bytes=32 tiempo<1m TTL=64\r\nEstad\u{FFFD}sticas de ping para 192.0.2.1:\r\n    Paquetes: enviados = 1, recibidos = 1, perdidos = 0", Reply::Alive),
            (Some(1), "Tiempo de espera agotado para esta solicitud.\r\n\r\nEstad\u{FFFD}sticas de ping para 192.0.2.10:\r\n    Paquetes: enviados = 1, recibidos = 0, perdidos = 1 (100% perdidos),", Reply::Silent),
            (Some(1), "PING: error en la transmisi\u{FFFD}n. Error general.\r\n\r\nEstad\u{FFFD}sticas de ping para 192.0.2.10:\r\n    Paquetes: enviados = 1, recibidos = 0, perdidos = 1 (100% perdidos),", Reply::Unsent),
            // Rien d'exploitable : on ne devine pas « libre ».
            (Some(1), "\u{FFFD}\u{FFFD}\u{FFFD}", Reply::Unsent),
            (Some(1), "", Reply::Unsent),
        ];
        for (code, out, want) in cases {
            assert_eq!(classify_ping(PingOs::Windows, *code, out), *want, "{code:?} {out}");
        }
    }

    #[test]
    fn system_ping_output_is_classified_by_os_code_and_text() {
        use PingOs::*;
        let cases: &[(PingOs, Option<i32>, &str, Reply)] = &[
            (Linux, Some(0), "64 bytes from 192.0.2.1", Reply::Alive),
            (Linux, Some(1), "1 packets transmitted, 0 received", Reply::Silent),
            (Linux, Some(2), "ping: socket: Operation not permitted", Reply::Unsent),
            (Linux, None, "", Reply::Unsent),
            (Mac, Some(0), "64 bytes from 192.0.2.1", Reply::Alive),
            (Mac, Some(2), "0 packets received", Reply::Silent),
            (Mac, Some(1), "ping: bind: Can't assign requested address", Reply::Unsent),
            (Mac, Some(68), "", Reply::Unsent),
            (Windows, Some(0), "Reply from 192.0.2.1: bytes=32 time<1ms TTL=64", Reply::Alive),
            (Windows, Some(1), "Réponse de 192.0.2.1 : octets=32 temps<1ms TTL=64", Reply::Alive),
            (Windows, Some(1), "Request timed out.\r\n\r\nPing statistics for 192.0.2.10:\r\n    Packets: Sent = 1, Received = 0, Lost = 1 (100% loss),", Reply::Silent),
            (Windows, Some(0), "Reply from 192.0.2.10: Destination host unreachable.\r\n\r\nPing statistics for 192.0.2.10:\r\n    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),", Reply::Silent),
            (Windows, Some(1), "Request timed out.", Reply::Unsent),
            (Windows, Some(1), "PING: transmit failed. General failure.", Reply::Unsent),
            (Windows, Some(1), "Bad IP address 192.0.2.1.", Reply::Unsent),
            // macOS : l'envoi refusé (accès Réseau local) sort en code 2 comme un silence.
            (Mac, Some(2), "ping: sendto: No route to host\n1 packets transmitted, 0 packets received", Reply::Unsent),
            (Mac, Some(2), "ping: sendto: Host is down", Reply::Silent),
        ];
        for (os, code, out, want) in cases {
            assert_eq!(classify_ping(*os, *code, out), *want, "{os:?} {code:?} {out}");
        }
    }
}
