//! Route du poste vers une adresse, telle que le système la choisit : par une
//! passerelle (réseau routé, un autre VLAN) ou directement sur le lien.
//!
//! ⚠️ À interroger AVANT de poser une adresse : une fois l'IP d'un compte
//! posée, le réseau est connecté et la route passe par le lien, même si le
//! routeur savait le joindre (sur macOS, la route connectée coupe même
//! l'accès routé : « Host is down »).

use std::net::Ipv4Addr;
use std::time::Duration;

use async_trait::async_trait;

use crate::proc::async_cmd;

/// Délai laissé à la commande du système.
const ROUTE_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Par cette passerelle : l'adresse est sur un autre réseau.
    Routed(Ipv4Addr),
    /// Sur le lien de cette interface (nom système : en0, eth0, alias Windows).
    OnLink(String),
    /// La commande a échoué ou sa sortie ne se lit pas : on ne suppose rien.
    Unknown,
}

/// La route vers une adresse ; le faux des tests rend une réponse fixe.
#[async_trait]
pub trait Routes: Send + Sync {
    async fn route_to(&self, ip: Ipv4Addr) -> Route;
}

/// `route -n get` (macOS), `ip -4 route get` (Linux), `Find-NetRoute` (Windows).
pub struct SystemRoutes;

#[async_trait]
impl Routes for SystemRoutes {
    async fn route_to(&self, ip: Ipv4Addr) -> Route {
        // L'adresse est un `Ipv4Addr` : rien d'autre ne peut entrer dans la commande.
        let ip = ip.to_string();
        #[cfg(target_os = "macos")]
        let (mut cmd, parse) = {
            let mut c = async_cmd("/sbin/route");
            c.args(["-n", "get", &ip]);
            (c, parse_macos as fn(&str) -> Route)
        };
        #[cfg(target_os = "windows")]
        let (mut cmd, parse) = {
            let script = format!(
                "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
                 Find-NetRoute -RemoteIPAddress '{ip}' -ErrorAction SilentlyContinue | Where-Object {{ $_.NextHop }} | \
                 ForEach-Object {{ \"$($_.NextHop)|$($_.InterfaceAlias)\" }}"
            );
            let mut c = async_cmd("powershell");
            c.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
            (c, parse_windows as fn(&str) -> Route)
        };
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let (mut cmd, parse) = {
            let mut c = async_cmd("ip");
            c.args(["-4", "route", "get", &ip]);
            (c, parse_linux as fn(&str) -> Route)
        };
        cmd.kill_on_drop(true);
        match tokio::time::timeout(ROUTE_TIMEOUT, cmd.output()).await {
            Ok(Ok(out)) if out.status.success() => parse(&String::from_utf8_lossy(&out.stdout)),
            _ => Route::Unknown,
        }
    }
}

/// `route -n get <ip>` : une ligne `gateway:` portant une IPv4 dit « routé » ;
/// sans elle, la ligne `interface:` dit « sur le lien ».
pub fn parse_macos(text: &str) -> Route {
    let field = |name: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.trim().split_once(':')?;
            (k.trim() == name).then(|| v.trim().to_string())
        })
    };
    // `gateway:` peut aussi nommer un lien (`link#4`) : seule une IPv4 est une passerelle.
    if let Some(gw) = field("gateway").and_then(|g| g.parse::<Ipv4Addr>().ok()) {
        return Route::Routed(gw);
    }
    match field("interface") {
        Some(i) if !i.is_empty() => Route::OnLink(i),
        _ => Route::Unknown,
    }
}

/// `ip -4 route get <ip>` : `… via <passerelle> dev <if> …` ou `… dev <if> …`.
pub fn parse_linux(text: &str) -> Route {
    let line = text.lines().next().unwrap_or_default();
    let words: Vec<&str> = line.split_whitespace().collect();
    let after = |key: &str| words.iter().position(|w| *w == key).and_then(|i| words.get(i + 1)).copied();
    if let Some(gw) = after("via").and_then(|g| g.parse::<Ipv4Addr>().ok()) {
        return Route::Routed(gw);
    }
    match after("dev") {
        Some(dev) => Route::OnLink(dev.to_string()),
        None => Route::Unknown,
    }
}

/// Script de `SystemRoutes` sous Windows : `NextHop|InterfaceAlias` ;
/// `0.0.0.0` (ou rien) comme NextHop : sur le lien.
pub fn parse_windows(text: &str) -> Route {
    let Some((hop, alias)) = text.lines().find_map(|l| l.trim().split_once('|')) else {
        return Route::Unknown;
    };
    let alias = alias.trim();
    match hop.trim().parse::<Ipv4Addr>() {
        Ok(gw) if !gw.is_unspecified() => Route::Routed(gw),
        Ok(_) if !alias.is_empty() => Route::OnLink(alias.to_string()),
        _ => Route::Unknown,
    }
}

/// Adresse dont on demande la route pour joindre un réseau : sa passerelle si
/// elle en fait partie, sinon la première adresse d'hôte. `None` pour un /31
/// ou un /32, qui n'ont pas d'hôte à part.
pub fn probe_address(network: Ipv4Addr, mask: Ipv4Addr, gateway: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
    let m = u32::from(mask);
    if m.count_ones() >= 31 {
        return None;
    }
    let net = u32::from(network) & m;
    gateway.filter(|g| u32::from(*g) & m == net && *g != Ipv4Addr::from(net) && *g != Ipv4Addr::from(net | !m))
        .or(Some(Ipv4Addr::from(net + 1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// Sortie réelle (macOS, Wi-Fi en 10.0.8.235/24) quand 10.0.20.2/24 est
    /// posée sur en0 : la route connectée passe par le lien.
    const MACOS_ON_LINK: &str = "   route to: 10.0.20.1
destination: 10.0.20.1
  interface: en0
      flags: <UP,HOST,DONE,LLINFO,WASCLONED,IFSCOPE,IFREF>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500      1199
";

    /// Même poste sans adresse posée : par le routeur du VLAN 8.
    const MACOS_ROUTED: &str = "   route to: 10.0.20.1
destination: default
       mask: default
    gateway: 10.0.8.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";

    #[test]
    fn macos_une_ligne_gateway_dit_route() {
        assert_eq!(parse_macos(MACOS_ROUTED), Route::Routed(ip("10.0.8.1")));
        assert_eq!(parse_macos(MACOS_ON_LINK), Route::OnLink("en0".into()));
    }

    #[test]
    fn macos_une_passerelle_qui_n_est_pas_une_ipv4_est_le_lien() {
        let link = "   route to: 10.0.8.50\ndestination: 10.0.8.0\n       mask: 255.255.255.0\n    gateway: link#4\n  interface: en0\n";
        assert_eq!(parse_macos(link), Route::OnLink("en0".into()));
        assert_eq!(parse_macos("route: writing to routing socket: not in table\n"), Route::Unknown);
        assert_eq!(parse_macos(""), Route::Unknown);
    }

    #[test]
    fn linux_via_dit_route_dev_seul_dit_le_lien() {
        let routed = "10.0.20.1 via 10.0.8.1 dev wlp2s0 src 10.0.8.235 uid 1000 \n    cache \n";
        assert_eq!(parse_linux(routed), Route::Routed(ip("10.0.8.1")));
        let on_link = "10.0.20.5 dev eth0 src 10.0.20.2 uid 1000 \n    cache \n";
        assert_eq!(parse_linux(on_link), Route::OnLink("eth0".into()));
        assert_eq!(parse_linux(""), Route::Unknown);
        assert_eq!(parse_linux("RTNETLINK answers: Network is unreachable"), Route::Unknown);
    }

    #[test]
    fn windows_next_hop_nul_dit_le_lien() {
        assert_eq!(parse_windows("10.0.8.1|Wi-Fi\r\n"), Route::Routed(ip("10.0.8.1")));
        assert_eq!(parse_windows("0.0.0.0|Ethernet 2\r\n"), Route::OnLink("Ethernet 2".into()));
        assert_eq!(parse_windows(""), Route::Unknown);
        assert_eq!(parse_windows("x|Wi-Fi"), Route::Unknown);
    }

    #[test]
    fn on_interroge_la_passerelle_du_compte_sinon_le_premier_hote() {
        let m = ip("255.255.255.0");
        assert_eq!(probe_address(ip("10.0.20.2"), m, Some(ip("10.0.20.254"))), Some(ip("10.0.20.254")));
        assert_eq!(probe_address(ip("10.0.20.2"), m, None), Some(ip("10.0.20.1")));
        // Passerelle hors du réseau, ou adresse réseau / diffusion : ignorée.
        for gw in ["10.0.21.1", "10.0.20.0", "10.0.20.255"] {
            assert_eq!(probe_address(ip("10.0.20.2"), m, Some(ip(gw))), Some(ip("10.0.20.1")), "{gw}");
        }
        assert_eq!(probe_address(ip("10.0.20.2"), ip("255.255.255.254"), None), None);
    }
}
