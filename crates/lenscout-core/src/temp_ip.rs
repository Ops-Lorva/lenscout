//! IP temporaire ajoutée au poste, avec les droits administrateur, pour
//! joindre une caméra hors de son sous-réseau (Axis neuve en 169.254.x.x,
//! ancienne Axis en 192.168.0.90), puis retirée quoi qu'il arrive.
//!
//! Le mécanisme d'élévation est repris de LanProbe
//! `crates/lanprobe-core/src/configure.rs` (2026-11-13) : macOS
//! `networksetup` par `sudo -n` (règle sudoers) ou `osascript … with
//! administrator privileges`, Windows `.bat` lancé par `Start-Process -Verb
//! RunAs`, Linux `nmcli`. Les plans sont des valeurs pures, testées sans
//! rien exécuter ; seul `SystemElevator` touche le poste.
//!
//! Garantie de retrait : le journal (`temp-ip.json`) est écrit AVANT l'ajout
//! et retiré seulement après un retrait réussi. Si l'app est tuée entre les
//! deux, `cleanup_leftover` (appelé au démarrage) retire l'adresse.

use std::future::Future;
use std::net::Ipv4Addr;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use futures_util::FutureExt;
use serde::{Deserialize, Serialize};

/// Nom du service networksetup dupliqué sur macOS.
const MACOS_SERVICE: &str = "Lenscout";

/// Une adresse ajoutée au poste : c'est aussi le contenu du journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempIp {
    pub iface: String,
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsKind {
    Macos,
    Windows,
    Linux,
}

impl OsKind {
    pub fn current() -> OsKind {
        if cfg!(target_os = "macos") {
            OsKind::Macos
        } else if cfg!(target_os = "windows") {
            OsKind::Windows
        } else {
            OsKind::Linux
        }
    }
}

/// Ce qui sera exécuté avec les droits administrateur : arguments de
/// `networksetup` (une commande par ligne), texte d'un `.bat`, arguments de
/// `nmcli`.
#[derive(Debug, Clone, PartialEq)]
pub enum ElevatedPlan {
    Networksetup(Vec<Vec<String>>),
    Bat(String),
    Nmcli(Vec<Vec<String>>),
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum TempIpError {
    /// Invite annulée : UAC « Non », mot de passe macOS annulé, polkit refusé.
    #[error("droits administrateur refusés")]
    ElevationRefused,
    #[error("valeur invalide : {0}")]
    Invalid(String),
    #[error("{0}")]
    Failed(String),
    #[error("aucune adresse temporaire libre")]
    NoFreeAddress,
}

/// La caméra est-elle hors du sous-réseau de l'interface du poste ?
pub fn needs_temp_ip(iface_ip: Ipv4Addr, iface_mask: Ipv4Addr, camera: Ipv4Addr) -> bool {
    let m = u32::from(iface_mask);
    u32::from(camera) & m != u32::from(iface_ip) & m
}

/// Seules les adresses d'un réseau local justifient d'ajouter une adresse au
/// poste : lien local 169.254.0.0/16 ou privées RFC 1918. Une adresse
/// publique hors sous-réseau n'est jamais une caméra posée sur la table.
pub fn reachable_with_temp_ip(camera: Ipv4Addr) -> bool {
    camera.is_link_local() || camera.is_private()
}

const LINK_LOCAL_HOSTS: u64 = 254 * 254;

/// Adresse temporaire pour joindre `camera`, jamais celle de la caméra ni une
/// adresse vue au dernier scan. Lien local : `169.254.a.b` (a, b ∈ 1..=254)
/// tiré de `seed`, masque /16. Sinon le /24 de la caméra, de `.200` à `.250`.
pub fn pick_temp_ip(
    iface: &str,
    camera: Ipv4Addr,
    in_use: &[Ipv4Addr],
    seed: u64,
) -> Result<TempIp, TempIpError> {
    let free = |ip: &Ipv4Addr| *ip != camera && !in_use.contains(ip);
    let (ip, mask) = if camera.is_link_local() {
        let start = seed % LINK_LOCAL_HOSTS;
        let ip = (0..LINK_LOCAL_HOSTS)
            .map(|k| {
                let n = (start + k) % LINK_LOCAL_HOSTS;
                Ipv4Addr::new(169, 254, (n / 254 + 1) as u8, (n % 254 + 1) as u8)
            })
            .find(free);
        (ip, Ipv4Addr::new(255, 255, 0, 0))
    } else {
        let [a, b, c, _] = camera.octets();
        let ip = (200..=250).map(|d| Ipv4Addr::new(a, b, c, d)).find(free);
        (ip, Ipv4Addr::new(255, 255, 255, 0))
    };
    let ip = ip.ok_or(TempIpError::NoFreeAddress)?;
    Ok(TempIp { iface: iface.to_string(), ip, mask })
}

fn prefix_len(mask: Ipv4Addr) -> u32 {
    u32::from(mask).count_ones()
}

/// Repris de LanProbe `validate_interface` : le nom est interpolé dans un
/// `.bat` lancé en administrateur, et dans une commande PowerShell de ce
/// `.bat`. Allowlist ASCII stricte (lettres, chiffres, espace, `-`, `(`,
/// `)`) : refuse tout guillemet, y compris typographique (PowerShell tient
/// `‘ ’ ‚ ‛` pour des `'`), et `%`, `^`, `&`, `|`, `<`, `>`, les retours à
/// la ligne.
fn validate_interface(name: &str) -> Result<(), TempIpError> {
    let ok = !name.is_empty()
        && name.len() <= 256
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '(' | ')'));
    if ok { Ok(()) } else { Err(TempIpError::Invalid("nom d'interface".into())) }
}

/// Nom de device Linux : `[A-Za-z0-9._-]`, sans `-` en tête (nmcli le
/// prendrait pour une option).
fn validate_device(name: &str) -> Result<(), TempIpError> {
    let ok = !name.is_empty()
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok { Ok(()) } else { Err(TempIpError::Invalid("nom d'interface".into())) }
}

/// Nom de service macOS : texte libre choisi par l'utilisateur (« USB
/// 10/100/1000 LAN »). Il part en argument (`sudo`) ou cité pour le shell
/// (`osascript`, voir `networksetup_shell`) ; seuls les caractères de
/// contrôle sont refusés.
fn validate_service(name: &str) -> Result<(), TempIpError> {
    let ok = !name.is_empty() && !name.starts_with('-') && !name.chars().any(char::is_control);
    if ok { Ok(()) } else { Err(TempIpError::Invalid("nom de service".into())) }
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Plan d'ajout. macOS : networksetup ne sait pas ajouter une 2e adresse à
/// un service ; un service dupliqué sur la même carte est la voie
/// documentée, couverte par la règle sudoers sur `networksetup`. Linux :
/// `device modify` change la connexion active sans l'enregistrer (un
/// redémarrage efface l'adresse même si tout le reste échoue).
pub fn add_plan(os: OsKind, t: &TempIp, service: &str) -> Result<ElevatedPlan, TempIpError> {
    let (ip, mask) = (t.ip.to_string(), t.mask.to_string());
    Ok(match os {
        OsKind::Macos => {
            validate_service(service)?;
            ElevatedPlan::Networksetup(vec![
                args(&["-duplicatenetworkservice", service, MACOS_SERVICE]),
                args(&["-setmanual", MACOS_SERVICE, &ip, &mask, &ip]),
            ])
        }
        OsKind::Windows => {
            validate_interface(&t.iface)?;
            // netsh refuse d'ajouter une adresse à une carte en DHCP : repli
            // New-NetIPAddress, qui l'accepte.
            //
            // ⚠️ Pas de `-SkipAsSource $true` (pourtant dans le plan) : une
            // adresse « SkipAsSource » n'est jamais choisie comme source, donc
            // les requêtes vers la caméra partiraient de l'adresse principale
            // et la caméra ne pourrait pas répondre.
            ElevatedPlan::Bat(format!(
                "@echo off\r\n\
                 netsh interface ipv4 add address name=\"{iface}\" address={ip} mask={mask}\r\n\
                 if errorlevel 1 powershell -NoProfile -NonInteractive -Command \"New-NetIPAddress -InterfaceAlias '{iface}' -IPAddress {ip} -PrefixLength {n}\"\r\n\
                 if errorlevel 1 exit /b 1\r\n",
                iface = t.iface,
                n = prefix_len(t.mask),
            ))
        }
        OsKind::Linux => {
            validate_device(&t.iface)?;
            ElevatedPlan::Nmcli(vec![args(&[
                "device",
                "modify",
                &t.iface,
                "+ipv4.addresses",
                &format!("{ip}/{}", prefix_len(t.mask)),
            ])])
        }
    })
}

/// Plan de retrait. Sous Windows, le repli PowerShell réussit si l'adresse
/// n'est plus là : un journal resté après un redémarrage ne bloque pas.
pub fn remove_plan(os: OsKind, t: &TempIp, service: &str) -> Result<ElevatedPlan, TempIpError> {
    let ip = t.ip.to_string();
    Ok(match os {
        OsKind::Macos => {
            // Le service dupliqué porte notre nom fixe : `service` ne sert pas.
            let _ = service;
            ElevatedPlan::Networksetup(vec![args(&["-removenetworkservice", MACOS_SERVICE])])
        }
        OsKind::Windows => {
            validate_interface(&t.iface)?;
            ElevatedPlan::Bat(format!(
                "@echo off\r\n\
                 netsh interface ipv4 delete address name=\"{iface}\" address={ip}\r\n\
                 if errorlevel 1 powershell -NoProfile -NonInteractive -Command \"Remove-NetIPAddress -IPAddress {ip} -Confirm:$false -ErrorAction SilentlyContinue; if (Get-NetIPAddress -IPAddress {ip} -ErrorAction SilentlyContinue) {{ exit 1 }}\"\r\n\
                 if errorlevel 1 exit /b 1\r\n",
                iface = t.iface,
            ))
        }
        OsKind::Linux => {
            validate_device(&t.iface)?;
            ElevatedPlan::Nmcli(vec![args(&[
                "device",
                "modify",
                &t.iface,
                "-ipv4.addresses",
                &format!("{ip}/{}", prefix_len(t.mask)),
            ])])
        }
    })
}

/// Commandes networksetup en une seule ligne shell (une seule invite
/// `osascript` pour tout le plan), chaque argument entre `'…'`.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn networksetup_shell(cmds: &[Vec<String>]) -> String {
    cmds.iter()
        .map(|a| {
            let quoted: Vec<String> = a.iter().map(|x| format!("'{}'", x.replace('\'', r"'\''"))).collect();
            format!("/usr/sbin/networksetup {}", quoted.join(" "))
        })
        .collect::<Vec<_>>()
        .join(" && ")
}

/// Exécute un plan avec les droits administrateur. Les tests passent un faux.
pub trait Elevator: Send + Sync {
    fn run(&self, plan: &ElevatedPlan) -> Result<(), TempIpError>;
}

/// L'élévation réelle, reprise de LanProbe, pour les trois systèmes.
pub struct SystemElevator;

impl Elevator for SystemElevator {
    fn run(&self, plan: &ElevatedPlan) -> Result<(), TempIpError> {
        let added = is_add(plan);
        let done = system::run(plan);
        if done.is_ok() && added {
            // Le temps que la nouvelle adresse soit utilisable (détection
            // d'adresse dupliquée sous Windows, activation du service macOS).
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        done
    }
}

fn is_add(plan: &ElevatedPlan) -> bool {
    match plan {
        ElevatedPlan::Networksetup(c) => c.iter().any(|a| a.first().is_some_and(|x| x == "-duplicatenetworkservice")),
        ElevatedPlan::Bat(s) => s.contains(" add address "),
        ElevatedPlan::Nmcli(c) => c.iter().flatten().any(|x| x == "+ipv4.addresses"),
    }
}

#[cfg(target_os = "macos")]
mod system {
    use super::{ElevatedPlan, TempIpError, networksetup_shell};
    use crate::permissions::{applescript_shell, has_permissions, install_permissions};
    use crate::proc::sync_cmd;

    fn refused(stderr: &str) -> bool {
        stderr.contains("-128") || stderr.contains("User cancel")
    }

    /// networksetup rend parfois 0 en écrivant « ** Error » sur sa sortie.
    fn failed(out: &std::process::Output) -> Option<String> {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() && !stdout.contains("** Error") {
            None
        } else {
            Some(format!("{} {}", stdout.trim(), stderr.trim()).trim().to_string())
        }
    }

    pub fn run(plan: &ElevatedPlan) -> Result<(), TempIpError> {
        let ElevatedPlan::Networksetup(cmds) = plan else {
            return Err(TempIpError::Invalid("plan d'un autre système".into()));
        };
        let removal = cmds.iter().any(|a| a.first().is_some_and(|x| x == "-removenetworkservice"));
        // Une seule invite pour poser la règle sudoers ; refusée, rien n'est fait.
        if !has_permissions() {
            install_permissions()?;
        }
        if has_permissions() {
            let mut via_sudo = true;
            for (i, args) in cmds.iter().enumerate() {
                let out = sync_cmd("sudo")
                    .args(["-n", "/usr/sbin/networksetup"])
                    .args(args)
                    .output()
                    .map_err(|e| TempIpError::Failed(e.to_string()))?;
                if let Some(err) = failed(&out) {
                    if removal && err.contains("not a recognized network service") {
                        return Ok(()); // déjà retiré
                    }
                    if i == 0 {
                        via_sudo = false; // règle absente ou expirée : repli osascript
                        break;
                    }
                    return Err(TempIpError::Failed(err));
                }
            }
            if via_sudo {
                return Ok(());
            }
        }
        let out = sync_cmd("osascript")
            .args(["-e", &applescript_shell(&networksetup_shell(cmds))])
            .output()
            .map_err(|e| TempIpError::Failed(e.to_string()))?;
        match failed(&out) {
            None => Ok(()),
            Some(err) if refused(&err) => Err(TempIpError::ElevationRefused),
            Some(err) if removal && err.contains("not a recognized network service") => Ok(()),
            Some(err) => Err(TempIpError::Failed(err)),
        }
    }
}

#[cfg(target_os = "windows")]
mod system {
    use super::{ElevatedPlan, TempIpError};
    use crate::proc::sync_cmd;

    /// Repris de LanProbe `run_elevated_bat` : une invite UAC pour tout le `.bat`.
    pub fn run(plan: &ElevatedPlan) -> Result<(), TempIpError> {
        let ElevatedPlan::Bat(script) = plan else {
            return Err(TempIpError::Invalid("plan d'un autre système".into()));
        };
        let temp = std::env::temp_dir().join(format!("lenscout-ip-{}.bat", std::process::id()));
        std::fs::write(&temp, script).map_err(|e| TempIpError::Failed(e.to_string()))?;
        let ps_cmd = format!(
            "$p = Start-Process -FilePath '{}' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode",
            temp.to_string_lossy().replace('\'', "''")
        );
        let out = sync_cmd("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
            .output();
        let _ = std::fs::remove_file(&temp);
        let out = out.map_err(|e| TempIpError::Failed(e.to_string()))?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if stderr.contains("canceled") || stderr.contains("annul") {
            return Err(TempIpError::ElevationRefused);
        }
        Err(TempIpError::Failed(if stderr.is_empty() {
            format!("code {}", out.status.code().unwrap_or(-1))
        } else {
            stderr
        }))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod system {
    use super::{ElevatedPlan, TempIpError};
    use crate::proc::sync_cmd;

    /// nmcli demande lui-même l'autorisation à polkit ; `LC_ALL=C` pour
    /// reconnaître le refus.
    pub fn run(plan: &ElevatedPlan) -> Result<(), TempIpError> {
        let ElevatedPlan::Nmcli(cmds) = plan else {
            return Err(TempIpError::Invalid("plan d'un autre système".into()));
        };
        for args in cmds {
            let out = sync_cmd("nmcli")
                .env("LC_ALL", "C")
                .args(args)
                .output()
                .map_err(|e| TempIpError::Failed(e.to_string()))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                if stderr.contains("Not authorized") {
                    return Err(TempIpError::ElevationRefused);
                }
                return Err(TempIpError::Failed(stderr));
            }
        }
        Ok(())
    }
}

/// Une seule IP temporaire à la fois : un seul journal, un seul service
/// « Lenscout » sur macOS.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Lit le journal ; absent → `None`.
pub fn read_journal(journal: &Path) -> Result<Option<TempIp>, TempIpError> {
    match std::fs::read(journal) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| TempIpError::Invalid("journal illisible".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TempIpError::Failed(e.to_string())),
    }
}

/// Écriture atomique (fichier temporaire puis renommage) : un journal n'est
/// jamais à moitié écrit.
pub fn write_journal(journal: &Path, t: &TempIp) -> Result<(), TempIpError> {
    let io = |e: std::io::Error| TempIpError::Failed(e.to_string());
    if let Some(dir) = journal.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let tmp = tmp_path(journal);
    let json = serde_json::to_vec(t).map_err(|e| TempIpError::Failed(e.to_string()))?;
    std::fs::write(&tmp, json).map_err(io)?;
    std::fs::rename(&tmp, journal).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io(e)
    })
}

fn tmp_path(journal: &Path) -> PathBuf {
    let mut name = journal.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    journal.with_file_name(name)
}

fn remove_journal(journal: &Path) {
    let _ = std::fs::remove_file(journal);
}

/// Ajoute `t`, exécute `f`, retire `t` dans tous les cas (erreur ou panique
/// de `f`). Une panique de `f` est relancée après le retrait. Un retrait
/// raté laisse le journal : `cleanup_leftover` réessaiera au démarrage.
///
/// L'élévation est synchrone (elle attend l'invite) : elle bloque le fil du
/// runtime le temps de l'invite, comme LanProbe.
pub async fn with_temp_ip<T, F, Fut>(
    elev: &dyn Elevator,
    journal: &Path,
    t: &TempIp,
    service: &str,
    f: F,
) -> Result<T, TempIpError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let os = OsKind::current();
    let add = add_plan(os, t, service)?;
    let remove = remove_plan(os, t, service)?;
    let _one_at_a_time = LOCK.lock().await;

    // Une adresse d'une session tuée d'abord : un seul journal à la fois.
    cleanup_unlocked(elev, journal)?;

    write_journal(journal, t)?;
    match elev.run(&add) {
        Ok(()) => {}
        Err(TempIpError::ElevationRefused) => {
            remove_journal(journal);
            return Err(TempIpError::ElevationRefused);
        }
        Err(e) => {
            // Ajout peut-être à moitié fait (service macOS dupliqué, adresse
            // refusée) : on retire au mieux. Le retrait échoue d'ordinaire
            // parce qu'il n'y a rien à retirer ; garder le journal bloquerait
            // toutes les actions suivantes.
            let _ = elev.run(&remove);
            remove_journal(journal);
            return Err(e);
        }
    }

    let outcome = AssertUnwindSafe(f()).catch_unwind().await;
    let removed = elev.run(&remove);
    if removed.is_ok() {
        remove_journal(journal);
    }
    let value = match outcome {
        Ok(v) => v,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    removed.map_err(|_| TempIpError::Failed(format!("IP temporaire {} restée sur {}", t.ip, t.iface)))?;
    Ok(value)
}

/// Retire l'adresse d'un journal laissé par une session tuée. Appelé au
/// démarrage de l'app, avant toute action (pas de verrou ici). Un journal
/// illisible est mis de côté (`.illisible`) : on ne sait pas quoi retirer.
pub fn cleanup_leftover(elev: &dyn Elevator, journal: &Path) -> Result<Option<TempIp>, TempIpError> {
    cleanup_unlocked(elev, journal)
}

fn cleanup_unlocked(elev: &dyn Elevator, journal: &Path) -> Result<Option<TempIp>, TempIpError> {
    let t = match read_journal(journal) {
        Ok(None) => return Ok(None),
        Ok(Some(t)) => t,
        Err(TempIpError::Invalid(why)) => {
            let _ = std::fs::rename(journal, journal.with_extension("json.illisible"));
            return Err(TempIpError::Invalid(why));
        }
        Err(e) => return Err(e),
    };
    // Sur macOS le retrait vise le service « Lenscout » : le nom du service
    // d'origine n'est pas nécessaire.
    elev.run(&remove_plan(OsKind::current(), &t, &t.iface)?)?;
    remove_journal(journal);
    Ok(Some(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeElevator;
    use std::path::PathBuf;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn tmp(iface: &str) -> TempIp {
        TempIp { iface: iface.into(), ip: ip("169.254.7.7"), mask: ip("255.255.0.0") }
    }

    /// Un journal dans un dossier propre au test (pas encore créé).
    fn journal() -> PathBuf {
        std::env::temp_dir()
            .join(format!("lenscout-test-{}", uuid::Uuid::new_v4()))
            .join("temp-ip.json")
    }

    fn os() -> OsKind {
        OsKind::current()
    }

    #[test]
    fn link_local_camera_gets_link_local_temp() {
        let cam = ip("169.254.10.20");
        for seed in [0, 1, 253, 254, 64_515, 64_516, u64::MAX, 0xDEAD_BEEF] {
            let t = pick_temp_ip("eth0", cam, &[], seed).unwrap();
            let [a, b, x, y] = t.ip.octets();
            assert_eq!((a, b), (169, 254), "{t:?}");
            assert!((1..=254).contains(&x) && (1..=254).contains(&y), "{t:?}");
            assert_ne!(t.ip, cam);
            assert_eq!(t.mask, ip("255.255.0.0"));
            assert_eq!(t.iface, "eth0");
        }
        // La graine qui tomberait sur la caméra ou une adresse vue passe à la suivante.
        let first = pick_temp_ip("eth0", cam, &[], 7).unwrap().ip;
        let next = pick_temp_ip("eth0", cam, &[first], 7).unwrap().ip;
        assert_ne!(next, first);
        let on_cam = pick_temp_ip("eth0", first, &[], 7).unwrap().ip;
        assert_ne!(on_cam, first);
    }

    #[test]
    fn old_axis_default_gets_slash24() {
        let cam = ip("192.168.0.90");
        let t = pick_temp_ip("eth0", cam, &[], 42).unwrap();
        assert_eq!(t, TempIp { iface: "eth0".into(), ip: ip("192.168.0.200"), mask: ip("255.255.255.0") });
        let t = pick_temp_ip("eth0", cam, &[ip("192.168.0.200")], 42).unwrap();
        assert_eq!(t.ip, ip("192.168.0.201"));
        // Une caméra posée sur .200 ne reçoit pas son propre double.
        assert_eq!(pick_temp_ip("eth0", ip("192.168.0.200"), &[], 0).unwrap().ip, ip("192.168.0.201"));
    }

    #[test]
    fn no_free_address() {
        let in_use: Vec<Ipv4Addr> = (200..=250).map(|d| Ipv4Addr::new(192, 168, 0, d)).collect();
        assert_eq!(pick_temp_ip("eth0", ip("192.168.0.90"), &in_use, 0), Err(TempIpError::NoFreeAddress));
    }

    #[test]
    fn needs_temp_ip_only_outside_subnet() {
        let (me, mask) = (ip("10.0.50.5"), ip("255.255.255.0"));
        assert!(!needs_temp_ip(me, mask, ip("10.0.50.90")));
        assert!(needs_temp_ip(me, mask, ip("169.254.1.1")));
        assert!(needs_temp_ip(me, mask, ip("192.168.0.90")));
    }

    #[test]
    fn only_link_local_or_private_can_get_a_temp_ip() {
        for ok in ["169.254.1.1", "192.168.0.90", "10.1.2.3", "172.16.0.9", "172.31.255.1"] {
            assert!(reachable_with_temp_ip(ip(ok)), "{ok}");
        }
        for no in ["8.8.8.8", "198.51.100.5", "172.32.0.1", "127.0.0.1", "224.0.0.251", "255.255.255.255", "0.0.0.0"] {
            assert!(!reachable_with_temp_ip(ip(no)), "{no}");
        }
    }

    #[test]
    fn macos_plans_exact() {
        let t = tmp("en0");
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            add_plan(OsKind::Macos, &t, "Ethernet").unwrap(),
            ElevatedPlan::Networksetup(vec![
                s(&["-duplicatenetworkservice", "Ethernet", "Lenscout"]),
                s(&["-setmanual", "Lenscout", "169.254.7.7", "255.255.0.0", "169.254.7.7"]),
            ])
        );
        assert_eq!(
            remove_plan(OsKind::Macos, &t, "Ethernet").unwrap(),
            ElevatedPlan::Networksetup(vec![s(&["-removenetworkservice", "Lenscout"])])
        );
        for bad in ["", "Wi-Fi\nrm", "a\0b"] {
            assert!(matches!(add_plan(OsKind::Macos, &t, bad), Err(TempIpError::Invalid(_))), "{bad:?}");
        }
    }

    #[test]
    fn macos_applescript_quotes_every_argument() {
        let cmds = vec![vec!["-duplicatenetworkservice".to_string(), r#"Wi-Fi "x" \ 'y'; rm"#.to_string(), "Lenscout".to_string()]];
        let script = crate::permissions::applescript_shell(&networksetup_shell(&cmds));
        assert_eq!(
            script,
            r#"do shell script "/usr/sbin/networksetup '-duplicatenetworkservice' 'Wi-Fi \"x\" \\ '\\''y'\\''; rm' 'Lenscout'" with administrator privileges"#
        );
        let two = vec![vec!["-a".to_string()], vec!["-b".to_string()]];
        assert_eq!(networksetup_shell(&two), "/usr/sbin/networksetup '-a' && /usr/sbin/networksetup '-b'");
    }

    #[test]
    fn windows_bat_exact_and_crlf() {
        let t = tmp("Ethernet");
        let ElevatedPlan::Bat(add) = add_plan(OsKind::Windows, &t, "Ethernet").unwrap() else { panic!() };
        assert!(add.contains(r#"netsh interface ipv4 add address name="Ethernet" address=169.254.7.7 mask=255.255.0.0"#), "{add}");
        assert!(add.contains("New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress 169.254.7.7 -PrefixLength 16"), "{add}");
        let ElevatedPlan::Bat(rm) = remove_plan(OsKind::Windows, &t, "Ethernet").unwrap() else { panic!() };
        assert!(rm.contains(r#"netsh interface ipv4 delete address name="Ethernet" address=169.254.7.7"#), "{rm}");
        assert!(rm.contains("Remove-NetIPAddress -IPAddress 169.254.7.7 -Confirm:$false"), "{rm}");
        for script in [&add, &rm] {
            assert!(script.ends_with("\r\n"));
            assert!(!script.replace("\r\n", "").contains('\n'), "LF seul : {script:?}");
            assert!(script.contains("if errorlevel 1 exit /b 1\r\n"));
        }
        // Les noms Windows réels passent.
        for n in ["Wi-Fi 2", "Ethernet (2)", "Local Area Connection"] {
            assert!(add_plan(OsKind::Windows, &tmp(n), n).is_ok(), "{n}");
        }
    }

    #[test]
    fn windows_rejects_injection() {
        for n in [
            "Ethernet\" & calc.exe",
            "a|b",
            "%PATH%",
            "Ethernet’; calc; ’",
            "Ethernet‘",
            "Ethernet'",
            "“Ethernet”",
            "a^b",
            "a<b",
            "a>b",
            "a&b",
            "a\nb",
            "a\r\nb",
            "",
        ] {
            assert!(matches!(add_plan(OsKind::Windows, &tmp(n), n), Err(TempIpError::Invalid(_))), "{n:?}");
            assert!(matches!(remove_plan(OsKind::Windows, &tmp(n), n), Err(TempIpError::Invalid(_))), "{n:?}");
        }
    }

    #[test]
    fn linux_plans_exact() {
        let t = tmp("eth0");
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            add_plan(OsKind::Linux, &t, "eth0").unwrap(),
            ElevatedPlan::Nmcli(vec![s(&["device", "modify", "eth0", "+ipv4.addresses", "169.254.7.7/16"])])
        );
        assert_eq!(
            remove_plan(OsKind::Linux, &t, "eth0").unwrap(),
            ElevatedPlan::Nmcli(vec![s(&["device", "modify", "eth0", "-ipv4.addresses", "169.254.7.7/16"])])
        );
        for bad in ["eth0 x", "eth0;reboot", "", "-h"] {
            assert!(matches!(add_plan(OsKind::Linux, &tmp(bad), bad), Err(TempIpError::Invalid(_))), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn error_in_action_still_removes() {
        let (elev, j, t) = (FakeElevator::new(), journal(), tmp("eth0"));
        let r: Result<Result<(), &str>, _> = with_temp_ip(&elev, &j, &t, "eth0", || async {
            assert!(j.exists(), "le journal est écrit avant l'ajout");
            Err("la caméra a refusé")
        })
        .await;
        assert_eq!(r, Ok(Err("la caméra a refusé")));
        assert_eq!(elev.plans(), vec![add_plan(os(), &t, "eth0").unwrap(), remove_plan(os(), &t, "eth0").unwrap()]);
        assert!(!j.exists());
    }

    #[tokio::test]
    async fn panic_in_action_still_removes() {
        let (elev, j, t) = (FakeElevator::new(), journal(), tmp("eth0"));
        let caught = AssertUnwindSafe(with_temp_ip(&elev, &j, &t, "eth0", || async {
            panic!("boum");
        }))
        .catch_unwind()
        .await;
        let payload = caught.expect_err("la panique remonte");
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"boum"));
        assert_eq!(elev.plans(), vec![add_plan(os(), &t, "eth0").unwrap(), remove_plan(os(), &t, "eth0").unwrap()]);
        assert!(!j.exists());
    }

    #[tokio::test]
    async fn refused_elevation_skips_action() {
        let elev = FakeElevator::replying(vec![Err(TempIpError::ElevationRefused)]);
        let (j, t) = (journal(), tmp("eth0"));
        let called = std::sync::atomic::AtomicBool::new(false);
        let r = with_temp_ip(&elev, &j, &t, "eth0", || async {
            called.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .await;
        assert_eq!(r, Err(TempIpError::ElevationRefused));
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(elev.plans(), vec![add_plan(os(), &t, "eth0").unwrap()], "aucun retrait");
        assert!(!j.exists());
    }

    #[tokio::test]
    async fn failed_add_is_undone_and_skips_action() {
        // Ajout à moitié fait (service dupliqué, adresse refusée) : on retire quand même.
        let elev = FakeElevator::replying(vec![Err(TempIpError::Failed("x".into())), Err(TempIpError::Failed("absente".into()))]);
        let (j, t) = (journal(), tmp("eth0"));
        let r = with_temp_ip(&elev, &j, &t, "eth0", || async { unreachable!() }).await;
        assert!(matches!(r, Err(TempIpError::Failed(_))));
        assert_eq!(elev.plans().len(), 2);
        assert!(!j.exists(), "rien n'a été posé : pas de journal qui bloquerait la suite");
    }

    #[tokio::test]
    async fn failed_removal_keeps_journal() {
        let elev = FakeElevator::replying(vec![Ok(()), Err(TempIpError::Failed("netsh".into()))]);
        let (j, t) = (journal(), tmp("eth0"));
        let r = with_temp_ip(&elev, &j, &t, "eth0", || async { 5 }).await;
        assert_eq!(r, Err(TempIpError::Failed("IP temporaire 169.254.7.7 restée sur eth0".into())));
        assert_eq!(read_journal(&j).unwrap(), Some(t));
    }

    #[tokio::test]
    async fn leftover_is_removed_before_a_new_temp_ip() {
        let (elev, j) = (FakeElevator::new(), journal());
        let old = TempIp { iface: "eth0".into(), ip: ip("169.254.3.3"), mask: ip("255.255.0.0") };
        write_journal(&j, &old).unwrap();
        let t = tmp("eth0");
        assert_eq!(with_temp_ip(&elev, &j, &t, "eth0", || async { 1 }).await, Ok(1));
        assert_eq!(
            elev.plans(),
            vec![
                remove_plan(os(), &old, "eth0").unwrap(),
                add_plan(os(), &t, "eth0").unwrap(),
                remove_plan(os(), &t, "eth0").unwrap(),
            ]
        );
        assert!(!j.exists());
    }

    #[test]
    fn cleanup_leftover_removes_journaled_ip() {
        let (elev, j, t) = (FakeElevator::new(), journal(), tmp("eth0"));
        assert_eq!(cleanup_leftover(&elev, &j), Ok(None), "pas de journal, rien à faire");
        assert!(elev.plans().is_empty());

        write_journal(&j, &t).unwrap();
        assert_eq!(cleanup_leftover(&elev, &j), Ok(Some(t.clone())));
        assert_eq!(elev.plans(), vec![remove_plan(os(), &t, &t.iface).unwrap()]);
        assert!(!j.exists());
    }

    #[test]
    fn cleanup_leftover_failure_keeps_journal() {
        let elev = FakeElevator::replying(vec![Err(TempIpError::ElevationRefused)]);
        let (j, t) = (journal(), tmp("eth0"));
        write_journal(&j, &t).unwrap();
        assert_eq!(cleanup_leftover(&elev, &j), Err(TempIpError::ElevationRefused));
        assert_eq!(read_journal(&j).unwrap(), Some(t));
    }

    #[test]
    fn unreadable_journal_is_set_aside() {
        let (elev, j) = (FakeElevator::new(), journal());
        std::fs::create_dir_all(j.parent().unwrap()).unwrap();
        std::fs::write(&j, b"{pas du json").unwrap();
        assert!(matches!(cleanup_leftover(&elev, &j), Err(TempIpError::Invalid(_))));
        assert!(!j.exists());
        assert!(j.with_extension("json.illisible").exists());
        assert!(elev.plans().is_empty());
    }

    #[test]
    fn journal_write_is_atomic_and_round_trips() {
        let (j, t) = (journal(), tmp("Ethernet (2)"));
        write_journal(&j, &t).unwrap();
        assert_eq!(read_journal(&j).unwrap(), Some(t));
        let names: Vec<_> = std::fs::read_dir(j.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("temp-ip.json")], "aucun fichier temporaire laissé");
    }
}
