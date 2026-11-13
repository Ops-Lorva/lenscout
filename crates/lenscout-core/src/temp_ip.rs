//! IP temporaire ajoutée au poste, avec les droits administrateur, pour
//! joindre une caméra hors de son sous-réseau (Axis neuve en 169.254.x.x,
//! ancienne Axis en 192.168.0.90), puis retirée quoi qu'il arrive.
//!
//! Le mécanisme d'élévation est repris de LanProbe
//! `crates/lanprobe-core/src/configure.rs` (2026-11-13) : macOS
//! `networksetup` par `sudo -n` (règle sudoers) ou `osascript … with
//! administrator privileges`, Windows PowerShell lancé par `Start-Process
//! -Verb RunAs`, Linux `nmcli`. Les plans sont des valeurs pures, testées
//! sans rien exécuter ; seul `SystemElevator` touche le poste.
//!
//! Garantie de retrait, par couches :
//! - le journal (`temp-ip.json`) est écrit AVANT l'ajout et retiré seulement
//!   après un retrait réussi ;
//! - retrait explicite après l'action, même sur erreur ou panique ;
//! - garde `Drop` : un futur abandonné entre l'ajout et le retrait retire
//!   quand même l'adresse ;
//! - `cleanup_leftover` au démarrage et à la sortie de l'app ;
//! - Linux (`device modify`) et Windows (`store=active` / `ActiveStore`) :
//!   l'adresse n'est jamais enregistrée, un redémarrage l'efface ;
//! - macOS : le service « Lenscout » dupliqué par `networksetup` est, lui,
//!   enregistré et survit à un redémarrage ; c'est `cleanup_leftover`, au
//!   démarrage suivant de l'app, qui le retire (le journal reste jusque-là).
//!
//! Un verrou de fichier (`temp-ip.json.lock`) écarte une seconde instance de
//! l'app pendant toute la durée d'une IP temporaire.

use std::fs::{File, TryLockError};
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
/// `networksetup` (une commande par ligne), texte d'un script PowerShell,
/// arguments de `nmcli`.
#[derive(Debug, Clone, PartialEq)]
pub enum ElevatedPlan {
    Networksetup(Vec<Vec<String>>),
    PowerShell(String),
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
    /// Le verrou est tenu par une autre instance de l'app.
    #[error("IP temporaire en cours dans une autre instance")]
    Busy,
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

/// Masque du réseau que l'IP temporaire ouvrira vers `camera` : /16 en lien
/// local, /24 sinon.
pub fn temp_mask(camera: Ipv4Addr) -> Ipv4Addr {
    if camera.is_link_local() { Ipv4Addr::new(255, 255, 0, 0) } else { Ipv4Addr::new(255, 255, 255, 0) }
}

/// Deux réseaux se recouvrent-ils ? Comparés sur le plus court des deux masques.
pub fn subnets_overlap(a: Ipv4Addr, a_mask: Ipv4Addr, b: Ipv4Addr, b_mask: Ipv4Addr) -> bool {
    let m = u32::from(a_mask) & u32::from(b_mask);
    u32::from(a) & m == u32::from(b) & m
}

const LINK_LOCAL_HOSTS: u64 = 254 * 254;
const SLASH24_HOSTS: u64 = 51; // .200 à .250

/// Adresse temporaire pour joindre `camera`, jamais celle de la caméra ni une
/// de `in_use` (adresses vues au scan, voisins ARP). Lien local :
/// `169.254.a.b` (a, b ∈ 1..=254), masque /16 ; sinon le /24 de la caméra,
/// de `.200` à `.250`. Le départ est tiré de `seed`, puis parcours circulaire.
pub fn pick_temp_ip(
    iface: &str,
    camera: Ipv4Addr,
    in_use: &[Ipv4Addr],
    seed: u64,
) -> Result<TempIp, TempIpError> {
    let free = |ip: &Ipv4Addr| *ip != camera && !in_use.contains(ip);
    let ip = if camera.is_link_local() {
        let start = seed % LINK_LOCAL_HOSTS;
        (0..LINK_LOCAL_HOSTS)
            .map(|k| {
                let n = (start + k) % LINK_LOCAL_HOSTS;
                Ipv4Addr::new(169, 254, (n / 254 + 1) as u8, (n % 254 + 1) as u8)
            })
            .find(free)
    } else {
        let [a, b, c, _] = camera.octets();
        let start = seed % SLASH24_HOSTS;
        (0..SLASH24_HOSTS)
            .map(|k| Ipv4Addr::new(a, b, c, 200 + ((start + k) % SLASH24_HOSTS) as u8))
            .find(free)
    };
    let ip = ip.ok_or(TempIpError::NoFreeAddress)?;
    Ok(TempIp { iface: iface.to_string(), ip, mask: temp_mask(camera) })
}

fn prefix_len(mask: Ipv4Addr) -> u32 {
    u32::from(mask).count_ones()
}

/// Repris de LanProbe `validate_interface` : le nom est interpolé dans le
/// script PowerShell lancé en administrateur. Allowlist ASCII stricte
/// (lettres, chiffres, espace, `-`, `(`, `)`) : refuse tout guillemet, y
/// compris typographique (PowerShell tient `‘ ’ ‚ ‛` pour des `'`), et `%`
/// (`--%` développe `%VAR%`), `^`, `&`, `|`, `<`, `>`, `$`, `` ` ``, les
/// retours à la ligne.
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
/// contrôle et un `-` en tête sont refusés.
fn validate_service(name: &str) -> Result<(), TempIpError> {
    let ok = !name.is_empty() && !name.starts_with('-') && !name.chars().any(char::is_control);
    if ok { Ok(()) } else { Err(TempIpError::Invalid("nom de service".into())) }
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Plan d'ajout. macOS : networksetup ne sait pas ajouter une 2e adresse à
/// un service ; un service dupliqué sur la même carte est la voie
/// documentée. Linux : `device modify` change la connexion active sans
/// l'enregistrer. Windows : `store=active` / `ActiveStore`, jamais
/// enregistré non plus.
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
            // New-NetIPAddress, qui l'accepte. `--%` passe la fin de ligne
            // telle quelle à netsh, comme le faisait le `.bat`.
            //
            // ⚠️ Pas de `-SkipAsSource $true` : une adresse « SkipAsSource »
            // n'est jamais choisie comme source, la caméra ne pourrait pas
            // répondre.
            ElevatedPlan::PowerShell(format!(
                "$ErrorActionPreference = 'Stop'\n\
                 netsh --% interface ipv4 add address name=\"{iface}\" address={ip} mask={mask} store=active\n\
                 if ($LASTEXITCODE -ne 0) {{ New-NetIPAddress -InterfaceAlias '{iface}' -IPAddress {ip} -PrefixLength {n} -PolicyStore ActiveStore | Out-Null }}\n\
                 exit 0\n",
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

/// Plan de retrait. Sous Windows, il réussit si l'adresse n'est plus là :
/// un journal resté après un redémarrage ne bloque pas.
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
            ElevatedPlan::PowerShell(format!(
                "$ErrorActionPreference = 'Stop'\n\
                 netsh --% interface ipv4 delete address name=\"{iface}\" address={ip} store=active\n\
                 if ($LASTEXITCODE -ne 0) {{ Remove-NetIPAddress -IPAddress {ip} -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue }}\n\
                 if (Get-NetIPAddress -IPAddress {ip} -PolicyStore ActiveStore -ErrorAction SilentlyContinue) {{ exit 1 }}\n\
                 exit 0\n",
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

/// Commande PowerShell (non élevée) qui relance PowerShell en administrateur
/// avec `script` en `-EncodedCommand` (base64 de l'UTF-16LE) : aucun fichier
/// temporaire, et rien du script n'est réinterprété en route.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn elevated_launcher(script: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
    format!(
        "$p = Start-Process -FilePath powershell -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{b64}'; exit $p.ExitCode"
    )
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
        ElevatedPlan::PowerShell(s) => s.contains(" add address "),
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
        let gone = |err: &str| removal && err.contains("not a recognized network service");
        // Règle absente ou différente de l'attendue : une invite pour la
        // (re)poser ; refusée, rien n'est fait.
        // Autre échec de l'installation : le repli osascript ci-dessous.
        if !has_permissions() && install_permissions() == Err(TempIpError::ElevationRefused) {
            return Err(TempIpError::ElevationRefused);
        }
        let mut via_osascript = false;
        for args in cmds {
            let out = sync_cmd("sudo")
                .env("LC_ALL", "C")
                .args(["-n", "/usr/sbin/networksetup"])
                .args(args)
                .output()
                .map_err(|e| TempIpError::Failed(e.to_string()))?;
            if let Some(err) = failed(&out) {
                if gone(&err) {
                    return Ok(());
                }
                // Seul « mot de passe requis » (règle absente) justifie le
                // repli osascript ; il survient dès la première commande.
                if err.contains("a password is required") {
                    via_osascript = true;
                    break;
                }
                return Err(TempIpError::Failed(err));
            }
        }
        if !via_osascript {
            return Ok(());
        }
        let out = sync_cmd("osascript")
            .args(["-e", &applescript_shell(&networksetup_shell(cmds))])
            .output()
            .map_err(|e| TempIpError::Failed(e.to_string()))?;
        match failed(&out) {
            None => Ok(()),
            Some(err) if refused(&err) => Err(TempIpError::ElevationRefused),
            Some(err) if gone(&err) => Ok(()),
            Some(err) => Err(TempIpError::Failed(err)),
        }
    }
}

#[cfg(target_os = "windows")]
mod system {
    use super::{ElevatedPlan, TempIpError, elevated_launcher};
    use crate::proc::sync_cmd;

    /// Repris de LanProbe `run_elevated_bat`, sans fichier : une invite UAC
    /// pour tout le script.
    pub fn run(plan: &ElevatedPlan) -> Result<(), TempIpError> {
        let ElevatedPlan::PowerShell(script) = plan else {
            return Err(TempIpError::Invalid("plan d'un autre système".into()));
        };
        let out = sync_cmd("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &elevated_launcher(script)])
            .output()
            .map_err(|e| TempIpError::Failed(e.to_string()))?;
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

/// Une seule IP temporaire à la fois dans l'instance (un seul journal, un
/// seul service « Lenscout » sur macOS) ; le verrou de fichier couvre les
/// autres instances.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `temp-ip.json.lock`, à côté du journal.
pub fn lock_path(journal: &Path) -> PathBuf {
    let mut name = journal.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    journal.with_file_name(name)
}

/// Verrou exclusif du système sur `temp-ip.json.lock`, relâché quand le
/// `File` est fermé (y compris si le processus meurt). Tenu ailleurs → `Busy`.
fn lock_journal(journal: &Path) -> Result<File, TempIpError> {
    let io = |e: std::io::Error| TempIpError::Failed(e.to_string());
    if let Some(dir) = journal.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let file = File::options().create(true).truncate(false).write(true).open(lock_path(journal)).map_err(io)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(TempIpError::Busy),
        Err(TryLockError::Error(e)) => Err(io(e)),
    }
}

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

/// Écriture atomique : fichier temporaire au nom unique, `sync_all`, puis
/// renommage. Un journal n'est jamais à moitié écrit, même après une coupure.
pub fn write_journal(journal: &Path, t: &TempIp) -> Result<(), TempIpError> {
    use std::io::Write;
    let io = |e: std::io::Error| TempIpError::Failed(e.to_string());
    if let Some(dir) = journal.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let tmp = tmp_path(journal);
    let json = serde_json::to_vec(t).map_err(|e| TempIpError::Failed(e.to_string()))?;
    let written = (|| {
        let mut f = File::create_new(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
        std::fs::rename(&tmp, journal)
    })();
    written.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io(e)
    })
}

fn tmp_path(journal: &Path) -> PathBuf {
    let mut name = journal.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    journal.with_file_name(name)
}

fn remove_journal(journal: &Path) {
    let _ = std::fs::remove_file(journal);
}

/// Retire l'adresse si on le lâche armé : futur abandonné entre l'ajout et
/// le retrait (tâche annulée, app qui se ferme), ou panique.
struct RemoveOnDrop<'a> {
    elev: &'a dyn Elevator,
    journal: &'a Path,
    remove: &'a ElevatedPlan,
    armed: bool,
}

impl RemoveOnDrop<'_> {
    /// Le retrait normal ; la garde est désarmée quoi qu'il arrive.
    fn remove(mut self) -> Result<(), TempIpError> {
        self.armed = false;
        let done = self.elev.run(self.remove);
        if done.is_ok() {
            remove_journal(self.journal);
        }
        done
    }
}

impl Drop for RemoveOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed && self.elev.run(self.remove).is_ok() {
            remove_journal(self.journal);
        }
    }
}

/// Ajoute `t`, exécute `f`, retire `t` dans tous les cas (erreur, panique
/// de `f`, futur abandonné). Une panique de `f` est relancée après le
/// retrait. Un retrait raté laisse le journal : `cleanup_leftover`
/// réessaiera. Une autre instance qui tient le verrou → `Busy`, rien n'est fait.
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
    let _one_here = LOCK.lock().await;
    // Déclaré avant la garde : relâché après elle.
    let _one_anywhere = lock_journal(journal)?;

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
    let guard = RemoveOnDrop { elev, journal, remove: &remove, armed: true };

    // `f()` lui-même dans le bloc : une panique à l'appel est rattrapée aussi.
    let outcome = AssertUnwindSafe(async move { f().await }).catch_unwind().await;
    let removed = guard.remove();
    let value = match outcome {
        Ok(v) => v,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    removed.map_err(|_| TempIpError::Failed(format!("IP temporaire {} restée sur {}", t.ip, t.iface)))?;
    Ok(value)
}

/// Retire l'adresse d'un journal laissé par une session tuée. Appelé au
/// démarrage et à la sortie de l'app. Verrou tenu par une autre instance →
/// `Busy`, rien n'est fait. Un journal illisible est mis de côté
/// (`.illisible`) : on ne sait pas quoi retirer.
pub fn cleanup_leftover(elev: &dyn Elevator, journal: &Path) -> Result<Option<TempIp>, TempIpError> {
    if !journal.exists() {
        return Ok(None);
    }
    let _lock = lock_journal(journal)?;
    cleanup_unlocked(elev, journal)
}

/// Filet de sortie de l'app. Une action en cours tient le verrou : on
/// attend qu'elle finisse son retrait, au plus `max`, puis on retire ce que
/// le journal porte encore. Au-delà de `max` → `Busy`, rien n'est fait (le
/// démarrage suivant s'en charge). Bloquant : à appeler hors de la boucle
/// d'événements de l'interface.
///
/// Le verrou n'est jamais relâché ensuite : le processus se termine, et
/// aucune IP temporaire ne doit plus démarrer d'ici là.
pub fn cleanup_before_exit(
    elev: &dyn Elevator,
    journal: &Path,
    max: std::time::Duration,
) -> Result<Option<TempIp>, TempIpError> {
    let deadline = std::time::Instant::now() + max;
    let lock = loop {
        match lock_journal(journal) {
            Ok(lock) => break lock,
            Err(TempIpError::Busy) => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Err(TempIpError::Busy);
                }
                std::thread::sleep((deadline - now).min(std::time::Duration::from_millis(50)));
            }
            Err(e) => return Err(e),
        }
    };
    let done = cleanup_unlocked(elev, journal);
    std::mem::forget(lock);
    done
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
        let t = pick_temp_ip("eth0", cam, &[], 0).unwrap();
        assert_eq!(t, TempIp { iface: "eth0".into(), ip: ip("192.168.0.200"), mask: ip("255.255.255.0") });
        let t = pick_temp_ip("eth0", cam, &[ip("192.168.0.200")], 0).unwrap();
        assert_eq!(t.ip, ip("192.168.0.201"));
        // Départ tiré dans .200–.250 par la graine, puis parcours circulaire.
        assert_eq!(pick_temp_ip("eth0", cam, &[], 5).unwrap().ip, ip("192.168.0.205"));
        assert_eq!(pick_temp_ip("eth0", cam, &[], 51).unwrap().ip, ip("192.168.0.200"));
        assert_eq!(pick_temp_ip("eth0", cam, &[ip("192.168.0.250")], 50).unwrap().ip, ip("192.168.0.200"));
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
    fn windows_script_exact_and_not_persistent() {
        let t = tmp("Ethernet");
        let ElevatedPlan::PowerShell(add) = add_plan(OsKind::Windows, &t, "Ethernet").unwrap() else { panic!() };
        assert_eq!(
            add,
            "$ErrorActionPreference = 'Stop'\n\
             netsh --% interface ipv4 add address name=\"Ethernet\" address=169.254.7.7 mask=255.255.0.0 store=active\n\
             if ($LASTEXITCODE -ne 0) { New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress 169.254.7.7 -PrefixLength 16 -PolicyStore ActiveStore | Out-Null }\n\
             exit 0\n"
        );
        let ElevatedPlan::PowerShell(rm) = remove_plan(OsKind::Windows, &t, "Ethernet").unwrap() else { panic!() };
        assert_eq!(
            rm,
            "$ErrorActionPreference = 'Stop'\n\
             netsh --% interface ipv4 delete address name=\"Ethernet\" address=169.254.7.7 store=active\n\
             if ($LASTEXITCODE -ne 0) { Remove-NetIPAddress -IPAddress 169.254.7.7 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue }\n\
             if (Get-NetIPAddress -IPAddress 169.254.7.7 -PolicyStore ActiveStore -ErrorAction SilentlyContinue) { exit 1 }\n\
             exit 0\n"
        );
        // Les noms Windows réels passent.
        for n in ["Wi-Fi 2", "Ethernet (2)", "Local Area Connection"] {
            assert!(add_plan(OsKind::Windows, &tmp(n), n).is_ok(), "{n}");
        }
    }

    #[test]
    fn windows_launcher_carries_the_script_encoded() {
        use base64::Engine;
        let script = "netsh --% interface ipv4 add address name=\"Wi-Fi 2\" address=169.254.7.7\nexit 0\n";
        let launcher = elevated_launcher(script);
        let (head, rest) = launcher.split_once("'-EncodedCommand','").unwrap();
        assert_eq!(
            head,
            "$p = Start-Process -FilePath powershell -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList '-NoProfile','-NonInteractive',"
        );
        let (b64, tail) = rest.split_once('\'').unwrap();
        assert_eq!(tail, "; exit $p.ExitCode");
        assert!(b64.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)));
        let raw = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        let units: Vec<u16> = raw.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        assert_eq!(String::from_utf16(&units).unwrap(), script);
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

    /// Lâche le futur de `with_temp_ip` pendant que l'action tourne (après l'ajout).
    async fn abandon_while_running(elev: &FakeElevator, j: &Path, t: &TempIp) {
        let (started, running) = tokio::sync::oneshot::channel();
        let fut = with_temp_ip(elev, j, t, "eth0", move || async move {
            let _ = started.send(());
            std::future::pending::<()>().await
        });
        tokio::select! {
            _ = fut => unreachable!("l'action ne finit jamais"),
            _ = running => {}
        }
    }

    #[tokio::test]
    async fn dropping_the_future_after_add_still_removes() {
        // L'action est abandonnée (tâche annulée, fenêtre fermée) entre l'ajout et le retrait.
        let (elev, j, t) = (FakeElevator::new(), journal(), tmp("eth0"));
        abandon_while_running(&elev, &j, &t).await;
        assert_eq!(elev.plans(), vec![add_plan(os(), &t, "eth0").unwrap(), remove_plan(os(), &t, "eth0").unwrap()]);
        assert!(!j.exists());
    }

    #[tokio::test]
    async fn dropped_future_whose_removal_fails_keeps_journal() {
        let elev = FakeElevator::replying(vec![Ok(()), Err(TempIpError::Failed("x".into()))]);
        let (j, t) = (journal(), tmp("eth0"));
        abandon_while_running(&elev, &j, &t).await;
        assert_eq!(read_journal(&j).unwrap(), Some(t));
    }

    #[tokio::test]
    async fn sync_panic_in_closure_still_removes() {
        let (elev, j, t) = (FakeElevator::new(), journal(), tmp("eth0"));
        let f = || -> std::future::Ready<()> { panic!("tout de suite") };
        let caught = AssertUnwindSafe(with_temp_ip(&elev, &j, &t, "eth0", f)).catch_unwind().await;
        assert!(caught.is_err(), "la panique remonte");
        assert_eq!(elev.plans(), vec![add_plan(os(), &t, "eth0").unwrap(), remove_plan(os(), &t, "eth0").unwrap()]);
        assert!(!j.exists());
    }

    /// Verrou tenu par « une autre instance ».
    fn hold_lock(j: &Path) -> std::fs::File {
        std::fs::create_dir_all(j.parent().unwrap()).unwrap();
        let f = std::fs::File::create(lock_path(j)).unwrap();
        f.lock().unwrap();
        f
    }

    #[tokio::test]
    async fn busy_lock_blocks_the_action() {
        let (elev, j, t) = (FakeElevator::new(), journal(), tmp("eth0"));
        let held = hold_lock(&j);
        let r = with_temp_ip(&elev, &j, &t, "eth0", || async { unreachable!() }).await;
        assert_eq!(r, Err(TempIpError::Busy));
        assert!(elev.plans().is_empty());
        assert!(!j.exists());
        drop(held);
        assert_eq!(with_temp_ip(&elev, &j, &t, "eth0", || async { 3 }).await, Ok(3));
    }

    #[test]
    fn busy_lock_makes_cleanup_do_nothing() {
        let (elev, j, t) = (FakeElevator::new(), journal(), tmp("eth0"));
        write_journal(&j, &t).unwrap();
        let _held = hold_lock(&j);
        assert_eq!(cleanup_leftover(&elev, &j), Err(TempIpError::Busy));
        assert!(elev.plans().is_empty());
        assert_eq!(read_journal(&j).unwrap(), Some(t));
    }

    #[test]
    fn exit_cleanup_waits_for_the_running_action_then_removes() {
        // Une action tient le verrou ; elle le relâche après 150 ms en
        // laissant son journal (retrait raté) : la sortie attend puis retire.
        let (elev, j, t) = (FakeElevator::new(), journal(), tmp("eth0"));
        write_journal(&j, &t).unwrap();
        let held = hold_lock(&j);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            drop(held);
        });
        let started = std::time::Instant::now();
        assert_eq!(cleanup_before_exit(&elev, &j, std::time::Duration::from_secs(10)), Ok(Some(t.clone())));
        assert!(started.elapsed() >= std::time::Duration::from_millis(100));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(elev.plans(), vec![remove_plan(os(), &t, &t.iface).unwrap()]);
        assert!(!j.exists());
        releaser.join().unwrap();
        // La sortie garde le verrou : plus aucune IP temporaire ne démarre.
        assert!(matches!(lock_journal(&j), Err(TempIpError::Busy)));
    }

    #[test]
    fn exit_cleanup_gives_up_after_the_deadline() {
        let (elev, j, t) = (FakeElevator::new(), journal(), tmp("eth0"));
        write_journal(&j, &t).unwrap();
        let _held = hold_lock(&j);
        let started = std::time::Instant::now();
        assert_eq!(cleanup_before_exit(&elev, &j, std::time::Duration::from_millis(300)), Err(TempIpError::Busy));
        let waited = started.elapsed();
        assert!(waited >= std::time::Duration::from_millis(300) && waited < std::time::Duration::from_secs(2), "{waited:?}");
        assert!(elev.plans().is_empty());
        assert_eq!(read_journal(&j).unwrap(), Some(t), "laissé au prochain démarrage");
    }

    #[test]
    fn exit_cleanup_without_journal_does_nothing() {
        let (elev, j) = (FakeElevator::new(), journal());
        assert_eq!(cleanup_before_exit(&elev, &j, std::time::Duration::from_secs(10)), Ok(None));
        assert!(elev.plans().is_empty());
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
        assert_eq!(read_journal(&j).unwrap(), Some(t.clone()));
        write_journal(&j, &t).unwrap();
        let names: Vec<_> = std::fs::read_dir(j.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("temp-ip.json")], "aucun fichier temporaire laissé");
    }
}
