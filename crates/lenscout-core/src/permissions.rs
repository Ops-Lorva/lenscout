// Repris de LanProbe crates/lanprobe-core/src/permissions.rs le 2026-11-13
//! Règle sudoers macOS posée une fois (une invite) : ensuite `networksetup`
//! passe par `sudo -n`, sans mot de passe. Linux (polkit via nmcli) et
//! Windows (UAC à chaque script) n'ont rien à installer.
//!
//! Adaptations :
//! - chemin `/etc/sudoers.d/lenscout` ;
//! - règle restreinte à l'utilisateur courant et aux trois commandes que
//!   Lenscout lance (service « Lenscout » seulement) — LanProbe ouvrait tout
//!   `networksetup` au groupe `%admin` ;
//! - écrite par `printf '%s\n'` (LanProbe la passait comme format à
//!   `printf`, où `%a` de `%admin` est une conversion), vérifiée par
//!   `visudo -c` puis mise en place par renommage — un fichier sudoers
//!   invalide casserait `sudo` ;
//! - root:wheel 0440, rien d'autre ; illisible par l'app, il est suivi par un
//!   marqueur (`<app_data_dir>/sudoers-rule.sha256`, hash de la règle
//!   installée) : règle attendue différente ou marqueur absent → réinstallation.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::temp_ip::TempIpError;

#[cfg(target_os = "macos")]
const SUDOERS_PATH: &str = "/etc/sudoers.d/lenscout";

/// Règle sudoers de `user`. Le nom est validé (`^[a-z_][a-z0-9_.-]*$`)
/// avant d'entrer dans un fichier sudoers et une commande shell.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn sudoers_rule(user: &str) -> Result<String, TempIpError> {
    let mut chars = user.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'));
    if !ok {
        return Err(TempIpError::Invalid("nom d'utilisateur".into()));
    }
    Ok(format!(
        "{user} ALL=(root) NOPASSWD: /usr/sbin/networksetup -duplicatenetworkservice * Lenscout, \
         /usr/sbin/networksetup -setmanual Lenscout *, /usr/sbin/networksetup -removenetworkservice Lenscout, /usr/sbin/networksetup -ordernetworkservices *"
    ))
}

/// Nom du marqueur, dans le dossier de données de l'app.
pub(crate) const MARKER_FILE: &str = "sudoers-rule.sha256";

/// Dossier de données de l'app, fixé au démarrage (`set_data_dir`).
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// À appeler au démarrage : le marqueur vit dans ce dossier.
pub fn set_data_dir(dir: &Path) {
    let _ = DATA_DIR.set(dir.to_path_buf());
}

#[cfg(target_os = "macos")]
fn marker_path() -> Option<PathBuf> {
    DATA_DIR.get().map(|d| d.join(MARKER_FILE))
}

/// SHA-256 de la règle, en hexadécimal.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn rule_hash(rule: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(rule.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Le fichier sudoers est root:wheel 0440, illisible par l'app : on se fie
/// au marqueur écrit après une installation réussie. Vrai seulement si le
/// fichier existe ET si le marqueur porte le hash de la règle attendue ;
/// sinon on réinstalle (une invite), ce qui écrase le fichier.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn rule_installed(sudoers: &Path, marker: &Path, rule: &str) -> bool {
    sudoers.exists()
        && std::fs::read_to_string(marker).is_ok_and(|m| m.trim() == rule_hash(rule))
}

/// Écrit le marqueur atomiquement (temporaire unique, `sync_all`, renommage).
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn write_marker(marker: &Path, rule: &str) -> Result<(), TempIpError> {
    use std::io::Write;
    let io = |e: std::io::Error| TempIpError::Failed(e.to_string());
    if let Some(dir) = marker.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let tmp = marker.with_file_name(format!("{MARKER_FILE}.{}.tmp", uuid::Uuid::new_v4()));
    let written = (|| {
        let mut f = std::fs::File::create_new(&tmp)?;
        f.write_all(rule_hash(rule).as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, marker)
    })();
    written.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io(e)
    })
}

/// Script shell (lancé en root) qui pose la règle : fichier temporaire
/// root:wheel 0440 — jamais d'autre mode, un fichier inattendu dans
/// `sudoers.d` peut faire refuser `sudo` entier —, vérifié par `visudo -c`,
/// puis renommé (atomique). `sudoers.d` ignore les noms contenant un point :
/// le temporaire n'est jamais lu par sudo.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn install_shell(rule: &str, path: &str) -> String {
    let tmp = format!("{path}.tmp");
    format!(
        "umask 077 && printf '%s\\n' '{rule}' > {tmp} && chown root:wheel {tmp} && chmod 440 {tmp} && /usr/sbin/visudo -cf {tmp} && mv -f {tmp} {path} || {{ rm -f {tmp}; exit 1; }}"
    )
}

/// Utilisateur courant, par `getuid` → `getpwuid` (pas l'environnement).
#[cfg(target_os = "macos")]
fn current_user() -> Option<String> {
    // SAFETY: getpwuid rend un pointeur vers une zone statique de la libc ou
    // NULL ; on copie le nom aussitôt, sans autre appel entre-temps.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() || (*pw).pw_name.is_null() {
            return None;
        }
        std::ffi::CStr::from_ptr((*pw).pw_name).to_str().ok().map(str::to_owned)
    }
}

#[cfg(target_os = "macos")]
fn expected_rule() -> Option<String> {
    sudoers_rule(&current_user()?).ok()
}

/// La règle attendue est-elle en place ? Toujours vrai hors macOS.
pub fn has_permissions() -> bool {
    #[cfg(target_os = "macos")]
    {
        match (expected_rule(), marker_path()) {
            (Some(rule), Some(marker)) => rule_installed(Path::new(SUDOERS_PATH), &marker, &rule),
            _ => false,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

/// Commande shell lancée en administrateur par `osascript`. Le texte est
/// échappé pour une chaîne AppleScript (`\` puis `"`) ; ce qu'il contient
/// doit déjà être cité pour le shell.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn applescript_shell(shell: &str) -> String {
    let escaped = shell.replace('\\', r"\\").replace('"', "\\\"");
    format!(r#"do shell script "{escaped}" with administrator privileges"#)
}

/// Pose (ou repose) la règle sudoers : une invite de mot de passe.
#[cfg(target_os = "macos")]
pub fn install_permissions() -> Result<(), TempIpError> {
    use crate::proc::sync_cmd;

    let user = current_user().ok_or_else(|| TempIpError::Failed("utilisateur inconnu".into()))?;
    let rule = sudoers_rule(&user)?;
    let shell = install_shell(&rule, SUDOERS_PATH);
    let out = sync_cmd("osascript")
        .args(["-e", &applescript_shell(&shell)])
        .output()
        .map_err(|e| TempIpError::Failed(e.to_string()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        if err.contains("-128") || err.contains("User cancel") || err.is_empty() {
            return Err(TempIpError::ElevationRefused);
        }
        return Err(TempIpError::Failed(err));
    }
    // Marqueur raté : la prochaine fois, une invite de plus ; pas une erreur.
    if let Some(marker) = marker_path() {
        let _ = write_marker(&marker, &rule);
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn install_permissions() -> Result<(), TempIpError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applescript_escapes_backslashes_then_quotes() {
        assert_eq!(
            applescript_shell(r#"printf '%s\n' "a""#),
            r#"do shell script "printf '%s\\n' \"a\"" with administrator privileges"#
        );
    }

    #[test]
    fn sudoers_rule_is_scoped_to_the_user_and_the_lenscout_service() {
        assert_eq!(
            sudoers_rule("alice").unwrap(),
            "alice ALL=(root) NOPASSWD: /usr/sbin/networksetup -duplicatenetworkservice * Lenscout, /usr/sbin/networksetup -setmanual Lenscout *, /usr/sbin/networksetup -removenetworkservice Lenscout, /usr/sbin/networksetup -ordernetworkservices *"
        );
        assert!(sudoers_rule("_svc.x-1").is_ok());
    }

    #[test]
    fn invalid_user_name_is_refused() {
        for bad in ["", "Alice", "1abc", "a b", "a,ALL", "a'b", "%admin", "a\nb", "a\n", "root ALL=(ALL) ALL #", "é"] {
            assert!(matches!(sudoers_rule(bad), Err(TempIpError::Invalid(_))), "{bad:?}");
        }
    }

    fn scratch() -> crate::testing::TmpDir {
        crate::testing::TmpDir::new("lenscout-test")
    }

    #[test]
    fn marker_matching_the_expected_rule_means_installed() {
        let d = scratch();
        let (sudoers, marker) = (d.join("lenscout"), d.join(MARKER_FILE));
        std::fs::write(&sudoers, b"").unwrap();
        let rule = sudoers_rule("alice").unwrap();
        write_marker(&marker, &rule).unwrap();
        assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), rule_hash(&rule));
        assert_eq!(rule_hash(&rule).len(), 64);
        assert!(rule_installed(&sudoers, &marker, &rule));
    }

    #[test]
    fn missing_or_different_marker_or_file_forces_a_reinstall() {
        let d = scratch();
        let (sudoers, marker) = (d.join("lenscout"), d.join(MARKER_FILE));
        let rule = sudoers_rule("bob").unwrap();
        std::fs::write(&sudoers, b"").unwrap();
        assert!(!rule_installed(&sudoers, &marker, &rule), "marqueur absent");
        write_marker(&marker, &sudoers_rule("alice").unwrap()).unwrap();
        assert!(!rule_installed(&sudoers, &marker, &rule), "marqueur d'une autre règle");
        write_marker(&marker, &rule).unwrap();
        std::fs::remove_file(&sudoers).unwrap();
        assert!(!rule_installed(&sudoers, &marker, &rule), "fichier sudoers absent");
    }

    #[test]
    fn install_script_keeps_0440_root_wheel_and_checks_before_moving() {
        let rule = sudoers_rule("alice").unwrap();
        let sh = install_shell(&rule, "/etc/sudoers.d/lenscout");
        let tmp = "/etc/sudoers.d/lenscout.tmp";
        let order = [
            format!("> {tmp}"),
            format!("chown root:wheel {tmp}"),
            format!("chmod 440 {tmp}"),
            format!("/usr/sbin/visudo -cf {tmp}"),
            format!("mv -f {tmp} /etc/sudoers.d/lenscout"),
        ];
        let mut at = 0;
        for step in &order {
            let found = sh[at..].find(step.as_str()).unwrap_or_else(|| panic!("{step} manquant ou mal placé : {sh}"));
            at += found + step.len();
        }
        assert!(!sh.contains("444"), "{sh}");
        assert!(sh.contains(&format!("printf '%s\\n' '{rule}'")), "{sh}");
    }

    #[test]
    fn nothing_to_install_off_macos() {
        if cfg!(not(target_os = "macos")) {
            assert!(has_permissions());
            assert_eq!(install_permissions(), Ok(()));
        }
    }
}
