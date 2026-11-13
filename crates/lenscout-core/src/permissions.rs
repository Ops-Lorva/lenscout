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
//! - lisible par tous (0444) : `has_permissions` compare son CONTENU à la
//!   règle attendue et la repose si elle diffère. sudo n'exige que l'absence
//!   d'écriture pour le groupe et les autres.

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
         /usr/sbin/networksetup -setmanual Lenscout *, /usr/sbin/networksetup -removenetworkservice Lenscout"
    ))
}

/// Le fichier installé contient-il exactement la règle (et rien d'autre) ?
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn rule_matches(content: &str, rule: &str) -> bool {
    content.trim_end_matches('\n') == rule
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
        match (expected_rule(), std::fs::read_to_string(SUDOERS_PATH)) {
            (Some(rule), Ok(content)) => rule_matches(&content, &rule),
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
    // `sudoers.d` ignore les noms contenant un point : le fichier temporaire
    // n'est jamais lu par sudo.
    let tmp = format!("{SUDOERS_PATH}.tmp");
    let shell = format!(
        "printf '%s\\n' '{rule}' > {tmp} && chmod 440 {tmp} && /usr/sbin/visudo -cf {tmp} && chmod 444 {tmp} && mv {tmp} {SUDOERS_PATH} || {{ rm -f {tmp}; exit 1; }}"
    );
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
            sudoers_rule("benjamin").unwrap(),
            "benjamin ALL=(root) NOPASSWD: /usr/sbin/networksetup -duplicatenetworkservice * Lenscout, /usr/sbin/networksetup -setmanual Lenscout *, /usr/sbin/networksetup -removenetworkservice Lenscout"
        );
        assert!(sudoers_rule("_svc.x-1").is_ok());
    }

    #[test]
    fn invalid_user_name_is_refused() {
        for bad in ["", "Benjamin", "1abc", "a b", "a,ALL", "a'b", "%admin", "a\nb", "a\n", "root ALL=(ALL) ALL #", "é"] {
            assert!(matches!(sudoers_rule(bad), Err(TempIpError::Invalid(_))), "{bad:?}");
        }
    }

    #[test]
    fn installed_rule_must_match_exactly() {
        let rule = sudoers_rule("benjamin").unwrap();
        assert!(rule_matches(&format!("{rule}\n"), &rule));
        assert!(!rule_matches("%admin ALL=(root) NOPASSWD: /usr/sbin/networksetup\n", &rule));
        assert!(!rule_matches(&format!("{rule}\nbenjamin ALL=(ALL) ALL\n"), &rule));
        assert!(!rule_matches("", &rule));
    }

    #[test]
    fn nothing_to_install_off_macos() {
        if cfg!(not(target_os = "macos")) {
            assert!(has_permissions());
            assert_eq!(install_permissions(), Ok(()));
        }
    }
}
