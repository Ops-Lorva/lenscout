// Repris de LanProbe crates/lanprobe-core/src/permissions.rs le 2026-11-13
//! Règle sudoers macOS posée une fois (une invite) : ensuite `networksetup`
//! passe par `sudo -n`, sans mot de passe. Linux (polkit via nmcli) et
//! Windows (UAC à chaque `.bat`) n'ont rien à installer.
//!
//! Adaptations : chemin `/etc/sudoers.d/lenscout` ; la règle est écrite par
//! `printf '%s\n'` (LanProbe la passait comme format à `printf`, où `%a` de
//! `%admin` est une conversion), vérifiée par `visudo -c` puis mise en place
//! par renommage — un fichier sudoers invalide casserait `sudo`.

use crate::temp_ip::TempIpError;

#[cfg(target_os = "macos")]
const SUDOERS_PATH: &str = "/etc/sudoers.d/lenscout";

/// La règle est-elle en place ? Toujours vrai hors macOS.
pub fn has_permissions() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::path::Path::new(SUDOERS_PATH).exists()
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

/// Pose la règle sudoers (une invite de mot de passe).
#[cfg(target_os = "macos")]
pub fn install_permissions() -> Result<(), TempIpError> {
    use crate::proc::sync_cmd;

    // Le groupe %admin couvre tous les administrateurs du Mac ; seul
    // networksetup est autorisé. `sudoers.d` ignore les noms contenant un
    // point : le fichier temporaire n'est jamais lu par sudo.
    let rule = "%admin ALL=(root) NOPASSWD: /usr/sbin/networksetup";
    let tmp = format!("{SUDOERS_PATH}.tmp");
    let shell = format!(
        "printf '%s\\n' '{rule}' > {tmp} && chmod 440 {tmp} && /usr/sbin/visudo -cf {tmp} && mv {tmp} {SUDOERS_PATH} || {{ rm -f {tmp}; exit 1; }}"
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
    fn nothing_to_install_off_macos() {
        if cfg!(not(target_os = "macos")) {
            assert!(has_permissions());
            assert_eq!(install_permissions(), Ok(()));
        }
    }
}
