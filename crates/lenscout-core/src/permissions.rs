// Repris de LanProbe crates/lanprobe-core/src/permissions.rs le 2026-11-13
//! Règle sudoers macOS posée une fois (une invite), avec l'assistant
//! `/usr/local/libexec/lenscout-nethelper` (root:wheel 0755) : ensuite
//! l'assistant passe par `sudo -n`, sans mot de passe. Linux (polkit via
//! nmcli) et Windows (UAC à chaque script) n'ont rien à installer.
//!
//! Adaptations :
//! - chemin `/etc/sudoers.d/lenscout` ;
//! - règle restreinte à l'utilisateur courant et au seul assistant, sans
//!   joker sur `networksetup` (les jokers de sudoers traversent les espaces :
//!   la règle d'avant laissait réordonner tous les services ou poser une IP
//!   quelconque). L'assistant (`nethelper.sh`) prend des arguments typés et
//!   revalide tout lui-même — LanProbe ouvrait tout `networksetup` au groupe
//!   `%admin` ;
//! - assistant posé avant la règle, dans un dossier que seul root peut
//!   modifier (sinon rien n'est posé : l'app reste sur l'invite à chaque
//!   fois) ;
//! - écrite par `printf '%s\n'` (LanProbe la passait comme format à
//!   `printf`, où `%a` de `%admin` est une conversion), vérifiée par
//!   `visudo -c` puis mise en place par renommage — un fichier sudoers
//!   invalide casserait `sudo` ;
//! - root:wheel 0440, rien d'autre ; illisible par l'app, il est suivi par un
//!   marqueur (`<app_data_dir>/sudoers-rule.sha256`, hash de la version, de
//!   la règle et de l'assistant installés) : installation attendue différente
//!   ou marqueur absent → réinstallation.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::temp_ip::TempIpError;

#[cfg(target_os = "macos")]
const SUDOERS_PATH: &str = "/etc/sudoers.d/lenscout";

/// Version de l'installation (règle + assistant) : la changer fait reposer
/// les deux une fois. 1 : règle à jokers sur `networksetup` ; 2 : assistant.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) const RULE_VERSION: u32 = 2;

/// L'assistant, seul programme autorisé par la règle.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) const HELPER_PATH: &str = "/usr/local/libexec/lenscout-nethelper";

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) const NETWORKSETUP: &str = "/usr/sbin/networksetup";

/// Texte de l'assistant, `networksetup` à `networksetup` (les tests passent un faux).
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn nethelper_script(networksetup: &str) -> String {
    include_str!("nethelper.sh").replace("@NETWORKSETUP@", networksetup)
}

/// Ce que le marqueur atteste : version, règle et assistant.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn install_id(rule: &str) -> String {
    format!("v{RULE_VERSION}\n{rule}\n{}", nethelper_script(NETWORKSETUP))
}

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
    Ok(format!("{user} ALL=(root) NOPASSWD: {HELPER_PATH}"))
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

/// `content` écrit tel quel (plus un saut de ligne) dans `path` : cité pour
/// le shell (`'…'`, `'` → `'\''`), passé en argument de `printf`, jamais
/// comme format.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn write_file_shell(content: &str, path: &str) -> String {
    format!("printf '%s\\n' '{}' > {path}", content.replace('\'', r"'\''"))
}

/// Script shell (lancé en root) qui pose l'assistant puis la règle.
///
/// L'assistant d'abord : `/usr/local` et `/usr/local/libexec` doivent
/// appartenir à root et n'être modifiables ni par le groupe ni par les autres
/// (un Homebrew d'Intel les donne à l'utilisateur : qui pourrait renommer le
/// dossier remplacerait l'assistant lancé en root) ; sinon rien n'est posé.
/// Temporaire root:wheel 0755, puis renommé.
///
/// La règle ensuite : fichier temporaire root:wheel 0440 — jamais d'autre
/// mode, un fichier inattendu dans `sudoers.d` peut faire refuser `sudo`
/// entier —, vérifié par `visudo -c`, puis renommé (atomique). `sudoers.d`
/// ignore les noms contenant un point : le temporaire n'est jamais lu par sudo.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn install_shell(rule: &str, path: &str) -> String {
    let tmp = format!("{path}.tmp");
    let htmp = format!("{HELPER_PATH}.tmp");
    let helper = write_file_shell(&nethelper_script(NETWORKSETUP), &htmp);
    format!(
        "umask 022 && /bin/mkdir -p /usr/local/libexec && \
         for d in /usr/local /usr/local/libexec; do case \"$(/usr/bin/stat -f '%Su %Lp' $d)\" in 'root '*[0145][0145]) ;; *) exit 1 ;; esac; done && \
         {helper} && chown root:wheel {htmp} && chmod 755 {htmp} && mv -f {htmp} {HELPER_PATH} && \
         umask 077 && printf '%s\\n' '{rule}' > {tmp} && chown root:wheel {tmp} && chmod 440 {tmp} && /usr/sbin/visudo -cf {tmp} && mv -f {tmp} {path} || {{ rm -f {htmp} {tmp}; exit 1; }}"
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
            (Some(rule), Some(marker)) => {
                Path::new(HELPER_PATH).exists() && rule_installed(Path::new(SUDOERS_PATH), &marker, &install_id(&rule))
            }
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

/// Pose (ou repose) l'assistant et la règle sudoers : une invite de mot de passe.
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
        let _ = write_marker(&marker, &install_id(&rule));
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

    /// La règle n'ouvre que l'assistant, qui revalide ses arguments : plus de
    /// joker sur `networksetup`.
    #[test]
    fn sudoers_rule_only_allows_the_helper() {
        assert_eq!(sudoers_rule("alice").unwrap(), "alice ALL=(root) NOPASSWD: /usr/local/libexec/lenscout-nethelper");
        assert!(!sudoers_rule("alice").unwrap().contains("networksetup"));
        assert!(!sudoers_rule("alice").unwrap().contains('*'));
        assert!(sudoers_rule("_svc.x-1").is_ok());
    }

    /// Le marqueur d'une installation porte la version : la règle à jokers
    /// d'avant (et son marqueur) est remplacée une fois.
    #[test]
    fn the_previous_rule_marker_forces_one_reinstall() {
        let d = scratch();
        let (sudoers, marker) = (d.join("lenscout"), d.join(MARKER_FILE));
        std::fs::write(&sudoers, b"").unwrap();
        let old = "alice ALL=(root) NOPASSWD: /usr/sbin/networksetup -duplicatenetworkservice * Lenscout, \
                   /usr/sbin/networksetup -setmanual Lenscout *, /usr/sbin/networksetup -removenetworkservice Lenscout, /usr/sbin/networksetup -ordernetworkservices * Lenscout";
        write_marker(&marker, old).unwrap();
        let id = install_id(&sudoers_rule("alice").unwrap());
        assert!(!rule_installed(&sudoers, &marker, &id));
        assert!(id.starts_with(&format!("v{RULE_VERSION}\n")), "{id}");
        const { assert!(RULE_VERSION >= 2) };
        assert!(id.contains(&nethelper_script(NETWORKSETUP)), "l'assistant fait partie de l'installation");
        write_marker(&marker, &id).unwrap();
        assert!(rule_installed(&sudoers, &marker, &id));
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

    /// L'assistant est posé avant la règle, root:wheel 0755, dans un dossier
    /// que seul root peut modifier ; sinon rien n'est posé.
    #[test]
    fn install_script_puts_the_helper_first_root_owned_in_a_root_only_directory() {
        let rule = sudoers_rule("alice").unwrap();
        let sh = install_shell(&rule, "/etc/sudoers.d/lenscout");
        let tmp = format!("{HELPER_PATH}.tmp");
        let order = [
            "mkdir -p /usr/local/libexec".to_string(),
            "/usr/local /usr/local/libexec".to_string(),
            format!("> {tmp}"),
            format!("chown root:wheel {tmp}"),
            format!("chmod 755 {tmp}"),
            format!("mv -f {tmp} {HELPER_PATH}"),
            "> /etc/sudoers.d/lenscout.tmp".to_string(),
        ];
        let mut at = 0;
        for step in &order {
            let found = sh[at..].find(step.as_str()).unwrap_or_else(|| panic!("{step} manquant ou mal placé : {sh}"));
            at += found + step.len();
        }
        assert!(sh.contains("stat -f"), "{sh}");
        // Le tout est une commande `sh` valide.
        #[cfg(unix)]
        assert!(std::process::Command::new("/bin/sh").args(["-n", "-c", &sh]).status().unwrap().success(), "{sh}");
    }

    /// Le texte de l'assistant traverse le shell intact (guillemets, `$`, `\`).
    #[cfg(unix)]
    #[test]
    fn the_helper_text_is_written_byte_for_byte_by_the_shell() {
        let d = scratch();
        let out = d.join("helper");
        let sh = write_file_shell(&nethelper_script(NETWORKSETUP), &out.to_string_lossy());
        let st = std::process::Command::new("/bin/sh").args(["-c", &sh]).status().unwrap();
        assert!(st.success());
        assert_eq!(std::fs::read_to_string(&out).unwrap(), format!("{}\n", nethelper_script(NETWORKSETUP)));
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

    /// Assistant lancé sous Linux avec un faux `networksetup` qui journalise
    /// ses arguments (`|` entre chacun) et rend des listes fixes.
    #[cfg(unix)]
    struct Helper {
        dir: crate::testing::TmpDir,
    }

    #[cfg(unix)]
    impl Helper {
        /// `fail_on` : argument dont la commande écrit « ** Error » (code 0).
        fn new(order: &str, fail_on: &str) -> Helper {
            use std::os::unix::fs::PermissionsExt;
            let dir = crate::testing::TmpDir::new("lenscout-helper");
            let log = dir.join("log");
            let stub = dir.join("networksetup");
            std::fs::write(
                &stub,
                format!(
                    "#!/bin/bash\nprintf '%s|' \"$@\" >> '{log}'\necho >> '{log}'\n\
                     case \"$1\" in\n\
                     -listallnetworkservices) printf 'An asterisk (*) denotes that a network service is disabled.\\nWi-Fi\\nUSB 10/100/1000 LAN\\n*Thunderbolt Bridge\\n' ;;\n\
                     -listnetworkserviceorder) printf '%s' '{order}' ;;\n\
                     {fail_on}) echo '** Error: refusé' ;;\n\
                     esac\nexit 0\n",
                    log = log.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::write(dir.join("helper"), nethelper_script(&stub.to_string_lossy())).unwrap();
            Helper { dir }
        }

        fn run(&self, args: &[&str]) -> (i32, Vec<String>) {
            let st = std::process::Command::new("bash").arg(self.dir.join("helper")).args(args).output().unwrap();
            let log = std::fs::read_to_string(self.dir.join("log")).unwrap_or_default();
            (st.status.code().unwrap_or(-1), log.lines().map(str::to_owned).collect())
        }
    }

    #[cfg(unix)]
    const ORDER: &str = "An asterisk (*) denotes that a network service is disabled.\n\
                         (1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n\
                         (2) Lenscout\n(Hardware Port: USB 10/100/1000 LAN, Device: en7)\n\n\
                         (*) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n\n\
                         (3) USB 10/100/1000 LAN\n(Hardware Port: USB 10/100/1000 LAN, Device: en7)\n";

    #[cfg(unix)]
    #[test]
    fn the_helper_is_valid_bash() {
        let d = scratch();
        std::fs::write(d.join("helper"), nethelper_script(NETWORKSETUP)).unwrap();
        let st = std::process::Command::new("bash").arg("-n").arg(d.join("helper")).status().unwrap();
        assert!(st.success());
        assert!(nethelper_script(NETWORKSETUP).starts_with("#!/bin/bash\n"));
        assert!(nethelper_script(NETWORKSETUP).contains("NS='/usr/sbin/networksetup'"));
    }

    /// Même service dupliqué, même adresse (routeur = elle-même), puis l'ordre
    /// recalculé par l'assistant à partir de l'ordre courant, « Lenscout » en
    /// dernier (la route par défaut ne change pas).
    #[cfg(unix)]
    #[test]
    fn the_helper_adds_the_service_then_puts_it_last() {
        let h = Helper::new(ORDER, "-nothing");
        let (code, log) = h.run(&["add", "USB 10/100/1000 LAN", "169.254.7.7", "255.255.0.0"]);
        assert_eq!(code, 0, "{log:?}");
        let writes: Vec<&String> = log.iter().filter(|l| !l.starts_with("-list")).collect();
        assert_eq!(
            writes,
            [
                "-duplicatenetworkservice|USB 10/100/1000 LAN|Lenscout|",
                "-setmanual|Lenscout|169.254.7.7|255.255.0.0|169.254.7.7|",
                "-ordernetworkservices|Wi-Fi|Thunderbolt Bridge|USB 10/100/1000 LAN|Lenscout|",
            ]
        );
        let (code, log) = h.run(&["add", "Wi-Fi", "192.168.1.250", "255.255.255.0"]);
        assert_eq!(code, 0, "{log:?}");
        let (code, log) = Helper::new(ORDER, "-nothing").run(&["remove"]);
        assert_eq!((code, log), (0, vec!["-removenetworkservice|Lenscout|".to_string()]));
    }

    /// Tout argument hors de ce que l'assistant accepte : rien n'est modifié.
    #[cfg(unix)]
    #[test]
    fn the_helper_refuses_anything_else_without_touching_the_network() {
        let h = Helper::new(ORDER, "-nothing");
        for args in [
            vec![],
            vec!["status"],
            vec!["remove", "Wi-Fi"],
            vec!["add", "Wi-Fi", "169.254.7.7"],
            vec!["add", "Wi-Fi", "169.254.7.7", "255.255.0.0", "extra"],
            // Adresses publiques ou mal formées.
            vec!["add", "Wi-Fi", "8.8.8.8", "255.255.255.0"],
            vec!["add", "Wi-Fi", "172.32.0.1", "255.255.255.0"],
            vec!["add", "Wi-Fi", "192.169.1.1", "255.255.255.0"],
            vec!["add", "Wi-Fi", "1.2.3", "255.255.255.0"],
            vec!["add", "Wi-Fi", "192.168.01.1", "255.255.255.0"],
            vec!["add", "Wi-Fi", "192.168.1.256", "255.255.255.0"],
            vec!["add", "Wi-Fi", "192.168.1.1 ", "255.255.255.0"],
            vec!["add", "Wi-Fi", "192.168.1.1;id", "255.255.255.0"],
            vec!["add", "Wi-Fi", "192.168.1.0", "255.255.255.0"],
            vec!["add", "Wi-Fi", "192.168.1.255", "255.255.255.0"],
            // Masques non contigus ou hors /8 à /30.
            vec!["add", "Wi-Fi", "192.168.1.1", "255.0.255.0"],
            vec!["add", "Wi-Fi", "192.168.1.1", "255.255.255.254"],
            vec!["add", "Wi-Fi", "10.1.1.1", "254.0.0.0"],
            vec!["add", "Wi-Fi", "10.1.1.1", "0.0.0.0"],
            // Service source absent, désactivé, ou « Lenscout » lui-même.
            vec!["add", "Ethernet", "192.168.1.1", "255.255.255.0"],
            vec!["add", "Thunderbolt Bridge", "192.168.1.1", "255.255.255.0"],
            vec!["add", "*Thunderbolt Bridge", "192.168.1.1", "255.255.255.0"],
            vec!["add", "Lenscout", "192.168.1.1", "255.255.255.0"],
            vec!["add", "-listallnetworkservices", "192.168.1.1", "255.255.255.0"],
            vec!["add", "", "192.168.1.1", "255.255.255.0"],
        ] {
            let (code, log) = h.run(&args);
            assert_ne!(code, 0, "{args:?}");
            assert!(log.iter().all(|l| l.starts_with("-list")), "{args:?} : {log:?}");
        }
        // Les bornes acceptées.
        for (ip, mask) in [("10.0.0.1", "255.0.0.0"), ("172.31.255.254", "255.240.0.0"), ("192.168.0.90", "255.255.255.252")] {
            let (code, log) = Helper::new(ORDER, "-nothing").run(&["add", "Wi-Fi", ip, mask]);
            assert_eq!(code, 0, "{ip}/{mask} : {log:?}");
        }
    }

    /// networksetup rend 0 en écrivant « ** Error » : l'assistant échoue et
    /// s'arrête ; un ordre illisible empêche toute pose.
    #[cfg(unix)]
    #[test]
    fn the_helper_fails_on_a_networksetup_error_or_an_unreadable_order() {
        let (code, log) = Helper::new(ORDER, "-setmanual").run(&["add", "Wi-Fi", "169.254.7.7", "255.255.0.0"]);
        assert_ne!(code, 0);
        assert!(!log.iter().any(|l| l.starts_with("-ordernetworkservices")), "{log:?}");
        let (code, log) = Helper::new("rien de lisible\n", "-nothing").run(&["add", "Wi-Fi", "169.254.7.7", "255.255.0.0"]);
        assert_ne!(code, 0);
        assert!(log.iter().all(|l| l.starts_with("-list")), "{log:?}");
    }

    #[test]
    fn nothing_to_install_off_macos() {
        if cfg!(not(target_os = "macos")) {
            assert!(has_permissions());
            assert_eq!(install_permissions(), Ok(()));
        }
    }
}
