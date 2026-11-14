//! Changement d'identifiant de l'app (`io.lenscout.app` → `io.lenscout.desktop`) :
//! les dossiers rangés sous l'identifiant (comptes, journal de l'IP
//! temporaire, `debug`, marqueur sudoers, profil du webview) sont recopiés
//! sous le nouveau, au lancement, AVANT tout chargement et avant le webview.
//! Copie vérifiée fichier par fichier, puis mise en place par `rename` ;
//! l'ancien dossier reste tel quel (jamais supprimé).

use std::io;
use std::path::{Path, PathBuf};

/// Ancien identifiant (Tauri avertit : un identifiant macOS ne doit pas finir par `.app`).
pub const OLD_IDENTIFIER: &str = "io.lenscout.app";
/// Identifiant actuel, celui de `tauri.conf.json`.
pub const IDENTIFIER: &str = "io.lenscout.desktop";

/// Ce que `migrate_dir` a fait.
#[derive(Debug, PartialEq)]
pub enum Migration {
    /// Le nouveau dossier existe déjà, ou l'ancien n'existe pas.
    NothingToDo,
    /// Contenu recopié et vérifié, nouveau dossier en place.
    Copied,
    /// Reprise après un échec : ce qui manquait au nouveau dossier y est
    /// recopié (voir `merge_dir`).
    Merged,
}

/// Nom sous lequel un fichier de l'ancien dossier est posé dans le nouveau
/// quand les deux diffèrent (`accounts.json` : comptes à fusionner).
pub fn set_aside_name(file: &str) -> String {
    format!("{file}.{OLD_IDENTIFIER}")
}

/// Fichiers dont l'ancienne version est posée à côté de la nouvelle quand
/// les deux existent et diffèrent ; les autres : la nouvelle gagne.
const SET_ASIDE: &[&str] = &["accounts.json"];

/// Une migration par dossier, avec reprise : un échec laisse le marqueur
/// `<new>.migration-incomplete`. Tant qu'il est là, chaque lancement
/// réessaie — et si le nouveau dossier a été créé entre-temps, `merge_dir`
/// complète sans rien écraser. Réussite : le marqueur est renommé
/// (`.migration-done-<horodatage>`), jamais effacé.
pub fn migrate_one(old: &Path, new: &Path) -> io::Result<Migration> {
    let marker = sibling(new, "migration-incomplete");
    let r = if new.exists() && marker.exists() && old.is_dir() {
        merge_dir(old, new).map(|()| Migration::Merged)
    } else {
        migrate_dir(old, new)
    };
    match &r {
        Err(_) => {
            let _ = std::fs::write(&marker, b"");
        }
        Ok(_) if marker.exists() => {
            std::fs::rename(&marker, sibling(new, &format!("migration-done-{}", stamp())))?;
        }
        Ok(_) => {}
    }
    r
}

/// Reprise dans un nouveau dossier déjà en service : chaque entrée de
/// `old` absente de `new` y est recopiée (via un voisin, puis `rename`) ;
/// une entrée présente n'est jamais écrasée ni mélangée (un dossier comme
/// le profil du webview ne se fusionne pas fichier à fichier). Exception :
/// `SET_ASIDE`, posé à côté sous `set_aside_name` quand il diffère.
fn merge_dir(old: &Path, new: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(old)? {
        let entry = entry?;
        let name = entry.file_name();
        let (src, mut dst) = (entry.path(), new.join(&name));
        if dst.exists() || dst.symlink_metadata().is_ok() {
            let file = name.to_string_lossy();
            if !SET_ASIDE.contains(&file.as_ref()) || same_file(&src, &dst)? {
                continue;
            }
            dst = new.join(set_aside_name(&file));
            if dst.exists() {
                continue;
            }
        }
        let tmp = sibling(&dst, "migration");
        if tmp.symlink_metadata().is_ok() {
            // Reprise interrompue : mise de côté, comme dans `migrate_dir`.
            std::fs::rename(&tmp, sibling(&dst, &format!("migration-{}", stamp())))?;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&src, &tmp)?;
        } else if kind.is_symlink() {
            copy_link(&src, &tmp)?;
        } else {
            std::fs::copy(&src, &tmp)?;
        }
        std::fs::rename(&tmp, &dst)?;
    }
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> io::Result<bool> {
    Ok(std::fs::read(a)? == std::fs::read(b)?)
}

fn stamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Recopie `old` en `new` si `new` n'existe pas encore. La copie se fait
/// dans un voisin `<new>.migration`, est comparée octet par octet à
/// l'original, puis renommée en `new`. Une copie interrompue d'un lancement
/// précédent est mise de côté (`.migration-<horodatage>`), pas effacée.
/// Échec : `new` n'est pas créé, `old` est intact ; le prochain lancement
/// réessaie.
pub fn migrate_dir(old: &Path, new: &Path) -> io::Result<Migration> {
    if new.exists() || !old.is_dir() {
        return Ok(Migration::NothingToDo);
    }
    let staging = sibling(new, "migration");
    if staging.exists() {
        std::fs::rename(&staging, sibling(new, &format!("migration-{}", stamp())))?;
    }
    if let Some(parent) = new.parent() {
        std::fs::create_dir_all(parent)?;
    }
    copy_tree(old, &staging)?;
    if !same_tree(old, &staging)? {
        return Err(io::Error::other("copie différente de l'original"));
    }
    std::fs::rename(&staging, new)?;
    Ok(Migration::Copied)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{suffix}"));
    path.with_file_name(name)
}

/// Fichiers et dossiers ; un lien symbolique est recopié comme lien.
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::create_dir(to)?;
    std::fs::set_permissions(to, std::fs::metadata(from)?.permissions())?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&src, &dst)?;
        } else if kind.is_symlink() {
            copy_link(&src, &dst)?;
        } else {
            // `fs::copy` reprend les droits (0600 de accounts.json).
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_link(src: &Path, dst: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(std::fs::read_link(src)?, dst)
}

#[cfg(not(unix))]
fn copy_link(src: &Path, dst: &Path) -> io::Result<()> {
    std::fs::copy(src, dst).map(|_| ())
}

/// Même arborescence, mêmes contenus.
fn same_tree(a: &Path, b: &Path) -> io::Result<bool> {
    let names = |p: &Path| -> io::Result<Vec<std::ffi::OsString>> {
        let mut v: Vec<_> = std::fs::read_dir(p)?.map(|e| e.map(|e| e.file_name())).collect::<Result<_, _>>()?;
        v.sort();
        Ok(v)
    };
    let list = names(a)?;
    if list != names(b)? {
        return Ok(false);
    }
    for name in list {
        let (x, y) = (a.join(&name), b.join(&name));
        let (mx, my) = (std::fs::symlink_metadata(&x)?, std::fs::symlink_metadata(&y)?);
        let same = if mx.is_dir() {
            my.is_dir() && same_tree(&x, &y)?
        } else if mx.file_type().is_symlink() {
            std::fs::read_link(&x)? == std::fs::read_link(&y)?
        } else {
            my.is_file() && std::fs::read(&x)? == std::fs::read(&y)?
        };
        if !same {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Les dossiers de l'app, ancien → nouveau, tels que Tauri les résout
/// (`app_config_dir`, `app_data_dir`, `app_local_data_dir` = profil du
/// webview sous Linux et Windows) ; macOS : aussi le profil WKWebView
/// (`~/Library/WebKit/<identifiant>`, `localStorage` : thème, langue). Sans
/// doublon (plusieurs se confondent selon l'OS).
pub fn identifier_moves(bases: &[PathBuf]) -> Vec<(PathBuf, PathBuf)> {
    let mut out: Vec<(PathBuf, PathBuf)> = Vec::new();
    for base in bases {
        let pair = (base.join(OLD_IDENTIFIER), base.join(IDENTIFIER));
        if !out.contains(&pair) {
            out.push(pair);
        }
    }
    out
}

/// Les dossiers de base du poste (ceux de Tauri : crate `dirs`, mêmes règles).
pub fn system_bases() -> Vec<PathBuf> {
    let mut bases: Vec<PathBuf> =
        [dirs_next::config_dir(), dirs_next::data_dir(), dirs_next::data_local_dir()].into_iter().flatten().collect();
    if cfg!(target_os = "macos")
        && let Some(home) = dirs_next::home_dir()
    {
        bases.push(home.join("Library").join("WebKit"));
    }
    bases
}

/// Au lancement : chaque dossier de l'ancien identifiant recopié sous le
/// nouveau (`migrate_one`). Rend les erreurs (dossier, message) sans
/// s'arrêter aux autres ; elles seront réessayées au prochain lancement.
pub fn migrate_identifier() -> Vec<(PathBuf, io::Error)> {
    identifier_moves(&system_bases())
        .into_iter()
        .filter_map(|(old, new)| migrate_one(&old, &new).err().map(|e| (old, e)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TmpDir;

    fn tree(root: &Path) {
        std::fs::create_dir_all(root.join("EBWebView/Default")).unwrap();
        std::fs::write(root.join("accounts.json"), b"{\"version\":2}").unwrap();
        std::fs::write(root.join("temp-ip.json"), b"{\"ip\":\"192.168.1.10\"}").unwrap();
        std::fs::write(root.join("debug"), b"").unwrap();
        std::fs::write(root.join("EBWebView/Default/Local Storage"), vec![7u8; 4096]).unwrap();
    }

    #[test]
    fn everything_is_copied_and_the_old_folder_stays() {
        let t = TmpDir::new("lenscout-migrate");
        let (old, new) = (t.join(OLD_IDENTIFIER), t.join(IDENTIFIER));
        tree(&old);
        assert_eq!(migrate_dir(&old, &new).unwrap(), Migration::Copied);
        assert!(same_tree(&old, &new).unwrap());
        assert_eq!(std::fs::read(new.join("temp-ip.json")).unwrap(), b"{\"ip\":\"192.168.1.10\"}");
        // Rien d'effacé, pas de dossier de travail laissé.
        assert!(old.join("accounts.json").exists());
        assert!(!t.join(format!("{IDENTIFIER}.migration")).exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_files_stay_private() {
        use std::os::unix::fs::PermissionsExt;
        let t = TmpDir::new("lenscout-migrate");
        let (old, new) = (t.join(OLD_IDENTIFIER), t.join(IDENTIFIER));
        tree(&old);
        std::fs::set_permissions(old.join("accounts.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
        migrate_dir(&old, &new).unwrap();
        let mode = std::fs::metadata(new.join("accounts.json")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn an_existing_new_folder_is_never_touched() {
        let t = TmpDir::new("lenscout-migrate");
        let (old, new) = (t.join(OLD_IDENTIFIER), t.join(IDENTIFIER));
        tree(&old);
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(new.join("accounts.json"), b"nouveau").unwrap();
        assert_eq!(migrate_dir(&old, &new).unwrap(), Migration::NothingToDo);
        assert_eq!(std::fs::read(new.join("accounts.json")).unwrap(), b"nouveau");
        assert!(!new.join("temp-ip.json").exists());
    }

    #[test]
    fn nothing_to_migrate_creates_nothing() {
        let t = TmpDir::new("lenscout-migrate");
        let new = t.join(IDENTIFIER);
        assert_eq!(migrate_dir(&t.join(OLD_IDENTIFIER), &new).unwrap(), Migration::NothingToDo);
        assert!(!new.exists());
    }

    #[test]
    fn an_interrupted_copy_is_set_aside_then_redone() {
        let t = TmpDir::new("lenscout-migrate");
        let (old, new) = (t.join(OLD_IDENTIFIER), t.join(IDENTIFIER));
        tree(&old);
        let staging = t.join(format!("{IDENTIFIER}.migration"));
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("accounts.json"), b"tronque").unwrap();
        assert_eq!(migrate_dir(&old, &new).unwrap(), Migration::Copied);
        assert!(same_tree(&old, &new).unwrap());
        // L'ancienne copie partielle est gardée à côté, renommée.
        let kept = std::fs::read_dir(&*t)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with(&format!("{IDENTIFIER}.migration-")));
        assert!(kept);
    }

    #[test]
    fn a_different_copy_is_detected() {
        let t = TmpDir::new("lenscout-migrate");
        let (a, b) = (t.join("a"), t.join("b"));
        tree(&a);
        tree(&b);
        assert!(same_tree(&a, &b).unwrap());
        std::fs::write(b.join("accounts.json"), b"autre").unwrap();
        assert!(!same_tree(&a, &b).unwrap());
        std::fs::write(b.join("en-trop"), b"").unwrap();
        assert!(!same_tree(&a, &b).unwrap());
    }

    fn marker(t: &Path) -> PathBuf {
        t.join(format!("{IDENTIFIER}.migration-incomplete"))
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_copy_leaves_a_marker_and_is_retried() {
        use std::os::unix::fs::PermissionsExt;
        let t = TmpDir::new("lenscout-migrate");
        let (old, new) = (t.join(OLD_IDENTIFIER), t.join(IDENTIFIER));
        tree(&old);
        let locked = old.join("debug");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(migrate_one(&old, &new).is_err());
        assert!(marker(&t).exists());
        // Le lancement raté a quand même créé le nouveau dossier (premier compte saisi).
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(new.join("accounts.json"), b"nouveau").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(migrate_one(&old, &new).unwrap(), Migration::Merged);
        assert!(!marker(&t).exists());
        assert_eq!(std::fs::read(new.join("temp-ip.json")).unwrap(), b"{\"ip\":\"192.168.1.10\"}");
        // Plus de marqueur : plus rien à reprendre.
        assert_eq!(migrate_one(&old, &new).unwrap(), Migration::NothingToDo);
    }

    #[test]
    fn a_retry_never_overwrites_and_sets_old_accounts_aside() {
        let t = TmpDir::new("lenscout-migrate");
        let (old, new) = (t.join(OLD_IDENTIFIER), t.join(IDENTIFIER));
        tree(&old);
        std::fs::write(old.join("EBWebView/Default/ancien"), b"x").unwrap();
        std::fs::create_dir_all(new.join("EBWebView/Default")).unwrap();
        std::fs::write(new.join("accounts.json"), b"nouveau").unwrap();
        std::fs::write(new.join("debug"), b"").unwrap();
        // Reste d'une reprise interrompue : mis de côté, pas bloquant.
        std::fs::create_dir_all(new.join("temp-ip.json.migration")).unwrap();
        std::fs::write(marker(&t), b"").unwrap();
        assert_eq!(migrate_one(&old, &new).unwrap(), Migration::Merged);
        // Le nouveau carnet reste ; l'ancien est posé à côté pour la fusion.
        assert_eq!(std::fs::read(new.join("accounts.json")).unwrap(), b"nouveau");
        assert_eq!(std::fs::read(new.join(set_aside_name("accounts.json"))).unwrap(), b"{\"version\":2}");
        // Ce qui manque est repris ; un dossier existant n'est jamais mélangé.
        assert!(new.join("temp-ip.json").exists());
        assert!(!new.join("EBWebView/Default/ancien").exists());
        assert!(old.join("accounts.json").exists());
        // Même contenu des deux côtés : rien posé à côté.
        let t2 = TmpDir::new("lenscout-migrate");
        let (old2, new2) = (t2.join(OLD_IDENTIFIER), t2.join(IDENTIFIER));
        tree(&old2);
        tree(&new2);
        std::fs::write(marker(&t2), b"").unwrap();
        assert_eq!(migrate_one(&old2, &new2).unwrap(), Migration::Merged);
        assert!(!new2.join(set_aside_name("accounts.json")).exists());
    }

    #[test]
    fn moves_follow_tauri_folders_without_duplicates() {
        let bases = [PathBuf::from("/c"), PathBuf::from("/c"), PathBuf::from("/d")];
        let moves = identifier_moves(&bases);
        assert_eq!(
            moves,
            vec![
                (PathBuf::from("/c/io.lenscout.app"), PathBuf::from("/c/io.lenscout.desktop")),
                (PathBuf::from("/d/io.lenscout.app"), PathBuf::from("/d/io.lenscout.desktop")),
            ]
        );
    }

    #[test]
    fn the_identifier_is_the_one_tauri_uses() {
        let conf = include_str!("../../../src-tauri/tauri.conf.json");
        let v: serde_json::Value = serde_json::from_str(conf).unwrap();
        assert_eq!(v["identifier"], IDENTIFIER);
        assert!(!IDENTIFIER.ends_with(".app"));
    }
}
