//! Export d'un rapport (test de login, réseau du compte) : le CSV est mis en
//! forme par le front, Rust ne fait que l'écrire.

use std::path::{Path, PathBuf};

use lenscout_core::accounts::write_file_private;

/// Le rapport porte l'extension `.csv` (la boîte Enregistrer peut la laisser
/// de côté).
fn with_csv_ext(path: &Path) -> PathBuf {
    match path.extension() {
        Some(e) if e.eq_ignore_ascii_case("csv") => path.to_path_buf(),
        _ => {
            let mut p = path.as_os_str().to_owned();
            p.push(".csv");
            p.into()
        }
    }
}

/// Écriture atomique (temporaire voisin puis `rename`, mécanisme du core).
/// Rend le chemin écrit. Erreur : `file_unwritable`, traduite par le front ;
/// le message de l'OS n'est pas renvoyé.
pub(crate) fn save_report(path: &Path, content: &str) -> Result<PathBuf, String> {
    let path = with_csv_ext(path);
    write_file_private(&path, content.as_bytes()).map_err(|_| "file_unwritable".to_string())?;
    Ok(path)
}

/// Écrit `content` dans `path`. Le chemin vient de la boîte Enregistrer du
/// plugin dialog, jamais d'un champ de saisie.
#[tauri::command]
pub async fn cmd_save_report(path: String, content: String) -> Result<(), String> {
    save_report(Path::new(&path), &content).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenscout_core::testing::TmpDir;

    #[test]
    fn report_is_written_atomically_with_csv_extension() {
        let dir = TmpDir::new("lenscout-report");
        let written = save_report(&dir.join("rapport"), "a;b\r\n").unwrap();
        assert_eq!(written, dir.join("rapport.csv"));
        assert_eq!(std::fs::read_to_string(&written).unwrap(), "a;b\r\n");
        // Aucun temporaire ne reste à côté.
        let names: Vec<_> = std::fs::read_dir(&*dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["rapport.csv"]);
        // Extension déjà là, quelle que soit la casse : gardée telle quelle.
        assert_eq!(save_report(&dir.join("x.CSV"), "").unwrap(), dir.join("x.CSV"));
    }

    #[test]
    fn report_to_unwritable_path_is_file_unwritable() {
        let dir = TmpDir::new("lenscout-report");
        let r = save_report(&dir.join("absent").join("rapport.csv"), "x");
        assert_eq!(r, Err("file_unwritable".to_string()));
    }
}
