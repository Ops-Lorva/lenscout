//! Export d'un rapport (test de login, réseau du compte) : le CSV est mis en
//! forme par le front, Rust ne fait que l'écrire. Le classeur Excel (rapport
//! d'opération) est décrit par le front et construit par le core.

use std::path::{Path, PathBuf};

use lenscout_core::accounts::write_file_private;
use lenscout_core::xlsx::{self, Report};

/// Le rapport porte son extension (la boîte Enregistrer peut la laisser de
/// côté).
fn with_ext(path: &Path, ext: &str) -> PathBuf {
    match path.extension() {
        Some(e) if e.eq_ignore_ascii_case(ext) => path.to_path_buf(),
        _ => {
            let mut p = path.as_os_str().to_owned();
            p.push(".");
            p.push(ext);
            p.into()
        }
    }
}

/// Écriture atomique (temporaire voisin puis `rename`, mécanisme du core).
/// Rend le chemin écrit. Erreur : `file_unwritable`, traduite par le front ;
/// le message de l'OS n'est pas renvoyé.
pub(crate) fn save_report(path: &Path, content: &str) -> Result<PathBuf, String> {
    let path = with_ext(path, "csv");
    write_file_private(&path, content.as_bytes()).map_err(|_| "file_unwritable".to_string())?;
    Ok(path)
}

/// Écrit `content` dans `path`. Le chemin vient de la boîte Enregistrer du
/// plugin dialog, jamais d'un champ de saisie.
#[tauri::command]
pub async fn cmd_save_report(path: String, content: String) -> Result<(), String> {
    save_report(Path::new(&path), &content).map(|_| ())
}

/// Classeur `.xlsx`, même écriture atomique que le CSV. Erreur :
/// `file_unwritable` (écriture ou construction du classeur).
pub(crate) fn save_xlsx(path: &Path, report: &Report) -> Result<PathBuf, String> {
    let path = with_ext(path, "xlsx");
    let bytes = xlsx::build(report).map_err(|_| "file_unwritable".to_string())?;
    write_file_private(&path, &bytes).map_err(|_| "file_unwritable".to_string())?;
    Ok(path)
}

/// Écrit le classeur décrit par `report` ; rend le chemin écrit (extension
/// comprise). Le chemin vient de la boîte Enregistrer.
#[tauri::command]
pub async fn cmd_save_xlsx(path: String, report: Report) -> Result<String, String> {
    save_xlsx(Path::new(&path), &report).map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenscout_core::testing::TmpDir;
    use lenscout_core::xlsx::{Report, Row, Sheet};

    #[test]
    fn xlsx_is_written_atomically_with_xlsx_extension() {
        let dir = TmpDir::new("lenscout-report");
        let report = Report {
            sheets: vec![Sheet {
                name: "Opérations".into(),
                header: vec!["IP".into()],
                rows: vec![Row { cells: vec!["10.0.50.11".into()], ..Default::default() }],
            }],
        };
        let written = save_xlsx(&dir.join("operations"), &report).unwrap();
        assert_eq!(written, dir.join("operations.xlsx"));
        // Un classeur : une archive zip.
        assert!(std::fs::read(&written).unwrap().starts_with(b"PK"));
        let names: Vec<_> = std::fs::read_dir(&*dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["operations.xlsx"]);
        assert_eq!(save_xlsx(&dir.join("x.XLSX"), &report).unwrap(), dir.join("x.XLSX"));
        let r = save_xlsx(&dir.join("absent").join("x.xlsx"), &report);
        assert_eq!(r, Err("file_unwritable".to_string()));
    }

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
