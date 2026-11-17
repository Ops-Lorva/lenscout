//! Classeur Excel à partir d'une description (feuilles, en-têtes, lignes,
//! teinte par ligne, cellules mises en valeur). Le front choisit les
//! libellés et l'ordre ; ici, seulement la mise en forme.

use std::collections::HashSet;

use rust_xlsxwriter::{Color, Format, FormatBorder, Table, TableColumn, TableStyle, Workbook, Worksheet, XlsxError};
use serde::Deserialize;

/// Teintes Excel habituelles : vert clair, rouge clair, ambre clair ;
/// l'orange vif marque une cellule à reprendre ailleurs (le NVR).
const OK_FILL: u32 = 0xC6EFCE;
const BAD_FILL: u32 = 0xFFC7CE;
const WARN_FILL: u32 = 0xFFEB9C;
const HIGHLIGHT_FILL: u32 = 0xFFC000;
const HEADER_FILL: u32 = 0x1F4E78;

/// Largeur d'une colonne, en caractères.
const MIN_WIDTH: f64 = 8.0;
const MAX_WIDTH: f64 = 60.0;

/// Teinte d'une ligne : réussie, en échec, à surveiller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    Ok,
    Bad,
    Warn,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Row {
    pub cells: Vec<String>,
    #[serde(default)]
    pub tone: Option<Tone>,
    /// Colonnes (à partir de 0) mises en valeur sur cette ligne.
    #[serde(default)]
    pub highlight: Vec<usize>,
}

/// En-tête présent : un tableau (en-tête figé, filtre). En-tête vide : des
/// couples libellé / valeur, libellé en gras.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Sheet {
    pub name: String,
    #[serde(default)]
    pub header: Vec<String>,
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Report {
    pub sheets: Vec<Sheet>,
}

/// Le classeur, en octets. Toute cellule est écrite en texte : une IP reste
/// une IP, une valeur qui commence par `=` ne devient pas une formule.
pub fn build(report: &Report) -> Result<Vec<u8>, String> {
    let mut book = Workbook::new();
    for sheet in &report.sheets {
        let ws = book.add_worksheet();
        write_sheet(ws, sheet).map_err(|e| e.to_string())?;
    }
    book.save_to_buffer().map_err(|e| e.to_string())
}

fn write_sheet(ws: &mut Worksheet, sheet: &Sheet) -> Result<(), XlsxError> {
    // Excel limite le nom d'une feuille à 31 caractères.
    ws.set_name(sheet.name.chars().take(31).collect::<String>())?;
    let fill = |rgb: u32| Format::new().set_background_color(Color::RGB(rgb)).set_border(FormatBorder::Thin).set_border_color(Color::RGB(0xBFBFBF));
    let header_fmt = Format::new().set_bold().set_font_color(Color::White).set_background_color(Color::RGB(HEADER_FILL));
    let plain = Format::new();
    let label = Format::new().set_bold();
    let highlight = fill(HIGHLIGHT_FILL).set_bold();
    let tone_fmt = |t: Option<Tone>| match t {
        Some(Tone::Ok) => fill(OK_FILL),
        Some(Tone::Bad) => fill(BAD_FILL),
        Some(Tone::Warn) => fill(WARN_FILL),
        None => Format::new(),
    };

    let table = !sheet.header.is_empty();
    let first = u32::from(table);
    let cols = sheet.rows.iter().map(|r| r.cells.len()).chain([sheet.header.len()]).max().unwrap_or(0);
    for (i, row) in sheet.rows.iter().enumerate() {
        let r = first + i as u32;
        let base = tone_fmt(row.tone);
        for (c, v) in row.cells.iter().enumerate() {
            let fmt = if row.highlight.contains(&c) {
                &highlight
            } else if !table && c == 0 {
                &label
            } else if row.tone.is_some() {
                &base
            } else {
                &plain
            };
            ws.write_string_with_format(r, c as u16, v, fmt)?;
        }
    }

    for c in 0..cols {
        let mut cells: Vec<&str> = sheet.rows.iter().filter_map(|r| r.cells.get(c).map(String::as_str)).collect();
        // L'en-tête porte la flèche du filtre : deux caractères de plus.
        let head = sheet.header.get(c).map(|h| format!("{h}  "));
        if let Some(h) = &head {
            cells.push(h);
        }
        ws.set_column_width(c as u16, width(&cells))?;
    }

    if !table {
        return Ok(());
    }
    let last_col = (cols.max(1) - 1) as u16;
    let last_row = sheet.rows.len() as u32;
    ws.set_freeze_panes(1, 0)?;
    let unique = sheet.header.iter().map(|h| h.to_lowercase()).collect::<HashSet<_>>().len() == sheet.header.len();
    if sheet.rows.is_empty() || !unique {
        // Un tableau Excel exige une ligne de données et des en-têtes uniques ;
        // à défaut, en-tête mis en forme et filtre simple.
        for (c, h) in sheet.header.iter().enumerate() {
            ws.write_string_with_format(0, c as u16, h, &header_fmt)?;
        }
        ws.autofilter(0, 0, last_row, last_col)?;
    } else {
        let columns: Vec<TableColumn> =
            sheet.header.iter().map(|h| TableColumn::new().set_header(h).set_header_format(&header_fmt)).collect();
        let t = Table::new().set_columns(&columns).set_style(TableStyle::Light1).set_banded_rows(false);
        ws.add_table(0, 0, last_row, last_col, &t)?;
    }
    Ok(())
}

/// Le plus long contenu, plus une marge, borné.
fn width(cells: &[&str]) -> f64 {
    let longest = cells.iter().map(|c| c.chars().count()).max().unwrap_or(0) as f64;
    (longest + 2.0).clamp(MIN_WIDTH, MAX_WIDTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    fn unzip(bytes: &[u8], name: &str) -> Option<String> {
        let mut z = zip::ZipArchive::new(Cursor::new(bytes)).expect("zip valide");
        let mut f = z.by_name(name).ok()?;
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        Some(s)
    }

    fn row(cells: &[&str], tone: Option<Tone>, highlight: &[usize]) -> Row {
        Row { cells: cells.iter().map(|c| c.to_string()).collect(), tone, highlight: highlight.to_vec() }
    }

    fn report() -> Report {
        Report {
            sheets: vec![
                Sheet {
                    name: "Opérations".into(),
                    header: vec!["Résultat".into(), "À changer dans le NVR".into(), "Nouvelle IP".into()],
                    rows: vec![
                        row(&["OK", "Oui", "10.0.50.21"], Some(Tone::Ok), &[1]),
                        row(&["KO", "Non", "=1+1"], Some(Tone::Bad), &[]),
                    ],
                },
                Sheet { name: "Infos".into(), header: vec![], rows: vec![row(&["Compte", "Site A"], None, &[])] },
            ],
        }
    }

    #[test]
    fn workbook_is_a_zip_with_its_sheets_and_values_as_text() {
        let bytes = build(&report()).unwrap();
        let sheet1 = unzip(&bytes, "xl/worksheets/sheet1.xml").expect("sheet1");
        assert!(unzip(&bytes, "xl/worksheets/sheet2.xml").is_some());
        let book = unzip(&bytes, "xl/workbook.xml").unwrap();
        assert!(book.contains("Opérations") && book.contains("Infos"));
        // Tout en chaînes partagées : aucune valeur numérique ni formule.
        let strings = unzip(&bytes, "xl/sharedStrings.xml").unwrap();
        for v in ["Résultat", "À changer dans le NVR", "10.0.50.21", "=1+1", "Oui", "Non", "Compte", "Site A"] {
            assert!(strings.contains(v), "{v} absent");
        }
        assert!(!sheet1.contains("<f>"));
        assert!(!sheet1.contains("<v>10.0.50.21</v>"));
    }

    #[test]
    fn table_sheet_has_frozen_header_filter_widths_and_fills() {
        let bytes = build(&report()).unwrap();
        let sheet1 = unzip(&bytes, "xl/worksheets/sheet1.xml").unwrap();
        assert!(sheet1.contains("<pane") && sheet1.contains("state=\"frozen\""));
        assert!(sheet1.contains("<col "), "largeurs de colonnes");
        // Un tableau Excel (filtre compris) sur toute la plage.
        let table = unzip(&bytes, "xl/tables/table1.xml").expect("tableau");
        assert!(table.contains("ref=\"A1:C3\"") && table.contains("autoFilter"));
        let styles = unzip(&bytes, "xl/styles.xml").unwrap();
        for rgb in ["FFC6EFCE", "FFFFC7CE", "FFFFC000"] {
            assert!(styles.contains(rgb), "{rgb} absent");
        }
        // La feuille Infos n'est pas un tableau.
        let sheet2 = unzip(&bytes, "xl/worksheets/sheet2.xml").unwrap();
        assert!(!sheet2.contains("tablePart") && !sheet2.contains("<pane"));
    }

    #[test]
    fn table_without_rows_keeps_a_filter() {
        let r = Report { sheets: vec![Sheet { name: "Vide".into(), header: vec!["A".into(), "B".into()], rows: vec![] }] };
        let bytes = build(&r).unwrap();
        let sheet1 = unzip(&bytes, "xl/worksheets/sheet1.xml").unwrap();
        assert!(sheet1.contains("<autoFilter ref=\"A1:B1\""));
    }

    #[test]
    fn width_follows_the_longest_cell_within_bounds() {
        assert_eq!(width(&["IP", "10.0.50.21"]), 12.0);
        assert_eq!(width(&["a"]), 8.0);
        assert_eq!(width(&["x".repeat(200).as_str()]), 60.0);
    }
}
