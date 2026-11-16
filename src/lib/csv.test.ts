import { expect, test } from 'vitest';
import { csvLang, csvName, toCsv } from './csv';

const BOM = '﻿';

test('quotes_separators_quotes_and_newlines', () => {
  const out = toCsv(['Nom', 'IP'], [['a;b', '10.0.0.1'], ['dit "oui"', 'x\ny'], ['simple', '']], 'fr');
  expect(out).toBe(`${BOM}Nom;IP\r\n"a;b";10.0.0.1\r\n"dit ""oui""";"x\ny"\r\nsimple;\r\n`);
});

test('semicolon_in_fr_es_comma_in_en', () => {
  expect(toCsv(['a', 'b'], [], 'fr')).toBe(`${BOM}a;b\r\n`);
  expect(toCsv(['a', 'b'], [], 'es')).toBe(`${BOM}a;b\r\n`);
  expect(toCsv(['a', 'b'], [['1,2', '3']], 'en')).toBe(`${BOM}a,b\r\n"1,2",3\r\n`);
});

test('starts_with_utf8_bom', () => {
  expect(toCsv(['Caméra'], [], 'fr').startsWith(BOM)).toBe(true);
});

test('a_cell_read_as_a_formula_by_a_spreadsheet_is_neutralised', () => {
  // Un nom d'appareil vient du réseau : il ne doit pas devenir une formule.
  const out = toCsv(['n'], [['=HYPERLINK("x")'], ['+1'], ['@a'], ['-2'], ['ok']], 'en');
  expect(out).toBe(`${BOM}n\r\n"'=HYPERLINK(""x"")"\r\n'+1\r\n'@a\r\n'-2\r\nok\r\n`);
});

test('csv_name_is_safe_for_any_account_name', () => {
  const d = new Date(2026, 10, 6);
  expect(csvName('login', 'Mairie / Arles: bât A', d)).toBe('lenscout-login-Mairie-Arles-bât-A-2026-11-06.csv');
  expect(csvName('reseau', 'a\\b*c?"<>|', d)).toBe('lenscout-reseau-a-b-c-2026-11-06.csv');
  expect(csvName('reseau', '  ', d)).toBe('lenscout-reseau-2026-11-06.csv');
});

test('the_csv_language_follows_the_interface_locale', () => {
  expect(csvLang('fr')).toBe('fr');
  expect(csvLang('en-US')).toBe('en');
  expect(csvLang('es')).toBe('es');
  expect(csvLang(null)).toBe('fr');
  expect(csvLang('de')).toBe('fr');
});
