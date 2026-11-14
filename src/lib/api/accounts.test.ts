import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import {
  applyImport, defaultChoices, exportAccounts, groupPlan, importPlan, noticeKey, passwordRequired, pickAccount,
  suffixedName, type ImportPlan,
} from './accounts';
import { errorKey } from './errors';

const list = [
  { id: 'a', name: 'A', login: 'root' },
  { id: 'b', name: 'B', login: 'admin' },
];

test('le dernier choix est repris s’il existe encore', () => {
  expect(pickAccount(list, 'b')).toBe('b');
});

test('un choix disparu ou absent retombe sur le premier compte', () => {
  expect(pickAccount(list, 'zzz')).toBe('a');
  expect(pickAccount(list, '')).toBe('a');
});

test('aucun compte : aucun choix', () => {
  expect(pickAccount([], 'a')).toBe('');
});

test('les codes de comptes ont leur libellé', () => {
  for (const code of ['empty_field', 'duplicate_name', 'not_found', 'secret_missing', 'keyring', 'io']) {
    expect(errorKey(code)).toBe(`error.${code}`);
  }
});

test('le mot de passe est obligatoire en création et pour un compte sans secret', () => {
  expect(passwordRequired(null)).toBe(true);
  expect(passwordRequired({ id: 'a', name: 'A', login: 'r', has_secret: false })).toBe(true);
  expect(passwordRequired({ id: 'a', name: 'A', login: 'r', has_secret: true })).toBe(false);
});

test('le signalement de démarrage a son libellé, un code inconnu est ignoré', () => {
  expect(noticeKey('quarantined')).toBe('notice.quarantined');
  expect(noticeKey('unwritable')).toBe('notice.unwritable');
  expect(noticeKey(null)).toBeNull();
  expect(noticeKey('autre')).toBeNull();
});

const plan: ImportPlan = {
  items: [
    { name: 'Mairie Arles', kind: 'differs', login_differs: true, password_differs: false },
    { name: 'Client Dupont', kind: 'differs', login_differs: false, password_differs: true },
    { name: 'Gare', kind: 'new', login_differs: false, password_differs: false },
    { name: 'Usine', kind: 'identical', login_differs: false, password_differs: false },
  ],
};

test('export : le chemin choisi part tel quel, le nombre de comptes revient', async () => {
  invoke.mockResolvedValueOnce(4);
  expect(await exportAccounts('/tmp/lenscout-comptes.lenscout')).toBe(4);
  expect(invoke).toHaveBeenCalledWith('cmd_accounts_export', { path: '/tmp/lenscout-comptes.lenscout' });
});

test('plan d’import : appel de la commande avec le chemin', async () => {
  invoke.mockResolvedValueOnce(plan);
  expect(await importPlan('/tmp/a.lenscout')).toEqual(plan);
  expect(invoke).toHaveBeenLastCalledWith('cmd_accounts_import_plan', { path: '/tmp/a.lenscout' });
});

test('le plan se range en trois groupes, ordre du fichier conservé', () => {
  const g = groupPlan(plan);
  expect(g.differs.map((i) => i.name)).toEqual(['Mairie Arles', 'Client Dupont']);
  expect(g.added.map((i) => i.name)).toEqual(['Gare']);
  expect(g.identical.map((i) => i.name)).toEqual(['Usine']);
});

test('Remplacer est le choix par défaut, pour les seuls comptes qui diffèrent', () => {
  expect(defaultChoices(plan)).toEqual({ 'Mairie Arles': 'replace', 'Client Dupont': 'replace' });
});

test('application : les choix partent par nom, en snake_case, sans les comptes qui ne diffèrent pas', async () => {
  invoke.mockResolvedValueOnce({ added: 1, identical: 1, replaced: 1, kept_both: 1, skipped: 0 });
  const choices = { ...defaultChoices(plan), 'Mairie Arles': 'keep_both' as const };
  const summary = await applyImport('/tmp/a.lenscout', choices);
  expect(summary.kept_both).toBe(1);
  expect(invoke).toHaveBeenLastCalledWith('cmd_accounts_import_apply', {
    path: '/tmp/a.lenscout',
    choices: { 'Mairie Arles': 'keep_both', 'Client Dupont': 'replace' },
  });
});

test('« Garder les deux » annonce le prochain nom libre', () => {
  expect(suffixedName('Mairie Arles', ['Mairie Arles', 'mairie arles 2'])).toBe('Mairie Arles 3');
  expect(suffixedName('Gare', ['Autre'])).toBe('Gare 2');
});

test('le code import_invalid a son libellé', () => {
  expect(errorKey('import_invalid')).toBe('error.import_invalid');
});
