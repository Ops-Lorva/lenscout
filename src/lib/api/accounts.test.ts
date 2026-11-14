import { expect, test, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import {
  accountPassword, createAccount, joinable, netIn, passwordToSend, pcIpError, updateAccount, whyKeys,
  applyImport, defaultChoices, exportAccounts, groupPlan, importPlan, keepBothNames, noticeKey, passwordRequired,
  pickAccount, suffixedName, withExtension, type ImportPlan,
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
  expect(noticeKey('migration_incomplete')).toBe('notice.migration_incomplete');
  expect(noticeKey(null)).toBeNull();
  expect(noticeKey('autre')).toBeNull();
});

const plan: ImportPlan = {
  items: [
    { name: 'Mairie Arles', kind: 'differs', login_differs: true, password_differs: false, network_differs: false, gateway_dropped: false },
    { name: 'Client Dupont', kind: 'differs', login_differs: false, password_differs: true, network_differs: false, gateway_dropped: false },
    { name: 'Gare', kind: 'new', login_differs: false, password_differs: false, network_differs: false, gateway_dropped: false },
    { name: 'Usine', kind: 'identical', login_differs: false, password_differs: false, network_differs: false, gateway_dropped: false },
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

test('« Garder les deux » évite aussi tous les noms du fichier et du carnet', () => {
  const file: ImportPlan = {
    items: [
      { name: 'X', kind: 'differs', login_differs: true, password_differs: false, network_differs: false, gateway_dropped: false },
      { name: 'X 2', kind: 'new', login_differs: false, password_differs: false, network_differs: false, gateway_dropped: false },
      { name: 'Y', kind: 'differs', login_differs: true, password_differs: false, network_differs: false, gateway_dropped: false },
    ],
  };
  const choices = { X: 'keep_both', Y: 'replace' } as const;
  expect(keepBothNames(file, { ...choices }, ['X', 'Y'])).toEqual(['X 3']);
  expect(keepBothNames(file, { X: 'keep_both', Y: 'keep_both' }, ['X', 'Y'])).toEqual(['X 3', 'Y 2']);
  expect(keepBothNames(file, { X: 'replace', Y: 'skip' }, ['X', 'Y'])).toEqual([]);
});

test('« Garder les deux » compare les noms sans tenir compte de la casse, comme le core', () => {
  const file: ImportPlan = {
    items: [
      { name: 'cam', kind: 'differs', login_differs: true, password_differs: false, network_differs: false, gateway_dropped: false },
      { name: 'CAM 2', kind: 'new', login_differs: false, password_differs: false, network_differs: false, gateway_dropped: false },
      { name: 'Nvr', kind: 'differs', login_differs: true, password_differs: false, network_differs: false, gateway_dropped: false },
      { name: 'nvr', kind: 'differs', login_differs: true, password_differs: false, network_differs: false, gateway_dropped: false },
    ],
  };
  const both = { cam: 'keep_both', Nvr: 'keep_both', nvr: 'keep_both' } as const;
  // « cam 2 » est pris par « CAM 2 » du fichier ; « nvr 2 » est réservé pour le suivant.
  expect(keepBothNames(file, { ...both }, ['CAM', 'NVR'])).toEqual(['cam 3', 'Nvr 2', 'nvr 3']);
});

test('le fichier exporté porte l’extension .lenscout', () => {
  expect(withExtension('/tmp/sauvegarde')).toBe('/tmp/sauvegarde.lenscout');
  expect(withExtension('/tmp/a.lenscout')).toBe('/tmp/a.lenscout');
  expect(withExtension('/tmp/a.LENSCOUT')).toBe('/tmp/a.LENSCOUT');
});

test('les codes d’E/S du fichier choisi ont leur libellé', () => {
  expect(errorKey('file_unwritable')).toBe('error.file_unwritable');
  expect(errorKey('file_unreadable')).toBe('error.file_unreadable');
});

test('champs réseau : vides → null, transmis à la création et à la modification', async () => {
  invoke.mockResolvedValue({});
  // Le réseau ne se saisit plus : Rust le déduit de l'IP du PC.
  const net = netIn(' 192.168.1.250/24 ', '192.168.1.1');
  expect(net).toEqual({ pc_ip: '192.168.1.250/24', network: null, gateway: '192.168.1.1' });
  await createAccount('A', 'root', 'pw', net);
  expect(invoke).toHaveBeenLastCalledWith('cmd_account_create', { name: 'A', login: 'root', password: 'pw', net });
  await updateAccount('id', 'A', 'root', null, net);
  expect(invoke).toHaveBeenLastCalledWith('cmd_account_update', { id: 'id', name: 'A', login: 'root', password: null, net });
});

test('ce qui diffère à l’import, réseau compris', () => {
  const item = (l: boolean, p: boolean, n: boolean) =>
    ({ name: 'X', kind: 'differs', login_differs: l, password_differs: p, network_differs: n, gateway_dropped: false }) as const;
  expect(whyKeys(item(true, true, false))).toEqual(['both']);
  expect(whyKeys(item(true, false, true))).toEqual(['login', 'network']);
  expect(whyKeys(item(false, false, true))).toEqual(['network']);
  expect(whyKeys(item(false, true, false))).toEqual(['password']);
});

test('passerelle écartée à l’import : dite pour tout compte, nouveau ou non', () => {
  const base = { name: 'X', login_differs: false, password_differs: false, network_differs: false, gateway_dropped: true };
  expect(whyKeys({ ...base, kind: 'new' })).toEqual(['gateway_dropped']);
  expect(whyKeys({ ...base, kind: 'identical' })).toEqual(['gateway_dropped']);
  expect(whyKeys({ ...base, kind: 'differs', login_differs: true })).toEqual(['login', 'gateway_dropped']);
});

test('le sélecteur de réseau ne propose que les comptes qui ont une IP du PC', () => {
  const list = [
    { id: 'a', name: 'A', login: 'r', pc_ip: '192.168.1.250/24' },
    { id: 'b', name: 'B', login: 'r' },
    { id: 'c', name: 'C', login: 'r', pc_ip: '' },
  ];
  expect(joinable(list).map((a) => a.id)).toEqual(['a']);
});

test('IP du PC sans masque : erreur sous le champ, jamais de /24 ajouté', () => {
  expect(pcIpError('192.168.1.250')).toBe('error.missing_mask');
  expect(pcIpError(' 192.168.1.250 ')).toBe('error.missing_mask');
  expect(pcIpError('192.168.1.250/24')).toBe('');
  // Champ vide : facultatif, pas d'erreur.
  expect(pcIpError('')).toBe('');
  expect(pcIpError('  ')).toBe('');
  expect(errorKey('missing_mask')).toBe('error.missing_mask');
});

test('mot de passe de la fiche Modifier : déchiffré à la demande, un compte à la fois', async () => {
  invoke.mockResolvedValue('pw');
  expect(await accountPassword('id-1')).toBe('pw');
  expect(invoke).toHaveBeenLastCalledWith('cmd_account_password', { id: 'id-1' });
});

test('mot de passe non touché : conservé (rien envoyé), modifié : envoyé', () => {
  expect(passwordToSend('secret', 'secret')).toBeNull();
  expect(passwordToSend('', 'secret')).toBeNull();
  expect(passwordToSend('', '')).toBeNull();
  expect(passwordToSend('neuf', 'secret')).toBe('neuf');
  // Compte à ressaisir : rien de prérempli, la saisie part.
  expect(passwordToSend('neuf', '')).toBe('neuf');
});
