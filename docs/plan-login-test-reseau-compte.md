# LenScout — Test de login et Réseau du compte : plan d'implémentation

> **Pour les agents :** exécuter tâche par tâche (superpowers:subagent-driven-development). Une tâche = un worktree sous `~/projects/LORVA/` = une branche tirée de la branche d'intégration `feat/login-reseau` (elle-même tirée de `origin/main`). Cases `- [ ]` à cocher.

**Demande :** Benjamin, 16/11, chantier réel : 173 caméras en 192.168.1.0/24, sans routeur, NVR en .251.

**Objectif :**
1. **Opérations → Test de login** : essayer les identifiants d'un compte sur les caméras cochées, en lecture seule, avec un résultat par caméra, un filtre et un export.
2. **Réseau du compte** : relever tout ce qui répond sur le sous-réseau du compte (pas seulement les caméras posées par LenScout), en garder l'inventaire daté par compte, mesurer l'occupation et proposer un masque plus large au-delà de 80 %.

**Architecture :** la même que l'existant. La logique vit dans `crates/lenscout-core` et se teste sans réseau (faux de `testing.rs`), `src-tauri` reste mince (état + `Channel` + `CancellationToken`, comme `commands/free_ips.rs`), le front ne fait qu'afficher (logique pure dans `src/lib/api/*.ts`, testée avec vitest).

## Décisions techniques (tranchées ici)

### Test de login
- **Requête par marque, strictement en lecture :**
  - Axis : `GET /axis-cgi/pwdgrp.cgi?action=get` en Digest, c'est-à-dire `vapix::try_auth`, déjà utilisé par « Changer les identifiants ». Cette requête ne passe que pour un administrateur. Or c'est le droit dont LenScout a besoin : un compte « viewer » valide sortira `denied`, et c'est voulu.
  - Hikvision / LTS : `GET /ISAPI/System/deviceInfo` en Digest, c'est-à-dire `isapi::device_identity`, déjà utilisé avant une réinitialisation. La même réponse confirme l'identité (MAC ou n° de série).
  - Autre marque : aucune requête, résultat `unsupported`.
- **Identité avant tout mot de passe**, comme les opérations existantes :
  - Axis : `actions::verify_identity(ctx, cam, None)`, une lecture anonyme. Si elle rend `NotNew` (lecture anonyme fermée sur un vieux firmware), on n'essaie que si l'adresse s'est annoncée au dernier scan sur cette interface (`ctx.seen`).
  - Hikvision : on n'essaie que si l'adresse s'est annoncée au dernier scan sur cette interface (règle de `reset_isapi`).
  - Un autre appareil à l'adresse donne `other_device`.
- **Pas d'IP temporaire.** Une caméra hors du sous-réseau et non routée est `unreachable`. Le test ne modifie ni les caméras ni le poste.
- **Non activée :** `cam.activation == New` donne `not_activated` sans aucune requête. Sur une Axis `Unknown` refusée, `vapix::activation_state` (anonyme) tranche entre `not_activated` et `denied`.
- **Anti-bruteforce :**
  - Un seul couple essayé par caméra et par passage : celui du compte. Le client Digest fait un premier aller sans identifiant puis une seule réponse au défi.
  - Mémoire de session côté Rust : par clé de ligne (MAC, sinon IP), les refus horodatés. À **2 refus en 30 min**, la caméra n'est plus essayée et sort `held`. Hikvision verrouille après 5 à 7 échecs selon le firmware, pour 30 min ; les autres écrans de LenScout (Cadrage, Opérations) consomment aussi des essais, d'où la marge. Constante `LOGIN_GUARD`, // À VÉRIFIER sur vraie Hikvision/LTS.
- **Concurrence et délais :**
  - 16 caméras à la fois. Le verrouillage est par caméra : paralléliser entre caméras ne le rapproche pas.
  - Délai de 3 s par requête : le `ctx.http` de `build_context` (8 s) est remplacé par un `ReqwestCameraHttp::new(LOGIN_TIMEOUT)`. Pire cas pour 173 caméras muettes : environ 11 vagues × 2 requêtes × 3 s ≈ 70 s.
- **Exécution côté Rust, en un seul appel**, et non pas ligne par ligne depuis le front comme `cmd_ops_step` : on veut la concurrence. Les résultats arrivent par `Channel`, l'annulation par numéro de passage (même mécanisme que `FreeIpsState`). L'annulation laisse finir les requêtes en vol et n'en lance plus.
- **Où :** un 5e choix dans le contrôle segmenté d'Opérations. On réutilise la table de sélection partagée avec Réseau (« toutes » = case d'en-tête). Ni aperçu ni confirmation : rien n'est écrit. Le résultat est rendu par un composant à part, `LoginTest.svelte`, pour ne pas alourdir `Operations.svelte` (507 lignes).
- **Filtre et export :**
  - Pastilles par résultat avec leur compte (un résultat à 0 est masqué) et recherche IP / MAC / modèle.
  - **L'export porte la vue filtrée**, en CSV.
- **Résultats non persistés.** Le test est un instantané, l'export sert de trace.

### Réseau du compte
- **Découverte : ping + ARP**, exactement le balayage de `free_ips::scan`, mis en commun. Les noms viennent ensuite de **deux paquets UDP unicast par hôte qui a répondu** :
  - NetBIOS « node status » (UDP 137) pour les PC Windows, NVR et serveurs ;
  - mDNS « legacy unicast » (PTR `d.c.b.a.in-addr.arpa` vers `ip:5353`, RFC 6762 §6.7) pour les caméras, imprimantes, Mac et Linux.
  - **Pas de DNS inverse :** un site sans routeur n'a pas de serveur DNS, et le résolveur système peut bloquer plusieurs secondes par adresse.
  - **Pas de sondage de ports :** Benjamin a demandé « passif ou léger ».
- **Type deviné** (`DeviceKind`), dans cet ordre :
  1. `this_pc` : l'IP du poste.
  2. `gateway` : la passerelle du compte ou de l'interface.
  3. Caméra vue au scan ou connue du compte : `nvr` si le modèle est un modèle de NVR (`DS-76…`, `DS-77…`, `DS-78…`, `DS-96…`, `iDS-7…`, `LTN…`, `NVR…`, liste en constante // À VÉRIFIER), sinon `camera`.
  4. OUI d'un fabricant de caméras (`oui::camera_brand_for_mac`) : `camera`.
  5. OUI d'un fabricant d'imprimantes (Brother, Canon, Epson, Kyocera, Lexmark, Ricoh, Xerox, Konica Minolta) : `printer`.
  6. OUI d'un fabricant de commutateurs (Cisco, Netgear, Ubiquiti, Aruba/HPE, D-Link, Zyxel, MikroTik, Juniper, Allied Telesis, Planet, Ruckus, Extreme) : `switch`.
  7. Réponse NetBIOS : `pc`.
  8. Sinon `unknown`.

  Le constructeur (OUI) est toujours affiché : l'installateur corrige de tête un type `unknown`.
- **Persistance : oui, par compte, horodatée.**
  - Dans `accounts.json`, à côté de `cameras` : chaque compte gagne `devices: [SeenDevice]` et `surveyed_at`. L'écriture reste atomique et le scellage est inchangé.
  - Chaque appareil porte `first_seen` / `last_seen`.
  - Un appareil absent d'un nouveau relevé **reste** (marqué « absent au dernier relevé ») et compte comme occupé, comme une caméra connue éteinte, jusqu'à « Oublier ».
  - **Pas dans l'export des comptes** : le format d'export ne bouge pas, les anciennes versions le relisent, et l'inventaire se refait en 5 s sur place. L'import « Remplacer » garde l'inventaire local.
- **Occupation :** `network_fill` compte désormais aussi les appareils relevés, avec un segment `device` sur la barre. Il ajoute les champs suivants :
  - `devices` ;
  - `used_pct = (utilisables − libres) / utilisables`, les exclues comptées comme prises ;
  - `crowded = used_pct ≥ 80` ;
  - `suggest` : le plus petit élargissement (/23, puis /22… jusqu'à /16) qui ramène l'occupation à 50 % ou moins, par exemple `192.168.0.0/23 (255.255.254.0)`.

  « Bientôt complet » (`almost_full`, moins de 10 % de libres) reste tel quel partout : aucune fonction retirée.
- **Les appareils relevés deviennent des adresses réservées** (`reserved_for`). Les feuilles IP / IP en lot / Renuméroter ne proposent plus l'IP d'un switch éteint. C'est cohérent avec la barre : ce qu'elle montre pris n'est pas proposé libre.
- **Où :** écran **Comptes**, section existante « Le réseau de ce compte » du panneau d'édition. On y ajoute :
  - le bouton « Relever » ;
  - la date du dernier relevé ;
  - l'occupation et la suggestion ;
  - un lien vers la liste complète, dans une feuille `Dialog` de 720 px (même modèle que « Agrandir la liste » des caméras connues), avec filtre par type, recherche, export CSV et « Oublier ».

  Pas l'écran Réseau : il reste la liste des caméras du scan.
- **Garde « sur place » :** le relevé balaie le réseau de l'IP du PC du compte. Il n'est permis que si l'interface choisie, ou l'adresse du compte posée (« Se mettre dans ce réseau »), est dans ce réseau. Sinon, erreur `not_on_account_network` et bouton désactivé côté front. Le mode routé (via le routeur) est accepté : le ping marche, mais sans MAC ni OUI.

### Commun
- **CSV :** `src/lib/csv.ts`, RFC 4180, BOM UTF-8 (Excel). Séparateur `;` en fr/es, `,` en en. En-têtes traduits. Nom de fichier `lenscout-<login|reseau>-<compte>-<AAAA-MM-JJ>.csv`.
- **Écriture du fichier :** une commande `cmd_save_report(path, content)` (nouveau `commands/report.rs`), écriture atomique, extension `.csv` imposée. Le chemin vient de `plugin-dialog` `save`, déjà autorisé dans `capabilities/default.json`.
- **i18n :**
  - deux nouveaux espaces : `logintest.json` et `sitenet.json` (fr/en/es) ;
  - les erreurs de commande restent dans les espaces existants : `configure.*` pour le test de login (comme Opérations), `free.*` pour le relevé (même balayage) ;
  - un seul nouveau code : `not_on_account_network`.

### Brickcom / ACTi (hors périmètre, pour mémoire)
- **Accueil prévu :** `login_test::test_login` aiguille par `Family`. Une branche **ONVIF** (`GetDeviceInformation` en WS-UsernameToken Digest, lecture seule) s'ajouterait sans toucher au reste, et servirait aussi les caméras `Other` vues en WSD. Il faudrait aussi, côté `model.rs`, une `Family::Onvif` ou des familles Brickcom et ACTi.
- **Inventaire :** il suffit d'ajouter `("brickcom", …)` et `("acti corporation", …)` à `oui::CAMERA_BRANDS`, et `guess_kind` les classe `camera`.

---

## Contrats (figés par ce plan, pour que les tâches parallèles s'accordent)

### Core `login_test.rs`
```rust
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum LoginOutcome { Ok, Denied, Unreachable, NotActivated, Unsupported, OtherDevice, Held }
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct LoginResult { pub index: usize, pub key: String, pub ip: Ipv4Addr, #[serde(flatten)] pub outcome: LoginOutcome }
#[derive(Clone, Copy)] pub struct LoginGuard { pub max_denials: u32, pub window: Duration }
#[derive(Default)] pub struct DenialLog { /* clé → Vec<Instant> */ }
impl DenialLog { pub fn allows(&self, key: &str, now: Instant, g: LoginGuard) -> bool; pub fn record(&mut self, key: &str, now: Instant); }
pub async fn test_login(ctx: &ActionContext, cam: &Camera, creds: &Credentials) -> LoginOutcome;
/// Rend `true` si annulé. `on_result` reçoit chaque ligne dès qu'elle est finie.
pub async fn run_login_test(ctx: &ActionContext, cams: &[Camera], creds: &Credentials, parallel: usize,
    log: &std::sync::Mutex<DenialLog>, guard: LoginGuard, cancel: CancellationToken, on_result: impl Fn(LoginResult)) -> bool;
```

### Tauri `commands/login_test.rs`
```rust
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoginEvent { Result(LoginResult), Done { cancelled: bool } }
#[tauri::command] pub async fn cmd_login_test(id: u64, cameras: Vec<Camera>, account_id: String, iface: String,
    channel: Channel<LoginEvent>, state: State<'_, LoginTestState>, scan: State<'_, ScanState>,
    journal: State<'_, TempIpJournal>, join: State<'_, JoinState>, accounts: State<'_, Mutex<AccountBook>>) -> Result<(), String>;
#[tauri::command] pub fn cmd_login_test_cancel(id: u64, state: State<'_, LoginTestState>);
```
Erreurs : `no_cameras`, `not_found`, `secret_missing`, `iface_unknown`, `iface_no_ipv4`, `internal`. Tous ces codes existent déjà dans `errors.ts`.

### Core `site_survey/`
```rust
// device.rs
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)] #[serde(rename_all = "snake_case")]
pub enum DeviceKind { Camera, Nvr, Switch, Pc, Printer, Gateway, ThisPc, Unknown }
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SeenDevice { pub ip: Ipv4Addr, pub mac: Option<String>, pub vendor: Option<String>, pub kind: DeviceKind,
    pub name: Option<String>, pub model: Option<String>, pub first_seen: u64, pub last_seen: u64 }
pub struct Clues<'a> { pub ip: Ipv4Addr, pub mac: Option<&'a str>, pub vendor: Option<&'a str>, pub camera_model: Option<&'a str>,
    pub is_camera: bool, pub netbios: bool, pub gateway: Option<Ipv4Addr>, pub pc: Option<Ipv4Addr> }
pub fn guess_kind(c: &Clues) -> DeviceKind;
pub fn is_nvr_model(model: &str) -> bool;
pub fn device_key(d: &SeenDevice) -> String;             // MAC, sinon IP
pub fn merge_devices(list: &mut Vec<SeenDevice>, seen: Vec<SeenDevice>) -> bool; // par clé ; une MAC qui change d'IP libère l'ancienne
// names.rs
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)] pub enum NameSource { NetBios, Mdns }
pub fn nbstat_query(txid: u16) -> Vec<u8>;
pub fn parse_nbstat(packet: &[u8]) -> Option<String>;               // 1er nom unique de type 0x00 ou 0x20
pub fn mdns_reverse_query(ip: Ipv4Addr) -> Vec<u8>;                 // hickory-proto
pub fn parse_mdns_reverse(packet: &[u8], ip: Ipv4Addr) -> Option<String>;
pub async fn resolve_names(ips: &[Ipv4Addr], netbios: Arc<dyn Datagram>, mdns: Arc<dyn Datagram>, wait: Duration)
    -> HashMap<Ipv4Addr, (String, NameSource)>;
// sweep.rs
#[derive(Debug, Clone, PartialEq)] pub struct HostSeen { pub ip: Ipv4Addr, pub mac: Option<String>, pub replied: bool }
pub async fn sweep(iface: &ScanInterface, probe: Arc<dyn FreeProbe>, progress: impl Fn(usize, usize),
    cancel: CancellationToken) -> Result<(Vec<HostSeen>, bool /* tronqué */), FreeError>;
```
`free_ips::FreeProbe::neighbours` rend désormais `HashMap<Ipv4Addr, String>` (IP → MAC).

### Core `accounts.rs` (ajouts)
```rust
pub enum SegmentKind { Gateway, Pc, Excluded, Camera, Device }
pub struct NetworkFill { /* existants */ pub devices: u32, pub used_pct: u8, pub crowded: bool, pub suggest: Option<String> }
pub fn network_fill_with(net: &AccountNetwork, cameras: &[KnownCamera], devices: &[SeenDevice], own: &[Ipv4Addr]) -> Option<NetworkFill>;
pub fn network_fill(net, cameras, own) -> Option<NetworkFill>  // inchangée : appelle network_fill_with(.., &[], ..)
pub fn suggest_network(base: Ipv4Addr, prefix: u8, used: u32) -> Option<String>; // "192.168.0.0/23"
impl AccountBook {
    pub fn record_survey(&mut self, id: &str, seen: Vec<SeenDevice>, at: u64) -> Result<(), AccountError>;
    pub fn devices(&self, id: &str) -> Result<(Vec<SeenDevice>, Option<u64>), AccountError>;
    pub fn forget_device(&mut self, id: &str, key: &str) -> Result<(), AccountError>;
}
```

### Tauri `commands/site_survey.rs` + `commands/accounts.rs`
```rust
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SurveyEvent { Progress { done: usize, total: usize }, Done { devices: Vec<SeenDevice>, surveyed_at: u64, fill: Option<NetworkFill>, truncated: bool } }
cmd_site_survey(id: u64, account_id: String, interface: String, cameras: Vec<Camera>, channel: Channel<SurveyEvent>, ...) -> Result<(), String>
cmd_site_survey_cancel(id: u64)
cmd_account_devices(id: String) -> Result<AccountDevices { devices, surveyed_at: Option<u64> }, String>   // dans commands/accounts.rs
cmd_account_forget_device(id: String, key: String) -> Result<(), String>                               // dans commands/accounts.rs
```
Erreurs du relevé : `iface_unknown`, `iface_no_ipv4`, `ping_unavailable`, `not_found`, `account_no_pc_ip`, `not_on_account_network` (seul nouveau code), `internal`.

### Front
- `src/lib/csv.ts` : `toCsv(header: string[], rows: string[][], lang: Lang): string` ; `csvName(kind: 'login' | 'reseau', account: string, d: Date): string`.
- `src/lib/api/report.ts` : `saveReport(path, content)`.
- `src/lib/api/loginTest.ts` : types miroirs, `startLoginTest(id, cameras, accountId, iface, onEvent)`, `cancelLoginTest(id)`, `loginCounts(rows)`, `filterLogin(rows, cams, codes, query)`, `loginCsvRows(rows, cams, t)`.
- `src/lib/api/siteNet.ts` : `SeenDevice`, `DeviceKind`, `startSurvey(...)`, `cancelSurvey(id)`, `accountDevices(id)`, `forgetDevice(id, key)`, `filterDevices(list, kinds, query)`, `devicesCsvRows(list, t)`, `absent(d, surveyedAt)`, `onAccountNetwork(addr, account)`.
- `src/lib/api/accounts.ts` : `NetworkFill` gagne `devices`, `used_pct`, `crowded`, `suggest`, et `FillSegment.kind` gagne `'device'`.

---

## Contraintes globales

- **Compilation :** `export CARGO_TARGET_DIR="$HOME/.cache/cargo-target/lenscout-<tâche>"`, un dossier par worktree, jamais `target/` dans le dépôt.
  - **Au plus 2 compilations Rust en même temps** sur la machine : les tâches Rust « parallèles » d'une même vague passent deux par deux.
  - Commandes : `cargo test -p lenscout-core`, `cargo test -p lenscout`, `cargo clippy --workspace --all-targets -- -D warnings`, `npm test` (svelte-check + vitest).
- **TDD** : écrire les tests listés, les voir échouer, implémenter, les voir passer.
- **Aucun mot de passe** dans un journal, un événement, un CSV ni un résultat (`Secret`, `Credentials` sans `Debug` révélateur).
- **Interface sobre :** pas de phrase d'évidence. Libellés courts, fr/en/es (test de parité). Aucun nom d'autre produit dans l'UI.
- **Aucune fonction retirée.** `almost_full`, l'Oublier des caméras connues, les quatre opérations existantes : intacts.
- Un nouveau fichier `.svelte` ou `.ts` ne demande aucun enregistrement manuel. Les modules Rust sont déclarés par la tâche 0, les commandes Tauri par la tâche W.
- Commits terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

---

## Tâches

### Tâche 0 : Échafaudage (séquentielle, avant tout)
**Objectif :** déclarer une fois pour toutes les modules et la brique d'export partagée, pour qu'aucune tâche suivante ne touche un fichier de déclaration.

**Fichiers :**
- Modify `crates/lenscout-core/src/lib.rs` : ajouter `pub mod login_test; pub mod site_survey;`.
- Create `crates/lenscout-core/src/login_test.rs` : commentaire de module seul.
- Create `crates/lenscout-core/src/site_survey/mod.rs` : `pub mod device; pub mod names; pub mod sweep;`.
- Create `crates/lenscout-core/src/site_survey/device.rs`, `names.rs`, `sweep.rs` : commentaires seuls.
- Modify `src-tauri/src/commands/mod.rs` : ajouter `pub mod login_test; pub mod report; pub mod site_survey;`.
- Create `src-tauri/src/commands/login_test.rs`, `src-tauri/src/commands/site_survey.rs` : commentaires seuls.
- Create `src-tauri/src/commands/report.rs`.
- Modify `src-tauri/src/lib.rs` : enregistrer `cmd_save_report`.
- Create `src/lib/csv.ts`, `src/lib/csv.test.ts`, `src/lib/api/report.ts`.

**Tests d'abord :**
- Rust (`report.rs`) :
  - `report_is_written_atomically_with_csv_extension` : `rapport` devient `rapport.csv`, le temporaire disparaît ;
  - `report_to_unwritable_path_is_file_unwritable`.
- vitest (`csv.test.ts`) :
  - `quotes_separators_quotes_and_newlines` ;
  - `semicolon_in_fr_es_comma_in_en` ;
  - `starts_with_utf8_bom` ;
  - `csv_name_is_safe_for_any_account_name` (`/`, `:` et espaces remplacés).

**Parallélisable :** non. Tout le reste en dépend.

**Réussite :** `cargo test -p lenscout`, `cargo clippy …`, `npm test` verts. Commit « Échafaudage test de login / réseau du compte ».

---

### Tâche L1 : Test de login, cœur (core)
**Objectif :** `test_login` et `run_login_test` selon le contrat, avec garde anti-verrouillage et annulation.

**Fichiers :** Modify `crates/lenscout-core/src/login_test.rs` (seul fichier touché).

**Tests d'abord** (`cargo test -p lenscout-core login_test`), avec `FakeHttp`, `FakeNeighbours`, `FakeRoutes` et un `ActionContext` de test comme dans `ops.rs` :
- `axis_ok_reads_pwdgrp_with_get_only` : 200, puis `Ok` ; toutes les requêtes enregistrées sont des `GET`.
- `axis_401_and_403_are_denied`.
- `axis_identity_mismatch_is_other_device_and_sends_no_password` : aucune requête authentifiée.
- `axis_closed_anonymous_identity_needs_the_last_scan`.
- `axis_unknown_activation_refused_then_systemready_new_is_not_activated`.
- `new_camera_is_not_activated_without_any_request`.
- `hikvision_ok_reads_device_info_and_checks_mac`.
- `hikvision_401_is_denied`.
- `hikvision_other_mac_is_other_device`.
- `hikvision_not_heard_at_this_address_is_unreachable_without_request`.
- `other_brand_is_unsupported_without_request`.
- `off_subnet_without_route_is_unreachable` : aucune IP temporaire, `PanicElevator`.
- `timeout_and_io_are_unreachable`.
- `guard_holds_after_two_denials_within_window_and_frees_after`.
- `run_tries_each_camera_once` : un seul envoi d'identifiant par caméra.
- `run_respects_parallel_limit` : compteur en vol dans un faux transport, au plus 16.
- `run_cancelled_starts_no_new_camera`.
- `run_records_denials_in_the_shared_log`.

**Parallélisable :** oui, avec L3, S1, S2, S3, S6 et E1 (aucun fichier commun). Dépend de 0.

**Réussite :** tests verts, clippy propre, aucune modification hors de `login_test.rs`.

---

### Tâche L2 : Test de login, commande Tauri
**Objectif :** `cmd_login_test` / `cmd_login_test_cancel` : passages numérotés, résultats en flux, garde partagée entre passages.

**Fichiers :** Modify `src-tauri/src/commands/login_test.rs` (seul fichier touché).

**Contenu :**
- `LoginTestState { runs: Mutex<Runs>, denials: Mutex<DenialLog> }`, avec le mécanisme `begin` / `cancel` de `FreeIpsState`, recopié : il fait 40 lignes, et l'extraire toucherait `free_ips.rs`, réservé à S5.
- `credentials_for` puis `build_context`, dont `ctx.http` est remplacé par `ReqwestCameraHttp::new(LOGIN_TIMEOUT = 3 s)`.
- Constantes `LOGIN_PARALLEL = 16` et `LOGIN_GUARD = { max_denials: 2, window: 30 min }` // À VÉRIFIER.
- Un échec d'envoi sur le `Channel` (webview partie) annule le passage.

**Tests d'abord** (`cargo test -p lenscout login_test`) :
- `events_serialize_as_the_front_reads_them` : `{"kind":"result","index":0,"key":…,"ip":…,"code":"ok"}` et `{"kind":"done","cancelled":false}`.
- `cancel_before_start_is_kept` / `new_run_cancels_the_previous`.
- `empty_selection_is_no_cameras`.

**Parallélisable :** oui, avec L4, S4 et S7. Dépend de L1.

**Réussite :** tests verts, clippy propre.

---

### Tâche L3 : Test de login, API front
**Objectif :** miroirs TS, appel par `Channel`, comptes, filtre et lignes CSV, en logique pure.

**Fichiers :** Create `src/lib/api/loginTest.ts`, `src/lib/api/loginTest.test.ts`.

**Tests d'abord** (`npx vitest run src/lib/api/loginTest.test.ts`) :
- `start_sends_cameras_account_and_iface_and_forwards_events` (`invoke` mocké comme dans `freeIps.test.ts`).
- `counts_by_code_and_hides_nothing_in_data`.
- `filter_by_codes_and_query_on_ip_mac_model` (réutilise `normalizeQuery` de `search.ts`).
- `csv_rows_follow_the_filtered_view_and_never_contain_a_password`.
- `cancel_calls_with_the_run_id`.

**Parallélisable :** oui, avec L1, S1, S2, S3, S6 et E1. Dépend de 0 (`csv.ts`).

**Réussite :** `npm test` vert.

---

### Tâche L4 : Test de login, écran
**Objectif :** 5e choix « Test de login » dans Opérations, avec résultat, filtre, export et Arrêter.

**Fichiers :**
- Create `src/lib/components/LoginTest.svelte`, `src/lib/i18n/{fr,en,es}/logintest.json`.
- Modify `src/lib/components/Operations.svelte`, `src/lib/i18n/{fr,en,es}/ops.json` (clé `kind.login_test` seule).

**Contenu :**
- Dans `Operations.svelte` : type local `Kind = OpKind | 'login_test'`, ajouté à `KINDS`. `api/ops.ts` n'est pas touché.
- Pour ce choix :
  - le formulaire ne montre que le compte ;
  - le pied montre « Tester » au lieu de « Aperçu » ;
  - les étapes 2 à 4 sont remplacées par `<LoginTest cams={targets} {accountId} {iface} bind:running={testing} />` ;
  - `choose()` et les cases sont bloqués pendant `testing`.
- `LoginTest.svelte` :
  - progression `n / total` et Arrêter ;
  - pastilles par résultat avec leur compte ;
  - champ de recherche ;
  - Exporter (`save` puis `saveReport`) ;
  - table Caméra / IP / MAC / Résultat.
- Libellés fr :
  - résultats : `OK`, `Refusé`, `Injoignable`, `Non activée`, `Marque non gérée`, `Autre appareil`, `Non essayée` ;
  - title de `held` : « Trop de refus récents ».
- Erreurs de commande : `configure.${errorKey(e)}`, comme Opérations.

**Tests d'abord :** la logique testable est en L3 (`loginTest.test.ts` appartient à L3, pas à cette tâche). Ici : parité i18n (test existant), `npm run check`.

**Vérification :** capture headless clair et sombre (HOU-DEV, écran virtuel) avec un faux résultat de 173 lignes. Rien ne déborde à 1200 px.

**Parallélisable :** oui, avec L2, S4 et S7. Dépend de L3.

**Réussite :** `npm test` vert. Les quatre opérations existantes sont inchangées (vérification manuelle d'un aperçu « Garder les IP »).

---

### Tâche E1 : Émulateur, verrouillage Hikvision
**Objectif :** pouvoir vérifier la garde sans matériel.

**Fichiers :** Modify `tools/fake-cameras/emulate.py`, `tools/fake-cameras/README.md`.

**Contenu :**
- Option `lock_after` / `lock_minutes` par caméra Hikvision : après N échecs Digest, renvoyer 401 avec `<lockStatus>lock</lockStatus><unlockTime>…</unlockTime>` dans le corps, même avec le bon mot de passe, pendant M minutes.
- Compteur d'échecs exposé dans la console.

**Tests :** `python3 -I tools/fake-cameras/emulate.py --selftest` (ajouter ce mode si absent) : 3 échecs puis un bon mot de passe donnent toujours 401 avec `lock_after=3`.

**Parallélisable :** oui, avec toutes les tâches (fichiers à lui seul). Dépend de rien.

**Réussite :** selftest vert, README à jour.

---

### Tâche S1 : Réseau du compte, appareils et type deviné (core)
**Objectif :** `SeenDevice`, `DeviceKind`, `guess_kind`, `is_nvr_model`, `merge_devices`.

**Fichiers :** Modify `crates/lenscout-core/src/site_survey/device.rs` (seul fichier touché).

**Tests d'abord** (`cargo test -p lenscout-core site_survey::device`) :
- `pc_and_gateway_win_over_everything`.
- `scanned_hikvision_nvr_model_is_nvr_and_camera_model_is_camera` : `DS-7608NI-K2` donne NVR, `DS-2CD2043G2-I` donne caméra, `LTN8708…` donne NVR.
- `camera_oui_without_scan_is_camera`.
- `printer_oui_is_printer`.
- `switch_oui_is_switch`.
- `netbios_reply_alone_is_pc`.
- `nothing_is_unknown`.
- `merge_keeps_first_seen_updates_last_seen_and_name`.
- `merge_by_mac_frees_old_ip`.
- `merge_without_mac_keys_by_ip`.
- `unknown_kind_never_overwrites_a_known_kind`.
- `serde_round_trip_snake_case`.

**Parallélisable :** oui, avec L1, L3, S2, S3, S6 et E1. Dépend de 0.

**Réussite :** tests verts, clippy propre.

---

### Tâche S2 : Réseau du compte, noms NetBIOS et mDNS (core)
**Objectif :** encoder et décoder les deux requêtes, et résoudre les noms d'un lot d'IP en un aller-retour borné.

**Fichiers :** Modify `crates/lenscout-core/src/site_survey/names.rs` (seul fichier touché).

**Tests d'abord** (`cargo test -p lenscout-core site_survey::names`), avec `FakeDatagram` :
- `nbstat_query_is_the_rfc1002_wildcard_node_status`.
- `parse_nbstat_takes_the_unique_workstation_name` (paquet capturé en constante).
- `parse_nbstat_truncated_or_hostile_is_none`.
- `mdns_reverse_query_asks_ptr_in_addr_arpa_without_qu`.
- `parse_mdns_reverse_matches_the_asked_ip_only`.
- `resolve_sends_one_packet_per_ip_per_protocol_and_stops_at_wait`.
- `resolve_prefers_netbios_then_mdns`.
- `reply_from_an_unasked_ip_is_ignored`.

**Parallélisable :** oui, avec L1, L3, S1, S3, S6 et E1. Dépend de 0.

**Réussite :** tests verts, clippy propre. Aucune panique sur un paquet aléatoire (test de 1 000 paquets aléatoires).

---

### Tâche S3 : Réseau du compte, balayage mis en commun (core)
**Objectif :** extraire de `free_ips::scan` le ping de masse et la lecture ARP (avec MAC), pour que `site_survey::sweep` les réutilise, sans changer le comportement des IP libres.

**Fichiers :** Modify `crates/lenscout-core/src/free_ips.rs`, `crates/lenscout-core/src/site_survey/sweep.rs`.

**Contenu :** `FreeProbe::neighbours` rend `HashMap<Ipv4Addr, String>`. On extrait `ping_all(...)`, utilisé par `scan` et par `sweep`. La règle « plus d'un tir sur dix non parti donne `PingUnavailable` » reste dans les deux.

**Tests d'abord :**
- `free_ips` : tous les tests existants restent verts sans modification de leurs assertions ; seuls les faux s'adaptent au nouveau type.
- `sweep` :
  - `sweep_lists_ping_replies_and_arp_only_hosts_with_their_mac` ;
  - `sweep_never_lists_silent_hosts_absent_from_arp` ;
  - `sweep_excludes_the_pc_address` ;
  - `sweep_is_capped_like_free_ips_and_says_truncated` ;
  - `sweep_cancelled` ;
  - `sweep_ping_unavailable`.

**Parallélisable :** oui, avec L1, L3, S1, S2, S6 et E1. Dépend de 0.

**Réussite :** `cargo test -p lenscout-core free_ips site_survey::sweep` verts, clippy propre.

---

### Tâche S4 : Réseau du compte, mémoire et occupation (core)
**Objectif :** inventaire par compte dans le carnet, `network_fill_with`, `suggest_network`.

**Fichiers :** Modify `crates/lenscout-core/src/accounts.rs` (seul fichier touché).

**Tests d'abord** (`cargo test -p lenscout-core accounts`) :
- `survey_is_saved_and_reloaded_with_its_date`.
- `old_file_without_devices_loads`.
- `bad_device_line_is_ignored_not_fatal`.
- `export_never_contains_devices`.
- `import_replace_keeps_local_devices`.
- `forget_device_by_mac_or_ip`.
- `fill_counts_devices_once`. Un appareil à l'IP d'une caméra connue, de la passerelle, du PC ou d'une exclue n'est pas recompté.
- `fill_device_segments_are_merged_runs`.
- `used_pct_counts_excluded_as_taken`.
- `crowded_at_80_percent`.
- `suggest_23_for_180_used_in_a_24` : donne `192.168.0.0/23`.
- `suggest_none_when_not_crowded_and_stops_at_16`.
- `network_fill_without_devices_is_unchanged`. Les tests existants de `network_fill`, `batch.rs` et `ops.rs` restent verts sans modification.

**Parallélisable :** oui, avec L2, L4 et S7. Dépend de S1.

**Réussite :** tests verts, clippy propre. `batch.rs` et `ops.rs` ne sont pas touchés.

---

### Tâche S5 : Réseau du compte, commandes Tauri
**Objectif :** `cmd_site_survey` / `cmd_site_survey_cancel`, `cmd_account_devices` / `cmd_account_forget_device`, appareils relevés dans `reserved_for`.

**Fichiers :** Modify `src-tauri/src/commands/site_survey.rs`, `src-tauri/src/commands/free_ips.rs`, `src-tauri/src/commands/accounts.rs`.

**Contenu :**
- `free_ips.rs` : extraire de `cmd_free_ips` un `pub(crate) async fn sweep_scope(interface, &JoinState) -> Result<(ScanInterface, Option<Ipv4Addr> /* passerelle */, bool /* routé */), String>`. `cmd_free_ips` l'utilise, sans changement de comportement.
- `site_survey.rs` :
  - même schéma d'état que `FreeIpsState` ;
  - garde « sur place » : réseau de `pc_ip` du compte = réseau de la portée, sinon `not_on_account_network` ;
  - enchaînement `sweep`, puis `resolve_names` (`open_ephemeral` ×2, attente 1,5 s), puis `guess_kind` avec les caméras du front et les caméras connues du compte, puis `record_survey`, puis `Done` ;
  - en mode routé : pas de MAC, donc pas d'OUI.
- `accounts.rs` : `reserved_for` ajoute les IP des appareils relevés (sauf `own`), plus les deux commandes d'appareils.

**Tests d'abord** (`cargo test -p lenscout site_survey free_ips accounts`) :
- `survey_refused_off_the_account_network`.
- `survey_events_serialize_as_the_front_reads_them`.
- `reserved_holds_surveyed_devices_but_not_own`.
- `free_ips_scope_unchanged`. Les tests existants de `commands/free_ips.rs` restent verts tels quels.
- `cancel_before_start_is_kept`.

**Parallélisable :** non, et par sa place elle ne court avec personne. Dépend de S1, S2, S3 et S4.

**Réussite :** tests verts, clippy propre.

---

### Tâche S6 : Réseau du compte, API front
**Objectif :** miroirs TS du relevé et des appareils, nouveaux champs de `NetworkFill`, filtre, CSV et garde « sur place » côté front.

**Fichiers :** Create `src/lib/api/siteNet.ts`, `src/lib/api/siteNet.test.ts` ; Modify `src/lib/api/accounts.ts`, `src/lib/api/accounts.test.ts`.

**Tests d'abord :**
- `start_survey_forwards_progress_and_done`.
- `filter_by_kinds_and_query_on_ip_mac_vendor_name`.
- `absent_when_last_seen_before_surveyed_at`.
- `csv_rows_follow_the_filtered_view`.
- `on_account_network_true_for_same_network_or_joined_account_false_otherwise`. Réutilise `activeAddress` et `joined` de `net.ts`.
- Dans `accounts.test.ts` : fixtures `NetworkFill` complétées ; `segmentBox` d'un segment `device`.

**Parallélisable :** oui, avec L1, L3, S1, S2, S3 et E1. Dépend de 0.

**Réussite :** `npm test` vert.

---

### Tâche S7 : Réseau du compte, écran
**Objectif :** relevé, occupation, alerte et suggestion dans la section « Le réseau de ce compte » de Comptes, plus une feuille Inventaire.

**Fichiers :**
- Create `src/lib/components/SiteSurvey.svelte` (bouton Relever, progression, date, lien vers la feuille), `src/lib/components/SiteDevices.svelte` (feuille `Dialog` : filtre par type, recherche, table IP / MAC / Constructeur / Type / Nom / Vu le / Oublier, Exporter), `src/lib/i18n/{fr,en,es}/sitenet.json`.
- Modify `src/lib/components/Accounts.svelte`, `src/lib/i18n/{fr,en,es}/accounts.json` (`net.devices`, `net.used`, `net.crowded`).

**Contenu de `Accounts.svelte` :**
- segment `k-device` (couleur `--text-2`, distincte des caméras) ;
- légende « Appareils N » ;
- ligne d'occupation « 71 % · 74 libres sur 254 » ;
- si `crowded` : « Passer en /23 (255.255.254.0) » ;
- monter `<SiteSurvey accountId={editing} iface={$scanIface} onDone={reloadFill} />` ;
- « Bientôt complet » est conservé.

**Libellés fr :**
- types : `Caméra`, `NVR`, `Switch`, `PC`, `Imprimante`, `Passerelle`, `Ce PC`, `Inconnu` ;
- `Relever`, `Relevé le {date}`, `{n} appareils`, `Absent au dernier relevé`, `Hors du réseau du compte` (bouton désactivé seulement).

**Tests d'abord :** la logique est en S6. Ici : parité i18n, `npm run check`.

**Vérification :** capture headless de Comptes avec un compte de 180 appareils, clair et sombre. Barre lisible, feuille défilante, rien ne déborde à 1200 px.

**Parallélisable :** oui, avec L2, L4 et S4. Dépend de S6.

**Réussite :** `npm test` vert. Les caméras connues, Oublier, Agrandir et Exporter/Importer des comptes marchent comme avant.

---

### Tâche W : Branchement final
**Objectif :** enregistrer états et commandes, et brancher les codes d'erreur sur la vérification automatique fr/en/es.

**Fichiers :** Modify `src-tauri/src/lib.rs`, `src/lib/api/errors.ts`, `src/lib/i18n/codes.test.ts`, `src/lib/i18n/{fr,en,es}/free.json`, `src/lib/i18n/{fr,en,es}/configure.json`.

**Contenu :**
- `lib.rs` :
  - `.manage(LoginTestState::default())`, `.manage(SiteSurveyState::default())` ;
  - enregistrer `cmd_login_test`, `cmd_login_test_cancel`, `cmd_site_survey`, `cmd_site_survey_cancel`, `cmd_account_devices`, `cmd_account_forget_device`.
- `errors.ts` : ajouter `not_on_account_network` à `CODES`.
- `codes.test.ts` :
  - `configure` += `commands/login_test.rs` et `commands/report.rs` ;
  - `free` += `commands/site_survey.rs` et `commands/report.rs` ;
  - `accounts` += `commands/report.rs` si son code y est affiché.
- `free.json` et `configure.json` : les clés `error.*` que le test réclame (`not_on_account_network`, `file_unwritable`, et ce qui manque).

**Tests :** `codes.test.ts` (étendu), `npm test`, `cargo test -p lenscout`, clippy.

**Parallélisable :** oui avec D seulement. Dépend de L2, L4, S5 et S7.

**Réussite :** `npm run tauri dev` démarre, les deux écrans appellent leurs commandes sans erreur « command not found ».

---

### Tâche D : Documentation
**Objectif :** CHANGELOG (section « Unreleased », EN/FR) et une ligne par fonction dans les README.

**Fichiers :** Modify `CHANGELOG.md`, `README.md`, `README.fr.md`, `README.es.md`.

**Tests :** aucun (texte). Notes de version courtes.

**Parallélisable :** oui avec W. Elle peut aussi partir dès la tâche 0 : ses fichiers ne sont à personne d'autre.

**Réussite :** relu, aucun nom d'autre produit.

---

### Tâche V : Vérification de bout en bout (aucun fichier source)
**Objectif :** prouver les deux fonctions sur l'émulateur avant de livrer.

**Fichiers :** captures dans `.superpowers/sdd/2026-11-16-login-reseau/` seulement.

**Étapes :**
1. Lancer `tools/fake-cameras` (avec `lock_after=3` sur la fausse Hikvision), puis `npm run tauri dev`.
2. Scan, puis Test de login sur tout le parc, une fois avec le bon compte et une fois avec un mauvais. Relancer : les caméras refusées deux fois sortent `Non essayée`, et l'émulateur ne s'est jamais verrouillé.
3. Arrêter en cours de passage.
4. Export CSV ouvert dans un tableur.
5. Relever sur le réseau de l'émulateur : appareils listés avec MAC et OUI, occupation, suggestion en forçant des exclusions au-delà de 80 %, Oublier, redémarrage de l'app (l'inventaire et sa date sont relus).

**Dépend de :** W.

**Réussite :** toutes les étapes observées, captures déposées. Rapport des écarts.

---

## Croisement des fichiers (vérifié deux à deux)

| Vague | Tâches en parallèle | Fichiers (aucun commun dans la vague) |
|---|---|---|
| 1 | 0 | `core/lib.rs`, `core/login_test.rs`, `core/site_survey/*`, `commands/mod.rs`, `commands/{login_test,site_survey,report}.rs`, `src-tauri/lib.rs`, `src/lib/csv*.ts`, `api/report.ts` |
| 2 | L1 · L3 · S1 · S2 · S3 · S6 · E1 (· D) | L1 `core/login_test.rs` · L3 `api/loginTest*.ts` · S1 `site_survey/device.rs` · S2 `site_survey/names.rs` · S3 `core/free_ips.rs` + `site_survey/sweep.rs` · S6 `api/siteNet*.ts` + `api/accounts*.ts` · E1 `tools/fake-cameras/*` · D `CHANGELOG.md` + `README*.md` |
| 3 | L2 · L4 · S4 · S7 | L2 `commands/login_test.rs` · L4 `LoginTest.svelte` + `Operations.svelte` + `i18n/*/logintest.json` + `i18n/*/ops.json` · S4 `core/accounts.rs` · S7 `SiteSurvey.svelte` + `SiteDevices.svelte` + `Accounts.svelte` + `i18n/*/sitenet.json` + `i18n/*/accounts.json` |
| 4 | S5 | `commands/site_survey.rs`, `commands/free_ips.rs`, `commands/accounts.rs` |
| 5 | W · D (si pas déjà faite) | W `src-tauri/lib.rs` + `api/errors.ts` + `i18n/codes.test.ts` + `i18n/*/free.json` + `i18n/*/configure.json` · D `CHANGELOG.md` + `README*.md` |
| 6 | V | captures seulement |

- `src-tauri/src/lib.rs` est touché par 0 puis par W, en séquence.
- `core/site_survey/mod.rs` et `core/lib.rs` le sont par 0 seulement.
- Vague 2 : L1, S1, S2 et S3 sont Rust, à lancer **deux par deux** (limite machine). L3, S6, E1 et D tournent librement.

## Questions pour Benjamin (le minimum)

Aucune n'est bloquante : le plan applique la réponse par défaut entre parenthèses. Une réponse contraire ne change qu'une tâche.

1. **Appareils absents au dernier relevé** : faut-il les compter comme occupés et les écarter des IP proposées jusqu'à « Oublier » ? (Défaut : oui, comme une caméra connue éteinte. Changerait S4 et S5.)
2. **Inventaire dans l'export des comptes** : faut-il l'emporter vers un autre PC ? (Défaut : non. On le relève en quelques secondes sur place, et le format d'export ne bouge pas. Changerait S4.)

## Risques

- **Verrouillage Hikvision :** le refus d'une caméra déjà verrouillée (par un passage antérieur ou un autre écran de LenScout depuis ce PC) sort `Refusé`, pas `Verrouillée`. `http_client::execute` jette le corps du second 401, où Hikvision indique `lockStatus`. Le lire demanderait une variante `NetError` de plus, à reporter dans tous les `match` : écarté ici, la garde à 2 refus en limite la cause.
- **Seuils de la garde et liste des modèles de NVR :** écrits d'après la documentation publique, // À VÉRIFIER sur le chantier (LTS en particulier : `is_lts` de `sadp.rs` est déjà marqué non vérifié).
- **Compte Axis non administrateur :** il sort `Refusé` alors qu'il s'authentifie. Voulu (LenScout a besoin de l'administration), mais peut surprendre.
- **NetBIOS filtré par le pare-feu Windows** (profil public) et **mDNS absent** sur certains appareils : le nom manque, le type tombe sur l'OUI, voire `Inconnu`.
- **Hôtes qui ne répondent ni au ping ni à l'ARP pendant le relevé** (éteints, en veille, ports isolés) : absents de l'inventaire, donc occupation sous-estimée. Un second relevé ou les exclusions comblent l'écart.
- **Appareils oubliés trop tard** : une liste qui grossit d'appareils DHCP de passage gonfle l'occupation. « Absent au dernier relevé » et Oublier y répondent.
- **Sous-réseau au-delà de /22 :** le relevé est borné à 1 024 adresses autour du poste (comme les IP libres) et le dit (`truncated`), mais l'occupation porte sur tout le réseau.
- **Taille d'`accounts.json` :** environ 150 o par appareil, soit 40 Ko pour 254 appareils. Écriture atomique inchangée, mais à chaque relevé.
- **Concurrence de 16 caméras :** sans effet de verrouillage, mais sur un switch PoE d'entrée de gamme les 16 premières connexions TLS ou HTTP simultanées peuvent dépasser 3 s. Le délai est en constante, à ajuster sur le chantier.
