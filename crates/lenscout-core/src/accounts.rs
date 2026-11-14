use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::seal;
use crate::secret::Secret;
use crate::transport::Credentials;

/// Métadonnées d'un compte. Le mot de passe n'y figure pas : il vit dans le
/// carnet, scellé dans le fichier (voir `seal`).
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub login: String,
    /// Champs réseau facultatifs, en clair (absents des anciens fichiers).
    #[serde(flatten)]
    pub net: AccountNetwork,
}

/// Réseau du site d'un compte, tout facultatif et en clair : `pc_ip` = IPv4 +
/// préfixe que prend le poste (`192.168.1.250/24`), `network` = CIDR
/// (`192.168.1.0/24`), `gateway` = IPv4. Normalisé par `validated`.
/// `network` ne se saisit plus : il se déduit de `pc_ip` (gardé dans le
/// fichier et l'export pour les versions précédentes, qui le lisent).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct AccountNetwork {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pc_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

/// `a.b.c.d/n` → adresse et préfixe (1 à 32).
fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, prefix) = s.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    ((1..=32).contains(&prefix)).then_some(())?;
    Some((ip.parse().ok()?, prefix))
}

fn mask_bits(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { !0u32 << (32 - u32::from(prefix)) }
}

/// Réseau `a.b.c.0/n` d'une IP du PC `a.b.c.d/n` lisible.
fn network_of(pc_ip: &str) -> Option<String> {
    let (ip, prefix) = parse_cidr(pc_ip.trim())?;
    Some(format!("{}/{prefix}", Ipv4Addr::from(u32::from(ip) & mask_bits(prefix))))
}

/// Adresse d'hôte du réseau : ni l'adresse de réseau ni la diffusion (sauf
/// /31 et /32, qui n'en ont pas).
fn is_host(ip: Ipv4Addr, prefix: u8) -> bool {
    let (ip, mask) = (u32::from(ip), mask_bits(prefix));
    prefix >= 31 || (ip & !mask != 0 && ip | mask != u32::MAX)
}

/// Adresse d'un appareil : ni 0.x, ni boucle locale, ni multicast, ni
/// réservée (240/4, diffusion comprise).
fn unicast(ip: Ipv4Addr) -> bool {
    let first = ip.octets()[0];
    first != 0 && !ip.is_loopback() && first < 224
}

/// Réseau `(adresse de réseau, préfixe)` contenant-il `ip` ?
fn contains(net: (Ipv4Addr, u8), ip: Ipv4Addr) -> bool {
    let mask = mask_bits(net.1);
    u32::from(ip) & mask == u32::from(net.0) & mask
}

impl AccountNetwork {
    /// Champs vides retirés, espaces ôtés, `network` recalculé depuis `pc_ip`
    /// (celui reçu est ignoré : anciens fichiers, ancien formulaire).
    /// `gateway` doit appartenir au réseau de `pc_ip`.
    pub fn validated(&self) -> Result<AccountNetwork, AccountError> {
        let clean = |f: &Option<String>| {
            f.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let (pc_ip, gateway) = (clean(&self.pc_ip), clean(&self.gateway));
        let pc = match &pc_ip {
            None => None,
            // Jamais de /24 ajouté d'office : le masque se saisit.
            Some(s) if !s.contains('/') => return Err(AccountError::MaskMissing),
            Some(s) => {
                let (ip, prefix) = parse_cidr(s).ok_or(AccountError::InvalidPcIp)?;
                // /8 à /30 : un réseau de site, avec de la place pour les caméras.
                if !(8..=30).contains(&prefix) || !unicast(ip) || !is_host(ip, prefix) {
                    return Err(AccountError::InvalidPcIp);
                }
                Some((ip, prefix))
            }
        };
        if let Some(g) = &gateway {
            let g: Ipv4Addr = g.parse().map_err(|_| AccountError::InvalidGateway)?;
            if !unicast(g) || pc.is_some_and(|(ip, _)| ip == g) {
                return Err(AccountError::InvalidGateway);
            }
            if let Some(scope) = pc {
                if !contains(scope, g) {
                    return Err(AccountError::GatewayOutsideNetwork);
                }
                if !is_host(g, scope.1) {
                    return Err(AccountError::InvalidGateway);
                }
            }
        }
        Ok(AccountNetwork {
            network: pc_ip.as_deref().and_then(network_of),
            pc_ip,
            gateway,
        })
    }

    fn fields(&self) -> [&Option<String>; 3] {
        [&self.pc_ip, &self.network, &self.gateway]
    }

    /// Un champ présent dans `imported` diffère-t-il ? Un champ absent du
    /// fichier ne compte pas : il ne vide jamais celui du carnet.
    fn differs_from(&self, imported: &AccountNetwork) -> bool {
        self.fields()
            .into_iter()
            .zip(imported.fields())
            .any(|(mine, theirs)| theirs.is_some() && theirs != mine)
    }

    /// Les champs présents dans `imported` remplacent les miens, les autres
    /// restent — sauf si le mélange ne passe plus `validated` (anciens réseau
    /// ou passerelle hors de la nouvelle IP) : alors le réseau du fichier
    /// seul, champs absents vides. Le résultat est toujours valide.
    fn merge(&mut self, imported: AccountNetwork) {
        let mut merged = self.clone();
        for (mine, theirs) in [
            (&mut merged.pc_ip, &imported.pc_ip),
            (&mut merged.network, &imported.network),
            (&mut merged.gateway, &imported.gateway),
        ] {
            if theirs.is_some() {
                *mine = theirs.clone();
            }
        }
        *self = merged.validated().unwrap_or(imported);
    }

    /// Lecture du carnet : un champ qui n'est pas une chaîne est ignoré
    /// (jamais un carnet perdu pour un champ facultatif) ; le réseau est
    /// recalculé depuis l'IP du PC.
    fn read_lenient(a: &serde_json::Value) -> AccountNetwork {
        let field = |key: &str| a.get(key).and_then(|v| v.as_str()).map(str::to_string);
        let pc_ip = field("pc_ip");
        AccountNetwork {
            network: pc_ip.as_deref().and_then(network_of),
            pc_ip,
            gateway: field("gateway"),
        }
    }

    /// Champs présents ajoutés à un objet JSON (fichier, export).
    fn write_into(&self, a: &mut serde_json::Value) {
        for (key, value) in [("pc_ip", &self.pc_ip), ("network", &self.network), ("gateway", &self.gateway)] {
            if let Some(v) = value {
                a[key] = v.clone().into();
            }
        }
    }

    /// Champs lus dans un objet JSON ; un champ présent qui n'est pas une
    /// chaîne → `None` (rendu `Err` par l'appelant).
    fn read_from(a: &serde_json::Value) -> Option<AccountNetwork> {
        let field = |key: &str| match a.get(key) {
            None | Some(serde_json::Value::Null) => Some(None),
            Some(v) => v.as_str().map(|s| Some(s.to_string())),
        };
        Some(AccountNetwork {
            pc_ip: field("pc_ip")?,
            network: field("network")?,
            gateway: field("gateway")?,
        })
    }
}

// L'identifiant est scellé dans le fichier : il n'apparaît pas non plus dans les journaux.
impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("login", &"***")
            .field("net", &self.net)
            .finish()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AccountError {
    #[error("compte introuvable")]
    NotFound,
    // Le compte existe mais n'a pas de mot de passe (reprise d'un trousseau
    // inaccessible) : à ressaisir.
    #[error("mot de passe absent")]
    SecretMissing,
    #[error("nom déjà utilisé")]
    DuplicateName,
    #[error("champ vide")]
    EmptyField,
    // Message de l'OS, jamais le mot de passe.
    #[error("trousseau : {0}")]
    Keyring(String),
    #[error("fichier : {0}")]
    Io(String),
    // Fichier d'import illisible, tronqué ou d'un autre logiciel.
    #[error("fichier d'import invalide")]
    ImportInvalid,
    #[error("IP du PC invalide")]
    InvalidPcIp,
    // IP du PC sans `/préfixe` : rien n'est supposé à la place de l'utilisateur.
    #[error("masque manquant")]
    MaskMissing,
    #[error("passerelle invalide")]
    InvalidGateway,
    #[error("passerelle hors du réseau")]
    GatewayOutsideNetwork,
}

/// Ancien trousseau : ne sert plus qu'à la reprise des comptes du format 1.
pub trait SecretStore: Send + Sync {
    fn set(&self, id: &str, password: &Secret) -> Result<(), AccountError>;
    fn get(&self, id: &str) -> Result<Secret, AccountError>;
    fn delete(&self, id: &str) -> Result<(), AccountError>;
}

/// Trousseau du système : Keychain (macOS), Credential Manager (Windows),
/// Secret Service (Linux).
pub struct KeyringStore;

const SERVICE: &str = "io.lenscout.app";

impl KeyringStore {
    fn entry(id: &str) -> Result<keyring::Entry, AccountError> {
        keyring::Entry::new(SERVICE, id).map_err(keyring_error)
    }
}

fn keyring_error(e: keyring::Error) -> AccountError {
    match e {
        keyring::Error::NoEntry => AccountError::NotFound,
        other => AccountError::Keyring(other.to_string()),
    }
}

impl SecretStore for KeyringStore {
    fn set(&self, id: &str, password: &Secret) -> Result<(), AccountError> {
        Self::entry(id)?
            .set_password(password.expose())
            .map_err(keyring_error)
    }

    fn get(&self, id: &str) -> Result<Secret, AccountError> {
        Self::entry(id)?
            .get_password()
            .map(Secret::new)
            .map_err(keyring_error)
    }

    fn delete(&self, id: &str) -> Result<(), AccountError> {
        Self::entry(id)?.delete_credential().map_err(keyring_error)
    }
}

/// Trousseau en mémoire, pour les tests.
#[derive(Default)]
pub struct MemoryStore {
    secrets: Mutex<HashMap<String, Secret>>,
}

impl SecretStore for MemoryStore {
    fn set(&self, id: &str, password: &Secret) -> Result<(), AccountError> {
        self.secrets
            .lock()
            .unwrap()
            .insert(id.to_string(), password.clone());
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Secret, AccountError> {
        self.secrets
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(AccountError::NotFound)
    }

    fn delete(&self, id: &str) -> Result<(), AccountError> {
        self.secrets
            .lock()
            .unwrap()
            .remove(id)
            .map(|_| ())
            .ok_or(AccountError::NotFound)
    }
}

#[derive(Clone)]
struct Entry {
    account: Account,
    // Absent : compte à ressaisir (« Mot de passe à ressaisir »).
    password: Option<Secret>,
    // Repris de l'ancien format sans son secret : on le redemande au trousseau
    // à chaque lancement tant que le compte n'a pas de mot de passe.
    legacy: bool,
}

pub struct AccountBook {
    path: PathBuf,
    entries: Vec<Entry>,
    // Ancien trousseau : repris au chargement, vidé du compte à la suppression.
    store: Arc<dyn SecretStore>,
    // Carnet en mémoire seule : toute écriture échoue (voir `load_or_quarantine`).
    read_only: bool,
}

/// Issue du chargement au démarrage.
#[derive(Debug)]
pub enum Startup {
    Clean,
    /// Fichier illisible renommé ; chemin du fichier mis de côté.
    Quarantined(PathBuf),
    /// Fichier illisible et renommage impossible : carnet vide, sans écriture.
    Unwritable,
}

/// Un `accounts.json` illisible ne doit ni bloquer le démarrage ni être
/// écrasé : on le renomme (jamais supprimé) et on repart d'un carnet vide.
/// Si même le renommage échoue, le carnet reste en mémoire seule.
pub fn load_or_quarantine(path: PathBuf, store: Arc<dyn SecretStore>) -> (AccountBook, Startup) {
    if let Ok(book) = AccountBook::load(path.clone(), store.clone()) {
        return (book, Startup::Clean);
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".corrupt-{stamp}"));
    let moved = path.with_file_name(name);
    let mut book = AccountBook {
        path: path.clone(),
        entries: Vec::new(),
        store,
        read_only: false,
    };
    if std::fs::rename(&path, &moved).is_ok() {
        (book, Startup::Quarantined(moved))
    } else {
        book.read_only = true;
        (book, Startup::Unwritable)
    }
}

impl fmt::Debug for AccountBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountBook")
            .field("path", &self.path)
            .field("accounts", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Résultat d'un import, par compte du fichier.
#[derive(Debug, Clone, PartialEq)]
pub enum ImportKind {
    New,
    Identical,
    Differs {
        login_differs: bool,
        password_differs: bool,
        network_differs: bool,
    },
}

/// Aucun secret ici : le plan part tel quel vers l'écran.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportItem {
    pub name: String,
    pub kind: ImportKind,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImportPlan {
    pub items: Vec<ImportItem>,
}

/// Choix pour un nom déjà présent qui diffère.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Choice {
    Replace,
    KeepBoth,
    Skip,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImportSummary {
    pub added: usize,
    pub identical: usize,
    pub replaced: usize,
    pub kept_both: usize,
    pub skipped: usize,
}

// Compte lu dans un fichier d'import, secrets déjà ouverts.
struct Imported {
    name: String,
    login: String,
    password: Option<Secret>,
    net: AccountNetwork,
}

/// Écriture atomique d'un fichier lisible par l'utilisateur seul (0600 sous
/// Unix) : temporaire voisin (`<chemin>.tmp`, recréé), puis `rename`. Le
/// temporaire ne reste pas derrière un échec.
pub fn write_file_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let result = write_private(&tmp, data).and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Crée le fichier lisible par l'utilisateur seul (0600) sous Unix.
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(data)
}

const EXPORT_FORMAT: &str = "lenscout-accounts";

fn open_text(sealed: &str) -> Option<String> {
    String::from_utf8(seal::open(sealed).ok()?).ok()
}

fn parse_import(data: &str) -> Result<Vec<Imported>, AccountError> {
    let invalid = || AccountError::ImportInvalid;
    let v: serde_json::Value = serde_json::from_str(data).map_err(|_| invalid())?;
    if v["format"] != EXPORT_FORMAT || v["version"] != 1 {
        return Err(invalid());
    }
    let mut out = Vec::new();
    for a in v["accounts"].as_array().ok_or_else(invalid)? {
        let name = a["name"].as_str().ok_or_else(invalid)?.trim().to_string();
        let login = open_text(a["login"].as_str().ok_or_else(invalid)?).ok_or_else(invalid)?;
        let password = match a.get("password") {
            None | Some(serde_json::Value::Null) => None,
            Some(p) => Some(Secret::new(
                open_text(p.as_str().ok_or_else(invalid)?).ok_or_else(invalid)?,
            )),
        };
        if name.is_empty() || login.is_empty() {
            return Err(invalid());
        }
        let net = AccountNetwork::read_from(a)
            .ok_or_else(invalid)?
            .validated()
            .map_err(|_| invalid())?;
        if out
            .iter()
            .any(|o: &Imported| o.name.to_lowercase() == name.to_lowercase())
        {
            return Err(invalid());
        }
        out.push(Imported {
            name,
            login,
            password: password.filter(|p| !p.expose().is_empty()),
            net,
        });
    }
    Ok(out)
}

fn classify(existing: &Entry, imported: &Imported) -> ImportKind {
    let login_differs = existing.account.login != imported.login;
    // Un import sans mot de passe n'efface jamais celui du carnet.
    let password_differs = imported
        .password
        .as_ref()
        .is_some_and(|p| Some(p.expose()) != existing.password.as_ref().map(Secret::expose));
    // De même, un import sans champs réseau ne vide pas ceux du carnet.
    let network_differs = existing.account.net.differs_from(&imported.net);
    if login_differs || password_differs || network_differs {
        ImportKind::Differs {
            login_differs,
            password_differs,
            network_differs,
        }
    } else {
        ImportKind::Identical
    }
}

fn position_of(entries: &[Entry], name: &str) -> Option<usize> {
    let wanted = name.to_lowercase();
    entries
        .iter()
        .position(|e| e.account.name.to_lowercase() == wanted)
}

impl AccountBook {
    /// Lit le fichier : format 2 (scellé) ou ancien format (tableau, login en
    /// clair, secret au trousseau), repris puis réécrit en format 2. Les
    /// entrées du trousseau ne sont jamais supprimées. Si un secret manque
    /// (trousseau inaccessible, entrée perdue), le compte reste listé « à
    /// ressaisir » et le fichier d'origine n'est pas réécrit : la reprise sera
    /// retentée au prochain lancement.
    pub fn load(path: PathBuf, store: Arc<dyn SecretStore>) -> Result<Self, AccountError> {
        let io = |e: String| AccountError::Io(e);
        let mut book = AccountBook {
            path,
            entries: Vec::new(),
            store,
            read_only: false,
        };
        let raw = match std::fs::read(&book.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(book),
            Err(e) => return Err(io(e.to_string())),
        };
        // Messages fixes : un message de serde peut citer le contenu du fichier.
        let v: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|_| io("JSON illisible".into()))?;
        if v.is_array() {
            let legacy: Vec<Account> =
                serde_json::from_value(v).map_err(|_| io("ancien format illisible".into()))?;
            let mut complete = true;
            for account in legacy {
                let password = book
                    .store
                    .get(&account.id)
                    .ok()
                    .filter(|p| !p.expose().is_empty());
                complete &= password.is_some();
                book.entries.push(Entry {
                    legacy: password.is_none(),
                    account,
                    password,
                });
            }
            if complete {
                // Réécriture ratée (dossier en lecture seule) : on garde le carnet en mémoire.
                let _ = book.write(&book.entries);
            }
            return Ok(book);
        }
        if v["version"] != 2 {
            return Err(io("version de fichier inconnue".into()));
        }
        let mut recovered = false;
        for a in v["accounts"]
            .as_array()
            .ok_or_else(|| io("comptes absents".into()))?
        {
            let text = |key: &str| {
                a[key]
                    .as_str()
                    .and_then(open_text)
                    .ok_or_else(|| io(format!("{key} illisible")))
            };
            let field = |key: &str| {
                a[key]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| io(format!("{key} absent")))
            };
            let mut entry = Entry {
                account: Account {
                    id: field("id")?,
                    name: field("name")?,
                    login: text("login")?,
                    net: AccountNetwork::read_lenient(a),
                },
                password: Some(Secret::new(text("password")?)).filter(|p| !p.expose().is_empty()),
                legacy: a["legacy"] == true,
            };
            // Compte repris sans secret : le trousseau a peut-être répondu depuis.
            let again = (entry.legacy && entry.password.is_none())
                .then(|| book.store.get(&entry.account.id).ok())
                .flatten()
                .filter(|p| !p.expose().is_empty());
            if let Some(p) = again {
                entry.password = Some(p);
                entry.legacy = false;
                recovered = true;
            }
            book.entries.push(entry);
        }
        if recovered {
            let _ = book.write(&book.entries);
        }
        Ok(book)
    }

    /// Vrai si le compte a un mot de passe ; faux : à ressaisir.
    pub fn has_secret(&self, id: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.account.id == id && e.password.is_some())
    }

    pub fn list(&self) -> Vec<Account> {
        self.entries.iter().map(|e| e.account.clone()).collect()
    }

    pub fn create(
        &mut self,
        name: &str,
        login: &str,
        password: Secret,
        net: AccountNetwork,
    ) -> Result<Account, AccountError> {
        let (name, login) = (name.trim(), login.trim());
        if name.is_empty() || login.is_empty() || password.expose().is_empty() {
            return Err(AccountError::EmptyField);
        }
        if self.name_taken(name, None) {
            return Err(AccountError::DuplicateName);
        }
        let net = net.validated()?;
        let account = Account {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            login: login.to_string(),
            net,
        };
        let mut next = self.entries.clone();
        next.push(Entry {
            account: account.clone(),
            password: Some(password),
            legacy: false,
        });
        self.write(&next)?;
        self.entries = next;
        Ok(account)
    }

    pub fn update(
        &mut self,
        id: &str,
        name: &str,
        login: &str,
        password: Option<Secret>,
        net: AccountNetwork,
    ) -> Result<Account, AccountError> {
        let (name, login) = (name.trim(), login.trim());
        let index = self.index_of(id)?;
        if name.is_empty() || login.is_empty() {
            return Err(AccountError::EmptyField);
        }
        if password.as_ref().is_some_and(|p| p.expose().is_empty()) {
            return Err(AccountError::EmptyField);
        }
        if self.name_taken(name, Some(id)) {
            return Err(AccountError::DuplicateName);
        }
        // Compte sans mot de passe : l'enregistrer sans en fournir un laisserait
        // croire qu'il est réparé.
        if password.is_none() && self.entries[index].password.is_none() {
            return Err(AccountError::SecretMissing);
        }
        let net = net.validated()?;
        let account = Account {
            id: id.to_string(),
            name: name.to_string(),
            login: login.to_string(),
            net,
        };
        let mut next = self.entries.clone();
        next[index].account = account.clone();
        if password.is_some() {
            next[index].password = password;
            next[index].legacy = false;
        }
        self.write(&next)?;
        self.entries = next;
        Ok(account)
    }

    pub fn remove(&mut self, id: &str) -> Result<(), AccountError> {
        let index = self.index_of(id)?;
        let mut next = self.entries.clone();
        next.remove(index);
        self.write(&next)?;
        self.entries = next;
        // Suppression voulue : l'ancien trousseau est nettoyé aussi (la
        // reprise, elle, ne supprime rien). Échec sans conséquence.
        let _ = self.store.delete(id);
        Ok(())
    }

    pub fn credentials(&self, id: &str) -> Result<Credentials, AccountError> {
        let entry = &self.entries[self.index_of(id)?];
        Ok(Credentials {
            login: entry.account.login.clone(),
            password: entry.password.clone().ok_or(AccountError::SecretMissing)?,
        })
    }

    /// Mot de passe d'un compte, pour la fiche Modifier qui le montre à la
    /// demande. `None` : compte à ressaisir.
    pub fn password(&self, id: &str) -> Result<Option<Secret>, AccountError> {
        Ok(self.entries[self.index_of(id)?].password.clone())
    }

    /// Fichier d'export : sans ids, identifiant et mot de passe scellés, sans
    /// `password` pour un compte à ressaisir.
    pub fn export(&self) -> String {
        let accounts: Vec<_> = self
            .entries
            .iter()
            .map(|e| {
                let mut a = serde_json::json!({
                    "name": e.account.name,
                    "login": seal::seal(e.account.login.as_bytes()),
                });
                if let Some(p) = &e.password {
                    a["password"] = seal::seal(p.expose().as_bytes()).into();
                }
                e.account.net.write_into(&mut a);
                a
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "format": EXPORT_FORMAT,
            "version": 1,
            "accounts": accounts,
        }))
        .expect("json")
    }

    /// Premier temps : ce que l'import ferait, sans rien modifier.
    pub fn import_plan(&self, data: &str) -> Result<ImportPlan, AccountError> {
        let items = parse_import(data)?
            .into_iter()
            .map(|imp| ImportItem {
                kind: match position_of(&self.entries, &imp.name) {
                    None => ImportKind::New,
                    Some(i) => classify(&self.entries[i], &imp),
                },
                name: imp.name,
            })
            .collect();
        Ok(ImportPlan { items })
    }

    /// Second temps : le fichier est relu et le plan recalculé. `choices` est
    /// indexé par nom du fichier ; absent ⇒ `Replace`. Tout ou rien : un
    /// échec d'écriture laisse le carnet intact.
    pub fn import_apply(
        &mut self,
        data: &str,
        choices: &HashMap<String, Choice>,
    ) -> Result<ImportSummary, AccountError> {
        let imports = parse_import(data)?;
        let mut next = self.entries.clone();
        let mut summary = ImportSummary::default();
        // Noms que « Garder les deux » ne doit pas prendre : tous ceux du fichier.
        let mut reserved: Vec<String> = imports.iter().map(|i| i.name.to_lowercase()).collect();
        for imp in imports {
            let fresh = |name: String, imp: Imported| Entry {
                account: Account {
                    id: uuid::Uuid::new_v4().to_string(),
                    name,
                    login: imp.login,
                    net: imp.net,
                },
                password: imp.password,
                legacy: false,
            };
            let Some(i) = position_of(&next, &imp.name) else {
                next.push(fresh(imp.name.clone(), imp));
                summary.added += 1;
                continue;
            };
            if classify(&next[i], &imp) == ImportKind::Identical {
                summary.identical += 1;
                continue;
            }
            match choices.get(&imp.name).copied().unwrap_or(Choice::Replace) {
                Choice::Replace => {
                    // Un autre identifiant : le secret du trousseau n'est plus le sien.
                    if next[i].account.login != imp.login {
                        next[i].legacy = false;
                    }
                    next[i].account.name = imp.name;
                    next[i].account.login = imp.login;
                    next[i].account.net.merge(imp.net);
                    if imp.password.is_some() {
                        next[i].password = imp.password;
                        next[i].legacy = false;
                    }
                    summary.replaced += 1;
                }
                Choice::KeepBoth => {
                    let name = (2..)
                        .map(|n| format!("{} {n}", imp.name))
                        .find(|candidate| {
                            position_of(&next, candidate).is_none()
                                && !reserved.contains(&candidate.to_lowercase())
                        })
                        .expect("suffixe libre");
                    reserved.push(name.to_lowercase());
                    next.push(fresh(name, imp));
                    summary.kept_both += 1;
                }
                Choice::Skip => summary.skipped += 1,
            }
        }
        if summary.added + summary.replaced + summary.kept_both > 0 {
            self.write(&next)?;
            self.entries = next;
        }
        Ok(summary)
    }

    fn index_of(&self, id: &str) -> Result<usize, AccountError> {
        self.entries
            .iter()
            .position(|e| e.account.id == id)
            .ok_or(AccountError::NotFound)
    }

    fn name_taken(&self, name: &str, except: Option<&str>) -> bool {
        let wanted = name.to_lowercase();
        self.entries.iter().any(|e| {
            Some(e.account.id.as_str()) != except && e.account.name.to_lowercase() == wanted
        })
    }

    /// Écriture atomique : fichier temporaire voisin puis `rename`. Format 2 :
    /// identifiant et mot de passe scellés (un compte à ressaisir porte un
    /// mot de passe scellé vide).
    fn write(&self, entries: &[Entry]) -> Result<(), AccountError> {
        let io = |e: std::io::Error| AccountError::Io(e.to_string());
        if self.read_only {
            return Err(AccountError::Io("lecture seule".into()));
        }
        let accounts: Vec<_> = entries
            .iter()
            .map(|e| {
                let mut a = serde_json::json!({
                    "id": e.account.id,
                    "name": e.account.name,
                    "login": seal::seal(e.account.login.as_bytes()),
                    "password": seal::seal(e.password.as_ref().map_or("", Secret::expose).as_bytes()),
                });
                if e.legacy && e.password.is_none() {
                    a["legacy"] = true.into();
                }
                e.account.net.write_into(&mut a);
                a
            })
            .collect();
        let json = serde_json::to_vec_pretty(&serde_json::json!({
            "version": 2,
            "accounts": accounts,
        }))
        .map_err(|e| AccountError::Io(e.to_string()))?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        // Un vieux temporaire plus ouvert garderait son mode : on repart de zéro.
        let _ = std::fs::remove_file(&tmp);
        write_private(&tmp, &json).map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            io(e)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PWD: &str = "S3cr3t-Unique!";

    struct Fixture {
        dir: PathBuf,
        store: Arc<MemoryStore>,
    }

    // Le dossier temporaire part avec la fixture, même si le test échoue.
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Fixture {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("lenscout-accounts-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Fixture {
                dir,
                store: Arc::new(MemoryStore::default()),
            }
        }
        fn path(&self) -> PathBuf {
            self.dir.join("accounts.json")
        }
        fn book(&self) -> AccountBook {
            AccountBook::load(self.path(), self.store.clone()).unwrap()
        }
        fn raw(&self) -> String {
            String::from_utf8(std::fs::read(self.path()).unwrap()).unwrap()
        }
        /// Fichier de l'ancien format : tableau sans `version`, login en clair.
        fn write_v1(&self, accounts: &[(&str, &str, &str)]) {
            let list: Vec<_> = accounts
                .iter()
                .map(
                    |(id, name, login)| serde_json::json!({"id": id, "name": name, "login": login}),
                )
                .collect();
            std::fs::write(self.path(), serde_json::to_vec(&list).unwrap()).unwrap();
        }
    }

    fn pwd(p: &str) -> Secret {
        Secret::new(p.into())
    }

    fn empty_book() -> (AccountBook, Fixture) {
        let fx = Fixture::new();
        (fx.book(), fx)
    }

    fn no_net() -> AccountNetwork {
        AccountNetwork::default()
    }

    fn net(pc_ip: &str, network: &str, gateway: &str) -> AccountNetwork {
        let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
        AccountNetwork {
            pc_ip: some(pc_ip),
            network: some(network),
            gateway: some(gateway),
        }
    }

    // ---- Champs réseau ----

    #[test]
    fn network_fields_are_stored_in_clear_and_reload() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book
            .create(
                "Mairie",
                "root",
                pwd(PWD),
                net("192.168.1.250/24", "192.168.1.0/24", "192.168.1.1"),
            )
            .unwrap();
        assert_eq!(acc.net.pc_ip.as_deref(), Some("192.168.1.250/24"));
        let raw = fx.raw();
        assert!(raw.contains("\"pc_ip\": \"192.168.1.250/24\""));
        assert!(raw.contains("\"network\": \"192.168.1.0/24\""));
        assert!(raw.contains("\"gateway\": \"192.168.1.1\""));
        assert_eq!(fx.book().list()[0].net, acc.net);
    }

    #[test]
    fn account_without_network_writes_no_network_keys() {
        let fx = Fixture::new();
        fx.book().create("A", "root", pwd(PWD), no_net()).unwrap();
        let raw = fx.raw();
        assert!(!raw.contains("pc_ip") && !raw.contains("gateway") && !raw.contains("\"network\""));
    }

    #[test]
    fn v2_file_without_network_fields_loads() {
        let fx = Fixture::new();
        let file = serde_json::json!({"version": 2, "accounts": [{
            "id": "1", "name": "A",
            "login": seal::seal(b"root"), "password": seal::seal(PWD.as_bytes()),
        }]});
        std::fs::write(fx.path(), file.to_string()).unwrap();
        let book = fx.book();
        assert_eq!(book.list()[0].net, no_net());
        assert_eq!(book.credentials("1").unwrap().password.expose(), PWD);
    }

    #[test]
    fn legacy_v1_file_loads_without_network_fields() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        assert_eq!(fx.book().list()[0].net, no_net());
    }

    #[test]
    fn network_fields_are_normalized() {
        let n = net(" 192.168.1.250/24 ", "192.168.1.77/24", " ")
            .validated()
            .unwrap();
        assert_eq!(n, net("192.168.1.250/24", "192.168.1.0/24", ""));
        assert_eq!(net("", "", "").validated().unwrap(), no_net());
    }

    #[test]
    fn network_is_derived_from_the_pc_ip() {
        // Le réseau reçu ne compte plus : il se déduit de l'IP du PC.
        let n = net("10.1.2.250/16", "192.168.1.0/24", "").validated().unwrap();
        assert_eq!(n, net("10.1.2.250/16", "10.1.0.0/16", ""));
        // Ancien réseau illisible : ignoré, pas une erreur.
        assert!(net("192.168.1.250/24", "réseau", "").validated().is_ok());
        // Sans IP du PC, pas de réseau.
        assert_eq!(net("", "192.168.1.0/24", "").validated().unwrap(), no_net());
    }

    #[test]
    fn pc_ip_without_mask_is_a_missing_mask() {
        let err = net("192.168.1.250", "", "").validated().unwrap_err();
        assert!(matches!(err, AccountError::MaskMissing));
        // Pas de /24 ajouté en douce.
        let (mut book, _fx) = empty_book();
        assert!(matches!(
            book.create("A", "root", pwd(PWD), net(" 192.168.1.250 ", "", "")),
            Err(AccountError::MaskMissing)
        ));
        assert!(book.list().is_empty());
    }

    #[test]
    fn stored_network_is_recomputed_on_load() {
        let fx = Fixture::new();
        let file = serde_json::json!({"version": 2, "accounts": [
            {"id": "1", "name": "A", "pc_ip": "192.168.1.250/24", "network": "192.168.0.0/22",
             "login": seal::seal(b"root"), "password": seal::seal(PWD.as_bytes())},
            {"id": "2", "name": "B", "network": "10.0.0.0/8",
             "login": seal::seal(b"root"), "password": seal::seal(PWD.as_bytes())},
        ]});
        std::fs::write(fx.path(), file.to_string()).unwrap();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(matches!(startup, Startup::Clean));
        assert_eq!(book.list()[0].net, net("192.168.1.250/24", "192.168.1.0/24", ""));
        assert_eq!(book.list()[1].net, no_net());
    }

    #[test]
    fn import_ignores_the_network_of_older_files() {
        let (mut book, _fx) = empty_book();
        book.create("Mairie", "root", pwd(PWD), net("192.168.1.250/24", "", "192.168.1.1"))
            .unwrap();
        let file = |network: &str| {
            serde_json::json!({
                "format": "lenscout-accounts", "version": 1,
                "accounts": [{"name": "Mairie", "login": seal::seal(b"root"), "password": seal::seal(PWD.as_bytes()),
                    "pc_ip": "192.168.1.250/24", "network": network, "gateway": "192.168.1.1"}],
            })
            .to_string()
        };
        // Réseau cohérent avec l'IP du PC : rien ne diffère.
        assert_eq!(book.import_plan(&file("192.168.1.0/24")).unwrap().items[0].kind, ImportKind::Identical);
        // Ancien réseau saisi à la main (autre préfixe) : recalculé, pas « différent ».
        assert_eq!(book.import_plan(&file("192.168.0.0/22")).unwrap().items[0].kind, ImportKind::Identical);
        // Réseau seul, sans IP du PC : le fichier se charge, le réseau est ignoré.
        let only = serde_json::json!({
            "format": "lenscout-accounts", "version": 1,
            "accounts": [{"name": "Gare", "login": seal::seal(b"root"), "network": "10.0.0.0/8"}],
        })
        .to_string();
        book.import_apply(&only, &HashMap::new()).unwrap();
        assert_eq!(book.list()[1].net, no_net());
    }

    #[test]
    fn network_fields_are_validated_with_stable_errors() {
        let err = |n: AccountNetwork| n.validated().unwrap_err();
        for bad in ["192.168.1.250/33", "192.168.1.0/24", "192.168.1.255/24", "x/24", "192.168.1.250/0"] {
            assert!(matches!(err(net(bad, "", "")), AccountError::InvalidPcIp), "{bad}");
        }
        for bad in ["192.168.1.1/24", "x", "192.168.1.0", "192.168.1.255"] {
            assert!(
                matches!(err(net("192.168.1.250/24", "192.168.1.0/24", bad)), AccountError::InvalidGateway),
                "{bad}"
            );
        }
        assert!(matches!(
            err(net("192.168.1.250/24", "192.168.1.250/24", "192.168.1.250")),
            AccountError::InvalidGateway
        ));
        // La passerelle doit appartenir au réseau de l'IP du PC.
        assert!(matches!(
            err(net("192.168.1.250/24", "", "192.168.2.1")),
            AccountError::GatewayOutsideNetwork
        ));
        assert!(net("192.168.1.250/24", "", "192.168.1.1").validated().is_ok());
        assert!(net("", "", "10.0.0.1").validated().is_ok());
    }

    #[test]
    fn pc_ip_prefix_is_bounded_and_addresses_are_unicast() {
        let err = |n: AccountNetwork| n.validated().unwrap_err();
        for bad in ["10.0.0.250/7", "192.168.1.250/31", "192.168.1.250/32", "0.0.0.1/8", "224.0.0.5/24", "127.0.0.5/8", "255.255.255.254/30"] {
            assert!(matches!(err(net(bad, "", "")), AccountError::InvalidPcIp), "{bad}");
        }
        for ok in ["10.0.0.250/8", "192.168.1.250/30"] {
            assert!(net(ok, "", "").validated().is_ok(), "{ok}");
        }
        for bad in ["0.0.0.0", "255.255.255.255", "224.0.0.1", "127.0.0.1"] {
            assert!(matches!(err(net("", "", bad)), AccountError::InvalidGateway), "{bad}");
        }
    }

    #[test]
    fn non_text_network_field_is_ignored_on_load() {
        let fx = Fixture::new();
        let file = serde_json::json!({"version": 2, "accounts": [{
            "id": "1", "name": "A", "pc_ip": 42, "network": {"x": 1}, "gateway": "192.168.1.1",
            "login": seal::seal(b"root"), "password": seal::seal(PWD.as_bytes()),
        }]});
        std::fs::write(fx.path(), file.to_string()).unwrap();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(matches!(startup, Startup::Clean));
        assert_eq!(book.list()[0].net, net("", "", "192.168.1.1"));
        assert_eq!(book.credentials("1").unwrap().password.expose(), PWD);
    }

    #[test]
    fn partial_import_replaces_only_the_fields_it_carries() {
        let (mut src, _fx_src) = empty_book();
        src.create("Mairie", "root", pwd(PWD), net("192.168.1.240/24", "", ""))
            .unwrap();
        let data = src.export();
        let (mut dst, _fx_dst) = empty_book();
        dst.create("Mairie", "root", pwd(PWD), net("192.168.1.250/24", "192.168.1.0/24", "192.168.1.1"))
            .unwrap();
        let plan = dst.import_plan(&data).unwrap();
        assert_eq!(
            plan.items[0].kind,
            ImportKind::Differs { login_differs: false, password_differs: false, network_differs: true }
        );
        dst.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(dst.list()[0].net, net("192.168.1.240/24", "192.168.1.0/24", "192.168.1.1"));
        // Les seuls champs présents sont identiques : rien ne diffère.
        assert_eq!(dst.import_plan(&data).unwrap().items[0].kind, ImportKind::Identical);
    }

    #[test]
    fn partial_import_never_keeps_an_incoherent_network() {
        let (mut src, _fx_src) = empty_book();
        src.create("Mairie", "root", pwd(PWD), net("10.0.0.250/24", "", "")).unwrap();
        let data = src.export();
        let (mut dst, _fx_dst) = empty_book();
        dst.create("Mairie", "root", pwd(PWD), net("192.168.1.250/24", "192.168.1.0/24", "192.168.1.1"))
            .unwrap();
        dst.import_apply(&data, &HashMap::new()).unwrap();
        // Passerelle ancienne hors du réseau de la nouvelle IP : celle du fichier (vide).
        let got = dst.list()[0].net.clone();
        assert_eq!(got, net("10.0.0.250/24", "10.0.0.0/24", ""));
        assert_eq!(got.validated().unwrap(), got);
    }

    #[test]
    fn invalid_network_fields_change_nothing() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let err = book
            .create("A", "root", pwd(PWD), net("192.168.2.250/24", "", "192.168.1.1"))
            .unwrap_err();
        assert!(matches!(err, AccountError::GatewayOutsideNetwork));
        assert!(book.list().is_empty());
        let acc = book.create("A", "root", pwd(PWD), no_net()).unwrap();
        let err = book
            .update(&acc.id, "A", "root", None, net("", "", "pas une ip"))
            .unwrap_err();
        assert!(matches!(err, AccountError::InvalidGateway));
        assert_eq!(fx.book().list()[0].net, no_net());
    }

    #[test]
    fn update_replaces_network_fields() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book
            .create("A", "root", pwd(PWD), net("10.1.0.250/16", "", ""))
            .unwrap();
        book.update(&acc.id, "A", "root", None, net("192.168.1.250/24", "", ""))
            .unwrap();
        assert_eq!(fx.book().list()[0].net, net("192.168.1.250/24", "192.168.1.0/24", ""));
    }

    #[test]
    fn export_and_import_carry_network_fields() {
        let (mut src, _fx_src) = empty_book();
        let full = net("192.168.1.250/24", "192.168.1.0/24", "192.168.1.1");
        src.create("Mairie", "root", pwd(PWD), full.clone()).unwrap();
        src.create("Gare", "admin", pwd(PWD), no_net()).unwrap();
        let data = src.export();
        assert!(data.contains("192.168.1.250/24"));
        let v: serde_json::Value = serde_json::from_str(&data).unwrap();
        let gare = v["accounts"].as_array().unwrap().iter().find(|a| a["name"] == "Gare").unwrap();
        assert!(gare.get("pc_ip").is_none() && gare.get("network").is_none() && gare.get("gateway").is_none());
        let (mut dst, _fx_dst) = empty_book();
        dst.import_apply(&data, &HashMap::new()).unwrap();
        let by = |n: &str| dst.list().into_iter().find(|a| a.name == n).unwrap();
        assert_eq!(by("Mairie").net, full);
        assert_eq!(by("Gare").net, no_net());
    }

    #[test]
    fn import_compares_network_fields() {
        let (mut src, _fx_src) = empty_book();
        src.create("Mairie", "root", pwd(PWD), net("192.168.1.250/24", "", ""))
            .unwrap();
        let data = src.export();
        let (mut dst, _fx_dst) = empty_book();
        let id = dst
            .create("Mairie", "root", pwd(PWD), net("10.0.0.250/24", "", ""))
            .unwrap()
            .id;
        let plan = dst.import_plan(&data).unwrap();
        assert_eq!(
            plan.items[0].kind,
            ImportKind::Differs { login_differs: false, password_differs: false, network_differs: true }
        );
        dst.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(dst.list()[0].net, net("192.168.1.250/24", "192.168.1.0/24", ""));
        assert_eq!(dst.list()[0].id, id);
        // Identique, réseau compris.
        let plan = dst.import_plan(&data).unwrap();
        assert_eq!(plan.items[0].kind, ImportKind::Identical);
    }

    #[test]
    fn import_without_network_fields_keeps_existing_ones() {
        let (mut src, _fx_src) = empty_book();
        src.create("Mairie", "autre", pwd(PWD), no_net()).unwrap();
        let data = src.export();
        let (mut dst, _fx_dst) = empty_book();
        let full = net("192.168.1.250/24", "192.168.1.0/24", "192.168.1.1");
        dst.create("Mairie", "root", pwd(PWD), full.clone()).unwrap();
        let plan = dst.import_plan(&data).unwrap();
        assert_eq!(
            plan.items[0].kind,
            ImportKind::Differs { login_differs: true, password_differs: false, network_differs: false }
        );
        dst.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(dst.list()[0].login, "autre");
        assert_eq!(dst.list()[0].net, full);
    }

    #[test]
    fn import_rejects_invalid_network_fields() {
        let mut book = sample_book();
        let before = book.list();
        let data = serde_json::json!({
            "format": "lenscout-accounts", "version": 1,
            "accounts": [{"name": "X", "login": seal::seal(b"root"), "pc_ip": "999.1.1.1/24"}],
        })
        .to_string();
        assert!(matches!(book.import_plan(&data), Err(AccountError::ImportInvalid)));
        assert!(matches!(
            book.import_apply(&data, &HashMap::new()),
            Err(AccountError::ImportInvalid)
        ));
        assert_eq!(book.list(), before);
    }

    #[test]
    fn file_never_contains_login_or_password_in_clear() {
        let fx = Fixture::new();
        let mut book = fx.book();
        book.create("Défaut LORVA", "root-unique", pwd(PWD), no_net())
            .unwrap();
        let raw = fx.raw();
        assert!(!raw.contains("S3cr3t"));
        assert!(!raw.contains("root-unique"));
        assert!(raw.contains("Défaut LORVA"));
        assert!(raw.contains("\"version\": 2"));
    }

    #[test]
    fn credentials_after_reload() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("Défaut LORVA", "root", pwd(PWD), no_net()).unwrap();
        let creds = fx.book().credentials(&acc.id).unwrap();
        assert_eq!(creds.login, "root");
        assert_eq!(creds.password.expose(), PWD);
        assert!(fx.book().has_secret(&acc.id));
    }

    #[test]
    fn reload_keeps_accounts() {
        let fx = Fixture::new();
        let mut book = fx.book();
        book.create("A", "root", pwd(PWD), no_net()).unwrap();
        book.create("B", "admin", pwd(PWD), no_net()).unwrap();
        assert_eq!(fx.book().list(), book.list());
        assert_eq!(fx.book().list().len(), 2);
    }

    #[test]
    fn missing_file_is_empty_book() {
        assert!(empty_book().0.list().is_empty());
    }

    #[test]
    fn duplicate_name_rejected() {
        let fx = Fixture::new();
        let mut book = fx.book();
        book.create("Client X", "root", pwd(PWD), no_net()).unwrap();
        let err = book.create("client x", "root", pwd(PWD), no_net()).unwrap_err();
        assert!(matches!(err, AccountError::DuplicateName));
        assert_eq!(book.list().len(), 1);
    }

    #[test]
    fn update_rejects_name_of_another_account() {
        let (mut book, _fx_book) = empty_book();
        book.create("A", "root", pwd(PWD), no_net()).unwrap();
        let b = book.create("B", "root", pwd(PWD), no_net()).unwrap();
        let err = book.update(&b.id, "a", "root", None, no_net()).unwrap_err();
        assert!(matches!(err, AccountError::DuplicateName));
        // Garder son propre nom (casse changée) reste permis.
        assert!(book.update(&b.id, "b", "root", None, no_net()).is_ok());
    }

    #[test]
    fn empty_fields_rejected() {
        let (mut book, _fx_book) = empty_book();
        assert!(matches!(
            book.create(" ", "root", pwd(PWD), no_net()).unwrap_err(),
            AccountError::EmptyField
        ));
        assert!(matches!(
            book.create("A", "", pwd(PWD), no_net()).unwrap_err(),
            AccountError::EmptyField
        ));
        assert!(matches!(
            book.create("A", "root", pwd(""), no_net()).unwrap_err(),
            AccountError::EmptyField
        ));
        assert!(book.list().is_empty());
    }

    #[test]
    fn update_without_password_keeps_secret() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("A", "root", pwd(PWD), no_net()).unwrap();
        let upd = book.update(&acc.id, "A2", "admin", None, no_net()).unwrap();
        assert_eq!((upd.name.as_str(), upd.login.as_str()), ("A2", "admin"));
        assert_eq!(upd.id, acc.id);
        assert_eq!(book.credentials(&acc.id).unwrap().password.expose(), PWD);
        assert_eq!(fx.book().list()[0].name, "A2");
        assert_eq!(
            fx.book().credentials(&acc.id).unwrap().password.expose(),
            PWD
        );
    }

    #[test]
    fn password_of_one_account_on_demand() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root"), ("id-2", "Gare", "admin")]);
        fx.store.set("id-2", &pwd(PWD)).unwrap();
        let book = fx.book();
        assert_eq!(book.password("id-2").unwrap().unwrap().expose(), PWD);
        // Compte repris sans secret : rien à montrer, pas une erreur.
        assert!(book.password("id-1").unwrap().is_none());
        assert!(matches!(book.password("zzz"), Err(AccountError::NotFound)));
    }

    #[test]
    fn update_with_password_replaces_secret() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("A", "root", pwd(PWD), no_net()).unwrap();
        book.update(&acc.id, "A", "root", Some(pwd("Autre-1")), no_net())
            .unwrap();
        assert_eq!(
            fx.book().credentials(&acc.id).unwrap().password.expose(),
            "Autre-1"
        );
    }

    #[test]
    fn remove_deletes_account() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("A", "root", pwd(PWD), no_net()).unwrap();
        book.remove(&acc.id).unwrap();
        assert!(book.list().is_empty());
        assert!(fx.book().list().is_empty());
        assert!(matches!(book.remove(&acc.id), Err(AccountError::NotFound)));
    }

    #[test]
    fn unknown_id_is_not_found() {
        let (mut book, _fx_book) = empty_book();
        assert!(matches!(book.credentials("x"), Err(AccountError::NotFound)));
        assert!(matches!(
            book.update("x", "A", "r", None, no_net()),
            Err(AccountError::NotFound)
        ));
    }

    #[test]
    fn account_debug_has_no_password() {
        let (mut book, _fx_book) = empty_book();
        let acc = book.create("A", "root", pwd(PWD), no_net()).unwrap();
        assert!(!format!("{book:?} {acc:?}").contains("S3cr3t"));
    }

    #[test]
    fn write_failure_leaves_book_unchanged() {
        let fx = Fixture::new();
        // Le chemin du fichier est un dossier : le `rename` final échoue.
        std::fs::create_dir_all(fx.path()).unwrap();
        let mut book = AccountBook::load(fx.dir.join("absent.json"), fx.store.clone()).unwrap();
        book.path = fx.path();
        let err = book.create("A", "root", pwd(PWD), no_net()).unwrap_err();
        assert!(matches!(err, AccountError::Io(_)));
        assert!(book.list().is_empty());
    }

    #[test]
    fn corrupt_file_is_quarantined_not_deleted() {
        let fx = Fixture::new();
        std::fs::write(fx.path(), b"{ pas du json").unwrap();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(book.list().is_empty());
        let Startup::Quarantined(moved) = startup else {
            panic!("attendu Quarantined, reçu {startup:?}");
        };
        assert!(!fx.path().exists());
        assert!(
            moved
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("accounts.json.corrupt-")
        );
        assert_eq!(std::fs::read(&moved).unwrap(), b"{ pas du json");
        // Le carnet vide reste utilisable.
        let mut book = book;
        assert!(book.create("A", "root", pwd(PWD), no_net()).is_ok());
    }

    #[test]
    fn unsealable_v2_file_is_quarantined() {
        let fx = Fixture::new();
        std::fs::write(
            fx.path(),
            br#"{"version":2,"accounts":[{"id":"1","name":"A","login":"AAAA","password":"AAAA"}]}"#,
        )
        .unwrap();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(book.list().is_empty());
        assert!(matches!(startup, Startup::Quarantined(_)));
    }

    #[test]
    fn absent_file_is_clean_start() {
        let fx = Fixture::new();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(book.list().is_empty());
        assert!(matches!(startup, Startup::Clean));
        assert!(std::fs::read_dir(&fx.dir).unwrap().next().is_none());
    }

    #[test]
    fn valid_file_is_clean_start() {
        let fx = Fixture::new();
        fx.book().create("A", "root", pwd(PWD), no_net()).unwrap();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert_eq!(book.list().len(), 1);
        assert!(matches!(startup, Startup::Clean));
    }

    #[cfg(unix)]
    #[test]
    fn failed_rename_gives_unwritable_memory_book() {
        use std::os::unix::fs::PermissionsExt;
        let fx = Fixture::new();
        std::fs::write(fx.path(), b"{ pas du json").unwrap();
        // Dossier en lecture seule : le rename échoue.
        std::fs::set_permissions(&fx.dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let (mut book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        std::fs::set_permissions(&fx.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(startup, Startup::Unwritable));
        assert!(book.list().is_empty());
        let err = book.create("A", "root", pwd(PWD), no_net()).unwrap_err();
        assert!(matches!(err, AccountError::Io(_)));
        assert!(book.list().is_empty());
        // Le fichier d'origine n'a pas été touché.
        assert_eq!(std::fs::read(fx.path()).unwrap(), b"{ pas du json");
    }

    // ---- Reprise de l'ancien format ----

    #[test]
    fn migrates_v1_file_from_store() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root-unique")]);
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        let (book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(matches!(startup, Startup::Clean));
        let creds = book.credentials("id-1").unwrap();
        assert_eq!(
            (creds.login.as_str(), creds.password.expose()),
            ("root-unique", PWD)
        );
        assert!(book.has_secret("id-1"));
        // Le fichier est réécrit en v2, sans rien en clair.
        let raw = fx.raw();
        assert!(raw.contains("\"version\": 2"));
        assert!(!raw.contains("root-unique") && !raw.contains("S3cr3t"));
        // Rechargé sans trousseau : le fichier se suffit.
        let alone = AccountBook::load(fx.path(), Arc::new(MemoryStore::default())).unwrap();
        assert_eq!(alone.credentials("id-1").unwrap().password.expose(), PWD);
    }

    #[test]
    fn migration_missing_secret_keeps_account_needing_password() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root"), ("id-2", "Gare", "admin")]);
        fx.store.set("id-2", &pwd(PWD)).unwrap();
        let (mut book, startup) = load_or_quarantine(fx.path(), fx.store.clone());
        assert!(matches!(startup, Startup::Clean));
        assert_eq!(book.list().len(), 2);
        assert!(!book.has_secret("id-1"));
        assert!(book.has_secret("id-2"));
        assert!(matches!(
            book.credentials("id-1"),
            Err(AccountError::SecretMissing)
        ));
        assert!(matches!(
            book.update("id-1", "Mairie", "root", None, no_net()),
            Err(AccountError::SecretMissing)
        ));
        // Ressaisir le mot de passe répare le compte.
        book.update("id-1", "Mairie", "root", Some(pwd("Neuf-1")), no_net())
            .unwrap();
        assert_eq!(
            book.credentials("id-1").unwrap().password.expose(),
            "Neuf-1"
        );
        assert_eq!(book.credentials("id-2").unwrap().password.expose(), PWD);
    }

    #[test]
    fn migration_with_missing_secret_does_not_rewrite_file() {
        // Trousseau inaccessible : le fichier d'origine reste tel quel, la
        // reprise sera retentée au lancement suivant.
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        let before = std::fs::read(fx.path()).unwrap();
        let (book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        assert_eq!(book.list().len(), 1);
        assert_eq!(std::fs::read(fx.path()).unwrap(), before);
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        let (book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        assert_eq!(book.credentials("id-1").unwrap().password.expose(), PWD);
        assert!(fx.raw().contains("\"version\": 2"));
    }

    #[test]
    fn migration_keeps_store_entries() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        let _ = load_or_quarantine(fx.path(), fx.store.clone());
        assert_eq!(fx.store.get("id-1").unwrap().expose(), PWD);
    }

    // ---- Export / import ----

    fn sample_book() -> AccountBook {
        let (mut book, _fx_book) = empty_book();
        book.create("Mairie Arles", "root-unique", pwd(PWD), no_net())
            .unwrap();
        book.create("Gare", "admin", pwd("Autre-1"), no_net()).unwrap();
        book
    }

    #[test]
    fn export_has_no_ids_no_clear_and_no_needs_password() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Sans secret", "root")]);
        let (mut book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        book.create("Mairie Arles", "root-unique", pwd(PWD), no_net())
            .unwrap();
        let out = book.export();
        assert!(!out.contains("root-unique") && !out.contains("S3cr3t"));
        assert!(!out.contains("needs_password") && !out.contains("\"id\""));
        assert!(!out.contains("legacy"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["format"], "lenscout-accounts");
        assert_eq!(v["version"], 1);
        let accounts = v["accounts"].as_array().unwrap();
        let sans = accounts
            .iter()
            .find(|a| a["name"] == "Sans secret")
            .unwrap();
        assert!(sans.get("password").is_none());
        assert!(sans.get("login").is_some());
    }

    #[test]
    fn export_then_import_on_empty_book_restores_all() {
        let src = sample_book();
        let data = src.export();
        let (mut dst, _fx_dst) = empty_book();
        let plan = dst.import_plan(&data).unwrap();
        assert!(plan.items.iter().all(|i| i.kind == ImportKind::New));
        let summary = dst.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(summary.added, 2);
        let find = |book: &AccountBook, name: &str| {
            let a = book.list().into_iter().find(|a| a.name == name).unwrap();
            book.credentials(&a.id).unwrap()
        };
        let c = find(&dst, "Mairie Arles");
        assert_eq!(
            (c.login.as_str(), c.password.expose()),
            ("root-unique", PWD)
        );
        assert_eq!(find(&dst, "Gare").password.expose(), "Autre-1");
    }

    #[test]
    fn import_survives_a_reload() {
        let fx = Fixture::new();
        let data = sample_book().export();
        fx.book().import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(fx.book().list().len(), 2);
    }

    #[test]
    fn import_identical_is_untouched() {
        let mut book = sample_book();
        let data = book.export();
        let before = book.list();
        let plan = book.import_plan(&data).unwrap();
        assert!(plan.items.iter().all(|i| i.kind == ImportKind::Identical));
        let summary = book.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(
            (summary.added, summary.replaced, summary.identical),
            (0, 0, 2)
        );
        assert_eq!(book.list(), before);
    }

    fn differing() -> (AccountBook, String, Fixture) {
        let src = sample_book();
        let (mut dst, fx) = empty_book();
        dst.create("Mairie Arles", "autre-login", pwd(PWD), no_net()).unwrap();
        (dst, src.export(), fx)
    }

    #[test]
    fn import_plan_reports_what_differs_without_secrets() {
        let (dst, data, _fx) = differing();
        let plan = dst.import_plan(&data).unwrap();
        let mairie = plan
            .items
            .iter()
            .find(|i| i.name == "Mairie Arles")
            .unwrap();
        assert_eq!(
            mairie.kind,
            ImportKind::Differs {
                login_differs: true,
                password_differs: false,
                network_differs: false
            }
        );
        let gare = plan.items.iter().find(|i| i.name == "Gare").unwrap();
        assert_eq!(gare.kind, ImportKind::New);
    }

    #[test]
    fn import_differs_default_replace() {
        let (mut dst, data, _fx) = differing();
        let id = dst.list()[0].id.clone();
        let summary = dst.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!((summary.added, summary.replaced), (1, 1));
        assert_eq!(dst.list().len(), 2);
        // Remplacé en gardant l'id.
        assert_eq!(dst.credentials(&id).unwrap().login, "root-unique");
    }

    #[test]
    fn import_keep_both_avoids_every_name_of_the_file() {
        // Le fichier porte « X » (qui diffère) et « X 2 » : « X » devient « X 3 ».
        let (mut src, _fx_src) = empty_book();
        src.create("X", "root", pwd("a"), no_net()).unwrap();
        src.create("X 2", "admin", pwd("b"), no_net()).unwrap();
        let data = src.export();
        let (mut dst, _fx_dst) = empty_book();
        dst.create("X", "autre", pwd("c"), no_net()).unwrap();
        let choices = HashMap::from([("X".to_string(), Choice::KeepBoth)]);
        let summary = dst.import_apply(&data, &choices).unwrap();
        assert_eq!((summary.kept_both, summary.added), (1, 1));
        let by_name = |n: &str| dst.list().into_iter().find(|a| a.name == n).unwrap();
        assert_eq!(dst.credentials(&by_name("X").id).unwrap().login, "autre");
        assert_eq!(dst.credentials(&by_name("X 2").id).unwrap().login, "admin");
        assert_eq!(dst.credentials(&by_name("X 3").id).unwrap().login, "root");
        assert_eq!(dst.list().len(), 3);
    }

    #[test]
    fn import_keep_both_picks_next_free_suffix() {
        let (mut dst, data, _fx) = differing();
        dst.create("Mairie Arles 2", "x", pwd("y"), no_net()).unwrap();
        let choices = HashMap::from([("Mairie Arles".to_string(), Choice::KeepBoth)]);
        let summary = dst.import_apply(&data, &choices).unwrap();
        assert_eq!(summary.kept_both, 1);
        let names: Vec<_> = dst.list().into_iter().map(|a| a.name).collect();
        assert!(names.contains(&"Mairie Arles".to_string()));
        assert!(names.contains(&"Mairie Arles 2".to_string()));
        assert!(names.contains(&"Mairie Arles 3".to_string()));
        let a3 = dst
            .list()
            .into_iter()
            .find(|a| a.name == "Mairie Arles 3")
            .unwrap();
        assert_eq!(dst.credentials(&a3.id).unwrap().login, "root-unique");
        // L'original n'a pas bougé.
        let a1 = dst
            .list()
            .into_iter()
            .find(|a| a.name == "Mairie Arles")
            .unwrap();
        assert_eq!(dst.credentials(&a1.id).unwrap().login, "autre-login");
    }

    #[test]
    fn import_skip_changes_nothing() {
        let (mut dst, data, _fx) = differing();
        let choices = HashMap::from([("Mairie Arles".to_string(), Choice::Skip)]);
        let summary = dst.import_apply(&data, &choices).unwrap();
        assert_eq!((summary.skipped, summary.replaced), (1, 0));
        let a = dst
            .list()
            .into_iter()
            .find(|a| a.name == "Mairie Arles")
            .unwrap();
        assert_eq!(dst.credentials(&a.id).unwrap().login, "autre-login");
    }

    #[test]
    fn import_rejects_garbage_and_foreign_json() {
        let mut book = sample_book();
        let before = book.list();
        let bad = [
            "",
            "pas du json",
            "{\"format\":\"lenscout-accounts\",\"version\":1,\"accounts\":[",
            "[]",
            "{\"hello\":1}",
            "{\"format\":\"autre\",\"version\":1,\"accounts\":[]}",
            "{\"format\":\"lenscout-accounts\",\"version\":9,\"accounts\":[]}",
            "{\"format\":\"lenscout-accounts\",\"version\":1,\"accounts\":[{\"name\":\"A\",\"login\":\"AAAA\"}]}",
        ];
        for data in bad {
            assert!(
                matches!(book.import_plan(data), Err(AccountError::ImportInvalid)),
                "{data}"
            );
            assert!(
                matches!(
                    book.import_apply(data, &HashMap::new()),
                    Err(AccountError::ImportInvalid)
                ),
                "{data}"
            );
        }
        // Tronqué.
        let good = sample_book().export();
        let cut = &good[..good.len() / 2];
        assert!(matches!(
            book.import_apply(cut, &HashMap::new()),
            Err(AccountError::ImportInvalid)
        ));
        assert_eq!(book.list(), before);
    }

    #[test]
    fn import_without_password_keeps_existing_password() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Sans secret", "root")]);
        let (nopass, _) = load_or_quarantine(fx.path(), fx.store.clone());
        let data = nopass.export();
        let (mut dst, _fx_dst) = empty_book();
        dst.create("Sans secret", "root", pwd(PWD), no_net()).unwrap();
        let plan = dst.import_plan(&data).unwrap();
        assert_eq!(plan.items[0].kind, ImportKind::Identical);
        // Sur un carnet vide : ajouté, à ressaisir.
        let (mut empty, _fx_empty) = empty_book();
        empty.import_apply(&data, &HashMap::new()).unwrap();
        assert!(!empty.has_secret(&empty.list()[0].id));
    }

    #[test]
    fn import_apply_is_atomic_on_write_failure() {
        let fx = Fixture::new();
        std::fs::create_dir_all(fx.path()).unwrap();
        let mut book = AccountBook::load(fx.dir.join("absent.json"), fx.store.clone()).unwrap();
        book.path = fx.path();
        let data = sample_book().export();
        assert!(matches!(
            book.import_apply(&data, &HashMap::new()),
            Err(AccountError::Io(_))
        ));
        assert!(book.list().is_empty());
    }

    // ---- Ronde 1 ----

    #[test]
    fn legacy_account_is_recovered_once_keyring_answers() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        // Trousseau vide au démarrage, puis l'utilisateur crée un autre compte.
        let (mut book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        book.create("Gare", "admin", pwd("Autre-1"), no_net()).unwrap();
        assert!(fx.raw().contains("\"legacy\": true"));
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        let (book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        assert_eq!(book.credentials("id-1").unwrap().password.expose(), PWD);
        assert!(!fx.raw().contains("legacy"));
        assert_eq!(
            book.credentials(&book.list()[1].id)
                .unwrap()
                .password
                .expose(),
            "Autre-1"
        );
    }

    #[test]
    fn replace_with_another_login_drops_the_legacy_marker() {
        // Fichier d'import sans mot de passe, identifiant différent.
        let src = Fixture::new();
        src.write_v1(&[("s", "Mairie", "autre")]);
        let (src_book, _) = load_or_quarantine(src.path(), src.store.clone());
        let data = src_book.export();
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        let (mut book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        // Fichier réécrit : le compte porte encore la marque `legacy`.
        book.create("Gare", "admin", pwd("x"), no_net()).unwrap();
        assert!(fx.raw().contains("\"legacy\": true"));
        let summary = book.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(summary.replaced, 1);
        assert!(!fx.raw().contains("legacy"));
        // Le trousseau ne rend pas un mot de passe à un autre identifiant.
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        assert!(fx.book().credentials("id-1").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn stale_temp_file_does_not_weaken_the_mode() {
        use std::os::unix::fs::PermissionsExt;
        let fx = Fixture::new();
        let tmp = fx.path().with_extension("json.tmp");
        std::fs::write(&tmp, b"vieux").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut book = fx.book();
        book.create("A", "root", pwd(PWD), no_net()).unwrap();
        let mode = std::fs::metadata(fx.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn legacy_marker_cleared_when_password_entered() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        let (mut book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        book.create("Gare", "admin", pwd("x"), no_net()).unwrap();
        book.update("id-1", "Mairie", "root", Some(pwd("Neuf-1")), no_net())
            .unwrap();
        assert!(!fx.raw().contains("legacy"));
        // Le trousseau, même rempli plus tard, ne remplace pas le mot de passe saisi.
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        assert_eq!(
            fx.book().credentials("id-1").unwrap().password.expose(),
            "Neuf-1"
        );
    }

    #[test]
    fn needing_password_account_reloads_from_v2_without_secret() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        let (mut book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        book.create("Gare", "admin", pwd("x"), no_net()).unwrap();
        let book = fx.book();
        assert!(!book.has_secret("id-1"));
        assert!(matches!(
            book.credentials("id-1"),
            Err(AccountError::SecretMissing)
        ));
    }

    #[test]
    fn import_rejects_names_repeated_ignoring_case() {
        let mut book = sample_book();
        let before = book.list();
        let one = |name: &str| serde_json::json!({"name": name, "login": seal::seal(b"root")});
        let data = serde_json::json!({
            "format": "lenscout-accounts", "version": 1,
            "accounts": [one("Gare Nord"), one("gare nord")],
        })
        .to_string();
        assert!(matches!(
            book.import_plan(&data),
            Err(AccountError::ImportInvalid)
        ));
        assert!(matches!(
            book.import_apply(&data, &HashMap::new()),
            Err(AccountError::ImportInvalid)
        ));
        assert_eq!(book.list(), before);
    }

    #[test]
    fn remove_also_cleans_keyring_entry() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        fx.store.set("id-1", &pwd(PWD)).unwrap();
        let (mut book, _) = load_or_quarantine(fx.path(), fx.store.clone());
        book.remove("id-1").unwrap();
        assert!(matches!(fx.store.get("id-1"), Err(AccountError::NotFound)));
    }

    #[test]
    fn debug_never_shows_login() {
        let (mut book, _fx_book) = empty_book();
        let acc = book.create("A", "root-unique", pwd(PWD), no_net()).unwrap();
        let creds = book.credentials(&acc.id).unwrap();
        let out = format!("{book:?} {acc:?} {creds:?}");
        assert!(!out.contains("root-unique") && !out.contains("S3cr3t"));
    }

    #[test]
    fn corrupt_v1_error_does_not_echo_content() {
        let fx = Fixture::new();
        std::fs::write(fx.path(), br#"["Secret-Nom-Unique"]"#).unwrap();
        let err = AccountBook::load(fx.path(), fx.store.clone()).unwrap_err();
        assert!(!err.to_string().contains("Secret-Nom-Unique"));
        assert!(!format!("{err:?}").contains("login"));
    }

    #[cfg(unix)]
    #[test]
    fn account_file_is_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let fx = Fixture::new();
        fx.book().create("A", "root", pwd(PWD), no_net()).unwrap();
        let mode = std::fs::metadata(fx.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
