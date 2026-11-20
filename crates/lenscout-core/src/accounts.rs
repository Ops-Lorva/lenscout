use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::seal;
use crate::site_survey::device::{DeviceKind, SeenDevice};
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
/// `exclusions` = adresses et plages jamais proposées aux caméras (voir
/// `Exclusions`).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct AccountNetwork {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pc_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusions: Option<String>,
}

/// Adresses qu'un site réserve (NVR, serveur, plage d'un autre installateur) :
/// la recherche d'IP libres et le plan en lot n'y touchent jamais. Saisies
/// comme `192.168.1.10, 192.168.1.20-192.168.1.29` ou en forme courte
/// `192.168.1.20-29` (la fin = dernier octet), virgules ou espaces.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Exclusions(Vec<(u32, u32)>);

impl Exclusions {
    /// `None` si un élément ne se lit pas : une plage à l'envers ou une
    /// adresse tronquée ne doit pas devenir « rien d'exclu » en silence.
    pub fn parse(s: &str) -> Option<Exclusions> {
        // `a - b` s'écrit aussi avec des espaces : on les retire autour du tiret
        // avant de découper sur les espaces.
        let mut compact = String::with_capacity(s.len());
        for c in s.chars() {
            if c.is_whitespace() && compact.ends_with('-') {
                continue;
            }
            if c == '-' {
                while compact.ends_with(char::is_whitespace) {
                    compact.pop();
                }
            }
            compact.push(c);
        }
        let mut out = Vec::new();
        for item in compact.split(|c: char| c == ',' || c.is_whitespace()).filter(|t| !t.is_empty()) {
            let (first, last) = item.split_once('-').unwrap_or((item, item));
            let first = u32::from(first.parse::<Ipv4Addr>().ok()?);
            // Forme courte `10.0.20.2-10` : la fin ne donne que le dernier octet.
            let last = match last.parse::<u8>() {
                Ok(octet) if last.bytes().all(|b| b.is_ascii_digit()) => (first & !0xff) | u32::from(octet),
                _ => u32::from(last.parse::<Ipv4Addr>().ok()?),
            };
            if first > last {
                return None;
            }
            out.push((first, last));
        }
        Some(Exclusions(out))
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let n = u32::from(ip);
        self.0.iter().any(|&(first, last)| first <= n && n <= last)
    }

    /// Première adresse non exclue à partir de `n` (comprise), `None` au-delà
    /// de 255.255.255.255. Saute une plage d'un coup : jamais une boucle sur
    /// des millions d'adresses.
    pub fn next_free(&self, mut n: u32) -> Option<u32> {
        while let Some(&(_, last)) = self.0.iter().find(|&&(first, last)| first <= n && n <= last) {
            n = last.checked_add(1)?;
        }
        Some(n)
    }

    /// Ces exclusions, plus les adresses `ips` (celles des caméras connues du
    /// compte) : la recherche d'IP libres et le plan en lot les sautent pareil.
    pub fn with_addresses(&self, ips: impl IntoIterator<Item = Ipv4Addr>) -> Exclusions {
        let mut out = self.clone();
        out.0.extend(ips.into_iter().map(|a| (u32::from(a), u32::from(a))));
        out
    }

    /// Forme enregistrée : `a`, `a-b`, séparés par `, `.
    fn normalized(&self) -> Option<String> {
        let items: Vec<String> = self
            .0
            .iter()
            .map(|&(first, last)| match first == last {
                true => Ipv4Addr::from(first).to_string(),
                // Même /24 : forme courte `a.b.c.d-N`, comme on la saisit.
                false if first >> 8 == last >> 8 => format!("{}-{}", Ipv4Addr::from(first), last & 0xff),
                false => format!("{}-{}", Ipv4Addr::from(first), Ipv4Addr::from(last)),
            })
            .collect();
        (!items.is_empty()).then(|| items.join(", "))
    }
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
        let exclusions = match &self.exclusions {
            None => None,
            Some(s) => Exclusions::parse(s).ok_or(AccountError::InvalidExclusions)?.normalized(),
        };
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
            exclusions,
        })
    }

    /// Adresses exclues du compte. Un champ illisible (fichier retouché à la
    /// main, jamais passé par `validated`) n'exclut rien.
    pub fn excluded(&self) -> Exclusions {
        self.exclusions.as_deref().and_then(Exclusions::parse).unwrap_or_default()
    }

    /// Import : comme `validated`, mais une passerelle incohérente (ancien
    /// réseau saisi à la main, hors de celui de l'IP du PC) est écartée au
    /// lieu de faire refuser le fichier. `true` quand elle l'a été.
    fn validated_for_import(&self) -> Result<(AccountNetwork, bool), AccountError> {
        match self.validated() {
            Err(AccountError::InvalidGateway | AccountError::GatewayOutsideNetwork) => {
                let without = AccountNetwork { gateway: None, ..self.clone() };
                Ok((without.validated()?, true))
            }
            r => r.map(|n| (n, false)),
        }
    }

    fn fields(&self) -> [&Option<String>; 4] {
        [&self.pc_ip, &self.network, &self.gateway, &self.exclusions]
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
            (&mut merged.exclusions, &imported.exclusions),
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
            exclusions: field("exclusions"),
        }
    }

    /// Champs présents ajoutés à un objet JSON (fichier, export).
    fn write_into(&self, a: &mut serde_json::Value) {
        for (key, value) in [
            ("pc_ip", &self.pc_ip),
            ("network", &self.network),
            ("gateway", &self.gateway),
            ("exclusions", &self.exclusions),
        ] {
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
            exclusions: field("exclusions")?,
        })
    }
}

/// Caméra que LenScout a vue ou adressée avec un compte : son adresse n'est
/// plus proposée comme libre, même caméra éteinte. Rien de secret : adresse,
/// identité, modèle, date. Clé : le n° de série, sinon la MAC (une caméra
/// sans l'un ni l'autre n'est pas retenue : on ne la reconnaîtrait pas).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct KnownCamera {
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Dernière vue, en secondes depuis l'époque Unix.
    pub last_seen: u64,
}

impl KnownCamera {
    /// La caméra `cam`, vue (ou posée) en `ip` à l'instant `at`.
    pub fn of(cam: &crate::model::Camera, ip: Ipv4Addr, at: u64) -> KnownCamera {
        KnownCamera { ip, serial: cam.serial.clone(), mac: cam.mac.clone(), model: cam.model.clone(), last_seen: at }
    }

    /// Champs vides retirés, MAC en majuscules ; `None` sans n° de série ni MAC.
    fn normalized(mut self) -> Option<KnownCamera> {
        let clean = |f: Option<String>| f.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        self.serial = clean(self.serial);
        self.mac = clean(self.mac).map(|m| m.to_uppercase());
        self.model = clean(self.model);
        (self.serial.is_some() || self.mac.is_some()).then_some(self)
    }

    /// Le n° de série, sinon la MAC.
    pub fn key(&self) -> String {
        self.serial.clone().or_else(|| self.mac.clone()).unwrap_or_default()
    }

    /// Même caméra : même n° de série (casse ignorée) quand les deux en ont
    /// un, sinon même MAC.
    fn same_as(&self, other: &KnownCamera) -> bool {
        match (&self.serial, &other.serial) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => self.mac.is_some() && self.mac == other.mac,
        }
    }
}

/// Secondes depuis l'époque Unix : la date de dernière vue d'une caméra.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Ajoute `incoming` à `list` ou met à jour sa ligne (jamais de doublon : une
/// caméra qui change d'adresse libère l'ancienne). La ligne n'est remplacée
/// que si `incoming` est plus récente (`ties` : ou du même instant) ; ce que
/// `incoming` ne dit pas (MAC, modèle…) reste. Rend `true` si `list` change.
fn merge_camera(list: &mut Vec<KnownCamera>, incoming: KnownCamera, ties: bool) -> bool {
    let Some(incoming) = incoming.normalized() else { return false };
    let Some(mine) = list.iter_mut().find(|c| c.same_as(&incoming)) else {
        list.push(incoming);
        return true;
    };
    if incoming.last_seen < mine.last_seen || (incoming.last_seen == mine.last_seen && !ties) {
        return false;
    }
    let merged = KnownCamera {
        serial: incoming.serial.or(mine.serial.take()),
        mac: incoming.mac.or(mine.mac.take()),
        model: incoming.model.or(mine.model.take()),
        ..incoming
    };
    let changed = *mine != merged;
    *mine = merged;
    changed
}

/// Fusion d'un import : par caméra, la ligne la plus récente gagne.
fn merge_cameras(list: &mut Vec<KnownCamera>, incoming: Vec<KnownCamera>) -> bool {
    incoming.into_iter().fold(false, |changed, c| merge_camera(list, c, false) | changed)
}

/// Caméras lues dans un objet JSON (carnet, import) : une ligne illisible est
/// ignorée, comme un champ qui n'est pas une liste — une mémoire, jamais une
/// raison de perdre un compte.
fn read_cameras(a: &serde_json::Value) -> Vec<KnownCamera> {
    let mut out = Vec::new();
    for c in a.get("cameras").and_then(|v| v.as_array()).into_iter().flatten() {
        if let Ok(cam) = serde_json::from_value::<KnownCamera>(c.clone()) {
            merge_camera(&mut out, cam, false);
        }
    }
    out
}

/// Appareils relevés lus dans un objet JSON du carnet : une ligne illisible
/// est ignorée, comme un champ qui n'est pas une liste.
fn read_devices(a: &serde_json::Value) -> Vec<SeenDevice> {
    let mut out = Vec::new();
    let seen = a.get("devices").and_then(|v| v.as_array()).into_iter().flatten();
    let list: Vec<SeenDevice> = seen.filter_map(|d| serde_json::from_value(d.clone()).ok()).collect();
    crate::site_survey::device::merge_devices(&mut out, list);
    out
}

/// Adresse réservée à la main dans le réseau d'un compte : une caméra posée
/// là mais pas encore joignable (switch pas configuré), donc absente des
/// relevés. Comptée prise partout (barre, IP libres, feuilles) jusqu'à
/// « Libérer », ou jusqu'à ce qu'un relevé l'entende (`record_survey`) :
/// l'appareil relevé porte alors l'adresse. Distincte des exclusions, qui
/// sont les plages données par le client.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ReservedIp {
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Date de la réservation, en secondes depuis l'époque Unix.
    pub at: u64,
}

/// Réservations lues dans un objet JSON (carnet, import) : une ligne
/// illisible est ignorée, une adresse en double aussi (la première reste).
fn read_reservations(a: &serde_json::Value) -> Vec<ReservedIp> {
    let mut out: Vec<ReservedIp> = Vec::new();
    for r in a.get("reserved").and_then(|v| v.as_array()).into_iter().flatten() {
        if let Ok(r) = serde_json::from_value::<ReservedIp>(r.clone()) {
            if !out.iter().any(|o| o.ip == r.ip) {
                out.push(r);
            }
        }
    }
    out.sort_by_key(|r| u32::from(r.ip));
    out
}

/// Ajoute à `list` les réservations d'`incoming` dont l'adresse n'y est pas ;
/// une réservation déjà là garde son libellé et sa date. `true` si `list` change.
fn merge_reservations(list: &mut Vec<ReservedIp>, incoming: Vec<ReservedIp>) -> bool {
    let before = list.len();
    for r in incoming {
        if !list.iter().any(|o| o.ip == r.ip) {
            list.push(r);
        }
    }
    list.sort_by_key(|r| u32::from(r.ip));
    list.len() != before
}

/// Au-delà, un appareil relevé qui n'a plus répondu ne compte plus pris :
/// matériel démonté depuis longtemps, son adresse redevient proposable. Il
/// reste dans l'inventaire (« Oublier » le retire).
pub const STALE_DEVICE_SECS: u64 = 180 * 24 * 3600;

/// Les appareils relevés qui comptent encore pris à l'instant `now` : vus il
/// y a au plus `STALE_DEVICE_SECS`.
pub fn current_devices(devices: &[SeenDevice], now: u64) -> Vec<SeenDevice> {
    devices.iter().filter(|d| now.saturating_sub(d.last_seen) <= STALE_DEVICE_SECS).cloned().collect()
}

/// Ce qu'occupe une portion de la barre du réseau d'un compte.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SegmentKind {
    Gateway,
    Pc,
    Excluded,
    Reserved,
    Camera,
    Device,
}

/// `first`..=`last` : décalages depuis l'adresse de réseau (0 = le réseau).
#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct Segment {
    pub kind: SegmentKind,
    pub first: u32,
    pub last: u32,
}

/// Remplissage du réseau d'un compte. `usable` = adresses d'hôte (sans réseau
/// ni diffusion) ; chacune n'est comptée qu'une fois, dans cet ordre :
/// passerelle, PC, exclues, réservées, caméras connues, appareils, libres.
#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct NetworkFill {
    pub network: String,
    /// Adresses du réseau, réseau et diffusion compris : l'échelle de la barre.
    pub size: u32,
    pub usable: u32,
    pub gateway: u32,
    pub pc: u32,
    pub excluded: u32,
    /// Réservées à la main (`ReservedIp`), hors passerelle, PC et exclues.
    pub reserved: u32,
    pub cameras: u32,
    pub free: u32,
    /// Moins de 10 % d'adresses libres.
    pub almost_full: bool,
    /// Triés par adresse.
    pub segments: Vec<Segment>,
    /// Appareils relevés (réseau du compte), hors caméras connues,
    /// passerelle, PC et exclues.
    pub devices: u32,
    /// Part des adresses prises (exclues comprises), en %, arrondie vers le bas.
    pub used_pct: u8,
    /// `used_pct` ≥ 80 : un masque plus large est proposé.
    pub crowded: bool,
    /// Le plus petit élargissement qui ramène l'occupation à 50 % ou moins
    /// (`192.168.0.0/23`) ; seulement si `crowded`.
    pub suggest: Option<String>,
}


/// Seuil « bientôt complet » : moins d'une adresse libre sur dix.
const ALMOST_FULL_RATIO: u32 = 10;
/// Occupation à partir de laquelle un masque plus large est proposé.
const CROWDED_PCT: u8 = 80;
/// Occupation visée par l'élargissement proposé.
const SUGGEST_TARGET_PCT: u64 = 50;
/// Plus large réseau proposé.
const SUGGEST_WIDEST: u8 = 16;

/// Le plus petit réseau plus large que `base/prefix` (/n-1, /n-2… jusqu'à
/// /16) où `used` adresses prises font 50 % ou moins des adresses d'hôte :
/// `192.168.0.0/23`. `None` si même un /16 n'y suffit pas.
pub fn suggest_network(base: Ipv4Addr, prefix: u8, used: u32) -> Option<String> {
    (SUGGEST_WIDEST..prefix).rev().find_map(|p| {
        let usable = (1u64 << (32 - u32::from(p))) - 2;
        (u64::from(used) * 100 <= usable * SUGGEST_TARGET_PCT)
            .then(|| format!("{}/{p}", Ipv4Addr::from(u32::from(base) & mask_bits(p))))
    })
}

/// Suites d'adresses consécutives (triées, sans doublon) : une portion chacune.
fn runs(sorted: &[u32]) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for n in sorted.iter().copied() {
        match out.last_mut() {
            Some((_, end)) if *end + 1 == n => *end = n,
            _ => out.push((n, n)),
        }
    }
    out
}

/// Remplissage du réseau de `net` avec les caméras `cameras` ; `own` : les
/// adresses actuelles des caméras qu'on est en train de réadresser, libres
/// pour elles (comme dans la recherche d'IP libres). `None` sans IP du PC.
pub fn network_fill(net: &AccountNetwork, cameras: &[KnownCamera], own: &[Ipv4Addr]) -> Option<NetworkFill> {
    network_fill_with(net, cameras, &[], own)
}

/// `network_fill`, plus les appareils relevés sur le réseau du compte : un
/// appareil compte comme une caméra connue (pris, même absent du dernier
/// relevé), une seule fois par adresse.
pub fn network_fill_with(net: &AccountNetwork, cameras: &[KnownCamera], devices: &[SeenDevice], own: &[Ipv4Addr]) -> Option<NetworkFill> {
    network_fill_full(net, cameras, devices, &[], own)
}

/// `network_fill_with`, plus les adresses réservées `reserved` : prises comme
/// des exclues (une adresse qu'on réadresse ne les libère pas), comptées
/// avant les caméras et les appareils.
pub fn network_fill_full(
    net: &AccountNetwork,
    cameras: &[KnownCamera],
    devices: &[SeenDevice],
    reserved: &[Ipv4Addr],
    own: &[Ipv4Addr],
) -> Option<NetworkFill> {
    let (pc, prefix) = parse_cidr(net.pc_ip.as_deref()?.trim())?;
    let mask = mask_bits(prefix);
    let base = u32::from(pc) & mask;
    let size = (!mask).checked_add(1)?;
    // /31, /32 : refusés par `validated`, rien à mesurer.
    if size < 4 {
        return None;
    }
    let (first, last) = (base + 1, base + size - 2);
    let host = |n: u32| (first..=last).contains(&n);
    let gw = net.gateway.as_deref().and_then(|g| g.parse::<Ipv4Addr>().ok()).map(u32::from).filter(|&g| host(g));
    let pc = Some(u32::from(pc)).filter(|&p| host(p));
    // Plages exclues bornées au réseau et fusionnées : jamais dépliées.
    let mut ranges: Vec<(u32, u32)> = net
        .excluded()
        .0
        .into_iter()
        .filter(|&(a, b)| b >= first && a <= last)
        .map(|(a, b)| (a.max(first), b.min(last)))
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::new();
    for (a, b) in ranges {
        match merged.last_mut() {
            Some((_, end)) if a <= end.saturating_add(1) => *end = (*end).max(b),
            _ => merged.push((a, b)),
        }
    }
    let in_ex = |n: u32| merged.iter().any(|&(a, b)| a <= n && n <= b);
    let special = [gw, pc];
    let excluded: u32 = merged.iter().map(|&(a, b)| b - a + 1).sum::<u32>()
        - special.iter().flatten().filter(|&&n| in_ex(n)).count() as u32;
    let mut held: Vec<u32> =
        reserved.iter().map(|&a| u32::from(a)).filter(|&n| host(n) && !in_ex(n) && !special.contains(&Some(n))).collect();
    held.sort_unstable();
    held.dedup();
    let is_held = |n: u32| held.binary_search(&n).is_ok();
    // Caméras connues, plus celles que le relevé a reconnues comme caméras.
    let surveyed = devices.iter().filter(|d| d.kind == DeviceKind::Camera).map(|d| d.ip);
    let mut cams: Vec<u32> = cameras
        .iter()
        .map(|c| c.ip)
        .chain(surveyed)
        .map(u32::from)
        .filter(|&n| host(n) && !in_ex(n) && !is_held(n) && !special.contains(&Some(n)) && !own.contains(&Ipv4Addr::from(n)))
        .collect();
    cams.sort_unstable();
    cams.dedup();
    let mut devs: Vec<u32> = devices
        .iter()
        .map(|d| u32::from(d.ip))
        .filter(|&n| {
            host(n)
                && !in_ex(n)
                && !is_held(n)
                && !special.contains(&Some(n))
                && !own.contains(&Ipv4Addr::from(n))
                && cams.binary_search(&n).is_err()
        })
        .collect();
    devs.sort_unstable();
    devs.dedup();
    let (n_gw, n_pc) = (gw.is_some() as u32, pc.is_some() as u32);
    let usable = size - 2;
    let free = usable - n_gw - n_pc - excluded - held.len() as u32 - cams.len() as u32 - devs.len() as u32;
    let used = usable - free;
    let used_pct = (u64::from(used) * 100 / u64::from(usable)) as u8;
    let crowded = used_pct >= CROWDED_PCT;

    let mut segments: Vec<Segment> = Vec::new();
    let mut push = |kind, a: u32, b: u32| segments.push(Segment { kind, first: a - base, last: b - base });
    gw.into_iter().for_each(|g| push(SegmentKind::Gateway, g, g));
    pc.into_iter().for_each(|p| push(SegmentKind::Pc, p, p));
    merged.iter().for_each(|&(a, b)| push(SegmentKind::Excluded, a, b));
    runs(&held).into_iter().for_each(|(a, b)| push(SegmentKind::Reserved, a, b));
    // Caméras (puis appareils) consécutives : une seule portion.
    runs(&cams).into_iter().for_each(|(a, b)| push(SegmentKind::Camera, a, b));
    runs(&devs).into_iter().for_each(|(a, b)| push(SegmentKind::Device, a, b));
    segments.sort_by_key(|s| s.first);
    Some(NetworkFill {
        network: format!("{}/{prefix}", Ipv4Addr::from(base)),
        size,
        usable,
        gateway: n_gw,
        pc: n_pc,
        excluded,
        reserved: held.len() as u32,
        cameras: cams.len() as u32,
        free,
        almost_full: free * ALMOST_FULL_RATIO < usable,
        segments,
        devices: devs.len() as u32,
        used_pct,
        crowded,
        suggest: if crowded { suggest_network(Ipv4Addr::from(base), prefix, used) } else { None },
    })
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
    // Le compte existe mais n'a pas de mot de passe (ancien format, import
    // sans mot de passe) : à ressaisir.
    #[error("mot de passe absent")]
    SecretMissing,
    #[error("nom déjà utilisé")]
    DuplicateName,
    #[error("champ vide")]
    EmptyField,
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
    // Une adresse ou une plage `a.b.c.d-a.b.c.e` illisible, ou à l'envers.
    #[error("IP exclues illisibles")]
    InvalidExclusions,
}

#[derive(Clone)]
struct Entry {
    account: Account,
    // Absent : compte à ressaisir (« Mot de passe à ressaisir »).
    password: Option<Secret>,
    // Caméras vues ou adressées avec ce compte (voir `KnownCamera`).
    cameras: Vec<KnownCamera>,
    // Réseau du compte : appareils relevés et date du dernier relevé. Hors
    // de l'export : l'inventaire se refait sur place en quelques secondes.
    devices: Vec<SeenDevice>,
    surveyed_at: Option<u64>,
    // Adresses réservées à la main (voir `ReservedIp`), rangées par adresse.
    reservations: Vec<ReservedIp>,
}

pub struct AccountBook {
    path: PathBuf,
    entries: Vec<Entry>,
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
pub fn load_or_quarantine(path: PathBuf) -> (AccountBook, Startup) {
    if let Ok(book) = AccountBook::load(path.clone()) {
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
    /// Passerelle du fichier écartée : hors du réseau de l'IP du PC.
    pub gateway_dropped: bool,
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
    gateway_dropped: bool,
    cameras: Vec<KnownCamera>,
    reservations: Vec<ReservedIp>,
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
        let (net, gateway_dropped) = AccountNetwork::read_from(a)
            .ok_or_else(invalid)?
            .validated_for_import()
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
            gateway_dropped,
            cameras: read_cameras(a),
            reservations: read_reservations(a),
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
    /// Lit le fichier : format 2 (scellé) ou format 1 (tableau, login en
    /// clair, mot de passe hors du fichier). Les comptes du format 1 sont
    /// listés « à ressaisir » ; le fichier n'est pas réécrit au chargement,
    /// il passe au format 2 au premier enregistrement.
    pub fn load(path: PathBuf) -> Result<Self, AccountError> {
        let io = |e: String| AccountError::Io(e);
        let mut book = AccountBook {
            path,
            entries: Vec::new(),
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
            book.entries = legacy
                .into_iter()
                .map(|account| Entry {
                    account,
                    password: None,
                    cameras: Vec::new(),
                    devices: Vec::new(),
                    surveyed_at: None,
                    reservations: Vec::new(),
                })
                .collect();
            return Ok(book);
        }
        if v["version"] != 2 {
            return Err(io("version de fichier inconnue".into()));
        }
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
            let entry = Entry {
                account: Account {
                    id: field("id")?,
                    name: field("name")?,
                    login: text("login")?,
                    net: AccountNetwork::read_lenient(a),
                },
                password: Some(Secret::new(text("password")?)).filter(|p| !p.expose().is_empty()),
                cameras: read_cameras(a),
                devices: read_devices(a),
                surveyed_at: a.get("surveyed_at").and_then(serde_json::Value::as_u64),
                reservations: read_reservations(a),
            };
            book.entries.push(entry);
        }
        Ok(book)
    }

    /// Fusion des comptes d'un autre carnet (celui de l'ancien identifiant,
    /// posé à côté par la migration) : chaque compte dont l'id manque est
    /// ajouté, sous un nom libre si le sien est pris (« Nom 2 ») ; un id déjà
    /// présent garde le compte de ce carnet. Rend le nombre de comptes
    /// ajoutés. Tout ou rien : un échec d'écriture laisse le carnet intact.
    /// Autre carnet illisible : `ImportInvalid`.
    pub fn absorb(&mut self, path: &std::path::Path) -> Result<usize, AccountError> {
        let other = AccountBook::load(path.to_path_buf()).map_err(|_| AccountError::ImportInvalid)?;
        let mut next = self.entries.clone();
        let mut added = 0;
        for mut entry in other.entries {
            if next.iter().any(|e| e.account.id == entry.account.id) {
                continue;
            }
            if position_of(&next, &entry.account.name).is_some() {
                let base = entry.account.name.clone();
                entry.account.name = (2..)
                    .map(|n| format!("{base} {n}"))
                    .find(|candidate| position_of(&next, candidate).is_none())
                    .expect("suffixe libre");
            }
            next.push(entry);
            added += 1;
        }
        if added > 0 {
            self.write(&next)?;
            self.entries = next;
        }
        Ok(added)
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
            cameras: Vec::new(),
            devices: Vec::new(),
            surveyed_at: None,
            reservations: Vec::new(),
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
                if !e.cameras.is_empty() {
                    a["cameras"] = serde_json::to_value(&e.cameras).expect("json");
                }
                // Décision de l'installateur, comme les exclusions : elle voyage.
                if !e.reservations.is_empty() {
                    a["reserved"] = serde_json::to_value(&e.reservations).expect("json");
                }
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
                gateway_dropped: imp.gateway_dropped,
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
        let mut cameras_changed = false;
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
                cameras: imp.cameras,
                devices: Vec::new(),
                surveyed_at: None,
                reservations: imp.reservations,
            };
            let Some(i) = position_of(&next, &imp.name) else {
                next.push(fresh(imp.name.clone(), imp));
                summary.added += 1;
                continue;
            };
            if classify(&next[i], &imp) == ImportKind::Identical {
                // Un compte identique reçoit quand même les caméras et réservations du fichier.
                cameras_changed |= merge_cameras(&mut next[i].cameras, imp.cameras);
                cameras_changed |= merge_reservations(&mut next[i].reservations, imp.reservations);
                summary.identical += 1;
                continue;
            }
            match choices.get(&imp.name).copied().unwrap_or(Choice::Replace) {
                Choice::Replace => {
                    next[i].account.name = imp.name;
                    next[i].account.login = imp.login;
                    next[i].account.net.merge(imp.net);
                    cameras_changed |= merge_cameras(&mut next[i].cameras, imp.cameras);
                    cameras_changed |= merge_reservations(&mut next[i].reservations, imp.reservations);
                    if imp.password.is_some() {
                        next[i].password = imp.password;
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
        if summary.added + summary.replaced + summary.kept_both > 0 || cameras_changed {
            self.write(&next)?;
            self.entries = next;
        }
        Ok(summary)
    }

    pub fn known_cameras(&self, id: &str) -> Result<Vec<KnownCamera>, AccountError> {
        Ok(self.entries[self.index_of(id)?].cameras.clone())
    }

    /// Caméras dont LenScout vient de poser l'adresse avec ce compte : retenues
    /// quel que soit le réseau saisi (il peut changer, ou manquer).
    pub fn remember(&mut self, id: &str, seen: Vec<KnownCamera>) -> Result<(), AccountError> {
        let index = self.index_of(id)?;
        let mut next = self.entries.clone();
        let mut changed = false;
        for cam in seen {
            changed |= merge_camera(&mut next[index].cameras, cam, true);
        }
        if changed {
            self.write(&next)?;
            self.entries = next;
        }
        Ok(())
    }

    /// Caméras vues au scan avec ce compte : seules celles du réseau du compte
    /// sont retenues (un compte sans IP du PC n'en retient aucune). Rend le
    /// nombre de caméras du réseau.
    pub fn remember_seen(&mut self, id: &str, seen: Vec<KnownCamera>) -> Result<usize, AccountError> {
        let net = &self.entries[self.index_of(id)?].account.net;
        let Some(scope) = net.pc_ip.as_deref().and_then(|p| parse_cidr(p.trim())) else { return Ok(0) };
        let inside: Vec<KnownCamera> = seen.into_iter().filter(|c| contains(scope, c.ip) && is_host(c.ip, scope.1)).collect();
        let n = inside.len();
        self.remember(id, inside)?;
        Ok(n)
    }

    /// Oublie la caméra de clé `key` (n° de série, sinon MAC, comme
    /// `KnownCamera::key`). `NotFound` : compte ou caméra inconnus.
    pub fn forget_camera(&mut self, id: &str, key: &str) -> Result<(), AccountError> {
        let index = self.index_of(id)?;
        let at = self.entries[index].cameras.iter().position(|c| c.key() == key).ok_or(AccountError::NotFound)?;
        let mut next = self.entries.clone();
        next[index].cameras.remove(at);
        self.write(&next)?;
        self.entries = next;
        Ok(())
    }

    /// Remplissage du réseau du compte (voir `network_fill`) ; `None` sans IP du PC.
    /// Retient un relevé du réseau du compte, daté `at` : fusion par appareil
    /// (`merge_devices`). Un appareil absent du relevé reste, compté pris,
    /// jusqu'à `forget_device`. Une adresse réservée qui répond n'est plus
    /// réservée : l'appareil relevé la porte désormais.
    pub fn record_survey(&mut self, id: &str, seen: Vec<SeenDevice>, at: u64) -> Result<(), AccountError> {
        let index = self.index_of(id)?;
        let mut next = self.entries.clone();
        next[index].reservations.retain(|r| !seen.iter().any(|d| d.ip == r.ip));
        crate::site_survey::device::merge_devices(&mut next[index].devices, seen);
        next[index].surveyed_at = Some(at);
        self.write(&next)?;
        self.entries = next;
        Ok(())
    }

    /// Inventaire du compte et date du dernier relevé (`None` : jamais relevé).
    pub fn devices(&self, id: &str) -> Result<(Vec<SeenDevice>, Option<u64>), AccountError> {
        let e = &self.entries[self.index_of(id)?];
        Ok((e.devices.clone(), e.surveyed_at))
    }

    /// Oublie l'appareil de clé `key` (MAC, sinon IP, comme `device_key` ;
    /// casse ignorée). `NotFound` : compte ou appareil inconnus.
    pub fn forget_device(&mut self, id: &str, key: &str) -> Result<(), AccountError> {
        let index = self.index_of(id)?;
        let key = key.trim().to_uppercase();
        let at = self.entries[index]
            .devices
            .iter()
            .position(|d| crate::site_survey::device::device_key(d) == key)
            .ok_or(AccountError::NotFound)?;
        let mut next = self.entries.clone();
        next[index].devices.remove(at);
        self.write(&next)?;
        self.entries = next;
        Ok(())
    }

    /// Vide tout l'inventaire relevé du compte et oublie la date du dernier
    /// relevé : on repart à zéro avant un nouveau scan (les réservations
    /// manuelles sont conservées). `NotFound` : compte inconnu.
    pub fn forget_all_devices(&mut self, id: &str) -> Result<(), AccountError> {
        let index = self.index_of(id)?;
        let mut next = self.entries.clone();
        next[index].devices.clear();
        next[index].surveyed_at = None;
        self.write(&next)?;
        self.entries = next;
        Ok(())
    }

    /// Appareils relevés vus depuis moins de `STALE_DEVICE_SECS` et adresses
    /// réservées comprises.
    pub fn fill(&self, id: &str, own: &[Ipv4Addr]) -> Result<Option<NetworkFill>, AccountError> {
        let e = &self.entries[self.index_of(id)?];
        let devices = current_devices(&e.devices, unix_now());
        let reserved: Vec<Ipv4Addr> = e.reservations.iter().map(|r| r.ip).collect();
        Ok(network_fill_full(&e.account.net, &e.cameras, &devices, &reserved, own))
    }

    /// Adresses réservées du compte, rangées par adresse.
    pub fn reservations(&self, id: &str) -> Result<Vec<ReservedIp>, AccountError> {
        Ok(self.entries[self.index_of(id)?].reservations.clone())
    }

    /// Réserve `ip` (libellé facultatif, `at` : la date). Déjà réservée : le
    /// libellé change, la date reste.
    pub fn reserve(&mut self, id: &str, ip: Ipv4Addr, label: Option<&str>, at: u64) -> Result<(), AccountError> {
        let index = self.index_of(id)?;
        let label = label.map(str::trim).filter(|l| !l.is_empty()).map(str::to_string);
        let mut next = self.entries.clone();
        let list = &mut next[index].reservations;
        match list.iter_mut().find(|r| r.ip == ip) {
            Some(r) => r.label = label,
            None => {
                list.push(ReservedIp { ip, label, at });
                list.sort_by_key(|r| u32::from(r.ip));
            }
        }
        self.write(&next)?;
        self.entries = next;
        Ok(())
    }

    /// Libère `ip`. `NotFound` : compte inconnu ou adresse non réservée.
    pub fn release(&mut self, id: &str, ip: Ipv4Addr) -> Result<(), AccountError> {
        let index = self.index_of(id)?;
        let at = self.entries[index].reservations.iter().position(|r| r.ip == ip).ok_or(AccountError::NotFound)?;
        let mut next = self.entries.clone();
        next[index].reservations.remove(at);
        self.write(&next)?;
        self.entries = next;
        Ok(())
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
                e.account.net.write_into(&mut a);
                if !e.cameras.is_empty() {
                    a["cameras"] = serde_json::to_value(&e.cameras).expect("json");
                }
                if !e.devices.is_empty() {
                    a["devices"] = serde_json::to_value(&e.devices).expect("json");
                }
                if let Some(at) = e.surveyed_at {
                    a["surveyed_at"] = at.into();
                }
                if !e.reservations.is_empty() {
                    a["reserved"] = serde_json::to_value(&e.reservations).expect("json");
                }
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
    use crate::site_survey::device::DeviceKind;

    const PWD: &str = "S3cr3t-Unique!";

    struct Fixture {
        dir: PathBuf,
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
            Fixture { dir }
        }
        fn path(&self) -> PathBuf {
            self.dir.join("accounts.json")
        }
        fn book(&self) -> AccountBook {
            AccountBook::load(self.path()).unwrap()
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
            exclusions: None,
        }
    }

    fn with_exclusions(mut n: AccountNetwork, exclusions: &str) -> AccountNetwork {
        n.exclusions = Some(exclusions.to_string());
        n
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    // ---- IP exclues ----

    #[test]
    fn exclusions_read_addresses_and_ranges_split_by_commas_or_spaces() {
        let e = Exclusions::parse("192.168.1.10, 192.168.1.20-192.168.1.25 192.168.1.30 - 192.168.1.31,,").unwrap();
        for yes in ["192.168.1.10", "192.168.1.20", "192.168.1.22", "192.168.1.25", "192.168.1.30", "192.168.1.31"] {
            assert!(e.contains(ip(yes)), "{yes}");
        }
        for no in ["192.168.1.11", "192.168.1.19", "192.168.1.26", "192.168.1.32"] {
            assert!(!e.contains(ip(no)), "{no}");
        }
        // Rien de saisi : rien d'exclu.
        assert!(!Exclusions::parse("  ").unwrap().contains(ip("192.168.1.10")));
        assert!(!Exclusions::default().contains(ip("192.168.1.10")));
    }

    #[test]
    fn exclusions_read_the_short_form_with_the_last_octet() {
        let e = Exclusions::parse("10.0.20.2-10,10.0.20.100-150,10.0.20.199").unwrap();
        for yes in ["10.0.20.2", "10.0.20.6", "10.0.20.10", "10.0.20.100", "10.0.20.150", "10.0.20.199"] {
            assert!(e.contains(ip(yes)), "{yes}");
        }
        for no in ["10.0.20.1", "10.0.20.11", "10.0.20.99", "10.0.20.151", "10.0.20.198", "10.0.21.5"] {
            assert!(!e.contains(ip(no)), "{no}");
        }
        // Une plage sur plusieurs /24 garde la forme longue.
        let n = with_exclusions(no_net(), "10.0.20.250-10.0.21.5, 10.0.20.2-10.0.20.10");
        assert_eq!(n.validated().unwrap().exclusions.as_deref(), Some("10.0.20.250-10.0.21.5, 10.0.20.2-10"));
    }

    #[test]
    fn unreadable_exclusions_are_refused() {
        for bad in ["x", "192.168.1", "192.168.1.300", "192.168.1.100-50", "192.168.1.2-256", "192.168.1.2-+5", "192.168.1.20-192.168.1.10", "192.168.1.1-", "-192.168.1.1", "1.2.3.4-5-6", "10.0.0.0/24"] {
            assert!(Exclusions::parse(bad).is_none(), "{bad}");
            assert!(
                matches!(
                    with_exclusions(net("192.168.1.250/24", "", ""), bad).validated(),
                    Err(AccountError::InvalidExclusions)
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn exclusions_are_normalized_by_validated() {
        let n = with_exclusions(no_net(), "  192.168.1.10   192.168.1.20 - 192.168.1.25 ,192.168.1.30 ");
        assert_eq!(
            n.validated().unwrap().exclusions.as_deref(),
            Some("192.168.1.10, 192.168.1.20-25, 192.168.1.30")
        );
        // Vide ou blanc : champ absent.
        assert_eq!(with_exclusions(no_net(), " , ").validated().unwrap().exclusions, None);
    }

    #[test]
    fn exclusions_are_stored_and_reload() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let wanted = with_exclusions(net("192.168.1.250/24", "", "192.168.1.1"), "192.168.1.10-192.168.1.19");
        let acc = book.create("Mairie", "root", pwd(PWD), wanted).unwrap();
        assert!(fx.raw().contains("\"exclusions\": \"192.168.1.10-19\""));
        assert_eq!(fx.book().list()[0].net, acc.net);
        assert!(acc.net.excluded().contains(ip("192.168.1.15")));
    }

    #[test]
    fn older_file_without_exclusions_loads_and_writes_no_key() {
        let fx = Fixture::new();
        let file = serde_json::json!({"version": 2, "accounts": [{
            "id": "1", "name": "A", "pc_ip": "192.168.1.250/24", "gateway": "192.168.1.1",
            "login": seal::seal(b"root"), "password": seal::seal(PWD.as_bytes()),
        }]});
        std::fs::write(fx.path(), file.to_string()).unwrap();
        let book = fx.book();
        assert_eq!(book.list()[0].net.exclusions, None);
        assert!(!book.export().contains("exclusions"));
        // Désérialisé directement (commande du front) : le champ est facultatif.
        let n: AccountNetwork = serde_json::from_str(r#"{"pc_ip": "192.168.1.250/24"}"#).unwrap();
        assert_eq!(n.exclusions, None);
    }

    #[test]
    fn export_and_import_carry_exclusions() {
        let (mut src, _fx_src) = empty_book();
        let full = with_exclusions(net("192.168.1.250/24", "192.168.1.0/24", "192.168.1.1"), "192.168.1.2-9");
        src.create("Mairie", "root", pwd(PWD), full.clone()).unwrap();
        let data = src.export();
        assert!(data.contains("\"exclusions\": \"192.168.1.2-9\""));
        let (mut dst, _fx_dst) = empty_book();
        dst.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(dst.list()[0].net, full);
    }

    #[test]
    fn import_compares_and_merges_exclusions() {
        let (mut src, _fx_src) = empty_book();
        src.create("Mairie", "root", pwd(PWD), with_exclusions(no_net(), "10.0.0.5")).unwrap();
        let data = src.export();
        let (mut dst, _fx_dst) = empty_book();
        let mine = with_exclusions(net("10.0.0.250/24", "", "10.0.0.1"), "10.0.0.9");
        dst.create("Mairie", "root", pwd(PWD), mine).unwrap();
        assert_eq!(
            dst.import_plan(&data).unwrap().items[0].kind,
            ImportKind::Differs { login_differs: false, password_differs: false, network_differs: true }
        );
        dst.import_apply(&data, &HashMap::new()).unwrap();
        // Les exclusions du fichier remplacent les miennes, le reste du réseau reste.
        assert_eq!(dst.list()[0].net, with_exclusions(net("10.0.0.250/24", "10.0.0.0/24", "10.0.0.1"), "10.0.0.5"));
        // Un fichier sans exclusions ne vide pas celles du carnet.
        let (mut bare, _fx_bare) = empty_book();
        bare.create("Mairie", "root", pwd(PWD), no_net()).unwrap();
        let data = bare.export();
        assert_eq!(dst.import_plan(&data).unwrap().items[0].kind, ImportKind::Identical);
    }

    #[test]
    fn import_rejects_unreadable_exclusions() {
        let book = sample_book();
        let before = book.list();
        let data = serde_json::json!({
            "format": "lenscout-accounts", "version": 1,
            "accounts": [{"name": "X", "login": seal::seal(b"root"), "exclusions": "pas une ip"}],
        })
        .to_string();
        assert!(matches!(book.import_plan(&data), Err(AccountError::ImportInvalid)));
        assert_eq!(book.list(), before);
    }

    // ---- Caméras connues ----

    fn known(ip_: &str, serial: Option<&str>, mac: Option<&str>, at: u64) -> KnownCamera {
        KnownCamera {
            ip: ip(ip_),
            serial: serial.map(str::to_string),
            mac: mac.map(str::to_string),
            model: Some("P3245-LVE".into()),
            last_seen: at,
        }
    }

    fn site() -> AccountNetwork {
        with_exclusions(net("10.0.8.250/24", "", "10.0.8.1"), "10.0.8.2-9, 10.0.8.100")
    }

    #[test]
    fn a_known_camera_that_moves_keeps_one_line() {
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.remember(&acc.id, vec![known("10.0.8.20", Some("ACCC8E01"), Some("AC:CC:8E:00:00:01"), 100)]).unwrap();
        book.remember(&acc.id, vec![known("10.0.8.21", Some("accc8e01 "), None, 200)]).unwrap();
        let cams = book.known_cameras(&acc.id).unwrap();
        assert_eq!(cams.len(), 1);
        assert_eq!(cams[0].ip, ip("10.0.8.21"));
        assert_eq!(cams[0].last_seen, 200);
        // Ce que la nouvelle observation ne dit pas reste : la MAC.
        assert_eq!(cams[0].mac.as_deref(), Some("AC:CC:8E:00:00:01"));
    }

    #[test]
    fn a_camera_without_serial_is_known_by_its_mac_and_without_either_not_at_all() {
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.remember(&acc.id, vec![known("10.0.8.30", None, Some("ac:cc:8e:00:00:02"), 100)]).unwrap();
        book.remember(&acc.id, vec![known("10.0.8.31", None, Some("AC:CC:8E:00:00:02"), 200)]).unwrap();
        book.remember(&acc.id, vec![known("10.0.8.32", None, None, 200)]).unwrap();
        let cams = book.known_cameras(&acc.id).unwrap();
        assert_eq!(cams.len(), 1);
        assert_eq!((cams[0].ip, cams[0].key()), (ip("10.0.8.31"), "AC:CC:8E:00:00:02".to_string()));
        // Le n° de série appris plus tard devient la clé, sans doublon.
        book.remember(&acc.id, vec![known("10.0.8.31", Some("S1"), Some("AC:CC:8E:00:00:02"), 300)]).unwrap();
        let cams = book.known_cameras(&acc.id).unwrap();
        assert_eq!((cams.len(), cams[0].key()), (1, "S1".to_string()));
    }

    #[test]
    fn a_scan_only_feeds_cameras_of_the_account_network() {
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        let bare = book.create("Sans réseau", "root", pwd(PWD), no_net()).unwrap();
        let seen = vec![known("10.0.8.40", Some("A"), None, 1), known("192.168.0.90", Some("B"), None, 1)];
        assert_eq!(book.remember_seen(&acc.id, seen.clone()).unwrap(), 1);
        assert_eq!(book.known_cameras(&acc.id).unwrap()[0].ip, ip("10.0.8.40"));
        assert_eq!(book.remember_seen(&bare.id, seen).unwrap(), 0);
        assert!(book.known_cameras(&bare.id).unwrap().is_empty());
    }

    #[test]
    fn known_cameras_are_stored_and_reload_and_older_files_have_none() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        assert!(!fx.raw().contains("cameras"));
        book.remember(&acc.id, vec![known("10.0.8.20", Some("S1"), None, 100)]).unwrap();
        assert!(fx.raw().contains("\"cameras\""));
        assert_eq!(fx.book().known_cameras(&acc.id).unwrap(), vec![known("10.0.8.20", Some("S1"), None, 100)]);
        // Une ligne illisible est ignorée, jamais le carnet.
        let mut v: serde_json::Value = serde_json::from_str(&fx.raw()).unwrap();
        v["accounts"][0]["cameras"].as_array_mut().unwrap().push(serde_json::json!({"ip": "x"}));
        std::fs::write(fx.path(), v.to_string()).unwrap();
        assert_eq!(fx.book().known_cameras(&acc.id).unwrap().len(), 1);
        v["accounts"][0]["cameras"] = "pas une liste".into();
        std::fs::write(fx.path(), v.to_string()).unwrap();
        assert!(fx.book().known_cameras(&acc.id).unwrap().is_empty());
    }

    #[test]
    fn an_update_keeps_the_known_cameras() {
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.remember(&acc.id, vec![known("10.0.8.20", Some("S1"), None, 100)]).unwrap();
        book.update(&acc.id, "Site 2", "root", None, site()).unwrap();
        assert_eq!(book.known_cameras(&acc.id).unwrap().len(), 1);
    }

    #[test]
    fn a_known_camera_can_be_forgotten() {
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.remember(&acc.id, vec![known("10.0.8.20", Some("S1"), None, 1), known("10.0.8.21", None, Some("AA:BB:CC:00:00:01"), 1)]).unwrap();
        book.forget_camera(&acc.id, "AA:BB:CC:00:00:01").unwrap();
        assert_eq!(book.known_cameras(&acc.id).unwrap().len(), 1);
        assert!(matches!(book.forget_camera(&acc.id, "inconnue"), Err(AccountError::NotFound)));
        assert!(matches!(book.forget_camera("zzz", "S1"), Err(AccountError::NotFound)));
    }

    #[test]
    fn export_and_import_merge_known_cameras_the_latest_wins() {
        let (mut src, _fx_src) = empty_book();
        let a = src.create("Site", "root", pwd(PWD), site()).unwrap();
        src.remember(&a.id, vec![
            known("10.0.8.20", Some("S1"), None, 300),
            known("10.0.8.21", Some("S2"), None, 100),
            known("10.0.8.22", Some("S3"), None, 100),
        ]).unwrap();
        let data = src.export();
        assert!(data.contains("\"cameras\""));
        let (mut dst, _fx_dst) = empty_book();
        let b = dst.create("Site", "root", pwd(PWD), site()).unwrap();
        dst.remember(&b.id, vec![known("10.0.8.30", Some("S1"), None, 200), known("10.0.8.31", Some("S2"), None, 200)]).unwrap();
        // Comptes identiques par ailleurs : les caméras se fusionnent quand même.
        assert_eq!(dst.import_plan(&data).unwrap().items[0].kind, ImportKind::Identical);
        dst.import_apply(&data, &HashMap::new()).unwrap();
        let mut cams = dst.known_cameras(&b.id).unwrap();
        cams.sort_by_key(|c| c.key());
        let ips: Vec<_> = cams.iter().map(|c| (c.key(), c.ip)).collect();
        assert_eq!(ips, [("S1".into(), ip("10.0.8.20")), ("S2".into(), ip("10.0.8.31")), ("S3".into(), ip("10.0.8.22"))]);
        // Survit au rechargement ; un nouveau compte importé arrive avec ses caméras.
        let (mut fresh, _fx_fresh) = empty_book();
        fresh.import_apply(&data, &HashMap::new()).unwrap();
        let id = fresh.list()[0].id.clone();
        assert_eq!(fresh.known_cameras(&id).unwrap().len(), 3);
    }

    #[test]
    fn the_fill_counts_every_kind_of_address_once() {
        // /24 : 254 adresses. Passerelle .1, PC .250, exclues .2–.9 et .100 (9),
        // caméras .20, .21 et .100 (déjà exclue), .5 (exclue), une hors réseau.
        let cams = [
            known("10.0.8.20", Some("A"), None, 1),
            known("10.0.8.21", Some("B"), None, 1),
            known("10.0.8.100", Some("C"), None, 1),
            known("10.0.8.5", Some("D"), None, 1),
            known("192.168.0.90", Some("E"), None, 1),
        ];
        let f = network_fill(&site().validated().unwrap(), &cams, &[]).unwrap();
        assert_eq!(f.network, "10.0.8.0/24");
        assert_eq!((f.size, f.usable, f.gateway, f.pc, f.excluded, f.cameras, f.free), (256, 254, 1, 1, 9, 2, 241));
        assert!(!f.almost_full);
        let kinds: Vec<_> = f.segments.iter().map(|s| (s.kind, s.first, s.last)).collect();
        assert_eq!(
            kinds,
            [
                (SegmentKind::Gateway, 1, 1),
                (SegmentKind::Excluded, 2, 9),
                (SegmentKind::Camera, 20, 21),
                (SegmentKind::Excluded, 100, 100),
                (SegmentKind::Pc, 250, 250),
            ]
        );
        // L'adresse actuelle de la caméra qu'on modifie compte libre.
        let f = network_fill(&site().validated().unwrap(), &cams, &[ip("10.0.8.20")]).unwrap();
        assert_eq!((f.cameras, f.free), (1, 242));
        // Sans réseau : rien à mesurer.
        assert!(network_fill(&no_net(), &cams, &[]).is_none());
    }

    #[test]
    fn known_addresses_join_the_exclusions() {
        let ex = Exclusions::parse("10.0.8.2-9").unwrap().with_addresses([ip("10.0.8.20"), ip("10.0.8.21")]);
        assert!(ex.contains(ip("10.0.8.5")) && ex.contains(ip("10.0.8.21")) && !ex.contains(ip("10.0.8.22")));
        assert_eq!(ex.next_free(u32::from(ip("10.0.8.20"))), Some(u32::from(ip("10.0.8.22"))));
    }

    #[test]
    fn under_ten_percent_free_is_almost_full() {
        // /28 : 14 adresses ; PC .14, 12 caméras → 1 libre.
        let n = net("10.0.9.14/28", "", "").validated().unwrap();
        let cams: Vec<_> = (1..=12).map(|i| known(&format!("10.0.9.{i}"), Some(&format!("S{i}")), None, 1)).collect();
        let f = network_fill(&n, &cams, &[]).unwrap();
        assert_eq!((f.usable, f.cameras, f.free), (14, 12, 1));
        assert!(f.almost_full);
        let f = network_fill(&n, &cams[..10], &[]).unwrap();
        assert_eq!(f.free, 3);
        assert!(!f.almost_full);
        // Une grande plage exclue sur un /8 se compte sans être dépliée.
        let big = with_exclusions(net("10.0.0.250/8", "", ""), "10.0.0.0-10.255.255.255");
        let f = network_fill(&big.validated().unwrap(), &[], &[]).unwrap();
        assert_eq!((f.usable, f.excluded, f.free), (16_777_214, 16_777_213, 0));
    }

    // ---- Réseau du compte : inventaire relevé ----

    fn device(ip_: &str, mac: Option<&str>, at: u64) -> SeenDevice {
        SeenDevice { ip: ip(ip_), mac: mac.map(str::to_string), vendor: None, kind: DeviceKind::Unknown, name: None, model: None, first_seen: at, last_seen: at }
    }

    #[test]
    fn survey_is_saved_and_reloaded_with_its_date() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        assert_eq!(book.devices(&acc.id).unwrap(), (vec![], None));
        book.record_survey(&acc.id, vec![device("10.0.8.30", Some("AA:BB:CC:00:00:30"), 100)], 100).unwrap();
        book.record_survey(&acc.id, vec![device("10.0.8.31", None, 200)], 200).unwrap();
        let (list, at) = fx.book().devices(&acc.id).unwrap();
        assert_eq!(at, Some(200));
        // Absent du dernier relevé, l'appareil reste (jusqu'à « Oublier »).
        assert_eq!(list.iter().map(|d| (d.ip, d.last_seen)).collect::<Vec<_>>(), [(ip("10.0.8.30"), 100), (ip("10.0.8.31"), 200)]);
        assert!(matches!(book.record_survey("zzz", vec![], 1), Err(AccountError::NotFound)));
        // Un mot de passe reste scellé : rien du relevé n'y touche.
        assert!(!fx.raw().contains(PWD));
    }

    #[test]
    fn old_file_without_devices_loads() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        assert!(!fx.raw().contains("devices") && !fx.raw().contains("surveyed_at"));
        assert_eq!(fx.book().devices(&acc.id).unwrap(), (vec![], None));
    }

    #[test]
    fn bad_device_line_is_ignored_not_fatal() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.record_survey(&acc.id, vec![device("10.0.8.30", None, 1)], 1).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&fx.raw()).unwrap();
        v["accounts"][0]["devices"].as_array_mut().unwrap().push(serde_json::json!({"ip": "x", "kind": "camera"}));
        v["accounts"][0]["devices"].as_array_mut().unwrap().push(serde_json::json!({"ip": "10.0.8.31", "kind": "grille-pain", "first_seen": 1, "last_seen": 1}));
        std::fs::write(fx.path(), v.to_string()).unwrap();
        assert_eq!(fx.book().devices(&acc.id).unwrap().0.len(), 1);
        v["accounts"][0]["devices"] = "pas une liste".into();
        v["accounts"][0]["surveyed_at"] = "hier".into();
        std::fs::write(fx.path(), v.to_string()).unwrap();
        assert_eq!(fx.book().devices(&acc.id).unwrap(), (vec![], None));
    }

    #[test]
    fn export_never_contains_devices() {
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.record_survey(&acc.id, vec![device("10.0.8.30", Some("AA:BB:CC:00:00:30"), 1)], 1).unwrap();
        let data = book.export();
        assert!(!data.contains("devices") && !data.contains("surveyed_at") && !data.contains("AA:BB:CC:00:00:30"));
    }

    #[test]
    fn import_replace_keeps_local_devices() {
        let (mut src, _fx_src) = empty_book();
        src.create("Site", "admin", pwd(PWD), site()).unwrap();
        let data = src.export();
        let (mut dst, _fx_dst) = empty_book();
        let b = dst.create("Site", "root", pwd(PWD), site()).unwrap();
        dst.record_survey(&b.id, vec![device("10.0.8.30", None, 1)], 7).unwrap();
        assert!(matches!(dst.import_plan(&data).unwrap().items[0].kind, ImportKind::Differs { .. }));
        dst.import_apply(&data, &HashMap::new()).unwrap();
        assert_eq!(dst.list()[0].login, "admin");
        assert_eq!(dst.devices(&b.id).unwrap(), (vec![device("10.0.8.30", None, 1)], Some(7)));
    }

    #[test]
    fn forget_device_by_mac_or_ip() {
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.record_survey(&acc.id, vec![device("10.0.8.30", Some("AA:BB:CC:00:00:30"), 1), device("10.0.8.31", None, 1)], 1).unwrap();
        book.forget_device(&acc.id, "aa:bb:cc:00:00:30").unwrap();
        book.forget_device(&acc.id, "10.0.8.31").unwrap();
        assert!(book.devices(&acc.id).unwrap().0.is_empty());
        assert!(matches!(book.forget_device(&acc.id, "10.0.8.31"), Err(AccountError::NotFound)));
        assert!(matches!(book.forget_device("zzz", "x"), Err(AccountError::NotFound)));
    }

    #[test]
    fn forget_all_devices_clears_inventory_and_survey_date() {
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.record_survey(&acc.id, vec![device("10.0.8.30", None, 1), device("10.0.8.31", None, 1)], 9).unwrap();
        assert_eq!(book.devices(&acc.id).unwrap().1, Some(9));
        book.forget_all_devices(&acc.id).unwrap();
        let (devices, surveyed_at) = book.devices(&acc.id).unwrap();
        assert!(devices.is_empty());
        assert_eq!(surveyed_at, None);
        assert!(matches!(book.forget_all_devices("zzz"), Err(AccountError::NotFound)));
    }

    #[test]
    fn fill_counts_devices_once() {
        // Passerelle .1, PC .250, exclues .2–.9 et .100, caméra connue .20.
        let cams = [known("10.0.8.20", Some("A"), None, 1)];
        let devs = [
            device("10.0.8.1", None, 1),
            device("10.0.8.250", None, 1),
            device("10.0.8.5", None, 1),
            device("10.0.8.20", None, 1),
            device("10.0.8.40", None, 1),
            device("10.0.8.40", Some("AA:BB:CC:00:00:40"), 1),
            device("10.0.8.41", None, 1),
            device("192.168.0.9", None, 1),
        ];
        let f = network_fill_with(&site().validated().unwrap(), &cams, &devs, &[]).unwrap();
        assert_eq!((f.cameras, f.devices, f.free), (1, 2, 254 - 1 - 1 - 9 - 1 - 2));
        // Une adresse qu'on réadresse compte libre, appareil compris.
        let f = network_fill_with(&site().validated().unwrap(), &cams, &devs, &[ip("10.0.8.41")]).unwrap();
        assert_eq!(f.devices, 1);
    }

    #[test]
    fn fill_device_segments_are_merged_runs() {
        let devs: Vec<_> = ["10.0.8.40", "10.0.8.41", "10.0.8.42", "10.0.8.60"].iter().map(|a| device(a, None, 1)).collect();
        let f = network_fill_with(&net("10.0.8.250/24", "", "").validated().unwrap(), &[], &devs, &[]).unwrap();
        let segs: Vec<_> = f.segments.iter().filter(|s| s.kind == SegmentKind::Device).map(|s| (s.first, s.last)).collect();
        assert_eq!(segs, [(40, 42), (60, 60)]);
        assert_eq!(serde_json::to_value(SegmentKind::Device).unwrap(), "device");
    }

    #[test]
    fn used_pct_counts_excluded_as_taken() {
        // /24, PC .250, exclues .1–.100 : 101 prises sur 254 → 39 %.
        let n = with_exclusions(net("10.0.8.250/24", "", ""), "10.0.8.1-100").validated().unwrap();
        let f = network_fill_with(&n, &[], &[], &[]).unwrap();
        assert_eq!((f.free, f.used_pct, f.crowded, f.suggest.as_deref()), (153, 39, false, None));
    }

    #[test]
    fn crowded_at_80_percent() {
        // 204 prises sur 254 = 80,3 % ; 203 = 79,9 %.
        let n = |last: u8| with_exclusions(net("10.0.8.250/24", "", ""), &format!("10.0.8.1-{last}")).validated().unwrap();
        let f = network_fill_with(&n(203), &[], &[], &[]).unwrap();
        assert_eq!((f.used_pct, f.crowded), (80, true));
        assert_eq!(f.suggest.as_deref(), Some("10.0.8.0/23"));
        let f = network_fill_with(&n(202), &[], &[], &[]).unwrap();
        assert_eq!((f.used_pct, f.crowded, f.suggest), (79, false, None));
        // « Bientôt complet » reste sa propre règle.
        assert!(!f.almost_full);
    }

    #[test]
    fn suggest_23_for_180_used_in_a_24() {
        assert_eq!(suggest_network(ip("192.168.1.0"), 24, 180).as_deref(), Some("192.168.0.0/23"));
        // 300 prises : un /23 (510) serait à 59 % ; un /22 (1 022) à 29 %.
        assert_eq!(suggest_network(ip("192.168.1.0"), 24, 300).as_deref(), Some("192.168.0.0/22"));
    }

    #[test]
    fn suggest_none_when_not_crowded_and_stops_at_16() {
        let f = network_fill_with(&site().validated().unwrap(), &[], &[], &[]).unwrap();
        assert_eq!(f.suggest, None);
        assert_eq!(suggest_network(ip("10.1.0.0"), 16, 60_000), None);
        assert_eq!(suggest_network(ip("10.1.0.0"), 17, 60_000), None);
        assert_eq!(suggest_network(ip("10.1.0.0"), 17, 30_000).as_deref(), Some("10.1.0.0/16"));
    }

    #[test]
    fn network_fill_without_devices_is_unchanged() {
        let cams = [known("10.0.8.20", Some("A"), None, 1), known("10.0.8.21", Some("B"), None, 1)];
        let n = site().validated().unwrap();
        let a = network_fill(&n, &cams, &[ip("10.0.8.21")]).unwrap();
        let b = network_fill_with(&n, &cams, &[], &[ip("10.0.8.21")]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.devices, 0);
        // Le carnet compte ses appareils relevés.
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        // Relevé du jour : un appareil vu il y a plus de six mois ne compterait plus.
        let now = unix_now();
        book.record_survey(&acc.id, vec![device("10.0.8.40", None, now)], now).unwrap();
        assert_eq!(book.fill(&acc.id, &[]).unwrap().unwrap().devices, 1);
    }

    #[test]
    fn surveyed_cameras_count_as_cameras_in_the_fill() {
        let n = site().validated().unwrap();
        let cam = SeenDevice { kind: DeviceKind::Camera, ..device("10.0.8.30", None, 1) };
        let nvr = SeenDevice { kind: DeviceKind::Nvr, ..device("10.0.8.31", None, 1) };
        let f = network_fill_with(&n, &[known("10.0.8.30", Some("A"), None, 1)], &[cam.clone(), nvr, device("10.0.8.40", None, 1)], &[]).unwrap();
        // La caméra relevée et déjà connue ne compte qu'une fois, en vert.
        assert_eq!((f.cameras, f.devices), (1, 2));
        let g = network_fill_with(&n, &[], &[cam, device("10.0.8.40", None, 1)], &[]).unwrap();
        assert_eq!((g.cameras, g.devices), (1, 1));
        assert!(g.segments.iter().any(|s| s.kind == SegmentKind::Camera));
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
        let (book, startup) = load_or_quarantine(fx.path());
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
    fn accounts_of_the_old_folder_are_merged_by_id() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let mairie = book.create("Mairie", "root", pwd(PWD), no_net()).unwrap();
        let old = fx.dir.join("accounts.json.io.lenscout.app");
        let file = serde_json::json!({"version": 2, "accounts": [
            // Même id : le compte du nouveau carnet gagne.
            {"id": mairie.id, "name": "Mairie bis", "login": seal::seal(b"autre"), "password": seal::seal(b"x")},
            {"id": "x2", "name": "Gare", "pc_ip": "10.1.0.250/16",
             "login": seal::seal(b"admin"), "password": seal::seal(PWD.as_bytes())},
            // Nom déjà pris par un autre compte : gardé sous un nom libre.
            {"id": "x3", "name": "mairie", "login": seal::seal(b"root"), "password": seal::seal(PWD.as_bytes())},
        ]});
        std::fs::write(&old, file.to_string()).unwrap();
        assert_eq!(book.absorb(&old).unwrap(), 2);
        let names: Vec<_> = book.list().into_iter().map(|a| (a.id, a.name, a.login)).collect();
        assert_eq!(
            names,
            [
                (mairie.id.clone(), "Mairie".to_string(), "root".to_string()),
                ("x2".into(), "Gare".into(), "admin".into()),
                ("x3".into(), "mairie 2".into(), "root".into()),
            ]
        );
        assert_eq!(book.password("x2").unwrap().unwrap().expose(), PWD);
        // Écrit sur disque : relu tel quel.
        assert_eq!(fx.book().list().len(), 3);
        // Le fichier fusionné n'est pas touché.
        assert_eq!(std::fs::read_to_string(&old).unwrap(), file.to_string());
        // Illisible : erreur à part, pour le mettre de côté.
        std::fs::write(&old, b"pas du json").unwrap();
        assert!(matches!(book.absorb(&old), Err(AccountError::ImportInvalid)));
    }

    #[test]
    fn an_incoherent_gateway_is_dropped_never_the_file() {
        // Ancien export : passerelle valable pour le réseau d'alors (/22),
        // hors du réseau recalculé depuis l'IP du PC (/24).
        let file = serde_json::json!({
            "format": "lenscout-accounts", "version": 1,
            "accounts": [
                {"name": "Mairie", "login": seal::seal(b"root"), "password": seal::seal(PWD.as_bytes()),
                 "pc_ip": "192.168.1.250/24", "network": "192.168.0.0/22", "gateway": "192.168.0.1"},
                {"name": "Gare", "login": seal::seal(b"root"), "pc_ip": "10.1.0.250/16", "gateway": "10.1.0.1"},
            ],
        })
        .to_string();
        let (mut book, _fx) = empty_book();
        let plan = book.import_plan(&file).unwrap();
        assert_eq!(
            plan.items.iter().map(|i| (i.name.as_str(), i.gateway_dropped)).collect::<Vec<_>>(),
            [("Mairie", true), ("Gare", false)]
        );
        book.import_apply(&file, &HashMap::new()).unwrap();
        assert_eq!(book.list()[0].net, net("192.168.1.250/24", "192.168.1.0/24", ""));
        assert_eq!(book.list()[1].net, net("10.1.0.250/16", "10.1.0.0/16", "10.1.0.1"));

        // Même compte chargé tel quel depuis le carnet puis réexporté.
        let fx = Fixture::new();
        let stored = serde_json::json!({"version": 2, "accounts": [
            {"id": "1", "name": "Mairie", "pc_ip": "192.168.1.250/24", "gateway": "192.168.0.1",
             "login": seal::seal(b"root"), "password": seal::seal(PWD.as_bytes())},
        ]});
        std::fs::write(fx.path(), stored.to_string()).unwrap();
        let (loaded, _) = load_or_quarantine(fx.path());
        let (other, _fx2) = empty_book();
        let plan = other.import_plan(&loaded.export()).unwrap();
        assert!(plan.items[0].gateway_dropped);
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
        let (book, startup) = load_or_quarantine(fx.path());
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
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        let mut book = fx.book();
        let gare = book.create("Gare", "admin", pwd(PWD), no_net()).unwrap();
        assert_eq!(book.password(&gare.id).unwrap().unwrap().expose(), PWD);
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
        let mut book = AccountBook::load(fx.dir.join("absent.json")).unwrap();
        book.path = fx.path();
        let err = book.create("A", "root", pwd(PWD), no_net()).unwrap_err();
        assert!(matches!(err, AccountError::Io(_)));
        assert!(book.list().is_empty());
    }

    #[test]
    fn corrupt_file_is_quarantined_not_deleted() {
        let fx = Fixture::new();
        std::fs::write(fx.path(), b"{ pas du json").unwrap();
        let (book, startup) = load_or_quarantine(fx.path());
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
        let (book, startup) = load_or_quarantine(fx.path());
        assert!(book.list().is_empty());
        assert!(matches!(startup, Startup::Quarantined(_)));
    }

    #[test]
    fn absent_file_is_clean_start() {
        let fx = Fixture::new();
        let (book, startup) = load_or_quarantine(fx.path());
        assert!(book.list().is_empty());
        assert!(matches!(startup, Startup::Clean));
        assert!(std::fs::read_dir(&fx.dir).unwrap().next().is_none());
    }

    #[test]
    fn valid_file_is_clean_start() {
        let fx = Fixture::new();
        fx.book().create("A", "root", pwd(PWD), no_net()).unwrap();
        let (book, startup) = load_or_quarantine(fx.path());
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
        let (mut book, startup) = load_or_quarantine(fx.path());
        std::fs::set_permissions(&fx.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(startup, Startup::Unwritable));
        assert!(book.list().is_empty());
        let err = book.create("A", "root", pwd(PWD), no_net()).unwrap_err();
        assert!(matches!(err, AccountError::Io(_)));
        assert!(book.list().is_empty());
        // Le fichier d'origine n'a pas été touché.
        assert_eq!(std::fs::read(fx.path()).unwrap(), b"{ pas du json");
    }

    // ---- Ancien format (format 1) ----

    #[test]
    fn v1_file_loads_accounts_without_password_and_untouched() {
        // Format 1 : mots de passe hors du fichier, plus repris. Les comptes
        // restent (nom, identifiant, réseau), à ressaisir ; le fichier n'est
        // ni réécrit ni mis de côté.
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root-unique")]);
        let before = std::fs::read(fx.path()).unwrap();
        let (book, startup) = load_or_quarantine(fx.path());
        assert!(matches!(startup, Startup::Clean));
        assert_eq!(book.list().len(), 1);
        assert_eq!(book.list()[0].login, "root-unique");
        assert!(!book.has_secret("id-1"));
        assert!(matches!(
            book.credentials("id-1"),
            Err(AccountError::SecretMissing)
        ));
        assert_eq!(std::fs::read(fx.path()).unwrap(), before);
        assert_eq!(std::fs::read_dir(&fx.dir).unwrap().count(), 1);
    }

    #[test]
    fn v1_account_is_repaired_by_entering_the_password() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root"), ("id-2", "Gare", "admin")]);
        let (mut book, _) = load_or_quarantine(fx.path());
        assert!(matches!(
            book.update("id-1", "Mairie", "root", None, no_net()),
            Err(AccountError::SecretMissing)
        ));
        book.update("id-1", "Mairie", "root", Some(pwd("Neuf-1")), no_net())
            .unwrap();
        // Premier enregistrement : le fichier passe au format 2, sans rien en clair.
        let raw = fx.raw();
        assert!(raw.contains("\"version\": 2"));
        assert!(!raw.contains("Neuf-1") && !raw.contains("legacy"));
        let book = fx.book();
        assert_eq!(
            book.credentials("id-1").unwrap().password.expose(),
            "Neuf-1"
        );
        assert!(!book.has_secret("id-2"));
    }

    #[test]
    fn v2_file_with_legacy_marker_still_loads() {
        // Marque `legacy` des versions précédentes : ignorée, puis effacée.
        let fx = Fixture::new();
        let file = serde_json::json!({"version": 2, "accounts": [
            {"id": "1", "name": "A", "legacy": true,
             "login": seal::seal(b"root"), "password": seal::seal(b"")},
        ]});
        std::fs::write(fx.path(), file.to_string()).unwrap();
        let mut book = fx.book();
        assert!(!book.has_secret("1"));
        book.create("B", "admin", pwd(PWD), no_net()).unwrap();
        assert!(!fx.raw().contains("legacy"));
        assert!(!fx.book().has_secret("1"));
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
        let (mut book, _) = load_or_quarantine(fx.path());
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
        let (nopass, _) = load_or_quarantine(fx.path());
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
        let mut book = AccountBook::load(fx.dir.join("absent.json")).unwrap();
        book.path = fx.path();
        let data = sample_book().export();
        assert!(matches!(
            book.import_apply(&data, &HashMap::new()),
            Err(AccountError::Io(_))
        ));
        assert!(book.list().is_empty());
    }

    // ---- Ronde 1 ----

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
    fn needing_password_account_reloads_from_v2_without_secret() {
        let fx = Fixture::new();
        fx.write_v1(&[("id-1", "Mairie", "root")]);
        let (mut book, _) = load_or_quarantine(fx.path());
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
        let err = AccountBook::load(fx.path()).unwrap_err();
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

    // ---- IP réservées ----

    fn held(ip_: &str, label: Option<&str>, at: u64) -> ReservedIp {
        ReservedIp { ip: ip(ip_), label: label.map(str::to_string), at }
    }

    #[test]
    fn reservations_are_stored_dated_labelled_and_released() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        assert!(book.reservations(&acc.id).unwrap().is_empty());
        book.reserve(&acc.id, ip("10.0.8.60"), Some("  Cam 110 "), 100).unwrap();
        book.reserve(&acc.id, ip("10.0.8.50"), Some("   "), 101).unwrap();
        // Rangées par adresse ; libellé vide = pas de libellé.
        assert_eq!(fx.book().reservations(&acc.id).unwrap(), [held("10.0.8.50", None, 101), held("10.0.8.60", Some("Cam 110"), 100)]);
        // Réserver à nouveau : le libellé change, la date reste, pas de doublon.
        book.reserve(&acc.id, ip("10.0.8.60"), Some("Cam 111"), 300).unwrap();
        assert_eq!(book.reservations(&acc.id).unwrap()[1], held("10.0.8.60", Some("Cam 111"), 100));
        book.release(&acc.id, ip("10.0.8.60")).unwrap();
        assert_eq!(fx.book().reservations(&acc.id).unwrap(), [held("10.0.8.50", None, 101)]);
        assert!(matches!(book.release(&acc.id, ip("10.0.8.60")), Err(AccountError::NotFound)));
        assert!(matches!(book.reserve("zzz", ip("10.0.8.60"), None, 1), Err(AccountError::NotFound)));
        assert!(matches!(book.reservations("zzz"), Err(AccountError::NotFound)));
        // Une mise à jour du compte garde ses réservations.
        book.update(&acc.id, "Site", "root", None, site()).unwrap();
        assert_eq!(book.reservations(&acc.id).unwrap().len(), 1);
    }

    #[test]
    fn older_file_without_reservations_loads_and_writes_no_key() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.remember(&acc.id, vec![known("10.0.8.20", Some("A"), None, 1)]).unwrap();
        assert!(!fx.raw().contains("reserved"));
        let before = fx.raw();
        // Fichier d'une version précédente : se relit sans perte, sans réservation.
        let reloaded = fx.book();
        assert!(reloaded.reservations(&acc.id).unwrap().is_empty());
        assert_eq!(reloaded.list(), book.list());
        assert_eq!(reloaded.known_cameras(&acc.id).unwrap().len(), 1);
        assert_eq!(fx.raw(), before);
    }

    #[test]
    fn bad_reservation_line_is_ignored_not_fatal() {
        let fx = Fixture::new();
        let mut book = fx.book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.reserve(&acc.id, ip("10.0.8.60"), None, 1).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&fx.raw()).unwrap();
        v["accounts"][0]["reserved"].as_array_mut().unwrap().push(serde_json::json!({"ip": "x", "at": 1}));
        std::fs::write(fx.path(), v.to_string()).unwrap();
        assert_eq!(fx.book().reservations(&acc.id).unwrap(), [held("10.0.8.60", None, 1)]);
        v["accounts"][0]["reserved"] = "pas une liste".into();
        std::fs::write(fx.path(), v.to_string()).unwrap();
        assert!(fx.book().reservations(&acc.id).unwrap().is_empty());
    }

    #[test]
    fn fill_counts_reserved_as_taken_once() {
        // Passerelle .1, PC .250, exclues .2–.9 et .100 : réservées .5 (déjà exclue), .60, .61, .62, et .20 (caméra connue).
        let n = site().validated().unwrap();
        let cams = [known("10.0.8.20", Some("A"), None, 1)];
        let held = [ip("10.0.8.5"), ip("10.0.8.60"), ip("10.0.8.61"), ip("10.0.8.62"), ip("10.0.8.20"), ip("192.168.0.9")];
        let f = network_fill_full(&n, &cams, &[], &held, &[]).unwrap();
        // La réservée prime sur la caméra à la même adresse : comptée une fois.
        assert_eq!((f.reserved, f.cameras, f.free), (4, 0, 254 - 1 - 1 - 9 - 4));
        let segs: Vec<_> = f.segments.iter().filter(|s| s.kind == SegmentKind::Reserved).map(|s| (s.first, s.last)).collect();
        assert_eq!(segs, [(20, 20), (60, 62)]);
        assert_eq!(serde_json::to_value(SegmentKind::Reserved).unwrap(), "reserved");
        // Une adresse qu'on réadresse ne libère jamais une réservée.
        assert_eq!(network_fill_full(&n, &[], &[], &held, &[ip("10.0.8.60")]).unwrap().reserved, 4);
        // Sans réservée : le calcul d'avant.
        assert_eq!(network_fill_full(&n, &cams, &[], &[], &[]).unwrap(), network_fill_with(&n, &cams, &[], &[]).unwrap());
        // Le carnet compte les siennes.
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.reserve(&acc.id, ip("10.0.8.60"), None, 1).unwrap();
        let f = book.fill(&acc.id, &[]).unwrap().unwrap();
        assert_eq!((f.reserved, f.free), (1, 254 - 1 - 1 - 9 - 1));
    }

    #[test]
    fn a_reserved_ip_heard_by_a_survey_is_released_and_stays_taken() {
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        book.reserve(&acc.id, ip("10.0.8.60"), Some("Cam 110"), 1).unwrap();
        book.reserve(&acc.id, ip("10.0.8.61"), None, 1).unwrap();
        let free_before = book.fill(&acc.id, &[]).unwrap().unwrap().free;
        let now = unix_now();
        book.record_survey(&acc.id, vec![device("10.0.8.60", Some("AA:BB:CC:00:00:60"), now)], now).unwrap();
        // .60 répond : la réservation part, l'appareil relevé porte l'adresse.
        assert_eq!(book.reservations(&acc.id).unwrap(), [held("10.0.8.61", None, 1)]);
        let f = book.fill(&acc.id, &[]).unwrap().unwrap();
        assert_eq!((f.reserved, f.devices, f.free), (1, 1, free_before));
    }

    #[test]
    fn export_and_import_carry_reservations_and_keep_local_ones() {
        let (mut src, _fx_src) = empty_book();
        let a = src.create("Site", "root", pwd(PWD), site()).unwrap();
        src.reserve(&a.id, ip("10.0.8.60"), Some("Cam 110"), 7).unwrap();
        let data = src.export();
        assert!(data.contains("\"reserved\"") && data.contains("Cam 110"));
        // Compte nouveau : il arrive avec ses réservations.
        let (mut dst, _fx_dst) = empty_book();
        dst.import_apply(&data, &HashMap::new()).unwrap();
        let id = dst.list()[0].id.clone();
        assert_eq!(dst.reservations(&id).unwrap(), [held("10.0.8.60", Some("Cam 110"), 7)]);
        // Compte identique : celles du fichier s'ajoutent, les miennes restent (libellé compris).
        let (mut mine, _fx_mine) = empty_book();
        let b = mine.create("Site", "root", pwd(PWD), site()).unwrap();
        mine.reserve(&b.id, ip("10.0.8.60"), Some("Ma cam"), 3).unwrap();
        mine.reserve(&b.id, ip("10.0.8.70"), None, 3).unwrap();
        src.reserve(&a.id, ip("10.0.8.80"), None, 8).unwrap();
        mine.import_apply(&src.export(), &HashMap::new()).unwrap();
        assert_eq!(
            mine.reservations(&b.id).unwrap(),
            [held("10.0.8.60", Some("Ma cam"), 3), held("10.0.8.70", None, 3), held("10.0.8.80", None, 8)]
        );
    }


    // ---- Appareils relevés anciens ----

    #[test]
    fn a_device_unseen_for_over_six_months_no_longer_counts_as_taken() {
        const DAY: u64 = 24 * 3600;
        assert_eq!(STALE_DEVICE_SECS, 180 * DAY);
        let now = 1_000 * DAY;
        let old = device("10.0.8.40", None, now - 181 * DAY);
        let recent = device("10.0.8.41", None, now - 179 * DAY);
        assert_eq!(current_devices(&[old.clone(), recent.clone()], now), [recent]);
        // Le carnet compte à l'heure qu'il est : 181 j libre, 179 j pris.
        let (mut book, _fx) = empty_book();
        let acc = book.create("Site", "root", pwd(PWD), site()).unwrap();
        let today = unix_now();
        let base = book.fill(&acc.id, &[]).unwrap().unwrap().free;
        book.record_survey(&acc.id, vec![device("10.0.8.40", None, today - 181 * DAY)], today - 181 * DAY).unwrap();
        assert_eq!(book.fill(&acc.id, &[]).unwrap().unwrap().free, base);
        book.record_survey(&acc.id, vec![device("10.0.8.41", None, today - 179 * DAY)], today - 179 * DAY).unwrap();
        let f = book.fill(&acc.id, &[]).unwrap().unwrap();
        assert_eq!((f.devices, f.free), (1, base - 1));
        // L'ancien reste dans l'inventaire.
        assert_eq!(book.devices(&acc.id).unwrap().0.len(), 2);
    }

}
