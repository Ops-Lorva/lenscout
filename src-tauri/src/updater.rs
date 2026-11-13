// Repris de LanProbe src-tauri/src/updater.rs et crates/lanprobe-core/src/updater.rs le 2026-11-13
use minisign_verify::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

const GITHUB_REPO: &str = "Ops-Lorva/lenscout";
const GITHUB_API: &str = "https://api.github.com/repos/Ops-Lorva/lenscout";

/// Hôtes où un asset peut être téléchargé. LanProbe ne restreint pas l'URL
/// que le front lui passe ; ici, une URL hors de ces préfixes est refusée
/// avant tout appel réseau, et une redirection qui en sort est coupée.
const ALLOWED_URL_PREFIXES: [&str; 3] = [
    "https://github.com/Ops-Lorva/lenscout/releases/download/",
    "https://objects.githubusercontent.com/",
    // Hôte actuel des redirections des assets de release.
    "https://release-assets.githubusercontent.com/",
];

/// Clé PUBLIQUE minisign de Lenscout (base64 du fichier .pub). La clé privée
/// reste sur le poste de release et dans le secret CI. Paire dédiée, jamais
/// partagée avec un autre produit.
const UPDATER_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDlCRjlEM0NCQTA0MzJCRTAKUldUZ0swT2d5OVA1bTEyeENrejVYL2p2eE4zZVFxanFDeG9EUjF0aGZVYmF6WFdYY1ZHVW9QeWoK";

#[derive(Debug, Serialize, Clone)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub has_update: bool,
    pub asset_url: Option<String>,
    pub asset_name: Option<String>,
    pub platform_supported: bool,
    pub release_notes_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

/// Vérifie une signature minisign produite par `tauri signer sign`.
///
/// - `data` : octets exacts de l'installeur téléchargé.
/// - `sig_b64` : contenu BRUT du fichier `.sig` (déjà en base64, tel quel).
/// - `pub_key_b64` : clé publique base64 (celle du fichier `.pub`).
/// - `asset_name` : nom attendu ; le commentaire signé (« trusted comment »,
///   que `tauri signer` écrit `timestamp:<n>\tfile:<nom du fichier>`) doit le
///   porter, sinon une signature valide d'un AUTRE fichier de Lenscout serait
///   acceptée ici (rejeu d'une vieille version).
///
/// Les signatures « legacy » (sans pré-hachage) sont refusées.
fn verify_signature(data: &[u8], sig_b64: &str, pub_key_b64: &str, asset_name: &str) -> Result<(), String> {
    let public_key = PublicKey::decode(&base64_to_string(pub_key_b64)?).map_err(|e| e.to_string())?;
    let signature = Signature::decode(&base64_to_string(sig_b64)?).map_err(|e| e.to_string())?;
    public_key.verify(data, &signature, false).map_err(|e| e.to_string())?;
    let wanted = format!("file:{asset_name}");
    if !signature.trusted_comment().split('\t').any(|part| part == wanted) {
        return Err("signature d'un autre fichier".into());
    }
    Ok(())
}

fn base64_to_string(b64: &str) -> Result<String, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

/// `vX.Y.Z` strict. Tout le reste (`latest`, `v1.0.0-rc1`, `app-v1.0.0`) est
/// ignoré : on ne compare que des versions publiées en bonne et due forme.
/// Lenscout n'a qu'une forme de tag, contrairement à LanProbe.
fn parse_version(tag: &str) -> Option<(u32, u32, u32)> {
    let s = tag.strip_prefix('v')?;
    let mut parts = s.split('.');
    let a = parts.next()?.parse().ok()?;
    let b = parts.next()?.parse().ok()?;
    let c = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((a, b, c))
}

/// `lenscout_vX.Y.Z_<suffixe>` -> `(X, Y, Z)`. Le suffixe est limité à
/// `[A-Za-z0-9._-]` : le nom sert à écrire un fichier et à lancer un programme.
fn asset_version(name: &str) -> Option<(u32, u32, u32)> {
    let rest = name.strip_prefix("lenscout_")?;
    let (tag, suffix) = rest.split_once('_')?;
    let ok = !suffix.is_empty()
        && suffix.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok { parse_version(tag) } else { None }
}

/// Refuse tout installeur dont la version n'est pas strictement supérieure à
/// celle de l'application en cours.
fn check_not_downgrade(asset_name: &str, current: &str) -> Result<(), String> {
    let offered = asset_version(asset_name).ok_or("nom d'asset refusé")?;
    let current = parse_version(&format!("v{current}")).ok_or("version courante illisible")?;
    if offered <= current {
        return Err("version plus ancienne ou identique : refusée".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Os {
    Linux,
    Windows,
    Mac,
}

const fn current_os() -> Os {
    if cfg!(target_os = "windows") {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::Mac
    } else {
        Os::Linux
    }
}

/// Linux : seul le paquet .deb est publié, donc seule une installation
/// système (`/usr/…`) peut être mise à jour par lui.
fn installed_from_deb() -> bool {
    std::env::current_exe().is_ok_and(|p| p.starts_with("/usr/"))
}

/// Nom de l'asset publié pour un OS. `deb` : l'application tourne depuis un
/// paquet .deb (sans objet hors Linux).
fn asset_name_for(os: Os, tag: &str, deb: bool) -> Option<String> {
    match os {
        Os::Windows => Some(format!("lenscout_{tag}_x64-setup.exe")),
        Os::Mac => Some(format!("lenscout_{tag}_universal.pkg")),
        Os::Linux => deb.then(|| format!("lenscout_{tag}_amd64.deb")),
    }
}

fn pick_asset(assets: &[GithubAsset], os: Os, tag: &str, deb: bool) -> Option<(String, String)> {
    let expected = asset_name_for(os, tag, deb)?;
    assets
        .iter()
        .find(|a| a.name == expected)
        .map(|a| (a.browser_download_url.clone(), a.name.clone()))
}

/// `true` si l'URL est un téléchargement de release du dépôt, ou le stockage
/// où GitHub redirige. L'URL est normalisée avant comparaison : `..`, `@`
/// et sous-domaines piégés ne passent pas le préfixe.
fn is_allowed_url(url: &str) -> bool {
    reqwest::Url::parse(url)
        .is_ok_and(|u| ALLOWED_URL_PREFIXES.iter().any(|p| u.as_str().starts_with(p)))
}

/// L'URL vient du front : on la vérifie, et le nom (qui sert à écrire un
/// fichier) doit être le dernier segment de cette URL, sans séparateur.
fn check_download_target(url: &str, asset_name: &str) -> Result<(), String> {
    if !is_allowed_url(url) {
        return Err("URL de téléchargement refusée".into());
    }
    let safe_name = asset_version(asset_name).is_some();
    let parsed = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    let last = parsed.path_segments().and_then(|mut s| s.next_back());
    if !safe_name || last != Some(asset_name) {
        return Err("nom d'asset refusé".into());
    }
    Ok(())
}

/// Un client qui ne suit que les redirections restées dans la liste.
fn download_client(timeout_secs: u64) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .user_agent("Lenscout-Updater")
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() < 5 && is_allowed_url(attempt.url().as_str()) {
                attempt.follow()
            } else {
                attempt.error("redirection refusée")
            }
        }))
        .build()
        .map_err(|e| e.to_string())
}

pub async fn check_update_impl() -> Result<UpdateInfo, String> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let current_tuple = parse_version(&format!("v{current}"));

    // GitHub exige un User-Agent et une version d'API ; pas de jeton, le
    // dépôt est public.
    let resp = download_client(10)?
        .get(format!("{GITHUB_API}/releases?per_page=20"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("GitHub API HTTP {}", resp.status()));
    }
    let releases: Vec<GithubRelease> = resp.json().await.map_err(|e| e.to_string())?;

    let latest = releases
        .into_iter()
        .filter(|r| !r.draft && !r.prerelease)
        .filter_map(|r| parse_version(&r.tag_name).map(|v| (v, r)))
        .max_by_key(|(v, _)| *v);
    let (latest_tuple, latest_release) = match latest {
        Some((v, r)) => (Some(v), Some(r)),
        None => (None, None),
    };
    let has_update = matches!((current_tuple, latest_tuple), (Some(cur), Some(lat)) if lat > cur);

    let picked = latest_release
        .as_ref()
        .filter(|_| has_update)
        .and_then(|r| pick_asset(&r.assets, current_os(), &r.tag_name, installed_from_deb()))
        // Une URL d'asset hors liste n'est jamais proposée au front.
        .filter(|(url, _)| is_allowed_url(url));
    let (asset_url, asset_name) = match picked {
        Some((u, n)) => (Some(u), Some(n)),
        None => (None, None),
    };

    let latest_tag = latest_release.map(|r| r.tag_name);
    Ok(UpdateInfo {
        current_version: current,
        platform_supported: asset_url.is_some() || !has_update,
        has_update: has_update && asset_url.is_some(),
        release_notes_url: latest_tag.as_ref().map(|t| format!("https://github.com/{GITHUB_REPO}/releases/tag/{t}")),
        latest_version: latest_tag.map(|t| t.trim_start_matches('v').to_string()),
        asset_url,
        asset_name,
    })
}

/// Plafonds de téléchargement : l'installeur, puis sa signature.
const MAX_ASSET_BYTES: u64 = 1 << 30;
const MAX_SIG_BYTES: u64 = 4096;

/// Lit la réponse par morceaux et s'arrête dès que `cap` est dépassé : un
/// serveur qui ment sur `Content-Length` (ou n'en donne pas) ne remplit pas la mémoire.
async fn download_capped(mut resp: reqwest::Response, cap: u64) -> Result<Vec<u8>, String> {
    if resp.content_length().is_some_and(|n| n > cap) {
        return Err("fichier trop volumineux".into());
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if out.len() as u64 + chunk.len() as u64 > cap {
            return Err("fichier trop volumineux".into());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

const TEMP_PREFIX: &str = "lenscout-update-";

/// Écrit l'installeur dans un dossier à soi (0700) et un fichier neuf (0600).
fn write_private(asset_name: &str, bytes: &[u8]) -> Result<std::path::PathBuf, String> {
    use std::io::Write;
    let tmp_dir = std::env::temp_dir().join(format!("{TEMP_PREFIX}{}", uuid::Uuid::new_v4()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&tmp_dir).map_err(|e| e.to_string())?;
    let dest = tmp_dir.join(asset_name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(&dest).and_then(|mut f| f.write_all(bytes)).map_err(|e| e.to_string())?;
    Ok(dest)
}

/// Retire les dossiers laissés par de précédentes mises à jour (l'installeur
/// lancé avant la fermeture de l'app ne pouvait pas être effacé à ce moment).
/// Appelé au démarrage ; les erreurs (installeur encore en cours, dossier
/// d'un autre compte) sont sans importance.
pub fn cleanup_old_updates() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else { return };
    for e in entries.flatten() {
        let is_ours = e.file_name().to_string_lossy().starts_with(TEMP_PREFIX);
        // `file_type` ne suit pas les liens symboliques.
        if is_ours && e.file_type().is_ok_and(|t| t.is_dir()) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

pub async fn apply_update_impl(url: String, asset_name: String) -> Result<String, String> {
    check_download_target(&url, &asset_name)?;
    check_not_downgrade(&asset_name, env!("CARGO_PKG_VERSION"))?;
    let client = download_client(300)?;

    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Download HTTP {}", resp.status()));
    }
    let bytes = download_capped(resp, MAX_ASSET_BYTES).await?;

    // Signature vérifiée AVANT d'écrire quoi que ce soit sur le disque, et
    // a fortiori de lancer l'installeur. La CI signe chaque asset avec la
    // clé privée de Lenscout, qui reste hors de GitHub : un asset de release
    // compromis ne déclenche pas d'exécution. Échec fermé : pas de `.sig`
    // valide, pas d'installeur.
    let sig_resp = client.get(format!("{url}.sig")).send().await.map_err(|e| e.to_string())?;
    if !sig_resp.status().is_success() {
        return Err(format!("Signature introuvable ({asset_name}.sig) : HTTP {}", sig_resp.status()));
    }
    let sig_b64 = String::from_utf8(download_capped(sig_resp, MAX_SIG_BYTES).await?).map_err(|e| e.to_string())?;
    verify_signature(&bytes, &sig_b64, UPDATER_PUBKEY, &asset_name)
        .map_err(|e| format!("Signature invalide, mise à jour refusée : {e}"))?;

    let dest = write_private(&asset_name, &bytes)?;

    // Relue et revérifiée juste avant le lancement : le fichier a vécu sur
    // disque, un autre processus du même compte a pu le remplacer entre-temps.
    let on_disk = std::fs::read(&dest).map_err(|e| e.to_string())?;
    verify_signature(&on_disk, &sig_b64, UPDATER_PUBKEY, &asset_name)
        .map_err(|e| format!("Fichier modifié sur le disque, mise à jour refusée : {e}"))?;

    launch_installer(&dest, &asset_name)?;
    Ok(dest.to_string_lossy().to_string())
}

#[cfg(target_os = "windows")]
fn launch_installer(path: &std::path::Path, name: &str) -> Result<(), String> {
    if !name.ends_with("-setup.exe") {
        return Err(format!("Unsupported Windows asset: {name}"));
    }
    // Pas de `cmd` : le chemin est un argument, jamais interprété par un shell.
    // `explorer.exe` plutôt que `Command::new(path)` : l'installeur NSIS est
    // en mode perMachine et demande l'élévation (UAC), que CreateProcess
    // refuse (erreur 740) alors que l'Explorateur la déclenche.
    std::process::Command::new("explorer.exe")
        .arg(path)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn launch_installer(path: &std::path::Path, name: &str) -> Result<(), String> {
    if !name.ends_with(".deb") {
        return Err(format!("Unsupported Linux asset: {name}"));
    }
    // xdg-open délègue au gestionnaire graphique (GNOME Software, Discover,
    // gdebi…), qui gère l'authentification. Pas de repli en `pkexec apt` :
    // une élévation lancée par l'app n'a pas à exister. Si rien ne s'ouvre,
    // l'erreur porte le chemin, et la personne installe à la main.
    std::process::Command::new("xdg-open")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|_| format!("launch_failed:{}", path.display()))
}

#[cfg(target_os = "macos")]
fn launch_installer(path: &std::path::Path, name: &str) -> Result<(), String> {
    if !name.ends_with(".pkg") {
        return Err(format!("Unsupported macOS asset: {name}"));
    }
    // Le .pkg est signé et notarisé : `open` le confie à Installer.app, qui
    // demande le mot de passe administrateur lui-même.
    std::process::Command::new("open").arg(path).spawn().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Clé de test jetable (sans mot de passe) : sans rapport avec la clé de
    // production de `UPDATER_PUBKEY`.
    const TEST_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEQ1NEJBRENBMkI3NTYwNzYKUldSMllIVXJ5cTFMMVl0aWp0VHdKYUY2UkJvVkFsSWttUmQrYjJiRXV5VVExVnk0dmFmL0RWRlUK";
    const TEST_SIG: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSMllIVXJ5cTFMMVROQk9iRXpBU3RmU1lRVGorY0NUaE9NVmt1UDNSMTZ2SkQ5NXcrUDNiTERKaVQyd3VrWUh2NmdwWDB0WFZYWTFJWnhkdkh6VFdYNjJWb1JaVVZjcUFrPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzgzODcwMDQ4CWZpbGU6Zml4dHVyZS5iaW4KZ0VDd0gyZFhBTWNBajZUWjh1b05oUjVSQVptMUNzMHQwYTdTQk5zWkg3bk8vOVZsSWgrRmlYaURtMWYreXRHU1ZxS0NDTTN0aDZ3UUNpOGszYnVCQkE9PQo=";
    // Nom de fichier porté par le commentaire signé des fixtures ci-dessous.
    const FIXTURE: &str = "fixture.bin";
    const TEST_DATA: &[u8] = b"lanprobe-updater-signature-fixture-v1";

    #[test]
    fn verifies_a_valid_signature() {
        assert!(verify_signature(TEST_DATA, TEST_SIG, TEST_PUBKEY, FIXTURE).is_ok());
    }

    #[test]
    fn rejects_tampered_payload() {
        let mut tampered = TEST_DATA.to_vec();
        tampered.push(b'!');
        assert!(verify_signature(&tampered, TEST_SIG, TEST_PUBKEY, FIXTURE).is_err());
    }

    #[test]
    fn rejects_asset_with_bad_signature() {
        // Une signature qui n'est même pas du minisign.
        assert!(verify_signature(TEST_DATA, "bm9wZQ==", TEST_PUBKEY, FIXTURE).is_err());
        assert!(verify_signature(TEST_DATA, "", TEST_PUBKEY, FIXTURE).is_err());
        assert!(verify_signature(TEST_DATA, "!!pas du base64!!", TEST_PUBKEY, FIXTURE).is_err());
    }

    #[test]
    fn production_key_rejects_the_test_signature() {
        assert!(verify_signature(TEST_DATA, TEST_SIG, UPDATER_PUBKEY, FIXTURE).is_err());
    }

    // `.sig` produit avec la VRAIE clé de Lenscout sur ces octets : prouve
    // que la clé embarquée est bien la paire dont la CI signe les assets.
    const PROD_SIG: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVUZ0swT2d5OVA1bXk4VTNhMlozTlNMZnJ2Yk8xY21sREFTMktINUtYYTFGUnpYbStsWVRSamVETC9WNE5RN1RxWTM1Uzc4QnZPOEs3T1RRZ2RwL3RxN1dXME1uWXhvTndjPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk0NTkzNDczCWZpbGU6Zml4dHVyZS5iaW4KOXRvbTk5YkRSbUx2VWtDemNtODIvbi92bEVFcmlIOURwOHk5OVhRTThYS2JXdjYyM3dySjVGTS9XeVhPQU1IRWdWQldXeDR1TUhOVU5tMGZhem8xQ2c9PQo=";

    #[test]
    fn production_key_verifies_a_signature_made_with_its_pair() {
        assert!(verify_signature(TEST_DATA_PROD, PROD_SIG, UPDATER_PUBKEY, FIXTURE).is_ok());
        assert!(verify_signature(TEST_DATA_PROD, PROD_SIG, TEST_PUBKEY, FIXTURE).is_err());
    }

    const TEST_DATA_PROD: &[u8] = b"lenscout-updater-signature-fixture-v1";

    #[test]
    fn production_key_decodes() {
        // Garde contre une clé collée tronquée : elle doit au moins se décoder.
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, UPDATER_PUBKEY).unwrap();
        assert!(PublicKey::decode(std::str::from_utf8(&decoded).unwrap()).is_ok());
    }

    #[test]
    fn parses_strict_semver_tags_only() {
        assert_eq!(parse_version("v0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_version("v10.20.30"), Some((10, 20, 30)));
        assert_eq!(parse_version("0.1.0"), None);
        assert_eq!(parse_version("v0.1"), None);
        assert_eq!(parse_version("v0.1.0.1"), None);
        assert_eq!(parse_version("v0.1.0-rc1"), None);
        assert_eq!(parse_version("latest"), None);
        assert_eq!(parse_version("app-v0.1.0"), None);
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(parse_version("v0.10.0") > parse_version("v0.9.0"));
        assert!(parse_version("v1.0.0") > parse_version("v0.99.99"));
    }

    #[test]
    fn asset_names_per_os() {
        assert_eq!(asset_name_for(Os::Windows, "v0.1.0", false).as_deref(), Some("lenscout_v0.1.0_x64-setup.exe"));
        assert_eq!(asset_name_for(Os::Mac, "v0.1.0", false).as_deref(), Some("lenscout_v0.1.0_universal.pkg"));
        assert_eq!(asset_name_for(Os::Linux, "v0.1.0", true).as_deref(), Some("lenscout_v0.1.0_amd64.deb"));
        // Linux hors paquet .deb : rien à proposer.
        assert_eq!(asset_name_for(Os::Linux, "v0.1.0", false), None);
    }

    #[test]
    fn picks_the_asset_of_the_platform_only() {
        let assets = vec![
            GithubAsset { name: "lenscout_v0.2.0_x64-setup.exe".into(), browser_download_url: "u1".into() },
            GithubAsset { name: "lenscout_v0.2.0_universal.pkg".into(), browser_download_url: "u2".into() },
            GithubAsset { name: "lenscout_v0.2.0_amd64.deb".into(), browser_download_url: "u3".into() },
        ];
        assert_eq!(pick_asset(&assets, Os::Mac, "v0.2.0", false), Some(("u2".into(), "lenscout_v0.2.0_universal.pkg".into())));
        assert_eq!(pick_asset(&assets, Os::Linux, "v0.2.0", true), Some(("u3".into(), "lenscout_v0.2.0_amd64.deb".into())));
        assert_eq!(pick_asset(&assets[..1], Os::Mac, "v0.2.0", false), None);
    }

    const GOOD_URL: &str = "https://github.com/Ops-Lorva/lenscout/releases/download/v0.2.0/lenscout_v0.2.0_amd64.deb";

    #[test]
    fn accepts_only_release_urls_of_the_repo() {
        assert!(is_allowed_url(GOOD_URL));
        assert!(is_allowed_url("https://objects.githubusercontent.com/github-production-release-asset/abc"));
        assert!(!is_allowed_url("http://github.com/Ops-Lorva/lenscout/releases/download/v0.2.0/x"));
        assert!(!is_allowed_url("https://github.com/Ops-Lorva/lenscout-evil/releases/download/v0.2.0/x"));
        assert!(!is_allowed_url("https://github.com.evil.example/Ops-Lorva/lenscout/releases/download/x"));
        assert!(!is_allowed_url("https://objects.githubusercontent.com.evil.example/x"));
        assert!(!is_allowed_url("https://github.com/Ops-Lorva/lenscout/releases/download/../../../x"));
        assert!(!is_allowed_url("file:///etc/passwd"));
    }

    #[test]
    fn download_target_must_be_consistent() {
        assert!(check_download_target(GOOD_URL, "lenscout_v0.2.0_amd64.deb").is_ok());
        // Ni chemin ni nom sans rapport avec l'URL : le nom sert à écrire un fichier.
        assert!(check_download_target(GOOD_URL, "../../../.bashrc").is_err());
        assert!(check_download_target(GOOD_URL, "lenscout_v0.2.0_amd64.deb/../x").is_err());
        assert!(check_download_target(GOOD_URL, "other.deb").is_err());
        assert!(check_download_target("https://evil.example/lenscout_v0.2.0_amd64.deb", "lenscout_v0.2.0_amd64.deb").is_err());
    }

    // Clé jetable produite avec `minisign` : une signature pré-hachée (celle de
    // `tauri signer`) et une « legacy » (`-l`), toutes deux sur
    // TEST_DATA_PROD, avec le commentaire signé `file:lenscout_v0.2.0_amd64.deb`.
    const T2_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXkgODc1QUUyODAwQjY3MUNGRApSV1Q5SEdjTGdPSmFoK3htMTNyWnlKcmJTZHBSZHBwZjVaMGt4RmVNR0dEbm5DMld4SGxpOEM1TQo=";
    const T2_SIG: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIG1pbmlzaWduIHNlY3JldCBrZXkKUlVUOUhHY0xnT0phaDBpZVNMSnNIK0ErL3ZQQ2ZkQjBnVk1Uc3Q5SENUWnp6TWx3SDd5aTQrTWtrd3U0bHB6WVYyZWtQK0puRFozY2FFZXJBNlA4a1pWemc5dWF0dVZ4SUF3PQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxCWZpbGU6bGVuc2NvdXRfdjAuMi4wX2FtZDY0LmRlYgpvaWpyR2R6TkdXWVh2RDV0UkpUWjR4UXN3aWlZSEdOVFhPNXpQdFIwYS9CQlU4Wnpzd1U0S0R3NkZOaHl4b3VXeG5LZ1YwbERVbitGR2pTekgxVk1Bdz09Cg==";
    const T2_LEGACY_SIG: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIG1pbmlzaWduIHNlY3JldCBrZXkKUldUOUhHY0xnT0phaHl4YjVXbmwyeFl1UnRNZnFKQ3JCTVdqRC9nVE9zSk9MUDFqT1FmZk9qaGJoK0ZQYlBGMVZ5UVZMVWs5WC9nN0E0WGpmNFlvR293SWRseU9BQkh4RXdnPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxCWZpbGU6bGVuc2NvdXRfdjAuMi4wX2FtZDY0LmRlYgppZUVQTXVwSUNUeTc4KzRIUm5VNmF1NExGOEhRc2ZkbHF4dUpnTGw1Nis3bHNhTFpoSVVxMmluc0tpMXp3S2hNbGJmNTEzcWhLY01aWUZaSTlQakdBUT09Cg==";
    const T2_NAME: &str = "lenscout_v0.2.0_amd64.deb";

    #[test]
    fn accepts_a_signature_whose_trusted_comment_names_the_asset() {
        assert!(verify_signature(TEST_DATA_PROD, T2_SIG, T2_PUBKEY, T2_NAME).is_ok());
    }

    #[test]
    fn rejects_a_trusted_comment_for_another_file() {
        // Signature valide, mais d'un autre fichier : rejeu d'une vieille release.
        assert!(verify_signature(TEST_DATA_PROD, T2_SIG, T2_PUBKEY, "lenscout_v0.1.0_amd64.deb").is_err());
        assert!(verify_signature(TEST_DATA_PROD, T2_SIG, T2_PUBKEY, "deb").is_err());
    }

    #[test]
    fn rejects_a_legacy_signature() {
        assert!(verify_signature(TEST_DATA_PROD, T2_LEGACY_SIG, T2_PUBKEY, T2_NAME).is_err());
    }

    #[test]
    fn refuses_a_downgrade_or_the_same_version() {
        assert!(check_not_downgrade("lenscout_v0.2.0_amd64.deb", "0.1.0").is_ok());
        assert!(check_not_downgrade("lenscout_v1.0.0_amd64.deb", "0.9.9").is_ok());
        assert!(check_not_downgrade("lenscout_v0.1.0_amd64.deb", "0.1.0").is_err());
        assert!(check_not_downgrade("lenscout_v0.1.0_amd64.deb", "0.2.0").is_err());
        assert!(check_not_downgrade("lenscout_v0.9.0_amd64.deb", "0.10.0").is_err());
        assert!(check_not_downgrade("evil.deb", "0.1.0").is_err());
    }

    #[test]
    fn asset_names_are_strictly_shaped() {
        assert_eq!(asset_version("lenscout_v1.2.3_x64-setup.exe"), Some((1, 2, 3)));
        assert_eq!(asset_version("lenscout_v1.2.3_universal.pkg"), Some((1, 2, 3)));
        for bad in ["lenscout_v1.2.3_", "lenscout_v1.2_x.deb", "lenscout_v1.2.3_a b.exe", "lenscout_v1.2.3_a&b.exe",
                    "lenscout_v1.2.3_a/b.exe", "lenscout_v1.2.3_a\\b.exe", "lenscout_v1.2.3-rc1_x.deb", "x_v1.2.3_a.deb"] {
            assert_eq!(asset_version(bad), None, "{bad}");
        }
    }

    #[test]
    fn accepts_the_current_github_asset_host() {
        assert!(is_allowed_url("https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?x=y"));
        assert!(!is_allowed_url("https://release-assets.githubusercontent.com.evil.example/x"));
    }

    #[cfg(unix)]
    #[test]
    fn installer_is_written_private() {
        use std::os::unix::fs::PermissionsExt;
        let name = format!("lenscout_v9.9.9_{}.deb", uuid::Uuid::new_v4().simple());
        let path = write_private(&name, b"x").unwrap();
        let dir = path.parent().unwrap();
        assert_eq!(std::fs::metadata(dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn startup_cleanup_removes_old_update_dirs_only() {
        let ours = std::env::temp_dir().join(format!("{TEMP_PREFIX}test-{}", uuid::Uuid::new_v4()));
        let other = std::env::temp_dir().join(format!("autre-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&ours).unwrap();
        std::fs::create_dir(&other).unwrap();
        cleanup_old_updates();
        assert!(!ours.exists());
        assert!(other.exists());
        std::fs::remove_dir(&other).unwrap();
    }
}
