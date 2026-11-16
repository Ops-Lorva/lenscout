# Changelog

Toutes les modifications notables de LenScout sont documentées ici (EN/FR).
All notable changes to LenScout are documented here (EN/FR).

Le format suit [Keep a Changelog](https://keepachangelog.com/), avec une section
`### English` et `### Français` par version. SemVer.

## [0.2.0] - 2026-11-16

### English

- **Accounts**: passwords live only in the app's accounts file; the system keychain is no longer used. Accounts saved by the very first builds open without their password: type it again once.
- **Signed macOS builds**: the macOS app and installer are signed and notarised, and update themselves like on Windows and Linux.

### Français

- **Comptes** : les mots de passe ne sont plus que dans le fichier des comptes de l'app ; le trousseau du système n'est plus utilisé. Les comptes enregistrés par les toutes premières versions s'ouvrent sans leur mot de passe : ressaisissez-le une fois.
- **Versions macOS signées** : l'app et l'installeur macOS sont signés et notarisés, et se mettent à jour comme sous Windows et Linux.

## [0.1.0] - 2026-11-15

### English

- **First release of LenScout** — a desktop app (Tauri) to discover and configure network cameras on an installation site.
- **Four tabs: Network, Framing, Accounts, Operations**, with the list of active interfaces and French / English / Spanish.
- **Operations**: keep IPs, renumber, set time or change credentials (Axis) on every checked camera, with a before / after preview that flags conflicts, confirmation, camera-by-camera apply with Stop, and a report.
- **Axis — full support**: discovery (layer-2 + routed scan + mDNS/WSD), activation, IP configuration (DHCP / static), credentials, time / NTP, and framing (multi-sensor views, zoom, focus).
- **Hikvision / LTS**: SADP discovery and ISAPI identification; recognised on a routed scan, with LTS told apart from Hikvision. Activation and IP change over SADP are not yet enabled (no reliable public source for the SADP password encoding).
- **Accounts**: optional PC IP (with prefix), network and gateway; stored and carried by export / import. A chosen account adds its PC IP to the interface and rescans.
- **Automatic updates**: the installer is downloaded from the project's GitHub releases and launched only if its minisign signature is valid and its version is newer.

### Français

- **Première version de LenScout** — une application de bureau (Tauri) pour découvrir et configurer les caméras réseau sur un site d'installation.
- **Quatre onglets : Réseau, Cadrage, Comptes, Opérations**, avec la liste des interfaces actives et le français / anglais / espagnol.
- **Opérations** : garder les IP, renuméroter, régler l’heure ou changer les identifiants (Axis) sur toutes les caméras cochées, avec un aperçu avant / après qui signale les conflits, une confirmation, une application caméra par caméra avec Arrêter, et un rapport.
- **Axis — prise en charge complète** : découverte (couche 2 + balayage routé + mDNS/WSD), activation, configuration IP (DHCP / fixe), identifiants, heure / NTP, et cadrage (vues multicapteur, zoom, mise au point).
- **Hikvision / LTS** : découverte SADP et identification ISAPI ; reconnues au balayage routé, LTS distinguée de Hikvision. L'activation et le changement d'IP par SADP ne sont pas encore activés (pas de source publique fiable pour le chiffrement du mot de passe SADP).
- **Comptes** : IP du PC facultative (avec préfixe), réseau et passerelle ; conservés et transportés par l'export / import. Choisir un compte ajoute son IP PC à l'interface et relance le balayage.
- **Mises à jour automatiques** : l'installeur est téléchargé depuis les releases GitHub du projet et lancé seulement si sa signature minisign est valide et sa version plus récente.
