# Changelog

Toutes les modifications notables de LenScout sont documentées ici (EN/FR).
All notable changes to LenScout are documented here (EN/FR).

Le format suit [Keep a Changelog](https://keepachangelog.com/), avec une section
`### English` et `### Français` par version. SemVer.

## [0.1.0] - 2026-11-15

### English

- **First release of LenScout** — a desktop app (Tauri) to discover and configure network cameras on an installation site.
- **Three tabs: Network, Framing, Accounts**, with the list of active interfaces and French / English / Spanish.
- **Axis — full support**: discovery (layer-2 + routed scan + mDNS/WSD), activation, IP configuration (DHCP / static), credentials, time / NTP, and framing (multi-sensor views, zoom, focus).
- **Hikvision / LTS**: SADP discovery and ISAPI identification; recognised on a routed scan, with LTS told apart from Hikvision. Activation and IP change over SADP are not yet enabled (no reliable public source for the SADP password encoding).
- **Accounts**: optional PC IP (with prefix), network and gateway; stored and carried by export / import. A chosen account adds its PC IP to the interface and rescans.
- **Automatic updates**: the installer is downloaded from the project's GitHub releases and launched only if its minisign signature is valid and its version is newer.

### Français

- **Première version de LenScout** — une application de bureau (Tauri) pour découvrir et configurer les caméras réseau sur un site d'installation.
- **Trois onglets : Réseau, Cadrage, Comptes**, avec la liste des interfaces actives et le français / anglais / espagnol.
- **Axis — prise en charge complète** : découverte (couche 2 + balayage routé + mDNS/WSD), activation, configuration IP (DHCP / fixe), identifiants, heure / NTP, et cadrage (vues multicapteur, zoom, mise au point).
- **Hikvision / LTS** : découverte SADP et identification ISAPI ; reconnues au balayage routé, LTS distinguée de Hikvision. L'activation et le changement d'IP par SADP ne sont pas encore activés (pas de source publique fiable pour le chiffrement du mot de passe SADP).
- **Comptes** : IP du PC facultative (avec préfixe), réseau et passerelle ; conservés et transportés par l'export / import. Choisir un compte ajoute son IP PC à l'interface et relance le balayage.
- **Mises à jour automatiques** : l'installeur est téléchargé depuis les releases GitHub du projet et lancé seulement si sa signature minisign est valide et sa version plus récente.
