# Changelog

Toutes les modifications notables de LenScout sont documentées ici (EN/FR).
All notable changes to LenScout are documented here (EN/FR).

Le format suit [Keep a Changelog](https://keepachangelog.com/), avec une section
`### English` et `### Français` par version. SemVer.

## [0.2.6] - 2026-11-19

### English

- **Fixed: a camera plugged in directly on 169.254 is now read** (serial, firmware, state) through a temporary address.
- **Fixed: scanning and applying an account work on an interface without an IP address.**
- **Fixed: "Ping is not possible" no longer shows after a temporary refusal.**
- **Fixed: the Rescan button no longer slides under the tabs when the search is empty.**

### Français

- **Corrigé : une caméra branchée en direct en 169.254 est lue** (série, firmware, état) via une adresse temporaire.
- **Corrigé : scan et pose d'un compte fonctionnent sur une interface sans adresse IP.**
- **Corrigé : « Ping impossible » ne s'affiche plus après un refus passager.**
- **Corrigé : le bouton Rescan ne glisse plus sous les onglets quand la recherche est vide.**

## [0.2.5] - 2026-11-17

### English

- **Excel export of operations**: once an operation is done, Export saves a formatted .xlsx: OK / KO with details, "Change in NVR" (Yes / No, listed first), old and new IP, brand, model, MAC, serial, plus a summary sheet. Filterable table, coloured rows. No password is written.
- **Settings: check for updates** next to the version, with Install when a new version is out.

### Français

- **Export Excel des opérations** : une fois l'opération terminée, Exporter enregistre un .xlsx mis en forme : OK / KO avec le détail, « À changer dans le NVR » (Oui / Non, en tête), ancienne et nouvelle IP, marque, modèle, MAC, n° de série, et une feuille de synthèse. Tableau filtrable, lignes colorées. Aucun mot de passe n'est écrit.
- **Réglages : rechercher une mise à jour** à côté de la version, avec Installer quand une version est sortie.

## [0.2.4] - 2026-11-17

### English

- **Fixed: free IP search when the network card already has an address in the account's network.** LenScout no longer asks to switch to the account and scans right away.
- **Fixed: free IP search in Operations** never started.

### Français

- **Corrigé : recherche d'IP libres quand la carte a déjà une adresse dans le réseau du compte.** LenScout ne demande plus de basculer sur le compte et balaie directement.
- **Corrigé : la recherche d'IP libres dans Opérations** ne démarrait jamais.

## [0.2.3] - 2026-11-17

### English

- **New Site tab**: pick a client to see its whole network: occupancy bar, surveyed devices listed in the page, known cameras. A click on a camera opens it in Framing. The account sheet keeps only its settings, with a "View site" button.
- **Free and reserved IPs**: the Site tab lists every free address of the account's network. An address can be reserved, with an optional label, for a camera set up behind a switch that is not configured yet. A reserved address is taken everywhere: network bar, free IP search, address sheets. The reservation goes away by itself once the device shows up in a survey.
- **Devices unseen for six months free their address**: they stay in the list, dimmed, and can still be forgotten.

### Français

- **Nouvel onglet Site** : on choisit le client et on voit tout son réseau : barre d'occupation, appareils relevés listés dans la page, caméras connues. Un clic sur une caméra l'ouvre dans le Cadrage. La fiche du compte ne garde que ses réglages, avec un bouton « Voir le site ».
- **IP libres et réservées** : l'onglet Site liste toutes les adresses libres du réseau du compte. Une adresse se réserve, avec un libellé facultatif, pour une caméra configurée derrière un switch qui ne l'est pas encore. Une adresse réservée est prise partout : barre du réseau, recherche d'IP libres, feuilles d'adresses. La réservation saute d'elle-même dès que l'appareil apparaît dans un relevé.
- **Un appareil absent des relevés depuis six mois libère son adresse** : il reste dans la liste, atténué, et « Oublier » reste possible.

## [0.2.2] - 2026-11-17

### English

- **Fixed: Framing on older Hikvision cameras.** Firmwares without an HTTP stream (e.g. V5.3) now show still images about three times a second, instead of a misleading "Authentication denied".
- **Fixed: Framing no longer retries after a refused password.** The retries could lock a Hikvision camera for 30 minutes, the right password included.
- **Fixed: the survey colours the cameras it recognises in green** in the network bar, with their count in the legend.
- **Fixed (Windows): MAC addresses and vendors are read again** when the account's address is added on top of the network card's own.

### Français

- **Corrigé : le Cadrage sur les anciennes Hikvision.** Les firmwares sans flux HTTP (ex. V5.3) affichent des images fixes, environ trois par seconde, au lieu d'un « Authentification refusée » trompeur.
- **Corrigé : le Cadrage ne réessaie plus après un mot de passe refusé.** Ces essais pouvaient verrouiller une Hikvision 30 min, bon mot de passe compris.
- **Corrigé : le relevé met en vert les caméras qu'il reconnaît** dans la barre du réseau, avec leur nombre dans la légende.
- **Corrigé (Windows) : les adresses MAC et les constructeurs sont de nouveau lus** quand l'adresse du compte est ajoutée en plus de celle de la carte réseau.

## [0.2.1] - 2026-11-16

### English

- **Operations — Login test**: tries the chosen account on the checked cameras, read-only, and lists OK, denied, unreachable, not activated or another device. A camera refused twice in 30 minutes is not tried again. CSV export.
- **Accounts — Survey**: lists every device on the account's network (type, vendor, name), keeps it until forgotten, counts it as taken in the network bar and in the address sheets, and suggests a wider mask above 80 % use. CSV export.
- **Fixed: the IP sheets no longer suggest free addresses from another network.** When the chosen account is not the one set on this computer, the sheet says so and offers to switch to it.
- **Fixed: Framing offers to switch to the account's network** when the camera is outside this computer's network.

### Français

- **Opérations — Test de login** : essaie le compte choisi sur les caméras cochées, en lecture seule, et liste OK, refusé, injoignable, non activée ou autre appareil. Une caméra refusée deux fois en 30 min n'est plus essayée. Export CSV.
- **Comptes — Relever** : liste les appareils du réseau du compte (type, constructeur, nom), les garde jusqu'à « Oublier », les compte pris dans la barre du réseau et les feuilles d'adresses, et propose un masque plus large au-delà de 80 % d'occupation. Export CSV.
- **Corrigé : les feuilles IP ne proposent plus d'adresses libres d'un autre réseau.** Si le compte choisi n'est pas celui posé sur ce PC, la feuille le dit et propose de passer dessus.
- **Corrigé : le Cadrage propose de passer sur le réseau du compte** quand la caméra est hors du réseau de ce PC.

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
