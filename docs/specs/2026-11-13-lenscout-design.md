# Lenscout : trouver et préparer des caméras IP sur un réseau

*Cahier des charges du 13/11/2026. Nom choisi par Benjamin.*

## Pourquoi

Benjamin installe des caméras IP chez ses clients, surtout des **Axis** et des **LTS**. AXIS IP Utility, l'outil de découverte d'Axis, n'existe que sous Windows, et chaque marque a son propre outil. Benjamin veut **un seul outil, sur Mac, Linux et Windows**, qui :

- trouve les caméras d'un réseau ;
- prépare une caméra neuve sans passer par son interface web ;
- affiche le flux pour orienter la caméra pendant la pose.

L'outil est **séparé de LanProbe**. Benjamin juge les deux sujets trop différents.

## Ce que c'est

Une application de bureau pour un installateur sur le terrain, branché sur le réseau du client. C'est un outil d'**installation** : il ne fait ni surveillance continue ni enregistrement.

## Objectifs

### 1. Découverte

La page « Réseau » liste les caméras trouvées. Pour chacune, elle affiche :
- la marque et le modèle ;
- l'IP et la MAC ;
- le n° de série, s'il est connu ;
- la version du firmware, si elle est lisible ;
- l'état : neuve (non activée) ou activée.

**Protocoles, par priorité :**
- **Axis** : Bonjour/mDNS (`_axis-video._tcp`), puis ONVIF.
- **LTS** : les LTS sont en majorité des Hikvision rebadgées, donc **SADP**, le protocole de Hikvision, en multicast UDP. C'est **à vérifier sur une vraie caméra LTS**.
- **ONVIF WS-Discovery**, en filet pour les autres marques.
- **Préfixe MAC (OUI)**, pour reconnaître la marque d'un appareil qui ne répond à aucun protocole.

**Comportement attendu :**
- La découverte se relance à la demande, avec un bouton « Rescanner ».
- La liste se met à jour pendant le scan.
- Un bouton **« Ouvrir la page web »** ouvre `http(s)://IP` dans le navigateur par défaut.

### 2. Recherche par MAC ou n° de série

On tape ce qui est imprimé sur la boîte, et la liste se réduit à la caméra correspondante, même sur un gros réseau de plusieurs centaines d'appareils. La recherche accepte la MAC dans tous les formats courants : `AC:CC:8E:…`, `ACCC8E…`, `ac-cc-8e-…`.


### 3. Comptes pré-enregistrés

- Benjamin enregistre des comptes nommés, par exemple « Défaut LORVA » ou « Client X ». Chaque compte a un login et un mot de passe.
- **À chaque action qui demande une authentification, il choisit le compte**, car un client peut avoir ses propres identifiants.
- Les mots de passe vont dans le **trousseau du système** : Keychain sur macOS, Credential Manager sur Windows, Secret Service sur Linux. Ils ne sont jamais écrits en clair dans un fichier de l'application.

### 4. Configuration de base sans l'interface web

Ces réglages se font sur une caméra ou sur plusieurs caméras sélectionnées :

- **Activer une caméra neuve** : poser le mot de passe du compte choisi. Côté Axis, c'est la création du compte root ou admin initial. Côté Hikvision/LTS, c'est l'activation SADP.
- **Changer l'IP** : DHCP ou IP fixe. En lot, on donne une plage, par exemple `10.0.50.11` puis `.12`, `.13`…, avec le masque, la passerelle et le DNS.
- **Régler l'heure** : serveur NTP et fuseau horaire.

Une caméra neuve est souvent hors du sous-réseau du poste. Une Axis sans DHCP prend une adresse en 169.254.x.x, ou 192.168.0.90 sur les anciens modèles.

- **Hikvision/LTS** : SADP permet de l'activer et de changer son IP sans être dans le même sous-réseau.
- **Axis** : il n'existe pas d'équivalent. Lenscout ajoute **temporairement** une IP du bon sous-réseau à la carte réseau du poste, ce qui demande les **droits administrateur** : mot de passe sur macOS, UAC sur Windows, polkit/sudo sur Linux. Il configure la caméra, puis **retire l'IP ajoutée**, y compris après une erreur. *(Choix de Claude, proposé à Benjamin le 13/11, qui a dit « fais le premier jet ».)*
- Si l'élévation est refusée, l'outil dit clairement pourquoi la caméra est injoignable.

**Plage d'IP en lot** : un **aperçu** caméra par caméra (MAC et n° de série → IP), dans l'ordre de la liste affichée, que l'utilisateur valide avant que rien ne soit appliqué. *(Choix de Claude)*

**Autres marques** (trouvées seulement par ONVIF ou par préfixe MAC) : dans la version 1, la liste et le bouton « Ouvrir la page web » seulement, pas de configuration. *(Choix de Claude)*

### 5. Cadrage

La page « Cadrage » se connecte à une caméra avec le compte choisi et affiche son **flux en direct**. L'image doit être assez fluide pour orienter la caméra : une latence d'environ une seconde est acceptable, une image fixe rafraîchie toutes les 5 s ne l'est pas.

## Hors périmètre

- **Pas d'export** ni de relevé de fin de chantier : Benjamin ne le juge pas utile.
- Pas d'enregistrement, pas de surveillance continue, pas d'alertes.
- Pas d'intégration à LanProbe.
- Pas de bouton « Identifier » (faire clignoter ou biper la caméra) : écarté par Benjamin.
- Pas de mise à jour de firmware dans cette version. L'outil affiche la version, c'est tout.

## Ce qui serait un échec, même si tout marche

- Un mot de passe de caméra stocké en clair ou affiché dans les journaux.
- Un outil qui ne marche bien que sur un seul OS. Benjamin déteste les logiciels bloqués sur un système.
- Une action en lot qui modifie une caméra non sélectionnée. Par exemple, une plage d'IP appliquée à la mauvaise caméra.
- Une interface bavarde. Les explications vont dans le code et la doc, pas à l'écran.

## Contraintes et choix déjà faits

- **OS** : macOS, Linux et Windows, à égalité. *(Benjamin)*
- **Open source**, licence **MIT** comme LanProbe. Le dépôt est **public sur le GitHub Ops-Lorva**, avec en plus un remote sur le GitLab LORVA pour les releases manuelles. *(Benjamin)*
- **Pile technique** : Tauri 2, Rust et Svelte, comme LanProbe, dont on reprend les recettes de build, de signature et de mise à jour automatique. *(Choix de Claude, annoncé à Benjamin)*
- **Releases** :
  - un tag `v*` déclenche GitHub Actions, qui construit pour les 3 OS, comme `release.yml` de LanProbe ;
  - les scripts de secours vont dans le dépôt privé `LORVA/releases/lenscout`, jamais dans le dépôt public.
- **Langues** : français, anglais et espagnol, comme LanProbe. *(Choix de Claude)*

## Tests sur du vrai matériel

- **Axis** : Benjamin en a sous la main et branchera le premier jet sur son réseau **le week-end du 14-15/11**.
- **LTS** : pas de caméra disponible pour l'instant. Le code SADP est donc écrit d'après la documentation et les implémentations connues, puis **validé plus tard sur une vraie LTS**. D'ici là, l'activation LTS est marquée « non vérifiée » dans le code et le changelog.

## Laissé au constructeur

- La façon d'afficher le flux. Options possibles : RTSP décodé, MJPEG via VAPIX (Axis) ou ISAPI (Hikvision), ou WebRTC. Le critère est la latence acceptable sur les 3 OS sans demander d'installer ffmpeg à part.
- Le détail des appels de configuration : VAPIX côté Axis, ISAPI et SADP côté Hikvision/LTS, ONVIF Device Management ailleurs.
- Le design des écrans, dans le style de LanProbe.
- La gestion des droits réseau propres à chaque OS : multicast, autorisation « réseau local » sur macOS.
