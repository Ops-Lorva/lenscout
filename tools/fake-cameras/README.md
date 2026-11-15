# Émulateur de parc de caméras Axis — outil de test LenScout

Outil de **test autonome**. Il ne fait pas partie de l'application : c'est un
script Python qui fait répondre plusieurs **fausses caméras Axis** (plus une
fausse Hikvision), chacune sur sa propre IP, en imitant au plus près le contrat
VAPIX que LenScout balaie. Il permet de tester le **traitement de masse** de
LenScout (le vrai app macOS) sans matériel.

- **Python 3, bibliothèque standard uniquement.** Rien à installer (pas de pip).
- Chaque caméra écoute en **HTTP sur le port 80** — c'est ce que balaie LenScout
  (`identify_anonymous` sonde le port 80). Donc **lancement en `sudo`**.
- Une instance de serveur HTTP est liée à **chaque IP** (`HTTPServer((ip, 80))`),
  en threads. L'hôte **doit posséder ces IP en alias**, sinon le bind échoue.

## 1. Poser les alias IP sur l'hôte

L'émulateur se lance sur une machine du réseau **10.0.20.0/24** (VLAN 20, mode
routé déjà en place). Cette machine doit porter toutes les IP du parc **et** du
pool de renumérotation. Exemple pour le parc par défaut (`fleet.json` :
10.0.20.30 → .45, pool .46 → .60) :

### macOS

```sh
# <if> = l'interface, p.ex. en0 (voir : ifconfig)
for i in $(seq 30 60); do
  sudo ifconfig en0 alias 10.0.20.$i 255.255.255.0
done
# Retrait ensuite : sudo ifconfig en0 -alias 10.0.20.$i
```

### Linux

```sh
# <if> = l'interface, p.ex. eth0 (voir : ip link)
for i in $(seq 30 60); do
  sudo ip addr add 10.0.20.$i/24 dev eth0
done
# Retrait ensuite : sudo ip addr del 10.0.20.$i/24 dev eth0
```

> Sous **Linux**, tout `127.0.0.0/8` est déjà local : l'auto-test sur loopback
> (ci-dessous) ne demande donc **aucun alias**.

## 2. Lancer

```sh
# Vrai parc, port 80 (root obligatoire pour le port privilégié) :
sudo python3 emulate.py --config fleet.json

# Options :
#   --port 80              port d'écoute de chaque caméra (défaut 80)
#   --migration-delay 2.5  délai (s) avant qu'une caméra reparaisse à sa nouvelle IP
```

LenScout tourne sur le Mac de Benjamin et joint le réseau 10.0.20.0/24 à travers
le routeur. Pointer son balayage sur cette plage.

> **https / http clair.** LenScout tente d'abord l'activation en https, puis
> bascule en http clair. L'émulateur ne fait **pas** de TLS : il faut donc, dans
> LenScout, autoriser l'http clair pour la caméra à activer (le `allow_cleartext`
> du contrat). C'est volontaire : l'émulateur n'a pas besoin de TLS pour le test.

## 3. Éditer le parc (`fleet.json`)

Un objet JSON : `netmask`, `pool` (IP libres pour les renumérotations), et
`cameras` (liste). Chaque caméra :

| champ | valeurs | rôle |
|---|---|---|
| `ip` | `10.0.20.30` | IP d'écoute (alias requis sur l'hôte) |
| `brand` | `axis` \| `hikvision` | Hikvision = « non pris en charge » |
| `model` | `P3268-LVE`… | modèle annoncé |
| `serial` | `ACCC8E100001` | n° de série (sert aussi de realm Digest) |
| `firmware` | `11.11.73` | version annoncée |
| `state` | `new` \| `activated` | neuve (aucun compte) ou activée |
| `addressing` | `dhcp` \| `static` | mode d'adressage |
| `mask`, `gateway`, `dns` | | config réseau rendue |
| `users` | `{"root": "motdepasse"}` | identifiant(s) courant(s) ; vide si neuve |
| `timezone` | `Europe/Paris` | fuseau par défaut |
| `views` | liste `{source, name, resolution}` | multicapteur (voir P4705) |

Parc par défaut : ~8 Axis (modèles variés, mélange neuve/activée et
DHCP/fixe, **4 couples d'identifiants distincts** pour exercer la recherche de
mots de passe) + **1 Hikvision**. La **P4705-PLVE** a 2 capteurs et 3 vues
(`Image.I0`, `Image.I1`, vue groupée `Image.I2.Source=1,0`).

## 4. Endpoints imités (contrat VAPIX de LenScout)

| # | Endpoint | Auth | Comportement |
|---|---|---|---|
| 1 | `POST /axis-cgi/basicdeviceinfo.cgi` | anonyme | identité (`propertyList`) |
| 2 | `POST /axis-cgi/systemready.cgi` | anonyme | `needsetup` `yes` (neuve) / `no` |
| 3 | `POST /axis-cgi/pwdgrp.cgi` `action=add` | **sans auth si neuve** | active la caméra, mémorise u/p |
| 4 | tout le reste, une fois activée | **Digest MD5** | mauvais mdp → 401 + `WWW-Authenticate` |
| 5 | `GET /axis-cgi/param.cgi?action=list&group=Network.*` | Digest | lecture réseau (`root.Network.*`) |
| 6 | `GET /axis-cgi/param.cgi?action=update&Network.*` | Digest | écriture réseau + **migration d'IP** |
| 7 | `POST /axis-cgi/time.cgi` `setTimeZone`, `POST /axis-cgi/ntp.cgi` | Digest | heure posée mémorisée, JSON de succès |
| 8 | `GET …&group=Image` / `…&group=Properties.Image` | Digest | vues (multicapteur pour la P4705) |
| 9 | `POST /axis-cgi/pwdgrp.cgi` `action=update`/`add` | Digest | change / crée un identifiant |
| 10 | `POST /axis-cgi/lensparams/*`, `opticscontrol.cgi` | Digest | réponses de succès minimales (panneau cadrage) |
| — | `GET /ISAPI/System/deviceInfo` (Hikvision) | anonyme | XML `<DeviceInfo>` → « non pris en charge » |
| — | tout autre chemin | — | **404** |

Chaque requête est journalisée sur stdout (heure, IP caméra, IP client, méthode,
résultat d'auth, chemin), **sans jamais afficher de mot de passe**.

## 5. Auto-test par curl (reproductible, sur loopback)

Sous Linux, `127.0.0.0/8` est entièrement local : pas besoin d'alias ni de root
avec un port non privilégié. Le parc `fleet.localhost.json` reprend les mêmes
états sur 127.0.0.x.

```sh
python3 emulate.py --config fleet.localhost.json --port 8080
```

Preuves obtenues (sorties réelles) :

### Identité anonyme (1), systemready (2), Hikvision

```
$ curl -s -X POST http://127.0.0.30:8080/axis-cgi/basicdeviceinfo.cgi \
       -d '{"apiVersion":"1.0","method":"getAllUnrestrictedProperties"}'
{"apiVersion": "1.2", "context": "lenscout", "data": {"propertyList": {"Brand": "AXIS",
 "ProdFullName": "AXIS P3268-LVE Network Camera", "ProdNbr": "P3268-LVE",
 "ProdShortName": "AXIS P3268-LVE", "SerialNumber": "ACCC8E100001", "Version": "11.11.73"}}}

$ curl -s -X POST http://127.0.0.30:8080/axis-cgi/systemready.cgi \
       -d '{"apiVersion":"1.1","method":"systemready","params":{"timeout":2}}'
{"apiVersion": "1.1", "data": {"needsetup": "yes"}}          # neuve
# sur une caméra activée : {"apiVersion": "1.1", "data": {"needsetup": "no"}}

$ curl -s http://127.0.0.45:8080/ISAPI/System/deviceInfo
<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<model>DS-2CD2043G2-I</model>
<serialNumber>DS-2CD2043G2-I20240101AAWRE00000001</serialNumber>
<firmwareVersion>V5.7.15</firmwareVersion>
</DeviceInfo>
```

### Mauvais mot de passe → 401 Digest (4), bon mot de passe → 200 (5)

```
$ curl -s -D - --digest -u root:MAUVAIS \
    "http://127.0.0.31:8080/axis-cgi/param.cgi?action=list&group=Network.BootProto"
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="AXIS_ACCC8E100002", nonce="4c5b9a69…", qop="auth"

$ curl -s --digest -u root:'Lentille#77' \
    "http://127.0.0.31:8080/axis-cgi/param.cgi?action=list&group=Network.BootProto,Network.IPAddress,Network.SubnetMask,Network.DefaultRouter,Network.DNSServer1,Network.DNSServer2"
root.Network.BootProto=none
root.Network.IPAddress=127.0.0.31
root.Network.SubnetMask=255.255.255.0
root.Network.DefaultRouter=10.0.20.1
root.Network.DNSServer1=10.0.20.1
root.Network.DNSServer2=1.1.1.1
```

### Vues multicapteur P4705-PLVE (8)

```
$ curl -s --digest -u root:'MultiCapteur$9' \
    "http://127.0.0.41:8080/axis-cgi/param.cgi?action=list&group=Image"
root.Image.I0.Enabled=yes
root.Image.I0.Name=Vue capteur 1
root.Image.I0.Source=0
root.Image.I1.Enabled=yes
root.Image.I1.Source=1
root.Image.I2.Enabled=yes
root.Image.I2.Name=Vue panoramique
root.Image.I2.Source=1,0                 # vue groupée (2 capteurs)
# group=Properties.Image → NbrOfViews=3 et Properties.Image.I<i>.Resolution
```

### Activation d'une caméra neuve, sans auth (3)

```
$ curl -s -X POST "http://127.0.0.30:8080/axis-cgi/pwdgrp.cgi" \
    --data-raw 'action=add&user=root&pwd=NouveauMdp!2026&grp=root&sgrp=admin:operator:viewer:ptz'
OK
# ensuite : systemready → needsetup=no ; et pwdgrp?action=get sans auth → 401,
# avec le nouveau mdp → 200.
```

### Écriture réseau + migration d'IP (6)

```
$ curl -s --digest -u root:'MultiCapteur$9' \
    "http://127.0.0.41:8080/axis-cgi/param.cgi?action=update&Network.BootProto=none&Network.IPAddress=127.0.0.90&Network.SubnetMask=255.255.255.0&Network.DefaultRouter=10.0.20.1&Network.DNSServer1=10.0.20.1"
OK
# après ~2,5 s :
#   ancienne 127.0.0.41 -> connexion refusée (la caméra a « redémarré »)
#   nouvelle 127.0.0.90 -> root.Network.IPAddress=127.0.0.90
# BootProto=dhcp : migre vers la prochaine IP libre du pool (127.0.0.91…).
# IP hors pool (127.0.0.250) : la caméra disparaît (ni ancienne ni cible ne répondent).
```

### Changement de mot de passe (9)

```
$ curl -s --digest -u root:'Lentille#77' -X POST \
    "http://127.0.0.31:8080/axis-cgi/pwdgrp.cgi" --data-raw 'action=update&user=root&pwd=MotDePasseChange#1'
OK
#   ancien  mdp -> HTTP 401
#   nouveau mdp -> HTTP 200
```

### Heure (7) et lensparams (10)

```
$ curl -s --digest -u root:'MultiCapteur$9' -X POST "…/axis-cgi/time.cgi" \
    -d '{"apiVersion":"1.0","method":"setTimeZone","params":{"timeZone":"Europe/Paris"}}'
{"apiVersion": "1.0", "method": "setTimeZone", "data": {}}

$ curl -s --digest -u … -X POST "…/axis-cgi/lensparams/getcapabilities.cgi" -d 'schemaversion=3'
<LensParamsResponse SchemaVersion="3.0" …><Success><GetCapabilitiesSuccess>
<ImageSource number="0" … userControlSupported="true"></ImageSource>
<ImageSource number="1" … userControlSupported="true"></ImageSource>
</GetCapabilitiesSuccess></Success></LensParamsResponse>
```

## 6. Limites connues

- **Digest.** L'émulateur n'advertise que le Digest (MD5, qop=auth), comme une
  Axis en http clair. La validation recalcule la réponse à partir du `nonce` que
  le client renvoie ; elle ne vérifie pas la fraîcheur du nonce (inutile : le
  client LenScout ne fait qu'un seul aller-retour défi/réponse). Pas de Basic.
- **Migration d'IP.** Elle ne marche que si l'hôte **possède déjà l'alias** de
  la nouvelle IP (elle doit être dans le `pool`). Une IP fixe hors pool, ou que
  l'hôte ne porte pas, fait **disparaître** la caméra (cas de test « injoignable
  après changement », conforme). Le délai de « reboot » est `--migration-delay`
  (défaut 2,5 s). Après migration, l'ancienne IP est reversée au pool.
- **TLS.** Pas d'https ; prévoir d'autoriser l'http clair côté LenScout pour
  l'activation (voir §2).
- **Hikvision.** Seul `GET /ISAPI/System/deviceInfo` est imité (ce que lit
  l'identification) ; le reste de l'ISAPI ne l'est pas — suffisant pour le test
  « marque non prise en charge ».
- **Port privilégié.** Le port 80 impose `sudo`. L'auto-test utilise `--port 8080`
  sur loopback, mais LenScout, lui, ne balaie **que** le port 80 : le vrai test
  se fait bien en `sudo … --config fleet.json`.
