#!/usr/bin/env python3
"""Émulateur de parc de caméras Axis (et une Hikvision) pour tester LenScout.

Outil de TEST autonome : il ne fait PAS partie de l'application. Il fait
répondre plusieurs fausses caméras, chacune sur sa propre IP, en HTTP, en
imitant au plus près le contrat VAPIX que LenScout balaie. Bibliothèque
standard de Python 3 uniquement — aucun paquet à installer.

Lancement typique (vraies IP du VLAN 20, port 80 → root) :

    sudo python3 emulate.py --config fleet.json

Pose des alias d'abord (voir le README). Test local sur loopback :

    python3 emulate.py --config fleet.localhost.json --port 8080

Chaque caméra écoute sur (son IP, port). L'hôte DOIT posséder ces IP (alias),
sinon le bind échoue et la caméra est signalée injoignable.
"""

import argparse
import hashlib
import json
import re
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


# --------------------------------------------------------------------------
# Journal (jamais de mot de passe)
# --------------------------------------------------------------------------

_LOG_LOCK = threading.Lock()


def log(cam_ip, client_ip, method, path, outcome):
    """Une ligne par requête, sans jamais le moindre secret."""
    ts = datetime.now().strftime("%H:%M:%S")
    # On tronque la query et on efface toute valeur de mot de passe au cas où
    # un chemin en porterait une (il ne devrait jamais, pwd part en POST).
    safe = re.sub(r"(pwd|password)=[^&\s]*", r"\1=***", path)
    with _LOG_LOCK:
        print(f"{ts}  {cam_ip:<15} <- {client_ip:<15} {method:<4} {outcome:<18} {safe}",
              flush=True)


# --------------------------------------------------------------------------
# Digest HTTP côté serveur (realm, nonce, MD5)
# --------------------------------------------------------------------------

def _md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


_AUTH_FIELD = re.compile(r'(\w+)=(?:"([^"]*)"|([^,\s]+))')


def parse_authorization(header):
    """Décompose un en-tête `Authorization: Digest …` en dict de champs."""
    if not header or not header.strip().lower().startswith("digest"):
        return None
    out = {}
    for key, quoted, bare in _AUTH_FIELD.findall(header.split(None, 1)[1]):
        out[key] = bare if bare else quoted
    return out


def digest_response_ok(fields, method, password):
    """Recalcule la réponse Digest attendue et la compare (MD5, qop=auth)."""
    try:
        username = fields["username"]
        realm = fields["realm"]
        nonce = fields["nonce"]
        uri = fields["uri"]
        got = fields["response"]
    except KeyError:
        return False
    ha1 = _md5(f"{username}:{realm}:{password}")
    ha2 = _md5(f"{method}:{uri}")
    qop = fields.get("qop")
    if qop:
        nc = fields.get("nc", "")
        cnonce = fields.get("cnonce", "")
        expected = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        expected = _md5(f"{ha1}:{nonce}:{ha2}")
    return expected == got


# --------------------------------------------------------------------------
# Modèle d'une caméra (état mutable, protégé par un verrou)
# --------------------------------------------------------------------------

class Camera:
    def __init__(self, cfg, default_mask):
        self.lock = threading.RLock()
        self.brand = cfg.get("brand", "axis").lower()
        self.ip = cfg["ip"]
        self.model = cfg.get("model", "")
        self.serial = cfg.get("serial", "")
        self.firmware = cfg.get("firmware", "11.11.0")
        # "new" = neuve (aucun compte) ; "activated" = compte posé.
        self.state = cfg.get("state", "activated").lower()
        self.addressing = cfg.get("addressing", "dhcp").lower()  # dhcp | static
        self.mask = cfg.get("mask", default_mask)
        self.gateway = cfg.get("gateway")
        self.dns = list(cfg.get("dns", []))
        # users : {login: mot_de_passe}. Vide si neuve.
        self.users = dict(cfg.get("users", {}))
        self.timezone = cfg.get("timezone", "UTC")
        self.ntp_servers = list(cfg.get("ntp_servers", []))
        # Vues : liste de {source, name, resolution}. Défaut : un seul capteur.
        views = cfg.get("views")
        if not views:
            views = [{"source": "0", "name": cfg.get("view_name", "View 1"),
                      "resolution": cfg.get("resolution", "1920x1080,1280x720,640x360")}]
        self.views = views
        self.realm = "AXIS_" + (self.serial or "00000000")
        # Heure posée par LenScout (mémorisée, renvoyée telle quelle).
        self.set_tz = None
        self.set_ntp = None
        # True une fois la caméra « disparue » après une migration hors pool.
        self.gone = False

    def is_new(self):
        return self.state == "new" or not self.users

    def first_user(self):
        return next(iter(self.users), "root")

    def password_of(self, login):
        return self.users.get(login)

    # ---- Paramètres param.cgi (dictionnaire clé Axis -> valeur) ----
    def params(self):
        """Toutes les clés `param.cgi` de la caméra, à plat."""
        p = {}
        proto = "dhcp" if self.addressing == "dhcp" else "none"
        p["Network.BootProto"] = proto
        p["Network.IPAddress"] = self.ip
        p["Network.SubnetMask"] = self.mask
        p["Network.DefaultRouter"] = self.gateway or ""
        p["Network.DNSServer1"] = self.dns[0] if len(self.dns) > 0 else ""
        p["Network.DNSServer2"] = self.dns[1] if len(self.dns) > 1 else ""
        p["Properties.System.SerialNumber"] = self.serial
        p["Properties.Image.NbrOfViews"] = str(len(self.views))
        # Nombre de capteurs distincts (une vue groupée « 1,0 » ne compte pas).
        sensors = {v.get("source", "0") for v in self.views if "," not in v.get("source", "0")}
        p["ImageSource.NbrOfSources"] = str(max(1, len(sensors)))
        for i, v in enumerate(self.views):
            p[f"Image.I{i}.Enabled"] = "yes"
            p[f"Image.I{i}.Name"] = v.get("name", f"View {i + 1}")
            p[f"Image.I{i}.Source"] = v.get("source", "0")
            p[f"Image.I{i}.Appearance.Rotation"] = "0"
            p[f"Properties.Image.I{i}.Resolution"] = v.get(
                "resolution", "1920x1080,1280x720,640x360")
            p[f"Properties.Image.I{i}.Rotation"] = "0"
        # Heure (repli param.cgi).
        if self.set_tz:
            p["Time.SyncSource"] = "NTP" if self.set_ntp else "None"
        return p

    def param_list_body(self, groups):
        """Corps texte d'un `action=list&group=g1,g2` : `root.K=V` par clé."""
        wanted = [g.strip() for g in groups.split(",") if g.strip()]
        params = self.params()
        lines = []
        for key in params:
            if any(key == g or key.startswith(g + ".") for g in wanted):
                lines.append(f"root.{key}={params[key]}")
        return "\n".join(lines) + ("\n" if lines else "")


# --------------------------------------------------------------------------
# Gestion du parc : un serveur HTTP par IP, migrations, pool d'IP libres
# --------------------------------------------------------------------------

class Fleet:
    def __init__(self, cfg, port, migration_delay):
        self.port = port
        self.default_mask = cfg.get("netmask", "255.255.255.0")
        self.migration_delay = migration_delay
        self.cameras = [Camera(c, self.default_mask) for c in cfg["cameras"]]
        self.pool = list(cfg.get("pool", []))  # IP libres pour renumérotation
        self.pool_lock = threading.Lock()
        # ip -> (server, thread). L'ensemble des serveurs actifs.
        self.servers = {}
        self.servers_lock = threading.Lock()

    # ---- Pool d'IP libres ----
    def take_pool_ip(self, wanted=None):
        with self.pool_lock:
            if wanted is not None:
                if wanted in self.pool:
                    self.pool.remove(wanted)
                    return wanted
                return None
            if self.pool:
                return self.pool.pop(0)
            return None

    def release_pool_ip(self, ip):
        with self.pool_lock:
            if ip and ip not in self.pool:
                self.pool.append(ip)

    # ---- Serveurs ----
    def start(self):
        for cam in self.cameras:
            self._bind(cam)
        if not self.servers:
            print("Aucune caméra n'a pu être liée. L'hôte possède-t-il les alias ?",
                  file=sys.stderr)
            sys.exit(1)

    def _bind(self, cam):
        """Lie un serveur HTTP sur (cam.ip, port). Renvoie True si lié."""
        try:
            server = ThreadingHTTPServer((cam.ip, self.port), Handler)
        except OSError as e:
            print(f"  bind {cam.ip}:{self.port} IMPOSSIBLE ({e}) — "
                  f"caméra {cam.model} injoignable (alias manquant ?)",
                  file=sys.stderr)
            cam.gone = True
            return False
        server.camera = cam
        server.fleet = self
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True,
                                  name=f"cam-{cam.ip}")
        thread.start()
        with self.servers_lock:
            self.servers[cam.ip] = (server, thread)
        tag = "NEUVE" if cam.is_new() else "activée"
        kind = cam.brand.upper()
        print(f"  {cam.ip}:{self.port}  {kind} {cam.model} [{tag}, {cam.addressing}] "
              f"sn={cam.serial}")
        return True

    def _unbind(self, ip):
        with self.servers_lock:
            entry = self.servers.pop(ip, None)
        if entry:
            server, thread = entry
            server.shutdown()
            server.server_close()

    def schedule_migration(self, cam, target_ip, dhcp):
        """Programme un changement d'IP après un court délai (simule le reboot)."""
        def run():
            time.sleep(self.migration_delay)
            self._migrate(cam, target_ip, dhcp)
        threading.Thread(target=run, daemon=True,
                         name=f"migrate-{cam.ip}").start()

    def _migrate(self, cam, target_ip, dhcp):
        old_ip = cam.ip
        if dhcp:
            new_ip = self.take_pool_ip()
            if new_ip is None:
                log(old_ip, "-", "SYS", "migrate", "dhcp:pas d'IP libre")
                return
        else:
            new_ip = self.take_pool_ip(target_ip)
            if new_ip is None:
                # IP hors pool (ou déjà prise) : l'hôte ne peut pas la servir.
                self._unbind(old_ip)
                with cam.lock:
                    cam.ip = target_ip
                    cam.gone = True
                log(old_ip, "-", "SYS", "migrate",
                    f"hors pool -> {target_ip} DISPARUE")
                return
        # On bascule : coupe l'ancienne, lie la nouvelle, libère l'ancienne IP.
        self._unbind(old_ip)
        with cam.lock:
            cam.ip = new_ip
            cam.addressing = "dhcp" if dhcp else "static"
        if self._bind(cam):
            self.release_pool_ip(old_ip)
            log(old_ip, "-", "SYS", "migrate", f"-> {new_ip} OK")
        else:
            with cam.lock:
                cam.gone = True
            log(old_ip, "-", "SYS", "migrate", f"-> {new_ip} bind KO")

    def serve_forever(self):
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("\nArrêt.")
            with self.servers_lock:
                ips = list(self.servers)
            for ip in ips:
                self._unbind(ip)


# --------------------------------------------------------------------------
# Handler HTTP commun à toutes les caméras
# --------------------------------------------------------------------------

JSON = "application/json"
TEXT = "text/plain"
XML = "text/xml"


class Handler(BaseHTTPRequestHandler):
    server_version = "AxisHTTP/1.0"
    protocol_version = "HTTP/1.1"

    # On garde le journal unifié ; on neutralise celui de la lib.
    def log_message(self, *args):
        pass

    @property
    def cam(self):
        return self.server.camera

    @property
    def fleet(self):
        return self.server.fleet

    # ---- utilitaires de réponse ----
    def _send(self, status, body, ctype=TEXT, extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj), JSON)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def _challenge(self):
        """401 avec un défi Digest frais."""
        nonce = _md5(f"{time.time()}:{id(self)}")
        hdr = f'Digest realm="{self.cam.realm}", nonce="{nonce}", qop="auth"'
        self._send(401, "Unauthorized", TEXT,
                   extra_headers=[("WWW-Authenticate", hdr)])

    def _authed(self):
        """Vérifie le Digest ; renvoie (ok, login). Challenge émis si absent."""
        fields = parse_authorization(self.headers.get("Authorization"))
        if not fields:
            return (False, None)
        login = fields.get("username")
        pwd = self.cam.password_of(login)
        if pwd is None:
            return (False, login)
        return (digest_response_ok(fields, self.command, pwd), login)

    def _require_auth(self):
        """True si authentifié ; sinon émet 401 et renvoie False."""
        ok, _login = self._authed()
        if ok:
            return True
        self._challenge()
        return False

    # ---- points d'entrée HTTP ----
    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_HEAD(self):
        self._route("HEAD")

    def _route(self, method):
        client = self.client_address[0]
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        with self.cam.lock:
            if self.cam.gone:
                # Caméra disparue : on ne devrait plus écouter ici.
                self._send(404, "")
                log(self.cam.ip, client, method, self.path, "GONE")
                return
            outcome = self._dispatch(method, path, query)
        log(self.cam.ip, client, method, self.path, outcome)

    def _dispatch(self, method, path, query):
        body = self._read_body()

        # Une caméra non-Axis (Hikvision) ne répond à AUCUN endpoint Axis :
        # sinon LenScout, qui sonde `basicdeviceinfo.cgi` en premier, la prendrait
        # pour une Axis. Une vraie Hikvision renvoie 404 là, puis est reconnue
        # par son ISAPI.
        if self.cam.brand != "axis" and path.startswith("/axis-cgi/"):
            return self._send(404, "Not Found")

        # 1. Identité (anonyme)
        if path == "/axis-cgi/basicdeviceinfo.cgi" and method == "POST":
            return self._basic_device_info()

        # 2. État d'activation (anonyme)
        if path == "/axis-cgi/systemready.cgi" and method == "POST":
            return self._systemready()

        # Hikvision : identité (le reste de ses endpoints n'est pas imité).
        if path == "/ISAPI/System/deviceInfo" and method == "GET":
            return self._hik_device_info()

        # 3 & 9. Comptes
        if path == "/axis-cgi/pwdgrp.cgi":
            return self._pwdgrp(method, query, body)

        # 5 & 6. param.cgi (lecture et écriture réseau, séries, vues).
        # L'écriture arrive en POST avec les paramètres dans le CORPS (comme
        # une vraie Axis) ; on les fusionne avec ceux de l'URL.
        if path == "/axis-cgi/param.cgi":
            # Un POST sur param.cgi est une écriture : comme une vraie Axis, on
            # exige l'auth AVANT de lire l'action. Les clients Digest sondent
            # d'abord avec un corps vide pour obtenir le défi 401 ; sans cette
            # garde, cette sonde vide retomberait sur « action inconnue » (200)
            # et le client ne s'authentifierait jamais.
            if method == "POST" and not self._require_auth():
                return "401"
            params = dict(query)
            if method == "POST" and body:
                params.update(parse_qs(body.decode("utf-8", "replace")))
            return self._param_cgi(params)

        # 7. Heure
        if path == "/axis-cgi/time.cgi" and method == "POST":
            return self._time_cgi(body)
        if path == "/axis-cgi/ntp.cgi" and method == "POST":
            return self._ntp_cgi(body)

        # Réinitialisation (authentifiée) — répond OK pour ne pas bloquer.
        if path in ("/axis-cgi/factorydefault.cgi", "/axis-cgi/hardfactorydefault.cgi"):
            if not self._require_auth():
                return "401"
            self._send(200, "OK\n")
            return "auth-ok"

        # 10. BDC / lensparams (facultatif)
        if path == "/axis-cgi/lensparams/getcapabilities.cgi" and method == "POST":
            return self._lens_capabilities()
        if path == "/axis-cgi/lensparams/setdistortioncorrectionmode.cgi" and method == "POST":
            return self._lens_set_bdc()
        if path == "/axis-cgi/opticscontrol.cgi" and method == "POST":
            return self._optics(body)

        self._send(404, "")
        return "404"

    # ---- implémentations ----
    def _basic_device_info(self):
        cam = self.cam
        data = {
            "apiVersion": "1.2",
            "context": "lenscout",
            "data": {
                "propertyList": {
                    "Brand": "AXIS",
                    "ProdFullName": f"AXIS {cam.model} Network Camera",
                    "ProdNbr": cam.model,
                    "ProdShortName": f"AXIS {cam.model}",
                    "SerialNumber": cam.serial,
                    "Version": cam.firmware,
                }
            },
        }
        self._json(200, data)
        return "anon-ok"

    def _systemready(self):
        needsetup = "yes" if self.cam.is_new() else "no"
        self._json(200, {"apiVersion": "1.1", "data": {"needsetup": needsetup}})
        return f"anon-ok needsetup={needsetup}"

    def _hik_device_info(self):
        cam = self.cam
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">\n'
            f"<model>{cam.model}</model>\n"
            f"<serialNumber>{cam.serial}</serialNumber>\n"
            f"<firmwareVersion>{cam.firmware}</firmwareVersion>\n"
            "</DeviceInfo>\n"
        )
        self._send(200, xml, XML)
        return "anon-ok (hikvision)"

    def _pwdgrp(self, method, query, body):
        form = parse_qs(body.decode("utf-8", "replace")) if body else {}
        # Certaines requêtes passent l'action en query (action=get).
        action = (form.get("action") or query.get("action") or [""])[0]
        user = (form.get("user") or [""])[0]
        pwd = (form.get("pwd") or [""])[0]

        # Caméra NEUVE : seule l'activation (action=add) est anonyme ; tout le
        # reste répond 401 (doc « Example 12 » : il faut d'abord un compte).
        if self.cam.is_new():
            if action == "add":
                if not user or not pwd:
                    self._send(200, "Error: invalid credentials.\n")
                    return "activate rejeté"
                self.cam.users[user] = pwd
                self.cam.state = "activated"
                self._send(200, "OK\n")
                return "ACTIVÉE (anon)"
            self._challenge()
            return "401 (neuve)"

        # Caméra ACTIVÉE : tout pwdgrp exige l'authentification. On la vérifie
        # AVANT de lire l'action, pour que la sonde Digest à corps vide reçoive
        # bien un 401 (sinon le client ne s'authentifie pas).
        if not self._require_auth():
            return "401"

        if action == "get":
            users = " ".join(self.cam.users)
            self._send(200, f"users=\"{users}\"\n")
            return "auth-ok get"
        if action == "add":
            # Création d'un compte supplémentaire.
            self.cam.users[user] = pwd
            self._send(200, "OK\n")
            return "auth-ok add-user"
        if action == "update":
            if not user or not pwd:
                self._send(200, "Error: invalid password.\n")
                return "update rejeté"
            self.cam.users[user] = pwd
            self._send(200, "OK\n")
            return "auth-ok change-pwd"

        self._send(200, "Error: unknown action.\n")
        return "pwdgrp action inconnue"

    def _param_cgi(self, query):
        action = (query.get("action") or [""])[0]
        if action == "list":
            group = (query.get("group") or [""])[0]
            # La série est lisible anonymement (repli AXIS OS < 8.40) ; le reste
            # exige le compte.
            anon_ok = group.strip() == "Properties.System.SerialNumber"
            if not anon_ok and not self._require_auth():
                return "401"
            self._send(200, self.cam.param_list_body(group))
            return "auth-ok list" if not anon_ok else "anon-ok list"
        if action == "update":
            if not self._require_auth():
                return "401"
            return self._param_update(query)
        self._send(200, "# Error: unknown action.\n")
        return "param action inconnue"

    def _param_update(self, query):
        cam = self.cam
        proto = (query.get("Network.BootProto") or [None])[0]
        new_ip = (query.get("Network.IPAddress") or [None])[0]
        mask = (query.get("Network.SubnetMask") or [None])[0]
        gw = (query.get("Network.DefaultRouter") or [None])[0]
        dns1 = (query.get("Network.DNSServer1") or [None])[0]
        dns2 = (query.get("Network.DNSServer2") or [None])[0]

        migrate = None  # (target_ip, dhcp)
        if proto == "dhcp":
            cam.addressing = "dhcp"
            migrate = (None, True)
        elif proto == "none":
            cam.addressing = "static"
            if mask:
                cam.mask = mask
            if gw is not None:
                cam.gateway = gw
            dns = [d for d in (dns1, dns2) if d]
            if dns:
                cam.dns = dns
            if new_ip and new_ip != cam.ip:
                migrate = (new_ip, False)
            elif new_ip:
                cam.ip = new_ip

        # Heure par repli param.cgi (Time.*), accepté en silence.
        self._send(200, "OK\n")
        if migrate is not None:
            self.fleet.schedule_migration(cam, migrate[0], migrate[1])
            return f"auth-ok update -> migration {migrate}"
        return "auth-ok update"

    def _time_cgi(self, body):
        if not self._require_auth():
            return "401"
        try:
            req = json.loads(body or b"{}")
        except json.JSONDecodeError:
            req = {}
        params = req.get("params", {})
        if req.get("method") == "setTimeZone":
            self.cam.set_tz = params.get("timeZone")
        self._json(200, {"apiVersion": "1.0",
                         "method": req.get("method", "setTimeZone"),
                         "data": {}})
        return f"auth-ok setTimeZone={self.cam.set_tz}"

    def _ntp_cgi(self, body):
        if not self._require_auth():
            return "401"
        try:
            req = json.loads(body or b"{}")
        except json.JSONDecodeError:
            req = {}
        params = req.get("params", {})
        if req.get("method") == "setNTPClientConfiguration":
            self.cam.set_ntp = params.get("staticServers")
        self._json(200, {"apiVersion": "1.0",
                         "method": req.get("method", "setNTPClientConfiguration"),
                         "data": {}})
        return "auth-ok setNTP"

    def _lens_capabilities(self):
        if not self._require_auth():
            return "401"
        sensors = sorted({v.get("source", "0") for v in self.cam.views
                          if "," not in v.get("source", "0")})
        srcs = "".join(
            f'<ImageSource number="{s}" cropSupported="false" '
            f'manualCorrectionSupported="false" currentMode="off" '
            f'userControlSupported="true"></ImageSource>'
            for s in sensors)
        xml = (
            '<LensParamsResponse SchemaVersion="3.0" '
            'xmlns="http://www.axis.com/vapix/http_cgi/lensparams3">'
            f"<Success><GetCapabilitiesSuccess>{srcs}"
            "</GetCapabilitiesSuccess></Success></LensParamsResponse>"
        )
        self._send(200, xml, XML)
        return "auth-ok lens-caps"

    def _lens_set_bdc(self):
        if not self._require_auth():
            return "401"
        xml = ('<LensParamsResponse SchemaVersion="3.0"><Success>'
               '<SetDistortionCorrectionModeSuccess></SetDistortionCorrectionModeSuccess>'
               '</Success></LensParamsResponse>')
        self._send(200, xml, XML)
        return "auth-ok lens-set"

    def _optics(self, body):
        if not self._require_auth():
            return "401"
        # Réponse getOptics minimale (un capteur, non mobile).
        self._json(200, {
            "apiVersion": "1.0",
            "method": "getOptics",
            "data": {"optics": [{"id": "0", "focusMoving": False,
                                 "zoomMoving": False}]},
        })
        return "auth-ok optics"


# --------------------------------------------------------------------------
# Entrée
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Émulateur de caméras Axis pour LenScout.")
    ap.add_argument("--config", required=True, help="fichier JSON du parc")
    ap.add_argument("--port", type=int, default=80,
                    help="port d'écoute de chaque caméra (défaut 80 ; root requis)")
    ap.add_argument("--migration-delay", type=float, default=2.5,
                    help="délai (s) avant qu'une caméra reparaisse à sa nouvelle IP")
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)

    fleet = Fleet(cfg, args.port, args.migration_delay)
    print(f"Émulateur : {len(fleet.cameras)} caméras, port {args.port}, "
          f"pool {len(fleet.pool)} IP, délai migration {args.migration_delay}s")
    fleet.start()
    print("Prêt. Ctrl-C pour arrêter.")
    fleet.serve_forever()


if __name__ == "__main__":
    main()
