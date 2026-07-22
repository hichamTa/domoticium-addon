#!/usr/bin/env python3
"""
Domoticium — Add-on Home Assistant
Phase 1 (une seule fois) :
  • Configure MQTT → Mosquitto local
  • Installe Zigbee2MQTT, Matter Server, Frigate NVR
  • Crée l'automation heartbeat + écrit les rest_commands (heartbeat, caméra hors ligne)
Phase 2 (service permanent) :
  • Démarre cloudflared (Cloudflare Tunnel → go2rtc Frigate + serveur de commandes)
  • Bridge HA WebSocket → Supabase (état temps réel, remplace EMQX)
  • Serveur de commandes HTTP local (Vercel → HA API, remplace EMQX)
  • Gestion des caméras : ajoute/supprime dans Frigate à la demande
  • Commissionnement Matter
"""
import base64, hashlib, hmac, http.server, json, os, re, secrets, socket, socketserver, struct, subprocess, sys, threading, time, uuid
import paho.mqtt.client as mqtt
import requests

# ── Config depuis l'UI HA ──────────────────────────────────────────────────────
with open("/data/options.json") as f:
    cfg = json.load(f)

SITE_PREFIX             = cfg["site_prefix"]
PI_USER                 = cfg["pi_username"]
PI_PASS                 = cfg["pi_password"]
COORDINATOR_HOST        = cfg.get("coordinator_host", "").strip()   # vide = mode USB
COORDINATOR_ZIGBEE_PORT = cfg.get("coordinator_zigbee_port", 6638)
COORDINATOR_THREAD_PORT = cfg.get("coordinator_thread_port", 20108)
ZIGBEE_ADAPTER          = cfg.get("zigbee_adapter", "auto")
ZIGBEE_ADAPTER_TYPE     = cfg.get("zigbee_adapter_type", "ember")
INSTALL_THREAD_ROUTER   = cfg.get("install_thread_border_router", False)
THREAD_ADAPTER          = cfg.get("thread_adapter", "auto")
APP_URL                 = cfg.get("app_url", "https://app.domoticium.fr")
CLOUDFLARE_TUNNEL_TOKEN = cfg.get("cloudflare_tunnel_token", "")
FORCE_SETUP             = cfg.get("force_setup", False)
INGEST_SECRET           = cfg.get("ingest_secret", "")

# Appels directs Pi → Supabase (heartbeat, sync Zigbee/Matter, états devices,
# statut caméra — cf. HANDOFF §36/§37) : seul chemin, plus de repli Vercel. URL et
# clé publique "anon" : pas des secrets, mêmes valeurs pour tous les sites,
# embarquées ici comme APP_URL plutôt qu'en option addon. L'authentification par
# site passe par une signature HMAC calculée avec INGEST_SECRET (cf.
# _pi_sign/_supabase_rpc), jamais par cette clé anon seule. En cas d'échec d'un
# appel (réseau, Supabase indisponible) : log + nouvelle tentative au prochain
# cycle (heartbeat/sync périodiques, ou réintégration dans le batch pour les
# états/statuts caméra) — aucune donnée n'est perdue silencieusement.
SUPABASE_URL        = "https://oomiihobburvajrypeqc.supabase.co"
SUPABASE_ANON_KEY   = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6"
                       "Im9vbWlpaG9iYnVydmFqcnlwZXFjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODIwODA3"
                       "MDMsImV4cCI6MjA5NzY1NjcwM30.tlNndai0Nw_cyoLDuemP7gsna_r8WW2f0O0VhmHuMg0")

# Serveur de commandes local (127.0.0.1 uniquement, exposé via le tunnel Cloudflare
# existant sous un hostname dédié ha-{slug}.domoticium.fr). Remplace EMQX entièrement :
# plus de broker cloud, Vercel appelle ce serveur en HTTPS, authentifié par INGEST_SECRET.
COMMAND_PORT = 8098

# Mode réseau (PoE) ou USB
NETWORK_MODE = bool(COORDINATOR_HOST)

SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
SUP  = "http://supervisor"
API  = f"{SUP}/core/api"
HDRS = {"Authorization": f"Bearer {SUPERVISOR_TOKEN}", "Content-Type": "application/json"}

SETUP_DONE   = "/data/.setup_done"
CAMERAS_FILE = "/data/cameras.json"


def _pi_sign(message: str) -> str:
    """Signature HMAC-SHA256 d'un message avec INGEST_SECRET — authentifie les
    appels directs vers les fonctions Postgres pi_* (cf. HANDOFF §36). Le secret
    n'est jamais transmis lui-même, seulement cette signature."""
    return hmac.new(INGEST_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()


def _supabase_rpc(fn_name: str, payload: dict, timeout: float = 10.0) -> requests.Response:
    """Appelle une fonction Postgres pi_* via PostgREST (clé publique anon — la vraie
    autorisation vient de la signature HMAC incluse dans payload, vérifiée côté DB)."""
    return requests.post(
        f"{SUPABASE_URL}/rest/v1/rpc/{fn_name}",
        json=payload,
        headers={
            "apikey": SUPABASE_ANON_KEY,
            "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
            "Content-Type": "application/json",
        },
        timeout=timeout,
    )

Z2M_REPO       = "https://github.com/zigbee2mqtt/hassio-zigbee2mqtt"
Z2M_SLUG       = "45df7312_zigbee2mqtt"
MATTER_SLUG    = "core_matter_server"
THREAD_SLUG    = "core_openthread_border_router"
FRIGATE_REPO   = "https://github.com/hichamTa/frigate-hass-addons"
FRIGATE_SLUG   = "582436be_frigate"
# Ancien dépôt Frigate (officiel, upstream) — Frigate n'y lit JAMAIS notre frigate.yml
# (CONFIG_FILE non défini dans son config.yaml, donc find_config_file() résout vers son
# stockage privé addon_config, jamais /homeassistant/frigate.yml — confirmé en réel le
# 2026-07-22, cf. HANDOFF §55). Notre fork (repo ci-dessus) ajoute juste CONFIG_FILE:
# /homeassistant/frigate.yml à la config officielle de l'add-on, rien d'autre — même
# image Docker, mêmes options. Le slug d'un add-on HA dépend d'un hash de l'URL du
# dépôt (sha1(url)[:8] + "_" + slug interne) : changer de dépôt change donc le slug
# installé, d'où la migration one-shot ci-dessous (_migrate_frigate_repo_once).
OLD_FRIGATE_SLUG = "ccab4aaf_frigate"
MOSQUITTO_SLUG = "core_mosquitto"
MOSQUITTO_USER = "domoticium"

# ── Mot de passe Mosquitto — généré une fois, persisté dans /data/ ─────────────
_MOSQUITTO_PASS_FILE = "/data/mosquitto_pass"
if os.path.exists(_MOSQUITTO_PASS_FILE):
    with open(_MOSQUITTO_PASS_FILE) as _f:
        MOSQUITTO_PASS = _f.read().strip()
else:
    MOSQUITTO_PASS = secrets.token_hex(16)
    with open(_MOSQUITTO_PASS_FILE, "w") as _f:
        _f.write(MOSQUITTO_PASS)

_cameras: dict[str, str] = {}  # {stream_name: rtsp_url}

# Caméras avec audio bidirectionnel ("parler") activé — dict séparé plutôt que
# d'étendre _cameras (type dict[str,str] déjà lu/écrit à de nombreux endroits, risque
# de casser le flux vidéo principal déjà validé en conditions réelles). Persisté à
# part, cf. _load_camera_talk/_save_camera_talk.
CAMERA_TALK_FILE = "/data/camera_talk.json"
_camera_talk_enabled: set = set()

# Identifiants ICE WebRTC (STUN + TURN Cloudflare Realtime) injectés dans go2rtc via
# frigate.yml — rafraîchis périodiquement par _turn_refresh_loop() (cf. plus bas).
_TURN_REFRESH_INTERVAL = 24 * 3600  # 24h — identifiants Cloudflare valables 48h max
_turn_ice_servers: list[dict] = []

# Client MQTT local (Mosquitto, Z2M ↔ HA) — plus de client cloud, EMQX est retiré.
_local_client: mqtt.Client | None = None


def log(msg):  print(f"[domoticium] {msg}", flush=True)
def warn(msg): print(f"[domoticium] ⚠ {msg}", file=sys.stderr, flush=True)


def _local_ipv4() -> str:
    """IPv4 LAN de l'hôte (l'addon Domoticium tourne en host_network: true, donc c'est
    bien l'IP de l'hôte lui-même). Utilisée pour le scan réseau ONVIF (cf.
    _subnet_onvif_scan) — PAS pour la config webrtc de go2rtc/Frigate : ce dernier
    tourne dans son propre réseau Docker isolé (host_network: false côté add-on
    Frigate), donc cette IP n'y existe pas et n'y serait d'aucune utilité."""
    try:
        out = subprocess.check_output(['ip', 'route', 'get', '1.1.1.1'], text=True, timeout=2)
        m = re.search(r'src\s+(\d+\.\d+\.\d+\.\d+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    try:
        ip = socket.gethostbyname(socket.getfqdn())
        if ip and not ip.startswith('127.'):
            return ip
    except Exception:
        pass
    return ''

def sup_get(path):
    return requests.get(f"{SUP}{path}", headers=HDRS, timeout=15)

def sup_post(path, data=None, timeout=60):
    return requests.post(f"{SUP}{path}", headers=HDRS, json=data or {}, timeout=timeout)

def ha_post(path, data=None):
    return requests.post(f"{API}{path}", headers=HDRS, json=data or {}, timeout=15)

def ha_get(path):
    return requests.get(f"{API}{path}", headers=HDRS, timeout=15)


# ── WebSocket HA (nécessaire pour area_registry / entity_registry / device_registry) ──
# L'API REST HA n'expose pas ces registres ; seul le WebSocket les supporte.

def _ws_recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Socket fermé ({len(buf)}/{n} octets)")
        buf += chunk
    return buf


def _ha_ws_connect(long_lived: bool = False):
    """Ouvre et authentifie une session WebSocket HA.
    Retourne (ws_send, ws_recv, ws_close) ou (None, None, None) en cas d'erreur.
    ws_send(data: dict) — inclure {"id": N} dans data.
    ws_recv() → dict.
    long_lived=True (ex: run_ha_ws_bridge) : retire le timeout après l'auth — sinon le
    timeout de connexion (15s) s'applique aussi aux recv() suivants, et une simple absence
    d'événement HA pendant 15s est prise pour une erreur de connexion (reconnexion en boucle).
    """
    try:
        s = socket.create_connection(("supervisor", 80), timeout=15)

        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall((
            "GET /core/websocket HTTP/1.1\r\n"
            "Host: supervisor\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        # Lire seulement les en-têtes HTTP (jusqu'à \r\n\r\n)
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(1)
            if not chunk:
                raise ConnectionError("Socket fermé pendant handshake")
            resp += chunk
        if b"101" not in resp:
            raise ConnectionError(f"Handshake refusé: {resp[:80]}")

        def _recv():
            while True:
                h = _ws_recv_exact(s, 2)
                opcode = h[0] & 0x0F
                length = h[1] & 0x7F
                if length == 126:
                    length = struct.unpack(">H", _ws_recv_exact(s, 2))[0]
                elif length == 127:
                    length = struct.unpack(">Q", _ws_recv_exact(s, 8))[0]
                mask_bit = h[1] & 0x80
                if mask_bit:
                    mask = _ws_recv_exact(s, 4)
                raw = _ws_recv_exact(s, length)
                if mask_bit:
                    raw = bytes(b ^ mask[i % 4] for i, b in enumerate(raw))
                if opcode == 0x09:
                    s.sendall(bytes([0x8A, 0x80, 0, 0, 0, 0]))
                    continue
                if opcode == 0x08:
                    raise ConnectionError("WS close frame reçu")
                return json.loads(raw.decode())

        def _send(data: dict):
            payload = json.dumps(data).encode()
            msk = os.urandom(4)
            masked = bytes(b ^ msk[i % 4] for i, b in enumerate(payload))
            n = len(payload)
            if n < 126:
                header = bytes([0x81, 0x80 | n])
            elif n < 65536:
                header = bytes([0x81, 0xFE]) + struct.pack(">H", n)
            else:
                header = bytes([0x81, 0xFF]) + struct.pack(">Q", n)
            s.sendall(header + msk + masked)

        # Auth HA
        msg = _recv()
        if msg.get("type") != "auth_required":
            raise Exception(f"auth_required attendu, reçu: {msg.get('type')}")
        _send({"type": "auth", "access_token": SUPERVISOR_TOKEN})
        msg = _recv()
        if msg.get("type") != "auth_ok":
            raise Exception(f"Auth WS échouée: {msg}")

        if long_lived:
            s.settimeout(None)  # bloquant — le ping/pong WS (déjà géré dans _recv) détecte les connexions mortes

        return _send, _recv, s.close

    except Exception as exc:
        warn(f"[ha_ws] Connexion échouée: {exc}")
        return None, None, None


def _ha_ws_call(cmd_type: str, **params):
    """Appel unique : ouvre une session WS, exécute une commande, ferme. Retourne le résultat ou None."""
    ws_send, ws_recv, ws_close = _ha_ws_connect()
    if not ws_send:
        return None
    try:
        ws_send({"id": 1, "type": cmd_type, **params})
        return ws_recv()
    except Exception as exc:
        warn(f"[ha_ws] {cmd_type}: {exc}")
        return None
    finally:
        try:
            ws_close()
        except Exception:
            pass

def _sup_repos():
    """Retourne la liste des URLs de dépôts depuis le Supervisor.
    Gère le format HA Supervisor : {"result":"ok","data":{"repositories":[...]}}.
    """
    resp = sup_get("/store/repositories")
    try:
        body = resp.json()
    except Exception as e:
        warn(f"/store/repositories parse error: {e} | raw: {resp.text[:200]}")
        return []
    if isinstance(body, list):
        repos = body
    elif isinstance(body, dict):
        data = body.get("data", body.get("repositories", []))
        if isinstance(data, list):
            repos = data
        elif isinstance(data, dict):
            repos = data.get("repositories", [])
        else:
            repos = []
    else:
        repos = []
    return [r.get("source", "") for r in repos if isinstance(r, dict)]


def _resolve_frigate_slug(attempts: int = 4, delay: float = 5.0) -> bool:
    """Détermine le VRAI slug de l'add-on Frigate installable depuis FRIGATE_REPO, en
    interrogeant le Supervisor plutôt qu'en devinant sha1(url)[:8] — cette formule
    correspond bien au slug de dépôt observé pour l'upstream officiel (vérifié par
    calcul), mais rien ne garantit qu'elle soit fiable pour n'importe quelle URL (ex:
    normalisation différente selon casse/slash final) : une 1ère tentative en
    conditions réelles avec un slug deviné a échoué (404 "does not exist in the
    store"), cf. HANDOFF §57. Réessaie plusieurs fois avec un délai : le Supervisor met
    un peu de temps à indexer les add-ons d'un dépôt tout juste ajouté. Met à jour la
    variable globale FRIGATE_SLUG si trouvé."""
    global FRIGATE_SLUG
    for attempt in range(1, attempts + 1):
        try:
            r = sup_get("/store/repositories")
            body = r.json()
            repos = body.get("data", body) if isinstance(body, dict) else body
            repos = repos.get("repositories", repos) if isinstance(repos, dict) else repos
            repo_slug = next(
                (repo.get("slug") for repo in repos
                 if isinstance(repo, dict) and repo.get("source") == FRIGATE_REPO),
                None,
            )
            if repo_slug:
                r2 = sup_get("/store/addons")
                body2 = r2.json()
                addons = body2.get("data", body2) if isinstance(body2, dict) else body2
                addons = addons.get("addons", addons) if isinstance(addons, dict) else addons
                for addon in addons:
                    if (
                        isinstance(addon, dict)
                        and addon.get("repository") == repo_slug
                        and str(addon.get("slug", "")).endswith("_frigate")
                    ):
                        FRIGATE_SLUG = addon["slug"]
                        log(f"[frigate] Slug résolu dynamiquement : {FRIGATE_SLUG}")
                        return True
        except Exception as e:
            warn(f"[frigate] Résolution du slug Frigate (tentative {attempt}/{attempts}) : {e}")
        if attempt < attempts:
            time.sleep(delay)
    warn("[frigate] Impossible de résoudre le slug Frigate depuis le store — utilisation du fallback codé en dur")
    return False


def _is_addon_installed(slug: str) -> bool:
    """Vérifie si un add-on est réellement installé (pas seulement disponible en store).
    Le Supervisor retourne 200 même pour les add-ons du store non installés.
    Seul un champ 'installed' contenant une version string prouve l'installation réelle.
    """
    r = sup_get(f"/addons/{slug}/info")
    if r.status_code == 404:
        return False
    if not r.ok:
        return False
    try:
        body = r.json()
        data = body.get("data", body) if isinstance(body, dict) else {}
        installed = data.get("installed")
        state     = data.get("state", "unknown")
        log(f"[check] {slug}: installed={installed!r} state={state!r}")
        # Seule preuve fiable : installed est une version string non vide
        if isinstance(installed, str) and installed:
            return True
        # state != "unknown" = add-on connu du supervisor et installé (peut être stopped/error/started)
        return state not in ("unknown", None, "")
    except Exception as e:
        warn(f"_is_addon_installed({slug}) erreur: {e}")
        return True

def _load_cameras():
    global _cameras
    try:
        with open(CAMERAS_FILE) as f:
            _cameras = json.load(f)
        log(f"Caméras chargées : {list(_cameras.keys()) or '(aucune)'}")
    except FileNotFoundError:
        _cameras = {}
    _load_camera_talk()

def _save_cameras():
    with open(CAMERAS_FILE, "w") as f:
        json.dump(_cameras, f)

def _load_camera_talk():
    global _camera_talk_enabled
    try:
        with open(CAMERA_TALK_FILE) as f:
            _camera_talk_enabled = set(json.load(f))
    except FileNotFoundError:
        _camera_talk_enabled = set()

def _save_camera_talk():
    with open(CAMERA_TALK_FILE, "w") as f:
        json.dump(sorted(_camera_talk_enabled), f)


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

def wait_for_ha():
    log("Attente de Home Assistant…")
    for _ in range(60):
        try:
            if requests.get(f"{API}/", headers=HDRS, timeout=3).status_code < 500:
                log("Home Assistant est prêt.")
                return
        except Exception:
            pass
        time.sleep(3)
    warn("HA ne répond pas après 3 min.")
    sys.exit(1)


# ── Mosquitto ─────────────────────────────────────────────────────────────────

def setup_mosquitto():
    """Installe Mosquitto (si absent) et crée le user dédié Domoticium."""
    log("── Mosquitto ────────────────────────────────")

    if not _is_addon_installed(MOSQUITTO_SLUG):
        log("Installation de Mosquitto…")
        r = sup_post(f"/store/addons/{MOSQUITTO_SLUG}/install")
        if r.ok:
            log("✓ Mosquitto installé")
            time.sleep(5)
        else:
            warn(f"✗ Installation Mosquitto : {r.status_code} {r.text[:100]}")
            return
    else:
        log("Mosquitto déjà installé")

    # Le schéma Mosquitto exige tous les champs, même ceux avec des valeurs par défaut.
    r = sup_post(f"/addons/{MOSQUITTO_SLUG}/options", {
        "options": {
            "logins": [{"username": MOSQUITTO_USER, "password": MOSQUITTO_PASS}],
            "require_certificate": False,
            "certfile": "fullchain.pem",
            "keyfile": "privkey.pem",
            "customize": {"active": False, "folder": "mosquitto"},
        }
    })
    if r.ok:
        log(f"✓ Mosquitto configuré (user: {MOSQUITTO_USER})")
    else:
        warn(f"✗ Mosquitto options : {r.status_code} {r.text[:150]}")

    r = sup_post(f"/addons/{MOSQUITTO_SLUG}/restart")
    if r.ok:
        log("✓ Mosquitto redémarré")
        time.sleep(4)  # laisser le broker démarrer avant que Z2M s'y connecte
    else:
        warn(f"✗ Mosquitto restart : {r.status_code} {r.text[:100]}")


# ── Zigbee2MQTT ───────────────────────────────────────────────────────────────

def install_zigbee2mqtt():
    log("── Zigbee2MQTT ──────────────────────────────")

    existing_urls = _sup_repos()
    if Z2M_REPO not in existing_urls:
        r = sup_post("/store/repositories", {"repository": Z2M_REPO})
        if r.ok:
            log("✓ Dépôt Zigbee2MQTT ajouté")
            time.sleep(3)
        else:
            warn(f"Dépôt Z2M : {r.status_code} — continuer quand même")
    else:
        log("Dépôt Zigbee2MQTT déjà présent")

    if not _is_addon_installed(Z2M_SLUG):
        log("Installation de Zigbee2MQTT…")
        r = sup_post(f"/store/addons/{Z2M_SLUG}/install")
        if r.ok:
            log("✓ Zigbee2MQTT installé")
            time.sleep(5)
        else:
            warn(f"Installation Z2M : {r.status_code} {r.text[:100]}")
            return
    else:
        log("Zigbee2MQTT déjà installé")

    if NETWORK_MODE:
        zigbee_port = f"tcp://{COORDINATOR_HOST}:{COORDINATOR_ZIGBEE_PORT}"
        # Z2M v2 exige 'serial.adapter' pour TCP (ember/zstack/zboss…).
        # Sans lui, Z2M tente une découverte réseau qui échoue systématiquement.
        # 'auto' n'est PAS une valeur valide en v2 — le champ zigbee_adapter_type
        # (défaut 'ember', valide pour les coordinateurs SMLIGHT/EFR32) est utilisé.
        serial_cfg: dict = {"port": zigbee_port, "adapter": ZIGBEE_ADAPTER_TYPE}
        log(f"Mode réseau PoE — coordinateur Zigbee : {zigbee_port} (adapter={ZIGBEE_ADAPTER_TYPE})")
    else:
        zigbee_port = ZIGBEE_ADAPTER  # "auto" ou port USB explicite
        serial_cfg  = {"port": zigbee_port}  # USB : pas besoin de préciser le type

    z2m_dir = "/homeassistant/zigbee2mqtt"
    os.makedirs(z2m_dir, exist_ok=True)

    # "network_key": "GENERATE" ne doit être écrit qu'à la toute première installation.
    # Le réécrire à chaque run_setup() (ex: force_setup) fait redemander une NOUVELLE clé
    # aléatoire à chaque fois → décalage avec le backup Zigbee-herdsman existant → Z2M
    # reforme un réseau vierge et perd TOUS les appareils déjà appairés (vu en test réel :
    # "Currently 0 devices are joined" après un force_setup sur un coordinateur déjà en service).
    is_first_setup = not os.path.exists(f"{z2m_dir}/configuration.yaml")
    advanced_cfg: dict = {"log_level": "info"}
    if is_first_setup:
        advanced_cfg["network_key"] = "GENERATE"

    z2m_config = {
        "mqtt": {
            # Z2M → Mosquitto local (offline-first).
            # Notre add-on relaie ensuite vers EMQX Cloud en phase 2.
            "server": "mqtt://core-mosquitto:1883",
            "username": MOSQUITTO_USER,
            "password": MOSQUITTO_PASS,
            "base_topic": "zigbee2mqtt",  # topic standard (sans préfixe site)
        },
        "serial": serial_cfg,
        # Discovery standard homeassistant/ — HA MQTT integration écoute ce préfixe.
        "homeassistant": {
            "discovery_topic": "homeassistant",
            "status_topic":    "homeassistant/status",
        },
        "permit_join": False,
        "advanced": advanced_cfg,
        "frontend": {"port": 8099},
    }

    with open(f"{z2m_dir}/configuration.yaml", "w") as f:
        f.write(_dict_to_yaml(z2m_config))
    log("✓ Configuration Zigbee2MQTT écrite")

    # Les options du Z2M add-on ont PRIORITÉ sur configuration.yaml (cf. DOCS Z2M).
    # Le startup script écrase les champs MQTT avec les valeurs des options —
    # il faut donc passer les credentials ici, pas seulement dans le YAML.
    # Note : le schéma add-on utilise 'user' (pas 'username') pour le champ MQTT.
    serial_opts: dict = {"port": zigbee_port, "adapter": ZIGBEE_ADAPTER_TYPE} if NETWORK_MODE else {"port": zigbee_port}
    r = sup_post(f"/addons/{Z2M_SLUG}/options", {
        "options": {
            "data_path": "/config/zigbee2mqtt",
            "socat": {
                "enabled": False,
                "master": "pty,raw,echo=0",
                "slave": "tcp-listen:8485,keepalive,nodelay,reuseaddr,keepidle=1,keepintvl=1,keepcnt=5",
                "options": "",
                "log": False,
            },
            "mqtt": {
                "server": "mqtt://core-mosquitto:1883",
                "user": MOSQUITTO_USER,
                "password": MOSQUITTO_PASS,
                "base_topic": "zigbee2mqtt",
            },
            "serial": serial_opts,
            # homeassistant: True → Z2M publie la discovery sur homeassistant/
            # HA MQTT integration (sur Mosquitto local) détecte les entités Zigbee.
            "homeassistant": True,
        }
    })
    if r.ok:
        log("✓ Options Zigbee2MQTT appliquées")
    else:
        warn(f"✗ Z2M options: {r.status_code} {r.text[:150]}")

    r = sup_post(f"/addons/{Z2M_SLUG}/restart")
    if r.ok:
        log("✓ Zigbee2MQTT démarré")
    else:
        warn(f"✗ {r.status_code} Zigbee2MQTT restart : {r.text[:150]}")


# ── Matter Server ─────────────────────────────────────────────────────────────

def install_matter_server():
    log("── Matter Server ────────────────────────────")

    if not _is_addon_installed(MATTER_SLUG):
        log("Installation de Matter Server…")
        r = sup_post(f"/store/addons/{MATTER_SLUG}/install")
        if r.ok:
            log("✓ Matter Server installé")
            time.sleep(5)
        else:
            warn(f"Installation Matter : {r.status_code} {r.text[:100]}")
            return
    else:
        log("Matter Server déjà installé")

    r = sup_post(f"/addons/{MATTER_SLUG}/restart")
    if r.ok:
        log("✓ Matter Server démarré")
    else:
        warn(f"✗ {r.status_code} Matter Server restart : {r.text[:150]}")

    flow = ha_post("/config/config_entries/flow", {"handler": "matter"})
    if flow.ok and flow.json().get("type") == "create_entry":
        log("✓ Intégration Matter activée")
    else:
        log("Intégration Matter : à activer manuellement si besoin")


# ── Thread Border Router ─────────────────────────────────────────────────────

def install_thread_border_router():
    log("── Thread Border Router ──────────────────────")

    if not _is_addon_installed(THREAD_SLUG):
        log("Installation de Open Thread Border Router…")
        r = sup_post(f"/store/addons/{THREAD_SLUG}/install")
        if r.ok:
            log("✓ Open Thread Border Router installé")
            time.sleep(5)
        else:
            warn(f"Installation Thread Border Router : {r.status_code} {r.text[:100]}")
            return
    else:
        log("Open Thread Border Router déjà installé")

    if NETWORK_MODE:
        # socat attend TCP:<host>:<port> — pas socket://host:port
        network_device = f"{COORDINATOR_HOST}:{COORDINATOR_THREAD_PORT}"
        device_label = f"socket://{COORDINATOR_HOST}:{COORDINATOR_THREAD_PORT}"
        log(f"Mode réseau PoE — coordinateur Thread : {device_label} (network_device={network_device})")
        # network_device = champ OTBR pour coordinateurs réseau (string libre, passé à socat)
        # device = port série requis par le schema, mis à /dev/ttyS0 par défaut (inutilisé en réseau)
        base_options = {
            "network_device": network_device,
            "device": "/dev/ttyS0",
            "baudrate": "460800",
            "flow_control": False,
            "firewall": True,
            "nat64": False,
            "otbr_log_level": "notice",
        }
    else:
        thread_port = THREAD_ADAPTER
        if thread_port == "auto":
            thread_port = _detect_thread_adapter()
            if thread_port:
                log(f"Dongle Thread détecté : {thread_port}")
            else:
                warn("Aucun dongle Thread détecté.")
                thread_port = "/dev/ttyACM1"
        device_label = thread_port
        base_options = {
            "device": thread_port,
            "baudrate": 460800,
            "flow_control": True,
            "autoflash_firmware": True,
        }

    # Lire le schéma réel + options actuelles pour diagnostiquer les formats acceptés
    schema_keys = None
    otbr_device_options = []  # valeurs autorisées pour le champ 'device'
    try:
        info = sup_get(f"/addons/{THREAD_SLUG}/info")
        if info.ok:
            data = info.json()
            if isinstance(data, dict):
                data = data.get("data", data)
            schema = data.get("schema", {})
            options_current = data.get("options", {})
            log(f"[OTBR] Schéma complet : {str(schema)[:2000]}")
            log(f"[OTBR] Options actuelles : {options_current}")
            # Le schema OTBR est une liste de champs, pas un dict
            if isinstance(schema, list):
                schema_keys = set()
                for field in schema:
                    if isinstance(field, dict) and field.get("name"):
                        fname = field["name"]
                        schema_keys.add(fname)
                        if fname == "device" and isinstance(field.get("options"), list):
                            otbr_device_options = field["options"]
                log(f"[OTBR] Champs schema : {sorted(schema_keys)}")
                log(f"[OTBR] Devices autorisés : {otbr_device_options}")
            elif isinstance(schema, dict) and schema:
                schema_keys = set(schema.keys())
    except Exception as e:
        warn(f"[OTBR] Lecture schéma : {e}")

    # Options filtrées aux champs connus du schéma (évite les 400 pour champ inconnu)
    if schema_keys:
        filtered = {k: v for k, v in base_options.items() if k in schema_keys}
    else:
        filtered = base_options

    # Si le schema liste des devices autorisés et que socket:// n'en fait pas partie,
    # OTBR ne supporte pas les coordinateurs réseau via l'API Supervisor.
    if otbr_device_options and device_label not in otbr_device_options:
        warn(
            f"[OTBR] Le device '{device_label}' n'est pas dans les options autorisées : {otbr_device_options}\n"
            f"       Le schéma OTBR ne liste que des ports série locaux.\n"
            f"       Vérification si un champ réseau existe dans le schéma : {sorted(schema_keys or [])}"
        )
        pass  # on continue avec les tentatives

    attempts = [
        ("network_device + device=/dev/ttyS0", {"options": filtered}),
        ("network_device seul",                {"options": {"network_device": device_label}}),
    ]
    options_ok = False
    for label, body in attempts:
        r = sup_post(f"/addons/{THREAD_SLUG}/options", body)
        if r.ok:
            log(f"✓ Configuration Thread Border Router ({device_label}) [{label}]")
            options_ok = True
            break
        err_text = r.text[:600]
        warn(f"[OTBR] {label} → {r.status_code}: {err_text}")

    if not options_ok:
        warn(f"✗ Impossible de configurer OTBR via Supervisor API — device={device_label}")
        return

    r = sup_post(f"/addons/{THREAD_SLUG}/restart")
    if r.ok:
        log("✓ Thread Border Router démarré")
    else:
        warn(f"✗ {r.status_code} Thread Border Router restart : {r.text[:150]}")

    time.sleep(5)
    flow = ha_post("/config/config_entries/flow", {"handler": "otbr"})
    log(f"[OTBR] flow init → {flow.status_code}: {flow.text[:400]}")
    if flow.ok:
        result = flow.json()
        flow_type = result.get("type")
        flow_id   = result.get("flow_id")
        step_id   = result.get("step_id")
        if flow_type == "create_entry":
            log("✓ Intégration OTBR (Thread) activée dans HA")
        elif flow_id:
            # Selon le step, soumettre l'URL de l'API OTBR (port 8081 par défaut).
            # "localhost" est FAUX ici : chaque add-on HA OS tourne dans son propre
            # conteneur — HA Core n'a pas d'API OTBR sur son propre "localhost".
            # Le nom d'hôte interne Supervisor suit toujours slug avec "_" → "-"
            # (même convention que core_mosquitto → "core-mosquitto:1883" ailleurs
            # dans ce fichier) — confirmé en test réel : OTBR démarre et forme
            # correctement son réseau Thread, seule cette URL était fausse.
            step_payload: dict = {}
            if step_id in ("user", None) or "url" in str(result.get("data_schema", "")):
                otbr_hostname = THREAD_SLUG.replace("_", "-")
                step_payload = {"url": f"http://{otbr_hostname}:8081"}
            log(f"[OTBR] step_id={step_id!r} → payload={step_payload}")
            r2 = requests.post(
                f"{API}/config/config_entries/flow/{flow_id}",
                headers=HDRS, json=step_payload, timeout=10
            )
            log(f"[OTBR] flow step → {r2.status_code}: {r2.text[:400]}")
            r2_json = r2.json() if r2.ok else {}
            r2_reason = r2_json.get("reason", "")
            if r2_json.get("type") == "create_entry" or "already" in r2_reason:
                log("✓ Intégration OTBR (Thread) activée dans HA")
            else:
                warn(f"[OTBR] Intégration non finalisée — {r2.status_code}: {r2.text[:200]}")
    else:
        log(f"[OTBR] Flow non démarré ({flow.status_code}) — intégration déjà active ou à vérifier")


def _detect_thread_adapter():
    """
    Détecte le port Thread parmi les dongles USB disponibles.

    Ordre de priorité :
      1. Dongles combo Zigbee+Thread (ex: SLZB-MR4U) → sélection par interface USB
         if00 = Zigbee (pour Z2M), if02 = Thread (pour OTBR)
      2. Nom explicitement Thread dans l'identifiant USB
      3. Fabricant Thread connu, en excluant les dongles Zigbee identifiés
      4. Fallback ttyACM1 / ttyUSB1
    """
    import glob

    # Dongles combo Zigbee+Thread — interface Thread connue
    # Format : { sous-chaîne du nom USB : interface Thread }
    COMBO_THREAD_IFACE = {
        "SLZB-MR": "if02",   # SMLIGHT SLZB-MR4U / SLZB-MR1 : if00=Zigbee, if02=Thread
    }

    ZIGBEE_ONLY   = ["zigbee", "sonoff", "conbee", "raspbee", "husbzb", "zha"]
    THREAD_NAMES  = ["thread", "openthread", "border_router", "otbr", "nrf52840"]
    THREAD_VENDORS = [
        "usb-Silicon_Labs",
        "usb-SEGGER",
        "usb-Nordic_Semiconductor",
        "usb-dresden_elektronik",
        "usb-SMLIGHT",
    ]

    by_id = glob.glob("/dev/serial/by-id/*")

    # Passe 0 : dongles combo → sélection par interface USB
    for device_key, thread_iface in COMBO_THREAD_IFACE.items():
        for path in by_id:
            if device_key in path and thread_iface in path:
                log(f"Dongle combo Zigbee+Thread détecté ({device_key}) — port Thread : {path}")
                return os.path.realpath(path)

    # Passe 1 : Thread explicite dans le nom USB
    for path in by_id:
        if any(kw in path.lower() for kw in THREAD_NAMES):
            log(f"Dongle Thread détecté (nom) : {path}")
            return os.path.realpath(path)

    # Passe 2 : fabricant Thread potentiel, dongles Zigbee exclus
    for path in by_id:
        if any(kw in path.lower() for kw in ZIGBEE_ONLY):
            continue
        if any(vid in path for vid in THREAD_VENDORS):
            log(f"Dongle Thread détecté (heuristique) : {path}")
            return os.path.realpath(path)

    # Fallback
    for port in ["/dev/ttyACM1", "/dev/ttyUSB1"]:
        if os.path.exists(port):
            return port
    return None


# ── Frigate NVR ───────────────────────────────────────────────────────────────

def _frigate_go2rtc_ready() -> bool:
    """Teste si Frigate est opérationnel (:1984 go2rtc ou :5000 UI). Retourne True si l'un répond."""
    for port, path in [(1984, "/api"), (5000, "/api")]:
        try:
            r = requests.get(f"http://127.0.0.1:{port}{path}", timeout=3)
            if r.status_code < 500:
                return True
        except Exception:
            pass
    return False


def _wait_frigate_ready(max_attempts: int = 36) -> bool:
    """Attend jusqu'à 3 min que Frigate soit disponible. Retourne True si succès."""
    log("Attente que Frigate (go2rtc :1984 ou UI :5000) soit disponible…")
    for i in range(max_attempts):
        time.sleep(5)
        for port, path in [(1984, "/api"), (5000, "/api")]:
            try:
                r = requests.get(f"http://127.0.0.1:{port}{path}", timeout=3)
                if r.status_code < 500:
                    log(f"✓ Frigate opérationnel sur :{port} (~{(i+1)*5}s)")
                    return True
            except Exception:
                pass
        if i % 6 == 5:
            log(f"  … toujours en attente ({(i+1)*5}s)")
    warn("Frigate pas disponible après 3 min (:1984 et :5000 inaccessibles)")
    return False


def _frigate_state() -> str:
    """Retourne l'état courant de l'add-on Frigate."""
    r = sup_get(f"/addons/{FRIGATE_SLUG}/info")
    if not r.ok:
        return "unknown"
    try:
        data = r.json()
        if isinstance(data, dict):
            data = data.get("data", data)
        return data.get("state", "unknown")
    except Exception:
        return "unknown"


def _configure_frigate_and_start() -> bool:
    """Configure et démarre Frigate. Retourne True si go2rtc est opérationnel."""
    # Log les ports déclarés par l'addon Frigate (diagnostic)
    info_r = sup_get(f"/addons/{FRIGATE_SLUG}/info")
    if info_r.ok:
        info = info_r.json()
        if isinstance(info, dict):
            info = info.get("data", info)
        log(f"[frigate] ports addon: {info.get('network', {})} / host_network: {info.get('host_network', '?')}")

    # Tentative de mapping port 1984 (ignorée si non déclaré dans config.yaml de Frigate)
    r = sup_post(f"/addons/{FRIGATE_SLUG}/options", {"network": {"1984/tcp": 1984}})
    log(f"[frigate] network/1984 → {r.status_code} {r.text[:120]}")

    _load_cameras()
    write_frigate_config()

    # start ou restart selon l'état courant
    state = _frigate_state()
    action = "restart" if state in ("started", "running") else "start"
    r = sup_post(f"/addons/{FRIGATE_SLUG}/{action}", timeout=120)
    if not r.ok:
        warn(f"[frigate] ✗ {action} : {r.status_code} {r.text[:150]}")
        return False
    log(f"[frigate] {action} → {r.status_code}")

    ok = _wait_frigate_ready()
    if not ok:
        try:
            ui = requests.get("http://127.0.0.1:5000/api", timeout=5)
            warn(f"[frigate] UI :5000 → {ui.status_code} (Frigate tourne mais go2rtc :1984 inaccessible)")
        except Exception as e:
            warn(f"[frigate] UI :5000 inaccessible → Frigate ne démarre pas ({e})")
        warn(f"[frigate] état Supervisor : {_frigate_state()}")
        try:
            lr = sup_get(f"/addons/{FRIGATE_SLUG}/logs")
            if lr.ok:
                lines = lr.text.strip().splitlines()
                excerpt = "\n".join(lines[-40:])
                warn(f"[frigate] Derniers logs Frigate:\n{excerpt}")
        except Exception as e:
            warn(f"[frigate] impossible de lire les logs Frigate : {e}")
        return False

    # Frigate prêt → désactiver l'auth une fois pour toutes (si ce n'est déjà fait)
    threading.Thread(target=_setup_frigate_auth_once, daemon=True).start()
    return True


def _migrate_frigate_repo_once():
    """Migration one-shot : bascule de l'add-on Frigate officiel (dépôt upstream, slug
    OLD_FRIGATE_SLUG) vers notre fork (FRIGATE_REPO/FRIGATE_SLUG, cf. commentaire à leur
    définition) — nécessaire pour que Frigate lise enfin /homeassistant/frigate.yml.
    Désinstalle l'ancien avec remove_config=True : sa config privée ne nous sert à rien
    (jamais synchronisée avec la nôtre) et ne doit pas laisser de résidu. Rien de notre
    propre état n'est perdu : caméras/capacités/scènes vivent dans Supabase et nos
    fichiers /data/, jamais dans Frigate lui-même. install_frigate() enchaîne ensuite
    normalement (nouveau dépôt pas encore ajouté → ajouté, pas installé → installé)."""
    if not _is_addon_installed(OLD_FRIGATE_SLUG):
        return
    log(f"[frigate] Migration vers le fork Domoticium — désinstallation de l'ancien Frigate ({OLD_FRIGATE_SLUG})…")
    r = sup_post(f"/addons/{OLD_FRIGATE_SLUG}/uninstall", {"remove_config": True}, timeout=120)
    log(f"[frigate] Désinstallation ancien Frigate → {r.status_code} {r.text[:150]}")
    time.sleep(10)


_FRIGATE_CONFIG_RACE_FIX_MARKER = "/data/.frigate_config_race_fixed"


def _fix_frigate_config_race_once():
    """Corrige une installation déjà faite AVANT le correctif d'ordre d'écriture
    (write_frigate_config() appelé avant install, pas seulement avant start —
    cf. install_frigate() étape 1bis) : sur ces sites, le tout premier démarrage de
    Frigate a pu rater la fenêtre de migration one-shot de son script "prepare" (config
    privée créée avec les valeurs par défaut de Frigate avant que notre fichier ne soit
    garanti présent), cf. HANDOFF §57. Un seul réinstall propre (remove_config=True)
    redonne une chance à cette migration, cette fois avec notre fichier garanti à jour
    puisqu'écrit avant l'installation. One-shot via marker — les nouvelles
    installations (jamais affectées, le correctif d'ordre s'applique dès le départ)
    n'ont rien à corriger et posent juste le marker sans action."""
    if os.path.exists(_FRIGATE_CONFIG_RACE_FIX_MARKER):
        return
    if not _is_addon_installed(FRIGATE_SLUG):
        open(_FRIGATE_CONFIG_RACE_FIX_MARKER, "w").close()
        return
    log("[frigate] Nouvelle tentative de migration de la config (installation potentiellement affectée par une course au tout 1er démarrage, cf. HANDOFF §57) — réinstallation propre…")
    r = sup_post(f"/addons/{FRIGATE_SLUG}/uninstall", {"remove_config": True}, timeout=120)
    log(f"[frigate] Désinstallation (nouvelle tentative migration) → {r.status_code} {r.text[:150]}")
    time.sleep(10)
    open(_FRIGATE_CONFIG_RACE_FIX_MARKER, "w").close()


_GO2RTC_PRIMARY_CONFIG_FIX_MARKER = "/data/.go2rtc_primary_config_fixed"


def _fix_go2rtc_primary_config_once():
    """Corrige un site où /config/go2rtc_homekit.yml (fichier "primaire" go2rtc,
    persistant, chargé en premier par Frigate) a pu être altéré par les PATCH
    /api/config répétés de l'ancien mécanisme _ensure_go2rtc_webrtc_persisted() —
    retiré le 2026-07-22 car devenu inutile ET risqué : ce mécanisme compensait
    l'absence de lecture de /homeassistant/frigate.yml par Frigate (corrigée depuis,
    cf. HANDOFF §55/§57), pas un besoin réel. Ses patchs texte répétés (splice par
    ligne, cf. pkg/yaml.patch côté go2rtc) sur ce même fichier au fil des versions de
    cette session ont vraisemblablement produit le YAML invalide observé au boot
    ("yaml: line 11: did not find expected ',' or ']'") et empêché la propagation de
    api.origin: "*" (auto-injecté par create_config.py UNIQUEMENT si go2rtc.api est
    absent de la config effective — un fichier primaire corrompu peut interférer).
    Un seul réinstall propre (remove_config=True) repart d'un fichier primaire vide ;
    le fichier régénéré à chaque boot depuis notre frigate.yml (désormais réellement
    lu) suffit seul. One-shot via marker — nouvelles installations : rien à corriger."""
    if os.path.exists(_GO2RTC_PRIMARY_CONFIG_FIX_MARKER):
        return
    if not _is_addon_installed(FRIGATE_SLUG):
        open(_GO2RTC_PRIMARY_CONFIG_FIX_MARKER, "w").close()
        return
    log("[frigate] Nettoyage du fichier de config primaire go2rtc (patches API obsolètes, cf. HANDOFF) — réinstallation propre…")
    r = sup_post(f"/addons/{FRIGATE_SLUG}/uninstall", {"remove_config": True}, timeout=120)
    log(f"[frigate] Désinstallation (nettoyage config primaire go2rtc) → {r.status_code} {r.text[:150]}")
    time.sleep(10)
    open(_GO2RTC_PRIMARY_CONFIG_FIX_MARKER, "w").close()


def install_frigate():
    log("── Frigate NVR ──────────────────────────────")

    # 0. S'assurer que le dépôt est présent et à jour AVANT toute résolution de slug —
    # nécessaire pour que _resolve_frigate_slug()/_fix_frigate_config_race_once()
    # ci-dessous travaillent avec le bon FRIGATE_SLUG plutôt que le repli codé en dur.
    existing_urls = _sup_repos()
    if FRIGATE_REPO not in existing_urls:
        r = sup_post("/store/repositories", {"repository": FRIGATE_REPO})
        if r.ok:
            log("✓ Dépôt Frigate ajouté")
            time.sleep(5)
        else:
            warn(f"Dépôt Frigate : {r.status_code} — on continue")
    else:
        log("Dépôt Frigate déjà présent")
        # Forcer un rafraîchissement du store — évite de travailler depuis un
        # manifeste potentiellement mis en cache par le Supervisor avant notre
        # dernière modification (config.yaml du fork), cf. HANDOFF §57.
        r = sup_post("/store/reload", timeout=60)
        log(f"[frigate] Rafraîchissement du store → {r.status_code}")

    _resolve_frigate_slug()

    _migrate_frigate_repo_once()
    _fix_frigate_config_race_once()
    _fix_go2rtc_primary_config_once()

    # 1. Nettoyer un go2rtc.yml résiduel de l'ancienne architecture standalone
    old_go2rtc = "/homeassistant/go2rtc.yml"
    if os.path.exists(old_go2rtc):
        os.rename(old_go2rtc, f"{old_go2rtc}.bak")
        log("⚠ Ancien go2rtc.yml archivé → go2rtc.yml.bak (utilise le go2rtc embarqué dans Frigate)")

    # 1bis. Écrire /homeassistant/frigate.yml AVANT toute installation (pas seulement
    # avant le démarrage, cf. plus bas) — sur une toute première installation, le script
    # de préparation de Frigate ("prepare", côté conteneur) migre ce fichier vers son
    # propre stockage privé UNE SEULE FOIS, dès son tout premier démarrage : s'il ne
    # trouve rien à cet instant précis, cette fenêtre est perdue pour de bon (le fichier
    # une fois "migré" ne l'est plus jamais une 2e fois). S'assurer qu'il existe déjà,
    # correctement rempli, avant même de déclencher l'installation.
    _load_cameras()
    write_frigate_config()

    # 2. Installer si nécessaire
    if not _is_addon_installed(FRIGATE_SLUG):
        log("Installation de Frigate (peut prendre 2-3 min)…")
        r = sup_post(f"/store/addons/{FRIGATE_SLUG}/install", timeout=300)
        if r.ok:
            log("✓ Frigate installé")
            time.sleep(10)
        elif "already_installed" in r.text or "already installed" in r.text.lower():
            # Supervisor dit "already installed" mais _is_addon_installed a retourné False
            # (peut arriver si Frigate est en crash loop → state='unknown').
            # On continue quand même à configurer.
            log("Frigate déjà installé (détection Supervisor corrigée)")
        else:
            warn(f"Installation Frigate : {r.status_code} {r.text[:200]}")
            return
    else:
        log("Frigate déjà installé")

    # 4. Configurer + démarrer
    if _configure_frigate_and_start():
        return

    # 5. Toujours en erreur → réinstallation propre automatique
    state = _frigate_state()
    warn(f"Frigate état={state!r} après timeout — réinstallation propre…")

    # Écrire la config AVANT la désinstallation.
    # remove_config=True efface l'addon_config privé de Frigate (= /config/config.yml
    # DANS le conteneur Frigate, stocké dans addon_configs/ccab4aaf_frigate/ sur l'hôte).
    # Un éventuel stale config.yml avec cameras:null (crash de migration 0.13→0.14) est
    # ainsi supprimé. Le prepare script de Frigate recopie /homeassistant/frigate.yml →
    # /config/config.yml dès lors que ce dernier n'existe plus.
    # Notre config contient version:"0.18-0" → migration entièrement skippée même si
    # un stale réapparaît d'une source externe.
    _load_cameras()
    write_frigate_config()

    # Effacer le marker d'auth désactivée : après remove_config+reinstall, Frigate
    # recréera un admin avec un nouveau password aléatoire → il faudra refaire le setup.
    if os.path.exists(_FRIGATE_AUTH_MARKER):
        os.remove(_FRIGATE_AUTH_MARKER)
    r_uninstall = sup_post(f"/addons/{FRIGATE_SLUG}/uninstall", {"remove_config": True})
    log(f"Désinstallation Frigate (remove_config=True) → {r_uninstall.status_code}")
    time.sleep(20)

    r = sup_post(f"/store/addons/{FRIGATE_SLUG}/install", timeout=300)
    if not r.ok:
        warn(f"✗ {r.status_code} Réinstallation Frigate impossible : {r.text[:100]}")
        return
    log("✓ Frigate réinstallé — reconfiguration…")
    time.sleep(30)

    if _configure_frigate_and_start():
        return
    warn("Frigate toujours inopérationnel après réinstallation — vérifier les logs Frigate dans HA")


_FRIGATE_AUTH_MARKER = "/data/.frigate_auth_disabled"


def _has_turn(servers: list[dict]) -> bool:
    """True si la liste contient un vrai serveur TURN (pas seulement le repli STUN)."""
    return any(s.get("credential") for s in servers)


def _fetch_turn_ice_servers() -> list[dict] | None:
    """Récupère des identifiants TURN Cloudflare Realtime de courte durée via le
    backend (secret Cloudflare — TURN_KEY_API_TOKEN — jamais exposé à l'addon, cf.
    /api/ingest/webrtc-credentials). Retourne None en cas d'échec (réseau, quota
    Vercel, etc.) — à distinguer d'un repli STUN volontaire : _turn_refresh_loop()
    ne doit PAS redémarrer Frigate sur un échec transitoire de ce fetch (bug corrigé
    le 2026-07-19 : un simple hoquet réseau faisait passer _turn_ice_servers d'un
    vrai TURN à un repli STUN, détecté comme un "changement" → redémarrage Frigate
    inutile → coupure caméra réelle → fausse alerte "hors ligne" envoyée au client)."""
    if not INGEST_SECRET:
        return None
    try:
        r = requests.post(
            f"{APP_URL}/api/ingest/webrtc-credentials",
            json={"siteSecret": INGEST_SECRET, "siteId": SITE_PREFIX},
            timeout=15,
        )
        if not r.ok:
            warn(f"[webrtc] identifiants TURN : {r.status_code} {r.text[:200]}")
            return None
        ice = r.json().get("iceServers")
        if not ice or not ice.get("urls"):
            return [{"urls": ["stun:stun.cloudflare.com:3478"]}]
        return [{"urls": ["stun:stun.cloudflare.com:3478"]}, ice]
    except Exception as e:
        warn(f"[webrtc] identifiants TURN : {e}")
        return None


def _webrtc_config_yaml_lines() -> list[str]:
    """Section go2rtc.webrtc — go2rtc ne charge ice_servers qu'au démarrage (pas de
    rechargement à chaud), d'où le restart Frigate après chaque rafraîchissement
    périodique des identifiants TURN (cf. _turn_refresh_loop).

    Cette section EST la source de vérité : /homeassistant/frigate.yml est réellement
    lu par Frigate (CONFIG_FILE, cf. HANDOFF §55/§57) et régénère /dev/shm/go2rtc.yaml
    à chaque démarrage. Jusqu'au 2026-07-22 un mécanisme de contournement persistait
    cette section via PATCH /api/config directement dans le fichier "primaire" de
    go2rtc — nécessaire tant que Frigate ne lisait pas notre fichier, mais devenu à la
    fois inutile ET risqué une fois ce problème corrigé (patches texte répétés sur le
    même fichier → YAML invalide observé au boot). Retiré (cf. _ensure_frigate) au
    profit de cette seule section, désormais suffisante seule (confirmé en conditions
    réelles : webrtc s'initialise correctement dès le premier boot suivant un reset
    complet de la config, avant même que l'ancien mécanisme n'ait pu agir).

    listen: "0.0.0.0:8555", PAS l'IP LAN de l'hôte — l'add-on Frigate tourne en réseau
    Docker isolé (host_network: false dans son propre config.yaml), donc l'IP LAN de
    l'hôte n'existe pas à l'intérieur de son conteneur (confirmé en réel : "cannot
    assign requested address" sur une IP pourtant correcte côté hôte). "0.0.0.0" est
    traité comme "unspecified" par go2rtc et énumère donc les interfaces DU CONTENEUR,
    filtrées par filters.networks: [udp4, tcp4] pour exclure l'IPv6 locale instable de
    son interface pont Docker.

    Pas de clé api/origin ici : create_config.py (script Frigate qui régénère
    /dev/shm/go2rtc.yaml) injecte automatiquement api.origin: "*" dès que go2rtc.api
    est absent de la config — ce qui est notre cas. Sans ce "*", go2rtc applique un
    contrôle same-origin strict sur son WebSocket de signalisation (cf. internal/api/
    ws/ws.go côté go2rtc) qui rejette app.domoticium.fr (origine différente du nom
    d'hôte du tunnel Cloudflare)."""
    lines = [
        "  webrtc:",
        '    listen: "0.0.0.0:8555"',
        "    filters:",
        "      networks: [udp4, tcp4]",
        "    ice_servers:",
    ]
    for server in (_turn_ice_servers or [{"urls": ["stun:stun.cloudflare.com:3478"]}]):
        urls = server.get("urls", [])
        if isinstance(urls, str):
            urls = [urls]
        urls_str = ", ".join(f'"{u}"' for u in urls)
        lines.append(f"      - urls: [{urls_str}]")
        if server.get("username"):
            lines.append(f"        username: \"{server['username']}\"")
        if server.get("credential"):
            lines.append(f"        credential: \"{server['credential']}\"")
    return lines


def _generate_frigate_yaml() -> str:
    """Génère le YAML complet de config Frigate depuis le registre des caméras.

    Jusqu'au 2026-07-22, ce fichier n'était en réalité JAMAIS lu par Frigate : l'add-on
    officiel ne définit pas CONFIG_FILE, donc find_config_file() (côté Frigate) résolvait
    vers son stockage privé (/config/config.yml), jamais vers /homeassistant/frigate.yml.
    Corrigé en migrant vers notre propre fork de l'add-on (cf. FRIGATE_REPO/FRIGATE_SLUG
    et _migrate_frigate_repo_once) qui ajoute CONFIG_FILE=/homeassistant/frigate.yml à la
    config officielle — Frigate lit désormais réellement ce fichier. mqtt/onvif ci-dessous
    ne sont donc plus des réglages morts (cf. HANDOFF §55/§56)."""
    lines = [
        "# Généré par Domoticium — ne pas modifier manuellement",
        'version: "0.18-0"',
        "auth:",
        "  enabled: false",
        "mqtt:",
        "  enabled: true",
        "  host: core-mosquitto",
        "  port: 1883",
        f'  user: "{MOSQUITTO_USER}"',
        f'  password: "{MOSQUITTO_PASS}"',
        "",
    ]

    if _cameras:
        lines.append("go2rtc:")
        # api.origin: "*" explicite — create_config.py (script Frigate qui régénère
        # /dev/shm/go2rtc.yaml) est censé l'injecter automatiquement quand go2rtc.api
        # est absent de la config, mais confirmé en conditions réelles le 2026-07-22 :
        # ça ne suffit pas (rejet WebSocket persistant, cf. HANDOFF §58/§59 —
        # internal/api/ws/ws.go côté go2rtc n'accepte que "" ou "*", sans repli par
        # défaut). Le définir nous-mêmes retire la dépendance à ce comportement
        # implicite plutôt que de continuer à en deviner la raison exacte.
        lines.append("  api:")
        lines.append('    origin: "*"')
        lines.append("  streams:")
        for name, rtsp_url in _cameras.items():
            lines += [f"    {name}:", f"      - {rtsp_url}"]
            if name in _camera_talk_enabled:
                # Deuxième source = même caméra, marquée #backchannel=0 → go2rtc y
                # envoie l'audio reçu du navigateur (bouton "parler") au lieu de le
                # lire. Combinaison confirmée par la doc communautaire go2rtc pour les
                # caméras Reolink — PAS testée en conditions réelles ici (cf. HANDOFF),
                # certains modèles n'acceptent qu'un seul client RTSP à la fois.
                lines.append(f"      - {rtsp_url}#backchannel=0")
        lines += _webrtc_config_yaml_lines()
        lines.append("")
        lines.append("cameras:")
        for name, rtsp_url in _cameras.items():
            lines += [
                f"  {name}:",
                "    ffmpeg:",
                "      inputs:",
                f"        - path: rtsp://127.0.0.1:8554/{name}",
                "          roles:",
                "            - detect",
                "    detect:",
                "      enabled: false",
                "    record:",
                "      enabled: false",
            ]
            # Identifiants ONVIF réutilisés depuis l'URL RTSP déjà stockée (même
            # hypothèse qu'ailleurs dans le fichier : matériel grand public utilise
            # en général les mêmes identifiants pour RTSP et ONVIF). Port par défaut
            # Frigate (8000) — pas de champ dédié pour un port ONVIF différent par
            # caméra, cohérent avec le premier port essayé par notre propre sonde.
            try:
                onvif_ip, onvif_user, onvif_pass = _onvif_credentials_from_rtsp(rtsp_url)
            except Exception:
                onvif_ip = ""
            if onvif_ip:
                lines += [
                    "    onvif:",
                    f'      host: "{onvif_ip}"',
                    f'      user: "{onvif_user}"',
                    f'      password: "{onvif_pass}"',
                ]
    else:
        lines.append("cameras: {}")

    return "\n".join(lines) + "\n"


def _setup_frigate_auth_once():
    """Marque l'auth Frigate comme gérée.
    Notre YAML génère toujours auth.enabled: false ; le prepare script Frigate le copie
    à chaque démarrage → pas besoin d'appel API. On pose simplement le marker."""
    if os.path.exists(_FRIGATE_AUTH_MARKER):
        return
    open(_FRIGATE_AUTH_MARKER, "w").close()
    log("[frigate] ✓ Auth gérée via YAML (auth.enabled: false dans frigate.yml)")


def write_frigate_config():
    """Écrit /homeassistant/frigate.yml. Le prepare script Frigate le copie dans son
    stockage privé à chaque démarrage — c'est la seule voie de config utilisée."""
    content = _generate_frigate_yaml()
    with open("/homeassistant/frigate.yml", "w") as fh:
        fh.write(content)
    log(f"✓ config Frigate mise à jour ({len(_cameras)} caméra(s))")


# ── MQTT / Automations ───────────────────────────────────────────────────────

def _unwrap(resp_json):
    """Dépaquète l'enveloppe Supervisor {result, data} si présente."""
    if isinstance(resp_json, dict) and "data" in resp_json and "result" in resp_json:
        return resp_json["data"]
    return resp_json


def _mqtt_submit(flow_id, payload, label):
    """Soumet une étape du flow MQTT. Retourne (ok, result_dict)."""
    r = requests.post(f"{API}/config/config_entries/flow/{flow_id}",
                      headers=HDRS, json=payload, timeout=15)
    if not r.ok:
        warn(f"[MQTT] {label} erreur {r.status_code}: {r.text[:400]}")
        return False, {}
    result = _unwrap(r.json())
    log(f"[MQTT] {label} → type={result.get('type','?')} step={result.get('step_id','?')}")
    return True, result


def _mqtt_is_done(result):
    """Retourne True si le flow est terminé (succès ou déjà configuré)."""
    t = result.get("type", "?")
    if t == "create_entry":
        log("✓ MQTT configuré")
        return True
    if t == "abort":
        reason = result.get("reason", "?")
        if reason in ("already_configured", "single_instance_allowed"):
            log("✓ MQTT déjà configuré")
        else:
            warn(f"MQTT flow abort : {reason}")
        return True
    return False


def _build_mqtt_broker_payload(schema: list) -> dict:
    """Construit le payload du flow MQTT HA pour Mosquitto local (core-mosquitto:1883, pas de TLS).
    Si schema vide → étape de confirmation sans champ → payload {}."""
    if not schema:
        return {}

    schema_names = {f.get("name", "") for f in schema}
    log(f"[MQTT] Champs du schéma : {sorted(schema_names)}")
    payload = {}

    for k in ("broker", "host", "server", "hostname"):
        if k in schema_names:
            payload[k] = "core-mosquitto"
            break
    if "port" in schema_names:
        payload["port"] = 1883
    for k in ("username", "user"):
        if k in schema_names:
            payload[k] = MOSQUITTO_USER
            break
    for k in ("password", "pass"):
        if k in schema_names:
            payload[k] = MOSQUITTO_PASS
            break

    return payload


def _mqtt_config_entry_exists() -> bool:
    """Lit core.config_entries (source fiable) — /services expose mqtt.publish même sans
    aucune entrée configurée (faux positif observé en test réel : configure_mqtt() se
    croyait "déjà configuré et actif" alors qu'aucune intégration MQTT n'existait dans HA,
    et ne créait donc jamais les entités Zigbee — état/commandes cassés en conséquence)."""
    try:
        with open("/homeassistant/.storage/core.config_entries") as f:
            storage = json.load(f)
        entries = storage.get("data", {}).get("entries", [])
        return any(e.get("domain") == "mqtt" for e in entries)
    except Exception as e:
        warn(f"[MQTT] Lecture core.config_entries impossible : {e}")
        return False


def configure_mqtt(force: bool = False):
    log("── MQTT (Mosquitto local) ───────────────────")

    # Vérifier si MQTT est déjà actif (sauf si force=True après suppression de l'entrée)
    if not force and _mqtt_config_entry_exists():
        log("MQTT déjà configuré et actif")
        return

    log("Configuration MQTT → core-mosquitto:1883…")
    flow_resp = ha_post("/config/config_entries/flow", {"handler": "mqtt"})
    if not flow_resp.ok:
        warn(f"Flow MQTT impossible ({flow_resp.status_code}): {flow_resp.text[:200]}")
        return

    flow = _unwrap(flow_resp.json())
    flow_id   = flow.get("flow_id")
    step_id   = flow.get("step_id", "?")
    flow_type = flow.get("type", "?")
    log(f"[MQTT] Flow démarré : type={flow_type} step={step_id}")

    if not flow_id:
        warn(f"[MQTT] Pas de flow_id : {flow_resp.text[:200]}")
        return

    if _mqtt_is_done(flow):
        return

    # Étape 1 : si le flow démarre par un menu (HA 2024.4+), choisir "broker"
    if flow_type == "menu":
        menu_options = flow.get("menu_options", [])
        log(f"[MQTT] Menu options : {menu_options}")
        choice = "broker" if "broker" in menu_options else (menu_options[0] if menu_options else "broker")
        ok, flow = _mqtt_submit(flow_id, {"next_step_id": choice}, f"menu→{choice}")
        if not ok or _mqtt_is_done(flow):
            return
        flow_type = flow.get("type", "?")
        step_id   = flow.get("step_id", "?")

    # Étape 2 : traiter les formulaires broker en boucle (max 5 étapes)
    for _step_num in range(5):
        if flow_type != "form":
            break

        schema = flow.get("data_schema", [])
        errors = flow.get("errors", {})
        log(f"[MQTT] Formulaire step={step_id} — schema={json.dumps(schema, ensure_ascii=False)}")
        if errors:
            warn(f"[MQTT] Erreurs dans le formulaire : {errors}")

        payload = _build_mqtt_broker_payload(schema)
        log(f"[MQTT] Payload envoyé : {payload}")

        ok, flow = _mqtt_submit(flow_id, payload, f"form step={step_id}")
        if not ok or _mqtt_is_done(flow):
            return

        flow_type = flow.get("type", "?")
        step_id   = flow.get("step_id", "?")

    if flow_type == "form":
        warn(f"[MQTT] Boucle de formulaires non résolue — dernier step={step_id}")
    elif flow_type not in ("create_entry", "abort"):
        warn(f"[MQTT] Type inattendu : {flow_type}")


# Anciennes automations HA (domoticium_state_stream/domoticium_command_handler MQTT/EMQX,
# domoticium_heartbeat, domoticium_camera_status) toutes retirées — remplacées par
# run_ha_ws_bridge() + le serveur de commandes HTTP local et les appels Supabase directs
# (cf. HANDOFF §36/§37). domoticium_camera_status en particulier n'a jamais servi en
# pratique : Frigate ne publie aucune entité camera.* dans HA (mqtt.enabled: false), et
# le jour où une intégration HACS en créera, "camera" fait déjà partie des domaines
# relayés par run_ha_ws_bridge() → aucun rest_command dédié ne sera nécessaire.
# Cf. _remove_legacy_heartbeat_automation_once() et _remove_legacy_rest_commands_once()
# pour le nettoyage des installations où ces automations/rest_commands existent déjà.


_LEGACY_HEARTBEAT_AUTO_MARKER = "/data/.legacy_heartbeat_automation_removed"


def _remove_legacy_heartbeat_automation_once():
    """Supprime l'automation HA 'domoticium_heartbeat' sur les installations où elle
    a déjà été enregistrée (avant le 2026-07-19) — dupliquait le heartbeat Python
    toutes les 30s. Idempotent via marker, tourne à chaque démarrage de l'addon."""
    if os.path.exists(_LEGACY_HEARTBEAT_AUTO_MARKER):
        return
    try:
        r = requests.delete(f"{API}/config/automation/config/domoticium_heartbeat",
                            headers=HDRS, timeout=15)
        if r.status_code in (200, 404):
            ha_post("/services/automation/reload")
            log("✓ Automation HA 'domoticium_heartbeat' (dupliquée, 30s) supprimée")
        else:
            warn(f"Suppression automation heartbeat legacy : HTTP {r.status_code}")
            return  # retente au prochain démarrage
    except Exception as e:
        warn(f"Suppression automation heartbeat legacy : {e}")
        return  # retente au prochain démarrage
    open(_LEGACY_HEARTBEAT_AUTO_MARKER, "w").close()


_WATCHDOG_ENABLED_MARKER = "/data/.watchdog_enabled"


def _enable_watchdogs_once():
    """Active le redémarrage automatique du Supervisor ("Watchdog", visible dans
    Paramètres → Modules complémentaires → [add-on] → interrupteur Watchdog) pour
    Domoticium et les add-ons dont il dépend, si installés. Ne protège que contre un
    add-on qui CRASHE (process qui meurt) — pas contre un service interne qui reste
    bloqué sans faire planter le container (ex: incident cmd-server du 2026-07-22,
    déjà corrigé par ailleurs) : le Watchdog Supervisor n'a pas de sonde applicative,
    juste "le process tourne-t-il encore ?". Complémentaire, pas un remplacement, des
    correctifs ciblés. `/addons/self/options` = API Supervisor dédiée pour qu'un
    add-on se configure lui-même sans connaître son propre slug installé (qui varie
    selon le dépôt d'installation). Idempotent via marker, retente à chaque démarrage
    tant qu'un appel a échoué."""
    if os.path.exists(_WATCHDOG_ENABLED_MARKER):
        return
    ok = True
    try:
        r = sup_post("/addons/self/options", {"watchdog": True})
        if r.ok:
            log("[watchdog] ✓ activé pour Domoticium")
        else:
            warn(f"[watchdog] échec activation pour Domoticium : HTTP {r.status_code}")
            ok = False
    except Exception as e:
        warn(f"[watchdog] Domoticium : {e}")
        ok = False

    for slug in (MOSQUITTO_SLUG, FRIGATE_SLUG, MATTER_SLUG, Z2M_SLUG, THREAD_SLUG):
        if not _is_addon_installed(slug):
            continue
        try:
            r = sup_post(f"/addons/{slug}/options", {"watchdog": True})
            if r.ok:
                log(f"[watchdog] ✓ activé pour {slug}")
            else:
                warn(f"[watchdog] échec activation pour {slug} : HTTP {r.status_code}")
                ok = False
        except Exception as e:
            warn(f"[watchdog] {slug} : {e}")
            ok = False

    if ok:
        open(_WATCHDOG_ENABLED_MARKER, "w").close()


_LEGACY_REST_COMMANDS_MARKER = "/data/.legacy_rest_commands_removed"


def _remove_legacy_rest_commands_once():
    """Nettoyage one-shot (2026-07-20) : supprime l'automation HA 'domoticium_camera_status'
    et le fichier rest_command associé (écrits par une version antérieure de l'addon pour
    notifier /api/webhooks/pi/camera-status au changement d'état d'une entité camera.* —
    jamais déclenché en pratique, Frigate ne publie aucune entité camera.* dans HA).
    Idempotent via marker, tourne à chaque démarrage."""
    if os.path.exists(_LEGACY_REST_COMMANDS_MARKER):
        return
    try:
        r = requests.delete(f"{API}/config/automation/config/domoticium_camera_status",
                            headers=HDRS, timeout=15)
        if r.status_code not in (200, 404):
            warn(f"Suppression automation camera_status legacy : HTTP {r.status_code}")
            return  # retente au prochain démarrage

        rest_file = "/homeassistant/domoticium_rest_commands.yaml"
        main_cfg = "/homeassistant/configuration.yaml"
        if os.path.exists(rest_file):
            os.remove(rest_file)
        if os.path.exists(main_cfg):
            with open(main_cfg) as f:
                existing = f.read()
            cleaned = existing.replace("rest_command: !include domoticium_rest_commands.yaml\n", "")
            if cleaned != existing:
                with open(main_cfg, "w") as f:
                    f.write(cleaned)

        ha_post("/services/automation/reload")
        log("✓ Automation HA 'domoticium_camera_status' + rest_commands obsolètes supprimés")
    except Exception as e:
        warn(f"Suppression rest_commands legacy : {e}")
        return  # retente au prochain démarrage
    open(_LEGACY_REST_COMMANDS_MARKER, "w").close()


def remove_legacy_mqtt_discovery_prefix():
    """Supprime l'ancien bloc custom discovery_prefix si présent (écrit par les versions < 1.6.0).
    Z2M utilise maintenant le préfixe standard 'homeassistant' — pas besoin de surcharge.
    """
    main_cfg = "/homeassistant/configuration.yaml"
    marker   = "# domoticium-mqtt-discovery"
    try:
        with open(main_cfg) as f:
            content = f.read()
        if marker not in content:
            return
        # Supprimer le bloc de 3 lignes : commentaire + clé mqtt + discovery_prefix
        lines = content.splitlines(keepends=True)
        cleaned = []
        skip_next = 0
        for line in lines:
            if skip_next > 0:
                skip_next -= 1
                continue
            if marker in line:
                skip_next = 2  # sauter "mqtt:" et "  discovery_prefix: ..."
                continue
            cleaned.append(line)
        with open(main_cfg, "w") as f:
            f.writelines(cleaned)
        log("✓ Ancien discovery_prefix non-standard supprimé de configuration.yaml")
    except Exception as e:
        warn(f"remove_legacy_mqtt_discovery_prefix: {e}")


def run_setup():
    wait_for_ha()
    log("═══ Début de la configuration Domoticium ═══")

    # 1. Mosquitto local d'abord — Z2M et HA MQTT integration en dépendent
    setup_mosquitto()

    # 2. HA MQTT integration → Mosquitto local
    configure_mqtt()

    # 3. Z2M → Mosquitto local
    install_zigbee2mqtt()

    # 4. Supprimer l'ancien discovery_prefix non-standard (migration v1.5 → v1.6)
    remove_legacy_mqtt_discovery_prefix()

    install_matter_server()
    if INSTALL_THREAD_ROUTER:
        install_thread_border_router()
    install_frigate()

    ha_post("/services/homeassistant/reload_all")
    with open(SETUP_DONE, "w") as f:
        f.write("done")
    log("═══ Configuration terminée ✓ ═══")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — SERVICE PERMANENT
# ══════════════════════════════════════════════════════════════════════════════

def start_cloudflared():
    """Démarre cloudflared → Frigate go2rtc port 1984 via Cloudflare Tunnel."""
    if not CLOUDFLARE_TUNNEL_TOKEN:
        log("cloudflared: pas de token — tunnel caméras désactivé")
        return

    log("Démarrage de cloudflared…")
    try:
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--no-autoupdate", "run",
             "--token", CLOUDFLARE_TUNNEL_TOKEN],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

        def _log_output():
            for line in proc.stdout:
                log(f"cloudflared: {line.decode().strip()}")

        threading.Thread(target=_log_output, daemon=True).start()
        log("✓ cloudflared actif — Frigate go2rtc accessible via Cloudflare Tunnel")
    except FileNotFoundError:
        warn("cloudflared introuvable")
    except Exception as e:
        warn(f"cloudflared: {e}")


def restart_frigate() -> bool:
    """Redémarre Frigate — bloquant sur la commande Supervisor (acceptée en quelques
    secondes). Le réponse HTTP appelante ne doit dire 'ok' que si cette commande a
    réellement été acceptée, pas avant qu'un thread de fond ait fini par l'envoyer.
    N'attend PAS la disponibilité complète du service (jusqu'à 3 min, cf.
    _wait_frigate_ready) — seulement que Supervisor a accepté la demande de restart."""
    r = sup_post(f"/addons/{FRIGATE_SLUG}/restart")
    mark = "✓" if r.ok else f"✗ {r.status_code}"
    log(f"{mark} Frigate redémarré (commande Supervisor)")
    return r.ok


def _go2rtc_upsert_stream(name: str, rtsp_url: str, timeout: float = 5.0) -> bool:
    """Ajoute/remplace un flux go2rtc à chaud (API PUT /api/streams) — les autres
    caméras (et sessions WebRTC/HLS actives) ne sont pas coupées, contrairement à un
    restart complet de l'add-on Frigate."""
    try:
        r = requests.put(
            "http://127.0.0.1:1984/api/streams",
            params={"name": name, "src": rtsp_url},
            timeout=timeout,
        )
        return r.ok
    except Exception as e:
        warn(f"[go2rtc] upsert stream '{name}' : {e}")
        return False


def _go2rtc_remove_stream(name: str, timeout: float = 5.0) -> bool:
    """Retire un flux go2rtc à chaud (API DELETE /api/streams)."""
    try:
        r = requests.delete(
            "http://127.0.0.1:1984/api/streams",
            params={"src": name},
            timeout=timeout,
        )
        return r.ok
    except Exception as e:
        warn(f"[go2rtc] remove stream '{name}' : {e}")
        return False


def _go2rtc_probe_online(name: str, timeout: float = 6.0) -> bool:
    """Force une connexion RTSP à chaud (pull d'une image JPEG) pour vérifier qu'un flux
    déjà enregistré est réellement accessible. go2rtc ne maintient aucune connexion
    permanente sans consommateur actif (WebRTC/HLS en cours de visionnage) — lire
    /api/streams seul ne reflète donc PAS l'état réel de la caméra la plupart du temps
    (le champ producer 'state' n'apparaît que pendant une connexion active)."""
    try:
        r = requests.get(
            "http://127.0.0.1:1984/api/frame.jpeg",
            params={"src": name},
            timeout=timeout,
        )
        return r.ok and r.headers.get("Content-Type", "").startswith("image")
    except Exception:
        return False


def _recent_go2rtc_error_hint() -> str:
    """Best-effort : cherche la dernière erreur go2rtc pertinente dans les logs Frigate
    (go2rtc y écrit ses erreurs de connexion RTSP, ex: 'wrong user/pass') pour donner un
    message plus précis que 'caméra injoignable' — notamment distinguer un mauvais mot
    de passe d'un problème réseau, seul cas où on redemande explicitement la saisie."""
    try:
        r = sup_get(f"/addons/{FRIGATE_SLUG}/logs")
        if not r.ok:
            return ""
        for line in reversed(r.text.strip().splitlines()[-60:]):
            low = line.lower()
            if "wrong user/pass" in low or "unauthorized" in low or " 401" in line:
                return "Mot de passe incorrect — veuillez le ressaisir"
            if "connection refused" in low or "no route to host" in low:
                return "Caméra injoignable — vérifiez l'adresse IP et que la caméra est allumée"
    except Exception:
        pass
    return ""


def _probe_rtsp_url(rtsp_url: str, timeout: float = 6.0) -> bool:
    """Teste une URL RTSP via un flux go2rtc temporaire (pull d'une image JPEG),
    nettoyé après coup."""
    test_name = f"_test_{secrets.token_hex(6)}"
    ok = False
    if _go2rtc_upsert_stream(test_name, rtsp_url, timeout=5.0):
        ok = _go2rtc_probe_online(test_name, timeout=timeout)
    _go2rtc_remove_stream(test_name)
    return ok


def _go2rtc_test_stream(rtsp_url: str, timeout: float = 8.0) -> tuple[bool, str]:
    """Teste une URL RTSP explicite (mode "URL manuelle" du formulaire) — aucune
    tentative de correction : l'utilisateur a fourni l'URL exacte, on la respecte telle
    quelle."""
    if _probe_rtsp_url(rtsp_url, timeout=timeout):
        return True, "ok"
    reason = _recent_go2rtc_error_hint()
    return False, reason or "Impossible de se connecter au flux vidéo — vérifiez l'URL"


def _normalize_brand(s: str) -> str:
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


# Ordre de test pour une marque "Inconnue" — marques grand public les plus courantes
# d'abord, pour que le cas fréquent se résolve vite ; le budget temps total est borné
# (cf. _test_camera_by_brand), donc les marques en fin de liste ne seront pas toujours
# toutes essayées si aucune des premières ne répond.
_BRAND_GUESS_ORDER = [
    "tplink", "reolink", "dahua", "hikvision", "imou", "ezviz", "foscam",
    "amcrest", "lorex", "swann", "annke", "uniview", "dlink", "hanwha",
    "axis", "vivotek", "bosch", "pelco", "flir",
]


def _test_camera_by_brand(
    ip: str, password: str, manufacturer: str, timeout: float = 8.0
) -> tuple[bool, str, str | None]:
    """Teste une caméra IP+mot de passe selon la marque choisie par l'utilisateur
    (menu déroulant du formulaire d'ajout) — une seule tentative directe, la bonne URL
    étant connue d'avance. Si aucune marque n'est choisie ("Inconnue"), teste tous les
    chemins RTSP connus l'un après l'autre (jamais en parallèle : certaines caméras
    d'entrée de gamme n'acceptent qu'UNE connexion RTSP à la fois — des tentatives
    concurrentes se percutent, observé en test réel : erreur go2rtc trompeuse "wrong
    response on DESCRIBE"), bornées à ~25s au total quel que soit le nombre de marques
    dans la table, pour rester dans le budget de la requête HTTP appelante.
    Retourne (ok, message, url_qui_fonctionne)."""
    norm = _normalize_brand(manufacturer)
    if norm and norm in _RTSP_TEMPLATES:
        url = _RTSP_TEMPLATES[norm].format(ip=ip).replace("MOTDEPASSE", password)
        if _probe_rtsp_url(url, timeout=timeout):
            return True, "ok", url
        reason = _recent_go2rtc_error_hint()
        return False, reason or f"Impossible de se connecter avec le chemin {manufacturer}", None

    candidates = [f"rtsp://admin:{password}@{ip}:554/stream"] + [
        _RTSP_TEMPLATES[k].format(ip=ip).replace("MOTDEPASSE", password)
        for k in _BRAND_GUESS_ORDER
    ]
    deadline = time.time() + 25.0
    for url in candidates:
        if time.time() > deadline:
            break
        if _probe_rtsp_url(url, timeout=3.0):
            return True, "ok", url

    reason = _recent_go2rtc_error_hint()
    return False, reason or (
        "Aucun chemin RTSP connu n'a fonctionné — vérifiez l'adresse IP et le mot de "
        "passe, ou saisissez l'URL manuellement"
    ), None


def _ha_remove_camera_entities(stream_name: str):
    """Supprime dans HA toutes les entités liées à une caméra Frigate (camera.* et ses
    siblings : micro, IR, PTZ, détection mouvement…) lors du retrait d'une caméra côté
    app. Frigate slugifie le nom de la caméra déclaré dans frigate.yml pour construire
    l'unique_id/entity_id de son entité camera.* — on matche par nom normalisé (le
    stream_name inclut un suffixe timestamp, donc quasi-unique, pas de faux positif
    attendu). Best-effort : ne bloque jamais la suppression du flux vidéo lui-même si
    HA est injoignable ou si rien n'est trouvé (device jamais rattaché, HA down…)."""
    result = _ha_ws_call("config/entity_registry/list")
    if not result or not result.get("success"):
        return
    entities = result.get("result", [])

    def _norm(s: str) -> str:
        return re.sub(r"[^a-z0-9]", "", (s or "").lower())

    target = _norm(stream_name)
    if not target:
        return

    device_id = None
    for e in entities:
        if not e.get("entity_id", "").startswith("camera."):
            continue
        uid = _norm(e.get("unique_id", ""))
        eid = _norm(e.get("entity_id", ""))
        if target in uid or target in eid or (uid and uid in target):
            device_id = e.get("device_id")
            break

    if not device_id:
        log(f"[ha-cleanup] Aucune entité HA trouvée pour '{stream_name}' — rien à nettoyer")
        return

    ws_send, ws_recv, ws_close = _ha_ws_connect()
    if not ws_send:
        warn(f"[ha-cleanup] Session WS indisponible — nettoyage HA de '{stream_name}' ignoré")
        return
    try:
        mid = [0]

        def call(cmd_type, **params):
            mid[0] += 1
            ws_send({"id": mid[0], "type": cmd_type, **params})
            return ws_recv()

        removed = 0
        for e in entities:
            if e.get("device_id") != device_id:
                continue
            eid = e.get("entity_id")
            res = call("config/entity_registry/remove", entity_id=eid)
            if res and res.get("success"):
                removed += 1
            else:
                warn(f"[ha-cleanup] Suppression entité HA '{eid}' échouée : {res}")
        log(f"[ha-cleanup] {removed} entité(s) HA supprimée(s) pour '{stream_name}'")
    except Exception as e:
        warn(f"[ha-cleanup] {e}")
    finally:
        try:
            ws_close()
        except Exception:
            pass


def _reconcile_cameras(app_cameras: list):
    """Réconciliation bidirectionnelle caméras — même principe que bridge/devices pour
    Zigbee/Matter. handle_camera_configure() est normalement appelé en direct par la
    route /camera/configure, mais si le Pi était hors-ligne au moment de l'action côté
    app (add/remove/mot de passe changé), l'appel direct est perdu : ce cycle de sync
    (toutes les ~5 min) rattrape la divergence en comparant l'état encore en DB avec
    l'état local (_cameras)."""
    app_by_name = {
        c["streamName"]: c
        for c in app_cameras
        if c.get("streamName") and c.get("rtspUrl")
    }

    # Caméras manquantes localement ou dont l'URL a changé (mot de passe mis à jour
    # pendant que le Pi était injoignable) → (ré)ajout.
    for name, cam in app_by_name.items():
        rtsp_url = cam["rtspUrl"]
        has_talk = bool(cam.get("hasTalk"))
        if _cameras.get(name) != rtsp_url or (name in _camera_talk_enabled) != has_talk:
            log(f"[sync/cameras] '{name}' manquante ou désynchronisée localement — ajout")
            try:
                handle_camera_configure("add", name, rtsp_url, has_talk)
            except Exception as e:
                warn(f"[sync/cameras] add '{name}': {e}")

    # Caméras encore locales mais supprimées côté app (delete manqué par l'addon).
    for name in list(_cameras):
        if name not in app_by_name:
            log(f"[sync/cameras] '{name}' supprimée côté app mais encore locale — nettoyage")
            try:
                handle_camera_configure("remove", name)
            except Exception as e:
                warn(f"[sync/cameras] remove '{name}': {e}")


def handle_camera_configure(action: str, stream_name: str, rtsp_url: str | None = None, has_talk: bool = False) -> bool:
    """Ajoute ou supprime une caméra dans Frigate. Appelé par le serveur de commandes HTTP.
    Entièrement bloquant, de bout en bout — la réponse HTTP appelante ne doit dire 'ok'
    que si le travail a réellement été fait (go2rtc à chaud OU restart complet, +
    nettoyage HA à la suppression), jamais avant qu'une tâche de fond ait fini. Retourne
    True si l'opération a effectivement abouti."""
    if action == "add":
        if not rtsp_url:
            raise ValueError("rtspUrl manquant")
        _cameras[stream_name] = rtsp_url
        _save_cameras()
        if has_talk:
            _camera_talk_enabled.add(stream_name)
        else:
            _camera_talk_enabled.discard(stream_name)
        _save_camera_talk()
        write_frigate_config()
        # backchannel audio (cf. _generate_frigate_yaml) change le nombre de sources
        # go2rtc du stream — l'upsert à chaud ne gère qu'une source, donc on force un
        # restart complet dans ce cas plutôt qu'un upsert partiel potentiellement bancal.
        if not has_talk and _go2rtc_upsert_stream(stream_name, rtsp_url):
            log(f"✓ Caméra add (à chaud, go2rtc) : '{stream_name}'")
            return True
        if not has_talk:
            warn(f"[go2rtc] upsert à chaud échoué pour '{stream_name}' — restart Frigate en secours")
    elif action == "remove":
        _cameras.pop(stream_name, None)
        _camera_talk_enabled.discard(stream_name)
        _save_cameras()
        _save_camera_talk()
        write_frigate_config()
        _ha_remove_camera_entities(stream_name)  # bloquant — cf. docstring
        if _go2rtc_remove_stream(stream_name):
            log(f"✓ Caméra remove (à chaud, go2rtc) : '{stream_name}'")
            return True
        warn(f"[go2rtc] remove à chaud échoué pour '{stream_name}' — restart Frigate en secours")
    else:
        raise ValueError(f"action inconnue: {action!r}")

    ok = restart_frigate()
    log(f"{'✓' if ok else '⚠'} Caméra {action} (via restart complet) : '{stream_name}'")
    return ok


def _matter_ws_frames(s):
    """Retourne (recv, send) pour un WebSocket déjà handshake."""
    def _recv():
        while True:
            h = _ws_recv_exact(s, 2)
            opcode = h[0] & 0x0F
            length = h[1] & 0x7F
            if length == 126:
                length = struct.unpack(">H", _ws_recv_exact(s, 2))[0]
            elif length == 127:
                length = struct.unpack(">Q", _ws_recv_exact(s, 8))[0]
            mask_bit = h[1] & 0x80
            if mask_bit:
                mask_b = _ws_recv_exact(s, 4)
            raw = _ws_recv_exact(s, length)
            if mask_bit:
                raw = bytes(b ^ mask_b[i % 4] for i, b in enumerate(raw))
            if opcode == 0x09:   # ping → pong
                s.sendall(bytes([0x8A, 0x80, 0, 0, 0, 0]))
                continue
            if opcode == 0x08:
                raise ConnectionError("WS close frame")
            return json.loads(raw.decode())

    def _send(data: dict):
        payload = json.dumps(data).encode()
        msk = os.urandom(4)
        masked = bytes(b ^ msk[i % 4] for i, b in enumerate(payload))
        n = len(payload)
        if n < 126:
            hdr = bytes([0x81, 0x80 | n])
        elif n < 65536:
            hdr = bytes([0x81, 0xFE]) + struct.pack(">H", n)
        else:
            hdr = bytes([0x81, 0xFF]) + struct.pack(">Q", n)
        s.sendall(hdr + msk + masked)

    return _recv, _send


def _get_otbr_active_dataset():
    """Récupère le dataset opérationnel Thread actif depuis OTBR (format TLV hex),
    à pousser vers matter-server avant tout commissioning Matter-over-Thread.
    Sans ça, matter-server ne connaît aucun réseau Thread à donner au device
    pendant la commande NetworkCommissioning → échec systématique
    "No Wi-Fi/Thread network credentials are configured for commissioning"
    (vu en test réel : PASE/attestation BLE réussissent, seule cette étape bloque).
    Retourne None si OTBR est désactivé ou injoignable (device WiFi-only : pas bloquant)."""
    if not INSTALL_THREAD_ROUTER:
        return None
    otbr_hostname = THREAD_SLUG.replace("_", "-")
    try:
        r = requests.get(
            f"http://{otbr_hostname}:8081/node/dataset/active",
            headers={"Accept": "text/plain"}, timeout=10,
        )
        if r.ok and r.text.strip():
            return r.text.strip()
        warn(f"[matter] Dataset Thread OTBR : {r.status_code} {r.text[:150]}")
    except Exception as e:
        warn(f"[matter] Lecture dataset Thread OTBR : {e}")
    return None


def _matter_ws_connect(timeout_s: int = 15):
    """Ouvre une connexion WS brute vers matter-server (localhost:5580/ws) et effectue
    le handshake. Retourne (sock, _recv, _send, info) ou (None, None, None, error_str)."""
    s = socket.create_connection(("localhost", 5580), timeout=15)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((
        "GET /ws HTTP/1.1\r\nHost: localhost:5580\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += s.recv(1)
    if b"101" not in resp:
        s.close()
        return None, None, None, f"Matter Server WS handshake échoué: {resp[:80]}"

    s.settimeout(timeout_s)
    _recv, _send = _matter_ws_frames(s)
    info = _recv()  # matter-server envoie un message info à la connexion
    return s, _recv, _send, info


def _matter_get_nodes():
    """Liste tous les devices commissionnés côté matter-server (get_nodes), pour
    réconciliation périodique (même logique que bridge/devices côté Zigbee) — plus
    robuste que le seul enregistrement post-commissioning (vu en test réel : un bug
    d'extraction de node_id a fait échouer l'auto-registration malgré un commissioning
    réussi ; une réconciliation périodique se serait auto-corrigée toute seule).
    Retourne une liste de nodes (dicts) ou None en cas d'erreur."""
    s = None
    try:
        s, _recv, _send, info = _matter_ws_connect(timeout_s=20)
        if not s:
            warn(f"[matter-server] get_nodes connexion : {info}")
            return None
        msg_id = "get-nodes-1"
        _send({"message_id": msg_id, "command": "get_nodes"})
        while True:
            msg = _recv()
            mid = msg.get("message_id") or msg.get("messageId")
            if mid == msg_id:
                if "error_code" in msg or "errorCode" in msg or "error" in msg:
                    warn(f"[matter-server] get_nodes échoué : {json.dumps(msg)[:200]}")
                    return None
                result = msg.get("result", [])
                return result if isinstance(result, list) else None
    except Exception as e:
        warn(f"[matter-server] get_nodes: {e}")
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


# Mapping best-effort deviceType Matter (Descriptor.DeviceTypeList) → type Domoticium.
# Pas exhaustif — les types non reconnus retombent sur "switch" (comme avant).
_MATTER_DEVICE_TYPES = {
    0x0100: "light", 0x0101: "light", 0x010C: "light",   # OnOff/Dimmable/ColorTemp Light
    0x0103: "switch", 0x010A: "plug",                     # OnOff Light Switch, Plug
    0x0202: "cover",                                       # Window Covering
    0x0301: "thermostat",
    0x0015: "sensor-contact",                              # Contact Sensor
    0x0107: "sensor-motion",                                # Occupancy Sensor
    0x0302: "sensor-temp",                                  # Temperature Sensor
    0x002C: "sensor-generic",                               # Air Quality Sensor
}


def _extract_matter_device_info(node: dict):
    """Extrait node_id/vendor/product/device_type depuis un node matter-server (format
    get_nodes / commission result : attributes plates 'endpoint/cluster/attribute')."""
    node_id = node.get("node_id")
    attrs = node.get("attributes", {}) or {}
    vendor  = attrs.get("0/40/1", "")
    product = attrs.get("0/40/3", "")
    # "switch" par défaut créait un faux toggle on/off pour les devices non reconnus
    # (vu en test réel : moniteur qualité d'air affiché comme actionneur). Un type
    # inconnu est presque toujours un pur capteur (mesures dans device_entities),
    # jamais un actionneur — "sensor-generic" est le fallback sûr.
    device_type = "sensor-generic"
    # Chercher le DeviceTypeList sur le premier endpoint fonctionnel (≠ 0, qui est RootNode)
    endpoints = sorted({k.split("/")[0] for k in attrs if "/" in k} - {"0"}, key=lambda x: int(x) if x.isdigit() else 999)
    for ep in endpoints:
        type_list = attrs.get(f"{ep}/29/0")
        if isinstance(type_list, list) and type_list:
            dt = type_list[0].get("0") if isinstance(type_list[0], dict) else None
            if dt in _MATTER_DEVICE_TYPES:
                device_type = _MATTER_DEVICE_TYPES[dt]
                break
    return node_id, vendor, product, device_type


def _sync_matter_devices_direct(devices_payload) -> bool:
    """pi_sync_matter_devices via Supabase direct — True si réussi."""
    try:
        rpc_devices = [{
            "node_id": d["node_id"], "name": d["name"],
            "type": d["device_type"], "vendor": d.get("vendor_name") or "",
            "model": d.get("product_name") or "",
        } for d in devices_payload]

        ts = int(time.time())
        id_sorted = ",".join(sorted(str(d["node_id"]) for d in rpc_devices))
        message = f"{SITE_PREFIX}:{ts}:matter_sync:{id_sorted}"
        r = _supabase_rpc("pi_sync_matter_devices", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
            "p_devices": rpc_devices,
        }, timeout=30)
        if r.status_code >= 300:
            warn(f"[supabase] pi_sync_matter_devices {r.status_code}: {r.text[:200]}")
            return False
        log(f"[supabase] pi_sync_matter_devices — {len(rpc_devices)} devices, réponse: {r.text[:120]}")
        return True
    except Exception as e:
        warn(f"[supabase] pi_sync_matter_devices: {e}")
        return False


def _sync_matter_devices_to_app():
    """Réconciliation périodique Matter → Supabase (analogue à bridge/devices Zigbee).
    Envoie la liste COMPLÈTE des nodes commissionnés — `pi_sync_matter_devices`
    réconcilie (upsert + suppression des devices absents), pas juste un ajout
    ponctuel. En cas d'échec : log, retenté au prochain cycle périodique."""
    nodes = _matter_get_nodes()
    if nodes is None:
        return
    devices_payload = []
    for node in nodes:
        node_id, vendor, product, device_type = _extract_matter_device_info(node)
        if node_id is None:
            continue
        devices_payload.append({
            "node_id": node_id,
            "name": product or f"Matter #{node_id}",
            "vendor_name": vendor,
            "product_name": product,
            "device_type": device_type,
        })

    _sync_matter_devices_direct(devices_payload)


def _matter_commission_ws(code: str, timeout_s: int = 200):
    """Commission via matter-server WebSocket direct (port 5580).
    HA 2026+ : ni REST ni HA WebSocket ne fonctionnent pour le commissioning.
    matter-server écoute sur localhost:5580/ws (host_network=true).
    matter-server met ~180s pour répondre (discovery PASE + retry) — timeout 200s.
    Retourne (success: bool, detail: str).
    """
    s = None
    try:
        s, _recv, _send, info = _matter_ws_connect(timeout_s=15)
        if not s:
            return False, info
        s.settimeout(timeout_s)
        log(f"[matter-server] Connecté — schema={info.get('schema_version')} sdk={info.get('sdk_version')}")

        # Matter-over-Thread : matter-server doit connaître le réseau Thread AVANT
        # de commissionner, sinon l'étape NetworkCommissioning.Validate échoue toujours
        # (device WiFi-only : dataset=None, on skip simplement, pas bloquant).
        dataset = _get_otbr_active_dataset()
        if dataset:
            _send({"message_id": "set-thread-dataset-1", "command": "set_thread_dataset",
                   "args": {"dataset": dataset}})
            while True:
                msg = _recv()
                mid = msg.get("message_id") or msg.get("messageId")
                if mid == "set-thread-dataset-1":
                    if "error_code" in msg or "errorCode" in msg or "error" in msg:
                        warn(f"[matter-server] set_thread_dataset échoué : {json.dumps(msg)[:300]}")
                    else:
                        log("[matter-server] ✓ Dataset Thread transmis")
                    break

        msg_id = "commission-1"
        _send({"message_id": msg_id, "command": "commission_with_code",
               "args": {"code": code, "network_only": False}})
        log(f"[matter-server] commission_with_code envoyé — attente résultat (max {timeout_s}s)…")

        while True:
            msg = _recv()
            # Log tous les messages pour diagnostic (camelCase vs snake_case)
            log(f"[matter-server] msg: {json.dumps(msg)[:300]}")
            # matter-server peut utiliser messageId (camelCase) ou message_id (snake_case)
            mid = msg.get("message_id") or msg.get("messageId")
            if mid == msg_id:
                if "error_code" in msg or "errorCode" in msg:
                    # error_code est un entier ; le vrai message est dans details
                    details = msg.get("details") or msg.get("message") or str(msg.get("error_code") or msg.get("errorCode", ""))
                    return False, details
                if "error" in msg:
                    return False, str(msg["error"])
                # result est le node complet (node_id, date_commissioned, attributes…),
                # pas juste l'id — extraire node_id explicitement (vu en test réel :
                # str(dict complet) passé tel quel faisait échouer int(detail) en aval,
                # "auto-registration ignorée" malgré un commissioning réussi).
                result = msg.get("result", {})
                node_id = result.get("node_id") if isinstance(result, dict) else result
                return True, str(node_id)

    except socket.timeout:
        return False, f"Timeout {timeout_s}s — device pas en mode jumelage (discriminator attendu: vérifier reset d'usine)"
    except Exception as e:
        return False, str(e)
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def handle_matter_commission(request_id: str, code: str):
    """Commissionne un device Matter via matter-server WebSocket (thread de fond).
    Le résultat est poussé vers Supabase (sites.last_commission_status) via ingest —
    l'app le lit par polling pendant la fenêtre de commissioning."""
    def _do():
        try:
            log(f"Matter commission {request_id[:8]}… code={code}")
            success, detail = _matter_commission_ws(code)
            if success:
                log(f"✓ Matter commission réussie — node_id={detail}")
                _post_ingest_commission_status(request_id, True, node_id=detail)
                # Pas d'enregistrement Supabase ponctuel ici (fragile — un seul device,
                # un seul essai) : on déclenche une réconciliation complète immédiate
                # (_sync_matter_devices_to_app via _sync_all_to_ha), même mécanisme
                # auto-réparateur que Zigbee. Le nouveau device sera repris avec les
                # autres au prochain cycle (déclenché tout de suite, pas dans 60s).
                _sync_requested.set()
            else:
                warn(f"⚠ Matter commission échouée: {detail}")
                _post_ingest_commission_status(request_id, False, error=detail)
        except Exception as exc:
            warn(f"Matter commission: {exc}")
            _post_ingest_commission_status(request_id, False, error=str(exc))

    threading.Thread(target=_do, daemon=True).start()


def _post_ingest_commission_status(
    request_id: str, success: bool, node_id: str | None = None, error: str | None = None
):
    """Pousse le résultat du commissioning Matter vers Supabase (sites.last_commission_status)."""
    if not INGEST_SECRET:
        return
    try:
        requests.post(
            f"{APP_URL}/api/ingest/commission-status",
            json={
                "siteSecret": INGEST_SECRET,
                "siteId": SITE_PREFIX,
                "requestId": request_id,
                "success": success,
                "nodeId": node_id,
                "error": error,
            },
            timeout=10,
        )
    except Exception as e:
        warn(f"[ingest/commission-status] {e}")


_z2m_online: bool | None = None  # état Z2M courant, None = inconnu

# ── Sync omnipresente App → HA ────────────────────────────────────────────────
_sync_requested  = threading.Event()  # déclenche un sync immédiat (ex: device supprimé)
_mqtt_broker_checked = False          # flag one-shot pour _check_and_fix_mqtt_broker
_last_ha_status_publish:    float = 0.0   # throttle homeassistant/status online
_last_z2m_devices_request:  float = 0.0   # throttle bridge/request/devices


def _check_and_fix_mqtt_broker():
    """Vérifie que l'intégration MQTT HA pointe sur Mosquitto local.
    Lit core.config_entries pour obtenir le broker réel.
    Si EMQX ou autre → modifie directement le fichier storage + restart HA Core.
    Appelé une seule fois au démarrage du service bridge."""
    global _mqtt_broker_checked
    if _mqtt_broker_checked:
        return
    _mqtt_broker_checked = True

    log("[mqtt-check] Vérification broker MQTT HA…")
    storage_path = "/homeassistant/.storage/core.config_entries"
    try:
        with open(storage_path) as f:
            storage = json.load(f)
    except Exception as e:
        warn(f"[mqtt-check] Impossible de lire core.config_entries : {e}")
        return

    entries = storage.get("data", {}).get("entries", [])
    mqtt_entries = [e for e in entries if e.get("domain") == "mqtt"]

    if not mqtt_entries:
        log("[mqtt-check] Aucune intégration MQTT dans HA — configure_mqtt() lancé")
        configure_mqtt()
        return

    for entry in mqtt_entries:
        data   = entry.get("data", {})
        broker = str(data.get("broker") or data.get("host") or "").strip()
        port   = int(data.get("port") or 1883)
        state  = entry.get("state", "?")
        log(f"[mqtt-check] HA MQTT : broker={broker!r} port={port} state={state}")

        is_mosquitto = (
            "mosquitto" in broker.lower()
            or broker in ("127.0.0.1", "localhost", "")
            or port == 1883
        )

        if is_mosquitto:
            log("[mqtt-check] ✓ Mosquitto local confirmé — Z2M discovery OK")
        else:
            warn(f"[mqtt-check] ⚠ MQTT sur {broker!r}:{port} (EMQX) → correction storage + restart HA")
            # Modifier l'entrée directement dans le fichier storage (homeassistant_config:rw)
            entry["data"] = {
                "broker":   "core-mosquitto",
                "port":     1883,
                "username": MOSQUITTO_USER,
                "password": MOSQUITTO_PASS,
            }
            # S'assurer que la discovery est activée dans les options
            opts = entry.setdefault("options", {})
            opts["discovery"]        = True
            opts["discovery_prefix"] = "homeassistant"
            try:
                with open(storage_path, "w") as f:
                    json.dump(storage, f, indent=4)
                log("[mqtt-check] ✓ core.config_entries corrigé → core-mosquitto:1883")
            except Exception as e:
                warn(f"[mqtt-check] Erreur écriture storage : {e}")
                break
            # Restart HA Core pour appliquer (notre add-on continue de tourner)
            log("[mqtt-check] Restart HA Core pour appliquer le broker Mosquitto…")
            try:
                r = requests.post(
                    f"{SUP}/homeassistant/restart",
                    headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"},
                    timeout=60,
                )
                log(f"[mqtt-check] Restart HA : {r.status_code} — Z2M discovery sera active au redémarrage")
            except Exception as e:
                warn(f"[mqtt-check] Erreur restart HA : {e}")
        break


def _sync_areas_batch(rooms: list, devices: list, all_devices: list) -> list:
    """Sync bidirectionnel App ↔ HA pour les pièces/areas.

    Push (App → HA) : crée les areas manquantes, assigne Zigbee ET Matter à leur area.
    Pull (HA → App) : détecte les devices dont l'area HA diverge du room_id DB et
                      retourne la liste de mises à jour à poster vers ingest/states.

    Retourne : liste de {deviceId, roomId} à appliquer en DB.
    """
    if not rooms and not devices and not all_devices:
        return []

    ws_send, ws_recv, ws_close = _ha_ws_connect()
    if not ws_send:
        warn("[sync] Session WebSocket indisponible — sync areas/devices ignorée")
        return []

    room_updates: list = []

    try:
        mid = [0]

        def call(cmd_type, **params):
            mid[0] += 1
            ws_send({"id": mid[0], "type": cmd_type, **params})
            return ws_recv()

        # 1. Areas HA existantes
        res = call("config/area_registry/list")
        existing_areas: dict[str, str] = {}  # name → area_id
        if res and res.get("success"):
            for a in res.get("result", []):
                existing_areas[a.get("name", "")] = a.get("area_id", "")
        log(f"[sync] Areas HA existantes : {list(existing_areas)}")

        # 2. Device registry HA complet (Zigbee + Matter)
        res = call("config/device_registry/list")
        ha_devices_full: list = []
        did_by_uid: dict[str, str] = {}  # identifier_value → ha_device_id
        if res and res.get("success"):
            ha_devices_full = res.get("result", [])
            for dev in ha_devices_full:
                did = dev.get("id")
                if not did:
                    continue
                for identifier in dev.get("identifiers", []):
                    if isinstance(identifier, (list, tuple)) and len(identifier) >= 2:
                        did_by_uid[str(identifier[1])] = did
                for conn in dev.get("connections", []):
                    if isinstance(conn, (list, tuple)) and len(conn) >= 2:
                        did_by_uid[str(conn[1])] = did
        if not did_by_uid:
            log("[sync] ⚠ Device registry HA vide — sera réessayé au prochain cycle")

        # 3. Créer les areas manquantes
        for room in rooms:
            name = room["name"]
            if name in existing_areas:
                continue
            res = call("config/area_registry/create", name=name)
            if res and res.get("success"):
                existing_areas[name] = res.get("result", {}).get("area_id", "")
                log(f"[sync] Area créée : '{name}'")
            else:
                err = (res or {}).get("error", {}).get("code", "?")
                if err == "name_exists":
                    log(f"[sync] Area '{name}' déjà présente (conflit résolu)")
                else:
                    warn(f"[sync] Erreur création area '{name}' : {res}")

        # ── Helper : résoudre le ha_device_id d'un device ──────────────────
        def _resolve_ha_device(ieee: str, matter_node_id) -> str | None:
            if ieee:
                ieee_l = ieee.lower()
                for id_val, did in did_by_uid.items():
                    if ieee_l in id_val.lower():
                        return did
            if matter_node_id is not None:
                hex_node = f"{int(matter_node_id):016x}"
                for id_val, did in did_by_uid.items():
                    if hex_node in id_val.lower():
                        return did
            return None

        # 4. Push App → HA (Zigbee + Matter)
        for d in devices:
            ieee           = (d.get("ieee_address")   or "").strip()
            matter_node_id = d.get("matter_node_id")
            area_name      = (d.get("area_name")      or "").strip()
            area_id        = existing_areas.get(area_name) if area_name else None

            if not ieee and matter_node_id is None:
                continue  # entité système sans identifiant — skip

            device_id = _resolve_ha_device(ieee, matter_node_id)
            if not device_id:
                label = ieee or f"Matter#{matter_node_id}"
                warn(f"[sync] Device non trouvé dans HA ({label}) — sera retentée au prochain cycle")
                continue
            if not area_id:
                warn(f"[sync] Area '{area_name}' inconnue pour {ieee or f'Matter#{matter_node_id}'}")
                continue

            res = call("config/device_registry/update", device_id=device_id, area_id=area_id)
            label = ieee or f"Matter#{matter_node_id}"
            if res and res.get("success"):
                log(f"[sync] {label} → area '{area_name}' ✓")
            else:
                warn(f"[sync] Erreur assignation {label} → '{area_name}': {res}")

        # 5. Pull HA → App : détecte les divergences area HA ↔ room_id DB
        area_id_to_name  = {v: k for k, v in existing_areas.items()}
        room_name_to_id  = {r["name"]: r["id"] for r in rooms}

        # Index des devices DB par identifiant
        db_by_ieee   = {(d.get("ieee_address") or "").lower(): d
                        for d in all_devices if d.get("ieee_address")}
        db_by_matter = {d["matter_node_id"]: d
                        for d in all_devices if d.get("matter_node_id") is not None}

        for ha_dev in ha_devices_full:
            ha_area_id = ha_dev.get("area_id")
            if not ha_area_id:
                continue
            expected_area = area_id_to_name.get(ha_area_id)
            if not expected_area:
                continue  # area HA non gérée par Domoticium
            expected_room_id = room_name_to_id.get(expected_area)
            if not expected_room_id:
                continue

            # Trouver le device DB correspondant
            db_dev = None
            for ident in ha_dev.get("identifiers", []):
                if not (isinstance(ident, (list, tuple)) and len(ident) >= 2):
                    continue
                val = str(ident[1])
                m = _IEEE_RE.search(val.lower())
                if m:
                    db_dev = db_by_ieee.get(m.group(0))
                    break
                # Matter : chercher node_id en hex dans l'identifier
                for node_id, d in db_by_matter.items():
                    if f"{int(node_id):016x}" in val.lower():
                        db_dev = d
                        break
                if db_dev:
                    break

            if not db_dev:
                continue

            if db_dev.get("room_id") != expected_room_id:
                label = ha_dev.get("name_by_user") or ha_dev.get("name") or ha_dev.get("id")
                room_updates.append({"deviceId": db_dev["id"], "roomId": expected_room_id})
                log(f"[sync] Pull pièce : '{label}' → '{expected_area}'")

    except Exception as e:
        warn(f"[sync] Erreur batch areas : {e}")
    finally:
        try:
            ws_close()
        except Exception:
            pass

    return room_updates


def _sync_all_to_ha():
    """Récupère l'état complet depuis l'app et l'applique à HA (idempotent, une session WS)."""
    global _last_ha_status_publish, _last_z2m_devices_request
    auth = base64.b64encode(f"{PI_USER}:{PI_PASS}".encode()).decode()
    try:
        r = requests.get(
            f"{APP_URL}/api/webhooks/pi/sync-state?siteId={SITE_PREFIX}",
            headers={"Authorization": f"Basic {auth}"},
            timeout=15,
        )
        if not r.ok:
            warn(f"[sync] sync-state HTTP {r.status_code}: {r.text[:100]}")
            return
        state = r.json()
    except Exception as e:
        warn(f"[sync] Impossible de récupérer sync-state: {e}")
        return

    rooms       = state.get("rooms", [])
    devices     = state.get("device_assignments", [])
    all_devices = state.get("all_devices", [])
    scenes      = state.get("scene_commands", [])
    autos       = state.get("automation_commands", [])
    app_cameras = state.get("cameras", [])

    log(f"[sync] Début : {len(rooms)} pièces, {len(devices)} assignations, "
        f"{len(all_devices)} devices total, {len(scenes)} scènes, {len(autos)} automations")

    # Déclencher Z2M pour republier ses discovery messages HA → HA peuple son device registry.
    # Envoyé EN PREMIER pour laisser à Z2M le temps de répondre pendant qu'on sync scènes/autos.
    # Throttlé à 1x/5min pour éviter le flood de messages MQTT à chaque cycle 60s.
    _now = time.time()
    if _local_client and (_now - _last_ha_status_publish > 300):
        _local_client.publish("homeassistant/status", "online", qos=1)
        _last_ha_status_publish = _now
        log("[sync] homeassistant/status online → Z2M republiera les discovery HA")

    # Scènes + automations via REST HA (rapide, pas de WebSocket)
    for scene in scenes:
        _handle_ha_command(json.dumps(scene).encode())
    for auto in autos:
        _handle_ha_command(json.dumps(auto).encode())

    # Areas + device assignments en une seule session WebSocket (bidirectionnel)
    room_updates = _sync_areas_batch(rooms, devices, all_devices)
    if room_updates and INGEST_SECRET:
        _report_room_assignments_direct(room_updates)

    # Forcer la redélivrance du retained zigbee2mqtt/bridge/devices → vendor/model/
    # features/z2m_name mis à jour sans redémarrer Z2M. Z2M n'expose AUCUN topic de
    # requête pour republier sa liste de devices à la demande (contrairement à
    # bridge/request/permit_join, bridge/request/restart, etc. — vérifié dans la doc
    # officielle Z2M le 2026-07-20 : bridge/devices n'est republié qu'au démarrage de
    # Z2M ou à un vrai événement device join/leave/rename). Se désabonner puis se
    # réabonner au topic exact force le broker MQTT (Mosquitto) à redélivrer
    # immédiatement le dernier message retained, qui déclenche on_local_message()
    # exactement comme un vrai événement Z2M — sans dépendre d'un mécanisme de
    # requête qui n'existe pas côté Z2M.
    # Throttlé à 1x/5min (inutile à chaque cycle 60s).
    if _local_client and (time.time() - _last_z2m_devices_request > 300):
        _local_client.unsubscribe("zigbee2mqtt/bridge/devices")
        _local_client.subscribe([("zigbee2mqtt/bridge/devices", 1)])
        _last_z2m_devices_request = time.time()
        log("[sync] Re-souscription bridge/devices → retained message redélivré (sync Zigbee)")

    # Réconciliation Matter (get_nodes) — même logique que bridge/devices Zigbee,
    # auto-réparatrice si l'enregistrement post-commissioning a échoué ou a été manqué.
    _sync_matter_devices_to_app()

    # Réconciliation caméras — rattrape un ajout/suppression manqué par l'addon si le Pi
    # était hors-ligne au moment de l'action côté app (sinon une caméra supprimée dans
    # l'app pendant une coupure réseau resterait fantôme sur le Pi indéfiniment).
    _reconcile_cameras(app_cameras)

    _backfill_ha_entity_links()
    _backfill_camera_entity_links()

    log("[sync] ✓ Terminé")


def _backfill_ha_entity_links():
    """Relie tout device (Zigbee ou Matter) dont ha_entity_id est encore vide à son
    entité HA — rattrape les devices créés avant le lien entity_registry_updated→
    ieee/node_id (ou dont l'événement a été manqué : redémarrage, erreur réseau
    ponctuelle…). Idempotent (ré-envoyer le même lien ne fait rien) — appelé à chaque
    cycle de sync. Sans ce lien pour Matter, l'état (ex: capteur d'ouverture) ne
    remonte jamais dans l'app — vu en test réel après le 1er commissioning."""
    result = _ha_ws_call("config/entity_registry/list")
    if not result or not result.get("success"):
        return
    for e in result.get("result", []):
        if e.get("entity_category") in ("diagnostic", "config"):
            continue  # jamais pertinent côté client (redémarrages, raison démarrage…)
        entity_id = e.get("entity_id", "")
        unique_id = e.get("unique_id") or ""
        m = _IEEE_RE.search(unique_id)
        payload = {
            "siteSecret": INGEST_SECRET,
            "siteId": SITE_PREFIX,
            "action": "added",
            "entityId": entity_id,
            "friendlyName": e.get("name") or e.get("original_name"),
            "domain": entity_id.split(".")[0] if "." in entity_id else None,
        }
        if m:
            payload["ieeeAddress"] = m.group(0)
        else:
            node_id = _matter_node_id_from_unique_id(unique_id)
            if node_id is None:
                continue
            payload["matterNodeId"] = node_id
        try:
            requests.post(f"{APP_URL}/api/ingest/registry", json=payload, timeout=10)
        except Exception as ex:
            warn(f"[sync] backfill ha_entity_id {entity_id}: {ex}")


def _backfill_camera_entity_links():
    """Relie chaque caméra HA à ses entités secondaires (micro, IR, PTZ presets,
    détection mouvement…) dans Supabase. Même pattern que _backfill_ha_entity_links()
    mais pour les caméras : lit le device_id HA de chaque entité camera.*, puis
    regroupe toutes les entités siblings (non diagnostic/config) du même device.
    Idempotent — upsert côté web ne réécrase pas visible_client (override admin préservé).
    """
    result = _ha_ws_call("config/entity_registry/list")
    if not result or not result.get("success"):
        return

    entities = result.get("result", [])

    # Grouper par device_id HA (UUID interne HA)
    by_device: dict[str, list[dict]] = {}
    for e in entities:
        did = e.get("device_id")
        if did:
            by_device.setdefault(did, []).append(e)

    WRITABLE_DOMAINS = {
        "switch", "select", "number", "input_boolean", "input_number",
        "input_select", "button", "light", "cover", "climate", "lock", "fan",
    }

    for e in entities:
        entity_id = e.get("entity_id", "")
        if not entity_id.startswith("camera."):
            continue
        if e.get("entity_category") in ("diagnostic", "config"):
            continue
        device_id = e.get("device_id")
        if not device_id:
            continue

        secondary = []
        for sibling in by_device.get(device_id, []):
            s_id = sibling.get("entity_id", "")
            if s_id == entity_id:
                continue
            if sibling.get("entity_category") in ("diagnostic", "config"):
                continue
            domain = s_id.split(".")[0] if "." in s_id else ""
            if not domain:
                continue
            secondary.append({
                "entityId": s_id,
                "domain": domain,
                "friendlyName": sibling.get("name") or sibling.get("original_name"),
                "deviceClass": sibling.get("device_class") or sibling.get("original_device_class"),
                "writable": domain in WRITABLE_DOMAINS,
            })

        if not secondary:
            continue

        try:
            requests.post(
                f"{APP_URL}/api/ingest/camera-registry",
                json={
                    "siteSecret": INGEST_SECRET,
                    "siteId": SITE_PREFIX,
                    "cameraHaEntityId": entity_id,
                    "entities": secondary,
                },
                timeout=10,
            )
            log(f"[camera-registry] {entity_id} → {len(secondary)} entité(s) secondaire(s)")
        except Exception as ex:
            warn(f"[camera-registry] {entity_id}: {ex}")


def _ha_sync_loop():
    """Thread de fond : synchronise l'app avec HA toutes les 5 minutes.
    Se déclenche immédiatement sur reconnexion EMQX (via _sync_requested)."""
    log("[sync] Thread de sync démarré — premier sync dans 30s")
    time.sleep(30)  # laisser HA + EMQX s'initialiser
    while True:
        try:
            _sync_all_to_ha()
        except Exception as e:
            warn(f"[sync] Erreur inattendue : {e}")
        # Attend 5 min OU un déclenchement immédiat (reconnexion EMQX, etc.) — le
        # timeout était resté à 60s (bug, 5x plus d'appels que prévu à /sync-state,
        # constaté en creusant le dépassement de quota Vercel du 2026-07-18).
        _sync_requested.wait(timeout=300)
        _sync_requested.clear()


def _heartbeat_direct() -> bool:
    """Heartbeat via pi_report_heartbeat (Supabase direct) — True si réussi."""
    try:
        ts = int(time.time())
        z2m_part = "null" if _z2m_online is None else str(_z2m_online).lower()
        message = f"{SITE_PREFIX}:{ts}:heartbeat:{z2m_part}"
        payload: dict = {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
        }
        if _z2m_online is not None:
            payload["p_z2m_online"] = _z2m_online
        r = _supabase_rpc("pi_report_heartbeat", payload)
        if r.status_code >= 300:
            warn(f"[supabase] pi_report_heartbeat {r.status_code}: {r.text[:120]}")
            return False
        return True
    except Exception as e:
        warn(f"[supabase] pi_report_heartbeat: {e}")
        return False


def call_heartbeat_api():
    """Envoie le heartbeat (+ état Z2M courant) via Supabase direct. En cas d'échec :
    log, retenté au prochain cycle (_heartbeat_loop, 60s)."""
    _heartbeat_direct()


def run_ha_ws_bridge():
    """Thread permanent : écoute HA WebSocket → persiste état + registre vers Supabase (ingest).
    Seul canal d'état — remplace entièrement EMQX et les automations HA State Stream."""
    # Domaines HA à persister (filtre pour réduire le trafic — tout ce que l'app affiche)
    RELAY_DOMAINS = {
        "light", "switch", "cover", "lock", "fan", "climate", "sensor",
        "binary_sensor", "input_boolean", "media_player", "camera",
        "alarm_control_panel", "scene", "automation",
    }
    while True:
        ws_send, ws_recv, ws_close = _ha_ws_connect(long_lived=True)
        if not ws_send:
            time.sleep(15)
            continue
        try:
            # Souscrit à state_changed et entity_registry_updated
            ws_send({"id": 1, "type": "subscribe_events", "event_type": "state_changed"})
            ws_recv()  # ack subscription
            ws_send({"id": 2, "type": "subscribe_events", "event_type": "entity_registry_updated"})
            ws_recv()  # ack subscription
            log("[ha-ws-bridge] Souscrit à state_changed + entity_registry_updated")

            while True:
                msg = ws_recv()
                if msg.get("type") != "event":
                    continue
                event = msg.get("event", {})
                event_type = event.get("event_type")
                data = event.get("data", {})

                if event_type == "state_changed":
                    entity_id = data.get("entity_id", "")
                    domain = entity_id.split(".")[0] if "." in entity_id else ""
                    if domain not in RELAY_DOMAINS:
                        continue
                    new_state = data.get("new_state")
                    if not new_state:
                        continue

                    state_val = new_state.get("state", "")
                    attributes = new_state.get("attributes", {})

                    # Accumule dans le batch — _flush_state_batch() envoie toutes les 2.5s.
                    # La déduplication par entity_id conserve uniquement le dernier état.
                    if INGEST_SECRET:
                        with _state_batch_lock:
                            _state_batch[entity_id] = (state_val, attributes)

                elif event_type == "entity_registry_updated":
                    action = data.get("action")
                    entity_id = data.get("entity_id") or (data.get("changes", {}) or {}).get("entity_id")
                    if entity_id and action in ("create", "remove", "update") and INGEST_SECRET:
                        ha_action = {"create": "added", "remove": "removed", "update": "updated"}.get(action, action)
                        threading.Thread(
                            target=_post_ingest_registry,
                            args=(entity_id, ha_action, data),
                            daemon=True,
                        ).start()

        except Exception as e:
            warn(f"[ha-ws-bridge] Erreur: {e} — reconnexion dans 15s")
        finally:
            try:
                ws_close()
            except Exception:
                pass
        time.sleep(15)


# ── Normalisation état HA → format Device Domoticium ─────────────────────────
# Port Python de web/src/lib/ha/normalize.ts (haEntityToNormalizedPatch) — utilisé
# uniquement par le chemin direct Supabase (cf. HANDOFF §36) : la fonction Postgres
# pi_report_device_state() reçoit un patch déjà normalisé plutôt que de dupliquer
# cette table de correspondance une 3e fois en SQL. À garder synchronisé avec le
# fichier TS d'origine si la logique de normalisation évolue.
def _ha_state_to_normalized(entity_id: str, state: str) -> dict:
    domain = entity_id.split(".")[0]
    if domain in ("light", "switch", "input_boolean"):
        return {"on": state == "on"}
    if domain == "binary_sensor":
        return {"on": state == "on"}
    if domain == "cover":
        return {"on": state not in ("closed", "unavailable")}
    if domain == "sensor":
        try:
            return {"value": float(state)}
        except ValueError:
            return {}
    if domain == "climate":
        return {"on": state != "off"}
    return {"on": state == "on"}


def _ha_attributes_to_normalized(entity_id: str, attrs: dict, merged: dict) -> dict:
    domain = entity_id.split(".")[0]
    result: dict = {}

    if domain == "light":
        brightness = attrs.get("brightness")
        if isinstance(brightness, (int, float)):
            result["brightness"] = round((brightness / 255) * 100)
        return result

    if domain == "sensor":
        dc = attrs.get("device_class")
        val = merged.get("value")
        if val is not None:
            if dc == "temperature": result["temperature"] = val
            elif dc == "humidity": result["humidity"] = val
            elif dc == "battery": result["battery"] = val
            elif dc in ("power", "energy"): result["power"] = val
            else: result["value"] = val
        return result

    if domain == "binary_sensor":
        dc = attrs.get("device_class")
        is_on = merged.get("on")
        if dc in ("motion", "occupancy", "presence"):
            result["motion"] = is_on
        elif dc in ("door", "window", "opening", "contact", "garage_door"):
            result["contact"] = (not is_on) if is_on is not None else None
        return result

    if domain == "climate":
        cur_temp = attrs.get("current_temperature")
        if isinstance(cur_temp, (int, float)):
            result["temperature"] = cur_temp
        target_temp = attrs.get("temperature")
        if isinstance(target_temp, (int, float)):
            result["targetTemperature"] = target_temp
        return result

    return result


def _ha_entity_to_normalized_patch(entity_id: str, state: str, attributes: dict) -> dict:
    state_patch = _ha_state_to_normalized(entity_id, state)
    attr_patch = _ha_attributes_to_normalized(entity_id, attributes, state_patch)
    return {**state_patch, **attr_patch}


# ── Batch d'états : accumule les state_changed, flush toutes les 2.5s ────────
# Réduit les appels Vercel de ×N (un par event) à 1 par fenêtre temporelle.
# La déduplication par entity_id garantit qu'on n'envoie que le dernier état connu.
_state_batch: dict = {}
_state_batch_lock = threading.Lock()

# ── Watchdog caméras ─────────────────────────────────────────────────────────
# Sonde go2rtc toutes les 60s, envoie les deltas dans le même flush que les états.
_cam_watch_online: dict[str, bool] = {}   # streamName → dernière valeur connue
_cam_watch_dirty: set[str] = set()        # streamNames dont le statut a changé
_cam_watch_lock = threading.Lock()


def _go2rtc_active_consumers() -> dict[str, bool]:
    """Liste (via /api/streams, une seule requête légère, aucune nouvelle connexion
    ouverte) les flux ayant au moins un consommateur actif (quelqu'un regarde le direct
    en ce moment — HLS/WebRTC). Retourne {stream_name: bool}."""
    try:
        r = requests.get("http://127.0.0.1:1984/api/streams", timeout=5)
        if not r.ok:
            return {}
        return {name: bool((info or {}).get("consumers")) for name, info in r.json().items()}
    except Exception:
        return {}


def _probe_cameras_go2rtc() -> dict[str, bool]:
    """Sonde chaque caméra enregistrée en forçant une connexion RTSP à chaud, en
    parallèle (cf. _go2rtc_probe_online). Une simple lecture de /api/streams ne suffit
    pas en général : go2rtc ne garde une connexion ouverte que s'il y a un consommateur
    actif (WebRTC/HLS en cours de visionnage), donc son champ producer 'state' est
    absent la quasi-totalité du temps même quand la caméra est parfaitement joignable.
    EXCEPTION : si un consommateur est déjà actif (quelqu'un regarde le direct), on
    saute la sonde active pour cette caméra — elle est forcément déjà joignable
    (un flux en cours de lecture le prouve), et une sonde en parallèle risquerait
    d'ouvrir une 2e connexion RTSP concurrente vers la caméra. Certaines caméras
    d'entrée de gamme n'acceptent qu'UNE connexion à la fois : la sonde entrait alors
    en collision avec la session de visionnage en cours et la coupait (observé en
    réel : erreur go2rtc "wrong response on DESCRIBE" pile au moment du visionnage,
    répétée à chaque cycle watchdog de 60s)."""
    names = list(_cameras)
    active_consumers = _go2rtc_active_consumers()
    result: dict[str, bool] = {}
    lock = threading.Lock()

    def _probe(name: str):
        online = _go2rtc_probe_online(name)
        with lock:
            result[name] = online

    to_probe = []
    for name in names:
        if active_consumers.get(name):
            result[name] = True
        else:
            to_probe.append(name)

    threads = [threading.Thread(target=_probe, args=(n,), daemon=True) for n in to_probe]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=8.0)
    return result


def _run_camera_watchdog():
    """Thread de fond : sonde les caméras via go2rtc toutes les 60s.
    Les deltas sont injectés dans _cam_watch_dirty pour être envoyés
    dans le prochain flush de _flush_state_batch."""
    time.sleep(30)  # laisser go2rtc démarrer
    while True:
        if _cameras:
            probed = _probe_cameras_go2rtc()
            if probed:
                with _cam_watch_lock:
                    for name in list(_cameras):
                        new_online = probed.get(name, False)
                        if _cam_watch_online.get(name) != new_online:
                            _cam_watch_online[name] = new_online
                            _cam_watch_dirty.add(name)
        time.sleep(60)


def _report_device_state_direct(entity_id: str, state: str, attributes: dict) -> bool:
    """pi_report_device_state via Supabase direct — True si réussi."""
    try:
        patch = _ha_entity_to_normalized_patch(entity_id, state, attributes)
        ts = int(time.time())
        message = f"{SITE_PREFIX}:{ts}:device_state:{entity_id}"
        r = _supabase_rpc("pi_report_device_state", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
            "p_ha_entity_id": entity_id, "p_patch": patch,
        })
        if r.status_code >= 300:
            warn(f"[supabase] pi_report_device_state({entity_id}) {r.status_code}: {r.text[:120]}")
            return False
        return True
    except Exception as e:
        warn(f"[supabase] pi_report_device_state({entity_id}): {e}")
        return False


def _report_camera_status_direct(stream_name: str, online: bool) -> bool:
    """pi_report_camera_status via Supabase direct — True si réussi."""
    try:
        ts = int(time.time())
        message = f"{SITE_PREFIX}:{ts}:camera_status:{stream_name}:{str(online).lower()}"
        r = _supabase_rpc("pi_report_camera_status", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
            "p_online": online, "p_stream_name": stream_name,
        })
        if r.status_code >= 300:
            warn(f"[supabase] pi_report_camera_status({stream_name}) {r.status_code}: {r.text[:120]}")
            return False
        return True
    except Exception as e:
        warn(f"[supabase] pi_report_camera_status({stream_name}): {e}")
        return False


def _flush_state_batch():
    """Thread de fond : envoie états devices + statuts caméras toutes les 2.5s via
    Supabase direct (un appel HMAC par item). Un item qui échoue (réseau, Supabase
    indisponible) est réintégré au batch pour être retenté au prochain cycle — pas
    de repli Vercel, aucune donnée perdue silencieusement."""
    while True:
        time.sleep(2.5)
        if not INGEST_SECRET:
            continue

        with _state_batch_lock:
            batch = dict(_state_batch)
            _state_batch.clear()

        with _cam_watch_lock:
            cam_batch = {
                n: _cam_watch_online[n]
                for n in _cam_watch_dirty
                if n in _cam_watch_online and n in _cameras
            }
            _cam_watch_dirty.clear()

        failed_states = {
            eid: (st, attrs) for eid, (st, attrs) in batch.items()
            if not _report_device_state_direct(eid, st, attrs)
        }
        failed_cams = {
            name: online for name, online in cam_batch.items()
            if not _report_camera_status_direct(name, online)
        }

        if failed_states:
            with _state_batch_lock:
                for eid, v in failed_states.items():
                    _state_batch.setdefault(eid, v)
        if failed_cams:
            with _cam_watch_lock:
                _cam_watch_dirty.update(failed_cams.keys())


_IEEE_RE = re.compile(r"0x[0-9a-fA-F]{16}")
# unique_id Matter HA : "{fabric_id_hex:16}-{node_id_hex:16}-{postfix}-{endpoint}-{key}-
# {cluster}-{attr}" (cf. get_device_id() dans homeassistant/components/matter/helpers.py
# — le node_id complet est présent en hex dans le 2e segment, pas hashé).
_MATTER_UID_RE = re.compile(r"^[0-9a-fA-F]{16}-([0-9a-fA-F]{16})-")

def _entity_registry_entry(entity_id: str) -> dict | None:
    """Retrouve l'entrée entity_registry HA d'une entité (unique_id, entity_category…) —
    pas exposé en REST, seulement WS."""
    result = _ha_ws_call("config/entity_registry/list")
    if not result or not result.get("success"):
        return None
    for e in result.get("result", []):
        if e.get("entity_id") == entity_id:
            return e
    return None


def _matter_node_id_from_unique_id(unique_id: str | None) -> int | None:
    """Retrouve le node_id Matter (int) d'une entité HA via son unique_id.
    None si l'entité n'est pas Matter ou introuvable."""
    m = _MATTER_UID_RE.match(unique_id or "")
    return int(m.group(1), 16) if m else None


def _post_ingest_registry(entity_id: str, action: str, data: dict):
    """Appelle /api/ingest/registry quand une entité HA est ajoutée/supprimée/renommée."""
    try:
        payload = {
            "siteSecret": INGEST_SECRET,
            "siteId": SITE_PREFIX,
            "action": action,
            "entityId": entity_id,
            "friendlyName": data.get("name") or data.get("changes", {}).get("name"),
            "domain": entity_id.split(".")[0] if "." in entity_id else None,
        }
        if action == "added":
            # Relie le device (Zigbee par IEEE, Matter par node_id — créé par
            # devices-sync, ha_entity_id encore null) à cette entité HA fraîchement
            # créée — sinon état et commandes ne fonctionnent jamais pour ce device
            # (vu en test réel : capteur Matter commissionné mais état jamais à jour).
            entry = _entity_registry_entry(entity_id)
            # entity_category "diagnostic"/"config" = jamais pertinent côté client
            # (ex: "Nombre de redémarrages", "Raison de démarrage") — vu en test réel
            # polluer la carte device une fois les entités secondaires affichées.
            if entry and entry.get("entity_category") in ("diagnostic", "config"):
                return
            # Nom lisible dès la liaison — ne pas attendre le 1er changement d'état
            # (name = override utilisateur, original_name = nom par défaut ; les deux
            # peuvent être absents de l'event live entity_registry_updated, vu en test
            # réel : libellé vide jusqu'au 1er state_changed, parfois jamais pour les
            # capteurs qui changent peu, ex. qualité de l'air).
            if entry and not payload["friendlyName"]:
                payload["friendlyName"] = entry.get("name") or entry.get("original_name")
            unique_id = entry.get("unique_id") if entry else None
            ieee = _IEEE_RE.search(unique_id or "")
            if ieee:
                payload["ieeeAddress"] = ieee.group(0)
            else:
                node_id = _matter_node_id_from_unique_id(unique_id)
                if node_id is not None:
                    payload["matterNodeId"] = node_id
        requests.post(f"{APP_URL}/api/ingest/registry", json=payload, timeout=10)
    except Exception as e:
        warn(f"[ingest/registry] {entity_id}: {e}")


def _heartbeat_loop():
    """Envoie un heartbeat toutes les 60 secondes via webhook API — met à jour
    sites.last_heartbeat_at, relayé au navigateur par Supabase Realtime.
    Était à 30s (réduit après dépassement de quota Vercel Hobby le 2026-07-18) —
    cf. seuils "online" côté web (2 min de marge, largement suffisant à 60s)."""
    time.sleep(10)
    while True:
        call_heartbeat_api()
        time.sleep(60)


def on_local_connect(client, userdata, flags, reason_code, properties):
    if reason_code.is_failure:
        warn(f"[local] Connexion Mosquitto échouée ({reason_code})")
        return
    client.subscribe([("zigbee2mqtt/#", 1)])  # tous les messages Z2M (états + bridge/state)
    log("[local] Connecté Mosquitto — souscrit zigbee2mqtt/# et ha/#")


def _get_ha_areas():
    """Retourne la liste des areas HA via WebSocket [{area_id, name, ...}]."""
    result = _ha_ws_call("config/area_registry/list")
    if result and result.get("success"):
        return result.get("result", [])
    warn(f"[ha/command] _get_ha_areas échoué: {result}")
    return []


def _get_ha_device_id(entity_id=None, ieee_address=None, matter_node_id=None):
    """Retourne le device_id HA depuis entity_id, ieee_address (Zigbee) ou
    matter_node_id (WebSocket) — matter_node_id est le repli nécessaire pour un
    device Matter dont l'entité principale n'est pas encore liée (ha_entity_id
    NULL), symétrique au repli ieee_address déjà utilisé côté Zigbee (observé en
    réel : set_device_area échouait silencieusement pour ces devices)."""
    result = _ha_ws_call("config/entity_registry/list")
    if not result or not result.get("success"):
        warn(f"[ha/command] entity registry inaccessible: {result}")
        return None
    entities = result.get("result", [])
    if entity_id:
        e = next((x for x in entities if x.get("entity_id") == entity_id), None)
        if e and e.get("device_id"):
            return e["device_id"]
    if ieee_address:
        e = next((x for x in entities if ieee_address in (x.get("unique_id") or "")), None)
        if e and e.get("device_id"):
            return e["device_id"]
    if matter_node_id is not None:
        e = next(
            (x for x in entities if _matter_node_id_from_unique_id(x.get("unique_id")) == matter_node_id),
            None,
        )
        if e and e.get("device_id"):
            return e["device_id"]
    return None


def _handle_ha_command(payload: bytes):
    """Exécute une commande ha/command reçue via MQTT."""
    try:
        data = json.loads(payload.decode())
    except Exception as e:
        warn(f"[ha/command] JSON invalide : {e}")
        return

    cmd_type  = data.get("type", "")
    object_id = data.get("object_id", "")

    # ── Scripts / Automations (nécessitent object_id) ────────────────────────
    if cmd_type in ("script_upsert", "script_delete", "automation_upsert", "automation_delete"):
        if not object_id:
            warn(f"[ha/command] object_id manquant pour {cmd_type} : {data}")
            return

        if cmd_type == "script_upsert":
            script_cfg = {
                "alias":    data.get("alias", object_id),
                "icon":     data.get("icon", "mdi:play"),
                "sequence": data.get("sequence", []),
                "mode":     "single",
            }
            r = ha_post(f"/config/script/config/{object_id}", script_cfg)
            if r.ok:
                ha_post("/services/script/reload", {})
                log(f"[ha/command] Script HA créé/mis à jour : {object_id}")
            else:
                warn(f"[ha/command] Erreur script {object_id} : {r.status_code} {r.text[:200]}")

        elif cmd_type == "script_delete":
            r = requests.delete(f"{API}/config/script/config/{object_id}", headers=HDRS, timeout=10)
            if r.ok:
                ha_post("/services/script/reload", {})
                log(f"[ha/command] Script HA supprimé : {object_id}")
            else:
                warn(f"[ha/command] Erreur suppression script {object_id} : {r.status_code} {r.text[:200]}")

        elif cmd_type == "automation_upsert":
            auto_cfg = {
                "alias":   data.get("alias", object_id),
                "trigger": data.get("trigger", []),
                "action":  data.get("action", []),
                "mode":    "single",
            }
            r = ha_post(f"/config/automation/config/{object_id}", auto_cfg)
            if r.ok:
                ha_post("/services/automation/reload", {})
                log(f"[ha/command] Automation HA créée/mise à jour : {object_id}")
            else:
                warn(f"[ha/command] Erreur automation {object_id} : {r.status_code} {r.text[:200]}")

        elif cmd_type == "automation_delete":
            r = requests.delete(f"{API}/config/automation/config/{object_id}", headers=HDRS, timeout=10)
            if r.ok:
                ha_post("/services/automation/reload", {})
                log(f"[ha/command] Automation HA supprimée : {object_id}")
            else:
                warn(f"[ha/command] Erreur suppression automation {object_id} : {r.status_code} {r.text[:200]}")

    # ── Areas (pièces) — WebSocket HA uniquement (pas d'API REST pour area_registry) ──
    elif cmd_type == "create_area":
        name = data.get("name", "")
        if not name:
            warn("[ha/command] create_area: name manquant")
            return
        result = _ha_ws_call("config/area_registry/create", name=name)
        if result and result.get("success"):
            log(f"[ha/command] Area HA créée : '{name}'")
        else:
            warn(f"[ha/command] Erreur création area '{name}' : {result}")

    elif cmd_type == "rename_area":
        old_name = data.get("name", "")
        new_name = data.get("new_name", "")
        if not old_name or not new_name:
            warn("[ha/command] rename_area: name et new_name requis")
            return
        areas = _get_ha_areas()
        area  = next((a for a in areas if a.get("name") == old_name), None)
        if not area:
            result = _ha_ws_call("config/area_registry/create", name=new_name)
            log(f"[ha/command] rename_area: '{old_name}' non trouvée — créée sous '{new_name}'")
            return
        result = _ha_ws_call("config/area_registry/update", area_id=area["area_id"], name=new_name)
        if result and result.get("success"):
            log(f"[ha/command] Area HA renommée : '{old_name}' → '{new_name}'")
        else:
            warn(f"[ha/command] Erreur rename area : {result}")

    elif cmd_type == "delete_area":
        name = data.get("name", "")
        if not name:
            warn("[ha/command] delete_area: name manquant")
            return
        areas = _get_ha_areas()
        area  = next((a for a in areas if a.get("name") == name), None)
        if not area:
            log(f"[ha/command] delete_area: area '{name}' non trouvée dans HA")
            return
        result = _ha_ws_call("config/area_registry/delete", area_id=area["area_id"])
        if result and result.get("success"):
            log(f"[ha/command] Area HA supprimée : '{name}'")
        else:
            warn(f"[ha/command] Erreur suppression area '{name}' : {result}")

    elif cmd_type == "set_device_area":
        entity_id      = data.get("entity_id")      or None
        ieee_address   = data.get("ieee_address")   or None
        matter_node_id = data.get("matter_node_id")
        area_name      = data.get("area_name")      or None

        device_id = _get_ha_device_id(
            entity_id=entity_id, ieee_address=ieee_address, matter_node_id=matter_node_id
        )
        if not device_id:
            warn(f"[ha/command] set_device_area: device non trouvé "
                 f"(entity={entity_id}, ieee={ieee_address}, matter_node_id={matter_node_id})")
            return

        area_id = None
        if area_name:
            areas   = _get_ha_areas()
            area    = next((a for a in areas if a.get("name") == area_name), None)
            area_id = area["area_id"] if area else None
            if not area_id:
                warn(f"[ha/command] set_device_area: area '{area_name}' non trouvée")

        result = _ha_ws_call("config/device_registry/update", device_id=device_id, area_id=area_id)
        if result and result.get("success"):
            log(f"[ha/command] Device area mis à jour : {entity_id or ieee_address} → {area_name or 'aucune'}")
        else:
            warn(f"[ha/command] Erreur set_device_area : {result}")

    else:
        warn(f"[ha/command] Type inconnu : {cmd_type}")


def _detect_device_type(exposes: list[dict]) -> str:
    """Port Python de detectDeviceType() (web/src/app/api/webhooks/pi/devices-sync/route.ts)
    — utilisé uniquement par le chemin direct Supabase, cf. HANDOFF §36."""
    types = [e.get("type", "") for e in exposes]
    names = [e.get("name", "") for e in exposes]
    if "light" in types: return "light"
    if "switch" in types: return "switch"
    if "cover" in types: return "cover"
    if "climate" in types or "thermostat" in types: return "thermostat"
    if "lock" in types: return "switch"
    if "occupancy" in names or "motion" in names: return "sensor-motion"
    if "contact" in names: return "sensor-contact"
    if "temperature" in names or "humidity" in names: return "sensor-temp"
    if "outlet" in types: return "plug"
    return "switch"


def _sync_zigbee_devices_direct(devices_list) -> bool:
    """pi_sync_zigbee_devices via Supabase direct — True si réussi. Réplique le
    filtrage (coordinateur/interview non terminée exclus) fait par la route Vercel."""
    try:
        payload_devices = []
        for d in devices_list:
            if d.get("type") == "Coordinator": continue
            if not d.get("interview_completed"): continue
            ieee = d.get("ieee_address")
            if not ieee: continue

            definition = d.get("definition") or {}
            exposes = definition.get("exposes") or []
            device_type = _detect_device_type(exposes)
            friendly_name = d.get("friendly_name")
            default_name = friendly_name if (friendly_name and friendly_name != ieee) \
                else (definition.get("model") or ieee)

            payload_devices.append({
                "ieee_address": ieee, "name": default_name, "z2m_name": friendly_name,
                "type": device_type, "vendor": definition.get("vendor") or "",
                "model": definition.get("model") or "", "features": exposes,
            })

        ts = int(time.time())
        ieee_sorted = ",".join(sorted(d["ieee_address"] for d in payload_devices))
        message = f"{SITE_PREFIX}:{ts}:zigbee_sync:{ieee_sorted}"
        r = _supabase_rpc("pi_sync_zigbee_devices", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
            "p_devices": payload_devices,
        }, timeout=30)
        if r.status_code >= 300:
            warn(f"[supabase] pi_sync_zigbee_devices {r.status_code}: {r.text[:200]}")
            return False
        log(f"[supabase] pi_sync_zigbee_devices — {len(payload_devices)} devices, réponse: {r.text[:120]}")
        return True
    except Exception as e:
        warn(f"[supabase] pi_sync_zigbee_devices: {e}")
        return False


def _sync_devices_to_app(devices_list):
    """Background thread : envoie la liste bridge/devices pour upsert auto (Supabase
    direct). En cas d'échec : log, retenté au prochain cycle périodique."""
    _sync_zigbee_devices_direct(devices_list)


def _report_room_assignments_direct(room_updates) -> bool:
    """pi_report_room_assignments via Supabase direct — corrige côté app un device dont
    la pièce a été changée directement dans HA (pas dans l'app). True si réussi."""
    try:
        ts = int(time.time())
        key = ",".join(sorted(f"{u['deviceId']}:{u['roomId']}" for u in room_updates))
        message = f"{SITE_PREFIX}:{ts}:room_assignments:{key}"
        r = _supabase_rpc("pi_report_room_assignments", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
            "p_assignments": [{"deviceId": u["deviceId"], "roomId": u["roomId"]} for u in room_updates],
        })
        if r.status_code >= 300:
            warn(f"[supabase] pi_report_room_assignments {r.status_code}: {r.text[:200]}")
            return False
        log(f"[supabase] pi_report_room_assignments — {len(room_updates)} assignation(s)")
        return True
    except Exception as e:
        warn(f"[supabase] pi_report_room_assignments: {e}")
        return False


def on_local_message(client, userdata, msg):
    """Messages reçus depuis Mosquitto local (Z2M). Plus de relay cloud —
    l'état passe uniquement par run_ha_ws_bridge() → Supabase direct (pi_report_device_state)."""
    global _z2m_online
    topic   = msg.topic
    payload = msg.payload

    # ── Z2M bridge/state → mise à jour statut Z2M ────────────────────────────
    if topic == "zigbee2mqtt/bridge/state":
        try:
            data   = json.loads(payload.decode())
            online = data.get("state") == "online"
        except Exception:
            online = payload.decode().strip() == "online"
        _z2m_online = online
        threading.Thread(target=call_heartbeat_api, daemon=True).start()
        return

    # ── Z2M bridge/devices → auto-registration dans Supabase ─────────────────
    if topic == "zigbee2mqtt/bridge/devices":
        try:
            devices_list = json.loads(payload.decode())
            if isinstance(devices_list, list):
                threading.Thread(
                    target=_sync_devices_to_app, args=(devices_list,), daemon=True
                ).start()
        except Exception as exc:
            warn(f"[devices-sync] parse error: {exc}")


def run_local_bridge():
    """Thread permanent : connexion à Mosquitto local (suivi Z2M, auto-registration devices)."""
    global _local_client
    _local_client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="domoticium-local-bridge",
        clean_session=True,
    )
    _local_client.username_pw_set(MOSQUITTO_USER, MOSQUITTO_PASS)
    _local_client.on_connect    = on_local_connect
    _local_client.on_message    = on_local_message
    _local_client.on_disconnect = lambda c, u, df, rc, props: (
        warn(f"[local] Déconnexion Mosquitto ({rc}) — reconnexion…") if rc.is_failure else None
    )
    while True:
        try:
            # host_network: true → namespace réseau hôte, "core-mosquitto" non résolvable.
            # Mosquitto mappe son port 1883 sur l'hôte → 127.0.0.1 est accessible.
            _local_client.connect("127.0.0.1", 1883, keepalive=60)
            _local_client.loop_forever()
        except Exception as e:
            warn(f"[local] Mosquitto : {e} — retry dans 10s")
            time.sleep(10)


def _is_addon_running(slug: str) -> bool:
    """Retourne True si l'addon est installé ET en état 'started'."""
    try:
        r = sup_get(f"/addons/{slug}/info")
        if not r.ok:
            return False
        body = r.json()
        data = body.get("data", body) if isinstance(body, dict) else {}
        return data.get("state") == "started"
    except Exception:
        return False


def _start_addon(slug: str, label: str) -> None:
    """Démarre un addon arrêté via l'API Supervisor."""
    r = sup_post(f"/addons/{slug}/start")
    if r.ok:
        log(f"{label} démarré ✓")
    else:
        warn(f"Impossible de démarrer {label}: {r.status_code} {r.text[:100]}")


def _ensure_matter_integration():
    """S'assure que l'intégration Matter est enregistrée dans HA (config entry).
    Le flow Matter sur Supervisor a 2 étapes :
      1. POST {"handler":"matter"} → type=form, step_id=on_supervisor
      2. POST {"use_addon":true}   → type=create_entry
    Si déjà configuré → type=abort reason=single_instance_allowed (idempotent).
    """
    def _handle_result(result, step):
        ftype = result.get("type")
        if ftype == "create_entry":
            log("[matter] ✓ Intégration Matter activée dans HA")
            return True
        if ftype == "abort":
            reason = result.get("reason", "?")
            if reason in ("single_instance_allowed", "already_configured", "reconfiguration_successful"):
                log(f"[matter] ✓ Intégration Matter configurée ({reason})")
            else:
                warn(f"[matter] Intégration Matter abort (step {step}): {reason}")
            return True
        return False  # besoin d'une autre étape

    try:
        r1 = None
        for attempt in range(1, 6):
            r1 = ha_post("/config/config_entries/flow", {"handler": "matter"})
            if r1.ok:
                break
            if r1.status_code in (502, 503):
                log(f"[matter] Matter Server pas encore prêt ({r1.status_code}), retry dans 15s (tentative {attempt}/5)…")
                time.sleep(15)
            else:
                warn(f"[matter] Intégration Matter step1: {r1.status_code} {r1.text[:100]}")
                return
        if not r1 or not r1.ok:
            warn(f"[matter] Intégration Matter step1: Matter Server toujours indisponible après 5 tentatives")
            return
        res1 = r1.json()
        if _handle_result(res1, 1):
            return

        # Étape on_supervisor : HA demande "use_addon" (booléen, défaut True)
        flow_id  = res1.get("flow_id")
        step_id  = res1.get("step_id", "?")
        log(f"[matter] Intégration Matter étape '{step_id}' → soumission use_addon=true")
        r2 = ha_post(f"/config/config_entries/flow/{flow_id}", {"use_addon": True})
        if not r2.ok:
            warn(f"[matter] Intégration Matter step2: {r2.status_code} {r2.text[:100]}")
            return
        _handle_result(r2.json(), 2)
    except Exception as e:
        warn(f"[matter] _ensure_matter_integration: {e}")


def _ensure_bluetooth_integration():
    """Ajoute l'intégration Bluetooth HA si un dongle USB est branché.

    Retourne True si Bluetooth est disponible (déjà configuré ou ajouté),
    False si aucun adaptateur n'est détecté.
    """
    # 1. Vérifier via config entries — seul check fiable : "bluetooth" peut apparaître
    # dans /config (composants chargés) simplement parce qu'une autre intégration (ex.
    # Matter BLE proxy) déclare "bluetooth" comme dépendance, sans qu'aucun adaptateur
    # ne soit réellement configuré (vu en test réel : composant chargé mais hci0 encore
    # en attente dans "Découvertes", jamais ajouté car ce check retournait déjà True).
    # NB : GET /config/config_entries/entries n'existe PAS en REST côté HA (seules les
    # actions flow le sont) — ce check échouait silencieusement à chaque appel (r.ok
    # toujours False), donc ne trouvait jamais Bluetooth même déjà configuré (vu en
    # test réel : Bluetooth visible dans "Configurées" mais l'addon retentait quand
    # même en boucle). Comme entity_registry/area_registry ailleurs dans ce fichier,
    # la liste des config entries n'est disponible que via le WebSocket.
    result = _ha_ws_call("config_entries/get")
    if result and result.get("success"):
        domains = [e.get("domain", "") for e in result.get("result", [])]
        bt_entries = [d for d in domains if "bluetooth" in d.lower()]
        if bt_entries:
            log(f"[bluetooth] ✓ Intégration Bluetooth déjà configurée ({bt_entries[0]})")
            return True
        log(f"[bluetooth] Config entries domains: {sorted(set(d for d in domains if d))[:15]}")

    # 2. Flow de découverte en attente (source=usb détecté par HA) ?
    rf = ha_get("/config/config_entries/flow")
    if rf.ok:
        for flow in rf.json():
            if flow.get("handler") == "bluetooth":
                flow_id = flow.get("flow_id")
                log(f"[bluetooth] Flow Bluetooth en attente (step={flow.get('step_id', '?')}) → confirmation…")
                rc = ha_post(f"/config/config_entries/flow/{flow_id}", {})
                if rc.ok:
                    res = rc.json()
                    if res.get("type") == "create_entry":
                        log("[bluetooth] ✓ Intégration Bluetooth ajoutée — BLE disponible pour Matter ✓")
                        return True
                    elif res.get("type") == "abort":
                        reason = res.get("reason", "?")
                        if "already" in reason:
                            log("[bluetooth] ✓ Bluetooth déjà configuré")
                            return True
                        warn(f"[bluetooth] Flow abort: {reason}")
                    else:
                        warn(f"[bluetooth] Flow inattendu: {res.get('type')} step={res.get('step_id')}")
                else:
                    warn(f"[bluetooth] Confirmation échouée: {rc.status_code}")
                return False

    # 3. Tentative de création directe (si HA a déjà détecté l'adaptateur)
    r1 = ha_post("/config/config_entries/flow", {"handler": "bluetooth"})
    if not r1.ok:
        log(f"[bluetooth] Aucun adaptateur Bluetooth détecté ({r1.status_code}) — dongle USB non reconnu par HA")
        return False

    res1 = r1.json()
    ftype = res1.get("type")

    if ftype == "create_entry":
        log("[bluetooth] ✓ Intégration Bluetooth ajoutée")
        return True
    if ftype == "abort":
        reason = res1.get("reason", "?")
        if "already" in reason or reason == "single_instance_allowed":
            log(f"[bluetooth] ✓ Bluetooth déjà configuré ({reason})")
            return True
        log(f"[bluetooth] Adaptateur non disponible (abort: {reason}) — HA charge encore le stack USB")
        return False

    # Étape de confirmation supplémentaire
    flow_id = res1.get("flow_id")
    log(f"[bluetooth] Flow étape '{res1.get('step_id', '?')}' → confirmation…")
    r2 = ha_post(f"/config/config_entries/flow/{flow_id}", {})
    if r2.ok:
        res2 = r2.json()
        if res2.get("type") == "create_entry":
            log("[bluetooth] ✓ Intégration Bluetooth configurée — BLE disponible pour Matter ✓")
            return True
        warn(f"[bluetooth] Flow étape 2 inattendu: {res2.get('type')}")
    else:
        warn(f"[bluetooth] Confirmation step 2 échouée: {r2.status_code}")
    return False


def _ensure_matter_ble_proxy():
    """Active l'option "Enable BLE proxy" du add-on Matter Server.

    Sans cette option, matter-server (qui tourne dans son propre conteneur) n'a
    aucun accès BLE — le commissioning Matter-over-Thread/BLE échoue toujours
    avec "No commissionable device was discovered", même avec un dongle
    Bluetooth fonctionnel et l'intégration Bluetooth HA active (vu en test
    réel : timeout complet à chaque tentative, adaptateur pourtant détecté).
    Le nom exact du champ n'est pas garanti stable → recherche dynamique dans
    le schéma (champ booléen dont le nom contient le token "ble"), même
    approche défensive que pour le schema OTBR ailleurs dans ce fichier.
    ATTENTION : "ble" doit être un token isolé (split sur "_"), pas une simple
    sous-chaîne — "enable_test_net_dcl_usage" contient "ble" dans "en-ABLE" et
    a été activé par erreur avant ce fix (vu en test réel).
    """
    try:
        info = sup_get(f"/addons/{MATTER_SLUG}/info")
        if not info.ok:
            warn(f"[matter] Lecture options BLE proxy : {info.status_code}")
            return
        data = info.json()
        if isinstance(data, dict):
            data = data.get("data", data)
        schema = data.get("schema", [])
        options_current = data.get("options", {}) or {}

        ble_field = None
        if isinstance(schema, list):
            for field in schema:
                if (
                    isinstance(field, dict)
                    and field.get("type") == "boolean"
                    and "ble" in str(field.get("name", "")).lower().split("_")
                ):
                    ble_field = field["name"]
                    break

        if not ble_field:
            warn("[matter] Champ BLE proxy introuvable dans le schéma Matter Server — à vérifier manuellement")
            return

        if options_current.get(ble_field) is True:
            log(f"[matter] ✓ BLE proxy déjà activé ({ble_field})")
            return

        r = sup_post(f"/addons/{MATTER_SLUG}/options", {"options": {**options_current, ble_field: True}})
        if r.ok:
            log(f"[matter] ✓ BLE proxy activé ({ble_field}) — redémarrage Matter Server…")
            sup_post(f"/addons/{MATTER_SLUG}/restart")
        else:
            warn(f"[matter] Activation BLE proxy : {r.status_code} {r.text[:150]}")
    except Exception as e:
        warn(f"[matter] _ensure_matter_ble_proxy: {e}")


def _go2rtc_stream_already_persisted(name: str, rtsp_url: str) -> bool:
    """Vérifie si le flux '{name}' est déjà enregistré côté go2rtc avec cette source,
    via l'API JSON structurée (GET /api/streams) plutôt qu'un regex sur le YAML brut
    du fichier de config — cf. _resync_go2rtc_streams pour le contexte (éviter de
    déclencher PUT /api/streams, donc son écriture disque fragile, quand ce n'est pas
    nécessaire). Une 1ère version (v2.9.15) comparait le texte YAML renvoyé par
    GET /api/config, mais la corruption a persisté en conditions réelles le 2026-07-22
    — signe que ce regex ne matchait pas le format réel écrit par go2rtc (jamais
    vérifié en direct, hypothèse sur l'indentation). L'API /api/streams est structurée
    (JSON, `{name: {producers: [{"url": ...}], ...}}`, cf. code source
    internal/streams/stream.go MarshalJSON/producer.go) — comparaison fiable, aucune
    hypothèse de formatage. Best-effort : toute erreur renvoie False (on retente le
    PUT, comportement d'avant ce fix, jamais pire)."""
    try:
        r = requests.get("http://127.0.0.1:1984/api/streams", timeout=5)
        if not r.ok:
            return False
        stream = r.json().get(name)
        if not stream:
            return False
        urls = {p.get("url") for p in (stream.get("producers") or []) if isinstance(p, dict)}
        return rtsp_url in urls
    except Exception:
        return False


def _resync_go2rtc_streams():
    """Repousse chaque caméra suivie (_cameras) vers go2rtc via l'API à chaud (PUT
    /api/streams). Nécessaire après TOUT (re)démarrage de Frigate : le prepare script
    de Frigate ne recopie /homeassistant/frigate.yml vers sa config privée QUE si
    celle-ci est absente (1er démarrage seulement) — jamais ensuite, y compris sur un
    simple restart de l'add-on. go2rtc (embarqué dans Frigate) repart donc avec le
    registre de flux de cette config privée, potentiellement périmée (vide, ou
    obsolète) — alors que notre suivi interne (_cameras/cameras.json) dit toujours "la
    caméra existe". La réconciliation périodique (_reconcile_cameras) ne détecte
    jamais cet écart puisqu'elle ne compare qu'à notre propre bookkeeping, pas à
    l'état réel de go2rtc — d'où une caméra qui reste invisible/hors-service après un
    redémarrage, sans que rien ne se corrige tout seul, jusqu'à ce fix.

    ⚠️ PUT /api/streams applique en interne le MÊME mécanisme de patch texte fragile
    que celui retiré en §58/v2.9.12 pour webrtc (`app.PatchConfig` côté go2rtc, cf.
    internal/streams/api.go — vérifié dans le code source) : un découpage par ligne
    recalculé à chaque appel sur le même fichier "primaire". Appelée sans condition à
    CHAQUE démarrage de l'addon pour CHAQUE caméra, cette fonction était en réalité la
    vraie source de la corruption YAML récurrente observée (§58/§59), pas le
    mécanisme webrtc déjà retiré — confirmé le 2026-07-22 : la corruption persistait
    (ligne 13 au lieu de ligne 11) et a même fini par recasser le bind webrtc lui-même
    un cycle plus tard. D'où la vérification via _go2rtc_stream_already_persisted()
    ci-dessous : ne PATCHer que si la valeur n'est pas déjà la bonne, au lieu de
    marteler l'API à chaque boot même quand rien n'a changé."""
    if not _cameras:
        return
    for name, rtsp_url in _cameras.items():
        if _go2rtc_stream_already_persisted(name, rtsp_url):
            continue
        if _go2rtc_upsert_stream(name, rtsp_url):
            log(f"[frigate] ✓ Flux go2rtc resynchronisé : '{name}'")
        else:
            warn(f"[frigate] Échec resynchronisation go2rtc : '{name}'")


_GO2RTC_API_ORIGIN_FIX_V3_MARKER = "/data/.go2rtc_api_origin_fixed_v3"


def _fix_go2rtc_api_origin_once():
    """Réinstalle Frigate proprement pour repartir d'un fichier de config "primaire"
    go2rtc vierge, ET applique go2rtc.api.origin: "*" (ajouté à _generate_frigate_yaml
    le 2026-07-22, cf. HANDOFF §59).

    v3 de ce correctif. v1 (marker _fixed) : simple restart, insuffisant (fichier déjà
    corrompu, un restart ne le vide pas). v2 (marker _fixed_v2) : reinstall complet +
    _resync_go2rtc_streams() rendue idempotente via un regex sur le YAML brut
    (GET /api/config) — corruption ET rejet WebSocket TOUS DEUX revenus en conditions
    réelles le 2026-07-22 après une mise à jour ultérieure, preuve que ce regex ne
    matchait pas le format réellement écrit par go2rtc (jamais vérifié en direct,
    juste une hypothèse sur l'indentation). _go2rtc_stream_already_persisted()
    réécrite pour utiliser l'API JSON structurée (GET /api/streams) à la place —
    comparaison fiable, plus d'hypothèse de formatage. Nouveau marker (suffixe _v3)
    pour retrigger un dernier reset propre sur les sites déjà pollués. One-shot —
    nouvelles installations : rien à corriger, jamais soumises à l'ancien comportement
    non-idempotent.

    Appelée depuis _ensure_frigate() APRÈS la branche d'état (donc potentiellement sur
    un Frigate jugé "opérationnel" à cet instant précis) — sans réinstallation
    immédiate ici, Frigate resterait désinstallé jusqu'au tout prochain boot de
    l'addon (install_frigate() n'est appelé par _ensure_frigate() que dans les
    branches "absent"/"error", jamais dans la branche "tout va bien"). D'où l'appel
    direct à install_frigate() ci-dessous plutôt que de compter sur le tour de
    boucle suivant."""
    if os.path.exists(_GO2RTC_API_ORIGIN_FIX_V3_MARKER):
        return
    if _is_addon_installed(FRIGATE_SLUG):
        log("[frigate] Reset du fichier de config primaire go2rtc (corruption résiduelle, cf. HANDOFF §62) — réinstallation propre…")
        r = sup_post(f"/addons/{FRIGATE_SLUG}/uninstall", {"remove_config": True}, timeout=120)
        log(f"[frigate] Désinstallation (reset config primaire go2rtc v3) → {r.status_code} {r.text[:150]}")
        time.sleep(10)
        install_frigate()
    open(_GO2RTC_API_ORIGIN_FIX_V3_MARKER, "w").close()


def _ensure_frigate():
    """Installe et démarre Frigate + go2rtc s'ils sont absents ou arrêtés.
    Appelé en thread de fond au démarrage du bridge — permet de lancer Frigate
    sur une installation existante sans déclencher un force_setup complet.
    Réessaie toutes les 5 min en cas d'échec (timeout Supervisor, réseau lent…)."""
    for attempt in range(1, 6):
        try:
            state = _frigate_state()
            if not _is_addon_installed(FRIGATE_SLUG):
                log(f"[frigate] Frigate absent — installation automatique… (tentative {attempt}/5)")
                install_frigate()
            elif state == "error":
                warn(f"[frigate] Frigate en état error — réinstallation propre… (tentative {attempt}/5)")
                sup_post(f"/addons/{FRIGATE_SLUG}/uninstall", timeout=120)
                time.sleep(15)
                install_frigate()
            elif not _is_addon_running(FRIGATE_SLUG):
                log("[frigate] Frigate installé mais arrêté — configuration port + démarrage…")
                _configure_frigate_and_start()
            elif not _frigate_go2rtc_ready():
                log("[frigate] Frigate en cours mais go2rtc indisponible — reconfiguration…")
                _configure_frigate_and_start()
            else:
                log("[frigate] ✓ Frigate et go2rtc opérationnels")
                threading.Thread(target=_setup_frigate_auth_once, daemon=True).start()
            _fix_go2rtc_api_origin_once()
            _resync_go2rtc_streams()
            return  # succès
        except Exception as e:
            warn(f"[frigate] _ensure_frigate tentative {attempt}/5 : {e}")
            if attempt < 5:
                log("[frigate] Nouvel essai dans 5 min…")
                time.sleep(300)
    warn("[frigate] ✗ Frigate non démarré après 5 tentatives — vérifier les logs Frigate dans HA")


def _ensure_matter_server():
    """Installe et démarre Matter Server + OTBR s'ils sont absents ou arrêtés."""
    if not _is_addon_installed(MATTER_SLUG):
        log("[matter] Matter Server absent — installation automatique…")
        install_matter_server()
    elif not _is_addon_running(MATTER_SLUG):
        log("[matter] Matter Server installé mais arrêté — démarrage…")
        _start_addon(MATTER_SLUG, "Matter Server")
    else:
        log("[matter] Matter Server en cours d'exécution ✓")
    # Même si Matter Server tourne déjà, le config entry HA peut être absent
    # (premier démarrage où l'addon était déjà installé → install_matter_server() skippé)
    _ensure_matter_integration()

    # Dongle USB Bluetooth → intégration Bluetooth HA (BLE requis pour commissioning Matter)
    # 10 tentatives (pas 5) : en test réel, le stack BlueZ/USB de HA n'était pas encore
    # prêt après 5×60s=5min suivant un redémarrage — le dongle a fini par être détecté
    # (visible dans Configurées) juste après que l'addon ait abandonné.
    BT_ATTEMPTS = 10
    for attempt in range(1, BT_ATTEMPTS + 1):
        if _ensure_bluetooth_integration():
            break
        if attempt < BT_ATTEMPTS:
            log(f"[bluetooth] Dongle non détecté, nouvel essai dans 60s (tentative {attempt}/{BT_ATTEMPTS})…")
            time.sleep(60)
    else:
        warn(f"[bluetooth] Intégration Bluetooth non disponible après {BT_ATTEMPTS} tentatives — le commissioning Matter via BLE sera impossible")

    # Matter Server a besoin de l'option "Enable BLE proxy" pour utiliser le Bluetooth
    # HA — sans ça, le commissioning BLE échoue toujours (No commissionable device),
    # même avec un dongle Bluetooth fonctionnel et l'intégration HA active.
    _ensure_matter_ble_proxy()

    if not INSTALL_THREAD_ROUTER:
        log("[matter] Open Thread Border Router désactivé (install_thread_border_router=false) — ignoré")
    elif not _is_addon_installed(THREAD_SLUG):
        log("[matter] Open Thread Border Router absent — installation automatique…")
        install_thread_border_router()
    else:
        # Vérifier que les options actuelles sont correctes (network_device peut être périmé)
        needs_reconfig = not _is_addon_running(THREAD_SLUG)
        if NETWORK_MODE and not needs_reconfig:
            try:
                info = sup_get(f"/addons/{THREAD_SLUG}/info")
                if info.ok:
                    data = info.json()
                    if isinstance(data, dict):
                        data = data.get("data", data)
                    current_nd = data.get("options", {}).get("network_device", "")
                    expected_nd = f"{COORDINATOR_HOST}:{COORDINATOR_THREAD_PORT}"
                    if current_nd != expected_nd:
                        log(f"[matter] OTBR network_device incorrect ({current_nd!r} → {expected_nd!r}) — reconfiguration…")
                        needs_reconfig = True
            except Exception as e:
                warn(f"[matter] Lecture options OTBR : {e}")

        if needs_reconfig:
            log("[matter] OTBR — reconfiguration et redémarrage…")
            install_thread_border_router()
        else:
            log("[matter] Open Thread Border Router en cours d'exécution ✓")


# ── Serveur de commandes (remplace EMQX) ───────────────────────────────────────
# Reçoit les appels HTTPS de Vercel (via tunnel Cloudflare, hostname dédié par site),
# authentifié par INGEST_SECRET. Liste blanche de verbes de service HA — pas de
# passthrough générique vers l'API HA (protège notamment contre camera.snapshot).
ALLOWED_SERVICES = {
    "light":         {"turn_on", "turn_off", "toggle"},
    "switch":        {"turn_on", "turn_off", "toggle"},
    "climate":       {"set_temperature", "set_hvac_mode", "turn_on", "turn_off"},
    "cover":         {"open_cover", "close_cover", "stop_cover", "set_cover_position"},
    "lock":          {"lock", "unlock"},
    "fan":           {"turn_on", "turn_off", "toggle", "set_percentage"},
    "media_player":  {"turn_on", "turn_off", "volume_set", "media_play", "media_pause"},
    "homeassistant": {"turn_on", "turn_off", "toggle"},
    "scene":         {"turn_on"},
    "alarm_control_panel": {
        "alarm_arm_home", "alarm_arm_away", "alarm_arm_night",
        "alarm_arm_vacation", "alarm_disarm", "alarm_trigger",
    },
}


# ── Helpers extraction XML (sans dépendances) ────────────────────────────────

def _xml_text(text: str, tag: str) -> str:
    """Premier texte d'un élément en ignorant les préfixes de namespace."""
    m = re.search(
        r'<(?:[^:>\s]+:)?' + re.escape(tag) + r'(?:\s[^>]*)?>([^<]*)</(?:[^:>]+:)?' + re.escape(tag) + r'>',
        text, re.DOTALL,
    )
    return m.group(1).strip() if m else ''


def _xml_all(text: str, tag: str) -> list:
    """Tous les textes des éléments avec ce nom local."""
    return [
        m.group(1).strip()
        for m in re.finditer(
            r'<(?:[^:>\s]+:)?' + re.escape(tag) + r'(?:\s[^>]*)?>([^<]*)</(?:[^:>]+:)?' + re.escape(tag) + r'>',
            text, re.DOTALL,
        )
    ]


def _xml_attr(text: str, tag: str, attr: str) -> str:
    """Valeur d'un attribut sur le premier élément trouvé."""
    m = re.search(
        r'<(?:[^:>\s]+:)?' + re.escape(tag) + r'\b[^>]*\b' + re.escape(attr) + r'=["\']([^"\']*)["\']',
        text,
    )
    return m.group(1) if m else ''


def _xml_has_tag(text: str, tag: str) -> bool:
    """True si un élément de ce nom local existe (avec ou sans enfants — contrairement
    à _xml_text/_xml_all qui exigent du texte direct, utile pour des sections comme
    <tt:PTZ><tt:XAddr>...</tt:XAddr></tt:PTZ> qui n'ont pas de texte propre)."""
    return re.search(r'<(?:[^:>\s]+:)?' + re.escape(tag) + r'(?:[\s/>])', text) is not None


# ── Découverte ONVIF ─────────────────────────────────────────────────────────

_WS_DISCOVER_ADDR = "239.255.255.250"
_WS_DISCOVER_PORT = 3702

_RTSP_TEMPLATES = {
    "hikvision": "rtsp://admin:MOTDEPASSE@{ip}:554/Streaming/Channels/101",
    "dahua":     "rtsp://admin:MOTDEPASSE@{ip}:554/cam/realmonitor?channel=1&subtype=0",
    "amcrest":   "rtsp://admin:MOTDEPASSE@{ip}:554/cam/realmonitor?channel=1&subtype=0",
    "imou":      "rtsp://admin:MOTDEPASSE@{ip}:554/cam/realmonitor?channel=1&subtype=0",  # marque Dahua, même SDK
    "lorex":     "rtsp://admin:MOTDEPASSE@{ip}:554/cam/realmonitor?channel=1&subtype=0",  # OEM Dahua
    "axis":      "rtsp://root:MOTDEPASSE@{ip}/axis-media/media.amp",
    "reolink":   "rtsp://admin:MOTDEPASSE@{ip}:554/h264Preview_01_main",
    "uniview":   "rtsp://admin:MOTDEPASSE@{ip}:554/media/video1",
    "hanwha":    "rtsp://admin:MOTDEPASSE@{ip}:554/profile1/media.smp",
    "vivotek":   "rtsp://root:MOTDEPASSE@{ip}:554/live.sdp",
    "bosch":     "rtsp://admin:MOTDEPASSE@{ip}:554/video?inst=1",
    "pelco":     "rtsp://admin:MOTDEPASSE@{ip}:554/stream1",
    "flir":      "rtsp://admin:MOTDEPASSE@{ip}:554/avc",
    "tplink":    "rtsp://admin:MOTDEPASSE@{ip}:554/stream1",                # Tapo / VIGI
    "foscam":    "rtsp://admin:MOTDEPASSE@{ip}:554/videoMain",
    "ezviz":     "rtsp://admin:MOTDEPASSE@{ip}:554/h264/ch1/main/av_stream",
    "dlink":     "rtsp://admin:MOTDEPASSE@{ip}:554/play1.sdp",
    "swann":     "rtsp://admin:MOTDEPASSE@{ip}:554/Streaming/Channels/101",  # OEM Hikvision
    "annke":     "rtsp://admin:MOTDEPASSE@{ip}:554/Streaming/Channels/101",  # OEM Hikvision
}


def _rtsp_fallback(manufacturer: str, ip: str) -> str:
    """Cherche le chemin RTSP connu pour un fabricant ONVIF (ex: 'TP-Link Systems Inc.',
    'Reolink' — le libellé exact varie selon la caméra). Normalise en supprimant tout ce
    qui n'est pas alphanumérique pour matcher malgré espaces/tirets/casse."""
    norm = _normalize_brand(manufacturer)
    tpl = None
    if norm:
        for key, candidate in _RTSP_TEMPLATES.items():
            if norm.startswith(key) or key in norm:
                tpl = candidate
                break
    if not tpl:
        tpl = "rtsp://admin:MOTDEPASSE@{ip}:554/stream"
    return tpl.format(ip=ip)


def _ws_discover(timeout: float = 5.0) -> list:
    """WS-Discovery UDP multicast — deux probes (avec et sans filtre Types) pour compat Reolink."""
    xaddrs: set = set()
    # Reolink répond mieux au probe sans filtre Types ; on essaie les deux
    for types_filter in ('<d:Types>dn:NetworkVideoTransmitter</d:Types>', ''):
        msg_id = str(uuid.uuid4())
        probe = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
            ' xmlns:d="http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"'
            ' xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            '<s:Header>'
            '<a:Action>http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/Probe</a:Action>'
            f'<a:MessageID>uuid:{msg_id}</a:MessageID>'
            '<a:To>urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01</a:To>'
            '</s:Header>'
            f'<s:Body><d:Probe>{types_filter}</d:Probe></s:Body>'
            '</s:Envelope>'
        ).encode('utf-8')
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(min(timeout, 3.0))
            sock.sendto(probe, (_WS_DISCOVER_ADDR, _WS_DISCOVER_PORT))
            deadline = time.time() + min(timeout, 3.0)
            while time.time() < deadline:
                try:
                    data, _ = sock.recvfrom(65535)
                    text = data.decode('utf-8', errors='ignore')
                    for addr in _xml_text(text, 'XAddrs').split():
                        if addr.startswith('http'):
                            xaddrs.add(addr)
                except socket.timeout:
                    break
        except Exception as e:
            warn(f'[onvif-scan] ws-discover: {e}')
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    return list(xaddrs)


def _subnet_onvif_scan_pass(base: str, onvif_ports: tuple, connect_timeout: float) -> list:
    """Un seul passage de scan TCP parallèle sur base.1-254."""
    found: list = []
    lock = threading.Lock()

    def _probe(octet: int):
        ip = f'{base}.{octet}'
        for port in onvif_ports:
            try:
                with socket.create_connection((ip, port), timeout=connect_timeout):
                    with lock:
                        found.append(f'http://{ip}:{port}/onvif/device_service')
                    return
            except OSError:
                pass

    threads = [threading.Thread(target=_probe, args=(i,), daemon=True) for i in range(1, 255)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=connect_timeout + 0.5)
    return found


def _subnet_onvif_scan(onvif_ports: tuple = (8000, 80), connect_timeout: float = 0.5) -> list:
    """Fallback : scan TCP parallèle du /24 local sur les ports ONVIF courants.
    Utilisé quand WS-Discovery ne retourne rien (Reolink derrière switch, IGMP absent…).
    Deux passages si le premier ne trouve rien : le tout premier scan peut échouer sur
    des IP dont l'entrée ARP est froide (le connect() attend la résolution ARP en plus
    du délai réseau, dépassant parfois connect_timeout) — observé en pratique : le
    scan échouait au 1er clic sur l'app et réussissait au 2e. Le premier passage
    réchauffe le cache ARP pour toutes les IP actives du réseau, donc un second passage
    immédiat est quasi instantané et beaucoup plus fiable, sans que l'utilisateur ait à
    recliquer manuellement."""
    my_ip = _local_ipv4()
    if not my_ip:
        warn('[onvif-scan] subnet-scan: impossible de déterminer l\'IP locale')
        return []

    base = '.'.join(my_ip.split('.')[:3])
    log(f'[onvif-scan] Fallback subnet scan {base}.1-254 sur ports {onvif_ports}')
    found = _subnet_onvif_scan_pass(base, onvif_ports, connect_timeout)
    if not found:
        log('[onvif-scan] 1er passage vide — nouveau passage (cache ARP réchauffé)')
        found = _subnet_onvif_scan_pass(base, onvif_ports, connect_timeout)
    return found


def _onvif_soap(url: str, body: str, timeout: float = 4.0, header: str = '') -> str:
    """Appel SOAP ONVIF. GetDeviceInfo/GetCapabilities répondent en clair ; les
    commandes qui changent un réglage (PTZ, Imaging) exigent en général le header
    WS-Security ci-dessous (cf. _onvif_ws_security_header) — sinon 401/SOAP Fault."""
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        + (f'<s:Header>{header}</s:Header>' if header else '')
        + f'<s:Body>{body}</s:Body>'
        '</s:Envelope>'
    )
    r = requests.post(
        url, data=envelope.encode('utf-8'),
        headers={'Content-Type': 'application/soap+xml; charset=utf-8'},
        timeout=timeout,
    )
    return r.text


def _onvif_ws_security_header(username: str, password: str) -> str:
    """UsernameToken WS-Security (PasswordDigest) — méthode d'authentification standard
    ONVIF pour les commandes qui modifient un réglage caméra (PTZ, vision nocturne...)."""
    nonce = os.urandom(16)
    created = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    digest = base64.b64encode(hashlib.sha1(nonce + created.encode() + password.encode()).digest()).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    return (
        '<Security xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        '<UsernameToken>'
        f'<Username>{username}</Username>'
        '<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
        f'{digest}</Password>'
        '<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
        f'{nonce_b64}</Nonce>'
        f'<wsu:Created>{created}</wsu:Created>'
        '</UsernameToken>'
        '</Security>'
    )


def _onvif_credentials_from_rtsp(rtsp_url: str) -> tuple:
    """Extrait (ip, username, password) d'une URL RTSP déjà stockée — les commandes
    ONVIF authentifiées utilisent en général les mêmes identifiants que le flux vidéo
    chez le matériel grand public (hypothèse, pas garantie par le standard)."""
    m = re.match(r'rtsp://(?:([^:@]*):([^@]*)@)?([^:/]+)', rtsp_url)
    if not m:
        raise ValueError('URL RTSP invalide')
    return m.group(3), (m.group(1) or ''), (m.group(2) or '')


def _scan_onvif_cameras(timeout: float = 12.0) -> list:
    """Retourne la liste des caméras ONVIF détectées sur le LAN avec leur URL RTSP."""
    xaddrs = _ws_discover(timeout=5.0)
    if not xaddrs:
        log('[onvif-scan] WS-Discovery: 0 résultat — fallback scan subnet direct')
        xaddrs = _subnet_onvif_scan()
    log(f'[onvif-scan] {len(xaddrs)} caméra(s) ONVIF détectée(s)')
    results = []
    for xaddr in xaddrs:
        ip_m = re.search(r'https?://([^:/]+)', xaddr)
        ip = ip_m.group(1) if ip_m else ''
        manufacturer = model = rtsp_url = ''
        onvif_confirmed = False  # True si au moins un appel ONVIF a répondu

        try:
            xml = _onvif_soap(
                xaddr,
                '<tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>',
                timeout=3.0,
            )
            manufacturer = _xml_text(xml, 'Manufacturer')
            model        = _xml_text(xml, 'Model')
            if manufacturer or model:
                onvif_confirmed = True
        except Exception as e:
            warn(f'[onvif-scan] GetDeviceInformation {ip}: {e}')

        media_url = ''
        try:
            xml = _onvif_soap(
                xaddr,
                '<tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
                '<tds:Category>Media</tds:Category>'
                '</tds:GetCapabilities>',
                timeout=3.0,
            )
            for xa in _xml_all(xml, 'XAddr'):
                if xa.startswith('http') and 'media' in xa.lower():
                    media_url = xa
                    break
            if not media_url:
                for xa in _xml_all(xml, 'XAddr'):
                    if xa.startswith('http'):
                        media_url = xa
                        break
            if media_url:
                onvif_confirmed = True
        except Exception as e:
            warn(f'[onvif-scan] GetCapabilities {ip}: {e}')

        if media_url:
            try:
                xml = _onvif_soap(
                    media_url,
                    '<trt:GetProfiles xmlns:trt="http://www.onvif.org/ver10/media/wsdl"/>',
                    timeout=3.0,
                )
                token = _xml_attr(xml, 'Profiles', 'token')
                if token:
                    xml2 = _onvif_soap(
                        media_url,
                        '<trt:GetStreamUri xmlns:trt="http://www.onvif.org/ver10/media/wsdl"'
                        ' xmlns:tt="http://www.onvif.org/ver10/schema">'
                        '<trt:StreamSetup>'
                        '<tt:Stream>RTP-Unicast</tt:Stream>'
                        '<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>'
                        '</trt:StreamSetup>'
                        f'<trt:ProfileToken>{token}</trt:ProfileToken>'
                        '</trt:GetStreamUri>',
                        timeout=3.0,
                    )
                    rtsp_url = _xml_text(xml2, 'Uri')
            except Exception as e:
                warn(f'[onvif-scan] GetStreamUri {ip}: {e}')

        # Ignorer les appareils non-ONVIF (routeur, NAS, etc. avec port 80/8000 ouvert)
        if not onvif_confirmed:
            warn(f'[onvif-scan] {ip} : port ouvert mais pas de réponse ONVIF — ignoré')
            continue

        if not rtsp_url:
            rtsp_url = _rtsp_fallback(manufacturer, ip)

        results.append({
            'ip':           ip,
            'manufacturer': manufacturer,
            'model':        model,
            'name':         (f'{manufacturer} {model}'.strip()) or f'Caméra {ip}',
            'rtspUrl':      rtsp_url,
            'capabilities': _onvif_capabilities_from_xaddr(xaddr),
        })
    log(f'[onvif-scan] {len(results)} caméra(s) ONVIF confirmée(s) sur {len(xaddrs)} IP(s) scannée(s)')
    return results


# ── Capacités caméra (PTZ, audio bidirectionnel, sortie relais) — pré-remplissage,
# jamais activation automatique : le matériel grand public annonce parfois des
# capacités ONVIF qu'il ne supporte pas réellement (cf. lib/cameras/capabilities.ts
# côté web), donc ceci ne fait que pré-cocher des cases dans le formulaire d'ajout —
# l'installateur confirme.

def _onvif_deviceio_xaddr(device_xaddr: str, timeout: float = 3.0) -> str:
    """Localise le service DeviceIO (sorties relais — souvent câblées sur une sirène ou
    un projecteur côté matériel grand public) via GetServices : contrairement à
    PTZ/Media/Imaging, DeviceIO n'est pas une "Category" du GetCapabilities catégorisé
    ci-dessous, il faut la liste complète des services exposés par la caméra."""
    try:
        xml = _onvif_soap(
            device_xaddr,
            '<tds:GetServices xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            '<tds:IncludeCapability>false</tds:IncludeCapability>'
            '</tds:GetServices>',
            timeout=timeout,
        )
    except Exception:
        return ''
    for xa in _xml_all(xml, 'XAddr'):
        if 'deviceio' in xa.lower():
            return xa
    return ''


def _onvif_has_relay_output(device_xaddr: str, timeout: float = 3.0) -> bool:
    """True si la caméra expose au moins une sortie relais ONVIF pilotable. Pas de
    service ONVIF standard "Sirène" — DeviceIO/RelayOutput est le seul mécanisme
    générique, et rien ne dit qu'il est câblé sur une sirène plutôt qu'un projecteur
    ou une gâche électrique : signal best-effort, pas une garantie de sémantique."""
    deviceio_xaddr = _onvif_deviceio_xaddr(device_xaddr, timeout=timeout)
    if not deviceio_xaddr:
        return False
    try:
        xml = _onvif_soap(
            deviceio_xaddr,
            '<tmd:GetRelayOutputs xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl"/>',
            timeout=timeout,
        )
    except Exception:
        return False
    return bool(_xml_attr(xml, 'RelayOutputs', 'token'))


def _onvif_capabilities_from_xaddr(device_xaddr: str, timeout: float = 3.0) -> list:
    """Détecte PTZ/zoom (service PTZ présent dans GetCapabilities), talk/speaker
    (AudioOutputConfiguration dans un profil média) et siren (sortie relais DeviceIO)
    à partir d'un device_service ONVIF déjà connu. Best-effort : liste vide si la
    caméra ne répond pas ou n'expose rien."""
    caps = set()
    try:
        xml = _onvif_soap(
            device_xaddr,
            '<tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>',
            timeout=timeout,
        )
    except Exception:
        return []

    if _xml_has_tag(xml, 'PTZ'):
        caps.add('ptz')
        caps.add('zoom')

    media_url = ''
    for xa in _xml_all(xml, 'XAddr'):
        if xa.startswith('http') and 'media' in xa.lower():
            media_url = xa
            break
    if media_url:
        try:
            pxml = _onvif_soap(
                media_url,
                '<trt:GetProfiles xmlns:trt="http://www.onvif.org/ver10/media/wsdl"/>',
                timeout=timeout,
            )
            if _xml_has_tag(pxml, 'AudioOutputConfiguration'):
                caps.add('talk')
                caps.add('speaker')
        except Exception:
            pass

    if _onvif_has_relay_output(device_xaddr, timeout=timeout):
        caps.add('siren')

    return sorted(caps)


def _probe_onvif_capabilities_by_ip(ip: str, timeout: float = 3.0) -> list:
    """Variante pour l'ajout manuel (IP connue, device_service ONVIF pas encore
    localisé) — essaie les ports ONVIF courants avant d'abandonner silencieusement."""
    for port in (8000, 80):
        caps = _onvif_capabilities_from_xaddr(f'http://{ip}:{port}/onvif/device_service', timeout=timeout)
        if caps:
            return caps
    return []


def _safe_probe_capabilities(ip: str) -> list:
    """Ne doit jamais faire échouer le test de connexion caméra (résultat principal)
    si la sonde ONVIF de capacités plante ou traîne — pure best-effort."""
    try:
        return _probe_onvif_capabilities_by_ip(ip)
    except Exception as e:
        warn(f'[onvif-capabilities] {ip}: {e}')
        return []


# ── Commandes ONVIF authentifiées (PTZ, vision nocturne) ────────────────────────
# Contrairement à la détection de capacités (lecture seule, non authentifiée), ces
# commandes modifient un réglage caméra et exigent en général le WS-Security
# UsernameToken ci-dessus. Résolution des services à chaque appel (pas de cache —
# fréquence d'appel faible, un clic utilisateur, la latence supplémentaire est
# négligeable en pratique).

def _onvif_locate_services(ip: str, timeout: float = 3.0) -> dict:
    """Retrouve device_xaddr/ptz_xaddr/media_xaddr/imaging_xaddr/profile_token/
    video_source_token pour une caméra — lève une exception explicite si le service
    demandé n'existe pas (PTZ/Imaging non supportés) plutôt que d'échouer en silence."""
    device_xaddr = ''
    xml = ''
    for port in (8000, 80):
        candidate = f'http://{ip}:{port}/onvif/device_service'
        try:
            xml = _onvif_soap(candidate, '<tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>', timeout=timeout)
        except Exception:
            continue
        if xml:
            device_xaddr = candidate
            break
    if not device_xaddr:
        raise RuntimeError('caméra injoignable en ONVIF')

    services = {'device_xaddr': device_xaddr, 'ptz_xaddr': '', 'media_xaddr': '', 'imaging_xaddr': ''}
    for xa in _xml_all(xml, 'XAddr'):
        low = xa.lower()
        if 'ptz' in low: services['ptz_xaddr'] = xa
        elif 'media' in low: services['media_xaddr'] = xa
        elif 'imaging' in low: services['imaging_xaddr'] = xa
    if not services['media_xaddr']:
        raise RuntimeError('service Media ONVIF introuvable')

    pxml = _onvif_soap(services['media_xaddr'], '<trt:GetProfiles xmlns:trt="http://www.onvif.org/ver10/media/wsdl"/>', timeout=timeout)
    services['profile_token'] = _xml_attr(pxml, 'Profiles', 'token')
    if not services['profile_token']:
        raise RuntimeError('aucun profil média ONVIF trouvé')

    try:
        vxml = _onvif_soap(services['media_xaddr'], '<trt:GetVideoSources xmlns:trt="http://www.onvif.org/ver10/media/wsdl"/>', timeout=timeout)
        services['video_source_token'] = _xml_attr(vxml, 'VideoSources', 'token')
    except Exception:
        services['video_source_token'] = ''

    services['deviceio_xaddr'] = _onvif_deviceio_xaddr(device_xaddr, timeout=timeout)
    services['relay_token'] = ''
    if services['deviceio_xaddr']:
        try:
            rxml = _onvif_soap(services['deviceio_xaddr'], '<tmd:GetRelayOutputs xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl"/>', timeout=timeout)
            services['relay_token'] = _xml_attr(rxml, 'RelayOutputs', 'token')
        except Exception:
            pass

    return services


# ── PTZ ─────────────────────────────────────────────────────────────────────
# Contrôleur PTZ natif de Frigate (topic MQTT frigate/<camera>/ptz), PAS l'ONVIF
# direct (essayé en v2.9.8-v2.9.15, abandonné) : la raison du premier abandon en
# v2.9.8 — Frigate ne lisait jamais /homeassistant/frigate.yml (CONFIG_FILE absent de
# son propre config.yaml d'add-on) — est corrigée depuis (fork de l'add-on Frigate,
# cf. FRIGATE_REPO/FRIGATE_SLUG, HANDOFF §55-§57). Confirmé en conditions réelles le
# 2026-07-22 : Frigate lit désormais réellement mqtt.enabled: true et onvif: par
# caméra (logs frigate.camera.maintainer "Camera processor started"), donc son
# contrôleur PTZ natif reçoit bien les messages sur ce topic. Mapping direction (API
# web, cf. lib/ha/command.ts PtzDirection) → commande du contrôleur ONVIF PTZ natif
# de Frigate (frigate.ptz.onvif.OnvifCommandEnum).
_FRIGATE_PTZ_COMMANDS = {
    'up': 'move_up', 'down': 'move_down', 'left': 'move_left', 'right': 'move_right',
    'zoom_in': 'zoom_in', 'zoom_out': 'zoom_out', 'stop': 'stop',
}


def _onvif_set_night_vision(ip: str, username: str, password: str, mode: str) -> tuple:
    """mode: on/off/auto → IrCutFilter ON/OFF/AUTO."""
    ir_mode = {'on': 'ON', 'off': 'OFF', 'auto': 'AUTO'}.get(mode)
    if not ir_mode:
        return False, f'Mode inconnu : {mode}'
    services = _onvif_locate_services(ip)
    if not services['imaging_xaddr'] or not services.get('video_source_token'):
        return False, "Cette caméra ne propose pas de réglage vision nocturne en ONVIF"
    header = _onvif_ws_security_header(username, password)
    body = (
        '<timg:SetImagingSettings xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl">'
        f'<timg:VideoSourceToken>{services["video_source_token"]}</timg:VideoSourceToken>'
        '<timg:ImagingSettings>'
        f'<tt:IrCutFilter xmlns:tt="http://www.onvif.org/ver10/schema">{ir_mode}</tt:IrCutFilter>'
        '</timg:ImagingSettings>'
        '</timg:SetImagingSettings>'
    )
    xml = _onvif_soap(services['imaging_xaddr'], body, header=header)
    if 'Fault' in xml:
        return False, _xml_text(xml, 'Text') or 'La caméra a refusé le réglage vision nocturne'
    return True, 'ok'


def _onvif_set_relay_output(ip: str, username: str, password: str, active: bool) -> tuple:
    """Active/désactive la première sortie relais ONVIF trouvée. Pas de service ONVIF
    standard "Sirène" : DeviceIO/RelayOutput est le seul mécanisme générique, câblé côté
    matériel sur une sirène, un projecteur ou une gâche selon le modèle — la capacité
    'siren' déclarée par l'installateur (cf. lib/cameras/capabilities.ts) porte la
    sémantique, cette fonction ne fait qu'actionner le relais détecté."""
    services = _onvif_locate_services(ip)
    if not services.get('deviceio_xaddr') or not services.get('relay_token'):
        return False, "Cette caméra ne propose pas de sortie relais (sirène) en ONVIF"
    header = _onvif_ws_security_header(username, password)
    state = 'active' if active else 'inactive'
    body = (
        '<tmd:SetRelayOutputState xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl">'
        f'<tmd:RelayOutputToken>{services["relay_token"]}</tmd:RelayOutputToken>'
        f'<tmd:LogicalState>{state}</tmd:LogicalState>'
        '</tmd:SetRelayOutputState>'
    )
    xml = _onvif_soap(services['deviceio_xaddr'], body, header=header)
    if 'Fault' in xml:
        return False, _xml_text(xml, 'Text') or 'La caméra a refusé la commande sirène'
    return True, 'ok'


class _CommandHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log(f"[cmd-server] {self.address_string()} — {fmt % args}")

    def _respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reject(self, code, msg):
        self._respond(code, {"error": msg})

    def _ok(self, data=None):
        self._respond(200, data or {"ok": True})

    def do_POST(self):
        if not INGEST_SECRET:
            return self._reject(503, "ingest_secret non configuré")
        if self.headers.get("X-Site-Secret") != INGEST_SECRET:
            return self._reject(401, "Non autorisé")

        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw.decode() or "{}")
        except Exception:
            return self._reject(400, "JSON invalide")

        try:
            # Le tunnel Cloudflare route ce port via le préfixe /addon (hostname unique
            # par site, partagé avec les caméras — cf. lib/cloudflare/tunnel.ts côté Vercel).
            route = self.path[len("/addon"):] if self.path.startswith("/addon") else self.path
            handlers = {
                "/cmd":                  self._handle_cmd,
                "/matter/commission":    self._handle_matter_commission,
                "/zigbee/permit-join":   self._handle_permit_join,
                "/zigbee/remove-device": self._handle_remove_device,
                "/zigbee/set-attribute": self._handle_set_attribute,
                "/ha-command":           self._handle_ha_command_route,
                "/camera/configure":     self._handle_camera_configure_route,
                "/camera/test":          self._handle_camera_test_route,
                "/camera/ptz":           self._handle_camera_ptz_route,
                "/camera/night-vision":  self._handle_camera_night_vision_route,
                "/camera/siren":         self._handle_camera_siren_route,
                "/sync-now":             self._handle_sync_now,
            }
            handler = handlers.get(route)
            if not handler:
                return self._reject(404, "Route inconnue")
            handler(data)
        except Exception as e:
            warn(f"[cmd-server] {self.path}: {e}")
            self._reject(500, str(e))

    def _handle_cmd(self, data):
        service = data.get("service", "")
        entity_id = data.get("entity_id")
        extra = data.get("data") or {}
        if "." not in service:
            return self._reject(400, "service invalide")
        domain, verb = service.split(".", 1)
        if verb not in ALLOWED_SERVICES.get(domain, set()):
            return self._reject(403, f"service non autorisé: {service}")
        payload = dict(extra)
        if entity_id:
            payload["entity_id"] = entity_id
        r = ha_post(f"/services/{domain}/{verb}", payload)
        if r.ok:
            self._ok()
        else:
            self._reject(502, f"HA {r.status_code}: {r.text[:200]}")

    def _handle_matter_commission(self, data):
        request_id = data.get("requestId") or secrets.token_hex(8)
        code = data.get("code", "")
        if not code:
            return self._reject(400, "code manquant")
        handle_matter_commission(request_id, code)
        self._ok({"requestId": request_id, "status": "commissioning"})

    def _handle_permit_join(self, data):
        enable = data.get("enable", True)
        duration = data.get("duration", 60)
        if not _local_client:
            return self._reject(503, "Mosquitto local non connecté")
        _local_client.publish(
            "zigbee2mqtt/bridge/request/permit_join",
            json.dumps({"value": bool(enable), "time": duration if enable else 0}),
            qos=1,
        )
        self._ok()

    def _handle_remove_device(self, data):
        ieee = data.get("ieee_address")
        if not ieee:
            return self._reject(400, "ieee_address manquant")
        if not _local_client:
            return self._reject(503, "Mosquitto local non connecté")
        _local_client.publish(
            "zigbee2mqtt/bridge/request/device/remove",
            json.dumps({"id": ieee, "force": False}),
            qos=1,
        )
        self._ok()

    def _handle_set_attribute(self, data):
        friendly_name = data.get("friendlyName")
        attribute = data.get("attribute")
        if not friendly_name or not attribute:
            return self._reject(400, "friendlyName et attribute requis")
        if not _local_client:
            return self._reject(503, "Mosquitto local non connecté")
        _local_client.publish(
            f"zigbee2mqtt/{friendly_name}/set",
            json.dumps({attribute: data.get("value")}),
            qos=1,
        )
        self._ok()

    def _handle_ha_command_route(self, data):
        _handle_ha_command(json.dumps(data).encode())
        self._ok()

    def _handle_camera_configure_route(self, data):
        action = data.get("action", "add")
        stream_name = data.get("streamName")
        if not stream_name:
            return self._reject(400, "streamName manquant")
        ok = handle_camera_configure(action, stream_name, data.get("rtspUrl"), bool(data.get("hasTalk")))
        if ok:
            self._ok()
        else:
            self._reject(502, "Échec de configuration Frigate/go2rtc — voir les logs de l'add-on")

    def _handle_camera_test_route(self, data):
        rtsp_url = data.get("rtspUrl")
        if rtsp_url:
            # Mode "URL manuelle" — l'utilisateur a fourni l'URL exacte, aucune devinette.
            ok, detail = _go2rtc_test_stream(rtsp_url)
            ip_m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', rtsp_url)
            caps = _safe_probe_capabilities(ip_m.group(1)) if ip_m else []
            return self._ok({"ok": ok, "detail": detail, "correctedUrl": None, "detectedCapabilities": caps})

        ip = data.get("ip")
        password = data.get("password")
        if not ip or password is None:
            return self._reject(400, "ip et password requis (ou rtspUrl)")
        manufacturer = data.get("manufacturer") or ""
        ok, detail, url = _test_camera_by_brand(ip, password, manufacturer)
        self._ok({"ok": ok, "detail": detail, "correctedUrl": url, "detectedCapabilities": _safe_probe_capabilities(ip)})

    def _camera_onvif_credentials(self, stream_name):
        """Retrouve (ip, username, password) à partir du streamName — réutilise les
        identifiants déjà stockés pour le flux vidéo (cf. _onvif_credentials_from_rtsp)."""
        rtsp_url = _cameras.get(stream_name)
        if not rtsp_url:
            return None
        try:
            return _onvif_credentials_from_rtsp(rtsp_url)
        except Exception:
            return None

    def _handle_camera_ptz_route(self, data):
        """Relaie la commande au contrôleur ONVIF PTZ natif de Frigate (topic MQTT
        frigate/<camera>/ptz, cf. _generate_frigate_yaml/_FRIGATE_PTZ_COMMANDS) — Frigate
        maintient déjà cette implémentation, pas de raison de la dupliquer. Publication
        MQTT fire-and-forget : Frigate ne renvoie pas d'accusé de réception sur ce
        topic, donc "ok" ici confirme l'envoi, pas l'exécution réelle par la caméra."""
        stream_name = data.get("streamName")
        direction = data.get("direction")
        if not stream_name or not direction:
            return self._reject(400, "streamName et direction requis")
        if stream_name not in _cameras:
            return self._reject(404, "Caméra inconnue")
        command = _FRIGATE_PTZ_COMMANDS.get(direction)
        if not command:
            return self._ok({"ok": False, "detail": f"Direction inconnue : {direction}"})
        if not _local_client:
            return self._ok({"ok": False, "detail": "Mosquitto local non connecté"})
        _local_client.publish(f"frigate/{stream_name}/ptz", command, qos=1)
        self._ok({"ok": True, "detail": "ok"})

    def _handle_camera_night_vision_route(self, data):
        stream_name = data.get("streamName")
        mode = data.get("mode")
        if not stream_name or not mode:
            return self._reject(400, "streamName et mode requis")
        creds = self._camera_onvif_credentials(stream_name)
        if not creds:
            return self._reject(404, "Caméra inconnue")
        ip, username, password = creds
        try:
            ok, detail = _onvif_set_night_vision(ip, username, password, mode)
        except Exception as e:
            warn(f"[camera-night-vision] {stream_name} ({mode}): {e}")
            return self._ok({"ok": False, "detail": str(e)})
        self._ok({"ok": ok, "detail": detail})

    def _handle_camera_siren_route(self, data):
        stream_name = data.get("streamName")
        active = data.get("active")
        if not stream_name or active is None:
            return self._reject(400, "streamName et active requis")
        creds = self._camera_onvif_credentials(stream_name)
        if not creds:
            return self._reject(404, "Caméra inconnue")
        ip, username, password = creds
        try:
            ok, detail = _onvif_set_relay_output(ip, username, password, bool(active))
        except Exception as e:
            warn(f"[camera-siren] {stream_name}: {e}")
            return self._ok({"ok": False, "detail": str(e)})
        self._ok({"ok": ok, "detail": detail})

    def _handle_sync_now(self, data):
        """Déclenche un cycle de _sync_all_to_ha() immédiat (pièces/scènes/automations
        + republication bridge/devices Z2M → réconciliation devices-sync) au lieu
        d'attendre le prochain cycle périodique (jusqu'à 60s) — bouton "Sync HA"."""
        _sync_requested.set()
        self._ok()

    def do_GET(self):
        if not INGEST_SECRET:
            return self._reject(503, "ingest_secret non configuré")
        if self.headers.get("X-Site-Secret") != INGEST_SECRET:
            return self._reject(401, "Non autorisé")
        route = self.path[len("/addon"):] if self.path.startswith("/addon") else self.path
        route = route.split("?")[0]
        if route == "/camera/scan":
            self._handle_camera_scan()
        else:
            self._reject(404, "Route inconnue")

    def _handle_camera_scan(self):
        try:
            cameras = _scan_onvif_cameras(timeout=7.0)
            self._ok({"cameras": cameras})
        except Exception as e:
            warn(f"[camera-scan] {e}")
            self._reject(500, str(e))


class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    # socketserver.ThreadingTCPServer laisse allow_reuse_address=False par défaut
    # (contrairement à http.server.HTTPServer) — un redémarrage rapide de l'addon
    # (supervisor arrête l'ancien process, démarre le nouveau) peut laisser le socket
    # 127.0.0.1:8098 précédent en TIME_WAIT côté noyau, faisant échouer le bind()
    # suivant avec "Address already in use" — observé en réel le 2026-07-22, tout le
    # serveur de commandes restait indisponible (PTZ, scènes, devices, tout).
    allow_reuse_address = True


def run_command_server():
    """Serveur HTTP local (127.0.0.1 uniquement) — exposé au monde via le tunnel
    Cloudflare existant (ingress ha-{slug}.domoticium.fr → 127.0.0.1:COMMAND_PORT)."""
    if not INGEST_SECRET:
        warn("[cmd-server] ingest_secret non configuré — serveur de commandes désactivé")
        return
    try:
        httpd = _ReusableTCPServer(("127.0.0.1", COMMAND_PORT), _CommandHandler)
        httpd.daemon_threads = True
        log(f"[cmd-server] ✓ Serveur de commandes actif sur 127.0.0.1:{COMMAND_PORT}")
        httpd.serve_forever()
    except Exception as e:
        warn(f"[cmd-server] Erreur fatale : {e}")


def _turn_refresh_loop():
    """Rafraîchit les identifiants TURN Cloudflare avant leur expiration (48h max) et
    redémarre Frigate pour que go2rtc les recharge. Nouvel essai dans 5 min si le
    dernier fetch a échoué (repli STUN encore actif), sinon attend
    _TURN_REFRESH_INTERVAL (24h) avant le prochain rafraîchissement.
    Un échec de fetch (None) ne touche JAMAIS _turn_ice_servers ni ne redémarre
    Frigate — les identifiants en place restent valides jusqu'à expiration réelle.
    Sans cette garde, un simple hoquet réseau/quota Vercel faisait passer un vrai
    TURN à un repli STUN, vu comme un "changement" → restart Frigate inutile →
    coupure caméra réelle → fausse alerte "hors ligne" envoyée au client (bug
    identifié le 2026-07-19 après 2 fausses alertes en une nuit)."""
    global _turn_ice_servers
    while True:
        time.sleep(_TURN_REFRESH_INTERVAL if _has_turn(_turn_ice_servers) else 300)
        servers = _fetch_turn_ice_servers()
        if servers is None:
            warn("[webrtc] échec du rafraîchissement TURN — identifiants actuels conservés")
            continue
        if servers != _turn_ice_servers:
            _turn_ice_servers = servers
            log("[webrtc] Identifiants TURN mis à jour — rafraîchissement config Frigate")
            write_frigate_config()
            restart_frigate()


def run_bridge():
    _load_cameras()
    global _turn_ice_servers
    # synchrone — requis avant la 1ère écriture frigate.yml ; repli STUN local si le
    # 1er fetch échoue (pas de restart en jeu ici, juste la valeur initiale)
    _turn_ice_servers = _fetch_turn_ice_servers() or [{"urls": ["stun:stun.cloudflare.com:3478"]}]
    start_cloudflared()
    threading.Thread(target=_remove_legacy_heartbeat_automation_once, daemon=True).start()
    threading.Thread(target=_remove_legacy_rest_commands_once, daemon=True).start()
    threading.Thread(target=_enable_watchdogs_once, daemon=True).start()
    threading.Thread(target=_ensure_frigate,       daemon=True).start()
    threading.Thread(target=_turn_refresh_loop,    daemon=True).start()
    threading.Thread(target=_ensure_matter_server, daemon=True).start()
    threading.Thread(target=_check_and_fix_mqtt_broker, daemon=True).start()
    threading.Thread(target=_heartbeat_loop, daemon=True).start()
    threading.Thread(target=_ha_sync_loop,   daemon=True).start()
    threading.Thread(target=run_local_bridge, daemon=True).start()
    # Bridge HA WebSocket → Supabase (ingest) : seul canal d'état, remplace EMQX
    threading.Thread(target=run_ha_ws_bridge, daemon=True).start()
    # Flush du batch d'états toutes les 2.5s (réduit les appels Vercel)
    threading.Thread(target=_flush_state_batch,      daemon=True).start()
    # Watchdog caméras : sonde go2rtc toutes les 60s, deltas envoyés dans le batch
    threading.Thread(target=_run_camera_watchdog,    daemon=True).start()

    # Serveur de commandes — bloquant, tourne dans le thread principal
    run_command_server()


# ══════════════════════════════════════════════════════════════════════════════
# UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

def _dict_to_yaml(d, indent=0):
    """Sérialisation YAML minimale (pas de PyYAML nécessaire)."""
    lines = []
    pad = "  " * indent
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{pad}{k}:")
            lines.append(_dict_to_yaml(v, indent + 1))
        elif isinstance(v, bool):
            lines.append(f"{pad}{k}: {'true' if v else 'false'}")
        elif isinstance(v, int):
            lines.append(f"{pad}{k}: {v}")
        elif v is None:
            lines.append(f"{pad}{k}:")
        else:
            escaped = str(v).replace('\\', '\\\\').replace('"', '\\"')
            lines.append(f'{pad}{k}: "{escaped}"')
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    log("══════════════════════════════════════════════")
    log("  DÉMARRAGE DOMOTICIUM")
    log("══════════════════════════════════════════════")

    # Écrire la config Frigate AVANT tout le reste.
    # Le prepare script Frigate copie /homeassistant/frigate.yml → addon_config privé
    # (/config/config.yml dans le conteneur Frigate) si ce dernier n'existe pas encore.
    # La config contient version:"0.18-0" → toute migration Frigate est skippée.
    _load_cameras()
    write_frigate_config()

    if FORCE_SETUP:
        log("force_setup activé — réinitialisation complète de la configuration")
        if os.path.exists(SETUP_DONE):
            os.remove(SETUP_DONE)
    if not os.path.exists(SETUP_DONE):
        run_setup()
    else:
        log("Déjà configuré — démarrage du service.")
    run_bridge()
