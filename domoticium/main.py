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
import base64, http.server, json, os, re, secrets, socket, socketserver, struct, subprocess, sys, threading, time
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

Z2M_REPO       = "https://github.com/zigbee2mqtt/hassio-zigbee2mqtt"
Z2M_SLUG       = "45df7312_zigbee2mqtt"
MATTER_SLUG    = "core_matter_server"
THREAD_SLUG    = "core_openthread_border_router"
FRIGATE_REPO   = "https://github.com/blakeblackshear/frigate-hass-addons"
FRIGATE_SLUG   = "ccab4aaf_frigate"
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

# Client MQTT local (Mosquitto, Z2M ↔ HA) — plus de client cloud, EMQX est retiré.
_local_client: mqtt.Client | None = None


def log(msg):  print(f"[domoticium] {msg}", flush=True)
def warn(msg): print(f"[domoticium] ⚠ {msg}", file=sys.stderr, flush=True)

def sup_get(path):
    return requests.get(f"{SUP}{path}", headers=HDRS, timeout=15)

def sup_post(path, data=None):
    return requests.post(f"{SUP}{path}", headers=HDRS, json=data or {}, timeout=60)

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

def _save_cameras():
    with open(CAMERAS_FILE, "w") as f:
        json.dump(_cameras, f)


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
    """Teste si go2rtc écoute sur :1984. Retourne True si opérationnel."""
    try:
        return requests.get("http://127.0.0.1:1984/api", timeout=3).status_code < 500
    except Exception:
        return False


def _wait_frigate_ready(max_attempts: int = 36) -> bool:
    """Attend jusqu'à 3 min que go2rtc soit disponible. Retourne True si succès."""
    log("Attente que go2rtc soit disponible sur :1984…")
    for i in range(max_attempts):
        time.sleep(5)
        if _frigate_go2rtc_ready():
            log(f"✓ Frigate go2rtc opérationnel sur :1984 (~{(i+1)*5}s)")
            return True
        if i % 6 == 5:
            log(f"  … toujours en attente ({(i+1)*5}s)")
    warn("go2rtc pas disponible après 3 min")
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
    r = sup_post(f"/addons/{FRIGATE_SLUG}/options", {"network": {"1984/tcp": 1984}})
    mark = "✓" if r.ok else f"✗ {r.status_code} {r.text[:80]}"
    log(f"{mark} Frigate port 1984 exposé")

    _load_cameras()
    write_frigate_config()

    r = sup_post(f"/addons/{FRIGATE_SLUG}/restart")
    if not r.ok:
        warn(f"✗ {r.status_code} Frigate restart : {r.text[:150]}")
        return False

    return _wait_frigate_ready()


def install_frigate():
    log("── Frigate NVR ──────────────────────────────")

    # 1. Nettoyer un go2rtc.yml résiduel de l'ancienne architecture standalone
    old_go2rtc = "/homeassistant/go2rtc.yml"
    if os.path.exists(old_go2rtc):
        os.rename(old_go2rtc, f"{old_go2rtc}.bak")
        log("⚠ Ancien go2rtc.yml archivé → go2rtc.yml.bak (utilise le go2rtc embarqué dans Frigate)")

    # 2. Ajouter le dépôt
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

    # 3. Installer si nécessaire
    if not _is_addon_installed(FRIGATE_SLUG):
        log("Installation de Frigate (peut prendre 2-3 min)…")
        r = sup_post(f"/store/addons/{FRIGATE_SLUG}/install")
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

    # Écrire la config AVANT la désinstallation : elle persiste sur le disque
    # et Frigate la lira lors de l'auto-démarrage post-réinstallation.
    _load_cameras()
    write_frigate_config()

    sup_post(f"/addons/{FRIGATE_SLUG}/uninstall")
    log("Désinstallation Frigate…")
    time.sleep(20)

    r = sup_post(f"/store/addons/{FRIGATE_SLUG}/install")
    if not r.ok:
        warn(f"✗ {r.status_code} Réinstallation Frigate impossible : {r.text[:100]}")
        return
    log("✓ Frigate réinstallé — reconfiguration…")
    time.sleep(30)

    if _configure_frigate_and_start():
        return
    warn("Frigate toujours inopérationnel après réinstallation — vérifier les logs Frigate dans HA")


def write_frigate_config():
    """Génère /homeassistant/frigate.yml depuis le registre des caméras."""
    lines = [
        "# Généré par Domoticium — ne pas modifier manuellement",
        "mqtt:",
        "  enabled: false",
        "",
    ]

    if _cameras:
        lines.append("cameras:")
        for name, rtsp_url in _cameras.items():
            lines += [
                f"  {name}:",
                "    ffmpeg:",
                "      inputs:",
                f"        - path: {rtsp_url}",
                "          roles:",
                "            - detect",
                "    detect:",
                "      enabled: false",
                "    record:",
                "      enabled: false",
            ]
    # Intentionnellement PAS de clé "cameras:" quand vide.
    # La migration Frigate 0.13→0.14 crashe si "cameras: {}" (parsé comme None).
    # Sans la clé, config.get("cameras", {}) retourne {} et la migration réussit.

    content = "\n".join(lines) + "\n"
    with open("/homeassistant/frigate.yml", "w") as fh:
        fh.write(content)

    log(f"✓ frigate.yml mis à jour ({len(_cameras)} caméra(s))")
    log(f"[frigate.yml]\n{content}")


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


def create_automations():
    log("── Automations ──────────────────────────────")

    # domoticium_state_stream et domoticium_command_handler (MQTT/EMQX) retirées —
    # remplacées par run_ha_ws_bridge() (état) et le serveur de commandes HTTP (commandes).
    automations = [
        {
            "id": "domoticium_heartbeat",
            "alias": "Domoticium — Heartbeat",
            "description": "Notifie l'API toutes les 30 secondes",
            "mode": "single",
            "trigger": [{"platform": "time_pattern", "seconds": "/30"}],
            "action": [{"service": "rest_command.domoticium_heartbeat"}],
        },
        {
            "id": "domoticium_camera_status",
            "alias": "Domoticium — Camera Status Reporter",
            "description": "Notifie l'API quand une caméra change d'état",
            "mode": "parallel", "max": 10,
            "trigger": [{"platform": "event", "event_type": "state_changed"}],
            "condition": [
                {"condition": "template",
                 "value_template": "{{ trigger.event.data.entity_id.startswith('camera.') }}"},
                {"condition": "template",
                 "value_template": "{{ trigger.event.data.old_state is not none and trigger.event.data.new_state is not none }}"},
                {"condition": "template",
                 "value_template": "{{ trigger.event.data.old_state.state != trigger.event.data.new_state.state }}"},
            ],
            "action": [{"service": "rest_command.domoticium_camera_status", "data": {
                "ha_entity_id": "{{ trigger.event.data.entity_id }}",
                "online": "{{ trigger.event.data.new_state.state != 'unavailable' }}",
            }}],
        },
    ]

    for auto in automations:
        r = requests.post(f"{API}/config/automation/config/{auto['id']}",
                          headers=HDRS, json=auto, timeout=15)
        mark = "✓" if r.status_code in (200, 201) else f"✗ {r.status_code}"
        log(f"{mark} {auto['alias']}")

    ha_post("/services/automation/reload")


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


def write_rest_commands():
    log("── rest_commands ─────────────────────────────")
    creds = base64.b64encode(f"{PI_USER}:{PI_PASS}".encode()).decode()
    p = SITE_PREFIX

    # Le fichier NE doit PAS contenir la clé "rest_command:" — elle est dans configuration.yaml.
    # Format correct HA : configuration.yaml → "rest_command: !include domoticium_rest_commands.yaml"
    content = (
        "domoticium_camera_status:\n"
        f'  url: "{APP_URL}/api/webhooks/pi/camera-status"\n'
        "  method: POST\n"
        "  headers:\n"
        '    Content-Type: "application/json"\n'
        f'    Authorization: "Basic {creds}"\n'
        "  payload: "
        f"'{{\"siteId\":\"{p}\",\"haEntityId\":\"{{{{ ha_entity_id }}}}\",\"online\":{{{{ online }}}}}}'\n"
        '  content_type: "application/json"\n'
        "domoticium_heartbeat:\n"
        f'  url: "{APP_URL}/api/webhooks/pi/heartbeat"\n'
        "  method: POST\n"
        "  headers:\n"
        '    Content-Type: "application/json"\n'
        f'    Authorization: "Basic {creds}"\n'
        f"  payload: '{{\"siteId\":\"{p}\"}}'\n"
        '  content_type: "application/json"\n'
    )

    rest_file = "/homeassistant/domoticium_rest_commands.yaml"
    # Format correct : clé + include sur la même ligne
    new_include = "rest_command: !include domoticium_rest_commands.yaml"
    # Ancienne forme incorrecte (include nu) à migrer si présente
    old_include = "!include domoticium_rest_commands.yaml"
    main_cfg  = "/homeassistant/configuration.yaml"

    with open(rest_file, "w") as f:
        f.write(content)

    with open(main_cfg) as f:
        existing = f.read()

    if new_include not in existing:
        # Remplacer l'ancienne forme bare si présente, sinon ajouter en fin de fichier
        if old_include in existing:
            existing = existing.replace(old_include, new_include)
            with open(main_cfg, "w") as f:
                f.write(existing)
        else:
            with open(main_cfg, "a") as f:
                f.write(f"\n{new_include}\n")

    log("✓ rest_commands configuré")


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
    # install_frigate()  — désactivé temporairement : Matter d'abord, caméras ensuite
    create_automations()
    write_rest_commands()

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


def restart_frigate():
    """Redémarre Frigate en arrière-plan pour recharger frigate.yml."""
    def _do():
        time.sleep(1)
        r = sup_post(f"/addons/{FRIGATE_SLUG}/restart")
        mark = "✓" if r.ok else f"✗ {r.status_code}"
        log(f"{mark} Frigate redémarré")

    threading.Thread(target=_do, daemon=True).start()


def handle_camera_configure(action: str, stream_name: str, rtsp_url: str | None = None):
    """Ajoute ou supprime une caméra dans Frigate. Appelé par le serveur de commandes HTTP."""
    if action == "add":
        if not rtsp_url:
            raise ValueError("rtspUrl manquant")
        _cameras[stream_name] = rtsp_url
        _save_cameras()
        write_frigate_config()
        restart_frigate()
        log(f"✓ Caméra ajoutée : '{stream_name}' — Frigate redémarre")
    elif action == "remove":
        _cameras.pop(stream_name, None)
        _save_cameras()
        write_frigate_config()
        restart_frigate()
        log(f"✓ Caméra supprimée : '{stream_name}' — Frigate redémarre")


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


def _sync_matter_devices_to_app():
    """Réconciliation périodique Matter → Supabase (analogue à bridge/devices Zigbee).
    Envoie la liste COMPLÈTE des nodes commissionnés — le webhook réconcilie (upsert +
    suppression des devices absents), pas juste un ajout ponctuel."""
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
    try:
        auth = base64.b64encode(f"{PI_USER}:{PI_PASS}".encode()).decode()
        r = requests.post(
            f"{APP_URL}/api/webhooks/pi/devices-sync",
            json={"siteId": SITE_PREFIX, "source": "matter", "devices": devices_payload},
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
            timeout=30,
        )
        log(f"[devices-sync/matter] HTTP {r.status_code} — {len(devices_payload)} devices, réponse: {r.text[:200]}")
    except Exception as e:
        warn(f"[devices-sync/matter] {e}")


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


def _sync_areas_batch(rooms: list, devices: list):
    """Crée les areas manquantes et assigne les devices en une seule session WebSocket."""
    if not rooms and not devices:
        return

    ws_send, ws_recv, ws_close = _ha_ws_connect()
    if not ws_send:
        warn("[sync] Session WebSocket indisponible — sync areas/devices ignorée")
        return

    try:
        mid = [0]  # compteur de message mutable dans la closure

        def call(cmd_type, **params):
            mid[0] += 1
            ws_send({"id": mid[0], "type": cmd_type, **params})
            return ws_recv()

        # 1. Lire les areas HA existantes (une seule fois)
        res = call("config/area_registry/list")
        existing_areas: dict[str, str] = {}  # name → area_id
        if res and res.get("success"):
            for a in res.get("result", []):
                existing_areas[a.get("name", "")] = a.get("area_id", "")
        log(f"[sync] Areas HA existantes : {list(existing_areas)}")

        # 2. Lire le registre des DEVICES HA (plus fiable que entity_registry pour Z2M)
        # Les devices Z2M ont des identifiers comme ["mqtt", "zigbee2mqtt_0x8c8b48..."]
        # qui contiennent l'adresse IEEE — entity unique_id peut utiliser le friendly_name.
        res = call("config/device_registry/list")
        did_by_entity: dict[str, str] = {}  # entity_id → device_id (non utilisé ici)
        did_by_uid:    dict[str, str] = {}  # valeur identifier (contient ieee) → device_id
        if res and res.get("success"):
            for dev in res.get("result", []):
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
            log("[sync] ⚠ Device registry HA vide — Z2M discovery pas encore reçue par HA"
                " (sera réessayé au prochain cycle)")

        # 3. Créer les areas manquantes
        for room in rooms:
            name = room["name"]
            if name in existing_areas:
                continue  # déjà présente, rien à faire
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

        # 4. Assigner les devices à leurs areas
        for d in devices:
            ieee      = (d.get("ieee_address") or "").strip()
            entity_id = (d.get("ha_entity_id") or "").strip()
            area_name = (d.get("area_name")    or "").strip()
            area_id   = existing_areas.get(area_name) if area_name else None

            # Résoudre le device_id HA via les identifiers du device registry
            # Les identifiers Z2M ont la forme "zigbee2mqtt_0x8c8b48..." → l'ieee est dedans
            device_id = None
            if ieee:
                ieee_lower = ieee.lower()
                for id_val, did in did_by_uid.items():
                    if ieee_lower in id_val.lower():
                        device_id = did
                        break

            if not device_id:
                sample = list(did_by_uid.keys())[:6]
                warn(f"[sync] Device non trouvé dans HA (ieee={ieee or '?'})"
                     f" — identifiers connus: {sample}"
                     " — sera retentée au prochain cycle")
                continue

            if not area_id:
                warn(f"[sync] Area '{area_name}' inconnue pour le device {ieee or entity_id}")
                continue

            res = call("config/device_registry/update", device_id=device_id, area_id=area_id)
            if res and res.get("success"):
                log(f"[sync] Device {ieee or entity_id} → area '{area_name}' ✓")
            else:
                warn(f"[sync] Erreur assignation {ieee or entity_id} → '{area_name}': {res}")

    except Exception as e:
        warn(f"[sync] Erreur batch areas : {e}")
    finally:
        try:
            ws_close()
        except Exception:
            pass


def _sync_all_to_ha():
    """Récupère l'état complet depuis l'app et l'applique à HA (idempotent, une session WS)."""
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

    rooms   = state.get("rooms", [])
    devices = state.get("device_assignments", [])
    scenes  = state.get("scene_commands", [])
    autos   = state.get("automation_commands", [])

    log(f"[sync] Début : {len(rooms)} pièces, {len(devices)} assignations, {len(scenes)} scènes, {len(autos)} automations")

    # Déclencher Z2M pour republier ses discovery messages HA → HA peuple son device registry.
    # Envoyé EN PREMIER pour laisser à Z2M le temps de répondre pendant qu'on sync scènes/autos.
    if _local_client:
        _local_client.publish("homeassistant/status", "online", qos=1)
        log("[sync] homeassistant/status online → Z2M republiera les discovery HA")

    # Scènes + automations via REST HA (rapide, pas de WebSocket)
    for scene in scenes:
        _handle_ha_command(json.dumps(scene).encode())
    for auto in autos:
        _handle_ha_command(json.dumps(auto).encode())

    # Areas + device assignments en une seule session WebSocket
    _sync_areas_batch(rooms, devices)

    # Demander à Z2M de republier bridge/devices → devices-sync webhook
    # → vendor/model/features/z2m_name mis à jour sans redémarrer Z2M
    if _local_client:
        _local_client.publish("zigbee2mqtt/bridge/request/devices", "", qos=1)
        log("[sync] bridge/request/devices publié → Z2M va republier bridge/devices")

    # Réconciliation Matter (get_nodes) — même logique que bridge/devices Zigbee,
    # auto-réparatrice si l'enregistrement post-commissioning a échoué ou a été manqué.
    _sync_matter_devices_to_app()

    _backfill_ha_entity_links()

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
        # Attend 5 min OU un déclenchement immédiat (reconnexion EMQX, etc.)
        _sync_requested.wait(timeout=60)
        _sync_requested.clear()


def call_heartbeat_api():
    """Envoie le heartbeat (+ état Z2M courant) au webhook API."""
    creds = base64.b64encode(f"{PI_USER}:{PI_PASS}".encode()).decode()
    payload: dict = {"siteId": SITE_PREFIX}
    if _z2m_online is not None:
        payload["z2mOnline"] = _z2m_online
    try:
        r = requests.post(
            f"{APP_URL}/api/webhooks/pi/heartbeat",
            json=payload,
            headers={"Authorization": f"Basic {creds}", "Content-Type": "application/json"},
            timeout=10,
        )
        if r.status_code != 200:
            warn(f"Heartbeat API {r.status_code}: {r.text[:120]}")
    except Exception as e:
        warn(f"Heartbeat API: {e}")


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

                    # Persiste en DB via /api/ingest/states — seul canal d'état vers l'app
                    # (Supabase Realtime relaie ensuite vers le navigateur).
                    if INGEST_SECRET:
                        threading.Thread(
                            target=_post_ingest_state,
                            args=(entity_id, state_val, attributes),
                            daemon=True,
                        ).start()

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


def _post_ingest_state(entity_id: str, state: str, attributes: dict):
    """Appelle /api/ingest/states pour persister un état HA (caméras, alarme)."""
    try:
        requests.post(
            f"{APP_URL}/api/ingest/states",
            json={
                "siteSecret": INGEST_SECRET,
                "siteId": SITE_PREFIX,
                "entityId": entity_id,
                "state": state,
                "attributes": attributes,
            },
            timeout=10,
        )
    except Exception as e:
        warn(f"[ingest/states] {entity_id}: {e}")


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
    """Envoie un heartbeat toutes les 30 secondes via webhook API — met à jour
    sites.last_heartbeat_at, relayé au navigateur par Supabase Realtime."""
    time.sleep(10)
    while True:
        call_heartbeat_api()
        time.sleep(30)


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


def _get_ha_device_id(entity_id=None, ieee_address=None):
    """Retourne le device_id HA depuis entity_id ou ieee_address Z2M (WebSocket)."""
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
        entity_id    = data.get("entity_id")    or None
        ieee_address = data.get("ieee_address") or None
        area_name    = data.get("area_name")    or None

        device_id = _get_ha_device_id(entity_id=entity_id, ieee_address=ieee_address)
        if not device_id:
            warn(f"[ha/command] set_device_area: device non trouvé (entity={entity_id}, ieee={ieee_address})")
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


def _sync_devices_to_app(devices_list):
    """Background thread : envoie la liste bridge/devices au backend pour upsert auto."""
    try:
        auth = base64.b64encode(f"{PI_USER}:{PI_PASS}".encode()).decode()
        r = requests.post(
            f"{APP_URL}/api/webhooks/pi/devices-sync",
            json={"siteId": SITE_PREFIX, "source": "zigbee", "devices": devices_list},
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
            timeout=30,
        )
        log(f"[devices-sync] HTTP {r.status_code} — {len(devices_list)} devices, réponse: {r.text[:120]}")
    except Exception as e:
        warn(f"[devices-sync] {e}")


def on_local_message(client, userdata, msg):
    """Messages reçus depuis Mosquitto local (Z2M). Plus de relay cloud —
    l'état passe uniquement par run_ha_ws_bridge() → /api/ingest/states."""
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
        log(f"[matter] {label} démarré ✓")
    else:
        warn(f"[matter] Impossible de démarrer {label}: {r.status_code} {r.text[:100]}")


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
        handle_camera_configure(action, stream_name, data.get("rtspUrl"))
        self._ok()

    def _handle_sync_now(self, data):
        """Déclenche un cycle de _sync_all_to_ha() immédiat (pièces/scènes/automations
        + republication bridge/devices Z2M → réconciliation devices-sync) au lieu
        d'attendre le prochain cycle périodique (jusqu'à 60s) — bouton "Sync HA"."""
        _sync_requested.set()
        self._ok()


def run_command_server():
    """Serveur HTTP local (127.0.0.1 uniquement) — exposé au monde via le tunnel
    Cloudflare existant (ingress ha-{slug}.domoticium.fr → 127.0.0.1:COMMAND_PORT)."""
    if not INGEST_SECRET:
        warn("[cmd-server] ingest_secret non configuré — serveur de commandes désactivé")
        return
    try:
        httpd = socketserver.ThreadingTCPServer(("127.0.0.1", COMMAND_PORT), _CommandHandler)
        httpd.daemon_threads = True
        log(f"[cmd-server] ✓ Serveur de commandes actif sur 127.0.0.1:{COMMAND_PORT}")
        httpd.serve_forever()
    except Exception as e:
        warn(f"[cmd-server] Erreur fatale : {e}")


def run_bridge():
    _load_cameras()
    start_cloudflared()
    threading.Thread(target=_ensure_matter_server, daemon=True).start()
    threading.Thread(target=_check_and_fix_mqtt_broker, daemon=True).start()
    threading.Thread(target=_heartbeat_loop, daemon=True).start()
    threading.Thread(target=_ha_sync_loop,   daemon=True).start()
    threading.Thread(target=run_local_bridge, daemon=True).start()
    # Bridge HA WebSocket → Supabase (ingest) : seul canal d'état, remplace EMQX
    threading.Thread(target=run_ha_ws_bridge, daemon=True).start()

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
    # Priorité absolue : écrire frigate.yml AVANT tout le reste.
    # Frigate peut auto-démarrer pendant notre setup et lire ce fichier.
    # On le fait ici, avant même d'attendre HA, pour éviter le crash de migration
    # causé par un "cameras: {}" ou "cameras: null" résiduel.
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
