#!/usr/bin/env python3
"""
Domoticium — Add-on Home Assistant
Phase 1 (une seule fois) :
  • Configure MQTT → EMQX
  • Installe Zigbee2MQTT, Matter Server, Frigate NVR
  • Crée les 4 automations MQTT (State Stream, Commands, Heartbeat, Camera Status)
  • Écrit le rest_command caméra hors ligne
Phase 2 (service permanent) :
  • Démarre cloudflared (Cloudflare Tunnel → go2rtc Frigate port 1984)
  • Gestion des caméras : ajoute/supprime dans Frigate à la demande
  • Commissionnement Matter
"""
import base64, json, os, secrets, subprocess, sys, threading, time
import paho.mqtt.client as mqtt
import requests

# ── Config depuis l'UI HA ──────────────────────────────────────────────────────
with open("/data/options.json") as f:
    cfg = json.load(f)

SITE_PREFIX             = cfg["site_prefix"]
EMQX_HOST               = cfg["emqx_host"]
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

# Références aux deux clients MQTT (cloud EMQX + local Mosquitto)
_cloud_client: mqtt.Client | None = None
_local_client: mqtt.Client | None = None


def log(msg):  print(f"[domoticium] {msg}", flush=True)
def warn(msg): print(f"[domoticium] ⚠ {msg}", file=sys.stderr, flush=True)

def sup_get(path):
    return requests.get(f"{SUP}{path}", headers=HDRS, timeout=15)

def sup_post(path, data=None):
    return requests.post(f"{SUP}{path}", headers=HDRS, json=data or {}, timeout=60)

def ha_post(path, data=None):
    return requests.post(f"{API}{path}", headers=HDRS, json=data or {}, timeout=15)

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
        "advanced": {"log_level": "info", "network_key": "GENERATE"},
        "frontend": {"port": 8099},
    }

    z2m_dir = "/homeassistant/zigbee2mqtt"
    os.makedirs(z2m_dir, exist_ok=True)
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
        device_label = f"socket://{COORDINATOR_HOST}:{COORDINATOR_THREAD_PORT}"
        log(f"Mode réseau PoE — coordinateur Thread : {device_label}")
        base_options = {
            "device": device_label,
            "baudrate": 460800,
            "flow_control": False,
            "autoflash_firmware": False,
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

    # Lire le schéma réel pour n'envoyer que les champs acceptés par cette version
    schema_keys = None
    try:
        info = sup_get(f"/addons/{THREAD_SLUG}/info")
        if info.ok:
            data = info.json()
            if isinstance(data, dict):
                data = data.get("data", data)
            schema = data.get("schema", {})
            if isinstance(schema, dict) and schema:
                schema_keys = set(schema.keys())
                log(f"[OTBR] Schéma : {sorted(schema_keys)}")
    except Exception as e:
        warn(f"[OTBR] Lecture schéma : {e}")

    # Options filtrées aux champs connus du schéma (évite les 400 pour champ inconnu)
    if schema_keys:
        filtered = {k: v for k, v in base_options.items() if k in schema_keys}
    else:
        filtered = base_options

    # 3 tentatives : schéma filtré → device seul → options à plat (sans wrapper)
    attempts = [
        ("options filtrées", {"options": filtered}),
        ("device seul",      {"options": {"device": device_label}}),
        ("sans wrapper",     base_options),
    ]
    options_ok = False
    for label, body in attempts:
        r = sup_post(f"/addons/{THREAD_SLUG}/options", body)
        if r.ok:
            log(f"✓ Configuration Thread Border Router ({device_label}) [{label}]")
            options_ok = True
            break
        warn(f"[OTBR] {label} → {r.status_code}: {r.text[:200]}")

    if not options_ok:
        warn(f"✗ Impossible de configurer OTBR via Supervisor API — device={device_label}")
        return

    r = sup_post(f"/addons/{THREAD_SLUG}/restart")
    if r.ok:
        log("✓ Thread Border Router démarré")
    else:
        warn(f"✗ {r.status_code} Thread Border Router restart : {r.text[:150]}")

    time.sleep(3)
    flow = ha_post("/config/config_entries/flow", {"handler": "otbr"})
    if flow.ok:
        result = flow.json()
        if result.get("type") == "create_entry":
            log("✓ Intégration OTBR (Thread) activée dans HA")
        elif result.get("flow_id"):
            r2 = requests.post(
                f"{API}/config/config_entries/flow/{result['flow_id']}",
                headers=HDRS, json={}, timeout=10
            )
            mark = "✓" if r2.ok else "? (à valider dans HA)"
            log(f"{mark} Intégration OTBR (Thread)")
    else:
        log("Intégration Thread : à activer si besoin dans Paramètres → Intégrations")


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


def _build_mqtt_broker_payload(schema: list, local: bool = False) -> dict:
    """
    Construit le payload pour chaque étape du flow MQTT HA en lisant le data_schema.
    local=True  → Mosquitto local (core-mosquitto:1883, pas de TLS)
    local=False → EMQX Cloud (port 8883, TLS obligatoire)
    Si schema vide → étape de confirmation sans champ → payload {}.
    """
    if not schema:
        return {}

    schema_names = {f.get("name", "") for f in schema}
    log(f"[MQTT] Champs du schéma : {sorted(schema_names)}")
    payload = {}

    # ── Credentials broker ────────────────────────────────────────────────────
    for k in ("broker", "host", "server", "hostname"):
        if k in schema_names:
            payload[k] = "core-mosquitto" if local else EMQX_HOST
            break

    if "port" in schema_names:
        payload["port"] = 1883 if local else 8883

    for k in ("username", "user"):
        if k in schema_names:
            payload[k] = MOSQUITTO_USER if local else PI_USER
            break

    for k in ("password", "pass"):
        if k in schema_names:
            payload[k] = MOSQUITTO_PASS if local else PI_PASS
            break

    if local:
        # Mosquitto local — pas de TLS, pas d'options avancées
        return payload

    # ── TLS EMQX Cloud (local=False) ─────────────────────────────────────────
    # EMQX Cloud Serverless n'expose que le port 8883 (TLS obligatoire).
    # Sans advanced_options=True, HA tente une connexion TCP plain → cannot_connect.
    if "advanced_options" in schema_names:
        payload["advanced_options"] = True

    # Le nom du champ CA a changé selon les versions HA :
    # 'certificate' (anciennes) ou 'set_ca_cert' (HA 2025.x).
    for k in ("certificate", "set_ca_cert"):
        if k in schema_names:
            payload[k] = "auto"  # CAs système — EMQX a un cert Let's Encrypt valide
    if "tls_insecure" in schema_names:
        payload["tls_insecure"] = False

    return payload


def configure_mqtt():
    log("── MQTT (Mosquitto local) ───────────────────")

    # Vérifier si MQTT est déjà actif
    svc_resp = requests.get(f"{API}/services", headers=HDRS, timeout=10)
    if svc_resp.ok:
        try:
            if any(s.get("domain") == "mqtt" for s in svc_resp.json()):
                log("MQTT déjà configuré et actif")
                return
        except Exception:
            pass

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

        payload = _build_mqtt_broker_payload(schema, local=True)
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
    p = SITE_PREFIX

    automations = [
        {
            "id": "domoticium_state_stream",
            "alias": "Domoticium — State Stream",
            "description": "Publie états et attributs vers EMQX",
            "mode": "parallel", "max": 50,
            "trigger": [{"platform": "event", "event_type": "state_changed"}],
            "condition": [{"condition": "template", "value_template": (
                "{{ trigger.event.data.entity_id.split('.')[0] in "
                "['light','switch','sensor','binary_sensor','climate','cover','camera'] "
                "and trigger.event.data.new_state is not none }}"
            )}],
            "action": [
                {"service": "mqtt.publish", "data": {
                    "topic": f"{p}/ha/{{{{ trigger.event.data.entity_id.split('.')[0] }}}}/{{{{ trigger.event.data.entity_id.split('.')[1] }}}}/state",
                    "payload": "{{ trigger.event.data.new_state.state }}", "retain": True,
                }},
                {"service": "mqtt.publish", "data": {
                    "topic": f"{p}/ha/{{{{ trigger.event.data.entity_id.split('.')[0] }}}}/{{{{ trigger.event.data.entity_id.split('.')[1] }}}}/attributes",
                    "payload": "{{ trigger.event.data.new_state.attributes | to_json }}", "retain": True,
                }},
            ],
        },
        {
            "id": "domoticium_command_handler",
            "alias": "Domoticium — Command Handler",
            "description": "Exécute les commandes reçues via EMQX",
            "mode": "parallel", "max": 20,
            "trigger": [{"platform": "mqtt", "topic": f"{p}/ha/command"}],
            "condition": [{"condition": "template",
                           "value_template": "{{ trigger.payload_json.service is defined }}"}],
            "action": [{
                "service": "{{ trigger.payload_json.service }}",
                "target": "{{ trigger.payload_json.target | default({}) }}",
                "data": "{{ trigger.payload_json.data | default({}) }}",
            }],
        },
        {
            "id": "domoticium_heartbeat",
            "alias": "Domoticium — Heartbeat",
            "description": "Publie un heartbeat toutes les 30 secondes (MQTT + API)",
            "mode": "single",
            "trigger": [{"platform": "time_pattern", "seconds": "/30"}],
            "action": [
                {"service": "mqtt.publish", "data": {
                    "topic": f"{p}/ha/heartbeat", "payload": "1", "retain": False,
                }},
                {"service": "rest_command.domoticium_heartbeat"},
            ],
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

    # À valider après Zigbee2MQTT
    # install_matter_server()
    # if INSTALL_THREAD_ROUTER:
    #     install_thread_border_router()
    # install_frigate()
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


def handle_camera_configure(client, msg):
    """
    Ajoute ou supprime une caméra dans Frigate.
    Topic   : {prefix}/cameras/{cameraId}/configure
    Payload : {"action": "add"|"remove", "streamName": "...", "rtspUrl": "rtsp://..."}
    """
    try:
        data        = json.loads(msg.payload.decode())
        action      = data.get("action", "add")
        stream_name = data["streamName"]

        if action == "add":
            rtsp_url = data["rtspUrl"]
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

    except Exception as e:
        warn(f"Camera configure: {e}")


def handle_matter_commission(client, msg):
    """
    Commissionne un device Matter via HA.
    Topic   : {prefix}/matter/commission/start
    Payload : {"requestId": "...", "code": "12345678"}
    """
    def _do():
        request_id = None
        try:
            data       = json.loads(msg.payload.decode())
            request_id = data.get("requestId")
            code       = data.get("code", "")
            if not code:
                raise ValueError("Code PIN manquant")

            log(f"Matter commission {(request_id or '?')[:8]}… code={code}")
            resp = ha_post("/services/matter/commission", {"code": code})

            result_topic = f"{SITE_PREFIX}/matter/commission/status/{request_id}"
            if resp.status_code in (200, 201, 204):
                log("✓ Matter commission réussie")
                client.publish(result_topic,
                               json.dumps({"requestId": request_id, "success": True}),
                               qos=1)
            else:
                try:
                    err_msg = resp.json().get("message", f"HTTP {resp.status_code}")
                except Exception:
                    err_msg = f"HTTP {resp.status_code}"
                warn(f"Matter commission {resp.status_code}: {resp.text[:200]}")
                client.publish(result_topic,
                               json.dumps({"requestId": request_id, "success": False,
                                           "error": err_msg}),
                               qos=1)
        except Exception as exc:
            warn(f"Matter commission: {exc}")
            if request_id:
                client.publish(
                    f"{SITE_PREFIX}/matter/commission/status/{request_id}",
                    json.dumps({"requestId": request_id, "success": False, "error": str(exc)}),
                    qos=1)

    threading.Thread(target=_do, daemon=True).start()


_z2m_online: bool | None = None  # état Z2M courant, None = inconnu


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


def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code.is_failure:
        warn(f"[cloud] Connexion EMQX échouée ({reason_code})")
        return
    p = SITE_PREFIX
    topics = [
        (f"{p}/cameras/+/configure", 1),        # commande ajout/suppression caméra
        (f"{p}/matter/commission/start", 1),    # jumelage Matter
        (f"{p}/zigbee2mqtt/+/set", 1),          # commandes Z2M cloud→local
        (f"{p}/ha/command", 1),                 # service HA cloud→local
    ]
    client.subscribe(topics)
    log(f"[cloud] Connecté EMQX — souscrit à {p}/cameras/+/configure, /matter/+, /zigbee2mqtt/+/set, /ha/command")


def on_message(client, userdata, msg):
    """Messages reçus depuis EMQX Cloud (commandes venant de l'app web)."""
    parts = msg.topic.split("/")
    if len(parts) < 2:
        return

    # ── Relay commandes Z2M cloud → local Mosquitto ──────────────────────────
    # {prefix}/zigbee2mqtt/{device}/set → zigbee2mqtt/{device}/set
    if parts[1] == "zigbee2mqtt" and parts[-1] in ("set", "get"):
        local_topic = "/".join(parts[1:])  # retire le prefix site
        if _local_client:
            _local_client.publish(local_topic, msg.payload, qos=1)
        return

    # ── Relay commandes HA cloud → local Mosquitto ────────────────────────────
    # {prefix}/ha/command → {prefix}/ha/command (même topic, broker différent)
    if len(parts) >= 3 and parts[1] == "ha" and parts[2] == "command":
        if _local_client:
            _local_client.publish(msg.topic, msg.payload, qos=1)
        return

    # ── Autres commandes locales ──────────────────────────────────────────────
    if len(parts) >= 4 and parts[1] == "cameras" and parts[3] == "configure":
        handle_camera_configure(client, msg)
    elif len(parts) >= 4 and parts[1] == "matter" and parts[2] == "commission" and parts[3] == "start":
        handle_matter_commission(client, msg)


def _heartbeat_loop():
    """Envoie un heartbeat au webhook toutes les 30 secondes directement depuis le add-on."""
    time.sleep(10)  # premier appel rapide au démarrage
    while True:
        call_heartbeat_api()
        time.sleep(30)


def on_local_connect(client, userdata, flags, reason_code, properties):
    if reason_code.is_failure:
        warn(f"[local] Connexion Mosquitto échouée ({reason_code})")
        return
    p = SITE_PREFIX
    topics = [
        ("zigbee2mqtt/#", 1),       # tous les messages Z2M (états + bridge/state)
        (f"{p}/ha/#", 1),           # état stream HA (publié par automation State Stream)
    ]
    client.subscribe(topics)
    log("[local] Connecté Mosquitto — souscrit zigbee2mqtt/# et ha/#")


def _handle_ha_command(payload: bytes):
    """Exécute une commande ha/command reçue via MQTT : crée/supprime un script HA."""
    try:
        data = json.loads(payload.decode())
    except Exception as e:
        warn(f"[ha/command] JSON invalide : {e}")
        return

    cmd_type   = data.get("type", "")
    object_id  = data.get("object_id", "")

    if not object_id:
        warn(f"[ha/command] object_id manquant : {data}")
        return

    if cmd_type == "script_upsert":
        script_cfg = {
            "alias":    data.get("alias", object_id),
            "icon":     data.get("icon", "mdi:play"),
            "sequence": data.get("sequence", []),
            "mode":     "single",
        }
        # ha_post préfixe déjà http://supervisor/core/api → pas de /api/ dans le path
        r = ha_post(f"/config/script/config/{object_id}", script_cfg)
        if r.ok:
            ha_post("/services/script/reload", {})
            log(f"[ha/command] Script HA créé/mis à jour : {object_id}")
        else:
            warn(f"[ha/command] Erreur création script {object_id} : {r.status_code} {r.text[:200]}")

    elif cmd_type == "script_delete":
        r = requests.delete(f"{API}/config/script/config/{object_id}", headers=HDRS, timeout=10)
        if r.ok:
            ha_post("/services/script/reload", {})
            log(f"[ha/command] Script HA supprimé : {object_id}")
        else:
            warn(f"[ha/command] Erreur suppression script {object_id} : {r.status_code} {r.text[:200]}")

    else:
        warn(f"[ha/command] Type inconnu : {cmd_type}")


def on_local_message(client, userdata, msg):
    """Messages reçus depuis Mosquitto local → relay vers EMQX Cloud."""
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
        return  # pas besoin de relayer bridge/state vers le cloud

    # ── Pas de relay des commandes /set et /get (sens inverse) ───────────────
    if topic.endswith("/set") or topic.endswith("/get"):
        return

    if not _cloud_client:
        return

    # ── Relay Z2M états local → EMQX : zigbee2mqtt/X → {prefix}/zigbee2mqtt/X ─
    if topic.startswith("zigbee2mqtt/"):
        _cloud_client.publish(f"{SITE_PREFIX}/{topic}", payload, qos=1)
        return

    # ── Commandes ha/command → scripts HA (ne pas relayer vers le cloud) ────────
    if topic == f"{SITE_PREFIX}/ha/command":
        threading.Thread(target=_handle_ha_command, args=(payload,), daemon=True).start()
        return

    # ── Relay HA état stream local → EMQX : {prefix}/ha/X → {prefix}/ha/X ────
    if topic.startswith(f"{SITE_PREFIX}/ha/"):
        _cloud_client.publish(topic, payload, qos=1)
        return


def run_local_bridge():
    """Thread permanent : connexion à Mosquitto local + relay vers EMQX Cloud."""
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


def run_bridge():
    global _cloud_client
    _load_cameras()
    start_cloudflared()
    threading.Thread(target=_heartbeat_loop, daemon=True).start()
    threading.Thread(target=run_local_bridge, daemon=True).start()

    _cloud_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="domoticium-cloud-bridge", clean_session=True)
    _cloud_client.username_pw_set(PI_USER, PI_PASS)
    _cloud_client.tls_set()
    _cloud_client.on_connect    = on_connect
    _cloud_client.on_message    = on_message
    _cloud_client.on_disconnect = lambda c, u, df, rc, props: (
        warn(f"[cloud] Déconnexion EMQX ({rc}) — reconnexion…") if rc.is_failure else None
    )
    while True:
        try:
            _cloud_client.connect(EMQX_HOST, 8883, keepalive=60)
            _cloud_client.loop_forever()
        except Exception as e:
            warn(f"[cloud] EMQX : {e} — retry dans 10s")
            time.sleep(10)


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
