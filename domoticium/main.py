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
import base64, json, os, subprocess, sys, threading, time
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

Z2M_REPO     = "https://github.com/zigbee2mqtt/hassio-zigbee2mqtt"
Z2M_SLUG     = "45df7312_zigbee2mqtt"
MATTER_SLUG  = "core_matter_server"
THREAD_SLUG  = "core_openthread_border_router"
FRIGATE_REPO = "https://github.com/blakeblackshear/frigate-hass-addons"
FRIGATE_SLUG = "ccab4aaf_frigate"

_cameras: dict[str, str] = {}  # {stream_name: rtsp_url}


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
        # Ou state explicitement "started" / "running" (add-on déjà en cours)
        return state in ("started", "running")
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
        log(f"Mode réseau PoE — coordinateur Zigbee : {zigbee_port}")
    else:
        zigbee_port = ZIGBEE_ADAPTER  # "auto" ou port USB explicite

    z2m_config = {
        "mqtt": {
            "server": f"mqtts://{EMQX_HOST}:8883",
            "user": PI_USER,
            "password": PI_PASS,
            "base_topic": f"{SITE_PREFIX}/zigbee2mqtt",
        },
        "serial": {"port": zigbee_port},
        "homeassistant": False,
        "permit_join": False,
        "advanced": {"log_level": "info", "network_key": "GENERATE"},
        "frontend": {"port": 8099},
    }

    z2m_dir = "/homeassistant/zigbee2mqtt"
    os.makedirs(z2m_dir, exist_ok=True)
    with open(f"{z2m_dir}/configuration.yaml", "w") as f:
        f.write(_dict_to_yaml(z2m_config))
    log("✓ Configuration Zigbee2MQTT écrite")

    sup_post(f"/addons/{Z2M_SLUG}/options", {
        "options": {"data_path": "/config/zigbee2mqtt"}
    })

    r = sup_post(f"/addons/{Z2M_SLUG}/start")
    if r.ok:
        log("✓ Zigbee2MQTT démarré")
    else:
        warn(f"✗ {r.status_code} Zigbee2MQTT start : {r.text[:150]}")


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

    r = sup_post(f"/addons/{MATTER_SLUG}/start")
    if r.ok:
        log("✓ Matter Server démarré")
    else:
        warn(f"✗ {r.status_code} Matter Server start : {r.text[:150]}")

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
        options = {
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
                warn("Aucun dongle Thread détecté — configurer manuellement.")
                thread_port = "/dev/ttyACM1"
        device_label = thread_port
        options = {
            "device": thread_port,
            "baudrate": 460800,
            "flow_control": True,
            "autoflash_firmware": True,
        }
    r = sup_post(f"/addons/{THREAD_SLUG}/options", {"options": options})
    mark = "✓" if r.ok else f"✗ {r.status_code}"
    log(f"{mark} Configuration Thread Border Router ({device_label})")

    r = sup_post(f"/addons/{THREAD_SLUG}/start")
    if r.ok:
        log("✓ Thread Border Router démarré")
    else:
        warn(f"✗ {r.status_code} Thread Border Router start : {r.text[:150]}")

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

def install_frigate():
    log("── Frigate NVR ──────────────────────────────")

    # 1. Ajouter le dépôt
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

    # 2. Installer si nécessaire
    if not _is_addon_installed(FRIGATE_SLUG):
        log("Installation de Frigate (peut prendre 2-3 min)…")
        r = sup_post(f"/store/addons/{FRIGATE_SLUG}/install")
        if r.ok:
            log("✓ Frigate installé")
            time.sleep(10)
        else:
            warn(f"Installation Frigate : {r.status_code} {r.text[:200]}")
            return
    else:
        log("Frigate déjà installé")

    # 3. Écrire la config initiale (caméras vides)
    _load_cameras()
    write_frigate_config()

    # 4. Démarrer
    r = sup_post(f"/addons/{FRIGATE_SLUG}/start")
    if r.ok:
        log("✓ Frigate démarré — go2rtc HLS disponible sur :1984")
    else:
        warn(f"✗ {r.status_code} Frigate start : {r.text[:150]}")


def write_frigate_config():
    """Génère /homeassistant/frigate.yml depuis le registre des caméras."""
    lines = [
        "# Généré par Domoticium — ne pas modifier manuellement",
        "mqtt:",
        "  enabled: false",
        "",
        "cameras:",
    ]

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

    if not _cameras:
        lines.append("  # Aucune caméra configurée")

    with open("/homeassistant/frigate.yml", "w") as fh:
        fh.write("\n".join(lines) + "\n")

    log(f"✓ frigate.yml mis à jour ({len(_cameras)} caméra(s))")


# ── MQTT / Automations ───────────────────────────────────────────────────────

def configure_mqtt():
    log("── MQTT ─────────────────────────────────────")
    entries = requests.get(f"{API}/config/config_entries/entry", headers=HDRS, timeout=10)
    if entries.ok and any(e.get("domain") == "mqtt" for e in entries.json()):
        log("MQTT déjà configuré")
        return

    log(f"Configuration MQTT → {EMQX_HOST}:8883…")
    flow = ha_post("/config/config_entries/flow", {"handler": "mqtt"}).json()
    flow_id = flow.get("flow_id")
    if not flow_id:
        warn(f"Flow MQTT impossible : {flow}")
        return

    payload = {"broker": EMQX_HOST, "port": 8883, "username": PI_USER, "password": PI_PASS}
    result = requests.post(f"{API}/config/config_entries/flow/{flow_id}",
                           headers=HDRS, json=payload, timeout=15).json()
    if result.get("type") == "form":
        payload["tls"] = True
        result = requests.post(f"{API}/config/config_entries/flow/{flow_id}",
                               headers=HDRS, json=payload, timeout=15).json()

    mark = "✓" if result.get("type") == "create_entry" else f"? ({result.get('type')})"
    log(f"{mark} MQTT configuré")


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
            "description": "Publie un heartbeat toutes les 30 secondes",
            "mode": "single",
            "trigger": [{"platform": "time_pattern", "seconds": "/30"}],
            "action": [{"service": "mqtt.publish", "data": {
                "topic": f"{p}/ha/heartbeat", "payload": "1", "retain": False,
            }}],
        },
        {
            "id": "domoticium_camera_status",
            "alias": "Domoticium — Camera Status Reporter",
            "description": "Notifie l'API quand une caméra change d'état",
            "mode": "parallel", "max": 10,
            "trigger": [{"platform": "state", "entity_id": ["camera.*"],
                         "to": ["unavailable", "idle", "recording", "streaming"]}],
            "action": [{"service": "rest_command.domoticium_camera_status", "data": {
                "site_id": p,
                "ha_entity_id": "{{ trigger.entity_id }}",
                "online": "{{ trigger.to_state.state != 'unavailable' }}",
            }}],
        },
    ]

    for auto in automations:
        r = requests.post(f"{API}/config/automation/config/{auto['id']}",
                          headers=HDRS, json=auto, timeout=15)
        mark = "✓" if r.status_code in (200, 201) else f"✗ {r.status_code}"
        log(f"{mark} {auto['alias']}")

    ha_post("/services/automation/reload")


def write_rest_commands():
    log("── rest_commands ─────────────────────────────")
    creds = base64.b64encode(f"{PI_USER}:{PI_PASS}".encode()).decode()
    p = SITE_PREFIX

    content = (
        "rest_command:\n"
        "  domoticium_camera_status:\n"
        f'    url: "{APP_URL}/api/webhooks/pi/camera-status"\n'
        "    method: POST\n"
        "    headers:\n"
        '      Content-Type: "application/json"\n'
        f'      Authorization: "Basic {creds}"\n'
        "    payload: "
        f"'{{\"siteId\":\"{p}\",\"haEntityId\":\"{{{{ ha_entity_id }}}}\",\"online\":{{{{ online }}}}}}'\n"
        '    content_type: "application/json"\n'
    )

    rest_file = "/homeassistant/domoticium_rest_commands.yaml"
    include   = "!include domoticium_rest_commands.yaml"
    main_cfg  = "/homeassistant/configuration.yaml"

    with open(rest_file, "w") as f:
        f.write(content)

    with open(main_cfg) as f:
        existing = f.read()
    if include not in existing:
        with open(main_cfg, "a") as f:
            f.write(f"\n{include}\n")

    log("✓ rest_commands configuré")


def run_setup():
    wait_for_ha()
    log("═══ Début de la configuration Domoticium ═══")
    configure_mqtt()
    install_zigbee2mqtt()
    install_matter_server()
    if INSTALL_THREAD_ROUTER:
        install_thread_border_router()
    install_frigate()
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


def on_connect(client, userdata, flags, rc):
    if rc != 0:
        warn(f"Connexion MQTT échouée (rc={rc})")
        return
    topics = [
        (f"{SITE_PREFIX}/cameras/+/configure", 1),
        (f"{SITE_PREFIX}/matter/commission/start", 1),
    ]
    client.subscribe(topics)
    log(f"Service actif — souscrit à {SITE_PREFIX}/cameras/#, /matter/#")


def on_message(client, userdata, msg):
    parts = msg.topic.split("/")
    if len(parts) >= 4 and parts[1] == "cameras" and parts[3] == "configure":
        handle_camera_configure(client, msg)
    elif len(parts) >= 4 and parts[1] == "matter" and parts[2] == "commission" and parts[3] == "start":
        handle_matter_commission(client, msg)


def run_bridge():
    _load_cameras()
    start_cloudflared()
    client = mqtt.Client(client_id="domoticium-addon", clean_session=True)
    client.username_pw_set(PI_USER, PI_PASS)
    client.tls_set()
    client.on_connect    = on_connect
    client.on_message    = on_message
    client.on_disconnect = lambda c, u, rc: (
        warn(f"Déconnexion MQTT (rc={rc}) — reconnexion…") if rc != 0 else None
    )
    while True:
        try:
            client.connect(EMQX_HOST, 8883, keepalive=60)
            client.loop_forever()
        except Exception as e:
            warn(f"MQTT : {e} — retry dans 10s")
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
            lines.append(f"{pad}{k}: {v}")
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if FORCE_SETUP:
        log("force_setup activé — réinitialisation complète de la configuration")
        if os.path.exists(SETUP_DONE):
            os.remove(SETUP_DONE)
    if not os.path.exists(SETUP_DONE):
        run_setup()
    else:
        log("Déjà configuré — démarrage du service.")
    run_bridge()
