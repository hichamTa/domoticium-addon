#!/usr/bin/env python3
"""
Domoticium — Add-on Home Assistant
Phase 1 (une seule fois) :
  • Installe et configure Zigbee2MQTT (→ EMQX direct)
  • Installe Matter Server
  • Crée les 4 automations MQTT (State Stream, Commands, Heartbeat, Camera Status)
  • Écrit le rest_command caméra hors ligne
Phase 2 (service permanent) :
  • Pont WebRTC : reçoit les SDP offers via MQTT, les forward à go2rtc local
  • Gestion des streams caméra : ajoute / supprime des flux dans go2rtc à la demande
"""
import base64, json, os, sys, threading, time
import paho.mqtt.client as mqtt
import requests

# ── Config depuis l'UI HA ──────────────────────────────────────────────────────
with open("/data/options.json") as f:
    cfg = json.load(f)

SITE_PREFIX     = cfg["site_prefix"]
EMQX_HOST       = cfg["emqx_host"]
PI_USER         = cfg["pi_username"]
PI_PASS         = cfg["pi_password"]
ZIGBEE_ADAPTER          = cfg.get("zigbee_adapter", "auto")
INSTALL_THREAD_ROUTER   = cfg.get("install_thread_border_router", False)
THREAD_ADAPTER          = cfg.get("thread_adapter", "auto")
APP_URL                 = cfg.get("app_url", "https://app.domoticium.fr")
GO2RTC_URL      = cfg.get("go2rtc_url", "http://localhost:1984")

SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
SUP  = "http://supervisor"
API  = f"{SUP}/core/api"
HDRS = {"Authorization": f"Bearer {SUPERVISOR_TOKEN}", "Content-Type": "application/json"}

SETUP_DONE = "/data/.setup_done"
Z2M_REPO   = "https://github.com/zigbee2mqtt/hassio-zigbee2mqtt"
Z2M_SLUG   = "45df7312_zigbee2mqtt"   # slug après ajout du repo communautaire
MATTER_SLUG  = "core_matter_server"          # add-on officiel HA
THREAD_SLUG  = "core_openthread_border_router"  # add-on officiel HA


def log(msg):  print(f"[domoticium] {msg}", flush=True)
def warn(msg): print(f"[domoticium] ⚠ {msg}", file=sys.stderr, flush=True)

def sup_get(path):
    return requests.get(f"{SUP}{path}", headers=HDRS, timeout=15)

def sup_post(path, data=None):
    return requests.post(f"{SUP}{path}", headers=HDRS, json=data or {}, timeout=30)

def ha_post(path, data=None):
    return requests.post(f"{API}{path}", headers=HDRS, json=data or {}, timeout=15)


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

    # 1. Ajouter le dépôt communautaire
    repos = sup_get("/store/repositories").json()
    existing_urls = [r.get("source", "") for r in (repos if isinstance(repos, list) else [])]
    if Z2M_REPO not in existing_urls:
        r = sup_post("/store/repositories", {"repository": Z2M_REPO})
        if r.ok:
            log("✓ Dépôt Zigbee2MQTT ajouté")
            time.sleep(3)  # laisser le Supervisor indexer
        else:
            warn(f"Dépôt Z2M : {r.status_code} — continuer quand même")
    else:
        log("Dépôt Zigbee2MQTT déjà présent")

    # 2. Installer l'add-on si pas encore installé
    info = sup_get(f"/addons/{Z2M_SLUG}/info")
    if info.status_code == 404:
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

    # 3. Écrire la configuration zigbee2mqtt
    z2m_config = {
        "mqtt": {
            "server": f"mqtts://{EMQX_HOST}:8883",
            "user": PI_USER,
            "password": PI_PASS,
            "base_topic": f"{SITE_PREFIX}/zigbee2mqtt",
        },
        "serial": {"port": ZIGBEE_ADAPTER},
        "homeassistant": False,  # on gère les états via EMQX, pas via HA discovery
        "permit_join": False,
        "advanced": {"log_level": "info", "network_key": "GENERATE"},
        "frontend": {"port": 8099},  # accessible depuis HA (ingress)
    }

    z2m_dir = "/homeassistant/zigbee2mqtt"
    os.makedirs(z2m_dir, exist_ok=True)
    with open(f"{z2m_dir}/configuration.yaml", "w") as f:
        # Écriture YAML simple sans dépendance PyYAML
        f.write(_dict_to_yaml(z2m_config))
    log("✓ Configuration Zigbee2MQTT écrite")

    # 4. Options add-on : pointer vers le dossier de config
    sup_post(f"/addons/{Z2M_SLUG}/options", {
        "options": {"data_path": "/config/zigbee2mqtt"}
    })

    # 5. Démarrer
    r = sup_post(f"/addons/{Z2M_SLUG}/start")
    mark = "✓" if r.ok else f"✗ {r.status_code}"
    log(f"{mark} Zigbee2MQTT démarré")


# ── Matter Server ─────────────────────────────────────────────────────────────

def install_matter_server():
    log("── Matter Server ────────────────────────────")

    info = sup_get(f"/addons/{MATTER_SLUG}/info")
    if info.status_code == 404:
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
    mark = "✓" if r.ok else f"✗ {r.status_code}"
    log(f"{mark} Matter Server démarré")

    # Activer l'intégration Matter dans HA
    flow = ha_post("/config/config_entries/flow", {"handler": "matter"})
    if flow.ok and flow.json().get("type") == "create_entry":
        log("✓ Intégration Matter activée")
    else:
        log("Intégration Matter : à activer manuellement si besoin (Paramètres → Intégrations → Matter)")


# ── Thread Border Router ─────────────────────────────────────────────────────

def install_thread_border_router():
    log("── Thread Border Router ──────────────────────")

    # 1. Installer l'add-on
    info = sup_get(f"/addons/{THREAD_SLUG}/info")
    if info.status_code == 404:
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

    # 2. Auto-détection du port série du dongle Thread
    thread_port = THREAD_ADAPTER
    if thread_port == "auto":
        thread_port = _detect_thread_adapter()
        if thread_port:
            log(f"Dongle Thread détecté : {thread_port}")
        else:
            warn("Aucun dongle Thread détecté — configurer manuellement dans l'add-on.")
            thread_port = "/dev/ttyACM1"  # valeur par défaut commune

    # 3. Configurer l'add-on
    options = {
        "device": thread_port,
        "baudrate": 460800,
        "flow_control": True,
        "autoflash_firmware": True,  # flash automatique du firmware OpenThread si besoin
    }
    r = sup_post(f"/addons/{THREAD_SLUG}/options", {"options": options})
    mark = "✓" if r.ok else f"✗ {r.status_code}"
    log(f"{mark} Configuration Thread Border Router (port: {thread_port})")

    # 4. Démarrer
    r = sup_post(f"/addons/{THREAD_SLUG}/start")
    mark = "✓" if r.ok else f"✗ {r.status_code}"
    log(f"{mark} Thread Border Router démarré")

    # 5. Activer l'intégration Thread dans HA (permet à Matter d'utiliser Thread)
    time.sleep(3)
    flow = ha_post("/config/config_entries/flow", {"handler": "otbr"})
    if flow.ok:
        result = flow.json()
        if result.get("type") == "create_entry":
            log("✓ Intégration OTBR (Thread) activée dans HA")
        elif result.get("flow_id"):
            # Soumettre la config par défaut si le flow demande confirmation
            r2 = requests.post(
                f"{API}/config/config_entries/flow/{result['flow_id']}",
                headers=HDRS, json={}, timeout=10
            )
            mark = "✓" if r2.ok else "? (à valider dans HA)"
            log(f"{mark} Intégration OTBR (Thread)")
    else:
        log("Intégration Thread : à activer si besoin dans Paramètres → Intégrations → OpenThread Border Router")


def _detect_thread_adapter():
    """Détecte automatiquement un dongle Thread USB parmi les ports série connus."""
    import glob, os

    # Dongles Thread courants (Silicon Labs EFR32, Nordic nRF52840, etc.)
    thread_ids = [
        "usb-Silicon_Labs",
        "usb-SEGGER",
        "usb-Nordic_Semiconductor",
        "usb-dresden_elektronik",
    ]
    by_id = glob.glob("/dev/serial/by-id/*")
    for path in by_id:
        for tid in thread_ids:
            # Éviter de prendre le coordinateur Zigbee (déjà affecté)
            if tid in path and "zigbee" not in path.lower():
                real = os.path.realpath(path)
                return real

    # Fallback : essayer le deuxième port ACM (le premier est souvent Zigbee)
    for port in ["/dev/ttyACM1", "/dev/ttyUSB1"]:
        if os.path.exists(port):
            return port

    return None


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
    create_automations()
    write_rest_commands()
    ha_post("/services/homeassistant/reload_all")
    with open(SETUP_DONE, "w") as f:
        f.write("done")
    log("═══ Configuration terminée ✓ ═══")
    log("Passage en mode service (WebRTC + caméras)…")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — SERVICE PERMANENT
# ══════════════════════════════════════════════════════════════════════════════

def handle_webrtc_request(client, msg):
    """Reçoit un SDP offer via MQTT, le forward à go2rtc, publie l'answer."""
    try:
        request_id  = msg.topic.split("/")[-1]
        data        = json.loads(msg.payload.decode())
        stream_name = data["streamName"]
        sdp_offer   = data["sdp"]

        log(f"WebRTC {request_id[:8]}… → '{stream_name}'")
        resp = requests.post(
            f"{GO2RTC_URL}/api/webrtc?src={stream_name}",
            data=sdp_offer.encode(),
            headers={"Content-Type": "application/sdp"},
            timeout=6,
        )
        if resp.status_code != 200:
            warn(f"go2rtc {resp.status_code}: {resp.text[:200]}")
            return

        answer_topic = f"{SITE_PREFIX}/webrtc/answer/{request_id}"
        client.publish(answer_topic, json.dumps({"sdp": resp.text}), qos=1)
        log(f"Answer → {answer_topic}")
    except Exception as e:
        warn(f"WebRTC: {e}")


def handle_matter_commission(client, msg):
    """
    Reçoit un code PIN Matter via MQTT, commissionne le device via HA,
    publie le résultat sur {prefix}/matter/commission/status/{requestId}.
    Exécuté dans un thread séparé pour ne pas bloquer la boucle MQTT.
    Topic : {prefix}/matter/commission/start
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

            # Appel au service matter.commission de Home Assistant
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


def handle_camera_configure(client, msg):
    """
    Ajoute ou supprime un flux dans go2rtc à la demande.
    Topic : {prefix}/cameras/{cameraId}/configure
    Payload : {"action": "add"|"remove", "streamName": "...", "rtspUrl": "rtsp://..."}
    """
    try:
        data        = json.loads(msg.payload.decode())
        action      = data.get("action", "add")
        stream_name = data["streamName"]

        if action == "add":
            rtsp_url = data["rtspUrl"]
            resp = requests.put(
                f"{GO2RTC_URL}/api/streams",
                params={"name": stream_name},
                data=rtsp_url,
                headers={"Content-Type": "text/plain"},
                timeout=5,
            )
            mark = "✓" if resp.status_code in (200, 204) else f"✗ {resp.status_code}"
            log(f"{mark} go2rtc stream ajouté : '{stream_name}' → {rtsp_url}")

        elif action == "remove":
            resp = requests.delete(
                f"{GO2RTC_URL}/api/streams",
                params={"name": stream_name},
                timeout=5,
            )
            mark = "✓" if resp.status_code in (200, 204) else f"✗ {resp.status_code}"
            log(f"{mark} go2rtc stream supprimé : '{stream_name}'")

    except Exception as e:
        warn(f"Camera configure: {e}")


def on_connect(client, userdata, flags, rc):
    if rc != 0:
        warn(f"Connexion MQTT échouée (rc={rc})")
        return
    topics = [
        (f"{SITE_PREFIX}/webrtc/request/+", 1),
        (f"{SITE_PREFIX}/cameras/+/configure", 1),
        (f"{SITE_PREFIX}/matter/commission/start", 1),
    ]
    client.subscribe(topics)
    log(f"Service actif — souscrit à {SITE_PREFIX}/webrtc/#, /cameras/#, /matter/#")


def on_message(client, userdata, msg):
    parts = msg.topic.split("/")
    if len(parts) >= 4 and parts[1] == "webrtc" and parts[2] == "request":
        handle_webrtc_request(client, msg)
    elif len(parts) >= 4 and parts[1] == "cameras" and parts[3] == "configure":
        handle_camera_configure(client, msg)
    elif len(parts) >= 4 and parts[1] == "matter" and parts[2] == "commission" and parts[3] == "start":
        handle_matter_commission(client, msg)


def run_bridge():
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
    if not os.path.exists(SETUP_DONE):
        run_setup()
    else:
        log("Déjà configuré — démarrage du service.")
    run_bridge()
