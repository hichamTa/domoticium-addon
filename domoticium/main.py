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
import base64, hashlib, hmac, http.server, json, logging, logging.handlers, os, queue, re, secrets, select, socket, socketserver, ssl, struct, subprocess, sys, threading, time, urllib.parse, uuid
from datetime import datetime, date, timedelta, timezone
import paho.mqtt.client as mqtt
import requests

# ── Config depuis l'UI HA ──────────────────────────────────────────────────────
with open("/data/options.json") as f:
    cfg = json.load(f)

SITE_PREFIX             = cfg["site_prefix"]
# (lot D phase 0) Plus utilisés : ils authentifiaient le tirage GET /api/webhooks/pi/sync-state, supprimé. Les options
# add-on `pi_username`/`pi_password` restent au schéma (config.yaml) pour ne pas casser les installations existantes.
PI_USER                 = cfg.get("pi_username", "")
PI_PASS                 = cfg.get("pi_password", "")
COORDINATOR_HOST        = cfg.get("coordinator_host", "").strip()   # vide = mode USB
COORDINATOR_ZIGBEE_PORT = cfg.get("coordinator_zigbee_port", 6638)
COORDINATOR_THREAD_PORT = cfg.get("coordinator_thread_port", 20108)
ZIGBEE_ADAPTER          = cfg.get("zigbee_adapter", "auto")
ZIGBEE_ADAPTER_TYPE     = cfg.get("zigbee_adapter_type", "ember")
INSTALL_THREAD_ROUTER   = cfg.get("install_thread_border_router", False)
THREAD_ADAPTER          = cfg.get("thread_adapter", "auto")
APP_URL                 = cfg.get("app_url", "https://app.domoticium.fr")
# Passerelle API Domoticium (Worker Cloudflare, dossier web/gateway/) : relais TURN pour les caméras (les
# secrets Cloudflare ne quittent jamais la passerelle). Adresse publique, identique pour tous les sites ;
# variable d'environnement seulement pour les tests (pas une option add-on).
GATEWAY_URL             = (os.environ.get("DOMOTICIUM_GATEWAY_URL") or "https://gateway.domoticium.fr").rstrip("/")
CLOUDFLARE_TUNNEL_TOKEN = cfg.get("cloudflare_tunnel_token", "")
FORCE_SETUP             = cfg.get("force_setup", False)
INGEST_SECRET           = cfg.get("ingest_secret", "")
# (2026-09-01) Intervalle max de reporting (secondes) appliqué aux attributs
# "sensibles pile" (batterie/tension pile/température/humidité/éclairement/CO2/
# PM2.5) des devices Zigbee À PILE de CE site — cf. _boost_device_reporting. 0 (par
# défaut) = comportement usine préservé (souvent 1h à ~18h selon l'attribut, pensé
# pour l'autonomie). Réglable PAR SITE via cette option add-on (HA Supervisor,
# onglet Configuration) plutôt qu'un simple interrupteur global tout-ou-rien —
# Hicham : "on peut regler le time ?", suite à la question du compromis
# autonomie/rapidité posée pour les devices à pile (cf. HANDOFF). Les devices
# SECTEUR ne sont jamais concernés par ce réglage (toujours boostés à 30s, aucune
# préoccupation de pile).
BATTERY_REPORTING_SECONDS = int(cfg.get("battery_reporting_seconds", 0) or 0)

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

# Proxy local (127.0.0.1 uniquement) retirant le préfixe /cameras avant de relayer vers
# go2rtc — voir _Go2rtcProxyHandler. L'ingress Cloudflare du tunnel pour /cameras doit
# pointer ici plutôt que directement sur 1984.
GO2RTC_PROXY_PORT = 8099

# Relais HTTPS local (0.0.0.0, pas 127.0.0.1 — doit être joignable depuis le LAN
# du client) — chantier pastille de statut 3 couleurs (2026-10-31). Écoute avec le
# certificat du site (cf. _fetch_local_cert) et relaie en clair vers 127.0.0.1:8100
# (l'add-on "Domoticium — Accès local", même réseau host_network) — UNIQUEMENT ce
# port : confirmé par un agent Explore dédié qu'en mode local le navigateur ne parle
# jamais directement à 8098/8099, seulement à 8100, qui relaie lui-même en interne
# côté serveur vers 8098/1984 (go2rtc) — pas de routage par chemin à faire ici.
LOCAL_TLS_PORT = 8443
# 2e relais HTTPS (même certificat) : page de connexion de Home Assistant. Sans lui, « Connexion via Home Assistant »
# faisait passer le navigateur d'une page HTTPS (l'app) à une page HTTP (HA) : avertissement Chrome « ce site ne
# prend pas en charge les connexions sécurisées » + mot de passe en clair sur le LAN (retest du 2026-11-21).
LOCAL_HA_TLS_PORT = 8444

# Mode réseau (PoE) ou USB
NETWORK_MODE = bool(COORDINATOR_HOST)

SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
SUP  = "http://supervisor"
API  = f"{SUP}/core/api"
HDRS = {"Authorization": f"Bearer {SUPERVISOR_TOKEN}", "Content-Type": "application/json"}

SETUP_DONE   = "/data/.setup_done"
CAMERAS_FILE = "/data/cameras.json"
CAMERA_MASKS_FILE = "/data/camera_masks.json"
ROOM_TYPES_FILE = "/data/room_types.json"


def _pi_sign(message: str) -> str:
    """Signature HMAC-SHA256 d'un message avec INGEST_SECRET — authentifie les
    appels directs vers les fonctions Postgres pi_* (cf. HANDOFF §36). Le secret
    n'est jamais transmis lui-même, seulement cette signature."""
    return hmac.new(INGEST_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()


def _jwt_payload(token: str) -> dict:
    """Décode le corps d'un JWT SANS vérifier sa signature — sert uniquement à en lire
    la date d'expiration (claim "exp"), jamais à faire confiance à son contenu pour une
    décision de sécurité (la validité réelle est vérifiée par Home Assistant lui-même
    au moment de l'utilisation du jeton, pas ici)."""
    part = token.split(".")[1]
    padded = part + "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# Pause progressive après un refus/une panne Supabase (2026-11-13). Constaté en
# conditions réelles : quota egress dépassé → chaque appel renvoyait 402, et
# l'add-on réinjectait les mêmes ~15 éléments toutes les 2,5 s sans jamais
# attendre — 537 000 requêtes refusées en 24 h (6/s) pour rien. Désormais, après
# un 402/429/5xx ou une erreur réseau, plus AUCUN appel pendant 30 s, puis 60,
# 120, 240, plafonné à 300 s ; remis à zéro dès le premier succès. Les appelants
# voient un statut 503 factice (déjà traité comme un échec → retenté plus tard).
_SUPABASE_BACKOFF_STEPS_S = (30, 60, 120, 240, 300)
_supabase_block_until = 0.0
_supabase_fail_count = 0
_supabase_backoff_lock = threading.Lock()


def _supabase_is_backing_off() -> bool:
    return time.time() < _supabase_block_until


def _supabase_note_result(ok: bool) -> None:
    global _supabase_block_until, _supabase_fail_count
    with _supabase_backoff_lock:
        if ok:
            _supabase_fail_count = 0
            return
        step = _SUPABASE_BACKOFF_STEPS_S[min(_supabase_fail_count, len(_SUPABASE_BACKOFF_STEPS_S) - 1)]
        _supabase_fail_count += 1
        _supabase_block_until = time.time() + step
        if _supabase_fail_count == 1:
            warn(f"[supabase] indisponible/refusé — pause {step}s avant de réessayer (pauses croissantes jusqu'à 300s)")


# ── Compteurs de requêtes sortantes vers le cloud (lot D phase 1 du chantier « Pi-first ») ─────────────
# Le dépassement du quota Supabase du 2026-11-13 s'est diagnostiqué à l'aveugle : aucune mesure de ce que l'add-on
# envoie n'existait. Chaque requête vers Supabase (RPC pi_*), Vercel (/api/ingest/*) ou la passerelle API est
# désormais comptée par « étiquette » (nombre, octets envoyés/reçus, erreurs), par heure (24 h conservées sur
# disque) et depuis le démarrage. Consultable par GET /local/stats ; un résumé de l'heure écoulée est écrit dans
# les journaux à chaque changement d'heure. Sert à PROUVER l'effet des retraits de flux (avant/après).
_CLOUD_STATS_FILE = "/data/cloud-stats.json"
_CLOUD_STATS_KEEP_HOURS = 24
_cloud_stats_lock = threading.Lock()
_cloud_stats = {"loaded": False, "since": time.time(), "totals": {}, "hours": {}}


def _cloud_stats_load() -> None:
    if _cloud_stats["loaded"]:
        return
    _cloud_stats["loaded"] = True
    try:
        with open(_CLOUD_STATS_FILE) as f:
            _cloud_stats["hours"] = {k: v for k, v in (json.load(f).get("hours") or {}).items() if isinstance(v, dict)}
    except Exception:
        _cloud_stats["hours"] = {}


def _cloud_stats_summary(bucket: dict) -> str:
    total_n = sum(v["n"] for v in bucket.values())
    total_b = sum(v["out"] + v["in"] for v in bucket.values())
    top = sorted(bucket.items(), key=lambda kv: kv[1]["n"], reverse=True)[:4]
    return f"{total_n} requêtes, {total_b / 1024:.1f} Ko — " + ", ".join(f"{k} ×{v['n']}" for k, v in top)


def _cloud_stats_flush(hours: dict) -> None:
    try:
        tmp = _CLOUD_STATS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"hours": hours}, f)
        os.replace(tmp, _CLOUD_STATS_FILE)
    except Exception:
        pass


def _cloud_note(label: str, sent: int, received: int, ok: bool, now: float | None = None) -> None:
    """Compte UNE requête sortante. Jamais d'exception (ne doit pas perturber l'envoi lui-même)."""
    try:
        now = time.time() if now is None else now
        hour = str(int(now // 3600))
        rolled = None
        with _cloud_stats_lock:
            _cloud_stats_load()
            hours = _cloud_stats["hours"]
            if hour not in hours and hours:
                previous = max(hours, key=int)
                rolled = (previous, dict(hours[previous]))
            for bucket in (hours.setdefault(hour, {}), _cloud_stats["totals"]):
                c = bucket.setdefault(label, {"n": 0, "out": 0, "in": 0, "err": 0})
                c["n"] += 1
                c["out"] += max(0, int(sent))
                c["in"] += max(0, int(received))
                c["err"] += 0 if ok else 1
            if rolled:
                for old in sorted(hours, key=int)[:-_CLOUD_STATS_KEEP_HOURS]:
                    del hours[old]
                snapshot = {h: dict(b) for h, b in hours.items()}
        if rolled:
            log(f"[cloud-stats] heure écoulée : {_cloud_stats_summary(rolled[1])}")
            _cloud_stats_flush(snapshot)
    except Exception:
        pass


def handle_local_stats() -> dict:
    """GET /local/stats : requêtes cloud depuis le démarrage + les dernières heures."""
    with _cloud_stats_lock:
        _cloud_stats_load()
        return {
            "since": _cloud_stats["since"],
            "totals": {k: dict(v) for k, v in _cloud_stats["totals"].items()},
            "hours": {h: {k: dict(v) for k, v in b.items()} for h, b in sorted(_cloud_stats["hours"].items(), key=lambda kv: int(kv[0]))},
        }


def _cloud_post(label: str, url: str, **kwargs):
    """requests.post compté (Vercel /api/ingest/*, passerelle). Même comportement que requests.post."""
    try:
        r = requests.post(url, **kwargs)
    except Exception:
        _cloud_note(label, len(json.dumps(kwargs.get("json"), default=str)) if kwargs.get("json") is not None else 0, 0, False)
        raise
    _cloud_note(label, len(r.request.body or b"") if getattr(r, "request", None) is not None else 0, len(r.content or b""), r.ok)
    return r


# ── Envois au portail : seulement ce qui CHANGE ───────────────────────────────────────────────────────────
# Retour du 2026-11-24 : Vercel a désactivé le portail (offre Hobby dépassée : 1,4 M d'appels de fonctions pour 1 M permis,
# CPU actif 5 h 18 pour 4 h). Cause : les entretiens de fond (_backfill_ha_entity_links / _backfill_camera_entity_links,
# toutes les ~5 min) renvoyaient CHAQUE entité à /api/ingest/registry à chaque passage — mesuré : 2035 appels à l'heure pour
# UN seul site, soit ~1,5 M par mois. Les envois sont désormais mémorisés (empreinte du contenu) : on ne renvoie que ce qui a
# changé, avec un renvoi de sécurité toutes les 24 h (réparation si le portail a perdu la donnée).
_registry_sent: dict = {}
_REGISTRY_RESEND_S = 24 * 3600
_registry_pause_until = 0.0  # portail en échec (HTTP non 2xx) : on arrête d'insister 10 min au lieu de renvoyer chaque entité en vain


def _cloud_post_if_changed(label: str, url: str, payload: dict, key: str) -> bool:
    """Poste `payload` au portail sauf s'il est identique au dernier envoi réussi (même clé) de moins de 24 h, ou si le portail vient de répondre en échec (pause 10 min). Renvoie True si envoyé."""
    body = {k: v for k, v in payload.items() if k != "siteSecret"}
    sig = hashlib.sha1(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    global _registry_pause_until
    now = time.time()
    if now < _registry_pause_until:
        return False
    prev = _registry_sent.get(key)
    if prev and prev[0] == sig and now - prev[1] < _REGISTRY_RESEND_S:
        return False
    r = _cloud_post(label, url, json=payload, timeout=10)
    if getattr(r, "ok", True):
        _registry_sent[key] = (sig, now)
    else:
        _registry_pause_until = now + 600
    return True


def _supabase_rpc(fn_name: str, payload: dict, timeout: float = 10.0) -> requests.Response:
    """Appelle une fonction Postgres pi_* via PostgREST (clé publique anon — la vraie
    autorisation vient de la signature HMAC incluse dans payload, vérifiée côté DB)."""
    if _supabase_is_backing_off():
        stub = requests.Response()
        stub.status_code = 503
        stub._content = b'{"message":"pause locale apres echec Supabase"}'
        return stub
    try:
        r = requests.post(
            f"{SUPABASE_URL}/rest/v1/rpc/{fn_name}",
            json=payload,
            headers={
                "apikey": SUPABASE_ANON_KEY,
                "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )
    except Exception:
        _supabase_note_result(False)
        _cloud_note(f"supabase:{fn_name}", len(json.dumps(payload, default=str)), 0, False)
        raise
    _supabase_note_result(not (r.status_code in (402, 429) or r.status_code >= 500))
    _cloud_note(f"supabase:{fn_name}", len(r.request.body or b"") if getattr(r, "request", None) is not None else 0, len(r.content or b""), r.ok)
    return r

def _normalize_device(
    protocol: str, *, external_id, name: str, type_: str,
    vendor: str = "", model: str = "", online: bool | None = None,
    extra: dict | None = None,
) -> dict:
    """Forme commune envoyée à pi_sync_devices (harmonisation Zigbee/Matter/WiFi,
    chantier approuvé — cf. plan de session). `external_id` est routé côté SQL
    vers ieee_address/matter_node_id/wifi_id selon `protocol`. `online` reste
    optionnel et absent pour Zigbee : la synchro périodique bridge/devices n'a
    jamais eu de signal de présence fiable (contrairement à Matter/WiFi, qui
    l'ont à chaque cycle) — l'omettre dit explicitement à pi_sync_devices de ne
    pas toucher online/alertes pour cette ligne, exactement le comportement
    actuel d'upsert_zigbee_device (jamais modifié sur UPDATE)."""
    device: dict = {
        "external_id": str(external_id),
        "name": name,
        "type": type_,
        "vendor": vendor or "",
        "model": model or "",
        "extra": extra or {},
    }
    if online is not None:
        device["online"] = online
    return device


def _sync_devices_to_supabase(protocol: str, devices: list[dict], timeout: float = 30.0) -> bool:
    """Appelle pi_sync_devices — remplace le bloc signature+appel+log répété en
    fin de chaque _sync_*_direct (harmonisation Zigbee/Matter/WiFi). True si
    réussi. `devices` : liste d'objets déjà normalisés via _normalize_device."""
    try:
        ts = int(time.time())
        id_sorted = ",".join(sorted(d["external_id"] for d in devices))
        message = f"{SITE_PREFIX}:{ts}:device_sync:{protocol}:{id_sorted}"
        r = _supabase_rpc("pi_sync_devices", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
            "p_protocol": protocol, "p_devices": devices,
        }, timeout=timeout)
        if r.status_code >= 300:
            warn(f"[supabase] pi_sync_devices({protocol}) {r.status_code}: {r.text[:200]}")
            return False
        log(f"[supabase] pi_sync_devices({protocol}) — {len(devices)} devices, réponse: {r.text[:120]}")
        return True
    except Exception as e:
        warn(f"[supabase] pi_sync_devices({protocol}): {e}")
        return False


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
# go2rtc reste nu (pas de base_path) — voir _Go2rtcProxyHandler plus bas : le préfixe
# /cameras exigé par Cloudflare Tunnel (qui ne retire jamais le préfixe transmis à
# l'origine) est retiré par un petit proxy local dédié, PAS par go2rtc lui-même.
# Historique (v2.9.123→129, 2026-08-15) : mettre base_path directement sur go2rtc a bien
# réglé l'accès externe, mais a aussi rendu sourd le healthcheck INTERNE de go2rtc/Frigate
# (intégré à l'image Docker Frigate, hors de notre contrôle — ping en dur sur /api/streams
# SANS préfixe) → 404 systématique → redémarrage forcé de go2rtc toutes les ~30-40s →
# coupure vidéo en boucle (cause racine des déconnexions caméra signalées ce soir-là,
# confirmée dans les logs Frigate). D'où ce constant qui reste bare : nos appels internes
# (127.0.0.1, jamais passés par le tunnel) parlent directement à go2rtc sans préfixe.
GO2RTC_API_BASE = "http://127.0.0.1:1984"
MOSQUITTO_SLUG = "core_mosquitto"
MOSQUITTO_USER = "domoticium"

# ── Add-on "Domoticium — Accès local" (chantier 2026-09-06, cf. HANDOFF.md côté
# web) — 2e add-on séparé (dépôt GitHub dédié, jamais fusionné avec celui-ci
# pour ne courir aucun risque sur l'addon en production) installé et mis à
# jour automatiquement par CET addon, exactement comme Frigate ci-dessus.
# LOCAL_WEB_SLUG est un repli codé en dur (deviné à partir de la formule
# observée pour Frigate) — TOUJOURS écrasé par _resolve_local_web_slug() une
# fois le dépôt indexé par le Supervisor, jamais utilisé tel quel en prod
# (même prudence que pour FRIGATE_SLUG, cf. commentaire au-dessus : deviner le
# hash a déjà été faux une fois par le passé).
#
# 2026-09-08 (chantier "add-on public, code privé", demande explicite
# d'Hicham) — LOCAL_WEB_REPO pointe vers hichamTa/domoticium-local-web, PAS
# hichamTa/domoticium-web où vit le vrai code (celui-ci reste privé — testé
# en conditions réelles ce soir : Supervisor ne sait cloner qu'un dépôt
# PUBLIC, git clone anonyme, aucune authentification possible). Repurposé en
# simple coquille : juste repository.json + config.yaml, dont l'`image:`
# pointe vers ghcr.io/hichamta/domoticium-web — une image Docker déjà
# construite, publiée automatiquement depuis le VRAI repo (privé) par
# GitHub Actions à chaque changement de code (cf. .github/workflows/
# publish-addon-image.yml côté web). Home Assistant télécharge cette image
# toute prête, ne clone/ne voit jamais le code source. Slug
# "domoticium_web" (pas "domoticium_local_web", l'ancien slug du prototype
# qui vivait ici avant) — _resolve_local_web_slug() mis à jour en
# conséquence ; coexiste sans conflit avec l'ancien prototype s'il traîne
# encore installé sur un site (slug différent).
LOCAL_WEB_REPO = "https://github.com/hichamTa/domoticium-local-web"
LOCAL_WEB_SLUG = "domoticium_web"

# ── Mot de passe Mosquitto — généré une fois, persisté dans /data/ ─────────────
_MOSQUITTO_PASS_FILE = "/data/mosquitto_pass"
if os.path.exists(_MOSQUITTO_PASS_FILE):
    with open(_MOSQUITTO_PASS_FILE) as _f:
        MOSQUITTO_PASS = _f.read().strip()
else:
    MOSQUITTO_PASS = secrets.token_hex(16)
    with open(_MOSQUITTO_PASS_FILE, "w") as _f:
        _f.write(MOSQUITTO_PASS)

# ── Mot de passe API go2rtc — même mécanisme, propre à CE site (2026-09-07,
# cf. HANDOFF.md : fuite trouvée, go2rtc:1984 accessible sans authentification
# à quiconque sur le réseau local, dont les identifiants RTSP/ONVIF en clair
# via /api/streams. go2rtc EXEMPTE en théorie les requêtes venant de
# 127.0.0.1 (vérifié dans sa vraie doc ET son code source réel) — MAIS
# Frigate (donc go2rtc) tourne en réseau Docker isolé : tout appelant
# EXTÉRIEUR à son conteneur (l'addon, le relais tunnel) traverse le NAT du
# pont Docker pour l'atteindre, qui réécrit l'adresse source (hairpin NAT,
# comportement Docker connu — jamais 127.x vu côté go2rtc, quelle que soit
# l'adresse visée côté appelant). Vérifié en conditions réelles le 2026-09-07
# (déployé sans ça une 1re fois → cassait la vue caméra cloud → annulé →
# vraie cause trouvée → cf. commentaire de _webrtc_config_yaml_lines()) :
# aucun appelant externe n'est jamais exempté ici. D'où GO2RTC_API_AUTH
# ci-dessous, présenté explicitement par CHAQUE appelant (addon ET relais
# tunnel _Go2rtcProxyHandler) plutôt que de compter sur une exemption qui ne
# peut pas s'appliquer à cette topologie.
_GO2RTC_API_PASS_FILE = "/data/go2rtc_api_pass"
if os.path.exists(_GO2RTC_API_PASS_FILE):
    with open(_GO2RTC_API_PASS_FILE) as _f:
        GO2RTC_API_PASSWORD = _f.read().strip()
else:
    GO2RTC_API_PASSWORD = secrets.token_hex(16)
    with open(_GO2RTC_API_PASS_FILE, "w") as _f:
        _f.write(GO2RTC_API_PASSWORD)
GO2RTC_API_AUTH = ("domoticium", GO2RTC_API_PASSWORD)  # requests.*(auth=GO2RTC_API_AUTH)

_cameras: dict[str, str] = {}  # {stream_name: rtsp_url}

# Masquage de zones "en dur" (§93) — {stream_name: [{"x":0-1,"y":0-1,"w":0-1,"h":0-1}, ...]}.
# Rectangles en fractions normalisées de la frame (indépendant de la résolution —
# fonctionne pareil pour le flux principal et le sous-flux qualité §87/§88). Séparé
# de _cameras plutôt que d'étendre sa structure : _cameras est utilisé partout comme
# dict[str, str] (name → rtsp_url), changer son type aurait forcé à retoucher tous
# ses usages pour un gain nul. Défini UNIQUEMENT côté admin (jamais côté client final).
_camera_masks: dict[str, list[dict]] = {}

# Sérialise handle_camera_configure() — chaque requête /addon/camera/configure arrive
# dans son propre thread (cmd-server), donc supprimer/ajouter plusieurs caméras d'un
# coup (ex: suppression groupée depuis l'app) déclenche plusieurs appels quasi
# simultanés. Sans verrou, chacun mute _cameras et appelle restart_frigate() en
# parallèle — confirmé en conditions réelles le 2026-07-25 : le 2e restart_frigate()
# reçoit un 400 du Supervisor HA (redémarrage déjà en cours pour le 1er), l'appelant
# HTTP correspondant reçoit un 502 alors que l'état final était pourtant correct.
# Sans conséquence dans ce cas précis (le dernier write_frigate_config() gagnait de
# toute façon), mais fragile en général — ce verrou fait passer les appels un par un :
# état et redémarrage toujours cohérents, plus de résultat "ok=False" trompeur pour
# une opération qui a en réalité réussi.
#
# Devenu aussi le verrou dédié pour toute LECTURE non triviale de _cameras/
# _camera_masks (audit dette technique, point 20, 2026-09-18) : write_frigate_config()
# (via _generate_frigate_yaml) et _resync_go2rtc_streams() itèrent tous les deux sur
# _cameras.items() avec du travail (I/O compris) entre chaque élément — une vraie
# itération Python, pas une simple lecture atomique — pendant qu'un thread HTTP
# concurrent peut muter le dict via handle_camera_configure()/handle_camera_mask().
# Sans protection, ça peut lever RuntimeError("dictionary changed size during
# iteration"), jamais observé en réel mais réel en théorie (1 seul site réel
# aujourd'hui, faible trafic concurrent). RLock (pas Lock) : write_frigate_config()
# est appelé À LA FOIS depuis l'intérieur de handle_camera_configure()/
# handle_camera_mask() (déjà sous ce verrou) ET depuis d'autres call sites qui ne
# l'ont jamais pris — Lock aurait provoqué un deadlock immédiat sur le 1er cas.
_camera_configure_lock = threading.RLock()

# Audit add-on 2026-09-22 : _scan_onvif_cameras()/_subnet_onvif_scan() lancent
# jusqu'à ~2×254 threads (un scan complet du /24 local, 2 ports par IP) sans
# aucune protection contre un 2e appel concurrent — deux requêtes /camera/scan
# simultanées (double-clic, appel automatisé répété) pouvaient cumuler jusqu'à
# ~1000 threads sur un Raspberry Pi. Lock simple (pas RLock, jamais rappelé
# depuis l'intérieur d'un scan) : un 2e scan pendant qu'un premier tourne est
# refusé plutôt que d'empiler les threads.
_camera_scan_lock = threading.Lock()

# Un seul commissioning Matter à la fois (matter-server ne sait pas gérer 2 sessions
# PASE simultanées vers le même discriminator — vu en test réel : 2 requêtes à 1s
# d'intervalle, le device a bien été commissionné mais les 2 connexions WS de l'addon
# ont chacune reçu un échec — l'une un vrai rejet matter-server côté discovery,
# l'autre un simple timeout local sans jamais recevoir la vraie réponse. Rejeter
# immédiatement la 2e requête plutôt que de laisser les 2 se percuter.
_matter_commission_lock = threading.Lock()

# Identifiants ICE WebRTC (STUN + TURN Cloudflare Realtime) injectés dans go2rtc via
# frigate.yml — rafraîchis périodiquement par _turn_refresh_loop() (cf. plus bas).
_TURN_REFRESH_INTERVAL = 24 * 3600  # 24h — identifiants Cloudflare valables 48h max
_turn_ice_servers: list[dict] = []

# Client MQTT local (Mosquitto, Z2M ↔ HA) — plus de client cloud, EMQX est retiré.
_local_client: mqtt.Client | None = None

# Cache court des capacités ONVIF détectées par le dernier scan réseau, par IP —
# cf. _safe_probe_capabilities. Évite une 2e salve de connexions ONVIF vers la même
# caméra quelques secondes après le scan (au moment du "Tester la connexion" lors de
# l'ajout), qui entre en collision avec la caméra encore occupée par le scan et fait
# échouer la détection silencieusement (confirmé en conditions réelles le 2026-07-23,
# persistait même avec un retry — cf. HANDOFF §68/§69).
_SCAN_CAPABILITIES_CACHE_TTL = 120.0  # secondes
_scan_capabilities_cache: dict[str, tuple[float, list]] = {}


def _log_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

def log(msg):  print(f"[domoticium] {_log_ts()} {msg}", flush=True)
def warn(msg): print(f"[domoticium] {_log_ts()} ⚠ {msg}", file=sys.stderr, flush=True)


# Audit add-on 2026-09-22 : jusqu'ici, les commandes reçues par _CommandHandler
# (serveur HTTP local, seul point d'entrée cloud → Pi) n'étaient tracées que dans
# le log général de l'add-on — capturé par HA sous forme de ring buffer éphémère
# (perdu au redémarrage, aucun moyen de retrouver "qu'est-ce qui a été exécuté sur
# ce site hier"). Fichier dédié, tournant (jamais illimité), séparé du log
# général — délibérément SANS le corps de la requête (route + adresse + verdict
# seulement) : plusieurs routes transportent des secrets en clair dans leur payload
# (delegatedRefreshToken, rtspUrl, codes PIN Alarmo…) — même prudence que
# _redact_rtsp_credentials pour _go2rtc_upsert_stream, mais ici on évite carrément
# de capturer la donnée sensible plutôt que de la rédiger après coup.
_COMMAND_AUDIT_LOG = "/data/command_audit.log"
_command_audit_logger = logging.getLogger("domoticium.command_audit")
_command_audit_logger.setLevel(logging.INFO)
_command_audit_logger.propagate = False
_command_audit_handler = logging.handlers.RotatingFileHandler(
    _COMMAND_AUDIT_LOG, maxBytes=1_000_000, backupCount=2,
)
_command_audit_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S"))
_command_audit_logger.addHandler(_command_audit_handler)


def _audit_command(route: str, remote_addr: str, verdict: str):
    """verdict : 'ok' (traitée), 'rejected:<raison>' (auth/route/format)."""
    try:
        _command_audit_logger.info(f"{remote_addr} {route} {verdict}")
    except Exception:
        pass  # l'audit ne doit jamais faire échouer une commande légitime


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

# Point 4 (audit add-on 2026-09-22) : _setup_step() ne retry que les ÉTAPES de
# run_setup() (la fonction entière, via check_fn) — un hoquet réseau transitoire
# (timeout/connexion refusée) sur UN appel Supervisor fait hors de run_setup()
# (watchdog, restart_frigate, bascule BLE Matter, logs…) remontait tel quel et
# plantait la fonction appelante, sans aucun filet. Retry ici, au niveau des
# primitives elles-mêmes, plutôt qu'à chaque site d'appel (~40 occurrences,
# logiques de contrôle différentes selon le site) : ne retry QUE les erreurs
# réseau/connexion (requests.exceptions.RequestException), jamais sur la base
# d'un code HTTP — de nombreux appelants testent déjà `r.ok`/`r.status_code`
# pour de la vraie logique métier (ex: "addon pas encore installé"), jamais une
# erreur transitoire. _setup_step() continue d'apporter sa propre couche
# (ré-essayer toute l'étape, idempotente) par-dessus, sans conflit.
def _sup_request_with_retry(method, url, retries, **kwargs):
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return method(url, **kwargs)
        except requests.exceptions.RequestException as e:
            last_exc = e
            if attempt < retries:
                time.sleep(2)
    raise last_exc

def sup_get(path, retries=2):
    return _sup_request_with_retry(requests.get, f"{SUP}{path}", retries, headers=HDRS, timeout=15)

def sup_post(path, data=None, timeout=60, retries=2):
    return _sup_request_with_retry(requests.post, f"{SUP}{path}", retries, headers=HDRS, json=data or {}, timeout=timeout)

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


def _ha_ws_connect(long_lived: bool = False, access_token: str = None, host: str = "supervisor",
                    port: int = 80, path: str = "/core/websocket"):
    """Ouvre et authentifie une session WebSocket HA.
    Retourne (ws_send, ws_recv, ws_close) ou (None, None, None) en cas d'erreur.
    ws_send(data: dict) — inclure {"id": N} dans data.
    ws_recv() → dict.
    long_lived=True (ex: run_ha_ws_bridge) : retire le timeout après l'auth — sinon le
    timeout de connexion (15s) s'applique aussi aux recv() suivants, et une simple absence
    d'événement HA pendant 15s est prise pour une erreur de connexion (reconnexion en boucle).

    access_token/host/port/path : par défaut (SUPERVISOR_TOKEN, "supervisor"/80/"/core/websocket")
    — connexion authentifiée en tant qu'add-on via le proxy du Supervisor, comportement
    inchangé pour tous les appelants existants.

    ⚠️ 2026-09-12 (accès distant technicien) — piège réel trouvé en lisant le code source du
    Supervisor (github.com/home-assistant/supervisor, supervisor/api/proxy.py) : la méthode
    `websocket()` de ce proxy fait SA PROPRE authentification préalable via
    `self.sys_apps.from_token(supervisor_token)` — elle n'accepte QUE des jetons enregistrés
    par le Supervisor pour CET add-on précis (ex. SUPERVISOR_TOKEN), jamais un jeton HA
    utilisateur arbitraire (comme le refresh_token délégué du client, converti en access_token
    via /auth/token) — même chose côté REST (`/core/api/*` : la requête réelle vers HA Core
    part toujours avec l'identité PROPRE du Supervisor, l'Authorization de l'appelant ne sert
    qu'à valider l'accès AU PROXY lui-même). Concrètement : impossible de créer un LLAT lié à
    un utilisateur HA précis en passant par ce proxy, quel que soit le jeton présenté.
    D'où les paramètres host/port/path ci-dessus : `_handle_ha_session_token_create`/`_revoke`
    passent `host="127.0.0.1", port=8123, path="/api/websocket"` — connexion DIRECTE à HA Core
    (possible car `host_network: true` dans config.yaml, cet add-on partage la pile réseau de
    l'hôte, donc 127.0.0.1:8123 est le vrai port d'écoute de Home Assistant Core, pas besoin du
    Supervisor) — HA Core authentifie alors réellement le jeton comme un jeton utilisateur
    normal, exactement le comportement voulu, plutôt que le pré-filtre du Supervisor.
    """
    try:
        s = socket.create_connection((host, port), timeout=15)

        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall((
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
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
        _send({"type": "auth", "access_token": access_token or SUPERVISOR_TOKEN})
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

def _ha_mint_access_token(refresh_token: str) -> str:
    """Échange un refresh_token OAuth2 délégué (consentement client, cf. HANDOFF côté
    web/project-remote-ha-access-consent) contre un access_token HA de courte durée.
    Miroir exact de mintHaAccessToken() dans web/src/lib/ha/delegatedSession.ts — même
    endpoint, même client_id — exécuté ICI (en local, sur le Pi) plutôt que depuis Vercel
    pour l'accès distant technicien (2026-09-12, cf. _handle_ha_session_token_create).

    ⚠️ Appel DIRECT à HA Core (127.0.0.1:8123), PAS via {SUP}/core/api — le proxy du
    Supervisor pour /core/api/{path} préfixe systématiquement "api/" (donc /core/api/auth/token
    viserait .../api/auth/token, qui n'existe pas — le vrai endpoint HA est /auth/token, hors
    /api/) ET, même avec le bon chemin, ce proxy fait toujours la requête réelle vers HA Core
    avec l'identité PROPRE du Supervisor, jamais avec les identifiants de l'appelant — cf.
    commentaire détaillé dans _ha_ws_connect(). 127.0.0.1:8123 fonctionne car
    host_network: true (config.yaml) fait partager à cet add-on la pile réseau de l'hôte,
    où Home Assistant Core écoute réellement."""
    resp = requests.post(
        f"http://127.0.0.1:{_ha_core_port()}/auth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": f"{APP_URL}/",
        },
        timeout=15,
    )
    try:
        body = resp.json()
    except Exception:
        body = {}
    if not resp.ok or not body.get("access_token"):
        raise Exception(f"Rafraîchissement du jeton HA échoué: {body.get('error') or resp.status_code}")
    return body["access_token"]


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

def _save_cameras():
    with open(CAMERAS_FILE, "w") as f:
        json.dump(_cameras, f)


def _load_camera_masks():
    global _camera_masks
    try:
        with open(CAMERA_MASKS_FILE) as f:
            _camera_masks = json.load(f)
    except FileNotFoundError:
        _camera_masks = {}


def _save_camera_masks():
    with open(CAMERA_MASKS_FILE, "w") as f:
        json.dump(_camera_masks, f)


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
        # Détection en ligne/hors ligne fiable par appareil — fonctionnalité native
        # Z2M (pas une heuristique maison) : ping actif pour les appareils secteur
        # (10 min par défaut). Pour les appareils à pile, Z2M ne les ping JAMAIS
        # (impossible physiquement — un end-device Zigbee dort la plupart du
        # temps) — le délai "passive" par défaut (25h) reste volontairement
        # INCHANGÉ : vérifié dans zigbee-herdsman-converters que la plupart des
        # appareils à pile utilisent un plafond de rapport périodique standard
        # de ~65000s (~18h03, repInterval.MAX, cf. lib/constants.ts) — le défaut
        # Z2M de 25h semble précisément choisi pour couvrir ce plafond avec de
        # la marge. Un réglage plus court (1h, essayé puis abandonné) aurait
        # déclenché des faux "hors ligne" sur la plupart des appareils sains
        # (2026-07-30, cf. HANDOFF §111/§112).
        "availability": {"enabled": True},
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


def _ensure_z2m_availability():
    """Patch one-shot pour les sites déjà provisionnés (install_zigbee2mqtt() ne
    tourne qu'à la toute première installation, cf. run_setup()) : ajoute/corrige
    le bloc "availability" de la configuration.yaml existante, puis redémarre Z2M
    pour l'appliquer. Idempotent — appelé à chaque démarrage de l'addon comme
    install_alarmo(), devient un no-op une fois à jour. Remplacement de
    sous-chaîne exacte plutôt qu'un parsing YAML complet : jamais de valeur
    modifiée à l'aveugle — pas le risque de repliage/corruption déjà rencontré
    avec ruamel.yaml côté Frigate (cf. HANDOFF §58-66).

    Cible = "enabled: true" SEUL, sans surcharge "passive.timeout" — v2.9.71
    avait réduit ce délai à 1h (déjà déployé un temps), mais vérifié ensuite
    que la plupart des appareils à pile utilisent un plafond de rapport
    périodique standard de ~65000s/~18h03 (repInterval.MAX, zigbee-herdsman-
    converters) : le défaut Z2M de 25h semble précisément choisi pour couvrir
    ce plafond avec de la marge, 1h aurait donc déclenché des faux "hors
    ligne" sur la plupart des appareils sains — revenu au défaut Z2M
    (2026-07-30, cf. HANDOFF §111/§112)."""
    cfg_path = "/homeassistant/zigbee2mqtt/configuration.yaml"
    try:
        with open(cfg_path) as f:
            content = f.read()
    except FileNotFoundError:
        return  # Z2M pas encore installé

    target_block = "\navailability:\n  enabled: true\n"
    v2_9_71_block = "\navailability:\n  enabled: true\n  passive:\n    timeout: 60\n"

    if target_block in content and v2_9_71_block not in content:
        return  # déjà au bon état (nouvelle installation, ou déjà corrigé)
    if v2_9_71_block in content:
        content = content.replace(v2_9_71_block, target_block)  # rollback depuis v2.9.71
    elif "availability:" in content:
        # Forme inattendue (édition manuelle ?) — on ne touche à rien plutôt que
        # de risquer une corruption sur un contenu qu'on ne reconnaît pas.
        return
    else:
        content += target_block

    with open(cfg_path, "w") as f:
        f.write(content)
    log("✓ [z2m] Fonctionnalité 'availability' activée/corrigée (délais par défaut Z2M)")

    r = sup_post(f"/addons/{Z2M_SLUG}/restart")
    if r.ok:
        log("✓ [z2m] Redémarré pour appliquer 'availability'")
    else:
        warn(f"✗ [z2m] Redémarrage après activation availability : {r.status_code} {r.text[:150]}")


# ── Matter Server ─────────────────────────────────────────────────────────────

def _wait_matter_server_ready(max_attempts: int = 12) -> bool:
    """Attend jusqu'à ~24s que matter-server accepte des connexions TCP sur
    localhost:5580 (même port que _matter_ws_connect). Audit add-on 2026-09-22 :
    install_matter_server() enchaînait auparavant restart → création immédiate
    de l'intégration HA "matter" SANS attendre, contrairement à Frigate
    (_wait_frigate_ready) — un restart frais prend quelques secondes à ouvrir
    son port WS, donc la création d'intégration échouait souvent en silence
    (retombait sur "à activer manuellement si besoin", déjà vu en usage réel).
    Simple connect TCP (pas le handshake WS complet de _matter_ws_connect) :
    suffisant pour savoir si le port écoute, sans le coût d'un aller-retour
    protocolaire complet à chaque tentative."""
    for i in range(max_attempts):
        try:
            s = socket.create_connection(("localhost", 5580), timeout=2)
            s.close()
            log(f"✓ matter-server opérationnel (:5580, ~{i * 2}s)")
            return True
        except OSError:
            time.sleep(2)
    warn("matter-server pas disponible sur :5580 après ~24s — intégration HA tentée quand même")
    return False


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

    _wait_matter_server_ready()

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
    _load_camera_masks()
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
    _load_camera_masks()
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
    _load_camera_masks()
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


def _resolve_local_web_slug(attempts: int = 4, delay: float = 5.0) -> bool:
    """Détermine le VRAI slug de l'add-on "Domoticium — Accès local" installable
    depuis LOCAL_WEB_REPO — même technique et même prudence que
    _resolve_frigate_slug() (deviner le hash du dépôt a déjà été faux une fois
    en prod, cf. commentaire de FRIGATE_SLUG). Met à jour la variable globale
    LOCAL_WEB_SLUG si trouvé."""
    global LOCAL_WEB_SLUG
    for attempt in range(1, attempts + 1):
        try:
            r = sup_get("/store/repositories")
            body = r.json()
            repos = body.get("data", body) if isinstance(body, dict) else body
            repos = repos.get("repositories", repos) if isinstance(repos, dict) else repos
            repo_slug = next(
                (repo.get("slug") for repo in repos
                 if isinstance(repo, dict) and repo.get("source") == LOCAL_WEB_REPO),
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
                        and str(addon.get("slug", "")).endswith("_domoticium_web")
                    ):
                        LOCAL_WEB_SLUG = addon["slug"]
                        log(f"[local-web] Slug résolu dynamiquement : {LOCAL_WEB_SLUG}")
                        return True
        except Exception as e:
            warn(f"[local-web] Résolution du slug (tentative {attempt}/{attempts}) : {e}")
        if attempt < attempts:
            time.sleep(delay)
    warn("[local-web] Impossible de résoudre le slug depuis le store — utilisation du fallback codé en dur")
    return False


def install_local_web_addon():
    """Installe ET met à jour automatiquement l'add-on "Domoticium — Accès
    local" (chantier 2026-09-06, cf. HANDOFF.md côté web) — même schéma que
    install_frigate() pour un dépôt tiers, en plus simple (pas de config à
    écrire avant installation, pas de logique de réinstallation en cas
    d'échec — à ajouter plus tard si un vrai besoin apparaît en conditions
    réelles, pas anticipé sans preuve).

    Idempotent — appelé à chaque démarrage de l'addon, comme install_alarmo().
    Transmet automatiquement ingest_secret (déjà connu de CET addon) aux
    options du nouvel add-on — aucune saisie manuelle pour Hicham, jamais.
    """
    log("── Domoticium — Accès local ─────────────────")

    existing_urls = _sup_repos()
    if LOCAL_WEB_REPO not in existing_urls:
        r = sup_post("/store/repositories", {"repository": LOCAL_WEB_REPO})
        if r.ok:
            log("✓ Dépôt Accès local ajouté")
            time.sleep(5)
        else:
            warn(f"Dépôt Accès local : {r.status_code} {r.text[:200]} — on continue")
    else:
        r = sup_post("/store/reload", timeout=60)
        log(f"[local-web] Rafraîchissement du store → {r.status_code}")

    _resolve_local_web_slug()

    if not _is_addon_installed(LOCAL_WEB_SLUG):
        log("Installation de l'add-on Accès local…")
        r = sup_post(f"/store/addons/{LOCAL_WEB_SLUG}/install", timeout=180)
        if not (r.ok or "already_installed" in r.text or "already installed" in r.text.lower()):
            warn(f"Installation Accès local : {r.status_code} {r.text[:200]}")
            return
        log("✓ Add-on Accès local installé")
        time.sleep(5)
    else:
        log("Add-on Accès local déjà installé")

    # ingest_secret transmis à chaque démarrage (pas seulement à l'install) —
    # couvre le cas d'une rotation future du secret côté site, idempotent si
    # inchangé (mêmes options réécrites, sans effet).
    # go2rtc_password (2026-09-08, chantier caméras locales) : même
    # mécanisme — GO2RTC_API_PASSWORD est déjà connu de CET addon (généré/
    # persisté une fois dans /data/go2rtc_api_pass, cf. plus haut), jamais
    # saisi à la main par Hicham. Sans ça, l'add-on local ne peut pas
    # s'authentifier auprès de go2rtc (127.0.0.1:1984, exige Basic Auth
    # depuis le fix sécurité du 2026-09-07) — caméras locales muettes.
    r = sup_post(f"/addons/{LOCAL_WEB_SLUG}/options", {
        "options": {
            "ingest_secret": INGEST_SECRET,
            "site_prefix": SITE_PREFIX,
            "go2rtc_password": GO2RTC_API_PASSWORD,
        }
    })
    if not r.ok:
        warn(f"[local-web] Écriture ingest_secret : {r.status_code} {r.text[:200]}")

    r = sup_post(f"/addons/{LOCAL_WEB_SLUG}/start")
    if r.ok or "already" in r.text.lower():
        log("✓ Add-on Accès local démarré")
    else:
        warn(f"[local-web] Démarrage : {r.status_code} {r.text[:200]}")


_FRIGATE_AUTH_MARKER = "/data/.frigate_auth_disabled"


def _has_turn(servers: list[dict]) -> bool:
    """True si la liste contient un vrai serveur TURN (pas seulement le repli STUN)."""
    return any(s.get("credential") for s in servers)


# ── Passerelle API : laissez-passer du site ─────────────────────────────────────
# Le Pi n'a AUCUNE clé de fournisseur. Il présente à la passerelle (Worker Cloudflare) un « laissez-passer »
# signé par le portail, obtenu une fois avec le secret du site (POST APP_URL/api/ingest/gateway-pass), conservé
# sur disque et renouvelé dès qu'il a plus de 30 jours. Même logique que l'app locale du Pi
# (web/src/lib/local/gateway.ts) : le fonctionnement courant ne dépend ni de Vercel ni de Supabase.
_GATEWAY_PASS_FILE = "/data/gateway-pass.json"
# Laissez-passer de 14 jours, renouvelé dès qu'il a plus d'UN jour (14 − 13) : c'est aussi comme ça que le boîtier apprend qu'un
# abonnement est suspendu (le portail répond 402 au lieu d'un laissez-passer) ; portail injoignable → l'ancien sert jusqu'à son
# expiration (13 jours de marge).
_GATEWAY_PASS_RENEW_WITHIN_S = 13 * 86400
_GATEWAY_PASS_MAX_AGE_S = 14 * 86400  # durée de vie des laissez-passer actuels
# Abonnement suspendu (décision d'Hicham, 2026-11-20) : services cloud coupés (passerelle, e-mails, accès à distance), usage LOCAL
# intact. Plus aucun appel à la passerelle ; le portail est re-sondé toutes les 30 min (un réabonnement se voit vite).
_GATEWAY_ENTITLEMENT_FILE = "/data/entitlement.json"
_GATEWAY_SUSPENDED_RECHECK_S = 1800
_gateway_ent = {"loaded": False, "suspended": False, "since": None, "next_check": 0.0}
_GATEWAY_PASS_RETRY_S = 600  # pas plus d'un essai toutes les 10 min après un échec ou un refus
_gateway_pass_lock = threading.Lock()
_gateway_pass_state = {"pass": None, "exp": 0.0, "loaded": False, "next_attempt": 0.0}


def _gateway_pass_load() -> tuple[str | None, float]:
    try:
        with open(_GATEWAY_PASS_FILE) as f:
            d = json.load(f)
        if isinstance(d.get("pass"), str) and isinstance(d.get("expiresAt"), (int, float)):
            return d["pass"], float(d["expiresAt"])
    except Exception:
        pass
    return None, 0.0


def _gateway_pass_save(token: str, exp: float) -> None:
    try:
        tmp = _GATEWAY_PASS_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"pass": token, "expiresAt": exp}, f)
        os.replace(tmp, _GATEWAY_PASS_FILE)
    except Exception as e:
        warn(f"[gateway] écriture du laissez-passer impossible : {e}")  # reste en mémoire, redemandé au prochain démarrage


def _gateway_ent_load() -> None:
    if _gateway_ent["loaded"]:
        return
    _gateway_ent["loaded"] = True
    try:
        with open(_GATEWAY_ENTITLEMENT_FILE) as f:
            d = json.load(f)
        # Un état « suspendu » écrit avant 2.9.258 n'a pas de drapeau « explicit » : il a pu venir d'un faux 402 de l'hébergeur du
        # portail. On ne le croit donc pas ; si la suspension est réelle, le prochain contrôle (≤ 90 s) la réécrit avec le drapeau.
        _gateway_ent["suspended"] = d.get("suspended") is True and d.get("explicit") is True
        _gateway_ent["since"] = d.get("since") if isinstance(d.get("since"), (int, float)) else None
    except Exception:
        pass


def _gateway_is_suspended() -> bool:
    """Vrai si le portail a signifié que l'abonnement est suspendu (état conservé sur disque entre deux redémarrages)."""
    _gateway_ent_load()
    return bool(_gateway_ent["suspended"])


def _gateway_set_suspended(suspended: bool) -> None:
    _gateway_ent_load()
    if _gateway_ent["suspended"] == suspended:
        return
    _gateway_ent["suspended"] = suspended
    _gateway_ent["since"] = int(time.time()) if suspended else None
    try:
        tmp = _GATEWAY_ENTITLEMENT_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"suspended": suspended, "since": _gateway_ent["since"], "explicit": True}, f)
        os.replace(tmp, _GATEWAY_ENTITLEMENT_FILE)
    except Exception as e:
        warn(f"[gateway] écriture de l'état d'abonnement impossible : {e}")
    if suspended:
        warn("[gateway] abonnement suspendu : services cloud coupés (l'usage local reste intact)")
        _gateway_pass_state["pass"], _gateway_pass_state["exp"] = None, 0.0
        try:
            os.remove(_GATEWAY_PASS_FILE)
        except OSError:
            pass
    else:
        log("[gateway] abonnement de nouveau actif : services cloud rétablis")


def _gateway_pass_request() -> tuple[str, tuple[str, float] | None]:
    """('ok', (laissez-passer, expiration)) | ('suspended', None) | ('error', None)."""
    if not INGEST_SECRET or not SITE_PREFIX:
        return "error", None
    try:
        r = _cloud_post(
            "vercel:ingest/gateway-pass",
            f"{APP_URL}/api/ingest/gateway-pass",
            json={"siteSecret": INGEST_SECRET, "siteId": SITE_PREFIX},
            timeout=15,
        )
        if r.status_code == 402:
            # Seul NOTRE refus explicite signifie « abonnement suspendu ». Un 402 sans ce motif vient de l'hébergeur du portail
            # (Vercel : 402 DEPLOYMENT_DISABLED quand le compte dépasse ses limites, constaté le 2026-11-24 — le boîtier de test
            # s'était alors déclaré « suspendu » alors que le client payait). Ce n'est pas une suspension.
            try:
                body = r.json()
            except Exception:
                body = None
            if isinstance(body, dict) and body.get("error") == "subscription_suspended":
                return "suspended", None
            warn("[gateway] HTTP 402 sans le motif « subscription_suspended » (hébergeur du portail indisponible ?) — pas une suspension")
            return "error", None
        if not r.ok:
            warn(f"[gateway] laissez-passer refusé par le portail : HTTP {r.status_code}")
            return "error", None
        d = r.json()
        if isinstance(d.get("pass"), str) and isinstance(d.get("expiresAt"), (int, float)):
            return "ok", (d["pass"], float(d["expiresAt"]))
    except Exception as e:
        warn(f"[gateway] portail injoignable pour le laissez-passer : {e}")
    return "error", None


def _gateway_get_pass(force: bool = False) -> str | None:
    """Laissez-passer utilisable, ou None. `force` = le précédent vient d'être refusé : en redemander un."""
    with _gateway_pass_lock:
        st = _gateway_pass_state
        if not st["loaded"]:
            st["pass"], st["exp"] = _gateway_pass_load()
            st["loaded"] = True
        now = time.time()
        if _gateway_is_suspended():
            if now < _gateway_ent["next_check"]:
                return None
            _gateway_ent["next_check"] = now + _GATEWAY_SUSPENDED_RECHECK_S
            kind, got = _gateway_pass_request()
            if kind != "ok" or not got:
                return None
            _gateway_set_suspended(False)
            st["pass"], st["exp"] = got
            _gateway_pass_save(*got)
            return st["pass"]
        valid = bool(st["pass"]) and st["exp"] > now + 60
        # « Frais » = émis il y a moins d'un jour (13 à 14 jours restants). Un laissez-passer qui en a PLUS est un ancien (180 jours,
        # émis avant le passage à 14 jours) : il ne serait jamais renouvelé de lui-même et le boîtier n'apprendrait jamais une
        # suspension → renouvelé tout de suite (tolérance d'1 h sur l'horloge).
        fresh = valid and _GATEWAY_PASS_RENEW_WITHIN_S < st["exp"] - now <= _GATEWAY_PASS_MAX_AGE_S + 3600
        if fresh and not force:
            return st["pass"]
        if now >= st["next_attempt"]:
            kind, got = _gateway_pass_request()
            if kind == "suspended":
                _gateway_set_suspended(True)
                _gateway_ent["next_check"] = now + _GATEWAY_SUSPENDED_RECHECK_S
                return None
            if got:
                st["pass"], st["exp"] = got
                _gateway_pass_save(*got)
            # Après un échec OU un renouvellement forcé (l'ancien venait d'être refusé) : 10 min de répit —
            # un site bloqué par la passerelle ne doit pas rappeler le portail à chaque tentative.
            if not got or force:
                st["next_attempt"] = now + _GATEWAY_PASS_RETRY_S
            if got:
                return st["pass"]
        return st["pass"] if (valid and not force) else None


def handle_local_entitlement() -> dict:
    """État d'abonnement connu du boîtier — lu par l'app du foyer (bandeau « Abonnement suspendu », refus de l'accès à distance).
    L'add-on principal est la SEULE autorité : c'est lui qui interroge le portail, en tâche de fond (cf. _run_entitlement_loop)."""
    _gateway_ent_load()
    return {"suspended": bool(_gateway_ent["suspended"]), "since": _gateway_ent["since"]}


def _entitlement_check_now() -> dict:
    """Interroge le portail MAINTENANT (laissez-passer) : 402 → suspendu ; laissez-passer reçu → actif (et conservé) ; panne du
    portail → l'état connu ne change pas (une panne ne suspend personne)."""
    with _gateway_pass_lock:
        st = _gateway_pass_state
        kind, got = _gateway_pass_request()
        if kind == "suspended":
            _gateway_set_suspended(True)
            _gateway_ent["next_check"] = time.time() + _GATEWAY_SUSPENDED_RECHECK_S
        elif kind == "ok" and got:
            _gateway_set_suspended(False)
            st["pass"], st["exp"], st["loaded"] = got[0], got[1], True
            _gateway_pass_save(*got)
    return handle_local_entitlement()


_ENTITLEMENT_LOOP_PERIOD_S = 3600
_entitlement_last_forced = [0.0]


def handle_local_entitlement_recheck() -> dict:
    """« J'ai payé : vérifier » — re-vérification immédiate, au plus une fois par minute."""
    if time.time() - _entitlement_last_forced[0] >= 60:
        _entitlement_last_forced[0] = time.time()
        return _entitlement_check_now()
    return handle_local_entitlement()


def _run_entitlement_loop(sleep=None, max_loops=None):
    """Thread permanent : interroge le portail TOUTES LES HEURES (et 90 s après le démarrage), qu'un service cloud soit utilisé
    ou non. Sans ça, une tablette murale allumée 24 h/24 n'apprendrait la suspension (ou le réabonnement) qu'au prochain besoin
    de la passerelle, parfois un jour plus tard. Latence maximale : 1 h (immédiate avec le bouton du bandeau)."""
    sleep = sleep or time.sleep
    sleep(90)
    loops = 0
    while max_loops is None or loops < max_loops:
        loops += 1
        try:
            _entitlement_check_now()
        except Exception as e:
            warn(f"[entitlement] cycle échoué (poursuite au prochain) : {e}")
        sleep(_ENTITLEMENT_LOOP_PERIOD_S)


def _gateway_request(method: str, route: str, params: dict | None = None, body: dict | None = None,
                     timeout: int = 15) -> tuple[int, dict | None]:
    """Requête JSON sur la passerelle → (code HTTP, corps JSON ou None). Code 0 = indisponible (pas de
    laissez-passer, réseau, délai). Un 401 (laissez-passer périmé ou clé de signature renouvelée) déclenche UN
    nouveau laissez-passer puis un nouvel essai."""
    used = None
    for attempt in (0, 1):
        force = attempt == 1 and used is not None and _gateway_pass_state["pass"] == used
        token = _gateway_get_pass(force)
        if not token:
            return (402 if _gateway_is_suspended() else 0), None
        used = token
        try:
            r = requests.request(method, f"{GATEWAY_URL}{route}", params=params or {}, json=body,
                                 headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        except Exception as e:
            warn(f"[gateway] {route} : {e}")
            _cloud_note(f"gateway:{method} {route}", len(json.dumps(body, default=str)) if body is not None else 0, 0, False)
            return 0, None
        _cloud_note(f"gateway:{method} {route}", len(r.request.body or b"") if getattr(r, "request", None) is not None else 0, len(r.content or b""), r.ok)
        if r.status_code == 401 and attempt == 0:
            continue
        if not r.ok:
            warn(f"[gateway] {route} : HTTP {r.status_code}")
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None
    return 0, None


def _gateway_get(route: str, params: dict | None = None, timeout: int = 15) -> dict | None:
    """GET JSON sur la passerelle : le corps si 2xx, None sinon."""
    status, data = _gateway_request("GET", route, params=params, timeout=timeout)
    return data if 200 <= status < 300 else None


def _fetch_turn_ice_servers() -> list[dict] | None:
    """Récupère des identifiants TURN Cloudflare Realtime de courte durée (48 h, rafraîchis toutes les 24 h)
    via la PASSERELLE API (secret Cloudflare — TURN_KEY_API_TOKEN — jamais exposé à l'addon ; avant le lot C du
    chantier « Pi-first », route Vercel /api/ingest/webrtc-credentials). Retourne None en cas d'échec (réseau,
    passerelle, quota…) — à distinguer d'un repli STUN volontaire : _turn_refresh_loop()
    ne doit PAS redémarrer Frigate sur un échec transitoire de ce fetch (bug corrigé
    le 2026-07-19 : un simple hoquet réseau faisait passer _turn_ice_servers d'un
    vrai TURN à un repli STUN, détecté comme un "changement" → redémarrage Frigate
    inutile → coupure caméra réelle → fausse alerte "hors ligne" envoyée au client)."""
    if not INGEST_SECRET:
        return None
    # 10 s : cet appel est SYNCHRONE au démarrage (run_bridge) — le pire cas reste ~15 s, comme avant.
    data = _gateway_get("/v1/turn", {"ttl": 172800}, timeout=10)
    if data is None:
        warn("[webrtc] identifiants TURN indisponibles (passerelle)")
        return None
    ice = data.get("iceServers")
    if not ice or not ice.get("urls"):
        return [{"urls": ["stun:stun.cloudflare.com:3478"]}]
    return [{"urls": ["stun:stun.cloudflare.com:3478"]}, ice]


def _yaml_dq(value: str) -> str:
    """Échappe une valeur pour un scalaire YAML entre guillemets doubles (point 1,
    audit add-on 2026-09-22) — ce fichier construit son YAML par concaténation de
    f-strings, jamais via une bibliothèque YAML. handle_camera_configure() interdit
    déjà \\n/\\r dans rtsp_url (seule injection de CLÉ possible dans ce générateur,
    déjà fermée), mais un `"` dans une valeur non sous notre contrôle (identifiants
    ONVIF extraits de rtsp_url, eux-mêmes saisis par le client à l'ajout d'une
    caméra) casserait le scalaire et invaliderait tout frigate.yml — pas une
    injection de clé (les guillemets ouvrants/fermants interdisent déjà toute
    syntaxe YAML de mapping sur une même ligne physique), mais un déni de service
    du parsing qui couperait TOUTES les caméras du site, pas seulement celle en
    cause."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


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

    Clé api (origin/username/password) le 2026-09-07 — anciennement un bloc
    séparé ("go2rtc: / api: / origin: '*'", juste avant l'appel à cette
    fonction) datant du 2026-07-22 (l'injection automatique par create_config.py,
    qui n'a lieu QUE si go2rtc.api est absent de la config, avait été trouvée
    insuffisante en conditions réelles — rejet WebSocket persistant). Fusionné
    ICI (une seule clé "api:" par section go2rtc — deux clés identiques dans le
    même mapping produiraient un YAML ambigu) pour ajouter username/password
    (cf. HANDOFF.md : go2rtc:1984 accessible sans authentification à quiconque
    sur le réseau local, identifiants RTSP/ONVIF en clair via /api/streams).
    `origin: "*"` reste nécessaire pour la même raison qu'avant : sans lui,
    go2rtc applique un contrôle same-origin strict sur son WebSocket de
    signalisation (cf. internal/api/ws/ws.go côté go2rtc) qui rejette
    app.domoticium.fr (origine différente du nom d'hôte du tunnel Cloudflare).

    1er essai (même jour) : compter sur l'exemption "127.0.0.1 passe toujours
    sans mot de passe" documentée par go2rtc — DÉPLOYÉ PUIS ANNULÉ, cassait la
    vue caméra cloud réelle (le relais tunnel _Go2rtcProxyHandler recevait 401
    malgré sa connexion depuis 127.0.0.1). Vraie cause trouvée en lisant le
    code source réel de la version déployée (v1.9.10, pas juste la doc) :
    `middlewareAuth()` compare bien `r.RemoteAddr` à un préfixe "127." — mais
    Frigate (donc go2rtc embarqué) tourne en réseau Docker ISOLÉ
    (host_network: false dans son propre config.yaml, déjà noté plus haut dans
    ce fichier) : TOUT appelant EXTÉRIEUR au conteneur Frigate — l'addon
    Domoticium (host_network: true) ET le relais tunnel, MÊME en visant
    "127.0.0.1:1984" côté appelant — traverse le NAT du pont Docker pour
    atteindre le port publié, qui réécrit l'adresse source en l'IP de la
    passerelle du pont (ex: 172.17.0.1), jamais 127.x, AVANT que go2rtc ne la
    voie. Aucun appelant EXTÉRIEUR à ce conteneur ne peut donc jamais
    apparaître "local" à ses yeux, quelle que soit l'adresse visée côté
    appelant — comportement Docker connu (hairpin NAT), pas un bug go2rtc.
    Vrai fix : présenter le mot de passe explicitement plutôt que compter sur
    une exemption qui ne peut pas s'appliquer ici — cf. GO2RTC_API_AUTH,
    ajouté aux requêtes de l'addon (_go2rtc_upsert_stream etc.) ET injecté par
    _Go2rtcProxyHandler dans chaque requête relayée pour le tunnel."""
    lines = [
        "  api:",
        '    username: "domoticium"',
        f'    password: "{GO2RTC_API_PASSWORD}"',
        '    origin: "*"',
        "  webrtc:",
        '    listen: "0.0.0.0:8555"',
        "    filters:",
        "      networks: [udp4, tcp4]",
        "    ice_servers:",
    ]
    # urls en style bloc (une entrée par ligne), PAS en style flow ("[url1, url2]")
    # — cause réelle de la corruption YAML observée au boot de go2rtc (cf. HANDOFF
    # §66) : create_config.py (script Frigate qui régénère /dev/shm/go2rtc.yaml)
    # charge notre frigate.yml puis le réécrit via ruamel.yaml, qui replie
    # automatiquement (largeur par défaut 80 caractères) toute liste flow-style trop
    # longue sur plusieurs lignes avec un format que le parseur YAML de Go (go2rtc)
    # rejette ("did not find expected ',' or ']'") — reproduit et confirmé en local.
    # N'apparaissait qu'avec un vrai serveur TURN (4 URLs, ligne > 80 caractères),
    # jamais avec le simple repli STUN (1 URL courte) : d'où le caractère
    # intermittent du bug qui a fait échouer toutes les tentatives précédentes basées
    # sur l'hypothèse d'un problème d'écriture/timing plutôt que de formatage.
    # Le style bloc place naturellement chaque URL sur sa propre ligne, quelle que
    # soit sa longueur — ruamel n'a alors jamais besoin de replier quoi que ce soit.
    for server in (_turn_ice_servers or [{"urls": ["stun:stun.cloudflare.com:3478"]}]):
        urls = server.get("urls", [])
        if isinstance(urls, str):
            urls = [urls]
        lines.append("      - urls:")
        for u in urls:
            lines.append(f'          - "{u}"')
        if server.get("username"):
            lines.append(f'        username: "{_yaml_dq(server["username"])}"')
        if server.get("credential"):
            lines.append(f'        credential: "{_yaml_dq(server["credential"])}"')
    return lines


def _mask_ffmpeg_preset(rects: list[dict]) -> str:
    """Construit la valeur du préréglage ffmpeg go2rtc pour masquer une caméra (§93) :
    une chaîne de filtres 'drawbox' (un par rectangle, en fractions iw/ih — les
    variables ffmpeg pour la largeur/hauteur RÉELLES du flux décodé, donc indépendant
    de la résolution — fonctionne identiquement pour le flux principal et le sous-flux
    qualité §87/§88, sans connaître la résolution à l'avance) suivie d'un encodage
    vidéo réel : masquer des pixels impose de décoder puis ré-encoder (plus possible
    de rester en 'video=copy', cf. HANDOFF §93 sur le coût CPU — accepté par Hicham,
    limité aux caméras effectivement masquées). Réglages d'encodage repris du
    préréglage 'h264' intégré à go2rtc (internal/ffmpeg/ffmpeg.go) pour rester cohérent
    avec ce que go2rtc utiliserait lui-même par défaut."""
    boxes = ",".join(
        f"drawbox=x=iw*{r['x']}:y=ih*{r['y']}:w=iw*{r['w']}:h=ih*{r['h']}:color=black:t=fill"
        for r in rects
    )
    return (
        f"-vf {boxes} "
        "-c:v libx264 -g 50 -profile:v high -level:v 4.1 "
        "-preset:v superfast -tune:v zerolatency -pix_fmt:v yuv420p"
    )


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
        f'  user: "{_yaml_dq(MOSQUITTO_USER)}"',
        f'  password: "{_yaml_dq(MOSQUITTO_PASS)}"',
        "",
        # ⚠️ TEST TEMPORAIRE (2026-09-09, demande explicite Hicham) — chantier
        # "reconnaissance de plaques" (cf. HANDOFF.md, encore au stade design) :
        # avant de construire quoi que ce soit, vérifier que la LPR native de
        # Frigate (PaddleOCR + détecteur YOLOv9, 100% locale/gratuite) lit
        # correctement une vraie plaque sur CE matériel précis. Point de
        # vigilance réel, pas juste théorique : la doc officielle de Frigate
        # liste "CPU avec AVX+AVX2" comme minimum — instructions x86 qu'un
        # Raspberry Pi (ARM) n'a PAS physiquement, aucun accélérateur matériel
        # (Coral/Hailo) configuré ici. Global, affecte tous les sites tant que
        # ce n'est pas retiré — À RETIRER si le test ne convainc pas, ou à
        # remonter proprement (option add-on ?) si Hicham valide la suite.
        "lpr:",
        "  enabled: true",
        "",
    ]

    if _cameras:
        lines.append("go2rtc:")
        # La clé "api:" (origin/username/password) est émise UNE SEULE FOIS, dans
        # _webrtc_config_yaml_lines() plus bas (même section go2rtc, ajoutée à
        # `lines` juste après ce bloc) — PAS ici. Avant le 2026-09-07 un bloc
        # "api: / origin: '*'" était dupliqué ici en plus (confirmé en conditions
        # réelles le 2026-07-22 : la laisser à l'injection automatique de
        # create_config.py, côté Frigate, ne suffit pas — rejet WebSocket
        # persistant, cf. HANDOFF §58/§59) — retiré en ajoutant username/password
        # à _webrtc_config_yaml_lines() : 2 clés "api:" dans le même mapping
        # go2rtc: auraient produit un YAML ambigu (clé dupliquée).
        # PAS de base_path ici — voir GO2RTC_API_BASE et _Go2rtcProxyHandler : le
        # retrait du préfixe /cameras (exigé par Cloudflare Tunnel côté externe) se fait
        # dans un proxy local dédié, pas dans go2rtc lui-même (base_path cassait le
        # healthcheck interne de Frigate, cf. commentaire GO2RTC_API_BASE plus haut).
        # Format ffmpeg personnalisé pour la conversion audio d'écoute (§79-§82) —
        # défini UNE FOIS ici, appliqué à toutes les caméras indifféremment de leur
        # matériel. Ne PAS coller ce réglage aux caractéristiques d'une caméra
        # particulière (ex. sa fréquence audio native) : le parc de caméras des
        # clients est hétérogène par nature (marques/modèles différents à chaque
        # installation), un réglage figé sur une seule caméra testée casserait pour
        # les autres. Sortie fixée à 48000Hz stéréo (le format natif attendu par
        # WebRTC/Opus côté navigateur, confirmé par l'offre SDP du navigateur :
        # "audio, sendonly, OPUS/48000/2") quelle que soit l'entrée — ffmpeg
        # rééchantillonne depuis n'importe quelle fréquence/nombre de canaux source.
        # -min_comp 0 : incrément d'horodatage audio constant, requis pour une bonne
        # qualité WebRTC (cf. internal/ffmpeg/ffmpeg.go, code source go2rtc, et
        # https://github.com/pion/webrtc/issues/1514).
        lines.append("  ffmpeg:")
        lines.append('    opus_listen: "-c:a libopus -application:a lowdelay -min_comp 0 -ar:a 48000 -ac:a 2"')
        # Préréglages de masquage (§93) — un par caméra masquée, jamais partagé (chaque
        # caméra a ses propres rectangles). Rien n'est émis pour les caméras sans masque.
        for name in _cameras:
            mask_rects = _camera_masks.get(name) or []
            if mask_rects:
                lines.append(f'    mask_{name}: "{_mask_ffmpeg_preset(mask_rects)}"')
        lines.append("  streams:")
        for name, rtsp_url in _cameras.items():
            mask_rects = _camera_masks.get(name) or []
            # PAS de 2e source '#backchannel=0' ici (retiré §76/§77) : contresens sur la
            # doc go2rtc (internal/rtsp/README.md) — ce flag DÉSACTIVE le two-way audio
            # sur la source qui le porte, il ne le redirige pas dessus. go2rtc négocie
            # le two-way audio automatiquement en ONVIF Profile T, dans LA MÊME session
            # RTSP que la vidéo, dès qu'un client WebRTC envoie une piste audio sendonly
            # — dans l'unique source ci-dessus, pas besoin d'une deuxième. Cette 2e
            # source dupliquée (même URL) ouvrait une vraie 2e connexion RTSP
            # concurrente vers la caméra — confirmé en conditions réelles le 2026-07-24
            # (§76) : erreurs RTP "bad cseq" + timeout + crash ffmpeg dès l'activation
            # du micro, sur une caméra qui n'accepte qu'un client RTSP à la fois.
            #
            # 2e source ffmpeg (§79-§82) : transcodage audio pour l'écoute — beaucoup
            # de caméras envoient leur audio natif en AAC, incompatible WebRTC.
            # 'opus_listen' est le format personnalisé défini plus haut, générique,
            # jamais spécifique à cette caméra précise. Toujours la source
            # auto-référencée (nom de stream go2rtc, pas l'URL RTSP physique) — pas de
            # 2e connexion RTSP vers la caméra, même raisonnement que ci-dessus §76/§77.
            if mask_rects:
                # Masquage "en dur" (§93) : le nom public {name} — celui que Frigate ET
                # l'app web interrogent tous les deux (rtsp://127.0.0.1:8554/{name} côté
                # Frigate, streamName côté web) — n'ingère JAMAIS le flux brut. L'ingest
                # réel de la caméra physique se fait sous un nom interne {name}__raw,
                # jamais exposé ; {name} n'est que des sources ffmpeg auto-référencées
                # dessus (donc toujours UNE SEULE connexion RTSP réelle vers la caméra,
                # même raisonnement §76/§77). La vidéo passe par le préréglage de
                # masquage (décode + drawbox + ré-encode — 'video=copy' n'est plus
                # possible dès qu'on touche aux pixels, coût CPU réel mais uniquement
                # pour les caméras effectivement masquées). L'audio n'a pas besoin
                # d'être masqué, simple passthrough.
                raw_name = f"{name}__raw"
                lines += [f"    {raw_name}:", f"      - {rtsp_url}"]
                lines += [
                    f"    {name}:",
                    f"      - ffmpeg:{raw_name}#video=mask_{name}#audio=copy",
                    f"      - ffmpeg:{raw_name}#video=copy#audio=opus_listen",
                ]
            else:
                lines += [f"    {name}:", f"      - {rtsp_url}"]
                lines.append(f"      - ffmpeg:{name}#video=copy#audio=opus_listen")
        lines += _webrtc_config_yaml_lines()
        lines.append("")
        lines.append("cameras:")
        for name, rtsp_url in _cameras.items():
            # `detect`/`record` sont désactivés (aucune détection IA ni enregistrement
            # côté Frigate, l'app n'utilise que go2rtc pour le direct) — mais un input
            # `roles: [detect]`, même avec detect.enabled=false, reste nécessaire :
            # retiré entièrement le 2026-08-15 en pensant (à tort) que ce pipeline
            # "detect" inutilisé causait les coupures vidéo — vraie cause trouvée
            # ailleurs et corrigée (redémarrage forcé de go2rtc, cf. GO2RTC_API_BASE)
            # sans lien avec ce réglage. Retirer entièrement `ffmpeg.inputs` a cassé
            # le PTZ (confirmé en conditions réelles) : le contrôleur ONVIF de Frigate
            # dépend de structures internes (`ptz_metrics`) peuplées par le thread de
            # capture de la caméra, qui ne démarre jamais sans input ffmpeg. Remis à
            # l'état confirmé fonctionnel (§61) : un input pointé sur le flux MASQUÉ
            # {name} (restream interne go2rtc, 127.0.0.1:8554, aucune 2e connexion
            # physique vers la caméra).
            # ⚠️ TEST TEMPORAIRE (2026-09-09, suite immédiate du test ci-dessus) —
            # Hicham : "on va tester sur la caméra intérieure... je vais juste
            # projeter une plaque d'immatriculation sur mon PC". Une plaque
            # affichée sur un écran n'a pas la forme d'une "voiture" pour le
            # détecteur d'objets — le chemin normal (LPR déclenchée par un
            # objet car/motorcycle confirmé, cf. caméra "exterieur" ci-dessus)
            # ne se déclencherait donc jamais. Frigate documente un mode
            # dédié pour ce cas précis (docs.frigate.video/configuration/
            # license_plate_recognition — "Dedicated LPR camera") : caméra en
            # `type: "lpr"`, pipeline de détection d'objets standard
            # entièrement contourné (`detect.enabled: false`, `objects.track`
            # VIDE), le lecteur de plaque tourne directement sur toute
            # l'image dès qu'il y a du MOUVEMENT. `record.enabled: true`
            # nécessaire ICI (contrairement aux autres caméras) : la doc
            # précise que le topic MQTT `frigate/reviews` — seul moyen de
            # vérifier le résultat à distance, `frigate/events` ne publie
            # PAS les mises à jour de ce mode dédié — n'est publié que si
            # l'enregistrement est activé.
            is_dedicated_lpr_test = "interieur" in name
            lines.append(f"  {name}:")
            if is_dedicated_lpr_test:
                lines.append('    type: "lpr"')
            lines += [
                "    ffmpeg:",
                "      inputs:",
                f"        - path: rtsp://127.0.0.1:8554/{name}",
                "          roles:",
                "            - detect",
                "    detect:",
                # ⚠️ TEST TEMPORAIRE (même chantier que "lpr: enabled: true"
                # au-dessus, cf. son commentaire) : la LPR "normale" a besoin
                # d'une vraie détection "car"/"motorcycle" pour avoir quelque
                # chose à lire — activée UNIQUEMENT sur la caméra dont le nom
                # contient "exterieur" (celle qui voit une allée/un portail).
                # La caméra "intérieur" (mode dédié, cf. juste au-dessus)
                # reste À "false" ici aussi — c'est le mode dédié qui bypass
                # ce pipeline entièrement, pas cette valeur qui l'active.
                # Aucun accélérateur matériel configuré ici : tourne sur CPU
                # nu, exactement ce qu'on veut mesurer. À retirer si le test
                # ne convainc pas.
                f"      enabled: {'true' if 'exterieur' in name else 'false'}",
                "    objects:",
            ]
            if is_dedicated_lpr_test:
                lines.append("      track: []")
            else:
                lines += ["      track:", "        - car", "        - motorcycle"]
            lines += [
                "    record:",
                f"      enabled: {'true' if is_dedicated_lpr_test else 'false'}",
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
                    f'      host: "{_yaml_dq(onvif_ip)}"',
                    f'      user: "{_yaml_dq(onvif_user)}"',
                    f'      password: "{_yaml_dq(onvif_pass)}"',
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


def _marketplace_find_repository(domain: str) -> dict | None:
    """Retourne le dict repo Marketplace (id/installed/available_version…) pour un
    domain d'intégration donné. Remplace l'ancien mécanisme HACS autonome : depuis
    Home Assistant 2026.11, HACS est intégré nativement à HA sous le nom
    "Marketplace" (confirmé par la doc officielle hacs.xyz : "HACS is built into
    Home Assistant as the Marketplace starting with 2026.11") — plus besoin de
    déployer/autoriser quoi que ce soit séparément, le composant `marketplace` est
    déjà chargé par défaut. API découverte en direct le 2026-11-09 (aucune doc
    publique trouvée au moment d'écrire ceci) via le WebSocket HA :
    `marketplace/repositories/list` (aucun paramètre, retourne tout le catalogue)
    et `marketplace/repository/info` (`repository_id`) pour un item précis."""
    result = _ha_ws_call("marketplace/repositories/list")
    if not result or not result.get("success"):
        warn(f"[marketplace] Liste des dépôts impossible : {result}")
        return None
    for repo in result.get("result", []):
        if repo.get("domain") == domain:
            return repo
    return None


def _marketplace_ensure_installed(domain: str) -> bool:
    """Installe/actualise une intégration via le Marketplace natif. Retourne True si
    un redémarrage HA est nécessaire (fichiers déposés/modifiés), False si déjà à
    jour ou en cas d'échec. Pas d'autorisation GitHub séparée nécessaire pour un
    dépôt du catalogue par défaut (vérifié : `marketplace/info` renvoie
    `github_connected: false`, et l'installation réussit quand même)."""
    repo = _marketplace_find_repository(domain)
    if repo is None:
        warn(f"[marketplace] Dépôt introuvable pour le domain {domain!r}")
        return False
    if repo.get("installed") and not repo.get("pending_upgrade"):
        return False  # déjà installé et à jour

    # Le paramètre s'appelle "repository" (pas "repository_id") pour cette commande
    # précise — vérifié en direct, HA renvoie `invalid_format` sinon.
    result = _ha_ws_call("marketplace/repository/install", repository=repo["id"])
    if not result or not result.get("success"):
        warn(f"[marketplace] Échec de l'installation de {domain} : {result}")
        return False
    log(f"✓ {domain} {'mis à jour' if repo.get('installed') else 'installé'} via le Marketplace")
    return True


def _alarmo_config_entry_exists() -> bool:
    """Même technique que _mqtt_config_entry_exists() : lecture directe du storage
    HA, pas d'appel API nécessaire pour un simple check."""
    try:
        with open("/homeassistant/.storage/core.config_entries") as f:
            storage = json.load(f)
        entries = storage.get("data", {}).get("entries", [])
        return any(e.get("domain") == "alarmo" for e in entries)
    except Exception as e:
        warn(f"[alarmo] Lecture core.config_entries impossible : {e}")
        return False


def install_alarmo():
    """Installe ET met à jour Alarmo via le Marketplace natif HA. Idempotent —
    appelé à chaque démarrage de l'addon (volontairement hors run_setup(), pour
    s'activer sur un site déjà provisionné sans réinitialiser toute la config).

    Réécrit le 2026-11-09 — l'ancienne version passait par une installation HACS
    manuelle (téléchargement direct du zip GitHub + autorisation OAuth device-code)
    qui a échoué de façon reproductible en conditions réelles sur ce site de test
    ("Cannot find integration hacs" côté HA, malgré des fichiers confirmés présents
    et valides — cause jamais élucidée). Hicham a découvert entre-temps que HACS
    est désormais intégré nativement à HA sous le nom "Marketplace" à partir de la
    version 2026.11 (cf. hacs.xyz/docs/use/download/download/) — toute cette
    mécanique de téléchargement/autorisation devient obsolète, Alarmo s'installe
    directement via `_marketplace_ensure_installed()`.

    Séquence : _marketplace_ensure_installed("alarmo") → restart HA Core si Alarmo
    vient d'être installé → création de l'entry de config Alarmo via son flow
    zéro-input (config_flow.py d'Alarmo appelle async_create_entry() dès la
    première étape, sans saisie utilisateur — vérifié dans le code source de la
    release, 2026-07-27)."""
    # Sortie rapide : dossier custom_component ET config entry présents → déjà installé
    if os.path.isdir("/homeassistant/custom_components/alarmo"):
        if _alarmo_config_entry_exists():
            log("[alarmo] ✓ Déjà installé et configuré — rien à faire")
            return
        log("[alarmo] Dossier présent mais config entry absente — création de l'entry")
    else:
        log("[alarmo] Dossier absent — installation via le Marketplace")

    log("── Alarmo (alarme) ──────────────────────────")
    wait_for_ha()

    if _marketplace_ensure_installed("alarmo"):
        log("[alarmo] Restart HA Core pour charger Alarmo…")
        try:
            requests.post(
                f"{SUP}/homeassistant/restart",
                headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"},
                timeout=60,
            )
        except Exception as e:
            warn(f"[alarmo] Erreur restart HA : {e}")
            return
        wait_for_ha()

    if _alarmo_config_entry_exists():
        return

    flow_resp = ha_post("/config/config_entries/flow", {"handler": "alarmo"})
    if not flow_resp.ok:
        warn(f"[alarmo] Flow impossible ({flow_resp.status_code}): {flow_resp.text[:200]}")
        return
    flow = _unwrap(flow_resp.json())
    if flow.get("type") == "create_entry":
        log("✓ Intégration Alarmo configurée")
    else:
        warn(f"[alarmo] Flow inattendu (type={flow.get('type')}) : {flow}")


# device_class HA → catégorie Alarmo — reproduit la logique de suggestion du
# frontend d'Alarmo (le backend ne fait AUCUN filtrage par device_class lui-même,
# vérifié dans sensors.py — ce mapping n'existe que côté frontend HA/Alarmo).
# Correspond au tableau du README officiel d'Alarmo (vérifié 2026-07-27).
_ALARMO_DEVICE_CLASS_TO_TYPE = {
    "door": "door", "garage_door": "door", "lock": "door", "opening": "door",
    "window": "window",
    "motion": "motion", "moving": "motion", "occupancy": "motion", "presence": "motion",
    "tamper": "tamper", "sound": "tamper", "vibration": "tamper",
    "carbon_monoxide": "environmental", "gas": "environmental", "heat": "environmental",
    "moisture": "environmental", "safety": "environmental", "smoke": "environmental",
}


def _alarmo_candidate_sensors(existing: dict, states: list) -> list[dict]:
    """Capteurs HA disponibles pour Alarmo mais pas encore ajoutés — on part des
    vraies entités HA (get_states + device_class) plutôt que de nos propres
    devices Domoticium, comme le fait le panneau Alarmo lui-même. "states" est
    pré-récupéré par l'appelant (partagé avec le nom natif des capteurs déjà
    configurés, pour un seul appel get_states)."""
    candidates = []
    for state in states:
        entity_id = state.get("entity_id", "")
        if not entity_id.startswith("binary_sensor.") or entity_id in existing:
            continue
        device_class = (state.get("attributes") or {}).get("device_class")
        alarmo_type = _ALARMO_DEVICE_CLASS_TO_TYPE.get(device_class)
        if not alarmo_type:
            continue
        candidates.append({
            "entity_id": entity_id,
            "name": (state.get("attributes") or {}).get("friendly_name", entity_id),
            "device_class": device_class,
            "suggested_type": alarmo_type,
        })
    return candidates


def handle_alarmo_get_sensors() -> dict:
    """Étape 1 de la reconstruction de la page Alarme : capteurs déjà configurés
    dans Alarmo (WS alarmo/sensors, seule voie de lecture — pas de REST GET côté
    Alarmo, cf. websockets.py::websocket_get_sensors) + capteurs HA candidats pas
    encore ajoutés (_alarmo_candidate_sensors)."""
    result = _ha_ws_call("alarmo/sensors")
    sensors = result.get("result") if result and result.get("success") else {}
    sensors = sensors or {}
    # sensor["area"] est l'area_id technique (horodatage Unix, cf. _alarmo_get_sole_area) —
    # pas affichable tel quel côté web (demande Hicham 2026-07-31 : "ça fait plus
    # professionnel" de voir le vrai nom de la zone). Une seule zone chez nous, un seul
    # nom à résoudre pour tous les capteurs.
    _, area = _alarmo_get_sole_area()
    area_name = (area or {}).get("name")
    for s in sensors.values():
        if s.get("area") and area_name:
            s["area_name"] = area_name

    states_result = _ha_ws_call("get_states")
    states = states_result.get("result", []) if states_result and states_result.get("success") else []
    states_by_entity = {s.get("entity_id"): s for s in states}
    for entity_id, s in sensors.items():
        state = states_by_entity.get(entity_id)
        if state:
            s["native_name"] = (state.get("attributes") or {}).get("friendly_name", entity_id)

    candidates = _alarmo_candidate_sensors(sensors, states)

    # Résout l'ieee Zigbee OU le node_id Matter de chaque capteur (configuré ou
    # candidat) via l'entity_registry HA (unique_id) — le web s'en sert pour
    # afficher le nom personnalisé assigné lors de l'ajout de l'équipement
    # (table `devices`, jamais poussé vers Z2M/HA ni vers matter-server) plutôt
    # que le nom natif (demande Hicham, 2026-08-01 : "les noms ne font pas
    # professionnel"). Bug trouvé en conditions réelles le jour même : capteurs
    # Matter (ex: "MYGGSPRAY wrlss mtn sensor", déjà identifié Matter en §117)
    # jamais résolus — seul l'ieee Zigbee était tenté, pas _matter_node_id_from_unique_id.
    registry_result = _ha_ws_call("config/entity_registry/list")
    registry = registry_result.get("result", []) if registry_result and registry_result.get("success") else []
    uid_by_entity = {e.get("entity_id"): e.get("unique_id") or "" for e in registry}

    def _identify(entity_id):
        uid = uid_by_entity.get(entity_id, "")
        m = _IEEE_RE.search(uid)
        if m:
            return "ieee_address", m.group(0)
        node_id = _matter_node_id_from_unique_id(uid)
        if node_id is not None:
            return "matter_node_id", node_id
        return None, None

    for entity_id, s in sensors.items():
        key, value = _identify(entity_id)
        if key:
            s[key] = value
    for c in candidates:
        key, value = _identify(c["entity_id"])
        if key:
            c[key] = value

    return {
        "sensors": sensors,
        "candidates": candidates,
    }


# Point 2 (suite étape 2) : armer/désarmer depuis l'app. L'entité alarm_control_panel
# elle-même (état live, armer/désarmer) n'est PAS une commande spécifique à Alarmo —
# ce sont des services HA standard (alarm_control_panel.alarm_arm_away/home/night,
# alarm_disarm), déjà whitelistés dans ALLOWED_SERVICES et exécutables via la route
# générique /cmd existante. Seul manque un moyen de savoir QUEL entity_id est le
# panneau de ce site (dépend du nom de la zone, jamais supposé fixe — cf. §118/§119,
# le renommage change justement l'entity_id) et son état actuel.
def handle_alarmo_get_panel_state() -> dict:
    area_id, _ = _alarmo_get_sole_area()
    if not area_id:
        return {"entity_id": None, "state": None}
    entities_result = _ha_ws_call("alarmo/entities")
    entities = entities_result.get("result") if entities_result and entities_result.get("success") else []
    entity_id = next((e.get("entity_id") for e in entities or [] if e.get("area_id") == area_id), None)
    if not entity_id:
        return {"entity_id": None, "state": None}
    r = ha_get(f"/states/{entity_id}")
    if not r.ok:
        return {"entity_id": entity_id, "state": None}
    payload = r.json()
    attrs = payload.get("attributes") or {}
    return {
        "entity_id": entity_id,
        "state": payload.get("state"),
        "code_arm_required": bool(attrs.get("code_arm_required", False)),
        "code_format": attrs.get("code_format"),
        # Durée totale (secondes) du délai en cours (pending/arming) — vérifié
        # dans le code source (alarm_control_panel.py::extra_state_attributes,
        # self.delay = exit_delay / effective_entry_delay au moment précis où
        # l'état bascule) : c'est la durée TOTALE, pas un compte à rebours déjà
        # décrémenté par Alarmo — le web calcule le temps restant lui-même à
        # partir du moment où il observe ce nouvel état (demande Hicham
        # 2026-08-06 : anneau de progression pendant l'armement).
        "delay": attrs.get("delay"),
        # Horodatage HA natif du dernier changement de VALEUR d'état (pas
        # attributs) — exactement le moment où Alarmo est passé à "pending"/
        # "arming". Ancre fiable pour l'anneau de progression, contrairement à
        # un simple Date.now() côté web mesuré à la 1ère observation : ce
        # dernier repart de zéro à chaque démontage du composant (ex: changer
        # d'onglet puis revenir), bug réel remonté par Hicham en conditions
        # réelles (2026-08-09) — le cercle "En attente…" recommençait à 0%
        # alors que le délai réel côté Alarmo continuait de s'écouler.
        "last_changed": payload.get("last_changed"),
    }


# action app (cf. web AlarmoAction) → verbe de service HA alarm_control_panel.
_ALARMO_ACTION_TO_SERVICE = {
    "arm_away": "alarm_arm_away", "arm_home": "alarm_arm_home", "arm_night": "alarm_arm_night",
    "disarm": "alarm_disarm", "trigger": "alarm_trigger",
}


def handle_alarmo_set_panel_state(entity_id: str, action: str, code: str | None) -> dict:
    """Arme/désarme le panneau et VÉRIFIE que l'état a réellement changé — trouvé en
    conditions réelles (Hicham, 2026-08-09) : Alarmo ne lève aucune erreur HA en cas de
    code manquant ou incorrect. Vérifié dans son code source
    (alarm_control_panel.py::_validate_code) : un code manquant/faux est rejeté en
    interne (juste un log "Wrong code provided"), le service HA répond quand même
    200 OK — sans cette vérification, un mauvais code ne montrait RIEN à l'utilisateur,
    ni erreur ni changement d'état. Le code manquant sur une action d'armement est un
    cas à part : Home Assistant lui-même (check_code_arm_required, avant même qu'Alarmo
    ne soit sollicité) lève une erreur non gérée proprement par l'API REST de HA, que
    l'ancien code aplatissait en un 502 générique sans aucun détail exploitable (bug
    d'origine remonté par Hicham) — la validation de présence du code se fait
    désormais côté web AVANT l'appel (cf. alarm/page.tsx), donc ce cas ne devrait plus
    jamais atteindre l'add-on en temps normal.

    L'appel HA (`ha_post`, blocking=True côté API REST de HA) attend que le service
    Alarmo ait fini de s'exécuter avant de répondre — Alarmo a donc déjà pris sa
    décision (accepter/rejeter) et mis à jour l'état AVANT que `ha_post` ne rende la
    main ici, aucun délai artificiel n'est nécessaire entre les deux lectures d'état."""
    verb = _ALARMO_ACTION_TO_SERVICE.get(action)
    if not verb:
        return {"ok": False, "error": "action inconnue"}

    before_r = ha_get(f"/states/{entity_id}")
    before_state = before_r.json().get("state") if before_r.ok else None

    payload = {"entity_id": entity_id}
    if code:
        payload["code"] = code
    r = ha_post(f"/services/alarm_control_panel/{verb}", payload)
    if not r.ok:
        try:
            detail = r.json().get("message") or r.text[:200]
        except Exception:
            detail = r.text[:200]
        return {"ok": False, "error": detail}

    if action == "trigger":
        return {"ok": True}

    after_r = ha_get(f"/states/{entity_id}")
    after_state = after_r.json().get("state") if after_r.ok else None

    # Lecture d'état impossible. Audit add-on 2026-09-22 : le repli "ok: True"
    # inconditionnel ici pouvait faire croire à un client que son domicile est
    # armé alors qu'un simple souci de lecture d'état a masqué un refus réel côté
    # Alarmo (fail-open dangereux, sécurité physique) — jamais toléré côté
    # armement, où l'incertitude doit se traduire par un échec explicite (le
    # client réessaie). Le désarmement reste tolérant : un échec silencieux dans
    # ce sens laisse au pire l'alarme armée par erreur (gênant, jamais
    # dangereux), comportement déjà documenté et volontaire.
    if before_state is None or after_state is None:
        if action == "disarm":
            return {"ok": True}
        return {"ok": False, "error": "État du panneau introuvable — réessayez pour confirmer"}

    # État cible déjà atteint avant même l'appel (ex: cliquer "Absent" alors que déjà
    # armé "Absent") — Alarmo l'ignore silencieusement lui aussi (log "already set to
    # X"), un vrai no-op légitime, pas un code refusé : ne jamais le signaler à tort.
    already_there = (
        (action == "disarm" and before_state == "disarmed")
        or (action != "disarm" and before_state == f"armed_{action.split('_', 1)[1]}")
    )
    if not already_there and after_state == before_state:
        return {"ok": False, "error": "Code incorrect"}

    return {"ok": True}


def handle_alarmo_get_keypad_status() -> dict:
    """Détection live d'un clavier physique — demandée par Hicham (2026-08-04) pour
    l'étape "clavier" de l'assistant de configuration web, qui n'affichait jusqu'ici
    qu'un message générique statique. Réutilise _find_ias_ace_keypad(), la MÊME
    fonction qui décide déjà si _ensure_alarmo_keypad_control() câble les
    automatisations d'armement — la réponse ici est donc garantie cohérente avec la
    réalité (jamais un signal indirect/dérivé qui pourrait diverger). Lit
    _last_z2m_devices_list (rempli à chaque zigbee2mqtt/bridge/devices reçu) plutôt
    que d'interroger Z2M à la demande — répond instantanément depuis ce thread HTTP
    séparé, cohérent avec le reste de la synchro (best-effort, jamais bloquant)."""
    friendly_name = _find_ias_ace_keypad(_last_z2m_devices_list, {"disarm", "arm_all_zones"})
    return {"detected": friendly_name is not None, "name": friendly_name}


# Codes/utilisateurs Alarmo — demande Hicham (2026-08-05) après avoir remarqué
# qu'on avait construit tout le nécessaire pour SAISIR un code (pavé numérique,
# étape "test" de l'assistant) mais rien pour en CRÉER un. Vérifié dans le code
# source d'Alarmo (websockets.py::AlarmoUserView) plutôt que deviné : endpoint
# POST /api/alarmo/users, distinct de /alarmo/area et /alarmo/sensor déjà
# utilisés — Alarmo supporte nativement plusieurs utilisateurs nommés avec
# permissions (can_arm/can_disarm), mais AUCUNE notion de calendrier (horaires,
# expiration). Le calendrier vit UNIQUEMENT dans un fichier local sur le Pi
# (ALARMO_SCHEDULES_FILE, même principe que CAMERAS_FILE) — Hicham a fait
# remarquer (à raison) qu'une 1ère version qui interrogeait Supabase en boucle
# pour ça coûterait cher à l'échelle (des centaines de clients, la plupart sans
# aucun code programmé) alors que l'addon connaît déjà tout ce qu'il faut dès
# qu'un code est créé — plus aucun appel réseau récurrent nécessaire.
ALARMO_SCHEDULES_FILE = "/data/alarmo_schedules.json"
_alarmo_schedules: dict = {}  # user_id -> {mode, valid_from_time, valid_until_time, expires_at}


def _load_alarmo_schedules():
    global _alarmo_schedules
    try:
        with open(ALARMO_SCHEDULES_FILE) as f:
            _alarmo_schedules = json.load(f)
    except FileNotFoundError:
        _alarmo_schedules = {}


def _save_alarmo_schedules():
    try:
        with open(ALARMO_SCHEDULES_FILE, "w") as f:
            json.dump(_alarmo_schedules, f)
    except Exception as e:
        warn(f"[alarmo-schedules] écriture échouée: {e}")


def handle_alarmo_get_users() -> dict:
    """Liste des utilisateurs/codes Alarmo (WS alarmo/users, seule voie de
    lecture, même principe que alarmo/sensors), enrichie avec le calendrier
    lu depuis le fichier local — un seul endroit à interroger côté web pour
    tout savoir sur un code. Le hash bcrypt du code n'est JAMAIS transmis
    (à sens unique, inutile côté client de toute façon, cf. README Alarmo :
    "if you lose your pincode, you cannot unlock the alarm") — seuls
    code_format/code_length (utiles pour l'UI) le sont."""
    result = _ha_ws_call("alarmo/users")
    users = result.get("result") if result and result.get("success") else {}
    users = users or {}
    return {
        uid: {
            "user_id": u.get("user_id", uid),
            "name": u.get("name", ""),
            "enabled": u.get("enabled", True),
            "code_format": u.get("code_format") or None,
            "code_length": u.get("code_length") or 0,
            "mode": _alarmo_schedules.get(uid, {}).get("mode", "permanent"),
            "valid_from_time": _alarmo_schedules.get(uid, {}).get("valid_from_time"),
            "valid_until_time": _alarmo_schedules.get(uid, {}).get("valid_until_time"),
            "expires_at": _alarmo_schedules.get(uid, {}).get("expires_at"),
        }
        for uid, u in users.items()
    }


def _ensure_alarmo_code_required():
    """Active l'exigence de code — réglage GLOBAL d'Alarmo (POST /api/alarmo/config,
    AlarmoConfigView), PAS un réglage par zone. Bug réel trouvé en conditions
    réelles (2026-08-05, Hicham : "je peux armer/désarmer sans code via l'app")
    : la 1ère version postait vers /api/alarmo/area (AlarmoAreaView), dont le
    schéma Voluptuous n'accepte même pas code_arm_required/code_disarm_required
    comme clés — requête rejetée en silence à chaque création de code (2 codes
    créés, jamais requis). Vérifié dans le code source (websockets.py) : ces 2
    clés n'existent QUE dans le schéma d'AlarmoConfigView. Idempotent, pas de
    vérification préalable nécessaire (POST sans effet si déjà à true)."""
    r = ha_post("/alarmo/config", {
        "code_arm_required": True,
        "code_disarm_required": True,
    })
    if r.ok:
        log("[alarmo] ✓ Code requis pour armer/désarmer activé")
    else:
        warn(f"[alarmo] Activation code requis échouée ({r.status_code}): {r.text[:200]}")


def _local_schedule_entry(mode: str | None, valid_from_time: str | None,
                           valid_until_time: str | None, expires_at: str | None) -> dict:
    scheduled = mode == "scheduled"
    return {
        "mode": mode or "permanent",
        "valid_from_time": valid_from_time if scheduled else None,
        "valid_until_time": valid_until_time if scheduled else None,
        "expires_at": expires_at if scheduled else None,
    }


def handle_alarmo_set_user(
    action: str, user_id: str | None, name: str | None, code: str | None, enabled: bool,
    mode: str | None = None, valid_from_time: str | None = None,
    valid_until_time: str | None = None, expires_at: str | None = None,
) -> dict:
    """CRUD utilisateur Alarmo + calendrier local (ALARMO_SCHEDULES_FILE). Le
    code stocké par Alarmo est bcrypt à sens unique (vérifié dans
    __init__.py::async_update_user_config) — changer le code d'un utilisateur
    EXISTANT nécessite donc un "old_code" que nous n'avons jamais : "reset_code"
    supprime puis recrée l'utilisateur plutôt que de tenter une vraie mise à
    jour du code (le calendrier déjà en place est conservé et transféré vers
    le nouvel id généré, l'appelant n'a rien à refaire)."""
    if action == "remove":
        if not user_id:
            return {"ok": False, "detail": "user_id requis"}
        r = ha_post("/alarmo/users", {"user_id": user_id, "remove": True})
        if r.ok and _alarmo_schedules.pop(user_id, None) is not None:
            _save_alarmo_schedules()
        return {"ok": r.ok}

    if action == "rename_or_toggle":
        if not user_id:
            return {"ok": False, "detail": "user_id requis"}
        payload = {"user_id": user_id, "enabled": enabled}
        if name:
            payload["name"] = name
        r = ha_post("/alarmo/users", payload)
        body = r.json() if r.ok else {}
        ok = r.ok and body.get("success", True)
        return {"ok": ok, "detail": None if ok else body.get("error")}

    if action == "update_schedule":
        if not user_id:
            return {"ok": False, "detail": "user_id requis"}
        _alarmo_schedules[user_id] = _local_schedule_entry(mode, valid_from_time, valid_until_time, expires_at)
        _save_alarmo_schedules()
        return {"ok": True}

    if action in ("create", "reset_code"):
        if not name or not code:
            return {"ok": False, "detail": "name et code requis"}
        carried_over_schedule = _alarmo_schedules.pop(user_id, None) if (action == "reset_code" and user_id) else None
        if action == "reset_code" and user_id:
            del_r = ha_post("/alarmo/users", {"user_id": user_id, "remove": True})
            if not del_r.ok:
                return {"ok": False, "detail": "suppression de l'ancien code échouée"}
        r = ha_post("/alarmo/users", {
            "name": name, "code": code, "enabled": enabled,
            "can_arm": True, "can_disarm": True,
        })
        body = r.json() if r.ok else {}
        if not r.ok or not body.get("success", True):
            detail = body.get("error") if r.ok else r.text[:200]
            return {"ok": False, "detail": detail or "échec inconnu"}
        # AlarmoUserView répond {"success", "error"} — jamais le user_id créé
        # (vérifié dans le code source) : on relit la liste pour le retrouver
        # (les noms sont garantis uniques par Alarmo lui-même, cf. _validate_user_name).
        users = handle_alarmo_get_users()
        new_id = next((uid for uid, u in users.items() if u.get("name") == name), None)
        _ensure_alarmo_code_required()
        if new_id:
            if action == "create":
                _alarmo_schedules[new_id] = _local_schedule_entry(mode, valid_from_time, valid_until_time, expires_at)
            elif carried_over_schedule:
                _alarmo_schedules[new_id] = carried_over_schedule
            _save_alarmo_schedules()
        return {"ok": True, "user_id": new_id}

    return {"ok": False, "detail": f"action inconnue: {action}"}


_ALARMO_CALENDAR_INTERVAL = 60  # purement local désormais — plus de coût réseau, cf. commentaire ci-dessous


def _alarmo_calendar_loop():
    """Applique le calendrier (horaires + date d'expiration) des codes
    temporaires — Alarmo n'a nativement AUCUNE notion de calendrier (vérifié
    source, cf. handle_alarmo_get_users), un utilisateur est juste activé ou
    désactivé. Lit UNIQUEMENT le fichier local ALARMO_SCHEDULES_FILE (poussé
    une seule fois à la création/modification d'un code, cf.
    handle_alarmo_set_user) — plus aucun appel réseau récurrent vers Supabase
    (la 1ère version interrogeait Supabase toutes les 5 min pour CHAQUE site,
    même sans aucun code programmé — à l'échelle de centaines de clients ça
    n'aurait servi à rien la plupart du temps ; signalé par Hicham, 2026-08-05).
    Le seul appel réseau restant (_ha_ws_call, résoudre le nom depuis l'id) est
    local à Home Assistant sur ce même Pi, pas vers le cloud. Toujours réaffirme
    l'état voulu plutôt que de diffuser — même principe idempotent que le reste
    de la synchro Alarmo (_ensure_alarmo_*)."""
    while True:
        time.sleep(_ALARMO_CALENDAR_INTERVAL)
        try:
            users = handle_alarmo_get_users()
        except Exception as exc:
            warn(f"[alarmo-calendar] lecture utilisateurs: {exc}")
            continue

        # Auto-guérison de l'exigence de code (§155) — était câblée sur le cycle
        # de synchro Zigbee (_sync_zigbee_devices_direct), qui dépend de messages
        # Z2M bridge/devices : sur une installation instable (matériel posé sur
        # une table, pas encore fixé — cas réel d'Hicham, 2026-08-06), ce cycle
        # peut ne jamais se déclencher, laissant le correctif sans effet. Ce
        # thread-ci tourne seul (indépendamment de tout matériel Zigbee et,
        # depuis ce fix, même sans code programmé) — le bon endroit pour
        # réaffirmer ce réglage de façon fiable, à chaque cycle.
        if users:
            try:
                _ensure_alarmo_code_required()
            except Exception as exc:
                warn(f"[alarmo-calendar] vérification code requis: {exc}")

        if not _alarmo_schedules:
            continue

        now_dt = datetime.now()
        today = now_dt.date()
        now_time = now_dt.time()

        for uid, sched in list(_alarmo_schedules.items()):
            if sched.get("mode") != "scheduled":
                continue
            name = users.get(uid, {}).get("name")
            if not name:
                continue
            expires_at = sched.get("expires_at")
            expired = bool(expires_at) and date.fromisoformat(expires_at) < today
            if expired:
                should_enable = False
            else:
                vf, vu = sched.get("valid_from_time"), sched.get("valid_until_time")
                if vf and vu:
                    vf_t = datetime.strptime(vf, "%H:%M:%S").time()
                    vu_t = datetime.strptime(vu, "%H:%M:%S").time()
                    should_enable = (vf_t <= now_time <= vu_t) if vf_t <= vu_t else (now_time >= vf_t or now_time <= vu_t)
                else:
                    should_enable = True  # pas de plage définie, seulement une expiration
            verb = "enable_user" if should_enable else "disable_user"
            try:
                ha_post(f"/services/alarmo/{verb}", {"name": name})
            except Exception as exc:
                warn(f"[alarmo-calendar] {verb} {name}: {exc}")


# Étape 2 : ajout d'un capteur candidat à Alarmo. Vérifié dans la source officielle
# (websockets.py::AlarmoSensorView, POST /api/alarmo/sensors) — SEUL entity_id est
# obligatoire ; "modes" vaut [] par défaut si omis, donc un capteur créé sans modes
# explicites est inerte (jamais surveillé, quel que soit l'état du panneau). On
# n'expose donc jamais un ajout sans modes côté web.
_ALARMO_MODE_MAP = {"away": "armed_away", "home": "armed_home", "night": "armed_night"}


def _alarmo_get_sole_area():
    """Une seule zone Alarmo chez nous (cf. décision produit — une zone Alarmo est
    un panneau indépendant, pas une pièce). Retourne (area_id, area_data) ou (None, None)."""
    areas_result = _ha_ws_call("alarmo/areas")
    if not areas_result or not areas_result.get("success"):
        return None, None
    areas = areas_result.get("result") or {}
    if not areas:
        return None, None
    return next(iter(areas.items()))


def handle_alarmo_update_sensor(entity_id: str, sensor_type: str, modes: list, always_on: bool = False) -> dict:
    if not entity_id or not entity_id.startswith("binary_sensor."):
        return {"ok": False, "detail": "entity_id invalide"}
    if sensor_type not in _ALARMO_DEVICE_CLASS_TO_TYPE.values() and sensor_type != "other":
        return {"ok": False, "detail": f"type inconnu: {sensor_type}"}
    # Bug trouvé en conditions réelles (2026-07-31) : un capteur sans "area" assignée
    # n'est JAMAIS évalué par aucune zone, même dans une installation à zone unique
    # (vérifié dans sensors.py : `if config["area"] != area_id: continue` — un capteur
    # avec area=None ne correspond jamais à un vrai area_id). Le panneau natif Alarmo
    # l'affichait d'ailleurs avec un triangle d'avertissement. Il faut donc toujours
    # résoudre et transmettre l'unique zone existante, même si l'utilisateur ne la
    # choisit jamais (aucune notion de zone exposée côté web).
    area_id, _ = _alarmo_get_sole_area()
    if not area_id:
        return {"ok": False, "detail": "Aucune zone Alarmo trouvée"}
    alarmo_modes = [_ALARMO_MODE_MAP[m] for m in modes if m in _ALARMO_MODE_MAP]
    r = ha_post("/alarmo/sensors", {
        "entity_id": entity_id,
        "type": sensor_type,
        "modes": alarmo_modes,
        "always_on": bool(always_on),
        "area": area_id,
    })
    if r.ok:
        return {"ok": True}
    warn(f"[alarmo-sensor] {entity_id} → {r.status_code}: {r.text[:200]}")
    return {"ok": False, "detail": f"Alarmo {r.status_code}: {r.text[:200]}"}


def handle_alarmo_remove_sensor(entity_id: str) -> dict:
    if not entity_id or not entity_id.startswith("binary_sensor."):
        return {"ok": False, "detail": "entity_id invalide"}
    r = ha_post("/alarmo/sensors", {"entity_id": entity_id, "remove": True})
    if r.ok:
        return {"ok": True}
    warn(f"[alarmo-sensor-remove] {entity_id} → {r.status_code}: {r.text[:200]}")
    return {"ok": False, "detail": f"Alarmo {r.status_code}: {r.text[:200]}"}


# Regroupement logique de capteurs (anti-fausse-alerte) — demande Hicham
# (2026-08-05, "je veux tout"). Vérifié dans le README Alarmo officiel : dans
# un groupe, le déclenchement d'UN SEUL capteur est ignoré — il faut que 2
# capteurs DIFFÉRENTS du même groupe se déclenchent l'un après l'autre, dans
# le délai configuré, pour que l'alarme se déclenche vraiment (ex: mouvement
# salon + mouvement couloir, pas juste un chat qui traverse une pièce).
# Endpoint POST /api/alarmo/sensor_groups, vérifié dans websockets.py::
# AlarmoSensorGroupView — mêmes sémantiques create/update/remove que
# /alarmo/sensor (pas de group_id → création, group_id + remove → suppression,
# group_id seul → mise à jour, cf. __init__.py::async_update_sensor_group_config).
def handle_alarmo_get_sensor_groups() -> dict:
    """Liste des groupes de capteurs (WS alarmo/sensor_groups, seule voie de
    lecture, même principe que alarmo/sensors)."""
    result = _ha_ws_call("alarmo/sensor_groups")
    groups = result.get("result") if result and result.get("success") else {}
    return groups or {}


def handle_alarmo_set_sensor_group(
    group_id: str | None, name: str | None, entities: list | None,
    timeout: int | None, remove: bool = False,
) -> dict:
    if remove:
        if not group_id:
            return {"ok": False, "detail": "group_id requis"}
        r = ha_post("/alarmo/sensor_groups", {"group_id": group_id, "remove": True})
        return {"ok": r.ok}

    # Un groupe à moins de 2 capteurs ne se déclenche jamais (cf. README :
    # "needs to have at least 2 sensors to function correctly") — refusé ici
    # plutôt que de laisser créer silencieusement un groupe inutilisable.
    if not name or not entities or len(entities) < 2:
        return {"ok": False, "detail": "Au moins 2 capteurs sont requis dans un groupe"}
    payload = {"name": name, "entities": entities, "timeout": timeout or 30, "event_count": 2}
    if group_id:
        payload["group_id"] = group_id
    r = ha_post("/alarmo/sensor_groups", payload)
    if not r.ok:
        return {"ok": False, "detail": r.text[:200]}
    return {"ok": True}


_ALARMO_MODE_MAP_REVERSE = {v: k for k, v in _ALARMO_MODE_MAP.items()}


def _resolve_entity_for_matter_node(node_id: int) -> str | None:
    """entity_id principal d'un node Matter, via l'entity_registry HA (unique_id,
    _matter_node_id_from_unique_id). Utilisé pour la migration après fusion de
    doublon (pi_sync_matter_devices) — l'ancien entity_id peut encore exister dans
    le registre HA même si le node correspondant est mort côté matter-server."""
    result = _ha_ws_call("config/entity_registry/list")
    entities = result.get("result", []) if result and result.get("success") else []
    for e in entities:
        if _matter_node_id_from_unique_id(e.get("unique_id")) == node_id:
            return e.get("entity_id")
    return None


# ── Fusion d'un équipement Matter re-jumelé (lot « Pi-first ») ───────────────────────────────────────────────────
# Cas réel : un équipement Matter est réinitialisé puis re-jumelé → matter-server lui donne un NOUVEAU node_id, Home
# Assistant crée un NOUVEL équipement (nouvelles entités, sans nom ni pièce) et garde l'ancien, hors ligne. Tout ce qui
# référence l'ancien entity_id en dur (automatisations, scènes, capteurs Alarmo, raccourcis de pièce, exposition vocale,
# réglages de l'app) est alors cassé.
# Avant : la détection et les suggestions vivaient dans Supabase (pi_sync_devices) et la fusion réécrivait les
# automatisations une par une. Maintenant tout se passe sur le boîtier, et SANS réécrire aucune référence : on retire l'ancien
# nœud, puis on donne aux entités du nouvel équipement les entity_id de l'ancien (+ son nom et sa pièce). Toutes les
# références restent valides, partout, parce que l'identité d'un équipement EST son entity_id.
#  - détection (à la demande, jamais automatique — décision d'Hicham du 2026-08-01 : seul le client sait si c'est le même
#    appareil physique) : un équipement Matter EN LIGNE, sans pièce, et UN SEUL équipement Matter hors ligne de mêmes
#    vendeur + modèle, de node_id plus ancien ; ambiguïté (2 anciens possibles, ou 2 nouveaux pour 1 ancien) = rien proposé ;
#  - « Non, ce n'est pas le même » : la paire est mémorisée (/data/matter-merge.json), plus jamais reproposée.
_MATTER_MERGE_FILE = "/data/matter-merge.json"
_MATTER_UID_REST_RE = re.compile(r"^[0-9a-fA-F]{16}-[0-9a-fA-F]{16}-(.+)$")


def _matter_merge_rejected() -> set:
    try:
        with open(_MATTER_MERGE_FILE) as f:
            return {str(x) for x in (json.load(f).get("rejected") or [])}
    except Exception:
        return set()


def _matter_merge_pair_key(new_node, old_node) -> str:
    return f"{int(new_node)}:{int(old_node)}"


def handle_matter_merge_suggestions() -> dict:
    """Paires (nouvel équipement Matter, ancien équipement hors ligne) que le client peut fusionner."""
    matter = [d for d in _build_local_devices() if d.get("matterNodeId") is not None and d.get("vendor") and d.get("model")]
    rejected = _matter_merge_rejected()
    olds_of = {}
    for new in matter:
        if not new.get("online") or new.get("areaId"):
            continue
        olds = [o for o in matter if o is not new and not o.get("online") and o["vendor"] == new["vendor"]
                and o["model"] == new["model"] and int(o["matterNodeId"]) < int(new["matterNodeId"])]
        if len(olds) == 1:
            olds_of[int(new["matterNodeId"])] = (new, olds[0])
    used = {}
    for new_node, (_n, old) in olds_of.items():
        used.setdefault(int(old["matterNodeId"]), []).append(new_node)
    out = []
    for new_node, (new, old) in sorted(olds_of.items()):
        if len(used[int(old["matterNodeId"])]) != 1:
            continue                                   # 2 nouveaux pour 1 ancien : ambigu
        if _matter_merge_pair_key(new_node, old["matterNodeId"]) in rejected:
            continue
        out.append({"newNodeId": new_node, "oldNodeId": int(old["matterNodeId"]), "newName": new["name"], "oldName": old["name"],
                    "newEntityId": new["haEntityId"], "oldEntityId": old["haEntityId"], "vendor": new["vendor"], "model": new["model"]})
    return {"suggestions": out}


def handle_matter_merge_reject(data: dict) -> dict:
    """« Ce n'est pas le même appareil » : la paire n'est plus jamais proposée."""
    try:
        key = _matter_merge_pair_key(data.get("newNodeId"), data.get("oldNodeId"))
    except (TypeError, ValueError):
        return {"ok": False, "detail": "newNodeId et oldNodeId requis"}
    rejected = _matter_merge_rejected() | {key}
    tmp = _MATTER_MERGE_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps({"rejected": sorted(rejected)}))
    os.replace(tmp, _MATTER_MERGE_FILE)
    return {"ok": True}


def _matter_entries(entries: list, node_id: int) -> list:
    return [e for e in entries if _matter_node_id_from_unique_id(e.get("unique_id")) == node_id]


def handle_matter_merge_confirm(data: dict, sleep=None) -> dict:
    """Fusionne : retire l'ancien nœud, puis les entités du nouvel équipement prennent les entity_id, le nom et la pièce
    de l'ancien. Idempotent côté lecture (une paire qui n'est plus proposée est refusée) ; la partie destructive n'a lieu
    qu'après avoir vérifié qu'au moins une entité du nouvel équipement correspond à une entité de l'ancien."""
    sleep = sleep or time.sleep
    try:
        new_node, old_node = int(data.get("newNodeId")), int(data.get("oldNodeId"))
    except (TypeError, ValueError):
        return {"ok": False, "detail": "newNodeId et oldNodeId requis"}
    if not any(s["newNodeId"] == new_node and s["oldNodeId"] == old_node for s in handle_matter_merge_suggestions()["suggestions"]):
        return {"ok": False, "detail": "Fusion introuvable ou déjà traitée"}

    ent = _ha_ws_call("config/entity_registry/list")
    dev = _ha_ws_call("config/device_registry/list")
    if not ent or not ent.get("success") or not dev or not dev.get("success"):
        return {"ok": False, "detail": "Home Assistant injoignable"}
    entries, devices = ent["result"], dev["result"]
    old_entries, new_entries = _matter_entries(entries, old_node), _matter_entries(entries, new_node)

    def rest(e):
        m = _MATTER_UID_REST_RE.match(e.get("unique_id") or "")
        return m.group(1) if m else None
    old_by_rest = {rest(e): e for e in old_entries if rest(e)}
    pairs = [(n, old_by_rest[rest(n)]) for n in new_entries if rest(n) in old_by_rest]
    if not pairs:
        return {"ok": False, "detail": "Aucune entité de l'ancien équipement ne correspond au nouveau (modèle différent ?)"}

    old_dev_id = next((e.get("device_id") for e in old_entries if e.get("device_id")), None)
    new_dev_id = next((e.get("device_id") for e in new_entries if e.get("device_id")), None)
    old_dev = next((d for d in devices if d.get("id") == old_dev_id), {})
    old_ids = {o["entity_id"] for _n, o in pairs} | {e["entity_id"] for e in old_entries}

    if not _matter_remove_node(old_node):
        return {"ok": False, "detail": "Impossible de retirer l'ancien équipement du réseau Matter — rien n'a été modifié"}

    # Home Assistant retire l'ancien équipement tout seul à la suite : on attend que ses entity_id se libèrent.
    remaining = old_ids
    for _ in range(15):
        res = _ha_ws_call("config/entity_registry/list")
        present = {e["entity_id"] for e in (res or {}).get("result", [])} if res and res.get("success") else remaining
        remaining = old_ids & present
        if not remaining:
            break
        sleep(1.5)
    for eid in remaining:                                  # filet : entrée orpheline qui n'a pas été retirée
        _ha_ws_call("config/entity_registry/remove", entity_id=eid)

    renamed, failed = 0, []
    for new_e, old_e in pairs:
        params = {"entity_id": new_e["entity_id"], "new_entity_id": old_e["entity_id"]}
        if old_e.get("name"):
            params["name"] = old_e["name"]
        res = _ha_ws_call("config/entity_registry/update", **params)
        if res and res.get("success"):
            renamed += 1
        else:
            failed.append(old_e["entity_id"])
            warn(f"[matter-merge] renommage {new_e['entity_id']} → {old_e['entity_id']} refusé : {json.dumps(res)[:200] if res else 'pas de réponse'}")
    if new_dev_id:
        dparams = {"device_id": new_dev_id, "name_by_user": old_dev.get("name_by_user") or old_dev.get("name")}
        if old_dev.get("area_id"):
            dparams["area_id"] = old_dev["area_id"]
        res = _ha_ws_call("config/device_registry/update", **dparams)
        if not (res and res.get("success")):
            warn(f"[matter-merge] nom / pièce non reportés : {json.dumps(res)[:200] if res else 'pas de réponse'}")
    log(f"[matter-merge] nœud {old_node} → {new_node} : {renamed} entité(s) reprennent leurs anciens identifiants, {len(failed)} échec(s)")
    _alerts_reindex.set()
    _alerts_wake.set()
    try:
        _sse_publish("fast")
    except Exception:
        pass
    return {"ok": True, "renamed": renamed, "failed": failed}


_ALARMO_SHORT_EXIT_TIME = 5  # secondes — voir docstring ci-dessous

def _ensure_alarmo_night_mode():
    """Patch one-shot idempotent (même principe que _ensure_z2m_availability) :
    Alarmo active tout seul les modes "absent"/"présent" à sa toute première
    installation (store.py::async_factory_default, vérifié dans la source
    officielle) mais PAS "nuit" — sans quoi cocher "nuit" sur un capteur serait
    sans effet, le mode lui-même n'existant pas encore côté panneau. Un seul
    appel one-shot par site suffit (persiste en base Alarmo), mais on le revérifie
    à chaque démarrage pour couvrir les sites déjà provisionnés avant ce fix.

    Étendu le 2026-09-08 (demande explicite Hicham, après avoir remarqué un
    délai de 60s perceptible en armant "Présent"/"Nuit" depuis l'app locale) :
    force AUSSI un délai de sortie COURT (_ALARMO_SHORT_EXIT_TIME, 5s) pour ces
    deux modes. Contrairement à "Absent" (on doit réellement sortir de la
    maison — délai de sortie raisonnable, laissé au défaut usine Alarmo,
    15s/30s vérifiés en réel), "Présent"/"Nuit" s'arment alors qu'on reste DANS
    la maison : un long délai de sortie n'a pas lieu d'être. Le défaut usine
    Alarmo pour "Présent" s'est avéré être 60s sur le site de test (jamais
    explicitement fixé par notre code jusqu'ici, juste préservé tel quel) —
    même chose pour "Nuit" (60s, mais LÀ hardcodé par nous-mêmes à l'origine,
    juste trop long). Comme pour l'activation du mode nuit lui-même : un mode
    d'armement n'est pas un choix personnalisable par site (cf. commentaire de
    _ensure_alarmo_area_name(), qui documente cette distinction) — donc forcé
    à chaque démarrage, pas seulement au tout premier provisionnement. Sans
    condition sur "déjà activé" comme avant (la vérification portait UNIQUEMENT
    sur `enabled`, jamais rejouée une fois vrai — insuffisant maintenant qu'il
    faut aussi corriger `exit_time` sur des sites où le mode nuit est déjà
    activé, comme le site de test)."""
    area_id, area = _alarmo_get_sole_area()
    if not area_id:
        return
    modes = area.get("modes") or {}
    away = modes.get("armed_away") or {}
    home = modes.get("armed_home") or {}
    night = modes.get("armed_night") or {}
    already_ok = (
        night.get("enabled")
        and home.get("exit_time") == _ALARMO_SHORT_EXIT_TIME
        and night.get("exit_time") == _ALARMO_SHORT_EXIT_TIME
    )
    if already_ok:
        log("[alarmo] ✓ Mode nuit activé, délais présent/nuit déjà courts — rien à faire")
        return
    payload = {
        "area_id": area_id,
        "modes": {
            # attr.evolve() côté Alarmo remplace tout le dict "modes" — il faut
            # renvoyer les modes déjà activés pour ne pas les écraser.
            "armed_away": {
                "enabled": bool(away.get("enabled", True)),
                "exit_time": away.get("exit_time", 60),
                "entry_time": away.get("entry_time", 60),
                "trigger_time": away.get("trigger_time", 1800),
            },
            "armed_home": {
                "enabled": bool(home.get("enabled", True)),
                "exit_time": _ALARMO_SHORT_EXIT_TIME,
                "entry_time": home.get("entry_time", 30),
                "trigger_time": home.get("trigger_time", 1800),
            },
            "armed_night": {
                "enabled": True,
                "exit_time": _ALARMO_SHORT_EXIT_TIME,
                "entry_time": night.get("entry_time", 30),
                "trigger_time": night.get("trigger_time", 1800),
            },
        },
    }
    r = ha_post("/alarmo/area", payload)
    if r.ok:
        log(f"[alarmo] ✓ Mode nuit activé, délais présent/nuit réduits à {_ALARMO_SHORT_EXIT_TIME}s")
    else:
        warn(f"[alarmo] Configuration modes présent/nuit échouée ({r.status_code}): {r.text[:200]}")


# Réglages "Modes" (délai de sortie/entrée, temps de fonctionnement avant
# réarmement, actif) + "Généraux" (désactivation après déclenchement) — demande
# Hicham (2026-08-09) après avoir montré les 3 onglets natifs Alarmo
# (Généraux/Modes/Zones) et comparé avec notre app qui n'exposait aucun des
# deux. Limité aux 3 modes déjà connus du reste de l'app (away/home/night,
# cf. AlarmoArmMode) — Vacances/Exception personnalisée jamais utilisés
# ailleurs, décision explicite de ne pas les exposer maintenant.
_ALARMO_MODE_STATE_KEYS = {"away": "armed_away", "home": "armed_home", "night": "armed_night"}


def handle_alarmo_get_area_modes() -> dict:
    _, area = _alarmo_get_sole_area()
    return {"modes": (area or {}).get("modes") or {}}


def handle_alarmo_set_area_mode(
    mode: str, enabled: bool, exit_time: int | None, entry_time: int | None, trigger_time: int | None,
) -> dict:
    state_key = _ALARMO_MODE_STATE_KEYS.get(mode)
    if not state_key:
        return {"ok": False, "detail": "mode invalide"}
    area_id, area = _alarmo_get_sole_area()
    if not area_id:
        return {"ok": False, "detail": "Alarmo non configuré"}
    # attr.evolve() côté Alarmo remplace tout le dict "modes" d'un coup (même
    # piège déjà rencontré dans _ensure_alarmo_night_mode) — renvoyer TOUS les
    # modes existants, pas seulement celui modifié, sous peine d'effacer les
    # réglages des autres modes.
    modes = dict((area or {}).get("modes") or {})
    modes[state_key] = {
        "enabled": bool(enabled), "exit_time": exit_time,
        "entry_time": entry_time, "trigger_time": trigger_time,
    }
    r = ha_post("/alarmo/area", {"area_id": area_id, "modes": modes})
    if not r.ok:
        return {"ok": False, "detail": r.text[:200]}
    return {"ok": True}


def handle_alarmo_get_general_config() -> dict:
    result = _ha_ws_call("alarmo/config")
    return result.get("result") if result and result.get("success") else {}


def handle_alarmo_set_general_config(disarm_after_trigger: bool) -> dict:
    r = ha_post("/alarmo/config", {"disarm_after_trigger": bool(disarm_after_trigger)})
    if not r.ok:
        return {"ok": False, "detail": r.text[:200]}
    return {"ok": True}


_ALARMO_FACTORY_DEFAULT_NAME = "Alarmo"  # store.py::async_factory_default, en dur côté Alarmo


def _ensure_alarmo_area_name():
    """Patch one-shot idempotent : renomme la zone "Alarmo" (nom par défaut imposé
    par Alarmo à sa création, store.py::async_factory_default) en "Habitation" —
    plus professionnel pour un client final (demande Hicham, 2026-07-31). Ne
    renomme QUE si le nom est encore le défaut Alarmo intouché — jamais un nom
    déjà personnalisé par nous ou un client, contrairement à _ensure_alarmo_night_mode()
    qui force toujours l'état voulu (un nom est un choix libre, un mode d'armement
    ne l'est pas). Important : renommer change aussi l'entity_id du panneau
    (`alarm_control_panel.{slugify(name)}`, vérifié dans alarm_control_panel.py) —
    volontairement fait tôt (juste après la création de la zone), avant qu'un client
    n'ait pu câbler une automatisation ou un clavier physique dessus."""
    area_id, area = _alarmo_get_sole_area()
    if not area_id or (area.get("name") or "") != _ALARMO_FACTORY_DEFAULT_NAME:
        return
    r = ha_post("/alarmo/area", {"area_id": area_id, "name": "Habitation"})
    if r.ok:
        log("[alarmo] ✓ Zone renommée en 'Habitation'")
    else:
        warn(f"[alarmo] Renommage de zone échoué ({r.status_code}): {r.text[:200]}")


def _alarmo_panel_entity_id(area_id: str) -> str | None:
    """entity_id du panneau alarm_control_panel de la zone — factorisé, utilisé par
    handle_alarmo_get_panel_state() et _ensure_alarmo_sos_automation()."""
    entities_result = _ha_ws_call("alarmo/entities")
    entities = entities_result.get("result") if entities_result and entities_result.get("success") else []
    return next((e.get("entity_id") for e in entities or [] if e.get("area_id") == area_id), None)


def _exposes_match_ias_ace_keypad(exposes: list[dict], required_actions: set[str]) -> bool:
    """Signature générique d'un clavier d'alarme Zigbee sur les exposes d'UN SEUL
    appareil — factorisé de _find_ias_ace_keypad() (2026-08-08) pour être réutilisable
    aussi par _detect_device_type(), qui ne voit qu'un device à la fois. Cf.
    _find_ias_ace_keypad ci-dessous pour le détail de pourquoi ce vocabulaire est
    fiable indépendamment de la marque (cluster IAS ACE standard)."""
    for expose in exposes:
        if expose.get("name") != "action":
            continue
        values = set(expose.get("values") or [])
        if required_actions.issubset(values):
            return True
    return False


def _find_ias_ace_keypad(devices_list, required_actions: set[str]) -> str | None:
    """Détection GÉNÉRIQUE d'un clavier d'alarme Zigbee — pas un modèle figé (même
    principe que §136). N'importe quel appareil dont les exposes Z2M documentent
    TOUTES les actions demandées est traité comme clavier compatible.

    Ces noms d'action ("disarm", "arm_day_zones", "arm_night_zones", "arm_all_zones",
    "emergency"…) ne sont PAS propres à un fabricant — vérifié (2026-08-03) : ce sont
    les valeurs standard du cluster Zigbee ZCL "IAS Ancillary Control Equipment"
    (IAS ACE, device type 0x0401), conçu précisément pour les claviers d'alarme.
    N'importe quelle marque qui respecte ce cluster standard (Hive KEYPAD001,
    Linkind, Xfinity XHK1-UE, Develco/frient KEYZB-110…) expose donc exactement le
    même vocabulaire — cette détection n'est pas limitée au clavier d'Hicham."""
    for d in devices_list:
        exposes = (d.get("definition") or {}).get("exposes") or []
        if _exposes_match_ias_ace_keypad(exposes, required_actions):
            return d.get("friendly_name")
    return None


_SOS_AUTOMATION_OBJECT_ID = "domoticium_sos_trigger"
_sos_wired_for: str | None = None  # friendly_name du clavier déjà câblé — évite de republier l'automation à chaque cycle bridge/devices si rien n'a changé
_sos_no_match_logged = False  # (2026-11-09) évite de spammer les logs toutes les ~5min pour un site sans clavier — log une seule fois par transition, cf. commentaire sur son utilisation plus bas


def _ensure_alarmo_sos_automation(devices_list):
    """Câble le bouton SOS d'un clavier Zigbee vers alarm_control_panel.alarm_trigger
    sur la zone Alarmo — appelé à chaque réception de zigbee2mqtt/bridge/devices
    (cf. _sync_zigbee_devices_direct), donc réactif dès qu'un clavier compatible
    est appairé, sans attendre un redémarrage.

    Précondition explicite demandée par Hicham (2026-08-02) : "juste après avoir
    installé Alarmo et s'être assuré de la bonne installation de celui-ci" —
    _alarmo_get_sole_area() retourne None tant qu'Alarmo n'est pas installé/configuré,
    donc rien ne se passe avant, même idempotent (pas de risque de câbler sur une
    zone qui n'existe pas encore).

    Piège connu, à surveiller en conditions réelles : sur le clavier Develco/frient
    KEYZB-110 (celui d'Hicham), un bug Z2M non résolu (issue #19123, vérifié
    2026-08-02) envoie parfois une action VIDE au lieu de "emergency" lors de l'appui
    SOS — cette automation reste correcte (déclenche bien sur "emergency" quand Z2M
    le rapporte correctement), mais un test réel sur le clavier physique est
    nécessaire pour confirmer la fiabilité réelle du bouton lui-même, pas garanti
    par ce fix seul."""
    global _sos_wired_for, _sos_no_match_logged
    area_id, _ = _alarmo_get_sole_area()
    if not area_id:
        # (2026-11-09) Diagnostic ajouté après un cas réel où ce retour silencieux
        # a été pris, à tort, pour un problème de détection du clavier (alors
        # qu'Alarmo/sa zone n'étaient en fait pas la cause) — ce cas est rare
        # (avant/juste après l'installation d'Alarmo) donc pas de risque de spam.
        log(f"[alarmo] SOS: zone Alarmo introuvable ({len(devices_list)} devices reçus) — rien câblé pour l'instant")
        return  # Alarmo pas encore installé/configuré

    friendly_name = _find_ias_ace_keypad(devices_list, {"emergency"})
    if not friendly_name:
        # Audit add-on 2026-09-22 : un clavier désappairé/renommé laissait
        # l'automation SOS câblée sur un topic MQTT mort — orpheline mais
        # inerte (plus jamais déclenchée), jamais nettoyée jusqu'ici. Un
        # renommage vers un AUTRE clavier compatible reste géré normalement
        # plus bas (même object_id, l'upsert la remplace en place).
        if _sos_wired_for is not None:
            _handle_ha_command(json.dumps({
                "type": "automation_delete", "object_id": _SOS_AUTOMATION_OBJECT_ID,
            }).encode())
            log(f"[alarmo] SOS retiré (plus de clavier compatible appairé, était câblé sur '{_sos_wired_for}')")
            _sos_wired_for = None
        # (2026-11-09) Une seule fois par transition vers "aucun match" — sinon
        # spam toutes les ~5min pour n'importe quel site sans clavier SOS.
        if not _sos_no_match_logged:
            log(f"[alarmo] SOS: aucun clavier IAS ACE (action='emergency') parmi {len(devices_list)} devices Zigbee reçus")
            _sos_no_match_logged = True
        return
    _sos_no_match_logged = False
    if friendly_name == _sos_wired_for:
        return  # déjà câblé sans changement

    panel_entity_id = _alarmo_panel_entity_id(area_id)
    if not panel_entity_id:
        log(f"[alarmo] SOS: clavier '{friendly_name}' détecté mais panel_entity_id introuvable pour la zone '{area_id}' — rien câblé")
        return

    auto_cfg = {
        "type": "automation_upsert",
        "object_id": _SOS_AUTOMATION_OBJECT_ID,
        "alias": "Domoticium — SOS clavier",
        "trigger": [{
            "platform": "mqtt",
            "topic": f"zigbee2mqtt/{friendly_name}",
            # default('') : ce topic publie TOUT l'état du clavier à chaque mise à
            # jour (battery/heartbeat compris), pas seulement les appuis bouton — les
            # messages sans clé "action" faisaient logguer un warning HA en boucle
            # ("dict object has no attribute action"), trouvé en creusant le journal
            # HA en direct (2026-08-08). Filtre Jinja standard pour ce cas, l'automation
            # elle-même était déjà correcte (ne se déclenche que sur "emergency").
            "value_template": "{{ value_json.action | default('') }}",
            "payload": "emergency",
        }],
        "action": [{
            "action": "alarm_control_panel.alarm_trigger",
            "target": {"entity_id": panel_entity_id},
        }],
    }
    # (2026-11-09) Retour vérifié — avant ça, un rejet de _validate_ha_action_steps
    # (ex: alarm_control_panel non trusted) logguait quand même "✓ câblé" en-dessous,
    # cf. _TRUSTED_WIRING_SERVICES pour le détail du bug réel trouvé ainsi.
    if not _handle_ha_command(json.dumps(auto_cfg).encode(), trusted_wiring=True):
        warn(f"[alarmo] Échec câblage SOS sur '{friendly_name}' — voir le warn [ha/command] ci-dessus")
        return
    _sos_wired_for = friendly_name
    log(f"[alarmo] ✓ SOS câblé sur le clavier '{friendly_name}' → {panel_entity_id}")


_KEYPAD_ARM_OBJECT_ID = "domoticium_keypad_arm"
_KEYPAD_FEEDBACK_OBJECT_ID = "domoticium_keypad_feedback"
_keypad_wired_for: str | None = None  # friendly_name du clavier déjà câblé (arm/disarm + retour LED)
_keypad_no_match_logged = False  # (2026-11-09) même principe anti-spam que _sos_no_match_logged

# mode clavier (ZCL IAS ACE) → service Alarmo à appeler, avec le code tapé
_KEYPAD_ACTION_TO_SERVICE = {
    "disarm":          "alarm_control_panel.alarm_disarm",
    "arm_day_zones":   "alarm_control_panel.alarm_arm_home",
    "arm_night_zones": "alarm_control_panel.alarm_arm_night",
    "arm_all_zones":   "alarm_control_panel.alarm_arm_away",
}

# état réel du panneau Alarmo → mode à republier vers le clavier (ses LED) — même
# vocabulaire ZCL IAS ACE que les actions reçues, dans l'autre sens.
_ALARMO_STATE_TO_KEYPAD_MODE = {
    "disarmed":     "disarm",
    "armed_home":   "arm_day_zones",
    "armed_night":  "arm_night_zones",
    "armed_away":   "arm_all_zones",
    "pending":      "entry_delay",
    "arming":       "exit_delay",
    "triggered":    "in_alarm",
}


def _ensure_alarmo_keypad_control(devices_list):
    """Câble l'armement/désarmement complet (Absent/Présent/Nuit + code) d'un
    clavier Zigbee vers Alarmo, DANS LES DEUX SENS — Alarmo n'a aucune prise en
    charge native d'un clavier physique (vérifié dans son README + un exemple
    communautaire déjà construit pour ce type de clavier, 2026-08-03) :

    1. Clavier → Alarmo : le clavier publie {action, action_code, action_transaction}
       sur son topic MQTT — une automation appelle le service alarm_control_panel
       correspondant avec le code tapé. Alarmo reste la SEULE autorité de validation
       du code (déjà le cas pour les boutons de l'app et code_arm_required) — pas de
       liste de codes dupliquée ici, contrairement à certains exemples communautaires
       qui revalident eux-mêmes le code (risque de désynchronisation entre 2 listes,
       écarté explicitement avec Hicham, 2026-08-03).
    2. Alarmo → clavier : dès que l'état RÉEL du panneau change, une 2e automation
       republie ce même état vers le clavier (zigbee2mqtt/{clavier}/set) pour que ses
       LED reflètent la vérité — jamais ce que le client vient juste de taper (un
       code refusé ne fait donc simplement rien, pas de fausse confirmation "armé").

    Même précondition et même détection générique que _ensure_alarmo_sos_automation
    (cf. _find_ias_ace_keypad) — n'importe quel clavier conforme au cluster Zigbee
    standard IAS ACE, pas un modèle figé."""
    global _keypad_wired_for, _keypad_no_match_logged
    area_id, _ = _alarmo_get_sole_area()
    if not area_id:
        log(f"[alarmo] Clavier: zone Alarmo introuvable ({len(devices_list)} devices reçus) — rien câblé pour l'instant")
        return  # Alarmo pas encore installé/configuré

    friendly_name = _find_ias_ace_keypad(devices_list, {"disarm", "arm_all_zones"})
    if not friendly_name:
        # Audit add-on 2026-09-22 : même nettoyage que _ensure_alarmo_sos_automation
        # (cf. son commentaire) — les 2 automatisations câblées sur un clavier
        # disparu restaient orphelines indéfiniment.
        if _keypad_wired_for is not None:
            _handle_ha_command(json.dumps({
                "type": "automation_delete", "object_id": _KEYPAD_ARM_OBJECT_ID,
            }).encode())
            _handle_ha_command(json.dumps({
                "type": "automation_delete", "object_id": _KEYPAD_FEEDBACK_OBJECT_ID,
            }).encode())
            log(f"[alarmo] Armement/désarmement clavier retiré (plus de clavier compatible appairé, était câblé sur '{_keypad_wired_for}')")
            _keypad_wired_for = None
        if not _keypad_no_match_logged:
            log(f"[alarmo] Clavier: aucun clavier IAS ACE (action avec disarm+arm_all_zones) parmi {len(devices_list)} devices Zigbee reçus")
            _keypad_no_match_logged = True
        return
    _keypad_no_match_logged = False
    if friendly_name == _keypad_wired_for:
        return

    panel_entity_id = _alarmo_panel_entity_id(area_id)
    if not panel_entity_id:
        log(f"[alarmo] Clavier: '{friendly_name}' détecté mais panel_entity_id introuvable pour la zone '{area_id}' — rien câblé")
        return

    keypad_topic = f"zigbee2mqtt/{friendly_name}"

    # (2026-11-23) Pas de réponse d'erreur envoyée au clavier : essayée en 2.9.253 (invalid_code / not_ready avec la
    # transaction), elle a au contraire SUPPRIMÉ le signal d'erreur du clavier (rouge + bips) que le clavier donne de lui-même
    # quand personne ne répond à sa requête — constaté par Hicham au retest. Un code refusé ne fait donc rien ici, volontairement.
    arm_cfg = {
        "type": "automation_upsert",
        "object_id": _KEYPAD_ARM_OBJECT_ID,
        "alias": "Domoticium — Armement clavier",
        "trigger": [{"platform": "mqtt", "topic": keypad_topic}],
        "action": [{
            "choose": [
                {
                    "conditions": [{
                        "condition": "template",
                        "value_template": f"{{{{ trigger.payload_json.action == '{action}' }}}}",
                    }],
                    "sequence": [{
                        "action": service,
                        "target": {"entity_id": panel_entity_id},
                        # default('') : un clavier sans code configuré (code_arm_required
                        # désactivé) peut omettre action_code du payload — un template
                        # non défini planterait sinon l'appel de service.
                        "data": {"code": "{{ trigger.payload_json.action_code | default('') }}"},
                    }],
                }
                for action, service in _KEYPAD_ACTION_TO_SERVICE.items()
            ],
        }],
    }
    # (2026-11-09) Retours vérifiés — cf. commentaire équivalent dans
    # _ensure_alarmo_sos_automation pour le détail du bug réel trouvé ainsi.
    arm_ok = _handle_ha_command(json.dumps(arm_cfg).encode(), trusted_wiring=True)

    feedback_cfg = {
        "type": "automation_upsert",
        "object_id": _KEYPAD_FEEDBACK_OBJECT_ID,
        "alias": "Domoticium — Retour LED clavier",
        "trigger": [{"platform": "state", "entity_id": panel_entity_id}],
        "action": [{
            "choose": [
                {
                    "conditions": [{"condition": "state", "entity_id": panel_entity_id, "state": state}],
                    "sequence": [{
                        "action": "mqtt.publish",
                        "data": {
                            "topic": f"{keypad_topic}/set",
                            "payload": json.dumps({"arm_mode": {"mode": mode}}),
                        },
                    }],
                }
                for state, mode in _ALARMO_STATE_TO_KEYPAD_MODE.items()
            ],
        }],
    }
    feedback_ok = _handle_ha_command(json.dumps(feedback_cfg).encode(), trusted_wiring=True)

    if not (arm_ok and feedback_ok):
        warn(f"[alarmo] Échec câblage clavier sur '{friendly_name}' (arm={bool(arm_ok)}, feedback={bool(feedback_ok)}) — voir le warn [ha/command] ci-dessus")
        return
    _keypad_wired_for = friendly_name
    log(f"[alarmo] ✓ Armement/désarmement clavier câblé sur '{friendly_name}' ↔ {panel_entity_id}")


# ── Import d'automatisations HA → app (2026-08-27) ───────────────────────────
# Hicham : "il faudrait pouvoir synchroniser Home Assistant et l'application
# web tout comme les scènes et les équipements" — jusqu'ici la sync des
# automatisations n'allait que dans un sens (site → HA). Construit à partir
# des constantes déjà déclarées ci-dessus (jamais une chaîne en dur) pour
# qu'un futur renommage ne puisse jamais faire fuiter une automatisation
# interne (câblage bouton SOS / armement clavier / retour LED) vers le
# client — ces 3-là ne doivent JAMAIS être visibles sur le site.
_INTERNAL_AUTOMATION_OBJECT_IDS = {
    _SOS_AUTOMATION_OBJECT_ID,
    _KEYPAD_ARM_OBJECT_ID,
    _KEYPAD_FEEDBACK_OBJECT_ID,
    "domoticium_heartbeat",       # legacy, cf. _remove_legacy_heartbeat_automation_once
    "domoticium_camera_status",   # legacy, cf. plus bas
    "domoticium_alarm_action",    # legacy — v1 des actions matérielles Alarmo (cf.
                                   # commentaire "Actions matérielles sur évènement
                                   # alarme" plus bas), remplacée depuis par le vrai
                                   # mécanisme natif Alarmo (WS alarmo/automations) mais
                                   # jamais supprimée des sites déjà provisionnés avec
                                   # l'ancienne version — trouvée en vérifiant contre le
                                   # vrai HA du site de test (2026-08-26), pas supposée.
}


def handle_list_ha_automations() -> dict:
    """Énumère les automatisations HA (GET /states filtré sur automation.*, il
    n'existe pas d'endpoint REST "lister toutes les configs" côté HA — seul
    /config/automation/config/{id} est unitaire) et lit la config complète de
    chacune, hors automatisations internes Domoticium. Best-effort par
    automatisation (un config illisible ne doit pas faire échouer tout le
    reste) — le web décide ensuite (classifyHaAutomation) si elle rentre dans
    le modèle simple du site ou doit rester en lecture seule.

    `ok: False` signale un échec de lecture des états eux-mêmes (HA hors
    ligne, etc.) — le web ne doit JAMAIS purger ses lignes "importées de HA"
    sur une réponse dégradée, une liste vide ne veut pas dire "tout supprimé
    dans HA"."""
    try:
        r = ha_get("/states")
        if not r.ok:
            return {"ok": False, "automations": []}
        states = r.json()
    except Exception as e:
        warn(f"[automations-ha] lecture /states: {e}")
        return {"ok": False, "automations": []}

    automations = []
    for s in states:
        entity_id = s.get("entity_id", "")
        if not entity_id.startswith("automation."):
            continue
        attrs = s.get("attributes") or {}
        object_id = attrs.get("id")
        if object_id in _INTERNAL_AUTOMATION_OBJECT_IDS:
            continue

        config = None
        if object_id:
            try:
                cr = ha_get(f"/config/automation/config/{object_id}")
                if cr.ok:
                    config = cr.json()
            except Exception as e:
                warn(f"[automations-ha] lecture config {object_id}: {e}")
                # best-effort : on la remonte quand même sans config détaillée,
                # le web la classera en lecture seule faute de trigger/action.

        automations.append({
            "ha_object_id": object_id,
            "entity_id": entity_id,
            "alias": attrs.get("friendly_name", entity_id),
            "enabled": s.get("state") == "on",
            "config": config,
            "last_triggered": attrs.get("last_triggered"),
        })

    return {"ok": True, "automations": automations}


def handle_list_ha_scenes() -> dict:
    """Énumère les scènes HA natives (GET /states filtré sur scene.*) — mode
    local uniquement, chantier "vraie intégration locale" v7 (2026-09-08, cf.
    HANDOFF.md côté web). Les scènes Domoticium sont poussées vers HA comme
    de VRAIES scènes natives (domoticium_scene_<local_id>, domaine scene.*,
    cf. scene_upsert dans _handle_ha_command — avant le 2026-10-18 c'était des
    scripts, migré après avoir trouvé que mqtt.publish (nécessaire pour le
    Zigbee) n'a jamais été ajouté à ALLOWED_SERVICES lors de l'audit de
    sécurité du 2026-09-22, cassant silencieusement toute scène Zigbee) — en
    local, sans Supabase pour stocker leurs métadonnées (nom/icône/steps
    structurés), ce sont CES scènes elles-mêmes qui deviennent la seule
    source de vérité côté web (icon lu depuis l'attribut natif HA, steps
    redécompilés depuis `entities` via haSceneEntitiesToSteps, cf.
    lib/scenes.ts). Même limitation assumée que handle_list_ha_automations :
    pas d'endpoint REST "lister toutes les configs", lecture unitaire par
    scène derrière /states — best-effort, une scène illisible ne fait pas
    échouer les autres."""
    try:
        r = ha_get("/states")
        if not r.ok:
            return {"ok": False, "scenes": []}
        states = r.json()
    except Exception as e:
        warn(f"[scenes-ha] lecture /states: {e}")
        return {"ok": False, "scenes": []}

    scenes = []
    for s in states:
        entity_id = s.get("entity_id", "")
        if not entity_id.startswith("scene."):
            continue
        attrs = s.get("attributes") or {}

        # (2026-10-18) VRAI BUG trouvé en auditant ce fichier : l'object_id de
        # CONFIG (= unique_id entity registry) n'est PAS le suffixe de
        # l'entity_id pour scene.* — HA le dérive du NOM, slugifié (cf.
        # _entity_id_by_unique_id). Ce code faisait donc TOUJOURS
        # /config/scene/config/{suffixe_du_nom}, qui ne matche jamais le
        # VRAI id de config (domoticium_scene_<uuid>) — `config` restait
        # silencieusement null pour CHAQUE scène en mode local, jamais
        # détecté sans relire la vraie entity registry.
        entry = _entity_registry_entry(entity_id)
        object_id = entry.get("unique_id") if entry else entity_id.split(".", 1)[1]

        config = None
        try:
            cr = ha_get(f"/config/scene/config/{object_id}")
            if cr.ok:
                config = cr.json()
        except Exception as e:
            warn(f"[scenes-ha] lecture config {object_id}: {e}")

        scenes.append({
            "object_id": object_id,
            "entity_id": entity_id,
            "alias": attrs.get("friendly_name", entity_id),
            "icon": attrs.get("icon"),
            "config": config,
        })

    return {"ok": True, "scenes": scenes}


def handle_get_device_triggers(ieee_address: str | None, matter_node_id: int | None) -> dict:
    """Liste les "device triggers" HA d'une télécommande/bouton de scène (Zigbee
    ou Matter) — pas d'entité à lire, ce mécanisme est la source de vérité pour
    savoir QUELLES actions (single/double/hold…) ce modèle précis sait produire.
    Piège connu, à faire savoir côté web : HA n'enregistre un device trigger
    qu'APRÈS au moins une pression réelle sur le bouton — un appareil tout juste
    appairé renverra une liste vide tant qu'il n'a jamais été pressé une fois."""
    ha_device_id = _get_ha_device_id(ieee_address=ieee_address, matter_node_id=matter_node_id)
    if not ha_device_id:
        return {"ok": True, "device_found": False, "triggers": []}

    result = _ha_ws_call("device_automation/trigger/list", device_id=ha_device_id)
    if not result or not result.get("success"):
        warn(f"[device-triggers] device_automation/trigger/list a échoué pour {ha_device_id}: {result}")
        return {"ok": False, "device_found": True, "triggers": []}

    raw = result.get("result", [])
    triggers = [
        {
            "domain": t.get("domain"),
            "type": t.get("type"),
            "subtype": t.get("subtype"),
            "device_id": t.get("device_id"),
        }
        for t in raw
        if isinstance(t, dict) and t.get("domain") and t.get("type")
    ]
    return {"ok": True, "device_found": True, "triggers": triggers}


def handle_energy_history(entity_id: str, hours: int, period: str = "hour") -> dict:
    """Consommation d'une entité énergie cumulative (ex: "prise salon >
    Énergie") via le système de STATISTIQUES long terme de HA
    (`recorder/statistics_during_period`), PAS l'historique brut d'états.
    Corrige un vrai bug trouvé par Hicham (2026-10-24, en comparant avec le
    graphe natif HA d'une prise connectée) : notre 1ère version lisait
    l'historique brut (/history/period) et calculait "dernier point - premier
    point" nous-mêmes — faux dès qu'un compteur se réinitialise (reboot du
    device) pendant la fenêtre, le delta devient alors négatif/aberrant. Le champ
    "change" des statistiques HA est déjà calculé par le Recorder en compensant
    ces remises à zéro (même mécanisme que les graphes HA natifs "Historique" et
    le tableau de bord "Énergie") — zéro logique de delta à réinventer ici.

    `period` (2026-10-30, chantier email de clôture de compte) : `"hour"` par
    défaut (seul appelant jusqu'ici, graphique 24h du dashboard) — passé tel
    quel à `recorder/statistics_during_period`, qui sait nativement agréger
    par `"day"`/`"week"`/`"month"`. Demander `"month"` directement à HA (6
    points sur 6 mois) plutôt que resommer nous-mêmes des centaines de points
    horaires : plus simple, et c'est exactement ce que fait déjà le Recorder
    pour les graphes HA natifs en vue longue durée."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    start_iso = start.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    end_iso = end.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    result = _ha_ws_call(
        "recorder/statistics_during_period",
        start_time=start_iso,
        end_time=end_iso,
        statistic_ids=[entity_id],
        period=period,
        types=["change"],
    )
    if not result or not result.get("success"):
        warn(f"[energy-history] statistics_during_period a échoué pour {entity_id}: {result}")
        return {"ok": False, "hourly": []}

    series = result.get("result", {}).get(entity_id, [])
    hourly = [
        {"start": s.get("start"), "kwh": round(s.get("change") or 0.0, 3)}
        for s in series
        if isinstance(s, dict)
    ]
    return {"ok": True, "hourly": hourly}


def handle_list_calendars() -> dict:
    """(2026-09-02) Liste les entités `calendar.*` déjà connues de HA — pour le
    déclencheur d'automatisation "Calendrier" (bloc Déclencheurs de l'éditeur
    avancé, demande Hicham). Aucune intégration calendrier n'est installée par
    l'addon lui-même (Google Agenda/CalDAV/local — au client de la connecter
    dans HA s'il le souhaite) ; cette route se contente de refléter ce qui
    existe déjà, avec une liste vide si rien n'est configuré (même repli que
    handle_get_device_triggers pour une télécommande jamais pressée)."""
    r = ha_get("/states")
    if not r.ok:
        warn(f"[calendars] /states {r.status_code}: {r.text[:150]}")
        return {"ok": False, "calendars": []}
    calendars = [
        {"entity_id": s.get("entity_id"), "name": (s.get("attributes") or {}).get("friendly_name") or s.get("entity_id")}
        for s in r.json()
        if isinstance(s, dict) and str(s.get("entity_id", "")).startswith("calendar.")
    ]
    return {"ok": True, "calendars": calendars}


def handle_list_counters() -> dict:
    """(2026-09-03) Liste les entités `counter.*` déjà connues de HA — pour
    référencer un compteur existant (créé par le client dans HA, Réglages →
    Assistants) dans une automatisation depuis l'app. Même principe que
    handle_list_calendars ci-dessous : aucun compteur n'est créé par l'addon
    lui-même, simple reflet de ce qui existe déjà côté HA."""
    r = ha_get("/states")
    if not r.ok:
        warn(f"[counters] /states {r.status_code}: {r.text[:150]}")
        return {"ok": False, "counters": []}
    counters = [
        {"entity_id": s.get("entity_id"), "name": (s.get("attributes") or {}).get("friendly_name") or s.get("entity_id")}
        for s in r.json()
        if isinstance(s, dict) and str(s.get("entity_id", "")).startswith("counter.")
    ]
    return {"ok": True, "counters": counters}


def handle_list_timers() -> dict:
    """(2026-09-03) Liste les entités `timer.*` déjà connues de HA — même
    principe que handle_list_counters ci-dessus."""
    r = ha_get("/states")
    if not r.ok:
        warn(f"[timers] /states {r.status_code}: {r.text[:150]}")
        return {"ok": False, "timers": []}
    timers = [
        {"entity_id": s.get("entity_id"), "name": (s.get("attributes") or {}).get("friendly_name") or s.get("entity_id")}
        for s in r.json()
        if isinstance(s, dict) and str(s.get("entity_id", "")).startswith("timer.")
    ]
    return {"ok": True, "timers": timers}


def handle_list_areas() -> dict:
    """(2026-09-02) Liste les areas (pièces) HA — pour l'action d'automatisation
    "Pièce entière" (bloc Actions de l'éditeur avancé, demande Hicham : "cibler
    une pièce entière"). Réutilise _get_ha_areas() (déjà utilisé en interne pour
    l'assignation automatique device→pièce, cf. _sync_zigbee_devices_direct) —
    reflet direct du registre HA, jamais recalculé depuis nos propres `rooms` :
    une pièce sans aucun device assigné n'a pas encore d'area HA correspondante,
    et une pièce renommée directement dans HA reste exacte ici sans synchro."""
    areas = _get_ha_areas()
    return {
        "ok": True,
        "areas": [
            {"area_id": a.get("area_id"), "name": a.get("name") or a.get("area_id")}
            for a in areas
            if isinstance(a, dict) and a.get("area_id")
        ],
    }


# Actions matérielles sur évènement alarme (sirène/lumières...) — demande
# Hicham (2026-08-05, "je veux tout" après explication des 3 features Alarmo
# manquantes ; 2026-08-09, comparaison directe avec le panneau natif Alarmo
# "Actions" — "récupère les bonnes variables", "il faut le garder tel que
# décrit dans alarmo").
#
# v1 (2026-08-05→09) construisait sa PROPRE automatisation HA générique
# (déclenchée sur l'état du panneau, une seule cible, marche/arrêt câblés en
# dur) — délibérément PAS via le système propriétaire d'Alarmo. Abandonné :
# Hicham a comparé avec le panneau natif Alarmo (captures à l'appui) et
# demandé de repartir sur le vrai mécanisme Alarmo (multi-équipements,
# plusieurs entrées possibles), avec notre propre formulaire par-dessus,
# pas de nouvelle logique inventée.
#
# Vraie API Alarmo (vérifiée dans son code source, PAS supposée) :
# - Lecture : WS `alarmo/automations` (AUCUN GET REST — AlarmoAutomationView
#   n'a qu'un POST, confirmé par un appel réel qui renvoie 405) → dict
#   {automation_id: {name, type, triggers, actions, enabled}}.
# - Écriture : POST REST `/api/alarmo/automations` (mêmes principe que
#   `/api/alarmo/sensor_groups`, déjà utilisé pour les groupes de capteurs) —
#   `remove: true` supprime, `automation_id` fourni = modification, absent =
#   création. `triggers: [{event, modes?}]`, `actions: [{entity_id, service}]`
#   — `automations.py::async_execute_automation` découpe `service` en
#   `domain.service` et appelle `hass.services.async_call()` directement,
#   sans magie cachée : PAS d'appariement automatique marche/arrêt, une
#   entrée = un évènement = une liste d'actions, exactement comme le panneau
#   natif. Si un client veut "allumer au déclenchement ET éteindre au
#   désarmement", il crée 2 entrées distinctes — reproduit fidèlement le vrai
#   comportement Alarmo plutôt que d'improviser un raccourci.
# §184 (2026-08-09) — corrigé après un vrai bug trouvé par Hicham : le panneau
# natif Alarmo affichait "Élément inconnu" pour "trigger". Les 5 valeurs
# précédentes ("trigger"/"arm"/"disarm"/"entry"/"leave") venaient des
# constantes internes `const.py::EVENT_*` — un bus d'évènements différent
# (diagnostics), pas le vocabulaire des automatisations. Vérifié dans la VRAIE
# source frontend (`frontend/src/types.ts::EAlarmEvent`) ET le comparateur
# backend (`automations.py::AutomationHandler.async_alarm_state_changed`,
# comparaison de chaînes EXACTE contre l'état alarme littéral) : les vraies
# valeurs sont "triggered"/"armed"/"disarmed"/"pending"/"arming" — une action
# créée avec l'ancien vocabulaire ne se serait JAMAIS déclenchée (écriture
# acceptée sans erreur, aucune validation sémantique, juste cv.string côté
# Alarmo), silencieusement inerte.
_ALARMO_ACTION_EVENTS = {"triggered", "armed", "disarmed", "pending", "arming"}


def handle_alarmo_get_automations() -> dict:
    result = _ha_ws_call("alarmo/automations")
    return result.get("result") if result and result.get("success") else {}


def handle_alarmo_set_automation(
    automation_id: str | None, name: str | None, event: str | None,
    modes: list | None, entities: list | None, service_verb: str | None,
    enabled: bool | None, remove: bool = False,
) -> dict:
    if remove:
        if not automation_id:
            return {"ok": False, "detail": "automationId requis"}
        r = ha_post("/alarmo/automations", {"automation_id": automation_id, "remove": True})
        return {"ok": True} if r.ok else {"ok": False, "detail": r.text[:200]}

    if event not in _ALARMO_ACTION_EVENTS:
        return {"ok": False, "detail": "Évènement invalide"}
    if service_verb not in ("turn_on", "turn_off"):
        return {"ok": False, "detail": "Action invalide"}
    if not entities:
        return {"ok": False, "detail": "Au moins un équipement requis"}
    if not name:
        return {"ok": False, "detail": "Nom requis"}

    trigger: dict = {"event": event}
    if modes:
        # Alarmo valide `modes` contre const.ARM_MODES (vérifié dans son code
        # source) — ce sont les VALEURS D'ÉTAT complètes ("armed_away", pas
        # "away") : notre nomenclature courte ("away"/"home"/"night", partagée
        # avec le reste de l'app, ex. armer/désarmer) doit être traduite ici,
        # jamais envoyée telle quelle. Sans cette traduction, Alarmo rejetait
        # la requête en 400 (validation Voluptuous côté HA) — bug réel trouvé
        # en conditions réelles (Hicham, 2026-08-09, "Error: 502" à la
        # création d'une action avec un mode coché).
        mode_map = {"away": "armed_away", "home": "armed_home", "night": "armed_night"}
        trigger["modes"] = [mode_map.get(m, m) for m in modes]
    # Les scènes (scene.*, scripts HA bruts éventuels en script.*) et
    # automatisations (automation.*) n'ont pas de notion d'allumer/éteindre —
    # les exposer avec le toggle Allumer/Éteindre n'aurait aucun sens (une
    # scène s'active, une automatisation se déclenche, point). Demande Hicham
    # 2026-08-09 : ces cibles sont forcées sur leur seul service pertinent,
    # quel que soit service_verb ; tout le reste (lumières, prises,
    # sirènes…) garde le comportement historique. "scene" ajouté 2026-10-18 :
    # les scènes Domoticium sont maintenant des scènes HA natives (scene.*),
    # plus des scripts — même raisonnement, scene.turn_on est le seul service
    # valide pour une scène.
    def _action_service(entity_id: str) -> str:
        domain = entity_id.split(".", 1)[0]
        if domain == "script":
            return "script.turn_on"
        if domain == "scene":
            return "scene.turn_on"
        if domain == "automation":
            return "automation.trigger"
        return f"{domain}.{service_verb}"

    actions = [{"entity_id": entity_id, "service": _action_service(entity_id)} for entity_id in entities]
    payload = {
        "name": name, "type": "action",
        "triggers": [trigger], "actions": actions,
        "enabled": enabled if enabled is not None else True,
    }
    if automation_id:
        payload["automation_id"] = automation_id

    r = ha_post("/alarmo/automations", payload)
    if not r.ok:
        return {"ok": False, "detail": r.text[:200]}
    log(f"[alarmo] ✓ Action '{name}' câblée ({event} → {service_verb} sur {len(entities)} équipement(s))")
    return {"ok": True}


def write_frigate_config():
    """Écrit /homeassistant/frigate.yml. Le prepare script Frigate le copie dans son
    stockage privé à chaque démarrage — c'est la seule voie de config utilisée.

    Écriture atomique (audit add-on 2026-09-22) : un `open(..., "w")` direct
    laisse une fenêtre où le fichier est tronqué/vide pendant l'écriture — une
    coupure d'alimentation ou un kill du process pile à ce moment corrompt
    frigate.yml, qui refuse alors de démarrer au redémarrage suivant (panne
    caméra totale du site jusqu'à intervention manuelle). Écrit dans un fichier
    temporaire sur le MÊME volume puis `os.replace()` (atomique sous Linux,
    même filesystem) — soit l'ancien fichier reste intact, soit le nouveau
    est intégralement en place, jamais un état intermédiaire visible."""
    with _camera_configure_lock:
        content = _generate_frigate_yaml()
        target = "/homeassistant/frigate.yml"
        tmp = f"{target}.tmp-{os.getpid()}"
        with open(tmp, "w") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
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


def _default_for_required_field(field: dict):
    """Valeur par défaut raisonnable pour UN champ de schéma HA marqué "required"
    sans valeur déjà connue (connexion broker) — cf. `_fill_required_schema_defaults`.
    Ne couvre QUE ce qui peut apparaître dans une section "avancé" repliée (booléens,
    listes déroulantes) ; un champ required d'un autre type (texte/fichier libre sans
    défaut évident) n'est pas deviné, laissé de côté (HA renverra une erreur explicite
    plutôt qu'une valeur inventée silencieusement)."""
    if "default" in field:
        return field["default"]
    selector = field.get("selector") or {}
    if "boolean" in selector:
        return False
    if "select" in selector:
        options = (selector["select"] or {}).get("options") or []
        # Options = liste de strings ("off"/"tcp"/...) OU de {"value","label"} —
        # les deux formes apparaissent dans le même schéma HA (ex: set_ca_cert vs transport).
        values = [o if isinstance(o, str) else o.get("value") for o in options]
        for preferred in ("off", "tcp", "none", "disabled"):
            if preferred in values:
                return preferred
        return values[0] if values else None
    return None


def _fill_required_schema_defaults(schema: list, known: dict) -> dict:
    """Parcourt un schéma de formulaire HA et complète, pour chaque champ "required"
    PAS déjà couvert par `known` (connexion broker), une valeur par défaut sûre —
    y compris récursivement dans les sections "expandable" (repliées dans l'UI,
    mais dont Postgres... pardon, HA valide quand même les champs required à
    l'intérieur). Bug réel trouvé en install réelle (2026-11-08) : le schéma MQTT HA
    a gagné un groupe "other_settings" (TLS/transport avancés) marqué required — le
    payload ne le fournissant jamais, HA refusait tout le formulaire ("other_settings:
    required key not provided"), MQTT ne se configurait jamais, et l'add-on se
    déclarait "Configuration INCOMPLÈTE" en boucle à chaque démarrage. Générique
    plutôt que spécifique à `other_settings` : protège aussi contre un futur champ
    required supplémentaire du même genre, sans dépendre d'un nom figé."""
    extra = {}
    for field in schema:
        name = field.get("name")
        if not name or name in known:
            continue
        if field.get("type") == "expandable":
            sub = _fill_required_schema_defaults(field.get("schema") or [], {})
            if field.get("required") or sub:
                extra[name] = sub
            continue
        if not field.get("required"):
            continue
        value = _default_for_required_field(field)
        if value is not None:
            extra[name] = value
    return extra


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

    payload.update(_fill_required_schema_defaults(schema, payload))

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


def _shelly_submit(flow_id, payload, label):
    """Soumet une étape du flow de config Shelly — même mécanique que _mqtt_submit."""
    r = requests.post(f"{API}/config/config_entries/flow/{flow_id}",
                       headers=HDRS, json=payload, timeout=15)
    if not r.ok:
        warn(f"[wifi-shelly] {label} erreur {r.status_code}: {r.text[:400]}")
        return False, {}
    result = _unwrap(r.json())
    log(f"[wifi-shelly] {label} → type={result.get('type','?')} step={result.get('step_id','?')}")
    return True, result


def _build_shelly_host_payload(schema: list, host: str) -> dict:
    """Construit le payload du flow HA 'shelly' à partir du schéma retourné — le
    champ s'appelle 'host' d'après la doc officielle, mais on reste générique
    (même précaution que _build_mqtt_broker_payload) pour ne pas dépendre d'un
    nom de champ figé côté HA."""
    schema_names = {f.get("name", "") for f in schema}
    payload = {}
    for k in ("host", "ip_address", "ip"):
        if k in schema_names:
            payload[k] = host
            break
    return payload


def handle_wifi_shelly_discovered() -> list:
    """Liste les appareils Shelly déjà détectés par la découverte zeroconf native
    de HA — aucun scan actif nécessaire côté addon, HA crée automatiquement un
    flow de config 'shelly' en arrière-plan dès qu'il voit l'appareil sur le
    réseau local. Lu via WebSocket (config_entries/flow/progress) : le endpoint
    REST /api/config/config_entries/flow ne supporte QUE POST (créer un flow),
    pas de listing — vérifié dans le code source HA (config/config_entries.py,
    2026-09)."""
    result = _ha_ws_call("config_entries/flow/progress")
    flows = ((result or {}).get("result")) or []
    discovered = []
    for f in flows:
        if f.get("handler") != "shelly":
            continue
        ctx = f.get("context") or {}
        name = (ctx.get("title_placeholders") or {}).get("name") or ctx.get("unique_id") or "Appareil Shelly"
        discovered.append({"flowId": f.get("flow_id"), "name": name})
    return discovered


def handle_wifi_shelly_add(flow_id, host) -> dict:
    """Confirme un appareil Shelly déjà découvert (flow_id fourni) OU démarre un
    appairage manuel par adresse IP (host fourni) — les 2 chemins du config flow
    HA 'shelly'. Gen2+ : aucune saisie supplémentaire nécessaire au-delà de
    l'hôte. Gen1 : peut échouer si le CoIoT unicast n'est pas configuré côté
    appareil lui-même (réglage à faire une fois dans l'app Shelly, hors de
    portée de ce flow)."""
    flow = None
    if not flow_id:
        start_resp = ha_post("/config/config_entries/flow", {"handler": "shelly"})
        if not start_resp.ok:
            return {"ok": False, "error": f"HA {start_resp.status_code}: {start_resp.text[:200]}"}
        flow = _unwrap(start_resp.json())
        if flow.get("type") == "create_entry":
            return {"ok": True, "title": flow.get("title")}
        flow_id = flow.get("flow_id")
        if not flow_id:
            return {"ok": False, "error": f"Pas de flow_id : {start_resp.text[:200]}"}
        if flow.get("type") == "form":
            payload = _build_shelly_host_payload(flow.get("data_schema", []), host or "")
            ok, flow = _shelly_submit(flow_id, payload, "form step=user")
            if not ok:
                return {"ok": False, "error": "Échec de soumission du formulaire"}
    else:
        ok, flow = _shelly_submit(flow_id, {}, "confirm")
        if not ok:
            return {"ok": False, "error": "Échec de confirmation"}

    flow_type = flow.get("type", "?")
    if flow_type == "create_entry":
        return {"ok": True, "title": flow.get("title")}
    if flow_type == "abort":
        return {"ok": False, "error": f"Refusé par HA ({flow.get('reason') or '?'})"}
    if flow_type == "form":
        return {
            "ok": False,
            "error": f"Étape supplémentaire requise ({flow.get('step_id')}) — non gérée",
            "needsInput": flow.get("step_id"),
            "errors": flow.get("errors"),
        }
    return {"ok": False, "error": f"Réponse HA inattendue : {flow}"}


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
        # Audit add-on 2026-09-22 : ce payload contient MOSQUITTO_PASS en clair
        # (champ "password" du flow HA) — jamais loggé tel quel, même si ce mot
        # de passe est auto-généré et local (127.0.0.1:1883), pas saisi par le client.
        redacted_payload = {k: ("***" if "pass" in k.lower() else v) for k, v in payload.items()}
        log(f"[MQTT] Payload envoyé : {redacted_payload}")

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


def handle_local_site() -> dict:
    """Coordonnées du logement pour l'app Domoticium servie par le Pi (route GET /local/site).

    Source : la config Home Assistant elle-même (zone « home »), lue en direct, sans aller-retour cloud (chantier « Pi-first », lot C :
    l'app du Pi en tire la météo/trafic/vigilance, via la passerelle API pour ce qui exige une clé).
    `latitude`/`longitude` valent None si la zone « home » n'est pas réglée : l'app affiche alors
    simplement « indisponible » au lieu de deviner."""
    r = ha_get("/config")
    if not r.ok:
        raise RuntimeError(f"HA /config : HTTP {r.status_code}")
    cfg = r.json()
    return {
        "latitude": cfg.get("latitude"),
        "longitude": cfg.get("longitude"),
        "elevation": cfg.get("elevation"),
        "time_zone": cfg.get("time_zone"),
    }


_WATCHDOG_ENABLED_MARKER = "/data/.watchdog_enabled_v2"


def _enable_watchdogs_once():
    """Active le redémarrage automatique du Supervisor ("Watchdog", visible dans
    Paramètres → Applications → [add-on] → interrupteur Watchdog) pour Domoticium
    et TOUS les add-ons installés par Domoticium, si présents sur ce site. Ne
    protège que contre un add-on qui CRASHE (process qui meurt) — pas contre un
    service interne qui reste bloqué sans faire planter le container (ex: incident
    cmd-server du 2026-07-22, déjà corrigé par ailleurs) : le Watchdog Supervisor
    n'a pas de sonde applicative, juste "le process tourne-t-il encore ?".
    Complémentaire, pas un remplacement, des correctifs ciblés. `/addons/self/options`
    = API Supervisor dédiée pour qu'un add-on se configure lui-même sans connaître
    son propre slug installé (qui varie selon le dépôt d'installation). Idempotent
    via marker, retente à chaque démarrage tant qu'un appel a échoué. Frigate inclus
    délibérément (demande explicite d'Hicham, 2026-08-01 — aucun problème observé en
    pratique malgré un risque théorique de faux positif documenté ailleurs, jugé
    acceptable). `LOCAL_WEB_SLUG` ("Domoticium — Accès local") ajouté le 2026-11-09
    (demande Hicham : activer le Watchdog sur TOUTES les apps installées, il
    manquait à la liste d'origine) — marker renommé en `_v2` pour que les sites déjà
    déployés (ancien marker déjà écrit) repassent une fois par cette fonction et
    couvrent ce nouvel add-on. cloudflared tourne en sous-processus DANS le
    container Domoticium lui-même (pas un add-on Supervisor séparé) — déjà couvert
    par le Watchdog "self" ci-dessus, pas d'entrée Watchdog propre possible côté
    Supervisor. Alarmo est un composant HA natif (Marketplace), pas un add-on — la
    notion de Watchdog Supervisor ne s'applique pas à lui non plus."""
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

    for slug in (MOSQUITTO_SLUG, FRIGATE_SLUG, MATTER_SLUG, Z2M_SLUG, THREAD_SLUG, LOCAL_WEB_SLUG):
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


_FRIGATE_WATCHDOG_DISABLED_MARKER = "/data/.frigate_watchdog_disabled"


def _reenable_frigate_watchdog_if_needed():
    """Contre-correctif : v2.9.79 avait désactivé le Watchdog sur Frigate (risque
    théorique de faux positif) sans validation préalable d'Hicham, qui a demandé de
    revenir en arrière ("n'agis pas sans me demander... je n'ai pas eu de problème,
    réactive-le") — cf. [[feedback-ask-before-risky-changes]]. Si le marker de
    _disable_frigate_watchdog_once() (v2.9.79) existe, ça veut dire cette désactivation
    a déjà été appliquée pour de vrai sur ce site — on la défait explicitement une
    fois, puis on nettoie le marker pour ne plus jamais repasser ici."""
    if not os.path.exists(_FRIGATE_WATCHDOG_DISABLED_MARKER):
        return
    if _is_addon_installed(FRIGATE_SLUG):
        try:
            r = sup_post(f"/addons/{FRIGATE_SLUG}/options", {"watchdog": True})
            if r.ok:
                log("[watchdog] ✓ ré-activé pour Frigate (annulation v2.9.79)")
            else:
                warn(f"[watchdog] échec réactivation pour Frigate : HTTP {r.status_code}")
                return
        except Exception as e:
            warn(f"[watchdog] réactivation Frigate : {e}")
            return
    os.remove(_FRIGATE_WATCHDOG_DISABLED_MARKER)


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


_HA_TRUSTED_PROXY_MARKER = "# domoticium-trusted-proxy"


def _ensure_ha_trusted_proxy():
    """Idempotent, tourne à chaque démarrage (patch aussi les sites déjà provisionnés
    avant l'accès distant HA, Phase 2) : Home Assistant refuse par défaut les requêtes
    venant d'un reverse proxy inconnu (cf. homeassistant.components.http.forwarded) —
    depuis que le tunnel Cloudflare route désormais Home Assistant lui-même (racine du
    hostname, plus seulement les caméras/l'addon), il faut déclarer 127.0.0.1 (là où
    cloudflared se connecte) comme proxy de confiance, sinon 400 Bad Request systématique.
    Erreur réelle observée en conditions réelles le 2026-08-13 : "A request from a
    reverse proxy was received from 127.0.0.1, but your HTTP integration is not
    set-up for reverse proxies" — jamais un problème avant ce jour car HA n'était
    jusque-là jamais exposé derrière le tunnel, seulement les caméras et l'addon.
    Ne touche jamais à un bloc "http:" déjà personnalisé par l'utilisateur — log
    seulement, pour ne jamais corrompre une config existante qu'on ne maîtrise pas."""
    main_cfg = "/homeassistant/configuration.yaml"
    try:
        with open(main_cfg) as f:
            content = f.read()
    except FileNotFoundError:
        return False

    # Diagnostic (2026-11-24) : l'accès technicien renvoyait 400 « request from a reverse proxy … not set-up » alors que le marqueur
    # est censé garantir le bloc http: → on journalise le bloc RÉEL (aucun secret n'y figure) pour voir ce que HA lit vraiment.
    m_http = re.search(r"(?m)^http:\s*$(?:\n(?:[ \t].*|\s*#.*|\s*))*", content)
    warn(f"[trusted-proxy] marqueur={'oui' if _HA_TRUSTED_PROXY_MARKER in content else 'non'} ; bloc http: "
         f"{('présent : ' + repr(m_http.group(0)[:400])) if m_http else 'ABSENT'} ; "
         f"nb de lignes 'http:' au niveau racine = {len(re.findall(r'(?m)^http:', content))}")

    if _HA_TRUSTED_PROXY_MARKER in content:
        return False  # déjà fait

    if re.search(r"(?m)^http:\s*$", content):
        warn("[trusted-proxy] Un bloc 'http:' existe déjà dans configuration.yaml — "
             "vérifier manuellement que use_x_forwarded_for/trusted_proxies (127.0.0.1) y figurent.")
        return False

    block = (
        f"\n{_HA_TRUSTED_PROXY_MARKER} — requis pour l'accès distant technicien (Phase 2),"
        " Home Assistant est désormais exposé (protégé par Cloudflare Access) via le tunnel\n"
        "http:\n"
        "  use_x_forwarded_for: true\n"
        "  trusted_proxies:\n"
        "    - 127.0.0.1\n"
    )
    with open(main_cfg, "a") as f:
        f.write(block)
    log("✓ configuration.yaml : proxy de confiance ajouté (127.0.0.1) pour l'accès distant HA")
    return True


# Nettoyage du diagnostic temporaire posé en v2.9.226 (logger debug loader/
# config_entries/setup, pour traquer "Cannot find integration hacs") — cause
# réelle trouvée le 2026-11-09 (HACS obsolète depuis HA 2026.11, remplacé par le
# Marketplace natif, cf. install_alarmo()) : plus besoin de ce niveau de détail.
# Retire le bloc entier (marqueur + les 5 lignes qui suivent) si présent, idempotent.
_HA_DEBUG_LOGGER_MARKER = "# domoticium-diag-logger-2026-11-09"


def _remove_ha_debug_logger_once():
    main_cfg = "/homeassistant/configuration.yaml"
    try:
        with open(main_cfg) as f:
            content = f.read()
    except FileNotFoundError:
        return False

    if _HA_DEBUG_LOGGER_MARKER not in content:
        return False  # jamais posé (nouveau site) ou déjà retiré

    pattern = re.escape(_HA_DEBUG_LOGGER_MARKER) + r"[^\n]*\n(?:logger:\n(?:  [^\n]*\n)*)"
    new_content, n = re.subn(pattern, "", content, count=1)
    if n == 0:
        warn("[diag-logger] Marqueur trouvé mais bloc non reconnu — pas touché, à retirer manuellement si besoin.")
        return False
    with open(main_cfg, "w") as f:
        f.write(new_content)
    log("✓ configuration.yaml : logger debug temporaire retiré (diagnostic HACS clos)")
    return True


def _setup_step(label: str, fn, check_fn, attempts: int = 3, backoff=(5, 15)) -> bool:
    """Exécute une étape de run_setup() avec retry — audit add-on 2026-09-22 :
    aucune des fonctions install_*/setup_* ne lève d'exception proprement
    gérée ni ne remonte de statut ; un simple hoquet réseau (timeout Supervisor
    pendant le tout premier boot, connexion domestique modeste) pouvait soit
    planter tout le process (exception non rattrapée), soit laisser l'étape
    silencieusement incomplète. `check_fn` vérifie l'ÉTAT RÉEL après chaque
    tentative (mêmes primitives qu'ailleurs dans le fichier, ex.
    _is_addon_installed) — on ne fait jamais confiance à un simple "ça n'a pas
    levé d'exception". Sûr à rappeler plusieurs fois : chaque fonction
    install_*/setup_* est déjà idempotente (_is_addon_installed/markers
    one-shot), donc une "nouvelle tentative" est en réalité un aller-retour
    supplémentaire, jamais une double installation."""
    for attempt in range(1, attempts + 1):
        try:
            fn()
        except Exception as e:
            warn(f"[setup] {label} (tentative {attempt}/{attempts}) a levé une exception : {e}")
        if check_fn():
            if attempt > 1:
                log(f"[setup] {label} confirmé après {attempt} tentative(s)")
            return True
        if attempt < attempts:
            delay = backoff[min(attempt - 1, len(backoff) - 1)]
            warn(f"[setup] {label} pas encore prêt (tentative {attempt}/{attempts}) — nouvelle tentative dans {delay}s")
            time.sleep(delay)
    warn(f"[setup] {label} a échoué après {attempts} tentatives")
    return False


def run_setup():
    # Filet de sécurité global (audit add-on 2026-09-22) : aucune clé
    # `watchdog` dans config.yaml — un crash total du process ici (exception
    # non prévue, ex. dans wait_for_ha() ou l'écriture finale du marker)
    # nécessiterait une intervention manuelle de Hicham sur CE site précis.
    # Capturé et journalisé plutôt que de laisser planter : SETUP_DONE ne sera
    # de toute façon jamais écrit dans ce cas, donc le prochain redémarrage de
    # l'add-on retente toute la séquence — même filet que pour chaque étape
    # individuelle ci-dessous (_setup_step), juste au niveau le plus large.
    try:
        _run_setup_inner()
    except Exception as e:
        warn(f"═══ run_setup() a levé une exception non prévue, configuration abandonnée : {e} ═══")
        warn("SETUP_DONE non écrit — retenté au prochain démarrage de l'add-on.")


def _run_setup_inner():
    wait_for_ha()
    log("═══ Début de la configuration Domoticium ═══")

    ok = True

    # 1. Mosquitto local d'abord — Z2M et HA MQTT integration en dépendent
    ok &= _setup_step("Mosquitto", setup_mosquitto, lambda: _is_addon_installed(MOSQUITTO_SLUG))

    # 2. HA MQTT integration → Mosquitto local
    ok &= _setup_step("intégration MQTT HA", configure_mqtt, _mqtt_config_entry_exists)

    # 3. Z2M → Mosquitto local
    ok &= _setup_step("Zigbee2MQTT", install_zigbee2mqtt, lambda: _is_addon_installed(Z2M_SLUG))

    # 4. Supprimer l'ancien discovery_prefix non-standard (migration v1.5 → v1.6)
    # — cosmétique/cleanup, jamais bloquant pour la suite.
    try:
        remove_legacy_mqtt_discovery_prefix()
    except Exception as e:
        warn(f"[setup] remove_legacy_mqtt_discovery_prefix a échoué (non bloquant) : {e}")

    ok &= _setup_step("Matter Server", install_matter_server, lambda: _is_addon_installed(MATTER_SLUG))
    if INSTALL_THREAD_ROUTER:
        ok &= _setup_step("Thread Border Router", install_thread_border_router, lambda: _is_addon_installed(THREAD_SLUG))
    ok &= _setup_step("Frigate", install_frigate, lambda: _is_addon_installed(FRIGATE_SLUG))

    try:
        ha_post("/services/homeassistant/reload_all")
    except Exception as e:
        warn(f"[setup] reload_all a échoué (non bloquant) : {e}")

    if not ok:
        warn("═══ Configuration INCOMPLÈTE malgré les tentatives de reprise — SETUP_DONE non écrit ═══")
        warn("La configuration sera retentée au prochain démarrage de l'add-on.")
        return

    with open(SETUP_DONE, "w") as f:
        f.write("done")
    log("═══ Configuration terminée ✓ ═══")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — SERVICE PERMANENT
# ══════════════════════════════════════════════════════════════════════════════

# ── Tunnel Cloudflare : lancement SUPERVISÉ (lot F, « santé du tunnel ») ──────────────────────────────────────
# Avant : cloudflared était lancé UNE fois, sans surveillance — s'il s'arrêtait (plantage, coupure réseau longue,
# processus tué), l'accès à distance restait coupé jusqu'au prochain redémarrage de l'add-on, sans que personne le sache.
# Maintenant : un fil surveille le processus ET son état réel (`/ready` de ses métriques : 200 seulement s'il a au moins
# une connexion établie vers Cloudflare). Processus arrêté → relancé (pause 5 s doublée jusqu'à 60 s) ; processus vivant
# mais non connecté depuis 5 min → relancé (au plus une fois par 5 min). L'état est publié dans le résumé de flotte
# (`tun`) et une coupure de plus de 10 min ouvre l'alerte `tunnel_down` (visible dans l'app et par le staff, sans e-mail :
# le client ne peut rien y faire, c'est à Domoticium d'agir).
_CLOUDFLARED_METRICS_ADDR = "127.0.0.1:20243"
_TUNNEL_PROBE_PERIOD_S = 15
_TUNNEL_STUCK_RESTART_S = 300
_TUNNEL_RESTART_MIN_GAP_S = 300
_TUNNEL_BACKOFF_MAX_S = 60
_tunnel_state = {"ready": None, "not_ready_since": None, "last_restart": 0.0, "failures": 0, "started_at": 0.0}


def _tunnel_next_action(now: float, proc_alive: bool, ready: bool) -> str:
    """Décision pure du superviseur : « none » ou « restart ». Met à jour _tunnel_state["ready" / "not_ready_since"]."""
    st = _tunnel_state
    if proc_alive and ready:
        st["ready"], st["not_ready_since"] = True, None
        if now - st["started_at"] > 300:
            st["failures"] = 0            # stable depuis 5 min : la pause de relance repart de zéro
        return "none"
    st["ready"] = False
    if st["not_ready_since"] is None:
        st["not_ready_since"] = now
    if not proc_alive:
        gap = min(5 * 2 ** st["failures"], _TUNNEL_BACKOFF_MAX_S)
        return "restart" if now - st["last_restart"] >= gap else "none"
    if now - st["not_ready_since"] >= _TUNNEL_STUCK_RESTART_S and now - st["last_restart"] >= _TUNNEL_RESTART_MIN_GAP_S:
        return "restart"
    return "none"


def _tunnel_probe_ready() -> bool:
    try:
        return requests.get(f"http://{_CLOUDFLARED_METRICS_ADDR}/ready", timeout=3).status_code == 200
    except Exception:
        return False


def _cloudflared_spawn():
    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--no-autoupdate", "--metrics", _CLOUDFLARED_METRICS_ADDR, "run",
         "--token", CLOUDFLARE_TUNNEL_TOKEN],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    def _log_output():
        for line in proc.stdout:
            log(f"cloudflared: {line.decode().strip()}")

    threading.Thread(target=_log_output, daemon=True).start()
    return proc


def _run_cloudflared_supervisor(spawn=None, probe=None, sleep=None, clock=None, max_loops=None):
    """Fil permanent : lance cloudflared et le garde en vie (cf. commentaire ci-dessus). Les paramètres ne servent qu'aux tests."""
    spawn, probe, sleep, clock = spawn or _cloudflared_spawn, probe or _tunnel_probe_ready, sleep or time.sleep, clock or time.time
    proc = None
    loops = 0
    while max_loops is None or loops < max_loops:
        loops += 1
        try:
            now = clock()
            alive = proc is not None and proc.poll() is None
            action = _tunnel_next_action(now, alive, bool(alive and probe()))
            if proc is None and _tunnel_state["last_restart"] == 0.0:
                action = "restart"            # premier lancement : sans attente
            if action == "restart":
                if alive:
                    warn("[tunnel] cloudflared vivant mais non connecté depuis 5 min — relance")
                    try:
                        proc.terminate()
                        proc.wait(timeout=10)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                elif proc is not None:
                    warn(f"[tunnel] cloudflared arrêté (code {proc.poll()}) — relance")
                _tunnel_state["failures"] += 1 if proc is not None else 0
                _tunnel_state["last_restart"], _tunnel_state["started_at"] = now, now
                proc = spawn()      # not_ready_since N'EST PAS remis à zéro : une boucle de relances ne doit pas masquer la coupure
                log("✓ cloudflared lancé — accès distant par le tunnel Cloudflare")
        except FileNotFoundError:
            warn("cloudflared introuvable")
            return
        except Exception as e:
            warn(f"[tunnel] cycle échoué (poursuite au prochain) : {e}")
        sleep(_TUNNEL_PROBE_PERIOD_S)


def start_cloudflared():
    """Démarre le superviseur du tunnel Cloudflare (fil de fond)."""
    if not CLOUDFLARE_TUNNEL_TOKEN:
        log("cloudflared: pas de token — tunnel caméras désactivé")
        return
    log("Démarrage du tunnel Cloudflare (supervisé)…")
    threading.Thread(target=_run_cloudflared_supervisor, daemon=True, name="cloudflared-supervisor").start()


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


def _redact_rtsp_credentials(text: str, rtsp_url: str) -> str:
    """Retire toute occurrence du mot de passe caméra contenu dans rtsp_url
    (forme brute ET url-encodée) d'un message avant de le logger — audit
    add-on 2026-09-22 : un message d'exception requests/urllib3 embarque
    typiquement l'URL complète (avec sa query string) de la requête en
    échec ; le mot de passe saisi par le client (passé en paramètre `src`
    ci-dessous) pouvait ainsi finir en clair dans les logs Supervisor sur un
    simple échec réseau transitoire (go2rtc indisponible, timeout).
    ⚠️ Une regex cherchant "://user:pass@" tel quel NE SUFFIT PAS : requests
    encode `src` dans la query string (`:`→%3A, `@`→%40), vérifié en local
    avant ce correctif — c'est pourquoi on remplace la sous-chaîne connue
    (extraite de rtsp_url lui-même) sous ses deux formes, plutôt que de
    deviner un motif dans le texte déjà formé."""
    m = re.match(r'^\w+://([^:@/]+):([^@/]+)@', rtsp_url)
    if not m:
        return text
    user, pwd = m.group(1), m.group(2)
    redacted = text.replace(f"{user}:{pwd}", "***:***")
    redacted = redacted.replace(urllib.parse.quote(f"{user}:{pwd}", safe=""), "***:***")
    if pwd:
        redacted = redacted.replace(pwd, "***")
        redacted = redacted.replace(urllib.parse.quote(pwd, safe=""), "***")
    return redacted


def _go2rtc_upsert_stream(name: str, rtsp_url: str, timeout: float = 5.0) -> bool:
    """Ajoute/remplace un flux go2rtc à chaud (API PUT /api/streams) — les autres
    caméras (et sessions WebRTC/HLS actives) ne sont pas coupées, contrairement à un
    restart complet de l'add-on Frigate."""
    try:
        r = requests.put(
            f"{GO2RTC_API_BASE}/api/streams",
            params={"name": name, "src": rtsp_url},
            auth=GO2RTC_API_AUTH,
            timeout=timeout,
        )
        return r.ok
    except Exception as e:
        warn(f"[go2rtc] upsert stream '{name}' : {_redact_rtsp_credentials(str(e), rtsp_url)}")
        return False


def _go2rtc_remove_stream(name: str, timeout: float = 5.0) -> bool:
    """Retire un flux go2rtc à chaud (API DELETE /api/streams)."""
    try:
        r = requests.delete(
            f"{GO2RTC_API_BASE}/api/streams",
            params={"src": name},
            auth=GO2RTC_API_AUTH,
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
            f"{GO2RTC_API_BASE}/api/frame.jpeg",
            params={"src": name},
            auth=GO2RTC_API_AUTH,
            timeout=timeout,
        )
        ok = r.ok and r.headers.get("Content-Type", "").startswith("image")
        if not ok:
            warn(f"[watchdog-probe] {name}: HTTP {r.status_code} Content-Type={r.headers.get('Content-Type')!r} body[:150]={r.text[:150]!r}")
        return ok
    except Exception as e:
        warn(f"[watchdog-probe] {name}: exception {type(e).__name__}: {e}")
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
) -> tuple[bool, str, str | None, str | None]:
    """Teste une caméra IP+mot de passe selon la marque choisie par l'utilisateur
    (menu déroulant du formulaire d'ajout) — une seule tentative directe, la bonne URL
    étant connue d'avance. Si aucune marque n'est choisie ("Inconnue"), teste tous les
    chemins RTSP connus l'un après l'autre (jamais en parallèle : certaines caméras
    d'entrée de gamme n'acceptent qu'UNE connexion RTSP à la fois — des tentatives
    concurrentes se percutent, observé en test réel : erreur go2rtc trompeuse "wrong
    response on DESCRIBE"), bornées à ~25s au total quel que soit le nombre de marques
    dans la table, pour rester dans le budget de la requête HTTP appelante.
    Retourne (ok, message, url_qui_fonctionne, url_sous_flux_ou_None).

    Le sous-flux (§87) n'est JAMAIS testé en direct ici, volontairement — seulement
    deviné depuis _RTSP_SUB_TEMPLATES pour la marque identifiée. Le tester ouvrirait
    une 2e connexion RTSP juste après celle qui vient de réussir, vers une caméra qui
    n'en accepte peut-être qu'une à la fois (même risque que §76/§77)."""
    norm = _normalize_brand(manufacturer)
    if norm and norm in _RTSP_TEMPLATES:
        url = _RTSP_TEMPLATES[norm].format(ip=ip).replace("MOTDEPASSE", password)
        if _probe_rtsp_url(url, timeout=timeout):
            sub_url = _RTSP_SUB_TEMPLATES.get(norm, '').format(ip=ip).replace("MOTDEPASSE", password) or None
            return True, "ok", url, sub_url
        reason = _recent_go2rtc_error_hint()
        return False, reason or f"Impossible de se connecter avec le chemin {manufacturer}", None, None

    candidates = [("", f"rtsp://admin:{password}@{ip}:554/stream")] + [
        (k, _RTSP_TEMPLATES[k].format(ip=ip).replace("MOTDEPASSE", password))
        for k in _BRAND_GUESS_ORDER
    ]
    deadline = time.time() + 25.0
    for brand_key, url in candidates:
        if time.time() > deadline:
            break
        if _probe_rtsp_url(url, timeout=3.0):
            sub_url = _RTSP_SUB_TEMPLATES.get(brand_key, '').format(ip=ip).replace("MOTDEPASSE", password) or None
            return True, "ok", url, sub_url

    reason = _recent_go2rtc_error_hint()
    return False, reason or (
        "Aucun chemin RTSP connu n'a fonctionné — vérifiez l'adresse IP et le mot de "
        "passe, ou saisissez l'URL manuellement"
    ), None, None


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


def handle_camera_configure(action: str, stream_name: str, rtsp_url: str | None = None) -> bool:
    """Ajoute ou supprime une caméra dans Frigate. Appelé par le serveur de commandes HTTP.
    Entièrement bloquant, de bout en bout — la réponse HTTP appelante ne doit dire 'ok'
    que si le travail a réellement été fait (restart complet, + nettoyage HA à la
    suppression), jamais avant qu'une tâche de fond ait fini. Retourne True si
    l'opération a effectivement abouti.

    Toujours un restart complet, plus de PUT/DELETE /api/streams (upsert/remove à chaud)
    — cf. HANDOFF §63/§64 : ces deux endpoints écrivent, via app.PatchConfig côté
    go2rtc, dans /config/go2rtc_homekit.yml, un fichier réservé par Frigate à sa propre
    fonctionnalité HomeKit. Pire que juste inutile : la corruption qui en résulte s'est
    révélée AUTO-PERPÉTUANTE — une fois le fichier malformé, le script de nettoyage
    HomeKit de Frigate lui-même échoue à le reparser (même erreur YAML) et abandonne
    sans y toucher, donc rien ne le corrige jamais tout seul, jusqu'à une réinstallation
    complète. Un restart (quelques secondes, plutôt qu'un ajout instantané) est le
    prix à payer pour ne plus jamais risquer de recasser toutes les caméras du site
    pour l'ajout ou la suppression d'une seule.

    Verrouillé de bout en bout (_camera_configure_lock) : plusieurs suppressions/ajouts
    quasi simultanés (ex: suppression groupée de plusieurs caméras depuis l'app) sont
    courants et arrivent chacun dans son propre thread — sans ce verrou, l'état partagé
    (_cameras) et surtout restart_frigate() se chevauchent, le Supervisor HA rejetant
    un redémarrage demandé pendant qu'un autre est déjà en cours (confirmé en
    conditions réelles le 2026-07-25 : 400 puis 502 pour l'appelant, alors que l'état
    final était pourtant correct). Ici, chaque appel passe entièrement l'un après
    l'autre — résultat toujours cohérent avec l'état réel, jamais de faux échec."""
    # Audit add-on 2026-09-22 : stream_name/rtsp_url finissent tels quels comme
    # clé/valeur YAML brutes dans _generate_frigate_yaml() (interpolation par
    # f-string, jamais échappée) — un caractère spécial (notamment un saut de
    # ligne) pouvait corrompre frigate.yml et couper TOUTES les caméras du
    # site. stream_name restreint à un identifiant sûr (déjà ce que produit la
    # dérivation côté web, cf. api/cameras/route.ts) ; rtsp_url seulement
    # interdit de saut de ligne/retour chariot (reste par ailleurs une URL
    # libre, schéma/identifiants/port variables selon le matériel).
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", stream_name or ""):
        raise ValueError("streamName invalide (caractères autorisés : lettres, chiffres, - et _)")

    with _camera_configure_lock:
        if action == "add":
            if not rtsp_url:
                raise ValueError("rtspUrl manquant")
            if "\n" in rtsp_url or "\r" in rtsp_url:
                raise ValueError("rtspUrl invalide (retour à la ligne interdit)")
            _cameras[stream_name] = rtsp_url
            _save_cameras()
            write_frigate_config()
        elif action == "remove":
            _cameras.pop(stream_name, None)
            _save_cameras()
            if _camera_masks.pop(stream_name, None) is not None:
                _save_camera_masks()
            write_frigate_config()
            _ha_remove_camera_entities(stream_name)  # bloquant — cf. docstring
        else:
            raise ValueError(f"action inconnue: {action!r}")

        ok = restart_frigate()
        log(f"{'✓' if ok else '⚠'} Caméra {action} (via restart complet) : '{stream_name}'")
        return ok


def handle_camera_mask(stream_name: str, rects: list[dict]) -> bool:
    """Définit (ou retire, si rects vide) le masquage 'en dur' d'une caméra déjà
    enregistrée (§93) — admin uniquement, jamais appelé côté client. Même verrou et
    même mécanisme (réécriture frigate.yml + restart complet) que
    handle_camera_configure(), pour ne jamais faire chevaucher les deux (ex: masquage
    modifié pendant qu'une bascule de qualité §88 est en cours)."""
    with _camera_configure_lock:
        if stream_name not in _cameras:
            raise ValueError(f"caméra inconnue: {stream_name!r}")
        if rects:
            _camera_masks[stream_name] = rects
        else:
            _camera_masks.pop(stream_name, None)
        _save_camera_masks()
        write_frigate_config()

        ok = restart_frigate()
        log(f"{'✓' if ok else '⚠'} Masquage mis à jour ({len(rects)} zone(s)) : '{stream_name}'")
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


def _matter_remove_node(node_id: int) -> bool:
    """Retire un node du fabric matter-server (commande remove_node — vérifiée dans
    la source officielle, device_controller.py : tente unpair_device puis nettoie
    son storage même si l'appareil est injoignable, exactement notre cas pour un
    nœud mort). Utilisé après une fusion confirmée par le client (cf.
    handle_matter_merge_confirm) pour que le nœud renouvelé ne réapparaisse plus
    comme fantôme au cycle de synchro suivant (demande Hicham, 2026-08-01)."""
    s = None
    try:
        s, _recv, _send, info = _matter_ws_connect(timeout_s=20)
        if not s:
            warn(f"[matter-server] remove_node connexion : {info}")
            return False
        msg_id = f"remove-node-{node_id}"
        _send({"message_id": msg_id, "command": "remove_node", "args": {"node_id": node_id}})
        while True:
            msg = _recv()
            mid = msg.get("message_id") or msg.get("messageId")
            if mid == msg_id:
                if "error_code" in msg or "errorCode" in msg or "error" in msg:
                    warn(f"[matter-server] remove_node {node_id} échoué : {json.dumps(msg)[:200]}")
                    return False
                log(f"[matter-server] ✓ Node {node_id} retiré du fabric")
                return True
    except Exception as e:
        warn(f"[matter-server] remove_node {node_id}: {e}")
        return False
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


# Mapping deviceType Matter (Descriptor.DeviceTypeList) → type Domoticium. Audité
# le 2026-08-19 contre la liste OFFICIELLE complète des 103 device types de la
# spec CSA (matter-devices.xml, repo project-chip/connectedhomeip — récupérée et
# comparée entrée par entrée, pas une estimation). Un type absent d'ici ne casse
# rien : _extract_matter_device_info() retombe sur "sensor-generic" (lecture
# seule, jamais un faux actionneur — cf. commentaire plus bas, ancien comportement
# "switch par défaut" corrigé début août).
_MATTER_DEVICE_TYPES = {
    0x0100: "light", 0x0101: "light", 0x010C: "light", 0x010D: "light",  # On/Off, Dimmable, Color Temp, Extended Color Light
    0x0103: "switch",                                      # On/Off Light Switch
    0x010A: "plug", 0x010B: "plug",                        # On/Off, Dimmable Plug-in Unit
    0x0202: "cover",                                       # Window Covering
    0x0301: "thermostat",
    0x000A: "lock",                                        # Door Lock (vérifié CSA Device Library 1.4)
    0x002B: "fan",                                         # Fan (vérifié CSA Device Library 1.4)
    0x0042: "valve",                                        # Water Valve (vérifié CSA Device Library 1.4)
    0x0015: "sensor-contact",                              # Contact Sensor
    0x0107: "sensor-motion",                                # Occupancy Sensor
    0x0302: "sensor-temp",                                  # Temperature Sensor
    0x0043: "sensor-water",                                 # Water Leak Detector (absent jusqu'ici — vrai trou : sans ça,
                                                             # une fuite Matter tombait en sensor-generic, sans alerte dédiée)
    0x002C: "sensor-generic",                               # Air Quality Sensor
    # Télécommande/bouton de scène (2026-08-27) — Generic Switch, Dimmer Switch,
    # Color Dimmer Switch (déjà repérés lors de l'audit CSA du 2026-08-19,
    # jamais mappés jusqu'ici). Pas d'état à afficher (device_trigger côté HA,
    # cf. handle_get_device_triggers) — juste besoin d'être reconnus pour
    # apparaître comme source de déclencheur d'automatisation.
    0x000F: "remote", 0x0104: "remote", 0x0105: "remote",
    # Famille "compteur électrique" (0x0510-0x0519) : plusieurs ID voisins existent
    # dans la spec pour des rôles différents (compteur utilitaire, point de
    # référence, tarif, disjoncteur…) — seuls ceux qui sont un vrai compteur de
    # consommation sont mappés ici, le reste (tarif/disjoncteur/protection) n'a
    # pas d'équivalent Domoticium et retombe sciemment en sensor-generic.
    0x0510: "energy-meter",                                 # Electrical Sensor
    0x0511: "energy-meter",                                 # Electrical Utility Meter
    0x0514: "energy-meter",                                 # Electrical Meter
    # Solaire/batterie domestique — HA modélise ces clusters directement en
    # sensor, sans traitement spécifique par device type (confirmé source HA
    # matter/sensor.py, 2026-08-19) ; nos catégories les plus proches restent des
    # mesures de production/stockage électrique, cf. "energy-meter". Nuance
    # documentée : un panneau solaire mesure de la PRODUCTION, pas de la
    # consommation — le calcul d'empreinte carbone du panneau Énergie
    # (DashboardCanvas) n'a de sens que pour un vrai compteur de consommation,
    # à garder en tête si un client en installe un.
    0x0017: "energy-meter",                                 # Solar Power
    0x0018: "energy-meter",                                 # Battery Storage
    0x0076: "smoke-co",                                     # Smoke CO Alarm
    0x0074: "vacuum",                                       # Robotic Vacuum Cleaner (HA "vacuum" domain confirmé,
                                                             # homeassistant/core matter/vacuum.py)
    0x050C: "evse",                                         # Energy EVSE (ID vérifié directement dans matter-devices.xml)
    # Famille électroménager — HA modélise le contrôle marche/arrêt en simple
    # switch pour CES types précisément (confirmé source HA matter/switch.py,
    # schéma MatterPowerToggle explicite pour ces 8 device types) ; l'état
    # opérationnel/mode détaillé (en cours, programme, alarme porte…) arrive
    # séparément en entité secondaire générique (sensor/select/binary_sensor),
    # déjà géré par le mécanisme device_entities existant — pas besoin d'un
    # DeviceType dédié par appareil.
    0x0075: "switch",                                       # Dishwasher
    0x007B: "switch",                                       # Oven
    0x0070: "switch",                                       # Refrigerator
    0x0073: "switch",                                       # Laundry Washer
    0x007C: "switch",                                       # Laundry Dryer
    0x007A: "switch",                                       # Extractor Hood
    0x0078: "switch",                                       # Cooktop
    0x0077: "switch",                                       # Cook Surface
    # Microwave Oven (0x0079) et Temperature Controlled Cabinet (0x0071) : PAS
    # dans le schéma MatterPowerToggle confirmé côté HA — pas assez de certitude
    # pour les classer "switch" sans risquer un faux contrôle, retombent sciemment
    # en sensor-generic jusqu'à vérification avec un vrai appareil.
}

# Compteurs d'énergie généraux Zigbee pré-configurés (tête de tableau électrique,
# recherche produit Hicham 2026-08-19, fichier "Compteurs_Energie_Zigbee_Matter") —
# identifiés par (vendor, model) EXACT tels que rapportés par Zigbee2MQTT
# (`definition.vendor`/`.model`, valeurs vérifiées dans le code source
# zigbee-herdsman-converters de chaque device, pas juste la doc). Signal fiable
# et sans ambiguïté, contrairement aux exposes qui varient beaucoup d'un modèle
# à l'autre pour ce type d'appareil (mono/triphasé, avec/sans séparation par
# phase). AUCUN de ces modèles testé en conditions réelles — pas de matériel
# physique installé chez un client à ce jour, cf. HANDOFF.
_ENERGY_METER_VENDOR_MODELS = {
    ("Shelly", "S4EM-002CXCEU"),      # EM Gen4 (mono, 2 pinces)
    ("Shelly", "S4EM-001PXCEU16"),    # EM Mini Gen4 (mono, 1 pince)
    ("Sunricher", "SR-ZG9042MP"),     # jusqu'à 200A/phase, mono ou triphasé selon câblage
    ("LiXee", "ZLinky_TIC"),          # lecture directe du compteur Linky (TIC), pas de pince
    ("Nous", "D4Z"),                  # triphasé, 3 pinces jusqu'à 120A (Tuya TS0601, décodé nativement par Z2M)
    ("OWON", "PC321"),                # triphasé, cluster Metering standard 0x0702
    # Bituo Technik : variantes mono ET 3P+N confirmées en code source Z2M.
    ("BITUO TECHNIK", "SPM01-U01"), ("BITUO TECHNIK", "SDM01B-U01"),
    ("BITUO TECHNIK", "SDM01W-U01"), ("BITUO TECHNIK", "SPM02-U01"),
    # Variantes -U00/-U02 : mêmes familles de modèle chez le même vendeur,
    # probablement même schéma d'exposes — pas vérifiées individuellement en
    # code source (à confirmer si un client en installe une).
    ("BITUO TECHNIK", "SPM01-U00"), ("BITUO TECHNIK", "SPM01-U02"),
    ("BITUO TECHNIK", "SDM02-U00"), ("BITUO TECHNIK", "SDM02-U02"),
    ("BITUO TECHNIK", "SPM02-U02"),   # variante manquée à l'ajout initial, trouvée à l'audit

    # ── Ajouts issus de l'audit complet du catalogue Zigbee2MQTT (2026-08-19,
    # zigbee-herdsman-converters@26.98.0, 4436 devices réels analysés un par un,
    # pas un échantillon). Uniquement des appareils dont les exposes sont
    # PUREMENT de la mesure électrique (power/energy/voltage/current et leurs
    # variantes par phase) — les appareils multi-fonctions ambigus (relais avec
    # suivi énergie, chauffage fil pilote français avec mesure de puissance,
    # compteurs de gaz/eau/chaleur par comptage d'impulsions) sont VOLONTAIREMENT
    # exclus d'ici : les y classer comme "energy-meter" (lecture seule) leur
    # ferait perdre leur vraie fonction de contrôle — décision produit à prendre
    # avec Hicham avant de les intégrer sous un type dédié.
    ("AVATTO", "ZWPM16"), ("AVATTO", "ZWPM16-2"),
    ("Develco", "EMIZB-132"),
    ("Frient", "EMIZB-141"), ("Frient", "EMIZB-151"),
    ("Legrand", "412175"), ("Legrand", "412015"),
    ("NodOn", "SEM-4-1-00"), ("NodOn", "SEM-4-3-20"),
    ("Schneider Electric", "A9MEM1570"),   # 3-phase industriel/tertiaire
    ("ELKO", "EKO01825"),
    ("ShinaSystem", "PMM-300Z1"),
    ("Slacky-DIY", "Electricity Meter TLSR8258"), ("Slacky-DIY", "ElectricityMeter-ABC-DIY"),
    ("Ourtop", "ATMS10013Z3"),
    # Famille Tuya SPM*/SDM* — même convention de nommage que BITUO TECHNIK
    # ci-dessus (très probablement le même OEM, vendor Z2M différent selon le lot).
    ("Tuya", "PJ-MGW1203"), ("Tuya", "SPM01"), ("Tuya", "SPM02"),
    ("Tuya", "SPM01V2"), ("Tuya", "SPM02V2"), ("Tuya", "2CT"),
    ("Tuya", "SPM01V2.5"), ("Tuya", "SPM02V2.5"), ("Tuya", "SPM02V3"),
    ("Tuya", "SDM01"), ("Tuya", "SDM01V1.5"), ("Tuya", "SDM02V1"),
    ("Tuya", "SPM01V1-GT"), ("Tuya", "SPM02V1-GT"),
    ("Tuya", "SDM01V1-GT"), ("Tuya", "SDM02V1-GT"),
    ("Tuya", "TS0601_bidirectional_energy meter"),
    ("Tuya", "PJ-1203A"), ("Tuya", "PC311-Z-TY"), ("Tuya", "EA4161C-BI"),
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
    """pi_sync_devices (protocole "matter") via Supabase direct — True si réussi.
    Un doublon détecté (node_id renouvelé) ne fusionne plus automatiquement ici
    — une suggestion en attente est créée côté SQL (logique de détection
    reprise à l'identique dans pi_sync_devices), confirmée explicitement par le
    client (cf. handle_matter_merge_confirm, route /matter/merge/confirm).
    Basculé de pi_sync_matter_devices vers la RPC générique le 2026-09-21, cf.
    chantier d'harmonisation Zigbee/Matter/WiFi (Zigbee fait en premier,
    Matter ensuite)."""
    try:
        normalized = [
            _normalize_device(
                "matter",
                external_id=d["node_id"], name=d["name"], type_=d["device_type"],
                vendor=d.get("vendor_name") or "", model=d.get("product_name") or "",
                online=d.get("online", True),
                extra={"explicitly_added": d.get("explicitly_added", False)},
            )
            for d in devices_payload
        ]
        return _sync_devices_to_supabase("matter", normalized, timeout=30)
    except Exception as e:
        warn(f"[supabase] pi_sync_devices(matter): {e}")
        return False


# Domaines d'intégration HA natifs pris en charge sous l'onglet "Autre" de l'app
# (équipements Wi-Fi, hors Zigbee/Matter) — Shelly pour commencer (2026-09-06,
# cf. HANDOFF.md), extensible si Tasmota/autres sont ajoutés plus tard.
_WIFI_INTEGRATION_DOMAINS = {"shelly"}

# Priorité de domaine pour choisir l'entité "principale" d'un device physique
# multi-entités (ex: prise Shelly avec un relais + un capteur de puissance) — un
# actionneur prime sur un capteur, même logique éditoriale que Zigbee/Matter.
_WIFI_DOMAIN_PRIORITY = ["light", "switch", "cover", "binary_sensor", "sensor"]

_WIFI_BINARY_SENSOR_TYPE = {
    "door": "sensor-contact", "window": "sensor-contact", "opening": "sensor-contact",
    "motion": "sensor-motion", "occupancy": "sensor-motion",
    "moisture": "sensor-water",
}


def _wifi_device_identifier(device_entry: dict):
    """Extrait l'identifiant physique stable (ex: adresse MAC) d'un device HA
    appartenant à un des domaines Wi-Fi pris en charge, depuis ses "identifiers"
    (device_registry) — même rôle que l'adresse IEEE pour Zigbee, mais lu depuis
    le device_registry plutôt que le unique_id d'une entité (Shelly n'a pas
    d'équivalent MQTT retained bridge/devices dont on pourrait tirer la liste)."""
    for domain, ident in device_entry.get("identifiers", []):
        if domain in _WIFI_INTEGRATION_DOMAINS:
            return ident
    return None


def _detect_wifi_device_type(domain: str, device_class):
    """Déduit le DeviceType Domoticium depuis le domaine/device_class HA de
    l'entité principale — construit à partir de la doc officielle HA (recherche
    2026-09, cf. HANDOFF.md), PAS ENCORE VÉRIFIÉ SUR DU MATÉRIEL RÉEL faute de
    Shelly physique disponible au moment de l'écriture. À revalider dès qu'un
    vrai appareil est disponible (cf. arch-device-type-frozen-at-insert.md :
    type se rafraîchit à chaque sync, donc une correction ultérieure se
    propagera automatiquement, pas besoin de migration de rattrapage)."""
    if domain == "light":
        return "light"
    if domain == "switch":
        # Shelly ne distingue pas "prise" vs "interrupteur mural" au niveau du
        # domaine HA (les deux sont des relais "switch") — "switch" est le
        # DeviceType le plus neutre des deux, cf. DEVICE_TYPE_OPTIONS (web).
        return "switch"
    if domain == "cover":
        return "cover"
    if domain == "sensor" and device_class == "temperature":
        return "sensor-temp"
    if domain == "binary_sensor":
        return _WIFI_BINARY_SENSOR_TYPE.get(device_class or "")
    return None


def _post_wifi_sync(devices_payload: list) -> bool:
    """pi_sync_devices (protocole "ha", wifi) via Supabase direct — True si
    réussi. Basculé de pi_sync_wifi_devices vers la RPC générique le
    2026-09-21, cf. chantier d'harmonisation Zigbee/Matter/WiFi (dernier des 3
    protocoles, après Zigbee/Matter déjà vérifiés en réel). `online` toujours
    fourni ici (état HA live au moment du sync) — WiFi gagne au passage une
    vraie alerte hors-ligne anti-flap, qu'il n'avait jamais eue jusqu'ici
    (pi_sync_wifi_devices ne touchait jamais la table alerts)."""
    try:
        normalized = [
            _normalize_device(
                "ha",
                external_id=d["wifi_id"], name=d["name"], type_=d["type"],
                vendor=d.get("vendor") or "", model=d.get("model") or "",
                online=d.get("online", True),
                extra={"ha_entity_id": d.get("ha_entity_id")},
            )
            for d in devices_payload
        ]
        return _sync_devices_to_supabase("ha", normalized, timeout=30)
    except Exception as e:
        warn(f"[supabase] pi_sync_devices(ha): {e}")
        return False


def _sync_wifi_devices_to_app():
    """Réconciliation périodique des équipements Wi-Fi natifs HA (Shelly pour
    commencer, cf. _WIFI_INTEGRATION_DOMAINS) → Supabase — même principe que
    _sync_matter_devices_to_app(), mais la source est le device_registry HA
    (pas de liste dédiée façon matter-server get_nodes() ou bridge/devices Z2M).
    Groupe les entités par device_id HA, choisit une entité principale par
    priorité de domaine, upsert via pi_sync_devices/protocole "ha" (clé
    wifi_id)."""
    dev_result = _ha_ws_call("config/device_registry/list")
    if not dev_result or not dev_result.get("success"):
        return
    ent_result = _ha_ws_call("config/entity_registry/list")
    if not ent_result or not ent_result.get("success"):
        return
    states_result = _ha_ws_call("get_states")
    states = states_result.get("result", []) if states_result and states_result.get("success") else []
    states_by_entity = {s.get("entity_id"): s for s in states}

    wifi_devices = {}
    for d in dev_result.get("result", []):
        wifi_id = _wifi_device_identifier(d)
        if wifi_id:
            wifi_devices[d.get("id")] = {
                "wifi_id": wifi_id,
                "name": d.get("name_by_user") or d.get("name") or "Appareil Wi-Fi",
                "vendor": d.get("manufacturer") or "",
                "model": d.get("model") or "",
            }

    entities_by_device: dict = {}
    for e in ent_result.get("result", []):
        did = e.get("device_id")
        if did in wifi_devices:
            entities_by_device.setdefault(did, []).append(e)

    def _sort_key(e):
        domain = e.get("entity_id", "").split(".")[0]
        return _WIFI_DOMAIN_PRIORITY.index(domain) if domain in _WIFI_DOMAIN_PRIORITY else len(_WIFI_DOMAIN_PRIORITY)

    devices_payload = []
    for device_id, info in wifi_devices.items():
        entities = [e for e in entities_by_device.get(device_id, [])
                    if e.get("entity_category") not in ("diagnostic", "config")]
        if not entities:
            continue
        entities.sort(key=_sort_key)
        primary = entities[0]
        primary_id = primary.get("entity_id", "")
        domain = primary_id.split(".")[0] if "." in primary_id else ""
        state = states_by_entity.get(primary_id) or {}
        attrs = state.get("attributes") or {}
        device_class = attrs.get("device_class") or primary.get("device_class") or primary.get("original_device_class")

        # Compteur général (2026-10-31, Hicham : un Shelly EM/3EM en Wi-Fi natif
        # sera systématiquement installé chez tout client sans Linky) : un device
        # dont UNE de ses entités est device_class "energy" est un compteur
        # général, peu importe l'entité choisie "principale" ci-dessus par la
        # priorité de domaine générique — un Shelly EM n'a aucun light/switch/
        # cover, seulement des capteurs puissance/énergie/tension/courant par
        # phase, dont l'ordre de retour HA n'a aucune raison de placer l'énergie
        # cumulée en premier. L'entité ENERGY elle-même est de toute façon déjà
        # reliée séparément via _backfill_ha_entity_links() (toutes les entités
        # du device, pas que la "principale") — seul le TYPE du device avait
        # besoin de cette correction pour que energy-breakdown/getSiteMonthlyEnergyRecap
        # (web) le reconnaissent comme compteur général. PAS ENCORE VÉRIFIÉ SUR
        # DU MATÉRIEL RÉEL (même réserve que _detect_wifi_device_type ci-dessus,
        # aucun Shelly physique disponible au moment de l'écriture) — basé sur
        # la doc officielle HA de l'intégration Shelly (device_class "energy"
        # garanti par l'intégration native). À revalider dès qu'un vrai Shelly
        # EM/3EM est disponible ; type se rafraîchit à chaque sync (upsert_wifi_device,
        # migration 0108), donc une correction ultérieure se propagera automatiquement.
        has_energy_entity = any(
            (states_by_entity.get(e.get("entity_id")) or {}).get("attributes", {}).get("device_class") == "energy"
            for e in entities
        )
        device_type = "energy-meter" if has_energy_entity else (_detect_wifi_device_type(domain, device_class) or "sensor-generic")

        devices_payload.append({
            "wifi_id": info["wifi_id"],
            "ha_entity_id": primary_id,
            "name": info["name"],
            "type": device_type,
            "vendor": info["vendor"],
            "model": info["model"],
            "online": state.get("state") != "unavailable",
        })

    _post_wifi_sync(devices_payload)


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
        explicitly_added = node_id in _explicitly_commissioned_matter_nodes
        _explicitly_commissioned_matter_nodes.discard(node_id)
        devices_payload.append({
            "node_id": node_id,
            "name": product or f"Matter #{node_id}",
            "vendor_name": vendor,
            "product_name": product,
            "device_type": device_type,
            # matter-server suit déjà nativement la joignabilité par nœud (champ
            # "available" de MatterNodeData, vérifié dans son code source) — pas
            # besoin d'un mécanisme séparé comme pour Zigbee (§109), juste
            # transmettre ce qu'il sait déjà à ce cycle de synchro périodique.
            "online": bool(node.get("available", False)),
            "explicitly_added": explicitly_added,
        })

    _sync_matter_devices_direct(devices_payload)


def _matter_commission_ws(code: str, request_id: str, timeout_s: int = 200):
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

        # message_id unique par tentative (pas une constante fixe) — 2 tentatives
        # concurrentes vers le même discriminator avaient sinon le même id, source
        # de confusion diagnostiquée en conditions réelles (cf. _matter_commission_lock).
        msg_id = f"commission-{request_id}"
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
    l'app le lit par polling pendant la fenêtre de commissioning.

    Une seule tentative à la fois (_matter_commission_lock) : matter-server ne gère
    pas 2 sessions PASE concurrentes vers le même discriminator — vu en test réel,
    2 requêtes envoyées à 1s d'intervalle ont fait échouer les 2 côté addon (l'une
    par un vrai rejet de discovery, l'autre par timeout sans jamais recevoir la
    vraie réponse) alors que matter-server avait réellement commissionné le device
    entre-temps (retrouvé ensuite par la sync périodique via get_nodes())."""
    if not _matter_commission_lock.acquire(blocking=False):
        warn(f"Matter commission {request_id[:8]}… rejetée — un appairage est déjà en cours")
        _post_ingest_commission_status(
            request_id, False,
            error="Un appairage Matter est déjà en cours — attends qu'il se termine avant de réessayer."
        )
        return

    def _do():
        try:
            # Audit add-on 2026-09-22 : le code de commissioning (PIN/QR, valable
            # le temps de la fenêtre de jumelage) ne doit jamais apparaître en
            # clair dans les logs Supervisor.
            log(f"Matter commission {request_id[:8]}… code=***")
            success, detail = _matter_commission_ws(code, request_id)
            if success:
                log(f"✓ Matter commission réussie — node_id={detail}")
                _post_ingest_commission_status(request_id, True, node_id=detail)
                try:
                    _explicitly_commissioned_matter_nodes.add(int(detail))
                except (TypeError, ValueError):
                    pass
            else:
                warn(f"⚠ Matter commission échouée: {detail}")
                _post_ingest_commission_status(request_id, False, error=detail)
        except Exception as exc:
            warn(f"Matter commission: {exc}")
            _post_ingest_commission_status(request_id, False, error=str(exc))
        finally:
            # Réveille la réconciliation complète (_sync_matter_devices_to_app via
            # _run_ha_maintenance_cycle) dans TOUS les cas — succès, échec ET exception — pas
            # seulement en cas de succès détecté par CE thread. Course PASE déjà
            # documentée plus haut (cf. _matter_commission_lock) : matter-server peut
            # avoir réellement commissionné le device même quand notre appel WS
            # timeout ou échoue côté addon, auquel cas l'ancien code ne réveillait
            # jamais la synchro — le device restait invisible dans l'appli jusqu'au
            # prochain cycle périodique naturel (~5 min), pas "tout de suite" comme
            # visé. Trouvé en conditions réelles (Hicham, 2026-08-02, §134) : ajout
            # via l'onglet Matter de l'appli, équipement bien présent côté Z2M/Matter,
            # mais apparu dans l'appli seulement ~5 minutes plus tard.
            _sync_requested.set()
            _matter_commission_lock.release()

    threading.Thread(target=_do, daemon=True).start()


def _post_ingest_commission_status(
    request_id: str, success: bool, node_id: str | None = None, error: str | None = None
):
    """Pousse le résultat du commissioning Matter vers Supabase (sites.last_commission_status)."""
    if not INGEST_SECRET:
        return
    try:
        _cloud_post(
            "vercel:ingest/commission-status",
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

# Audit add-on 2026-09-22 : le heartbeat (toutes les 60s) confirmait seulement
# que le processus Python tournait et joignait Supabase — un run_ha_ws_bridge()
# mort ou bloqué en boucle de reconnexion (ex: jeton HA expiré, crash silencieux
# du thread) laissait le site "en ligne" côté app alors qu'aucun état d'appareil
# ne remontait plus jamais. Vrai/Faux reflète l'état de connexion WS actuel
# (pas de lock : simple assignation bool, déjà atomique sous le GIL), inclus
# dans chaque heartbeat pour que Supabase puisse détecter ce cas précis.
_ws_bridge_connected = False

# ── Sync omnipresente App → HA ────────────────────────────────────────────────
_sync_requested  = threading.Event()  # déclenche un sync immédiat (ex: device supprimé)
_mqtt_broker_checked = False          # flag one-shot pour _check_and_fix_mqtt_broker
_last_ha_status_publish:    float = 0.0   # throttle homeassistant/status online
_last_z2m_devices_request:  float = 0.0   # throttle bridge/request/devices
# friendly_name → ieee_address, reconstruit à chaque bridge/devices reçu — les
# messages zigbee2mqtt/{friendly_name}/availability n'identifient le device QUE
# par son friendly_name (jamais l'ieee), il faut ce pont pour reporter le bon
# device à Supabase (ieee_address, seule clé stable si le nom change).
_z2m_friendly_to_ieee: dict[str, str] = {}
# Dernier payload brut zigbee2mqtt/bridge/devices reçu — permet à la route
# /alarmo/keypad (thread HTTP séparé, cf. _CommandHandler) de répondre
# instantanément sans redemander la liste à Z2M à chaque requête web.
_last_z2m_devices_list: list = []
# ieee_address -> dernier état COMPLET reçu sur zigbee2mqtt/{friendly_name}
# (cf. on_local_message et _report_zigbee_state_direct, qui pousse le MÊME
# payload vers Supabase pour le mode cloud) — jusqu'ici jeté après l'envoi
# Supabase, jamais retenu ici. Mode local (audit useHomeStore, "device sans
# entité utilisable", 2026-09-08) : `_build_local_devices()` n'a pas de
# Supabase à lire, ce cache est donc SA seule source pour les mêmes valeurs
# (battery/action/linkquality...) qu'un device Zigbee sans entité HA
# principale liée ne publie nulle part ailleurs (même bug que §167-169,
# jamais corrigé côté local faute d'exister à l'époque). Republié en entier
# à chaque changement par Z2M (jamais un diff partiel, cf. migration
# 0076_pi_report_zigbee_state.sql) — une simple affectation suffit, pas de
# merge nécessaire.
_last_z2m_raw_state: dict[str, dict] = {}

# (2026-09-01) Suivi des réponses à zigbee2mqtt/bridge/request/device/reporting/configure
# (cf. _handle_zigbee_boost_reporting) — Z2M répond de façon asynchrone sur
# bridge/response/device/reporting/configure, ce dict + les Event associés permettent
# à la route HTTP d'attendre la VRAIE confirmation ok/error par attribut au lieu de
# publier en aveugle (piège du 2026-09-01 : device/configure ne donne aucun retour,
# ce qui avait caché un fix incomplet — cf. HANDOFF).
_reporting_configure_lock = threading.Lock()
_reporting_configure_events: dict[tuple, threading.Event] = {}
_reporting_configure_results: dict[tuple, dict] = {}

# ieee_address déjà "boostés" (reporting reconfiguré, cf. _boost_device_reporting)
# DEPUIS LE DÉMARRAGE de ce process — mémoire simple en RAM, pas persistée : au pire
# un device est reconfiguré une 2e fois après un redémarrage de l'add-on, ce qui est
# sans risque (idempotent côté Z2M, se contente de renvoyer "ok"). Évite de
# republier à chaque cycle de synchro (toutes les 5 min).
_boosted_ieees: set[str] = set()

# Attribut Z2M (property exposée) → cluster/attribut ZCL réel + seuil de variation
# officiel + "sensible pile" (True = l'intervalle par défaut du convertisseur est
# volontairement long pour économiser une pile — cf. HANDOFF, ne JAMAIS raccourcir
# sans confirmation explicite d'Hicham device par device selon power_source).
# Tout vérifié dans le code source zigbee-herdsman-converters (src/lib/modernExtend.ts)
# avant d'écrire cette table, rien deviné :
# - genericMeter()/electricityMeter() : power/current/voltage(AC)/energy — jamais
#   sur un device à pile (une mesure de conso électrique suppose le secteur).
# - battery() : batteryPercentageRemaining/batteryVoltage — défaut Z2M 1h/MAX(~18h).
# - numeric() (temperature/humidity/illuminance/co2/pm25) : défaut Z2M 10s/1h.
# "voltage" est AMBIGU (tension secteur À  volts, ou tension de pile en millivolts,
# même nom de property côté Z2M) — désambiguïsé par l'unité réelle de l'expose
# (V → secteur, mV → pile), jamais par le nom seul.
_REPORTING_ATTRS = {
    # power/current : seuils desserrés le 2026-09-21 (2e passe du correctif
    # egress Supabase, sur demande explicite d'Hicham d'aller plus loin) —
    # 0,05 A était plus fin que le bruit de mesure réel d'un capteur de
    # courant bas de gamme, déclenchant un report quasiment à chaque cycle
    # même sans vraie variation de charge. 0,15 A/8 W filtrent ce bruit sans
    # perdre les vraies transitions (allumer/éteindre une charge change
    # bien plus que ça).
    "power":       ("haElectricalMeasurement", "activePower",          8,        False),
    "current":     ("haElectricalMeasurement", "rmsCurrent",           0.15,     False),
    "voltage":     ("haElectricalMeasurement", "rmsVoltage",           5,        False),
    "energy":      ("seMetering",               "currentSummDelivered", 0.1,     False),
    "temperature": ("msTemperatureMeasurement", "measuredValue",       100,      True),
    "humidity":    ("msRelativeHumidity",        "measuredValue",       100,      True),
    "illuminance": ("msIlluminanceMeasurement",  "measuredValue",       5,        True),
    "co2":         ("msCO2",                     "measuredValue",       0.00005,  True),
    "pm25":        ("pm25Measurement",           "measuredValue",       1,        True),
    "battery":     ("genPowerCfg",               "batteryPercentageRemaining", 10, True),
    "voltage_battery": ("genPowerCfg",           "batteryVoltage",       10,      True),
}


def _boost_device_reporting(ieee: str, exposes: list, power_source: str | None,
                             battery_reporting_seconds: int | None = None) -> dict:
    """Reconfigure explicitement un intervalle de reporting court pour les mesures
    d'un device Zigbee, via zigbee2mqtt/bridge/request/device/reporting/configure —
    l'API Z2M officielle et DISTINCTE de bridge/request/device/configure (utilisée
    par /zigbee/reconfigure) : cette dernière ne fait que ré-exécuter la fonction
    configure() du convertisseur du device (qui pour les prises IKEA E22xx ne
    configure QUE acPowerDivisor, vérifié dans le code source — jamais les mesures
    elles-mêmes). ATTEND la vraie réponse Z2M (ok/error) par attribut au lieu de
    publier en aveugle. Le seuil de changement (reportable_change) réutilise tel
    quel les valeurs par défaut du convertisseur officiel — seul l'intervalle max
    est raccourci.

    (2026-09-01) Généralisé de "mesures électriques uniquement" à TOUS les attributs
    numériques standards après une 2e demande explicite d'Hicham : "pourquoi tu
    reste focus seulement sur le domaine de l'energie [...] il faudrait que toute
    valeurs de tout les attribut disponible [...] soit mis a jour en temps reel [...]
    j'ai bien dit la valeur de tout les attributs". Les attributs marqués
    "battery_sensitive" dans _REPORTING_ATTRS (batterie %, tension de pile,
    température, humidité, éclairement, CO2, PM2.5 — tout ce qui existe aussi bien
    sur un device secteur qu'un device à pile) sont boostés à 30s SANS CONDITION sur
    un device secteur ; sur un device À PILE, ils utilisent `battery_reporting_seconds`
    (par défaut BATTERY_REPORTING_SECONDS, l'option add-on réglable par site — 0 =
    comportement usine préservé, souvent 1h à ~18h) au lieu d'un simple
    tout-ou-rien : Hicham, "on peut regler le time ?", en réponse au compromis
    autonomie/rapidité signalé pour ces devices — cf. HANDOFF. Les mesures
    électriques (power/current/voltage/energy) restent TOUJOURS boostées à 30s sans
    condition : elles n'existent structurellement que sur des devices secteur
    (prise/interrupteur à mesure de conso)."""
    if not _local_client:
        return {"error": "Mosquitto local non connecté"}

    if battery_reporting_seconds is None:
        battery_reporting_seconds = BATTERY_REPORTING_SECONDS
    is_mains = bool(power_source) and ("mains" in power_source.lower() or "dc" in power_source.lower())
    expose_by_prop = {e.get("property"): e for e in exposes if isinstance(e, dict) and e.get("property")}

    targets = []  # (label_pour_résultat, cluster, attr, change, max_interval)
    for prop, (cluster, attr, change, battery_sensitive) in _REPORTING_ATTRS.items():
        lookup_prop = "voltage" if prop == "voltage_battery" else prop
        expose = expose_by_prop.get(lookup_prop)
        if not expose:
            continue
        if prop == "voltage" and (expose.get("unit") or "").strip().lower() != "v":
            continue  # "voltage" en mV → tension de pile, traité par "voltage_battery"
        if prop == "voltage_battery" and (expose.get("unit") or "").strip().lower() != "mv":
            continue
        if not battery_sensitive or is_mains:
            max_interval = 30
        elif battery_reporting_seconds > 0:
            max_interval = battery_reporting_seconds
        else:
            continue  # device à pile, réglage désactivé (0) → comportement usine préservé
        targets.append((prop, cluster, attr, change, max_interval))
    if not targets:
        return {}

    results = {}
    for prop, cluster, attr, change, max_interval in targets:
        key = (ieee, cluster, attr)
        ev = threading.Event()
        with _reporting_configure_lock:
            _reporting_configure_events[key] = ev
            _reporting_configure_results.pop(key, None)
        # Bug réel trouvé le 2026-09-21 (facture Supabase, dépassement egress
        # gratuit) : minimum_report_interval à 1s laissait un device dont la
        # mesure a du bruit naturel (courant/tension électriques surtout)
        # republier jusqu'à 1x/seconde en continu — confirmé en conditions
        # réelles : 259 649 appels HTTP en 24h rien que sur le report d'un
        # device Zigbee (~3/s en continu). Générique à TOUT attribut de
        # _REPORTING_ATTRS, donc à TOUT futur équipement/client, pas
        # spécifique aux prises qui l'ont révélé. 1re passe : 10s. 2e passe
        # (toujours le 2026-09-21, sur demande explicite d'Hicham "aller plus
        # loin" après avoir vu que 10s seul ramenait la conso mensuelle
        # projetée à ~6,5-7 Go — toujours au-dessus du forfait gratuit 5,5 Go) :
        # remonté à 20s, ET seuils de changement desserrés ci-dessus
        # (power/current) — l'intervalle seul ne plafonne que le PIRE cas, les
        # seuils desserrés réduisent la fréquence RÉELLE en filtrant le bruit
        # de mesure qui saturait l'ancien seuil à chaque cycle. Toujours
        # imperceptible sur un dashboard, toujours sans lien avec
        # l'actionnement d'équipement (cf. commentaire plus haut, genOnOff
        # jamais dans _REPORTING_ATTRS). min(..., max_interval) : ne jamais
        # dépasser l'intervalle max lui-même (invalide côté ZCL) si
        # battery_reporting_seconds est configuré plus bas sur un futur site.
        min_interval = min(20, max_interval)
        _local_client.publish(
            "zigbee2mqtt/bridge/request/device/reporting/configure",
            json.dumps({
                "id": ieee, "endpoint": 1, "cluster": cluster, "attribute": attr,
                "minimum_report_interval": min_interval, "maximum_report_interval": max_interval,
                "reportable_change": change,
            }),
            qos=1,
        )
        got = ev.wait(timeout=8)
        with _reporting_configure_lock:
            resp = _reporting_configure_results.pop(key, None)
            _reporting_configure_events.pop(key, None)
        if not got or not resp:
            results[prop] = {"status": "timeout"}
        else:
            results[prop] = {"status": resp.get("status"), "error": resp.get("error")}
    return results


# (2026-11-11) Suivi des réponses à zigbee2mqtt/bridge/request/device/options —
# même mécanisme request/réponse corrélée que _reporting_configure_* ci-dessus,
# mais clé = ieee seul (une option par device, pas par attribut).
_options_configure_lock = threading.Lock()
_options_configure_events: dict[str, threading.Event] = {}
_options_configure_results: dict[str, dict] = {}

# ieee déjà configurés (cf. _configure_zlinky_tic_polling) DEPUIS LE DÉMARRAGE de
# ce process — même logique que _boosted_ieees, idempotent côté Z2M de toute
# façon (republier la même option ne fait rien de plus).
_tic_poll_configured: set[str] = set()


def _configure_zlinky_tic_polling(ieee: str) -> dict:
    """Bug réel trouvé en conditions réelles (Hicham, 2026-11-11) : le module
    LiXee ZLinky_TIC (lecture Linky) ne remontait presque plus aucune mise à
    jour de ses mesures cumulées (EAST, EASF01…) après le tout premier appairage
    — `measurement_poll_interval` (option PROPRE à ce convertisseur Z2M, PAS
    une config de reporting Zigbee standard comme _boost_device_reporting
    ci-dessus, car ce module publie en partie des attributs en lecture seule
    non-"reportable", lus par Z2M via polling actif plutôt que par push du
    device) vaut 600s (10 min) par défaut d'après la doc officielle
    (zigbee2mqtt.io/devices/ZLinky_TIC.html) — et un bug connu en amont a pu le
    laisser bloqué/inopérant pour de bon tant qu'il n'est jamais explicitement
    redéfini (cf. Koenkk/zigbee-herdsman-converters#10485). Confirmé en
    conditions réelles : capture du panneau "Paramètres de l'appareil" Z2M de
    Hicham montrant le champ vide (= défaut jamais forcé), et l'historique HA
    de `sensor..._east` figé ~24h malgré une vraie conso ailleurs dans le
    logement. Fixé ici à 60s (valeur qui a résolu le même symptôme pour
    plusieurs utilisateurs tiers, cf. recherche faite avant ce fix) — demandé
    UNE FOIS via l'API Z2M dédiée (bridge/request/device/options, DISTINCTE de
    device/reporting/configure), au tout premier appairage de CE module
    précis, sans aucune action manuelle de l'installateur ni du client."""
    if not _local_client:
        return {"error": "Mosquitto local non connecté"}
    ev = threading.Event()
    with _options_configure_lock:
        _options_configure_events[ieee] = ev
        _options_configure_results.pop(ieee, None)
    _local_client.publish(
        "zigbee2mqtt/bridge/request/device/options",
        json.dumps({"id": ieee, "options": {"measurement_poll_interval": 60}}),
        qos=1,
    )
    got = ev.wait(timeout=10)
    with _options_configure_lock:
        resp = _options_configure_results.pop(ieee, None)
        _options_configure_events.pop(ieee, None)
    if not got or not resp:
        return {"status": "timeout"}
    return {"status": resp.get("status"), "error": resp.get("error")}


def _configure_zlinky_tic_polling_logged(ieee: str) -> None:
    """Wrapper loggué de _configure_zlinky_tic_polling() — appelé en thread
    séparé depuis _sync_zigbee_devices_direct(), son retour serait sinon
    silencieusement perdu (pas de code appelant pour le lire)."""
    result = _configure_zlinky_tic_polling(ieee)
    if result.get("status") == "ok":
        log(f"[zlinky-tic] ✓ measurement_poll_interval=60s configuré pour {ieee}")
    else:
        warn(f"[zlinky-tic] échec configuration polling pour {ieee} : {result}")


# node_id Matter commissionnés explicitement via "Ajouter un équipement" (cf.
# handle_matter_commission) — exclus de la détection de fusion de doublon
# (pi_sync_matter_devices) : un vrai nouvel achat, identique à un équipement déjà
# hors ligne, ne doit jamais être confondu avec ce dernier. Retiré dès consommé
# par le premier cycle de sync qui voit ce node_id (cf. _sync_matter_devices_to_app).
_explicitly_commissioned_matter_nodes: set[int] = set()


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


def _run_ha_maintenance_cycle():
    """Cycle d'entretien LOCAL (toutes les 5 min, ou tout de suite via _sync_requested) : réveil de Z2M, réconciliation
    des équipements Matter/Wi-Fi, liens d'entités, réconciliation de l'alarme, IP locale et certificat.

    Lot D (phase 0) du chantier « Pi-first » : ce cycle (ex-`_sync_all_to_ha`) commençait par TIRER l'état voulu depuis le
    cloud (GET /api/webhooks/pi/sync-state : pièces, affectations, scènes, automatisations et caméras de Supabase) et
    l'appliquait à Home Assistant. Le cloud n'est plus la source de vérité — l'app du Pi écrit directement dans HA par le
    serveur de commandes — et ce tirage était devenu DESTRUCTEUR :
      - `_reconcile_cameras` supprimait de Frigate (puis redémarrait Frigate) toute caméra locale absente de la table
        `cameras` de Supabase ; or une caméra ajoutée depuis l'app du Pi n'y est jamais écrite → un site Pi-first aurait
        perdu TOUTES ses caméras au plus tard 5 min après son premier passage (reproduit sur le vrai code) ;
      - les scènes/automatisations supprimées dans l'app du Pi étaient recréées depuis le cloud, les pièces ré-affectées.
    Retiré en bloc (avec `_sync_areas_batch`, `_reconcile_cameras`, `_report_room_assignments_direct`). Les actions de
    l'app arrivent par les commandes directes ; il n'y a plus de « rattrapage » depuis le cloud."""
    global _last_ha_status_publish, _last_z2m_devices_request

    # Déclencher Z2M pour republier ses discovery messages HA → HA peuple son device registry.
    # Throttlé à 1x/5min pour éviter le flood de messages MQTT.
    _now = time.time()
    if _local_client and (_now - _last_ha_status_publish > 300):
        _local_client.publish("homeassistant/status", "online", qos=1)
        _last_ha_status_publish = _now
        log("[sync] homeassistant/status online → Z2M republiera les discovery HA")

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
    # Throttlé à 1x/5min.
    if _local_client and (time.time() - _last_z2m_devices_request > 300):
        _local_client.unsubscribe("zigbee2mqtt/bridge/devices")
        _local_client.subscribe([("zigbee2mqtt/bridge/devices", 1)])
        _last_z2m_devices_request = time.time()
        log("[sync] Re-souscription bridge/devices → retained message redélivré (sync Zigbee)")

    # Réconciliation Matter (get_nodes) — même logique que bridge/devices Zigbee,
    # auto-réparatrice si l'enregistrement post-commissioning a échoué ou a été manqué.
    _sync_matter_devices_to_app()

    # Réconciliation équipements Wi-Fi natifs HA (onglet "Autre" — Shelly pour
    # commencer, cf. HANDOFF.md 2026-09-06).
    _sync_wifi_devices_to_app()

    _backfill_ha_entity_links()
    _backfill_camera_entity_links()
    _reconcile_alarm_state()
    _report_local_ip()
    _fetch_local_cert()

    log("[sync] ✓ Entretien local terminé")


def _backfill_ha_entity_links():
    """Relie tout device (Zigbee ou Matter) dont ha_entity_id est encore vide à son
    entité HA — rattrape les devices créés avant le lien entity_registry_updated→
    ieee/node_id (ou dont l'événement a été manqué : redémarrage, erreur réseau
    ponctuelle…). Idempotent (ré-envoyer le même lien ne fait rien) — appelé à chaque
    cycle de sync. Sans ce lien pour Matter, l'état (ex: capteur d'ouverture) ne
    remonte jamais dans l'app — vu en test réel après le 1er commissioning.

    Les entités "diagnostic"/"config" (batterie, tension, infos réseau Thread,
    défauts matériels…) étaient jusqu'ici exclues en bloc — audit en conditions
    réelles (Hicham, 2026-08-09, sur "Capteur de mouvement" Matter) : 17 entités
    réelles côté HA pour ce device, 1 seule captée côté app. Batterie notamment
    manquait, alors qu'explicitement demandée pour de futures conditions
    d'automatisation. Repli symétrique à celui déjà fait côté Zigbee (§168, web) :
    ne plus pré-filtrer par catégorie HA — NOISE_DOMAINS côté web
    (/api/ingest/registry, update/button/event) continue d'exclure ce qui reste
    du bruit pur (firmware, boutons "Identifier")."""
    result = _ha_ws_call("config/entity_registry/list")
    if not result or not result.get("success"):
        return
    # device_id HA → wifi_id (identifiant physique stable, ex: adresse MAC Shelly,
    # cf. migration 0108) — même rôle que _IEEE_RE / _matter_node_id_from_unique_id
    # ci-dessous, mais l'identifiant n'est pas dans unique_id : il faut passer par
    # device_registry pour lire les "identifiers" ([domaine, valeur]) du device HA.
    wifi_ids_by_device_id = {}
    dev_result = _ha_ws_call("config/device_registry/list")
    if dev_result and dev_result.get("success"):
        for d in dev_result.get("result", []):
            wid = _wifi_device_identifier(d)
            if wid:
                wifi_ids_by_device_id[d.get("id")] = wid
    # device_class/unit (2026-09-01) — Hicham, capture HA à l'appui : "sur Home
    # Assistant [...] j'arrive à avoir les unités et pas sur le site [...] que ce
    # soit du matter ou du zigbee". 1er jet : lu sur l'entrée entity_registry
    # elle-même (device_class/original_device_class, même pattern déjà éprouvé
    # côté caméras) — marchait pour Matter, mais PAS pour Zigbee2MQTT (plateforme
    # "mqtt") : vérifié en conditions réelles sur le vrai HA du site de test
    # (WebSocket direct) qu'une entrée entity_registry `platform: mqtt` ne porte
    # JAMAIS ces champs, ni même unit_of_measurement — uniquement présents sur
    # l'ÉTAT (attributs), pas le registre, pour cette plateforme précise. Un seul
    # get_states ici (même pattern que handle_alarmo_get_sensors), pas un appel
    # par entité — ce backfill tourne déjà sur TOUTES les entités du site.
    states_result = _ha_ws_call("get_states")
    states = states_result.get("result", []) if states_result and states_result.get("success") else []
    states_by_entity = {s.get("entity_id"): s for s in states}
    for e in result.get("result", []):
        entity_id = e.get("entity_id", "")
        unique_id = e.get("unique_id") or ""
        m = _IEEE_RE.search(unique_id)
        attrs = (states_by_entity.get(entity_id) or {}).get("attributes") or {}
        payload = {
            "siteSecret": INGEST_SECRET,
            "siteId": SITE_PREFIX,
            "action": "added",
            "entityId": entity_id,
            "friendlyName": e.get("name") or e.get("original_name"),
            "domain": entity_id.split(".")[0] if "." in entity_id else None,
            # Permet au web de ne jamais laisser une entité diagnostic/config
            # (ex: "Défauts matériels", binary_sensor comme le vrai capteur
            # d'occupation) usurper le lien ha_entity_id PRINCIPAL du device juste
            # parce que son domaine correspond — seul un vrai état (catégorie vide)
            # doit pouvoir le faire. Trouvé en vérifiant le résultat de ce fix
            # (2026-08-09) : sans ça, l'ordre de retour de la liste HA déciderait
            # au hasard, à chaque cycle, quelle entité fait autorité pour ce device.
            "entityCategory": e.get("entity_category"),
            # État en priorité (seule source fiable pour mqtt/Zigbee2MQTT),
            # registre en repli (utile pour un éventuel override utilisateur côté
            # Matter/natif — jamais présent côté mqtt de toute façon, cf. ci-dessus).
            "deviceClass": attrs.get("device_class") or e.get("device_class") or e.get("original_device_class"),
            "unit": attrs.get("unit_of_measurement") or e.get("unit_of_measurement") or e.get("original_unit_of_measurement"),
        }
        if m:
            payload["ieeeAddress"] = m.group(0)
        else:
            node_id = _matter_node_id_from_unique_id(unique_id)
            if node_id is not None:
                payload["matterNodeId"] = node_id
            else:
                wifi_id = wifi_ids_by_device_id.get(e.get("device_id"))
                if wifi_id is None:
                    continue
                payload["wifiId"] = wifi_id
        try:
            _cloud_post_if_changed("vercel:ingest/registry", f"{APP_URL}/api/ingest/registry", payload, f"ent:{entity_id}")
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
        "valve", "humidifier",
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
            sent = _cloud_post_if_changed(
                "vercel:ingest/camera-registry",
                f"{APP_URL}/api/ingest/camera-registry",
                {
                    "siteSecret": INGEST_SECRET,
                    "siteId": SITE_PREFIX,
                    "cameraHaEntityId": entity_id,
                    "entities": secondary,
                },
                f"cam:{entity_id}",
            )
            if sent:
                log(f"[camera-registry] {entity_id} → {len(secondary)} entité(s) secondaire(s)")
        except Exception as ex:
            warn(f"[camera-registry] {entity_id}: {ex}")


def _ha_sync_loop():
    """Thread de fond : cycle d'entretien local (_run_ha_maintenance_cycle) toutes les 5 minutes.
    Se déclenche immédiatement via _sync_requested (appairage Matter, entité créée/retirée, bouton « Sync HA »)."""
    log("[sync] Thread de sync démarré — premier sync dans 30s")
    time.sleep(30)  # laisser HA + EMQX s'initialiser
    while True:
        try:
            _run_ha_maintenance_cycle()
        except Exception as e:
            warn(f"[sync] Erreur inattendue : {e}")
        # Attend 5 min OU un déclenchement immédiat (reconnexion EMQX, etc.) — le
        # timeout était resté à 60s (bug, 5x plus d'appels que prévu à /sync-state,
        # constaté en creusant le dépassement de quota Vercel du 2026-07-18).
        _sync_requested.wait(timeout=300)
        _sync_requested.clear()


def call_heartbeat_api():
    """Demande l'envoi du résumé de flotte (cf. _run_fleet_status_loop) — appelé quand la santé de Z2M change. L'envoi
    effectif est limité à 1 par minute. (Nom conservé : ancien heartbeat à la minute, remplacé par le résumé de flotte.)"""
    _fleet_request.set()


def _relay_alarm_state(entity_id: str, state_val: str, attributes: dict):
    """Pousse l'état d'une alarme (alarm_control_panel.*) vers Supabase (pi_report_alarm_state) — appel direct
    immédiat (rare : seulement les transitions). Depuis le lot D (phase 1) du chantier « Pi-first », c'est le SEUL état
    d'équipement encore remonté au cloud : il déclenche le PUSH « alarme déclenchée » (pg_net → /api/webhooks/push-alarm),
    fonction de sécurité conservée jusqu'à ce que le Pi envoie lui-même ses notifications (lot F). Tout le reste
    (lumières, capteurs, prises, mesures… — le gros du volume Supabase) n'est plus envoyé : l'app du Pi lit HA directement.

    Audit add-on 2026-09-22 : l'appel direct n'avait aucun filet de retry — un échec (Supabase indisponible, timeout)
    perdait la transition définitivement, sur la donnée la plus sensible du système. En cas d'échec du premier essai,
    réintégré dans _alarm_state_batch pour être retenté par _flush_alarm_state_batch au prochain cycle (2.5s)."""
    if not entity_id.startswith("alarm_control_panel.") or not INGEST_SECRET:
        return
    _alarm_push_on_state(entity_id, state_val)       # push d'alarme envoyé par le boîtier (lot F), indépendant du cloud

    def _send_alarm_with_retry():
        if not _report_alarm_state_direct(entity_id, state_val, attributes):
            with _state_batch_lock:
                _alarm_state_batch[entity_id] = (state_val, attributes)
    threading.Thread(target=_send_alarm_with_retry, daemon=True).start()


# ── Flux temps réel vers l'app locale (SSE) ────────────────────────────────
# Chantier « Pi-first » (2026-11-17) : l'app Domoticium servie par le Pi n'interroge plus
# l'add-on toutes les 4 s — elle ouvre UN flux Server-Sent Events (GET /local/events, via sa
# route Next /api/local/events) et ne relit l'état QUE lorsqu'on lui signale un changement.
# Le flux ne transporte volontairement AUCUNE donnée d'état : seulement « quelque chose a
# changé » (voie `fast`) ou « une mesure a bougé » (voie `slow`). Le client relit alors
# /local/devices, qui garde l'UNIQUE logique de classification/mise en forme des équipements
# (_build_local_devices) — pas de 2e copie à tenir synchronisée.
#  - voie `fast` : tout ce qui n'est pas une mesure (interrupteur, contact, mouvement,
#    alarme, volet, clim…) — signal envoyé au plus toutes les _SSE_FAST_MIN_INTERVAL_S ;
#  - voie `slow` : les `sensor.*` (puissance, température…) — au plus toutes les
#    _SSE_SLOW_MIN_INTERVAL_S, pour qu'un compteur d'énergie qui bouge chaque seconde ne
#    déclenche pas une relecture complète chaque seconde ;
#  - un événement dont l'état ET les attributs (hors attributs « horloge » déjà ignorés par
#    _DEDUPE_IGNORED_ATTRS, ex. position d'un lecteur média) sont identiques au précédent est
#    ignoré — un seul téléviseur représentait 91 % des state_changed (cf. plus haut) ;
#  - rien n'est calculé tant qu'aucun client n'est connecté.
# Aucun quota à ménager (plus de Supabase dans ce chemin) : c'est la charge du Pi qu'on borne
# (_SSE_MAX_SUBSCRIBERS flux simultanés, file de 64 signaux par abonné, un signal perdu est
# rattrapé par le suivant ou par la relève de sécurité périodique côté client).
_SSE_MAX_SUBSCRIBERS = 8
_SSE_FAST_MIN_INTERVAL_S = 0.25
_SSE_SLOW_MIN_INTERVAL_S = 4.0
_SSE_KEEPALIVE_S = 15.0
_SSE_IGNORED_DOMAINS = frozenset({
    "sun", "weather", "update", "person", "zone", "persistent_notification",
    "conversation", "tts", "stt", "todo", "calendar",
})
_sse_lock = threading.Lock()
_sse_subscribers: set = set()
_sse_last_sig: dict = {}


def _sse_publish(lane: str) -> None:
    with _sse_lock:
        subscribers = list(_sse_subscribers)
    for q in subscribers:
        try:
            q.put_nowait(lane)
        except queue.Full:
            pass  # abonné lent : le prochain signal (ou la relève client) le rattrape


def _sse_note_state_change(entity_id: str, new_state: dict) -> None:
    """Appelé par le pont WebSocket pour chaque state_changed — très bon marché tant qu'aucun client n'est connecté."""
    if not _sse_subscribers:
        return
    domain = entity_id.split(".", 1)[0]
    if domain in _SSE_IGNORED_DOMAINS:
        return
    attrs = new_state.get("attributes") or {}
    sig = (
        new_state.get("state"),
        tuple(sorted((k, repr(v)) for k, v in attrs.items() if k not in _DEDUPE_IGNORED_ATTRS)),
    )
    if _sse_last_sig.get(entity_id) == sig:
        return
    _sse_last_sig[entity_id] = sig
    _sse_publish("slow" if domain == "sensor" else "fast")


def run_ha_ws_bridge():
    """Thread permanent : écoute le WebSocket de Home Assistant (state_changed + entity_registry_updated). Seul canal d'état
    événementiel. Alimente : le flux temps réel de l'app du Pi (SSE), le moteur d'alertes, le relais d'ALARME vers le cloud
    (seul état encore remonté, cf. _relay_alarm_state) et le registre d'entités. Depuis le lot D (phase 1) du chantier
    « Pi-first », les états d'équipements ne sont plus envoyés à Supabase."""
    global _ws_bridge_connected
    while True:
        _ws_bridge_connected = False
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
            _ws_bridge_connected = True

            while True:
                msg = ws_recv()
                if msg.get("type") != "event":
                    continue
                event = msg.get("event", {})
                event_type = event.get("event_type")
                data = event.get("data", {})

                if event_type == "state_changed":
                    entity_id = data.get("entity_id", "")
                    new_state = data.get("new_state")
                    if not new_state:
                        continue
                    _sse_note_state_change(entity_id, new_state)
                    _alerts_note_state(entity_id, new_state.get("state", ""), new_state.get("attributes") or {})
                    _relay_alarm_state(entity_id, new_state.get("state", ""), new_state.get("attributes", {}))

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
                    # Une entité créée/retirée dans HA (Matter ou natif — Zigbee est
                    # déjà instantané via zigbee2mqtt/bridge/devices, cf. on_local_message)
                    # réveille tout de suite le cycle de synchro périodique plutôt que
                    # d'attendre jusqu'à 5 min — que le device ait été appairé/retiré
                    # depuis notre appli ou directement dans HA. Même mécanisme que le
                    # commissioning Matter réussi ou la reconnexion EMQX (_sync_requested,
                    # un réveil ponctuel, pas un nouveau minuteur) — ne recrée pas le
                    # risque de quota Vercel du 2026-07-18, qui venait d'une PÉRIODE trop
                    # courte, pas d'un déclenchement événementiel. Corrige le délai
                    # signalé par Hicham (2026-08-02, §133) pour un appareil ajouté ou
                    # retiré directement dans HA plutôt que via l'appli.
                    if action in ("create", "remove"):
                        _sync_requested.set()
                        _alerts_reindex.set()   # l'index des équipements du moteur d'alertes suit
                        _alerts_wake.set()
                    # Équipement ajouté/retiré/renommé : l'app locale doit se relire sans attendre.
                    if action in ("create", "remove", "update") and entity_id:
                        _sse_publish("fast")

        except Exception as e:
            _ws_bridge_connected = False
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
        # §163 : le state HA d'une entité climate EST son hvac_mode ("heat"/"cool"/
        # "auto"/"dry"/"fan_only"/"off"…) — jamais capturé jusqu'ici au-delà d'un
        # simple on/off dérivé.
        return {"on": state != "off", "hvacMode": state}
    if domain == "lock":
        # §163 : "jammed" existe comme 3e état réel (ni verrouillé ni déverrouillé,
        # le loquet a essayé de bouger et s'est bloqué) — jusqu'ici confondu avec
        # "déverrouillé" par le simple booléen "on".
        return {"on": state == "locked", "lockState": state}
    if domain == "valve":
        return {"on": state not in ("closed", "unavailable")}
    # §2026-08-19 — select (fil pilote) : le state HA d'une entité select EST
    # l'option actuellement choisie (ex: "eco"/"comfort"/"off"), à l'identique du
    # pattern déjà utilisé pour climate.hvac_mode ci-dessus. On dérive aussi un
    # "on" indicatif (frost_protection/off = pas en train de chauffer) — utile
    # pour de futures règles de suggestion, cette catégorie n'étant pas un
    # actionneur simple ailleurs dans l'app.
    if domain == "select":
        return {"pilotWireMode": state, "on": state not in ("off", "frost_protection")}
    # §2026-08-19 — vacuum : le state HA EST déjà le VacuumActivity normalisé
    # (cleaning/docked/idle/paused/returning/error), vérifié doc HA officielle.
    if domain == "vacuum":
        return {"vacuumState": state}
    return {"on": state == "on"}


def _ha_attributes_to_normalized(entity_id: str, attrs: dict, merged: dict) -> dict:
    domain = entity_id.split(".")[0]
    result: dict = {}

    if domain == "light":
        brightness = attrs.get("brightness")
        if isinstance(brightness, (int, float)):
            result["brightness"] = round((brightness / 255) * 100)
        # Couleur (§160+) : HA calcule et expose TOUJOURS rgb_color/color_temp_kelvin
        # de façon standard sur une entité light, quel que soit le protocole d'origine
        # (Zigbee via Z2M, Matter via matter-server) et quel que soit le mode de
        # couleur natif du device (xy, hs, rgb) — vérifié dans la doc HA LightEntity.
        # Un seul code ici couvre donc Zigbee ET Matter, pas besoin de reconstruire
        # la conversion xy/hs → rgb nous-mêmes.
        rgb = attrs.get("rgb_color")
        if isinstance(rgb, (list, tuple)) and len(rgb) == 3:
            result["color"] = "#{:02x}{:02x}{:02x}".format(*(max(0, min(255, int(c))) for c in rgb))
        color_temp_kelvin = attrs.get("color_temp_kelvin")
        if isinstance(color_temp_kelvin, (int, float)):
            result["colorTemp"] = round(color_temp_kelvin)
        return result

    if domain == "sensor":
        dc = attrs.get("device_class")
        val = merged.get("value")
        if val is not None:
            if dc == "temperature": result["temperature"] = val
            elif dc == "humidity": result["humidity"] = val
            elif dc == "battery": result["battery"] = val
            # "power" (W, instantané) et "energy" (kWh, cumulatif depuis la mise
            # en service) sont deux grandeurs différentes, pas interchangeables —
            # avant, les deux tombaient dans state.power, ce qui rendait
            # EnergyChart.tsx (qui lit payload.energy) muet pour tout appareil
            # n'exposant QUE l'énergie cumulative (ex: un compteur général sans
            # mesure de puissance instantanée séparée).
            # "apparent_power" (VA) : device_class HA distinct de "power" (W), c'est
            # ce que le Lixee ZLinky (lecture Linky) expose comme grandeur
            # instantanée (property Z2M `apparent_power`, PAPP/SINSTS) — pas de vrai
            # "power" actif sur ce modèle. Approximation raisonnable en contexte
            # domestique (facteur de puissance proche de 1 pour la plupart des
            # usages), mieux qu'un state.power vide.
            elif dc in ("power", "apparent_power"): result["power"] = val
            elif dc == "energy": result["energy"] = val
            # §2026-08-19 — utility-meter (gaz/eau, PAS électrique) : HA n'a pas de
            # device_class dédié "heat"/chauffage collectif (vérifié doc HA
            # SensorDeviceClass officielle) — un compteur de calories remonterait
            # sous "energy" comme n'importe quel appareil électrique, indistinguable
            # ici ; seuls gas/water ont un device_class propre et sans ambiguïté.
            elif dc in ("gas", "water"):
                result["utilityReading"] = val
                unit = attrs.get("unit_of_measurement")
                if isinstance(unit, str):
                    result["utilityUnit"] = unit
            # HA n'a pas de device_class standard "people_count" — repli sur le
            # nom d'entité (même principe que les autres cas déjà tolérés ici,
            # ex. utility-meter), le seul signal disponible pour ce capteur
            # (2026-08-27, ShinaSystem CSM-300ZB, cf. people-counter).
            elif "people" in entity_id:
                result["peopleCount"] = val
            else: result["value"] = val
        return result

    if domain == "binary_sensor":
        dc = attrs.get("device_class")
        is_on = merged.get("on")
        if dc in ("motion", "occupancy", "presence"):
            result["motion"] = is_on
        elif dc in ("door", "window", "opening", "contact", "garage_door"):
            result["contact"] = (not is_on) if is_on is not None else None
        elif dc == "moisture":
            result["waterLeak"] = is_on  # HA: on = fuite détectée
        # §2026-08-19 — smoke-co : device_class "gas" (fuite de gaz naturel/méthane,
        # distincte de "carbon_monoxide") repliée sur le même champ state.co par
        # simplification volontaire (cf. commentaire types/index.ts) — un vrai
        # 3e champ dédié serait plus exact mais plus de complexité pour un premier
        # jet, aucun device de ce type installé chez un client à ce jour.
        elif dc == "smoke":
            result["smoke"] = is_on
        elif dc in ("carbon_monoxide", "gas"):
            result["co"] = is_on
        return result

    if domain == "climate":
        cur_temp = attrs.get("current_temperature")
        if isinstance(cur_temp, (int, float)):
            result["temperature"] = cur_temp
        target_temp = attrs.get("temperature")
        if isinstance(target_temp, (int, float)):
            result["targetTemperature"] = target_temp
        # §163 — motifs HA standards climate (doc officielle developers.home-assistant.io/
        # docs/core/entity/climate), jamais lus jusqu'ici : préréglage, vitesse
        # ventilation, balayage vertical/horizontal.
        for src, dst in (("preset_mode", "presetMode"), ("fan_mode", "climateFanMode"),
                         ("swing_mode", "swingMode"), ("swing_horizontal_mode", "swingHorizontalMode")):
            val = attrs.get(src)
            if isinstance(val, str):
                result[dst] = val
        return result

    # Pilotage en direct fan/cover/valve/humidifier (§158 web, généralisation du
    # panneau de pilotage) — jusqu'ici seules leurs CAPACITÉS (limites) étaient lues
    # (_ha_attributes_to_capabilities ci-dessous), jamais leur valeur courante :
    # un ventilateur/volet/vanne/humidificateur n'avait donc qu'un on/off, sans
    # vitesse/position/humidité cible affichée ni pilotable en direct (seul
    # l'éditeur de scènes le permettait, sur un brouillon local jamais relu).
    if domain == "fan":
        percentage = attrs.get("percentage")
        if isinstance(percentage, (int, float)):
            result["percentage"] = percentage
        # Motifs HA standards (§163, doc officielle developers.home-assistant.io/
        # docs/core/entity/fan) — présents sur toute entité fan qui les supporte,
        # Zigbee ou Matter, jamais lus jusqu'ici.
        preset_mode = attrs.get("preset_mode")
        if isinstance(preset_mode, str):
            result["presetMode"] = preset_mode
        direction = attrs.get("direction")
        if isinstance(direction, str):
            result["direction"] = direction
        oscillating = attrs.get("oscillating")
        if isinstance(oscillating, bool):
            result["oscillating"] = oscillating
        return result

    if domain in ("cover", "valve"):
        position = attrs.get("current_position")
        if isinstance(position, (int, float)):
            result["position"] = position
        # Tilt (§163) : attribut current_cover_tilt_position, distinct de la
        # position — un volet vénitien pilote les deux indépendamment (vérifié
        # doc HA officielle, jamais lu jusqu'ici). "valve" n'a pas de tilt (pas
        # de service set_valve_tilt_position dans HA), seul "cover" l'a.
        if domain == "cover":
            tilt = attrs.get("current_tilt_position")
            if isinstance(tilt, (int, float)):
                result["tiltPosition"] = tilt
        return result

    if domain == "humidifier":
        target_humidity = attrs.get("humidity")
        if isinstance(target_humidity, (int, float)):
            result["targetHumidity"] = target_humidity
        # Mode (§163, ex: "normal"/"eco"/"away"…) — doc HA officielle, jamais lu.
        mode = attrs.get("mode")
        if isinstance(mode, str):
            result["humidifierMode"] = mode
        return result

    return result


def _ha_entity_to_normalized_patch(entity_id: str, state: str, attributes: dict) -> dict:
    state_patch = _ha_state_to_normalized(entity_id, state)
    attr_patch = _ha_attributes_to_normalized(entity_id, attributes, state_patch)
    return {**state_patch, **attr_patch}


# Attributs "capacité" (limites propres à l'appareil — jamais son état courant) vs
# attributs "état" (_ha_attributes_to_normalized ci-dessus) : une fois qu'un
# appareil Zigbee OU Matter est une entité HA, les deux exposent ces limites de la
# même façon générique (min_temp/max_temp d'un climate, current_position d'un
# cover/valve qui en a une, percentage_step d'un fan, min/max_humidity d'un
# humidifier…) — jusqu'ici seul Zigbee avait un équivalent (les "exposes" Z2M, lus
# séparément). §130 (2026-08-02) : lire ces attributs HA bruts directement comble
# ce point aveugle pour Matter, sans dupliquer un schéma par protocole.
def _ha_attributes_to_capabilities(entity_id: str, attrs: dict) -> dict:
    domain = entity_id.split(".")[0]
    result: dict = {}

    if domain == "climate":
        if isinstance(attrs.get("min_temp"), (int, float)):
            result["minTemp"] = attrs["min_temp"]
        if isinstance(attrs.get("max_temp"), (int, float)):
            result["maxTemp"] = attrs["max_temp"]
        if isinstance(attrs.get("target_temp_step"), (int, float)):
            result["tempStep"] = attrs["target_temp_step"]
        # §163 — présence réelle par device, jamais supposée. `presetModes`
        # partagé avec le domaine "fan" (même concept de raccourci prédéfini),
        # les deux types de device sont mutuellement exclusifs en pratique.
        for src, dst in (("hvac_modes", "hvacModes"), ("preset_modes", "presetModes"),
                         ("fan_modes", "climateFanModes"), ("swing_modes", "swingModes"),
                         ("swing_horizontal_modes", "swingHorizontalModes")):
            val = attrs.get(src)
            if isinstance(val, list) and val:
                result[dst] = val

    elif domain == "fan":
        if isinstance(attrs.get("percentage_step"), (int, float)):
            result["percentageStep"] = attrs["percentage_step"]
        # §163 : présence de la liste = support réel par CE device, jamais supposé.
        preset_modes = attrs.get("preset_modes")
        if isinstance(preset_modes, list) and preset_modes:
            result["presetModes"] = preset_modes
        if "direction" in attrs:
            result["supportsDirection"] = True
        if "oscillating" in attrs:
            result["supportsOscillating"] = True

    elif domain in ("cover", "valve"):
        # Présence de l'attribut (pas sa valeur) = signal de support natif HA — un
        # cover/valve tout-ou-rien ne l'expose jamais.
        if "current_position" in attrs:
            result["supportsPosition"] = True
        if domain == "cover" and "current_tilt_position" in attrs:
            result["supportsTilt"] = True

    elif domain == "humidifier":
        if isinstance(attrs.get("min_humidity"), (int, float)):
            result["minHumidity"] = attrs["min_humidity"]
        if isinstance(attrs.get("max_humidity"), (int, float)):
            result["maxHumidity"] = attrs["max_humidity"]
        # §163
        modes = attrs.get("available_modes")
        if isinstance(modes, list) and modes:
            result["humidifierModes"] = modes

    elif domain == "select":
        # Aujourd'hui, seul le fil pilote (heating-relay) utilise une entité
        # select.* en position PRIMAIRE — à revoir si un futur DeviceType fait
        # de même (l'entité select générique en position SECONDAIRE, §161, ne
        # passe jamais par cette fonction : elle n'a pas de "capacités" propres,
        # juste ses options lues directement au moment de la commande).
        options = attrs.get("options")
        if isinstance(options, list) and options:
            result["pilotWireModes"] = options

    elif domain == "lock":
        # §163 — LockEntityFeature.OPEN = bit 1 du bitmask HA standard
        # supported_features (vérifié doc HA officielle) : seuls les verrous qui le
        # supportent exposent réellement lock.open (porte à loquet électrique).
        features = attrs.get("supported_features")
        if isinstance(features, int) and features & 1:
            result["supportsOpen"] = True

    elif domain == "light":
        # supported_color_modes (liste HA standard, ex: ["xy"], ["hs"], ["color_temp"],
        # ["rgb"]…) — présence = source de vérité pour savoir si CE device précis
        # supporte la couleur/temp. de couleur, pas une supposition par type.
        modes = attrs.get("supported_color_modes") or []
        if isinstance(modes, list):
            if any(m in ("xy", "hs", "rgb", "rgbw", "rgbww") for m in modes):
                result["supportsColor"] = True
            if "color_temp" in modes:
                result["supportsColorTemp"] = True
        if isinstance(attrs.get("min_color_temp_kelvin"), (int, float)):
            result["minColorTempKelvin"] = attrs["min_color_temp_kelvin"]
        if isinstance(attrs.get("max_color_temp_kelvin"), (int, float)):
            result["maxColorTempKelvin"] = attrs["max_color_temp_kelvin"]

    return result


# ── Retry de l'état d'alarme (seul état encore remonté au cloud) ──────────────────────────────────────
# Les batchs d'états d'équipements (HA + Zigbee brut), leurs frein/filtres/tolérances et le « statut caméra » ont été retirés
# au lot D (phase 1) : c'était le gros du volume Supabase (3 dépassements de quota en novembre 2026). Reste le retry de
# l'alarme, qui utilise une RPC dédiée (pi_report_alarm_state) — cf. _relay_alarm_state / _flush_alarm_state_batch.
_state_batch_lock = threading.Lock()
_alarm_state_batch: dict = {}

# Attributs « horloge » qui changent sans valeur pour l'app (position d'un lecteur média…) : un événement dont l'état ET
# tous les autres attributs sont identiques au précédent est ignoré par le flux temps réel local (cf. _sse_note_state_change)
# — un seul téléviseur représentait 91 % des state_changed d'un site (mesuré le 2026-09-27).
_DEDUPE_IGNORED_ATTRS = frozenset({"media_position", "media_position_updated_at", "last_seen"})

def _go2rtc_active_consumers() -> dict[str, bool]:
    """Liste (via /api/streams, une seule requête légère, aucune nouvelle connexion
    ouverte) les flux ayant au moins un consommateur actif (quelqu'un regarde le direct
    en ce moment — HLS/WebRTC). Retourne {stream_name: bool}."""
    try:
        r = requests.get(f"{GO2RTC_API_BASE}/api/streams", auth=GO2RTC_API_AUTH, timeout=5)
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
    répétée à chaque cycle watchdog de 60s).

    §92/§95/§96 — un contrôle "flux figé malgré consommateur actif" (comparaison de
    bytes_recv entre deux cycles) avait été ajouté puis restreint aux caméras
    masquées, dans l'idée de détecter plus vite une coupure pendant que la page
    Caméras reste ouverte (cf. HANDOFF §92). Retiré entièrement : confirmé en
    conditions réelles le 2026-07-26 que le bug touchait aussi une caméra NON
    masquée (donc le problème n'était pas spécifique au masquage comme supposé en
    §95) — chaque caméra a de toute façon 2 producteurs go2rtc depuis §79-82 (le
    flux RTSP brut + la source ffmpeg auto-référencée pour l'écoute audio), et
    l'hypothèse sur le comportement de bytes_recv pour un producteur ffmpeg exec
    n'était donc jamais valable, masquage ou non. Retour pur et simple au
    comportement d'avant §92 : le filet pg_cron (§91, toutes les 5 min, basé sur
    last_seen) reste la seule protection contre une coupure prolongée pendant que
    la page reste ouverte — accepté comme compromis plutôt que de retenter une
    heuristique non prouvée sans données réelles sur le comportement de go2rtc."""
    names = list(_cameras)
    active_consumers = _go2rtc_active_consumers()
    result: dict[str, bool] = {}
    lock = threading.Lock()

    def _probe(name: str):
        # ATTENTION : ne JAMAIS sonder {name}__raw directement pour une caméra masquée.
        # Tenté le 2026-08-15 (v2.9.124) pour éviter le coût de transcodage du flux
        # public (~2.8s, proche du timeout) — a réintroduit EXACTEMENT la collision
        # RTSP déjà documentée (§76/77/69, HANDOFF) : cette sonde ouvre sa PROPRE
        # connexion RTSP vers la caméra physique, qui peut entrer en collision avec la
        # connexion déjà utilisée par le pipeline de masquage de Frigate — une caméra
        # qui n'accepte qu'UNE connexion à la fois se déconnecte alors en boucle
        # ("Connection reset by peer"), confirmé en conditions réelles le 2026-08-15
        # (Hicham). Retour au flux public {name} : go2rtc réutilise la connexion RTSP
        # déjà active du pipeline de masquage plutôt que d'en ouvrir une nouvelle,
        # aucun risque de collision — seul reste le coût de transcodage, compensé par
        # un timeout plus généreux pour les caméras masquées (au lieu d'inventer un
        # raccourci qui casse la caméra qu'il est censé vérifier).
        mask_rects = _camera_masks.get(name) or []
        probe_timeout = 12.0 if mask_rects else 6.0
        online = _go2rtc_probe_online(name, timeout=probe_timeout)
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
        # >= le plus long des deux timeouts possibles dans _probe (12s pour une caméra
        # masquée) + marge — sinon un probe masqué qui aurait fini par réussir est
        # abandonné ici avant d'avoir pu écrire son résultat, et compté à tort "hors
        # ligne" par le résultat par défaut de probed.get(name, False) chez l'appelant.
        t.join(timeout=14.0)
    return result


def _run_camera_watchdog():
    """Thread de fond : sonde les caméras via go2rtc toutes les 60s et transmet chaque résultat au moteur d'alertes
    (_alerts_note_camera). Depuis le lot D (phase 1) du chantier « Pi-first », le statut des caméras n'est plus envoyé à
    Supabase (1 requête par caméra et par minute) : l'ancien filet pg_cron « check_stale_cameras », qui supposait un
    last_seen rafraîchi toutes les minutes, n'a plus d'objet. Blindé : une exception non prévue ne tue pas le thread
    (§97, journalisée, la boucle continue)."""
    time.sleep(30)  # laisser go2rtc démarrer
    while True:
        try:
            if _cameras:
                probed = _probe_cameras_go2rtc()
                if probed:
                    for name in list(_cameras):
                        _alerts_note_camera(name, probed.get(name, False))
        except Exception as e:
            warn(f"[watchdog] cycle échoué (poursuite au prochain) : {e}")
        time.sleep(60)


# ── Moteur d'alertes du Pi (lot D du chantier « Pi-first ») ─────────────────────
# Jusqu'ici les alertes (équipement/caméra hors ligne, batterie faible, pont HA figé) étaient fabriquées par
# SUPABASE (≈ 30 migrations : pi_report_*, pg_cron) puis envoyées par Vercel ; l'app du Pi, elle, les
# recalculait à chaque lecture, sans historique ni « depuis quand » réel. Le Pi devient le moteur : alertes
# PERSISTANTES (/data/alerts.json), « depuis » réel, résolution à la reprise, e-mails par le relais de la
# passerelle (POST /v1/notify, destinataire scellé par le portail). Règles REPRISES à l'identique des migrations,
# y compris les décisions d'Hicham :
#   - un équipement est hors ligne quand l'état HA de son entité principale vaut unavailable/unknown (0101) ;
#   - une alerte ouverte par (type, équipement) : jamais de doublon (0053) ;
#   - anti-flap : une coupure qui revient en < 5 min RÉ-OUVRE la même alerte, sans nouvelle notification (0103) ;
#   - e-mail IMMÉDIAT pour caméra, capteurs, sirène, clavier…, mais JAMAIS pour ampoule/interrupteur/prise
#     (light/switch/plug : push seulement, décision du 2026-09-02 — le push revient au lot F) ;
#   - batterie faible < 15 % : alerte dans l'app uniquement, jamais d'e-mail (0092) ;
#   - pont WebSocket HA déconnecté > 5 min alors que l'add-on tourne : « ws_bridge_down » (0122).
# `ha_offline` (Pi éteint) ne peut pas venir du Pi lui-même : surveillance côté portail (lot F).
_ALERTS_FILE = "/data/alerts.json"
_ALERT_FLAP_WINDOW_S = 300
_ALERT_BATTERY_LOW_PCT = 15
_ALERT_WS_BRIDGE_DOWN_S = 300
_ALERT_TUNNEL_DOWN_S = 600        # tunnel Cloudflare coupé depuis 10 min (cf. _run_cloudflared_supervisor)
_ALERT_HISTORY_MAX = 100          # alertes résolues conservées (anti-flap + historique)
_ALERT_HISTORY_KEEP_S = 7 * 86400
_ALERT_NOTIFY_GIVE_UP_S = 24 * 3600   # un e-mail « hors ligne » vieux d'un jour n'a plus de sens
_ALERT_NOTIFY_PER_TICK = 5            # étale les envois (redémarrage du Pi : N équipements d'un coup)
_ALERT_NO_EMAIL_DEVICE_TYPES = frozenset({"light", "switch", "plug"})
_ALERT_EMAIL_TYPES = frozenset({"camera_offline", "device_offline", "ws_bridge_down"})
_ALERTS_TICK_S = 30
_ALERTS_RECONCILE_S = 300
# Notifications PUSH (lot F) : envoyées par l'app du Pi (127.0.0.1:8100, route interne signée) qui détient la clé VAPID du
# site et les abonnements des appareils du foyer. Règles reprises à la lettre de l'ancienne route Vercel alerts-email
# (décisions d'Hicham du 2026-09-02) : tout ce qui part par e-mail part aussi en push ; prises/interrupteurs : push SEUL,
# tout de suite ; ampoules : push seul, après 24 h hors ligne (coupées au mur = normal) ; batterie faible : app seulement.
_PUSH_URL = "http://127.0.0.1:8100/api/internal/push/send"
_PUSH_ROUTE = "/push/send"
_ALERT_PUSH_LIGHT_DELAY_S = 24 * 3600
_ALERT_PUSH_GIVE_UP_S = 24 * 3600        # un push « hors ligne » dû depuis plus d'un jour n'a plus de sens
_ALERT_PUSH_GROUP_MIN = 4                # ≥ 4 équipements dus au même passage (redémarrage) : UN push groupé
_ALERT_PUSH_TYPES = frozenset({"camera_offline", "device_offline", "ws_bridge_down"})
_PUSH_CONTENT = {
    "camera_offline": ("⚠️ Caméra hors ligne", "votre caméra", "vérifiez son alimentation et sa connexion Wi-Fi", "/cameras"),
    "device_offline": ("⚠️ Équipement déconnecté", "votre équipement", "vérifiez sa portée et sa pile", "/devices"),
    "ws_bridge_down": ("⚠️ États des équipements figés", "votre installation",
                       "un redémarrage de l'add-on Domoticium depuis Home Assistant suffit généralement", "/"),
}

_alerts_lock = threading.RLock()
_alerts_state = {"loaded": False, "items": [], "dirty": False, "priming_since": None}
_ALERT_PRIMING_MAX_S = 600        # amorçage : au plus 10 min, même si la réconciliation n'aboutit pas
# Période de grâce à CHAQUE démarrage de l'add-on (mise à jour, redémarrage du Pi) : Z2M, Matter, HA et les caméras
# repartent et paraissent « indisponibles » quelques minutes. Les alertes ouvertes pendant ce temps sont inscrites
# tout de suite, mais leur e-mail n'est envoyé qu'une minute APRÈS la fin de la grâce, et seulement si l'incident dure
# encore (sinon « skipped », cf. _alerts_process_notifications).
_ALERTS_BOOT_AT = time.time()
_ALERT_STARTUP_GRACE_S = 300
_ALERT_STARTUP_GRACE_MARGIN_S = 60
_alerts_index: dict = {}        # entity_id principal -> {"name", "type"} (équipements classés)
_alerts_wake = threading.Event()    # réveille la boucle : nouvelle alerte à notifier / réindexation
# Dernier état connu des équipements (entité principale → en ligne ?) et des caméras, pour le résumé de flotte.
_fleet_devices: dict = {}
_fleet_cameras: dict = {}
_fleet_request = threading.Event()    # un envoi du résumé de flotte est demandé
_FLEET_MIN_INTERVAL_S = 60
_FLEET_PERIOD_S = 300
_addon_version_cache: list = []
_alerts_reindex = threading.Event()
_alerts_ws_last_alive = time.time()


def _alert_message(alert_type: str, name: str) -> str:
    return {
        "device_offline": f"Équipement « {name} » hors ligne",
        "camera_offline": f"Caméra « {name} » hors ligne",
        "battery_low": f"Batterie faible sur « {name} »",
        "ws_bridge_down": "Connexion Home Assistant instable — les états des équipements ne se mettent plus à jour",
        "tunnel_down": "Accès à distance interrompu — le boîtier n'est plus joignable depuis l'extérieur de la maison",
    }[alert_type]


def _alerts_load() -> None:
    """Charge /data/alerts.json une fois (sous verrou). Fichier absent/corrompu : on repart de zéro."""
    if _alerts_state["loaded"]:
        return
    _alerts_state["loaded"] = True
    try:
        with open(_ALERTS_FILE) as f:
            items = json.load(f).get("items", [])
        _alerts_state["items"] = [a for a in items if isinstance(a, dict) and a.get("id") and a.get("type")]
    except FileNotFoundError:
        # TOUT PREMIER démarrage du moteur sur ce site : ce qui est déjà hors ligne à cet instant n'est pas un
        # incident qui commence — il est inscrit dans l'app, mais sans e-mail (amorçage, cf. _alerts_priming_active).
        _alerts_state["items"] = []
        _alerts_state["priming_since"] = time.time()
    except Exception:
        _alerts_state["items"] = []


def _alerts_save() -> None:
    """Écriture atomique (0600) si quelque chose a changé ; élague l'historique résolu."""
    with _alerts_lock:
        if not _alerts_state["dirty"]:
            return
        now = time.time()
        opened = [a for a in _alerts_state["items"] if a.get("resolved_at") is None]
        resolved = [a for a in _alerts_state["items"] if a.get("resolved_at") is not None and now - a["resolved_at"] < _ALERT_HISTORY_KEEP_S]
        resolved.sort(key=lambda a: a["resolved_at"], reverse=True)
        _alerts_state["items"] = opened + resolved[:_ALERT_HISTORY_MAX]
        payload = json.dumps({"items": _alerts_state["items"]})
        _alerts_state["dirty"] = False
    try:
        tmp = _ALERTS_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(payload)
        os.replace(tmp, _ALERTS_FILE)
    except Exception as e:
        warn(f"[alerts] écriture impossible : {e}")
        with _alerts_lock:
            _alerts_state["dirty"] = True


def _alert_initial_push(alert_type: str, device_type: str | None, now: float, silent: bool = False) -> dict:
    """État initial du PUSH d'une alerte (indépendant de l'e-mail). `due_at` : instant où il devient dû, conservé pour
    la règle d'abandon ; les ampoules attendent 24 h."""
    wants = alert_type in _ALERT_PUSH_TYPES and not silent
    due = now
    if now < _ALERTS_BOOT_AT + _ALERT_STARTUP_GRACE_S:
        due = _ALERTS_BOOT_AT + _ALERT_STARTUP_GRACE_S + _ALERT_STARTUP_GRACE_MARGIN_S
    if alert_type == "device_offline" and device_type == "light":
        due = max(due, now + _ALERT_PUSH_LIGHT_DELAY_S)
    return {"state": "pending" if wants else "none", "attempts": 0, "next_at": due, "due_at": due}


def _alerts_priming_active(now: float) -> bool:
    """Vrai pendant l'amorçage du tout premier démarrage (fichier d'alertes absent) : de la création du moteur
    jusqu'à la fin de sa première réconciliation complète, 10 min au plus. Sous verrou."""
    since = _alerts_state.get("priming_since")
    if since is None:
        return False
    if now - since > _ALERT_PRIMING_MAX_S:
        _alerts_state["priming_since"] = None
        return False
    return True


def _alert_initial_notify(alert_type: str, device_type: str | None, now: float, silent: bool = False) -> dict:
    wants_email = alert_type in _ALERT_EMAIL_TYPES and not (alert_type == "device_offline" and device_type in _ALERT_NO_EMAIL_DEVICE_TYPES)
    next_at = now
    if now < _ALERTS_BOOT_AT + _ALERT_STARTUP_GRACE_S:
        next_at = _ALERTS_BOOT_AT + _ALERT_STARTUP_GRACE_S + _ALERT_STARTUP_GRACE_MARGIN_S
    return {"state": "pending" if wants_email and not silent else "none", "attempts": 0, "next_at": next_at}


def _alert_set_condition(alert_type: str, key: str, name: str, active: bool, now: float, device_type: str | None = None) -> bool:
    """Ouvre / ré-ouvre / résout l'alerte (type, clé). True si quelque chose a changé (à diffuser et sauvegarder)."""
    with _alerts_lock:
        _alerts_load()
        items = _alerts_state["items"]
        opened = next((a for a in items if a["type"] == alert_type and a.get("key") == key and a.get("resolved_at") is None), None)
        if not active:
            if opened is None:
                return False
            opened["resolved_at"] = now
            _alerts_state["dirty"] = True
            return True
        if opened is not None:
            message = _alert_message(alert_type, name)
            if opened.get("name") != name or opened.get("message") != message:  # équipement renommé
                opened["name"], opened["message"] = name, message
                _alerts_state["dirty"] = True
                return True
            return False
        recent = [a for a in items if a["type"] == alert_type and a.get("key") == key and a.get("resolved_at") is not None
                  and now - a["resolved_at"] < _ALERT_FLAP_WINDOW_S]
        if recent:
            # Anti-flap (0103) : MÊME alerte ré-ouverte — pas de nouvelle ligne, donc pas de nouvelle notification ;
            # created_at inchangé (« depuis » = début réel de la coupure).
            alert = max(recent, key=lambda a: a["resolved_at"])
            alert["resolved_at"] = None
            alert["name"], alert["message"] = name, _alert_message(alert_type, name)
        else:
            items.append({
                "id": secrets.token_hex(6), "type": alert_type, "key": key, "name": name, "device_type": device_type,
                "message": _alert_message(alert_type, name), "created_at": now, "resolved_at": None,
                "notify": _alert_initial_notify(alert_type, device_type, now, silent=_alerts_priming_active(now)),
                "push": _alert_initial_push(alert_type, device_type, now, silent=_alerts_priming_active(now)),
            })
            _alerts_wake.set()
        _alerts_state["dirty"] = True
        return True


def _alert_send_email(alert: dict) -> int:
    """Envoie l'e-mail d'une alerte par le relais de la passerelle ; code HTTP (0 = injoignable). La clé = id de
    l'alerte : un nouvel essai après une coupure ne fait pas partir deux e-mails (idempotence côté Resend)."""
    status, _ = _gateway_request("POST", "/v1/notify", body={
        "type": alert["type"],
        "name": alert.get("name") if alert["type"] != "ws_bridge_down" else None,
        "since": datetime.fromtimestamp(alert["created_at"], timezone.utc).isoformat(),
        "key": alert["id"],
    }, timeout=15)
    return status


def _alerts_process_notifications(now: float, send=None) -> int:
    """Envoie les e-mails dus (au plus _ALERT_NOTIFY_PER_TICK par passage). Retourne le nombre d'envois tentés."""
    send = send or _alert_send_email
    with _alerts_lock:
        _alerts_load()
        due = [a for a in _alerts_state["items"] if a.get("notify", {}).get("state") == "pending" and a["notify"]["next_at"] <= now]
        due.sort(key=lambda a: a["created_at"])
        to_send = []
        for a in due:
            if a.get("resolved_at") is not None:
                a["notify"]["state"] = "skipped"        # incident terminé avant l'envoi : un mail tardif serait trompeur
                _alerts_state["dirty"] = True
            elif now - a["created_at"] > _ALERT_NOTIFY_GIVE_UP_S:
                a["notify"]["state"] = "given_up"
                _alerts_state["dirty"] = True
            elif len(to_send) < _ALERT_NOTIFY_PER_TICK:
                to_send.append(a)
        snapshots = [dict(a) for a in to_send]
    for snap in snapshots:
        status = send(snap)       # hors verrou : réseau
        with _alerts_lock:
            a = next((x for x in _alerts_state["items"] if x["id"] == snap["id"]), None)
            if a is None:
                continue
            n = a["notify"]
            n["attempts"] += 1
            if 200 <= status < 300:
                n["state"], n["sent_at"] = "sent", now
            elif status in (400, 413):
                n["state"] = "given_up"                  # notre requête est refusée : réessayer ne servirait à rien
                warn(f"[alerts] e-mail refusé par la passerelle (HTTP {status}) pour {a['type']}")
            elif status == 402:
                n["state"] = "given_up"                  # abonnement suspendu : service cloud coupé, rien à retenter
            elif status == 409:
                n["next_at"] = now + 6 * 3600            # pas encore d'adresse dans le laissez-passer (renouvelé tout seul)
            elif status == 429:
                n["next_at"] = now + 3600                # limite de la passerelle
            else:                                        # injoignable / 5xx : retrait exponentiel plafonné à 1 h
                n["next_at"] = now + min(300 * 2 ** (n["attempts"] - 1), 3600)
            _alerts_state["dirty"] = True
    return len(snapshots)


def _push_auth_header(body: str) -> str:
    """Même jeton que celui que l'app du Pi présente à l'add-on, dans le sens inverse :
    `<ts>.<hmac>` sur `<ts>:POST:<route>:<sha256(corps)>` avec le secret du site."""
    ts = int(time.time())
    message = f"{ts}:POST:{_PUSH_ROUTE}:{hashlib.sha256(body.encode('utf-8')).hexdigest()}"
    return f"{ts}." + hmac.new(INGEST_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()


def _push_send(title: str, body: str, url: str = "/dashboard", tag: str | None = None, urgent: bool = False) -> tuple[int, int]:
    """Demande à l'app du Pi d'envoyer une notification push à TOUS les appareils abonnés. Retourne (code HTTP, échecs) :
    (0, 0) = app injoignable ; (200, n) avec n > 0 = n envois ont échoué côté service de push (à retenter). Un foyer sans
    appareil abonné répond (200, 0) : rien à retenter."""
    if not INGEST_SECRET:
        return 0, 0
    # `n` : aléa propre à CETTE requête — deux push identiques dans la même seconde ne doivent pas avoir la même signature
    # (l'app du Pi refuse toute signature déjà vue, anti-rejeu).
    payload = {"title": title, "body": body, "url": url, "n": secrets.token_hex(6)}
    if tag:
        payload["tag"] = tag
    if urgent:
        payload["urgent"] = True
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    try:
        r = requests.post(_PUSH_URL, data=raw.encode("utf-8"), timeout=20,
                          headers={"Content-Type": "application/json", "X-Site-Secret": _push_auth_header(raw)})
        failed = 0
        if r.status_code == 200:
            try:
                failed = int((r.json() or {}).get("failed", 0))
            except Exception:
                failed = 0
        return r.status_code, failed
    except Exception as e:
        warn(f"[push] app du Pi injoignable : {e}")
        return 0, 0


def _alert_push_text(alert: dict) -> tuple[str, str, str, str]:
    title, fallback, hint, url = _PUSH_CONTENT[alert["type"]]
    name = alert.get("name") if alert["type"] != "ws_bridge_down" else None
    return title, f"{name or fallback} — {hint}.", url, f"domoticium-alert-{alert['id']}"


def _alerts_process_push(now: float, send=None) -> int:
    """Envoie les push dus. ≥ _ALERT_PUSH_GROUP_MIN équipements dus au même passage (redémarrage, coupure de courant) :
    UN seul push groupé plutôt qu'une salve. Retourne le nombre de requêtes d'envoi tentées."""
    send = send or _push_send
    with _alerts_lock:
        _alerts_load()
        due = []
        for a in _alerts_state["items"]:
            p = a.get("push")
            if not p or p.get("state") != "pending" or p["next_at"] > now:
                continue
            if a.get("resolved_at") is not None:
                p["state"] = "skipped"             # incident terminé avant l'envoi : un push tardif serait trompeur
                _alerts_state["dirty"] = True
            elif now - p.get("due_at", p["next_at"]) > _ALERT_PUSH_GIVE_UP_S:
                p["state"] = "given_up"
                _alerts_state["dirty"] = True
            else:
                due.append(a)
        due.sort(key=lambda a: a["created_at"])
        devices = [a for a in due if a["type"] == "device_offline"]
        group = devices if len(devices) >= _ALERT_PUSH_GROUP_MIN else []
        singles = [a for a in due if a not in group][:_ALERT_NOTIFY_PER_TICK]
        jobs = []
        if group:
            names = [a.get("name") or "équipement" for a in group]
            shown = ", ".join(names[:3]) + (f" et {len(names) - 3} autre(s)" if len(names) > 3 else "")
            jobs.append(([a["id"] for a in group], ("⚠️ Équipements déconnectés", f"{len(names)} équipements ne répondent plus : {shown}.", "/devices", "domoticium-offline-group")))
        for a in singles:
            jobs.append(([a["id"]], _alert_push_text(a)))
    for ids, (title, body, url, tag) in jobs:
        status, failed = send(title, body, url, tag)       # hors verrou : réseau local
        with _alerts_lock:
            for a in _alerts_state["items"]:
                if a["id"] not in ids:
                    continue
                p = a["push"]
                p["attempts"] += 1
                if status == 200 and failed == 0:
                    p["state"], p["sent_at"] = "sent", now
                elif status in (400, 413):
                    p["state"] = "given_up"
                    warn(f"[alerts] push refusé par l'app du Pi (HTTP {status}) pour {a['type']}")
                else:
                    p["next_at"] = now + min(60 * 2 ** (p["attempts"] - 1), 1800)    # app en redémarrage : 1, 2, 4… 30 min
                _alerts_state["dirty"] = True
    return len(jobs)


_alarm_push_state: dict = {}


def _alarm_push_deliver(send=None, sleep=None) -> bool:
    """Envoie le push d'alarme, avec reprises (l'app du Pi peut être en redémarrage) : 0, 3, 10, 30 s puis abandon."""
    send = send or _push_send
    sleep = sleep or time.sleep
    for delay in (0, 3, 10, 30):
        if delay:
            sleep(delay)
        status, failed = send("🚨 Alarme déclenchée", "L'alarme de votre logement vient de se déclencher.", "/alarm", "domoticium-alarm", True)
        if status == 200 and failed == 0:
            return True
        if status in (400, 413):
            break
    warn("[alarm-push] push d'alarme non délivré")
    return False


def _alarm_push_on_state(entity_id: str, state: str, deliver=None) -> bool:
    """Alarme : UN push « déclenchée » à chaque passage RÉEL à l'état `triggered` (jamais à l'armement/désarmement ni
    quand un attribut change pendant que l'alarme reste déclenchée). Livraison en fil de fond. True si lancé."""
    previous = _alarm_push_state.get(entity_id)
    _alarm_push_state[entity_id] = state
    if state != "triggered" or previous == "triggered":
        return False
    if deliver is None:
        threading.Thread(target=_alarm_push_deliver, daemon=True).start()
    else:
        deliver()
    return True


def _alerts_eval_device(entity_id: str, state: str, attributes: dict, now: float) -> bool:
    """Évalue UN équipement (entité principale) : hors ligne (0101) et batterie faible (0092)."""
    info = _alerts_index.get(entity_id)
    if not info:
        return False
    offline = state in ("unavailable", "unknown")
    _fleet_devices[entity_id] = not offline
    changed = _alert_set_condition("device_offline", entity_id, info["name"], offline, now, info["type"])
    if attributes.get("device_class") == "battery" and entity_id.startswith("sensor."):
        try:
            level = _ha_entity_to_normalized_patch(entity_id, state, attributes).get("battery")
        except Exception:
            level = None
        if isinstance(level, (int, float)):
            changed |= _alert_set_condition("battery_low", entity_id, info["name"], level < _ALERT_BATTERY_LOW_PCT, now, info["type"])
    return changed


def _alerts_note_state(entity_id: str, state: str, attributes: dict) -> None:
    """Appelé par le pont WebSocket pour chaque state_changed — un simple accès dict tant que l'entité n'est pas
    celle d'un équipement."""
    if entity_id not in _alerts_index:
        return
    if _alerts_eval_device(entity_id, state, attributes, time.time()):
        _alerts_changed()


def _alerts_note_camera(name: str, online: bool) -> None:
    """Appelé par la sonde caméra (toutes les 60 s)."""
    if name not in _cameras:
        return
    _fleet_cameras[name] = bool(online)
    if _alert_set_condition("camera_offline", name, name, not online, time.time()):
        _alerts_changed()


def _alerts_changed() -> None:
    _alerts_save()
    _alerts_wake.set()
    _fleet_request.set()       # la vue staff est prévenue dans la minute
    try:
        _sse_publish("fast")       # l'app relit ses alertes tout de suite
    except Exception:
        pass


def _alerts_reconcile(now: float) -> None:
    """Filet périodique : reconstruit l'index des équipements (renommage, ajout, suppression) puis évalue TOUS
    les équipements sur l'état HA réel — rattrape un state_changed manqué (redémarrage de l'add-on, HA relancé)."""
    devices = _build_local_devices()
    r = ha_get("/states")
    if not r.ok:
        warn(f"[alerts] /states {r.status_code}")
        return
    states = {s["entity_id"]: s for s in r.json() if isinstance(s, dict) and s.get("entity_id")}
    global _alerts_index
    index = {d["haEntityId"]: {"name": d["name"], "type": d["type"]} for d in devices if d.get("haEntityId")}
    for gone in [k for k in _fleet_devices if k not in index]:
        _fleet_devices.pop(gone, None)
    _alerts_index = index       # remplacement atomique : le pont HA lit cet index en continu (jamais d'index vide, même brièvement)
    changed = False
    for entity_id in index:
        s = states.get(entity_id)
        if s is not None:
            changed |= _alerts_eval_device(entity_id, s.get("state", ""), s.get("attributes") or {}, now)
    # Équipements / caméras supprimés : plus d'alerte à garder (0064).
    with _alerts_lock:
        _alerts_load()
        if _alerts_state.get("priming_since") is not None and index:
            # Première réconciliation complète terminée : fin de l'amorçage, le fichier d'alertes existe désormais.
            _alerts_state["priming_since"] = None
            _alerts_state["dirty"] = True
            changed = True
        for a in _alerts_state["items"]:
            if a.get("resolved_at") is not None:
                continue
            # `index` vide = registre HA pas encore prêt (démarrage) : on ne conclut JAMAIS « tout a disparu ».
            gone = (a["type"] in ("device_offline", "battery_low") and bool(index) and a.get("key") not in index) or \
                   (a["type"] == "camera_offline" and a.get("key") not in _cameras)
            if gone:
                a["resolved_at"] = now
                _alerts_state["dirty"] = True
                changed = True
    if changed:
        _alerts_changed()


def _alerts_check_ws_bridge(now: float) -> bool:
    """« ws_bridge_down » : le pont WebSocket HA (seul canal d'état événementiel) est déconnecté depuis plus de 5 min
    alors que l'add-on, lui, tourne (0122). Résolu dès la reconnexion."""
    global _alerts_ws_last_alive
    if _ws_bridge_connected:
        _alerts_ws_last_alive = now
        return _alert_set_condition("ws_bridge_down", "site", "", False, now)
    if now - _alerts_ws_last_alive > _ALERT_WS_BRIDGE_DOWN_S:
        return _alert_set_condition("ws_bridge_down", "site", "", True, now)
    return False


def _alerts_check_tunnel(now: float) -> bool:
    """« tunnel_down » : le tunnel Cloudflare est coupé depuis plus de 10 min (hors cas « pas de tunnel configuré »).
    App + vue staff seulement : ni e-mail ni push, le client ne peut rien y faire. Résolu dès la reconnexion."""
    if not CLOUDFLARE_TUNNEL_TOKEN:
        return False
    st = _tunnel_state
    down = st["ready"] is False and st["not_ready_since"] is not None and now - st["not_ready_since"] > _ALERT_TUNNEL_DOWN_S
    if st["ready"] is True:
        return _alert_set_condition("tunnel_down", "site", "", False, now)
    return _alert_set_condition("tunnel_down", "site", "", True, now) if down else False


def _addon_version() -> str | None:
    """Version de l'add-on (API Supervisor), lue une fois."""
    if not _addon_version_cache:
        try:
            r = sup_get("/addons/self/info")
            _addon_version_cache.append(((r.json().get("data") or {}).get("version")) if r.ok else None)
        except Exception:
            _addon_version_cache.append(None)
    return _addon_version_cache[0]


def _fleet_status_payload() -> dict:
    """Résumé de flotte : santé + présence des équipements/caméras + alertes ouvertes (cf. migration 0154)."""
    with _alerts_lock:
        _alerts_load()
        alerts = [
            {"type": a["type"], "key": a.get("key"), "message": a["message"], "since": int(a["created_at"])}
            for a in _alerts_state["items"] if a.get("resolved_at") is None
        ]
    return {
        "v": _addon_version(), "ha": True, "z2m": _z2m_online, "ws": bool(_ws_bridge_connected),
        "tun": (_tunnel_state["ready"] if CLOUDFLARE_TUNNEL_TOKEN else None),
        "devices": dict(_fleet_devices),
        "cameras": {n: o for n, o in _fleet_cameras.items() if n in _cameras},
        "alerts": alerts,
    }


def _fleet_status_direct() -> bool:
    """pi_report_fleet_status via Supabase direct — True si réussi. Le corps part en TEXTE et la signature porte sur son
    SHA-256 : la base hache exactement les mêmes octets (UTF-8)."""
    if not INGEST_SECRET:
        return False
    try:
        body = json.dumps(_fleet_status_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        ts = int(time.time())
        message = f"{SITE_PREFIX}:{ts}:fleet_status:{hashlib.sha256(body.encode('utf-8')).hexdigest()}"
        r = _supabase_rpc("pi_report_fleet_status", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message), "p_status": body,
        })
        if r.status_code >= 300:
            warn(f"[supabase] pi_report_fleet_status {r.status_code}: {r.text[:120]}")
            return False
        return True
    except Exception as e:
        warn(f"[supabase] pi_report_fleet_status: {e}")
        return False


# ── Assistants vocaux (Alexa / Google Home) — lot F ────────────────────────────────────────────────────────────
# Avant : les appels vocaux étaient traités par le cloud à partir des TABLES Supabase (équipements, scènes, drapeau
# `voice_exposed`, état recopié). Depuis le chantier « Pi-first », ces tables ne sont plus alimentées : le boîtier est la
# source de vérité. Le cloud (obligatoire : Amazon et Google appellent une URL publique, et le lien de compte OAuth y
# vit) ne garde que le travail de traduction ; il demande au boîtier, par le tunnel, un INSTANTANÉ des seuls éléments que
# le client a choisi d'exposer (POST /voice/snapshot) et lui fait exécuter les commandes (/cmd, déjà en liste blanche).
#  - le choix « quoi exposer » est un réglage du foyer : /data/voice-exposure.json, modifié depuis l'app du Pi ;
#  - un changement de ce choix prévient le cloud (ingest/voice-changed) pour qu'Alexa / Google redécouvrent tout seuls.
_VOICE_FILE = "/data/voice-exposure.json"
_VOICE_TYPES = frozenset({"light", "switch", "plug", "cover", "valve", "lock", "thermostat", "fan", "humidifier"})
_VOICE_MAX_ITEMS = 300
_VOICE_ID_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_VOICE_SNAPSHOT_TTL_S = 5
_voice_lock = threading.Lock()
_voice_cache = {"at": 0.0, "data": None}
_voice_notify_timer = {"t": None}


def _voice_clean_ids(raw) -> list:
    out, seen = [], set()
    for x in (raw if isinstance(raw, list) else []):
        if isinstance(x, str) and _VOICE_ID_RE.match(x) and x not in seen:
            seen.add(x)
            out.append(x)
        if len(out) >= _VOICE_MAX_ITEMS:
            break
    return out


def _voice_load() -> dict:
    try:
        with open(_VOICE_FILE) as f:
            d = json.load(f)
        return {"devices": _voice_clean_ids(d.get("devices")), "scenes": _voice_clean_ids(d.get("scenes"))}
    except Exception:
        return {"devices": [], "scenes": []}


def _voice_save(d: dict) -> None:
    tmp = _VOICE_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(d))
    os.replace(tmp, _VOICE_FILE)


def _voice_notify_cloud() -> None:
    """Prévient le cloud que l'exposition a changé (il relance la découverte Alexa / la synchro Google). Regroupé :
    plusieurs bascules rapprochées ne font qu'UN appel, 5 s après la dernière."""
    if not INGEST_SECRET:
        return

    def _send():
        try:
            _cloud_post("vercel:ingest/voice-changed", f"{APP_URL}/api/ingest/voice-changed",
                        json={"siteSecret": INGEST_SECRET, "siteId": SITE_PREFIX}, timeout=10)
        except Exception as e:
            warn(f"[voice] notification du cloud impossible : {e}")

    with _voice_lock:
        if _voice_notify_timer["t"] is not None:
            _voice_notify_timer["t"].cancel()
        t = threading.Timer(5.0, _send)
        t.daemon = True
        _voice_notify_timer["t"] = t
        t.start()


def _voice_area_names() -> dict:
    r = _ha_ws_call("config/area_registry/list")
    areas = r.get("result", []) if r and r.get("success") else []
    return {a.get("area_id"): a.get("name") for a in areas}


def _voice_scene_candidates() -> list:
    """Scènes HA (id d'entité + nom) — lecture légère de /states, sans interroger la config de chaque scène."""
    try:
        r = ha_get("/states")
        if not r.ok:
            return []
        return [{"id": s["entity_id"], "name": (s.get("attributes") or {}).get("friendly_name") or s["entity_id"]}
                for s in r.json() if isinstance(s, dict) and str(s.get("entity_id", "")).startswith("scene.")]
    except Exception as e:
        warn(f"[voice] lecture des scènes : {e}")
        return []


def handle_voice_exposure_get() -> dict:
    """Réglage + candidats (pour l'écran « Assistants vocaux » de l'app du Pi)."""
    exposure = _voice_load()
    names = _voice_area_names()
    devices = [{"id": d["id"], "name": d["name"], "type": d["type"], "room": names.get(d.get("areaId"))}
               for d in _build_local_devices() if d.get("type") in _VOICE_TYPES and d.get("id")]
    return {"exposed": exposure, "candidates": {"devices": devices, "scenes": _voice_scene_candidates()}}


def handle_voice_exposure_set(data: dict) -> dict:
    """Enregistre le choix (identifiants invalides ignorés) et prévient le cloud si quelque chose a changé."""
    new = {"devices": _voice_clean_ids(data.get("devices")), "scenes": _voice_clean_ids(data.get("scenes"))}
    with _voice_lock:
        old = _voice_load()
        if new == old:
            return {"ok": True, "changed": False, "exposed": new}
        _voice_save(new)
        _voice_cache["data"] = None
    _voice_notify_cloud()
    return {"ok": True, "changed": True, "exposed": new}


def handle_voice_snapshot(now=None) -> dict:
    """Instantané demandé par le cloud : UNIQUEMENT les équipements et scènes exposés, sous la forme neutre que le cloud
    traduit en Alexa / Google (type, capacités, état normalisé, en ligne, pièce). Court cache (5 s) : Alexa et Google
    envoient des rafales de QUERY."""
    now = time.time() if now is None else now
    cached = _voice_cache["data"]
    if cached is not None and now - _voice_cache["at"] < _VOICE_SNAPSHOT_TTL_S:
        return cached
    exposure = _voice_load()
    wanted = set(exposure["devices"])
    out_devices = []
    if wanted:
        names = _voice_area_names()
        for d in _build_local_devices():
            if d.get("id") in wanted and d.get("type") in _VOICE_TYPES:
                out_devices.append({
                    "id": d["id"], "name": d["name"], "type": d["type"], "room": names.get(d.get("areaId")),
                    "online": bool(d.get("online")), "capabilities": d.get("capabilities") or {}, "state": d.get("state") or {},
                })
    scenes = [s for s in _voice_scene_candidates() if s["id"] in set(exposure["scenes"])] if exposure["scenes"] else []
    data = {"devices": out_devices, "scenes": scenes}
    _voice_cache["at"], _voice_cache["data"] = now, data
    return data


def handle_local_alerts() -> dict:
    """GET /local/alerts : alertes OUVERTES, la plus récente d'abord — lues par l'app du Pi."""
    with _alerts_lock:
        _alerts_load()
        opened = [a for a in _alerts_state["items"] if a.get("resolved_at") is None]
    opened.sort(key=lambda a: a["created_at"], reverse=True)
    return {"alerts": [{
        "id": a["id"], "type": a["type"], "message": a["message"], "resolved": False,
        "createdAt": datetime.fromtimestamp(a["created_at"], timezone.utc).isoformat(),
    } for a in opened]}


def _run_alerts_engine():
    """Thread permanent : toutes les 30 s pont HA + e-mails dus ; toutes les 5 min (ou sur demande) réconciliation
    complète des équipements. Les transitions en temps réel arrivent par _alerts_note_state/_alerts_note_camera."""
    time.sleep(20)     # laisser HA, go2rtc et le pont démarrer
    last_reconcile = 0.0
    while True:
        try:
            now = time.time()
            if now - last_reconcile >= _ALERTS_RECONCILE_S or _alerts_reindex.is_set():
                _alerts_reindex.clear()
                try:
                    _alerts_reconcile(now)
                    last_reconcile = now
                except Exception as e:
                    warn(f"[alerts] réconciliation échouée (nouvel essai au prochain passage) : {e}")
                    last_reconcile = now - _ALERTS_RECONCILE_S + 60
            if _alerts_check_ws_bridge(now):
                _alerts_changed()
            if _alerts_check_tunnel(now):
                _alerts_changed()
            _alerts_process_notifications(now)
            _alerts_process_push(now)
            _alerts_save()
        except Exception as e:
            warn(f"[alerts] cycle échoué (poursuite au prochain) : {e}")
        _alerts_wake.wait(timeout=_ALERTS_TICK_S)
        _alerts_wake.clear()


def _reconcile_alarm_state():
    """Sécurité add-on, point 12 (audit 2026-09-22, resté ouvert jusqu'ici) : l'état
    alarme (armé/désarmé) ne remonte QUE via le bridge événementiel (state_changed
    sur alarm_control_panel.*, cf. run_ha_ws_bridge). Si l'add-on redémarre pile
    pendant un changement d'état, ou si HA était déjà dans un état donné avant que
    le bridge WebSocket ne se (re)connecte, aucun state_changed n'est émis pour le
    rattraper — même raisonnement déjà établi pour les devices (_reconcile_device_states,
    0104/0105/0111) : HA ne republie jamais le même état en boucle une fois émis.

    Comparé à _reconcile_device_states, on ne peut pas simplement repousser l'état
    HA à chaque cycle sans condition : pi_report_alarm_state (0116) insère une ligne
    alarm_events ET déclenche la notification push "alarme déclenchée" quand
    state='triggered' — un push inconditionnel toutes les 60s dupliquerait
    l'historique et réenverrait cette alerte en boucle. On ne corrige donc QUE s'il
    y a un vrai écart avec ce que l'app a stocké (pi_get_alarm_state, lecture
    seule) — jamais un resync aveugle."""
    area_id, _ = _alarmo_get_sole_area()
    if not area_id:
        return
    entity_id = _alarmo_panel_entity_id(area_id)
    if not entity_id:
        return
    r = ha_get(f"/states/{entity_id}")
    if not r.ok:
        return
    try:
        payload = r.json()
    except Exception:
        return
    real_state = payload.get("state")
    if not real_state or real_state in ("unavailable", "unknown"):
        return

    try:
        ts = int(time.time())
        message = f"{SITE_PREFIX}:{ts}:get_alarm_state"
        resp = _supabase_rpc("pi_get_alarm_state", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
        })
        rows = resp.json() if resp.ok else []
        stored_state = rows[0].get("alarm_state") if rows else None
    except Exception as e:
        warn(f"[reconcile] pi_get_alarm_state échoué : {e}")
        return

    if stored_state == real_state:
        return
    if _report_alarm_state_direct(entity_id, real_state, payload.get("attributes") or {}):
        log(f"[reconcile] alarme resynchronisée : {stored_state!r} → {real_state!r} (filet périodique)")


# Dernière IP locale réellement signalée — évite un appel RPC à chaque cycle
# de sync (5 min) quand rien n'a changé (cas normal, l'IP ne bouge presque
# jamais une fois le bail DHCP établi). Pas besoin de persister across un
# redémarrage de l'add-on : un rapport en plus après un redémarrage est sans
# conséquence (idempotent côté SQL), juste évité ici pour le bruit des logs.
_last_reported_local_ip: str | None = None


def _report_local_ip():
    """Signale l'IP locale (LAN) actuelle du boîtier à Supabase — chantier
    pastille de statut 3 couleurs (2026-10-31) : le web a besoin de savoir à
    quelle adresse joindre le boîtier en direct sur le réseau local (le nom
    `pi-{slug}.local` en mDNS ne peut jamais avoir de certificat HTTPS valide
    — remplacé par un vrai enregistrement DNS A `local-{mqtt_prefix}.
    domoticium.fr` — même zone que les tunnels, zone déléguée séparée
    abandonnée le 2026-10-31, cf. tunnel.ts — qui doit suivre l'IP réelle du
    boîtier, pouvant changer au gré du bail DHCP). Volontairement HORS de la boucle heartbeat (60s,
    trop fréquent pour une valeur qui ne bouge presque jamais) — même cadence
    que le reste de la réconciliation périodique (_run_ha_maintenance_cycle, 5 min).
    Best-effort : un échec ici ne doit jamais interrompre le reste du cycle
    de sync (cohérent avec tous les autres appels de cette fonction)."""
    global _last_reported_local_ip
    ip = _local_ipv4()
    if not ip or ip == _last_reported_local_ip:
        return
    try:
        ts = int(time.time())
        message = f"{SITE_PREFIX}:{ts}:local_ip:{ip}"
        r = _supabase_rpc("pi_report_local_ip", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
            "p_local_ip": ip,
        })
        if r.status_code >= 300:
            warn(f"[supabase] pi_report_local_ip {r.status_code}: {r.text[:120]}")
            return
        _last_reported_local_ip = ip
        log(f"[sync] ✓ IP locale signalée : {ip}")
    except Exception as e:
        warn(f"[supabase] pi_report_local_ip: {e}")


# Dernière valeur expires_at vraiment appliquée — comme _last_reported_local_ip,
# évite de réécrire les fichiers /data/ et de recréer le contexte TLS à chaque
# cycle de sync (5 min) quand le certificat n'a pas changé (cas normal, un
# renouvellement n'arrive qu'environ tous les 60 jours).
_last_local_cert_expires_at: str | None = None
_local_tls_context: "ssl.SSLContext | None" = None

_LOCAL_CERT_FILE = "/data/local_cert.pem"
_LOCAL_KEY_FILE = "/data/local_key.pem"


def _fetch_local_cert():
    """Récupère le certificat HTTPS local du site (émis côté cloud — DNS-01 via
    acme-client/Vercel cron, jamais sur le Pi, cf. web/src/lib/acme/issueCert.ts)
    et recharge le contexte TLS du relais local (run_local_tls_relay) si la
    valeur a changé (1ère émission ou renouvellement). Lecture seule, même
    cadence que _report_local_ip (5 min, cf. _run_ha_maintenance_cycle) — un cycle en
    plus après un renouvellement (tous les ~60 jours) est sans conséquence."""
    global _last_local_cert_expires_at, _local_tls_context
    if not INGEST_SECRET:
        return
    try:
        ts = int(time.time())
        message = f"{SITE_PREFIX}:{ts}:get_local_cert"
        r = _supabase_rpc("pi_get_local_cert", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
        })
        if not r.ok:
            warn(f"[local-tls] pi_get_local_cert {r.status_code}: {r.text[:120]}")
            return
        rows = r.json()
        if not rows:
            return  # pas encore émis côté cloud (nouveau site, cron pas encore passé)
        row = rows[0]
        expires_at = row.get("expires_at")
        if not expires_at or expires_at == _last_local_cert_expires_at:
            return
        with open(_LOCAL_CERT_FILE, "w") as f:
            f.write(row["cert_pem"])
        with open(_LOCAL_KEY_FILE, "w") as f:
            f.write(row["key_pem"])
        os.chmod(_LOCAL_KEY_FILE, 0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(_LOCAL_CERT_FILE, _LOCAL_KEY_FILE)
        _local_tls_context = context
        _last_local_cert_expires_at = expires_at
        log(f"[local-tls] ✓ Certificat local chargé (expire {expires_at})")
    except Exception as e:
        warn(f"[local-tls] {e}")


def _report_alarm_state_direct(entity_id: str, state: str, attributes: dict) -> bool:
    """pi_report_alarm_state via Supabase direct — True si réussi. alarm_control_panel
    n'est pas un "device" au sens de notre schéma (pas de room_id/ieee_address…) —
    table dédiée sites.alarm_* plutôt que le pipeline générique pi_report_device_state
    (qui ne trouverait aucune ligne correspondante dans `devices`).

    open_sensors : dict {entity_id: sensor_state} côté Alarmo (vérifié dans
    sensors.py::async_arm — "open_sensors[entity] = sensor_state"), pas une liste —
    on prend la première clé comme capteur déclencheur."""
    try:
        mode = attributes.get("arm_mode")
        open_sensors = attributes.get("open_sensors") or {}
        triggered_by = next(iter(open_sensors.keys()), None) if isinstance(open_sensors, dict) else None
        ts = int(time.time())
        message = f"{SITE_PREFIX}:{ts}:alarm_state:{state}"
        r = _supabase_rpc("pi_report_alarm_state", {
            "p_mqtt_prefix": SITE_PREFIX, "p_timestamp": ts, "p_signature": _pi_sign(message),
            "p_state": state, "p_mode": mode, "p_triggered_by": triggered_by,
        })
        if r.status_code >= 300:
            warn(f"[supabase] pi_report_alarm_state({entity_id}) {r.status_code}: {r.text[:120]}")
            return False
        return True
    except Exception as e:
        warn(f"[supabase] pi_report_alarm_state({entity_id}): {e}")
        return False


def _flush_alarm_state_batch():
    """Thread de fond (cycle 2,5 s) : retente les transitions d'alarme qui n'ont pas pu partir (réseau, Supabase). Seul reste de
    l'ancien _flush_state_batch, qui groupait aussi états d'équipements (HA + Zigbee brut) et statuts de caméras — retirés au
    lot D (phase 1). Une transition non envoyée est réintégrée pour être retentée — jamais perdue silencieusement ; après un
    refus Supabase, pause croissante (cf. _supabase_rpc). Blindé : une exception non prévue ne tue pas le thread."""
    while True:
        time.sleep(2.5)
        try:
            if not INGEST_SECRET or _supabase_is_backing_off():
                continue
            with _state_batch_lock:
                alarm_batch = dict(_alarm_state_batch)
                _alarm_state_batch.clear()
            if not alarm_batch:
                continue
            failed = {
                eid: (st, attrs) for eid, (st, attrs) in alarm_batch.items()
                if not _report_alarm_state_direct(eid, st, attrs)
            }
            if failed:
                with _state_batch_lock:
                    for eid, v in failed.items():
                        _alarm_state_batch.setdefault(eid, v)
        except Exception as e:
            warn(f"[flush-alarm] cycle échoué (poursuite au prochain) : {e}")


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


def _entity_id_by_unique_id(unique_id: str, domain: str = "scene") -> str | None:
    """Résout l'entity_id RÉEL d'une entité HA à partir de son unique_id (= notre
    object_id de config, stocké tel quel par HA dans l'entity registry) — nécessaire
    pour scene.* dont l'entity_id réel est dérivé du NOM (slugifié) au moment de la
    première sauvegarde, jamais de l'id de config qu'on choisit (contrairement à
    script.*/automation.*... qui ont en réalité le MÊME problème, cf. le commentaire
    historique de automationEntityId côté web/lib/automationBuilder.ts — seules les
    scènes avaient jusqu'ici un calcul qui prétendait le contraire). Confirmé en
    conditions réelles (2026-10-18) : une scène nommée "allumage lumieres", créée
    avec l'id de config "domoticium_scene_<uuid>", a pour entity_id réel
    scene.allumage_lumieres — PAS scene.domoticium_scene_<uuid>.

    `domain` (défaut "scene") est OBLIGATOIRE en pratique, pas cosmétique : une
    scène migrée depuis l'ancien mécanisme (script_upsert, avant le 2026-10-18)
    garde le même object_id de config que son ancien script.domoticium_scene_<uuid>
    JAMAIS supprimé — son unique_id entre donc en collision avec celui de la
    NOUVELLE entité scene.*. Confirmé en conditions réelles : sans ce filtre, la
    1ère entrée trouvée dans l'entity registry était systématiquement l'ancien
    script, jamais la scène — exactement le même bug qu'on corrige, mais déplacé."""
    result = _ha_ws_call("config/entity_registry/list")
    if not result or not result.get("success"):
        return None
    for e in result.get("result", []):
        entity_id = e.get("entity_id", "")
        if e.get("unique_id") == unique_id and entity_id.startswith(f"{domain}."):
            return entity_id
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
            # entity_category transmis au web (pas de filtrage ici) — permet
            # d'afficher batterie/diagnostics comme attribut secondaire (demande
            # explicite Hicham, 2026-08-09) sans jamais la laisser usurper le lien
            # ha_entity_id PRINCIPAL du device (cf. commentaire équivalent dans
            # _backfill_ha_entity_links, même fix appliqué aux deux chemins).
            if entry:
                payload["entityCategory"] = entry.get("entity_category")
            # device_class/unit (2026-09-01) — Hicham, capture HA à l'appui : "sur
            # Home Assistant [...] j'arrive à avoir les unités et pas sur le site
            # [...] que ce soit du matter ou du zigbee". 1er jet (au-dessus, sur
            # `entry` = config/entity_registry/list) : marchait pour les entités
            # Matter, PAS pour Zigbee2MQTT (plateforme "mqtt") — vérifié en
            # conditions réelles sur le vrai HA du site de test (WebSocket direct,
            # pas supposé) : ni device_class ni (original_)unit_of_measurement ne
            # sont JAMAIS présents sur une entrée entity_registry `platform: mqtt`,
            # ces champs ne vivent que sur l'ÉTAT (attrs), pas le registre, pour
            # cette plateforme. Repli sur l'état réel de l'entité — présent pour
            # les deux protocoles (confirmé aussi sur les entités Matter).
            state = ha_get(f"/states/{entity_id}")
            attrs = state.json().get("attributes", {}) if state.ok else {}
            payload["deviceClass"] = attrs.get("device_class") or (entry.get("device_class") or entry.get("original_device_class") if entry else None)
            payload["unit"] = attrs.get("unit_of_measurement") or (entry.get("unit_of_measurement") or entry.get("original_unit_of_measurement") if entry else None)
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
        _cloud_post("vercel:ingest/registry", f"{APP_URL}/api/ingest/registry", json=payload, timeout=10)
    except Exception as e:
        warn(f"[ingest/registry] {entity_id}: {e}")


def _run_fleet_status_loop():
    """Envoie le résumé de flotte (RPC pi_report_fleet_status) toutes les 5 min, et dès que la santé ou les alertes
    changent (au plus 1 envoi par minute). Remplace le heartbeat à la minute (lot D, phase 2)."""
    time.sleep(45)   # laisser le moteur d'alertes faire sa 1re réconciliation
    last = 0.0
    while True:
        try:
            wait = _FLEET_MIN_INTERVAL_S - (time.time() - last)
            if wait > 0:
                time.sleep(wait)
            _fleet_status_direct()
            last = time.time()
        except Exception as e:
            warn(f"[fleet] cycle échoué (poursuite au prochain) : {e}")
        _fleet_request.wait(timeout=_FLEET_PERIOD_S)
        _fleet_request.clear()


def on_local_connect(client, userdata, flags, reason_code, properties):
    if reason_code.is_failure:
        warn(f"[local] Connexion Mosquitto échouée ({reason_code})")
        return
    client.subscribe([("zigbee2mqtt/#", 1)])  # tous les messages Z2M (états + bridge/state)
    # Audit add-on 2026-09-22 : ce log annonçait une souscription à "ha/#" qui
    # n'existe pas (reliquat de l'ancienne architecture EMQX, cf. commentaire
    # historique plus haut dans le fichier — _handle_ha_command() n'est plus
    # jamais atteinte via MQTT, seulement en appel Python direct) — corrigé
    # pour refléter la réalité, aucun risque de confusion pour un futur dev.
    log("[local] Connecté Mosquitto — souscrit zigbee2mqtt/#")


def _get_ha_areas():
    """Retourne la liste des areas HA via WebSocket [{area_id, name, ...}]."""
    result = _ha_ws_call("config/area_registry/list")
    if result and result.get("success"):
        return result.get("result", [])
    warn(f"[ha/command] _get_ha_areas échoué: {result}")
    return []


_LOCAL_APP_NOISE_DOMAINS = {"update", "button", "event"}

# Domaine HA "principal" attendu pour chaque DeviceType — PORT délibéré de
# EXPECTED_DOMAIN (web/src/app/api/ingest/registry/route.ts), qui décide déjà
# ce lien côté cloud (Zigbee2MQTT/Matter créent plusieurs entités par device
# physique partageant la même adresse IEEE/node_id — sans ce filtre, n'importe
# laquelle pourrait usurper le lien "entité principale"). Copie, pas un
# import : aucun runtime JS partagé entre l'addon Python et web/ — même risque
# de divergence déjà assumé et documenté pour _detect_device_type() (port de
# detectDeviceType()). À tenir synchronisé à la main si EXPECTED_DOMAIN change
# côté TS — cf. HANDOFF.md, étape 3 du chantier "vraie intégration locale".
_EXPECTED_PRIMARY_DOMAIN = {
    "light": "light", "switch": "switch", "plug": "switch", "cover": "cover",
    "lock": "lock", "fan": "fan", "valve": "valve", "humidifier": "humidifier",
    "thermostat": "climate", "sensor-motion": "binary_sensor",
    "sensor-contact": "binary_sensor", "sensor-water": "binary_sensor",
    "sensor-temp": "sensor",
}

# Domaines HA pilotables — PORT de v_writable (RPC Postgres upsert_device_entity)
# — décide si une entité SECONDAIRE (multi-mesures/réglages d'un même device
# physique) s'affiche comme pilotable ou en lecture seule. Même avertissement
# de synchronisation manuelle que _EXPECTED_PRIMARY_DOMAIN ci-dessus.
_WRITABLE_DOMAINS = {
    "light", "switch", "cover", "climate", "lock", "fan",
    "input_boolean", "input_number", "input_select", "select", "number",
}


def _build_local_devices() -> list[dict]:
    """Construit la liste des équipements CLASSÉS (vrai DeviceType, entité
    principale + entités secondaires, état normalisé) depuis les données
    HA/Zigbee2MQTT/Matter locales — chantier "accès local", étape 3
    (2026-09-07, cf. HANDOFF.md). Remplace le squelette v1 de
    handle_local_devices() (domaine HA brut, pas de vrai type) posé le
    2026-09-06 comme 1re preuve de bout en bout.

    Réutilise EXACTEMENT les mêmes fonctions déjà utilisées pour la synchro
    cloud plutôt que d'en réécrire une 2e copie divergente :
    _detect_device_type() (Zigbee), _extract_matter_device_info() (Matter),
    _detect_wifi_device_type() (Wi-Fi natif HA), _ha_entity_to_normalized_patch()
    (état), _ha_attributes_to_capabilities() (capacités/limites) — mêmes
    fonctions Python, appelées directement, donc IMPOSSIBLE de diverger avec
    le chemin cloud pour un même device (contrairement à
    _EXPECTED_PRIMARY_DOMAIN/_WRITABLE_DOMAINS ci-dessus, qui SONT une 2e
    copie faute d'équivalent Python déjà existant côté cloud — cette
    logique-là vit dans web/src/app/api/ingest/registry/route.ts, en TypeScript,
    donc pas directement appelable depuis l'addon).

    Le panneau d'alarme (alarm_control_panel.*) est délibérément HORS de cette
    liste — dans l'architecture réelle (cf. types.ts, InitialState), l'alarme
    n'est PAS un Device : état/commandes passent par un chemin séparé
    (SiteStatusUpdate/sendAlarmCommand), pas encore construit pour le mode
    local — prochain morceau du chantier, pas celui-ci."""
    dev_result = _ha_ws_call("config/device_registry/list")
    devices_ha = dev_result.get("result", []) if dev_result and dev_result.get("success") else []
    ent_result = _ha_ws_call("config/entity_registry/list")
    entities = ent_result.get("result", []) if ent_result and ent_result.get("success") else []
    states_result = _ha_ws_call("get_states")
    states = states_result.get("result", []) if states_result and states_result.get("success") else []
    states_by_entity = {s.get("entity_id"): s for s in states}

    # Device VIRTUEL créé par l'intégration MQTT pour exposer les contrôles du
    # pont Zigbee2MQTT lui-même (permit join, restart, log level...) — pas un
    # équipement du logement (cf. v2.9.164, filtre déjà vérifié en conditions
    # réelles). Exclu explicitement AVANT toute tentative de classification —
    # ses entités contiennent l'adresse IEEE du COORDINATEUR dans leur
    # unique_id (ex: "bridge_0x449fdafffe78a7d5_permit_join_zigbee2mqtt"), qui
    # matcherait sinon _IEEE_RE comme un faux device Zigbee.
    _noise_device_ids = {
        d.get("id") for d in devices_ha
        if d.get("manufacturer") == "Zigbee2MQTT" and d.get("model") == "Bridge"
    }

    # ── Identité (DeviceType/vendor/model) par protocole ────────────────────

    # Zigbee : ieee_address -> identité, depuis le cache MQTT bridge/devices
    # (_last_z2m_devices_list, déjà tenu à jour en continu par on_local_message)
    # — aucun nouvel appel réseau, contrairement à un premier réflexe qui
    # aurait interrogé Z2M à la demande.
    zigbee_by_ieee: dict[str, dict] = {}
    for d in _last_z2m_devices_list:
        if d.get("type") == "Coordinator":
            continue
        ieee = d.get("ieee_address")
        if not ieee:
            continue
        definition = d.get("definition") or {}
        exposes = definition.get("exposes") or []
        zigbee_by_ieee[ieee] = {
            "type": _detect_device_type(
                exposes, ieee_address=ieee, ha_entities=entities,
                vendor=definition.get("vendor"), model=definition.get("model"),
            ),
            "vendor": definition.get("vendor") or "",
            "model": definition.get("model") or "",
            # Schéma des exposes Z2M (battery/action/linkquality/...) — gap
            # "device sans entité utilisable" en local (2026-09-08) :
            # jusqu'ici jamais transmis par cette route, features restait
            # TOUJOURS [] côté web (local.ts, mapDevice) quel que soit le
            # device. Même donnée déjà utilisée juste au-dessus pour
            # _detect_device_type(), simplement pas conservée avant.
            "features": exposes,
        }

    # Matter : node_id -> identité, depuis matter-server (get_nodes).
    matter_by_node: dict[int, dict] = {}
    for node in _matter_get_nodes():
        node_id, vendor, product, device_type = _extract_matter_device_info(node)
        if node_id is not None:
            matter_by_node[node_id] = {"type": device_type, "vendor": vendor, "model": product}

    # Wi-Fi natif HA (Shelly...) : device_id HA -> wifi_id + vendor/model, déjà
    # présents tels quels dans device_registry (pas de "exposes" séparé comme
    # Z2M — cf. _wifi_device_identifier).
    wifi_by_device_id: dict[str, dict] = {}
    for d in devices_ha:
        wifi_id = _wifi_device_identifier(d)
        if wifi_id:
            wifi_by_device_id[d.get("id")] = {
                "wifi_id": wifi_id,
                "vendor": d.get("manufacturer") or "",
                "model": d.get("model") or "",
            }

    entities_by_device_id: dict[str, list] = {}
    for e in entities:
        did = e.get("device_id")
        if did:
            entities_by_device_id.setdefault(did, []).append(e)

    devices_out: list[dict] = []

    for dev in devices_ha:
        device_id = dev.get("id")
        if not device_id or device_id in _noise_device_ids:
            continue
        entities_here = entities_by_device_id.get(device_id, [])
        if not entities_here:
            continue

        # Entités utilisables : jamais diagnostic/config, jamais un domaine de
        # bruit pur (update/button/event) — même filtre que le chemin cloud
        # (NOISE_DOMAINS côté web, _sync_wifi_devices_to_app côté addon).
        usable = [
            e for e in entities_here
            if e.get("entity_category") not in ("diagnostic", "config")
            and (e.get("entity_id", "").split(".", 1)[0] if "." in e.get("entity_id", "") else "") not in _LOCAL_APP_NOISE_DOMAINS
        ]
        if not usable:
            continue

        # Identité du device HA : Zigbee (unique_id -> ieee) puis Matter
        # (unique_id -> node_id) puis Wi-Fi (identifiers du device_registry) —
        # un device HA n'appartient jamais qu'à un seul de ces 3 protocoles.
        ieee = None
        matter_node_id = None
        identity = None
        for e in entities_here:
            m = _IEEE_RE.search(e.get("unique_id") or "")
            if m:
                ieee = m.group(0)
                identity = zigbee_by_ieee.get(ieee)
                break
            node_id = _matter_node_id_from_unique_id(e.get("unique_id"))
            if node_id is not None:
                matter_node_id = node_id
                identity = matter_by_node.get(node_id)
                break
        wifi_info = wifi_by_device_id.get(device_id)

        if wifi_info and identity is None:
            # Choix de l'entité principale par PRIORITÉ de domaine (pas par
            # DeviceType attendu — le type n'est justement connu qu'APRÈS ce
            # choix côté Wi-Fi) — même algorithme, même ordre que
            # _sync_wifi_devices_to_app(), copié à l'identique plutôt que
            # factorisé pour l'instant (2 call sites seulement).
            usable_sorted = sorted(
                usable,
                key=lambda e: (
                    _WIFI_DOMAIN_PRIORITY.index(e["entity_id"].split(".")[0])
                    if e["entity_id"].split(".")[0] in _WIFI_DOMAIN_PRIORITY
                    else len(_WIFI_DOMAIN_PRIORITY)
                ),
            )
            primary = usable_sorted[0]
            primary_domain = primary["entity_id"].split(".")[0]
            primary_state0 = states_by_entity.get(primary["entity_id"]) or {}
            primary_attrs0 = primary_state0.get("attributes") or {}
            device_class = primary_attrs0.get("device_class") or primary.get("device_class") or primary.get("original_device_class")
            # Compteur général — même correction, même raison que _sync_wifi_devices_to_app()
            # (2026-10-31) : un Shelly EM/3EM n'a aucun light/switch/cover, la priorité de
            # domaine ne suffit pas à le reconnaître comme compteur général.
            has_energy_entity = any(
                (states_by_entity.get(e.get("entity_id")) or {}).get("attributes", {}).get("device_class") == "energy"
                for e in usable
            )
            device_type = "energy-meter" if has_energy_entity else (_detect_wifi_device_type(primary_domain, device_class) or "sensor-generic")
            vendor, model = wifi_info["vendor"], wifi_info["model"]
        elif identity:
            device_type = identity["type"]
            vendor, model = identity["vendor"], identity["model"]
            expected_domain = _EXPECTED_PRIMARY_DOMAIN.get(device_type)
            primary = next(
                (e for e in usable
                 if (e.get("entity_id", "").split(".")[0] if "." in e.get("entity_id", "") else "") == expected_domain
                 and not e.get("entity_category")),
                usable[0],  # repli : aucune entité ne matche le domaine attendu du type -> 1re utilisable plutôt que perdre le device
            )
        else:
            # Device HA reconnu par aucun des 3 protocoles pris en charge —
            # ignoré plutôt que mal classé (même repli sûr que
            # _extract_matter_device_info pour un type inconnu : jamais un
            # faux actionneur par défaut, ni un faux type Zigbee/Wi-Fi).
            continue

        primary_id = primary.get("entity_id", "")
        primary_state = states_by_entity.get(primary_id) or {}
        primary_attrs = primary_state.get("attributes") or {}
        online = primary_state.get("state") not in (None, "unavailable")
        # Même repli que le squelette v1 : friendly_name de l'ÉTAT avant le nom
        # du registre (beaucoup d'entités platform "mqtt" n'ont ni name ni
        # original_name) — nom du DEVICE HA (name_by_user/name) en priorité
        # absolue ici, plus fiable qu'un nom d'entité isolée pour un device
        # multi-entités.
        name = (
            dev.get("name_by_user") or dev.get("name")
            or primary.get("name") or primary_attrs.get("friendly_name")
            or primary.get("original_name") or primary_id
        )

        secondary_entities = []
        for e in usable:
            eid = e.get("entity_id", "")
            if eid == primary_id:
                continue
            domain = eid.split(".")[0] if "." in eid else ""
            st = states_by_entity.get(eid) or {}
            attrs = st.get("attributes") or {}
            writable = domain in _WRITABLE_DOMAINS
            # "primaryEntity" ici = cette entité SECONDAIRE a, à titre individuel,
            # un domaine qui matche le domaine attendu du type du device (flag
            # cosmétique du chemin cloud, PORT de v_primary dans upsert_device_entity
            # — rare en pratique, gardé pour fidélité). Ne PAS confondre avec le
            # choix de l'entité PRINCIPALE du device (primary_id, plus haut).
            primary_entity_flag = _EXPECTED_PRIMARY_DOMAIN.get(device_type) == domain
            secondary_entities.append({
                "haEntityId": eid,
                "domain": domain,
                "friendlyName": e.get("name") or attrs.get("friendly_name") or e.get("original_name"),
                "deviceClass": attrs.get("device_class") or e.get("device_class") or e.get("original_device_class"),
                "unit": attrs.get("unit_of_measurement") or e.get("unit_of_measurement") or e.get("original_unit_of_measurement"),
                # Valeur brute HA (ex: "584"), PAS le patch normalisé (Device.state
                # l'est, DeviceEntity.state ne l'est PAS — vérifié contre
                # web/src/types/index.ts : "state?: string // valeur brute HA" — et
                # web/src/lib/deviceEntities.ts, qui compare entity.state === "on",
                # Number(entity.state)... jamais entity.state.on. Corrigé avant
                # d'écrire local.ts plutôt qu'après coup.
                "state": st.get("state"),
                "primaryEntity": primary_entity_flag,
                "writable": writable,
                "visibleClient": True,
                "shownOnCard": primary_entity_flag or writable,
                "entityCategory": e.get("entity_category"),
            })

        devices_out.append({
            "id": primary_id,  # pas d'UUID Supabase en local — l'entity_id HA principal identifie le device de façon stable
            "haEntityId": primary_id,
            "name": name,
            "type": device_type,
            "vendor": vendor,
            "model": model,
            "ieeeAddress": ieee,
            "matterNodeId": matter_node_id,
            "wifiId": wifi_info.get("wifi_id") if wifi_info else None,
            "online": online,
            "lastSeen": primary_state.get("last_changed"),
            "areaId": dev.get("area_id"),
            "capabilities": _ha_attributes_to_capabilities(primary_id, primary_attrs),
            "state": _ha_entity_to_normalized_patch(primary_id, primary_state.get("state"), primary_attrs),
            "entities": secondary_entities,
            # Gap "device sans entité utilisable" (2026-09-08) — schéma +
            # valeurs des exposes Z2M (battery/action/linkquality/...) pour un
            # device Zigbee, MÊME s'il n'a aucune entité HA principale pour
            # les porter (ex: une télécommande classée sensor-generic, même
            # cas que §167-169 déjà corrigé côté cloud). `ieee` uniquement :
            # Matter/Wi-Fi n'ont pas cette notion, restent []/None.
            "features": (zigbee_by_ieee.get(ieee, {}).get("features") or []) if ieee else [],
            "rawAttributes": _last_z2m_raw_state.get(ieee) if ieee else None,
        })

    return devices_out


def handle_local_devices() -> dict:
    """Route locale /local/devices — équipements RÉELLEMENT classés (voir
    _build_local_devices()), groupés par pièce. Chantier "accès local", étape
    3 (2026-09-07, cf. HANDOFF.md) — remplace le squelette v1 du 2026-09-06."""
    areas_result = _ha_ws_call("config/area_registry/list")
    areas = areas_result.get("result", []) if areas_result and areas_result.get("success") else []
    area_names = {a.get("area_id"): a.get("name") for a in areas}

    # Clé de regroupement = area_id HA brut (stable), pas le nom affiché — un
    # nom peut se renommer, l'id HA non. "Sans pièce" (aucune area_id) regroupé
    # sous la clé None, cohérent : local.ts (web/) a besoin d'un identifiant de
    # pièce stable pour construire Room[] (roomId), pas juste un libellé.
    rooms: dict[str | None, list] = {}
    for dev in _build_local_devices():
        area_id = dev.get("areaId")
        rooms.setdefault(area_id, []).append(dev)

    room_types = _load_room_types()
    return {
        "rooms": [
            {
                "id": area_id,
                "name": area_names.get(area_id) or "Sans pièce",
                "roomType": room_types.get(area_id) if area_id else None,
                "devices": devs,
            }
            for area_id, devs in rooms.items()
        ]
    }


def _load_room_types() -> dict:
    try:
        with open(ROOM_TYPES_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_room_types(room_types: dict) -> None:
    with open(ROOM_TYPES_FILE, "w") as f:
        json.dump(room_types, f)


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


def _validate_ha_action_steps(steps, trusted: bool = False) -> bool:
    """Vérifie récursivement que chaque appel de service d'une séquence
    d'actions HA respecte ALLOWED_SERVICES. Audit add-on 2026-09-22 :
    script_upsert/automation_upsert (ci-dessous) construisaient un script/
    automatisation HA à partir d'un `sequence`/`action` ENTIÈREMENT fourni par
    l'appelant, sans jamais repasser par la whitelist appliquée sur la route
    /cmd (ligne ~9199) — un tel script, une fois créé, est déclenchable via
    `script.turn_on` (lui bien whitelisté), permettant en pratique d'exécuter
    N'IMPORTE QUEL service HA en 2 appels. Couvre les 3 seules constructions de
    contrôle réellement produites par l'app (cf. web/src/lib/automationBuilder.ts) :
    delay (rien à valider), repeat.sequence, choose[].sequence + default —
    toute autre forme (wait_for_trigger, if/then, parallel, event…) est
    refusée par défaut plutôt que de maintenir une liste blanche de clés de
    contrôle qui pourrait devenir incomplète.

    `trusted=True` (2026-11-09) : réservé aux 2 automatisations internes de
    câblage clavier/SOS Alarmo, jamais à un appel app-facing — cf.
    _TRUSTED_WIRING_SERVICES pour le détail de pourquoi c'est sûr pour ces
    2 cas précis uniquement.
    """
    if not isinstance(steps, list):
        return False
    for step in steps:
        if not isinstance(step, dict):
            return False
        svc = step.get("service") or step.get("action")
        if svc:
            if not isinstance(svc, str) or "." not in svc:
                return False
            domain, _, verb = svc.partition(".")
            if verb in ALLOWED_SERVICES.get(domain, set()):
                continue
            if trusted and verb in _TRUSTED_WIRING_SERVICES.get(domain, set()):
                continue
            return False
        if "delay" in step:
            continue
        if "repeat" in step and isinstance(step["repeat"], dict):
            if not _validate_ha_action_steps(step["repeat"].get("sequence", []), trusted=trusted):
                return False
            continue
        if "choose" in step and isinstance(step["choose"], list):
            for branch in step["choose"]:
                if not isinstance(branch, dict) or not _validate_ha_action_steps(branch.get("sequence", []), trusted=trusted):
                    return False
            if "default" in step and not _validate_ha_action_steps(step.get("default", []), trusted=trusted):
                return False
            continue
        return False
    return True


def _handle_ha_command(payload: bytes, trusted_wiring: bool = False) -> bool | dict:
    """Exécute une commande ha/command (appelée en direct depuis Python — cf.
    docstring de _validate_ha_action_steps, ce topic MQTT lui-même n'existe
    plus — ET depuis /ha-command, la vraie route HTTP app-facing).

    `trusted_wiring=True` (2026-11-09) : réservé aux 2 appelants internes
    Alarmo SOS/clavier (cf. _TRUSTED_WIRING_SERVICES) — jamais passé par
    _handle_ha_command_route (route app-facing), qui garde la valeur par
    défaut False et donc la whitelist stricte ALLOWED_SERVICES seule.

    Retourne True/False (audit add-on 2026-09-22) : jusqu'ici cette fonction
    ne retournait jamais rien, et _handle_ha_command_route répondait "ok" au
    client SYSTÉMATIQUEMENT, même quand l'écriture HA échouait réellement
    (ex: HA temporairement indisponible) — un client pouvait croire une
    automatisation/scène enregistrée alors qu'elle ne l'était pas. Les autres
    appelants (Alarmo SOS/clavier, _run_ha_maintenance_cycle) ignorent déjà la valeur
    de retour sans rien casser — ajout rétrocompatible.

    (2026-10-18) scene_upsert renvoie désormais {"ok": True, "entity_id": ...}
    au lieu de True nu — un dict non vide reste "truthy" en Python, donc tous
    les appelants existants (if ok / if not ok, jamais de `is True`) continuent
    de fonctionner sans changement ; seul _handle_ha_command_route lit le
    détail pour le transmettre au web, qui en a besoin pour activer la scène
    plus tard (cf. _entity_id_by_unique_id)."""
    try:
        data = json.loads(payload.decode())
    except Exception as e:
        warn(f"[ha/command] JSON invalide : {e}")
        return False

    cmd_type  = data.get("type", "")
    object_id = data.get("object_id", "")

    # ── Scripts / Scènes / Automations (nécessitent object_id) ───────────────
    if cmd_type in (
        "script_upsert", "script_delete",
        "scene_upsert", "scene_delete",
        "automation_upsert", "automation_delete",
    ):
        if not object_id:
            warn(f"[ha/command] object_id manquant pour {cmd_type} : {data}")
            return False

        if cmd_type == "script_upsert":
            sequence = data.get("sequence", [])
            if not _validate_ha_action_steps(sequence):
                warn(f"[ha/command] script_upsert refusé (service non autorisé dans sequence) : {object_id}")
                return False
            script_cfg = {
                "alias":    data.get("alias", object_id),
                "icon":     data.get("icon", "mdi:play"),
                "sequence": sequence,
                "mode":     "single",
            }
            r = ha_post(f"/config/script/config/{object_id}", script_cfg)
            if r.ok:
                ha_post("/services/script/reload", {})
                log(f"[ha/command] Script HA créé/mis à jour : {object_id}")
                return True
            warn(f"[ha/command] Erreur script {object_id} : {r.status_code} {r.text[:200]}")
            return False

        elif cmd_type == "script_delete":
            # (2026-09-03) VRAI BUG trouvé en vérifiant en conditions réelles (web) :
            # un reload appelé IMMÉDIATEMENT après le DELETE course avec l'écriture
            # disque de HA pour sa config store (Store.async_delay_save, écriture
            # différée) — le reload peut relire le fichier AVANT que la suppression
            # y soit effectivement écrite, et RECONSTRUIT le script "supprimé" à
            # partir du contenu encore présent sur disque. Reproduit à répétition en
            # testant depuis l'extérieur (DELETE + reload immédiat = résurrection
            # systématique ; DELETE + quelques secondes d'attente, sans reload =
            # suppression qui tient). Un client cliquant "Supprimer" sur une scène
            # aurait donc pu se retrouver avec un script fantôme toujours actif côté
            # HA, invisible dans l'app (plus de ligne DB), jamais nettoyé. Fix : petit
            # délai avant le reload, le temps que l'écriture différée de HA se termine.
            r = requests.delete(f"{API}/config/script/config/{object_id}", headers=HDRS, timeout=10)
            if r.ok:
                time.sleep(2)
                ha_post("/services/script/reload", {})
                log(f"[ha/command] Script HA supprimé : {object_id}")
                return True
            warn(f"[ha/command] Erreur suppression script {object_id} : {r.status_code} {r.text[:200]}")
            return False

        elif cmd_type == "scene_upsert":
            # (2026-10-18) Scènes Domoticium RECONSTRUITES en vraies scènes HA
            # natives (scene.*, même storage que l'éditeur de scènes natif de
            # HA) — remplacent script_upsert+mqtt.publish pour cet usage.
            # Trouvé en auditant les scènes à la demande de Hicham : une scène
            # touchant un équipement Zigbee échouait silencieusement depuis
            # l'audit de sécurité du 2026-09-22 (_validate_ha_action_steps,
            # ALLOWED_SERVICES) — mqtt n'y a jamais été ajouté, et l'ajouter
            # aurait rouvert un vrai risque (mqtt.publish non restreint =
            # service HA arbitraire exécutable). Une scène HA native est un
            # INSTANTANÉ {entity_id: {attributs}}, jamais un appel de service —
            # rien à valider via _validate_ha_action_steps, structurellement
            # plus sûr que l'ancien mécanisme (pas de surface d'exécution).
            entities = data.get("entities", {})
            if not isinstance(entities, dict):
                warn(f"[ha/command] scene_upsert refusé (entities invalide) : {object_id}")
                return False
            scene_cfg = {
                "id":       object_id,
                "name":     data.get("name", object_id),
                "entities": entities,
            }
            r = ha_post(f"/config/scene/config/{object_id}", scene_cfg)
            if r.ok:
                ha_post("/services/scene/reload", {})
                # L'entity_id réel (scene.<nom_slugifié>) n'est JAMAIS celui qu'on
                # devinerait depuis object_id (cf. _entity_id_by_unique_id) — résolu
                # ici et renvoyé au client (web) pour qu'il le stocke, plutôt que de
                # laisser chaque appelant deviner un entity_id potentiellement faux
                # (bug réel trouvé en auditant les scènes à la demande de Hicham,
                # 2026-10-18 : scene.turn_on ciblant l'ancien entity_id calculé
                # échouait silencieusement, HA n'erreure pas sur une cible
                # inexistante). Petite marge de retry : le reload venant de
                # s'exécuter, l'entity registry peut mettre un instant à refléter
                # le changement.
                entity_id = _entity_id_by_unique_id(object_id)
                if not entity_id:
                    time.sleep(0.5)
                    entity_id = _entity_id_by_unique_id(object_id)
                log(f"[ha/command] Scène HA créée/mise à jour : {object_id} → {entity_id or '?'}")
                return {"ok": True, "entity_id": entity_id}
            warn(f"[ha/command] Erreur scène {object_id} : {r.status_code} {r.text[:200]}")
            return False

        elif cmd_type == "scene_delete":
            # Même course reload/écriture disque que script_delete/automation_delete
            # ci-dessus — cf. leurs commentaires pour le détail complet.
            r = requests.delete(f"{API}/config/scene/config/{object_id}", headers=HDRS, timeout=10)
            if r.ok:
                time.sleep(2)
                ha_post("/services/scene/reload", {})
                log(f"[ha/command] Scène HA supprimée : {object_id}")
                return True
            warn(f"[ha/command] Erreur suppression scène {object_id} : {r.status_code} {r.text[:200]}")
            return False

        elif cmd_type == "automation_upsert":
            # "condition" était silencieusement ignoré ici alors que web/src/app/api/
            # automations/route.ts l'envoie bien — toute automatisation avec condition
            # perdait cette condition dès sa création/mise à jour. Trouvé en construisant
            # _republish_automation() (migration Matter, 2026-08-01), corrigé au passage.
            #
            # (2026-09-02, bloc Actions) "mode" était figé en dur à "single" ici — le
            # réglage de mode d'exécution (unique/redémarrer/file/parallèle) ajouté côté
            # web n'aurait donc jamais atteint HA, quelle que soit la valeur envoyée.
            # Repris depuis data (repli "single", comportement historique préservé).
            action = data.get("action", [])
            if not _validate_ha_action_steps(action, trusted=trusted_wiring):
                warn(f"[ha/command] automation_upsert refusé (service non autorisé dans action) : {object_id}")
                return False
            auto_cfg = {
                "alias":     data.get("alias", object_id),
                "trigger":   data.get("trigger", []),
                "condition": data.get("condition", []),
                "action":    action,
                "mode":      data.get("mode", "single"),
            }
            r = ha_post(f"/config/automation/config/{object_id}", auto_cfg)
            if r.ok:
                ha_post("/services/automation/reload", {})
                log(f"[ha/command] Automation HA créée/mise à jour : {object_id}")
                return True
            warn(f"[ha/command] Erreur automation {object_id} : {r.status_code} {r.text[:200]}")
            return False

        elif cmd_type == "automation_delete":
            # (2026-09-03) Même course reload/écriture disque que script_delete
            # ci-dessus — cf. son commentaire pour le détail complet. Reproduit
            # explicitement pour automation_delete aussi (pas seulement script_delete) :
            # une automatisation supprimée depuis l'app pouvait rester ARMÉE côté HA
            # (déclencheurs + actions toujours actifs), invisible dans l'app.
            r = requests.delete(f"{API}/config/automation/config/{object_id}", headers=HDRS, timeout=10)
            if r.ok:
                time.sleep(2)
                ha_post("/services/automation/reload", {})
                log(f"[ha/command] Automation HA supprimée : {object_id}")
                return True
            warn(f"[ha/command] Erreur suppression automation {object_id} : {r.status_code} {r.text[:200]}")
            return False
        return False  # cmd_type dans le groupe mais aucune branche ci-dessus ne l'a traité (ne devrait pas arriver)

    # ── Areas (pièces) — WebSocket HA uniquement (pas d'API REST pour area_registry) ──
    elif cmd_type == "create_area":
        name = data.get("name", "")
        if not name:
            warn("[ha/command] create_area: name manquant")
            return False
        result = _ha_ws_call("config/area_registry/create", name=name)
        if result and result.get("success"):
            area_id = (result.get("result") or {}).get("area_id")
            room_type = data.get("room_type")
            if area_id and room_type:
                room_types = _load_room_types()
                room_types[area_id] = room_type
                _save_room_types(room_types)
            log(f"[ha/command] Area HA créée : '{name}'")
            return True
        warn(f"[ha/command] Erreur création area '{name}' : {result}")
        return False

    elif cmd_type == "rename_area":
        old_name = data.get("name", "")
        new_name = data.get("new_name", "")
        if not old_name or not new_name:
            warn("[ha/command] rename_area: name et new_name requis")
            return False
        areas = _get_ha_areas()
        area  = next((a for a in areas if a.get("name") == old_name), None)
        if not area:
            result = _ha_ws_call("config/area_registry/create", name=new_name)
            log(f"[ha/command] rename_area: '{old_name}' non trouvée — créée sous '{new_name}'")
            return bool(result and result.get("success"))
        result = _ha_ws_call("config/area_registry/update", area_id=area["area_id"], name=new_name)
        if result and result.get("success"):
            log(f"[ha/command] Area HA renommée : '{old_name}' → '{new_name}'")
            return True
        warn(f"[ha/command] Erreur rename area : {result}")
        return False

    elif cmd_type == "delete_area":
        name = data.get("name", "")
        if not name:
            warn("[ha/command] delete_area: name manquant")
            return False
        areas = _get_ha_areas()
        area  = next((a for a in areas if a.get("name") == name), None)
        if not area:
            log(f"[ha/command] delete_area: area '{name}' non trouvée dans HA")
            return True  # déjà absente — état cible déjà atteint, pas un échec
        result = _ha_ws_call("config/area_registry/delete", area_id=area["area_id"])
        if result and result.get("success"):
            room_types = _load_room_types()
            if room_types.pop(area["area_id"], None) is not None:
                _save_room_types(room_types)
            log(f"[ha/command] Area HA supprimée : '{name}'")
            return True
        warn(f"[ha/command] Erreur suppression area '{name}' : {result}")
        return False

    elif cmd_type == "set_device_area":
        entity_id      = data.get("entity_id")      or None
        ieee_address   = data.get("ieee_address")   or None
        matter_node_id = data.get("matter_node_id")
        area_name      = data.get("area_name")      or None
        # (2026-09-08, mode local, "audit useHomeStore") `name` optionnel —
        # renomme le device dans le registre HA (name_by_user) EN PLUS de son
        # area, dans le MÊME appel WS. Ajouté pour le mode local : sans
        # Supabase pour stocker un nom personnalisé, HA (name_by_user) EST le
        # seul endroit où ce nom peut vivre — sinon le prochain cycle de
        # lecture (_build_local_devices) écraserait silencieusement tout
        # renommage optimiste côté web au tour suivant. Absent/vide = nom
        # inchangé (comportement historique préservé pour le cloud, qui
        # n'appelle ce cmd_type que pour l'area).
        name = data.get("name") or None

        device_id = _get_ha_device_id(
            entity_id=entity_id, ieee_address=ieee_address, matter_node_id=matter_node_id
        )
        if not device_id:
            warn(f"[ha/command] set_device_area: device non trouvé "
                 f"(entity={entity_id}, ieee={ieee_address}, matter_node_id={matter_node_id})")
            return False

        # ⚠️ Bug réel trouvé le 2026-09-09 (rencontré en testant un renommage
        # groupé, un device a atterri dans la mauvaise pièce) : `area_id`
        # n'est ajouté à `ws_kwargs` QUE si effectivement résolu — jamais
        # envoyé comme `None` explicite. `config/device_registry/update` (HA)
        # traite un `area_id` explicitement présent, même `null`, comme "vider
        # l'aire du device" — PAS "ne rien changer". Avant ce fix, tout appel
        # SANS area_name valide (y compris un simple renommage sans changement
        # de pièce, cas qui va devenir courant côté cloud, cf. commit web
        # associé) risquait de VIDER l'aire déjà en place au lieu de la
        # laisser intacte.
        area_id = None
        if area_name:
            areas   = _get_ha_areas()
            area    = next((a for a in areas if a.get("name") == area_name), None)
            area_id = area["area_id"] if area else None
            if not area_id:
                warn(f"[ha/command] set_device_area: area '{area_name}' non trouvée — aire laissée inchangée")

        ws_kwargs = {"device_id": device_id}
        if area_id:
            ws_kwargs["area_id"] = area_id
        if name:
            ws_kwargs["name_by_user"] = name
        if len(ws_kwargs) == 1:
            log(f"[ha/command] set_device_area: rien à mettre à jour pour {entity_id or ieee_address} (ni aire ni nom résolus)")
            return True  # rien à faire n'est pas un échec
        result = _ha_ws_call("config/device_registry/update", **ws_kwargs)
        if result and result.get("success"):
            log(f"[ha/command] Device mis à jour : {entity_id or ieee_address} → "
                f"area={area_name or 'aucune'}{f', name={name}' if name else ''}")
            return True
        warn(f"[ha/command] Erreur set_device_area : {result}")
        return False

    else:
        warn(f"[ha/command] Type inconnu : {cmd_type}")
        return False


def _detect_device_type(
    exposes: list[dict], ieee_address: str | None = None, ha_entities: list[dict] | None = None,
    vendor: str | None = None, model: str | None = None,
) -> str:
    """Port Python de detectDeviceType() (ex web/src/app/api/webhooks/pi/devices-sync/route.ts,
    renommé depuis) — utilisé uniquement par le chemin direct Supabase, cf. HANDOFF §36."""
    # Compteurs d'énergie généraux (tête de tableau électrique) : identification
    # par (vendor, model) EXACT (_ENERGY_METER_VENDOR_MODELS, défini plus haut),
    # signal beaucoup plus fiable que les exposes — un compteur multi-phase
    # (Bituo/NOUS D4Z/Owon) a des exposes numériques variés (power_a, energy_l1…)
    # sans forme standard reconnaissable, mais vendor/model Z2M sont stables
    # (`definition.vendor`/`.model`, vérifiés dans zigbee-herdsman-converters).
    # Vérifié AVANT toute heuristique par exposes : aucun de ces modèles
    # n'expose "light"/"switch"/"cover" (pure mesure, jamais d'actionneur), donc
    # aucun risque de conflit avec les checks ci-dessous, mais on ne prend pas
    # de risque avec l'ordre. Non testé en conditions réelles (aucun matériel
    # physique installé chez un client à ce jour) — cf. HANDOFF.
    if vendor and model and (vendor.strip(), model.strip()) in _ENERGY_METER_VENDOR_MODELS:
        return "energy-meter"
    types = [e.get("type", "") for e in exposes]
    names = [e.get("name", "") for e in exposes]
    if "light" in types: return "light"
    if "switch" in types: return "switch"
    if "cover" in types: return "cover"
    if "climate" in types or "thermostat" in types: return "thermostat"
    if "lock" in types: return "lock"
    if "fan" in types: return "fan"
    # "valve" existe comme type Z2M standard mais AUCUN device du catalogue actuel
    # (4436 réels, audit 2026-08-19) ne l'utilise au niveau top-level — gardé par
    # sécurité/cohérence avec notre propre DeviceType "valve", coûte rien.
    if "valve" in types: return "valve"
    # Vannes d'irrigation/gaz Tuya — jamais de type "valve"/"cover" standard chez
    # Z2M pour ces modèles (exposes tout en binary/numeric/enum custom), donc
    # identification par (vendor, model), même principe que les compteurs
    # d'énergie. Repérés lors de l'audit du 2026-08-19 : GIEX QT06 (1 vanne,
    # expose "state"), GIEX GX03 (2 vannes indépendantes, "valve_1"/"valve_2" —
    # seule la 1ère devient l'état principal, la 2e reste visible en entité
    # secondaire générique comme tout device multi-mesures), QOTO QT-05M
    # ("valve_state"), ShinaSystem GCM-300Z (vanne de coupure GAZ, pas eau —
    # même sémantique ouverte/fermée, "gas_valve_state").
    if vendor and model and (vendor.strip(), model.strip()) in {
        ("GIEX", "QT06_1"), ("GIEX", "QT06_2"), ("GIEX", "GX03"),
        ("QOTO", "QT-05M"), ("ShinaSystem", "GCM-300Z"),
    }:
        return "valve"
    # Chauffage fil pilote français (standard 6 fils, Legrand/NodOn confirmés dans
    # le code source zigbee-herdsman-converters, 2026-08-19) — signal exact et
    # sans ambiguïté, jamais utilisé pour autre chose.
    if "pilot_wire_mode" in names: return "heating-relay"
    # Détecteur fumée/CO/gaz — enjeu sécurité, sémantique dédiée (cf. types/index.ts).
    # Noms trouvés en conditions réelles à l'audit : "smoke" (Xiaomi JTYJ-GD-01LM/BW,
    # Slacky-DIY, Aqara JY-GZ-01AQ), "gas" (Aqara JT-BZ-01AQ/A — détecteur de gaz
    # naturel/méthane, pas CO — replié sur le même champ state.co par simplicité,
    # cf. commentaire types/index.ts), "carbon_monoxide"/"co" (eWeLink
    # CK-TLSR8656-SS5-01(7037)).
    if any(n in ("smoke", "gas", "carbon_monoxide", "co") for n in names): return "smoke-co"
    # Chargeur de véhicule électrique — un seul device Zigbee réel trouvé à l'audit
    # (Futurehome Charge), identification par vendor/model comme les autres cas
    # sans signal exposes générique.
    if vendor and model and (vendor.strip(), model.strip()) == ("Futurehome", "Charge"):
        return "evse"
    # Compteurs d'utilité NON électriques (gaz/eau/chaleur par comptage
    # d'impulsions) — Develco ZHEMI101 (gaz+eau+chauffage, exposes "gas"/
    # "water_consumed"/"flow" en plus d'"energy" — un vrai compteur multi-fluide,
    # classé ici plutôt qu'"energy-meter" car son usage principal chez un client
    # est le suivi gaz/eau, pas électrique), Tuya TS0601_heat_meter (chauffage
    # collectif/calories, "cumulative_heat"/"water_consumed").
    if vendor and model and (vendor.strip(), model.strip()) in {
        ("Develco", "ZHEMI101"), ("Tuya", "TS0601_heat_meter"),
    }:
        return "utility-meter"
    # Présence (radar mmWave) traité comme "motion" — audit complet du catalogue
    # Zigbee2MQTT le 2026-08-19 (4436 devices réels, zigbee-herdsman-converters,
    # pas un échantillon) : 45+ capteurs de présence radar réels et vendus
    # aujourd'hui (Aqara FP1E/FP2, gamme Tuya ZY-M100/ZG-205x, HOBEIAN, etc.)
    # exposent "presence" au lieu de "occupancy"/"motion" et tombaient tous en
    # sensor-generic. Sémantiquement équivalent pour nous (même besoin : quelqu'un
    # est-il dans la pièce), déjà géré côté normalisation d'état HA
    # (_ha_attributes_to_normalized traite déjà device_class "presence" comme
    # "motion" depuis le début — seule la détection du TYPE ici avait un trou).
    if "occupancy" in names or "motion" in names or "presence" in names: return "sensor-motion"
    # "contact_alarm_1"/"contact_alarm_2" (EZVIZ CS-T2C, même audit) : variante
    # non-standard mais un vrai capteur d'ouverture.
    if "contact" in names or any(n.startswith("contact_alarm") for n in names): return "sensor-contact"
    # "water_leak_alarm_1"/"water_leak_alarm_2" (ADEO/BlitzWolf/Sunricher, même
    # audit) : 3 vrais détecteurs de fuite avec un nom non-standard.
    if any(n == "water_leak" or n.startswith("water_leak_alarm") for n in names): return "sensor-water"
    # Capteur de comptage de personnes (ShinaSystem CSM-300ZB/CSM-300ZB_V2,
    # audit 2026-08-19) — expose top-level "people" (numérique), sémantique
    # différente de sensor-motion (présent/absent binaire). Vérifié dans le
    # catalogue réel (zigbee-herdsman-converters) : exposes = battery,
    # battery_voltage, enum "status" (idle/in/out), numeric "people".
    if "people" in names: return "people-counter"
    # (2026-09-04) VRAI BUG trouvé par Hicham (télécommande STYRBAR figée en
    # "sensor-generic", jamais reclassée malgré un recalcul correct à chaque
    # sync — cf. migration 0107 pour le fix côté upsert_zigbee_device) : en
    # creusant pourquoi le clavier d'alarme n'avait pas le même problème,
    # trouvé un 2e bug latent, masqué jusqu'ici UNIQUEMENT parce que le type
    # n'était jamais rafraîchi. Un clavier IAS ACE (cf. plus bas, "keypad")
    # expose LUI AUSSI un champ top-level nommé "action" (mêmes valeurs
    # disarm/arm_all_zones/... rangées DANS cet expose "action", pas un champ
    # à part) — le check générique ci-dessous aurait donc TOUJOURS classé un
    # clavier comme "remote" avant d'atteindre la règle "keypad" plus bas.
    # Cf. _exposes_match_ias_ace_keypad : elle cherche elle-même
    # expose.get("name") == "action", exactement la même signature. Le check
    # spécifique clavier doit donc être évalué EN PREMIER, jamais après.
    if _exposes_match_ias_ace_keypad(exposes, {"disarm", "arm_all_zones"}):
        return "keypad"
    # Télécommande/bouton de scène (2026-08-27, audit 2026-08-19 : 284 devices
    # réels rien que dans le catalogue, très répandu) — expose top-level
    # "action" (enum single/double/hold…) sans aucun autre signal actionnable
    # (déjà éliminé par les checks light/switch/cover/climate/lock/fan/valve
    # au-dessus, ET désormais par le check clavier juste au-dessus). Pas
    # d'état à afficher, cf. commentaire DeviceType "remote" côté web — juste
    # reconnu pour servir de source de déclencheur.
    if "action" in names: return "remote"
    if "temperature" in names or "humidity" in names: return "sensor-temp"
    # Serrure Tuya sans expose "lock" standard (easyiot ZB-ZL01, même audit) —
    # signature `lock_status`/`unlock_door` propre à ce modèle mais sans
    # ambiguïté possible avec un autre type.
    if "lock_status" in names or "unlock_door" in names: return "lock"
    # Sirène : signal fiable = HA a déjà créé l'entité native siren.* pour ce
    # device — Z2M le fait pour tout appareil exposant "warning" depuis
    # Koenkk/zigbee2mqtt#31000 (vérifié source 2026-07-28), prioritaire sur
    # "outlet" (une sirène mal détectée remonterait sinon comme prise "plug").
    if ieee_address and ha_entities:
        if any(
            ieee_address in (e.get("unique_id") or "") and (e.get("entity_id") or "").startswith("siren.")
            for e in ha_entities
        ):
            return "siren"
    if "outlet" in types: return "plug"
    # Repli si l'entité HA n'est pas encore enregistrée (juste après appairage,
    # avant que Z2M/HA n'aient eu le temps de créer l'entité siren.*) : expose
    # top-level "warning" (composite) sur toutes les sirènes standard Z2M —
    # vérifié sur la doc Z2M (SIRZB-110, HS2WD-E). (2026-07-27)
    if "warning" in names: return "siren"
    # Sirènes qui n'utilisent PAS le composite "warning" standard (modèles NEO
    # notamment, ex: NAS-AB02B2 d'Hicham) — exposes top-level directs
    # alarm/melody/duration/volume au lieu d'un seul composite groupé. Trouvé en
    # vérifiant les devices déjà classés "switch" par erreur en base (2026-08-08,
    # suite à la question d'Hicham sur d'autres types mal classés) : "Alarme
    # entrée" (NEO NAS-AB02B2) n'a ni "warning" ni entité HA siren.* détectable,
    # tombait dans le repli générique — pourtant un vrai boîtier sirène, cible
    # potentielle de l'action matérielle sur déclenchement. Combinaison
    # melody+duration+volume est un signal fort et peu ambigu (rarement présent
    # ensemble sur un device qui ne serait pas une sirène).
    if {"melody", "duration", "volume"}.issubset(names): return "siren"
    # 3 variantes supplémentaires trouvées lors de l'audit complet du catalogue
    # (2026-08-19, 4436 devices réels) — mêmes principes que ci-dessus (signal
    # fort et peu ambigu), noms de propriété différents selon le fabricant :
    # Bosch BSIR-EZ (sirène extérieure solaire), eWeLink NAS-AB03B3/NAS-AB06B3
    # ("alarm_duration" au lieu de "duration"), SONOFF SNZB-09P ("siren_on"
    # explicite, signal fort à lui seul).
    if {"siren_volume", "siren_duration"}.issubset(names): return "siren"
    if {"melody", "alarm_duration", "volume"}.issubset(names): return "siren"
    if "siren_on" in names: return "siren"
    # Clavier d'alarme — détection déplacée plus haut (2026-09-04, cf. son
    # commentaire juste après le check "people"), doit être évaluée AVANT la
    # règle générique "action" -> "remote" puisqu'un clavier IAS ACE expose
    # lui aussi un champ nommé "action".
    # Repli sûr (bug de fond, pas juste le clavier — question directe d'Hicham,
    # 2026-08-08 : "est-ce que ça fera la même chose pour un autre type qui ne
    # saurait pas se classer ?"). Réponse : oui, avant ce fix — "switch" était le
    # repli final pour TOUT type non reconnu, donnant un faux bouton marche/arrêt
    # à n'importe quel appareil non-actionneur qu'on n'a pas encore anticipé
    # (vibration, fumée, CO, télécommande à boutons…), pas seulement le clavier.
    # Exactement le même bug déjà trouvé et corrigé côté Matter en conditions
    # réelles (_extract_matter_device_info ci-dessus, "moniteur qualité d'air
    # affiché comme actionneur") — jamais reporté ici. "sensor-generic" est le
    # même repli sûr : ses mesures/entités s'affichent génériquement (device_entities),
    # jamais de faux toggle. Un vrai switch/plug Zigbee n'atteint jamais ce repli —
    # Z2M expose toujours son type "switch"/"outlet" en top-level par convention,
    # déjà attrapé plus haut.
    return "sensor-generic"


def _sync_zigbee_devices_direct(devices_list) -> bool:
    """pi_sync_devices (protocole "zigbee") via Supabase direct — True si réussi.
    Réplique le filtrage (coordinateur/interview non terminée exclus) fait par
    la route Vercel. Basculé de pi_sync_zigbee_devices (RPC dédiée, toujours en
    place mais plus appelée par l'add-on) vers la RPC générique le 2026-09-21,
    cf. chantier d'harmonisation Zigbee/Matter/WiFi."""
    global _z2m_friendly_to_ieee
    try:
        payload_devices = []
        friendly_to_ieee: dict[str, str] = {}
        ha_entities = None  # chargé paresseusement, une seule fois pour toute la synchro
        for d in devices_list:
            if d.get("type") == "Coordinator": continue
            if not d.get("interview_completed"): continue
            ieee = d.get("ieee_address")
            if not ieee: continue

            definition = d.get("definition") or {}
            exposes = definition.get("exposes") or []
            if ha_entities is None:
                result = _ha_ws_call("config/entity_registry/list")
                ha_entities = result.get("result", []) if result and result.get("success") else []
            device_type = _detect_device_type(
                exposes, ieee_address=ieee, ha_entities=ha_entities,
                vendor=definition.get("vendor"), model=definition.get("model"),
            )
            friendly_name = d.get("friendly_name")
            default_name = friendly_name if (friendly_name and friendly_name != ieee) \
                else (definition.get("model") or ieee)
            if friendly_name:
                friendly_to_ieee[friendly_name] = ieee

            payload_devices.append({
                "ieee_address": ieee, "name": default_name, "z2m_name": friendly_name,
                "type": device_type, "vendor": definition.get("vendor") or "",
                "model": definition.get("model") or "", "features": exposes,
                # (2026-09-03) power_source Zigbee natif (cluster PowerSource, ex:
                # "Mains (single phase)"/"Battery"/"Emergency mains constantly
                # powered" pour un device secteur AVEC batterie de secours) — déjà lu
                # juste en dessous pour _boost_device_reporting, transmis ici en plus
                # pour le badge secteur/pile de l'app (purement informatif, jamais
                # utilisé pour online/alerts).
                "power_source": d.get("power_source") or "",
            })

            # (2026-09-01) Reporting "temps réel" appliqué AUTOMATIQUEMENT à tout
            # device Zigbee exposant une mesure standard (électrique, environnement,
            # batterie), sur CE site comme sur tout autre — pas un correctif manuel
            # réservé au site de test (Hicham : "l'app web ainsi que l'addon ont pour
            # but d'être proposés aux clients"). Une seule fois par ieee depuis le
            # démarrage du process (_boosted_ieees) — cf. _boost_device_reporting pour
            # le détail (dont le garde-fou "pile" sur les attributs battery_sensitive).
            # En thread séparé : jusqu'à 11 attentes de 8s chacune dans le pire cas, ne
            # doit jamais ralentir cette synchro (démarrage + toutes les 5 min).
            if ieee not in _boosted_ieees:
                exposed_props = {e.get("property") for e in exposes if isinstance(e, dict)}
                if exposed_props & set(_REPORTING_ATTRS.keys()):
                    _boosted_ieees.add(ieee)
                    power_source = d.get("power_source")
                    threading.Thread(
                        target=_boost_device_reporting,
                        args=(ieee, exposes, power_source, BATTERY_REPORTING_SECONDS),
                        daemon=True,
                    ).start()

            # Module LiXee ZLinky_TIC (lecture Linky) : certaines de ses mesures
            # sont en lecture seule/non-"reportable" côté Zigbee et dépendent
            # du polling ACTIF de Z2M (measurement_poll_interval, 600s par
            # défaut, cf. _configure_zlinky_tic_polling) — hors du mécanisme
            # _boost_device_reporting ci-dessus (reporting Zigbee standard,
            # jamais applicable ici). Une seule fois par ieee, même logique
            # d'idempotence que _boosted_ieees.
            if (ieee not in _tic_poll_configured
                    and definition.get("vendor") == "LiXee"
                    and definition.get("model") == "ZLinky_TIC"):
                _tic_poll_configured.add(ieee)
                threading.Thread(
                    target=_configure_zlinky_tic_polling_logged, args=(ieee,), daemon=True,
                ).start()

        # Reconstruit entièrement à chaque synchro plutôt qu'un merge — gère
        # naturellement les renommages/suppressions sans entrée périmée.
        _z2m_friendly_to_ieee = friendly_to_ieee

        # SOS + armement/désarmement clavier — best-effort, ne doit jamais faire
        # échouer la synchro principale des devices si Alarmo/HA est momentanément
        # indisponible.
        try:
            _ensure_alarmo_sos_automation(devices_list)
        except Exception as exc:
            warn(f"[alarmo] SOS automation: {exc}")
        try:
            _ensure_alarmo_keypad_control(devices_list)
        except Exception as exc:
            warn(f"[alarmo] Keypad automation: {exc}")

        # Harmonisation Zigbee/Matter/WiFi (chantier approuvé, 2026-09-21) —
        # bascule vers pi_sync_devices générique. `online` volontairement absent
        # ici : cf. docstring de _normalize_device, la synchro Zigbee n'a jamais
        # eu de signal de présence fiable à ce stade (contrairement à Matter/
        # WiFi) — la RPC laisse online/alertes intacts pour ces lignes, comme
        # upsert_zigbee_device le fait déjà.
        normalized = [
            _normalize_device(
                "zigbee",
                external_id=d["ieee_address"], name=d["name"], type_=d["type"],
                vendor=d["vendor"], model=d["model"],
                extra={
                    "z2m_name": d["z2m_name"],
                    "features": d["features"],
                    "power_source": d["power_source"],
                },
            )
            for d in payload_devices
        ]
        return _sync_devices_to_supabase("zigbee", normalized, timeout=30)
    except Exception as e:
        warn(f"[supabase] pi_sync_devices(zigbee): {e}")
        return False


def _sync_devices_to_app(devices_list):
    """Background thread : envoie la liste bridge/devices pour upsert auto (Supabase
    direct). En cas d'échec : log, retenté au prochain cycle périodique."""
    _sync_zigbee_devices_direct(devices_list)


def on_local_message(client, userdata, msg):
    """Messages reçus depuis Mosquitto local (Z2M). Plus aucun relais d'état vers le cloud (lot D, phase 1) : l'app du Pi lit HA
    directement ; seuls la liste des équipements (bridge/devices) et la santé de Z2M (heartbeat) partent encore."""
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

    # ── Réponse au health_check de Zigbee2MQTT (cf. _health_probe_z2m) : seule PRÉSENCE d'une réponse compte
    if topic == "zigbee2mqtt/bridge/response/health_check":
        _z2m_health_event.set()
        return

    # ── Réponse à une demande de reporting/configure (cf. _handle_zigbee_boost_reporting)
    if topic == "zigbee2mqtt/bridge/response/device/reporting/configure":
        try:
            resp = json.loads(payload.decode())
            rdata = resp.get("data") or {}
            key = (rdata.get("id"), rdata.get("cluster"), rdata.get("attribute"))
            with _reporting_configure_lock:
                _reporting_configure_results[key] = resp
                ev = _reporting_configure_events.get(key)
            if ev:
                ev.set()
        except Exception as exc:
            warn(f"[zigbee-reporting] parse error: {exc}")
        return

    # ── Réponse à une demande d'options device (cf. _configure_zlinky_tic_polling)
    if topic == "zigbee2mqtt/bridge/response/device/options":
        try:
            resp = json.loads(payload.decode())
            rdata = resp.get("data") or {}
            ieee = rdata.get("id")
            with _options_configure_lock:
                _options_configure_results[ieee] = resp
                ev = _options_configure_events.get(ieee)
            if ev:
                ev.set()
        except Exception as exc:
            warn(f"[zigbee-options] parse error: {exc}")
        return

    # ── Z2M bridge/devices → auto-registration dans Supabase ─────────────────
    if topic == "zigbee2mqtt/bridge/devices":
        try:
            devices_list = json.loads(payload.decode())
            if isinstance(devices_list, list):
                global _last_z2m_devices_list
                _last_z2m_devices_list = devices_list
                threading.Thread(
                    target=_sync_devices_to_app, args=(devices_list,), daemon=True
                ).start()
        except Exception as exc:
            warn(f"[devices-sync] parse error: {exc}")
        return

    # ── Z2M état individuel d'un device → valeurs réelles des exposes (battery,
    # linkquality, action...) — cf. _report_zigbee_state_direct ci-dessus. Topic
    # exact "zigbee2mqtt/{friendly_name}", sans rien après (ni /availability, déjà
    # géré au-dessus, ni /set — jamais republié par Z2M, uniquement publié PAR
    # nous en sortie) ; exclut aussi bridge/* (logging, response, extensions...).
    # Un friendly_name introuvable dans le cache (ex: message d'un GROUPE Z2M,
    # pas un device) est silencieusement ignoré — comportement attendu, pas une
    # erreur : seuls les vrais devices ont une ligne `devices.ieee_address`.
    if topic.startswith("zigbee2mqtt/") and "/" not in topic[len("zigbee2mqtt/"):]:
        friendly_name = topic[len("zigbee2mqtt/"):]
        ieee = _z2m_friendly_to_ieee.get(friendly_name)
        if ieee:
            try:
                raw_state = json.loads(payload.decode())
                if isinstance(raw_state, dict):
                    # Cache LOCAL (2026-09-08, gap "device sans entité utilisable") : la seule source
                    # disponible pour _build_local_devices(). Depuis le lot D (phase 1) ce n'est plus envoyé au cloud.
                    _last_z2m_raw_state[ieee] = raw_state
            except Exception as exc:
                warn(f"[zigbee-state] parse error ({friendly_name}): {exc}")
        return


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
    via l'API JSON structurée (GET /api/streams, `{name: {producers: [{"url": ...}]}}`,
    cf. code source internal/streams/stream.go MarshalJSON/producer.go). Best-effort :
    toute erreur renvoie False (traité comme "pas encore synchronisé" par l'appelant)."""
    try:
        r = requests.get(f"{GO2RTC_API_BASE}/api/streams", auth=GO2RTC_API_AUTH, timeout=5)
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
    """Vérifie que chaque caméra suivie (_cameras) est bien enregistrée côté go2rtc ;
    sinon redémarre Frigate pour forcer une régénération propre depuis notre vraie
    config, plutôt que d'écrire à chaud dans /config/go2rtc_homekit.yml.

    Nécessaire après un redémarrage go2rtc : le prepare script de Frigate ne recopie
    /homeassistant/frigate.yml vers sa config privée QUE si celle-ci est absente (1er
    démarrage seulement) — jamais ensuite. go2rtc peut donc repartir avec un registre
    de flux périmé par rapport à notre suivi interne (_cameras/cameras.json).

    ⚠️ NE PLUS UTILISER PUT /api/streams ici (cf. HANDOFF §63) — cause réelle,
    confirmée en lisant le VRAI fichier /config/go2rtc_homekit.yml puis le script
    officiel de Frigate (docker/main/rootfs/etc/s6-overlay/s6-rc.d/go2rtc/run,
    fonction setup_homekit_config()) : ce fichier est réservé par Frigate à SA PROPRE
    fonctionnalité HomeKit — à CHAQUE démarrage de go2rtc, AVANT même que go2rtc ne
    lise le fichier, ce script convertit son contenu en JSON et, s'il ne trouve pas de
    clé "homekit", VIDE ENTIÈREMENT LE FICHIER (`: > "${config_path}"`). Tout ce que
    PUT /api/streams y avait persisté (via app.PatchConfig côté go2rtc) est donc
    systématiquement détruit au redémarrage suivant — expliquant pourquoi 3 tentatives
    successives (§58/§59/§60/§62, dont une vérifiée contre l'API JSON structurée de
    go2rtc) n'ont jamais tenu au-delà du tout premier boot après un reset : le
    problème n'a jamais été LA FRÉQUENCE de nos écritures, mais leur EXISTENCE MÊME
    dans ce fichier précis, qui n'est simplement pas fait pour ça. Le seul mécanisme
    fiable reste celui déjà vérifié à plusieurs reprises cette session : notre vrai
    frigate.yml → config privée Frigate (une fois, cf. §57) → /dev/shm/go2rtc.yaml
    régénéré PROPREMENT à CHAQUE démarrage du conteneur — jamais touché par le script
    HomeKit (fichier différent). D'où : un redémarrage complet plutôt qu'un patch à
    chaud dès qu'un écart est détecté."""
    with _camera_configure_lock:
        if not _cameras:
            return
        missing = [name for name, url in _cameras.items() if not _go2rtc_stream_already_persisted(name, url)]
    if not missing:
        return
    log(f"[frigate] Caméra(s) absente(s) de go2rtc ({', '.join(missing)}) — redémarrage pour resynchroniser…")
    restart_frigate()


_GO2RTC_API_ORIGIN_FIX_V5_MARKER = "/data/.go2rtc_api_origin_fixed_v5"


def _fix_go2rtc_api_origin_once():
    """Réinstalle Frigate proprement pour repartir d'un fichier de config "primaire"
    go2rtc (/config/go2rtc_homekit.yml) vierge.

    v5 de ce correctif. v1-v4 (markers _fixed/_v2/_v3/_v4) traitaient chacune une
    cause réelle mais partielle : fiabilité des écritures (v1-v3), puis suppression
    complète des écritures elles-mêmes (v4, §63/§64) — corruption toujours revenue en
    conditions réelles le 2026-07-22, cette fois sans AUCUNE écriture en cause :
    _ensure_frigate() enchaînait un redémarrage Frigate "de routine" (quirk de timing
    du slug, cf. son propre code) puis, immédiatement après, un second redémarrage
    déclenché par _resync_go2rtc_streams() (caméras jugées "absentes" juste après le
    1er redémarrage, probablement une lecture trop précoce de l'état go2rtc) — deux
    redémarrages Frigate quasi simultanés, correspondant exactement au moment où la
    corruption réapparaissait dans les logs. Hypothèse retenue (§65) : une course
    d'accès fichier entre l'ancien processus go2rtc qui termine et le nouveau qui
    démarre, tous deux sur /config/go2rtc_homekit.yml. Fix : _ensure_frigate() ne
    déclenche plus JAMAIS _resync_go2rtc_streams() dans la même itération qu'un
    (re)démarrage déjà effectué — cf. son code, variable `just_restarted`. Ce reset
    (nouveau marker _v5) nettoie une dernière fois la corruption accumulée par ce
    nouveau mécanisme. One-shot — nouvelles installations : rien à corriger.

    Appelée depuis _ensure_frigate() APRÈS la branche d'état (donc potentiellement sur
    un Frigate jugé "opérationnel" à cet instant précis) — sans réinstallation
    immédiate ici, Frigate resterait désinstallé jusqu'au tout prochain boot de
    l'addon (install_frigate() n'est appelé par _ensure_frigate() que dans les
    branches "absent"/"error", jamais dans la branche "tout va bien"). D'où l'appel
    direct à install_frigate() ci-dessous plutôt que de compter sur le tour de
    boucle suivant."""
    if os.path.exists(_GO2RTC_API_ORIGIN_FIX_V5_MARKER):
        return
    if _is_addon_installed(FRIGATE_SLUG):
        log("[frigate] Reset du fichier de config primaire go2rtc (course entre deux redémarrages successifs, cf. HANDOFF §65) — réinstallation propre…")
        r = sup_post(f"/addons/{FRIGATE_SLUG}/uninstall", {"remove_config": True}, timeout=120)
        log(f"[frigate] Désinstallation (reset config primaire go2rtc v5) → {r.status_code} {r.text[:150]}")
        time.sleep(10)
        install_frigate()
    open(_GO2RTC_API_ORIGIN_FIX_V5_MARKER, "w").close()


def _ensure_frigate():
    """Installe et démarre Frigate + go2rtc s'ils sont absents ou arrêtés.
    Appelé en thread de fond au démarrage du bridge — permet de lancer Frigate
    sur une installation existante sans déclencher un force_setup complet.
    Réessaie toutes les 5 min en cas d'échec (timeout Supervisor, réseau lent…)."""
    for attempt in range(1, 6):
        try:
            state = _frigate_state()
            just_restarted = False
            if not _is_addon_installed(FRIGATE_SLUG):
                log(f"[frigate] Frigate absent — installation automatique… (tentative {attempt}/5)")
                install_frigate()
                just_restarted = True
            elif state == "error":
                warn(f"[frigate] Frigate en état error — réinstallation propre… (tentative {attempt}/5)")
                sup_post(f"/addons/{FRIGATE_SLUG}/uninstall", timeout=120)
                time.sleep(15)
                install_frigate()
                just_restarted = True
            elif not _is_addon_running(FRIGATE_SLUG):
                log("[frigate] Frigate installé mais arrêté — configuration port + démarrage…")
                _configure_frigate_and_start()
                just_restarted = True
            elif not _frigate_go2rtc_ready():
                log("[frigate] Frigate en cours mais go2rtc indisponible — reconfiguration…")
                _configure_frigate_and_start()
                just_restarted = True
            else:
                log("[frigate] ✓ Frigate et go2rtc opérationnels")
                threading.Thread(target=_setup_frigate_auth_once, daemon=True).start()
            _fix_go2rtc_api_origin_once()
            # Ne pas ré-évaluer/redémarrer juste après un (re)démarrage déjà effectué
            # dans cette même itération — cf. HANDOFF §65 : deux redémarrages Frigate
            # coup sur coup (celui-ci juste après un autre) ont provoqué une corruption
            # du fichier de config primaire go2rtc, probablement une course d'accès
            # fichier entre l'ancien processus qui termine et le nouveau qui démarre.
            # Un (re)démarrage tout juste effectué a déjà rechargé les caméras depuis
            # notre config réelle — inutile de re-vérifier immédiatement après.
            if not just_restarted:
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
    "lock":          {"lock", "unlock", "open"},
    "fan":           {"turn_on", "turn_off", "toggle", "set_percentage"},
    "valve":         {"open_valve", "close_valve", "stop_valve", "set_valve_position", "toggle"},
    "humidifier":    {"turn_on", "turn_off", "toggle", "set_humidity"},
    # Ajouté 2026-08-19 pour le chauffage fil pilote (heating-relay) — le service
    # générique existe déjà côté web (entityCommand.ts, command "select", construit
    # pour les entités secondaires §161) mais n'était jamais whitelisté ici pour une
    # entité PRINCIPALE : un select en entité primaire (pilot_wire_mode) n'existait
    # pas avant ce type. Service standard HA, un seul nom quel que soit le domaine
    # d'origine du device.
    "select":        {"select_option"},
    "media_player":  {"turn_on", "turn_off", "volume_set", "media_play", "media_pause"},
    "homeassistant": {"turn_on", "turn_off", "toggle"},
    # Les "scènes" de l'app sont implémentées côté HA comme de vraies scènes
    # natives (scene.domoticium_scene_..., cf. api/scenes/[id]/activate côté
    # web) depuis le 2026-10-18 — avant cette date, c'était des scripts
    # (script.domoticium_scene_...), d'où l'entrée "script" ci-dessous, gardée
    # pour les scripts HA bruts qu'un client peut cibler directement (pas
    # Domoticium) depuis une action d'alarme/automatisation.
    "scene":         {"turn_on"},
    # "script" était absent de cette liste blanche à l'origine, donc chaque
    # activation de scène (alors un script) était rejetée en 403 (trouvé en
    # conditions réelles le 2026-07-26, après un signalement d'Hicham : le
    # bouton "Activer" ne faisait rien) — gardé depuis pour les scripts HA
    # bruts (pas seulement l'ancien mécanisme de scène).
    "script":        {"turn_on", "turn_off", "toggle"},
    # alarm_control_panel RETIRÉ le 2026-09-22 (audit add-on) : cette entrée
    # permettait de contourner ENTIÈREMENT handle_alarmo_set_panel_state() via
    # la route générique /command — Alarmo répond 200 OK côté HA même quand un
    # code est refusé en interne (cf. docstring de cette fonction), et la route
    # générique ne relit jamais l'état avant/après pour détecter ce faux-succès.
    # Un appelant utilisant /command pour armer/désarmer recevait donc "ok"
    # même si RIEN n'a été armé/désarmé — risque de sécurité physique réel.
    # Vérifié avant suppression : aucun code web n'utilise plus ce chemin
    # (grep exhaustif sur "alarm_control_panel." dans web/src — seuls 2
    # commentaires obsolètes, code réel déjà migré vers la route dédiée
    # /alarmo/set-panel-state, cf. haAlarmoSetPanelState côté web).
    # Ajouté 2026-08-27 pour le toggle activer/désactiver des automatisations
    # importées depuis HA (import bidirectionnel, cf. handle_list_ha_automations
    # plus haut) — absent jusqu'ici, un appel automation.turn_on/turn_off était
    # rejeté en 403.
    "automation":    {"turn_on", "turn_off", "toggle"},
}

# (2026-11-09) Services supplémentaires autorisés UNIQUEMENT pour les 2 automatisations
# internes de câblage clavier/SOS Alarmo (_ensure_alarmo_sos_automation,
# _ensure_alarmo_keypad_control) — JAMAIS pour la route /ha-command app-facing ni pour
# aucun autre appelant. Bug réel trouvé en conditions réelles (2026-11-09, clavier Frient
# réappairé) : alarm_control_panel avait été retiré d'ALLOWED_SERVICES le 2026-09-22 pour
# fermer un vrai trou de sécurité côté route générique /command (cf. son commentaire) —
# mais _validate_ha_action_steps() est la MÊME fonction utilisée pour automation_upsert,
# donc ce retrait bloquait AUSSI ces 2 automatisations internes, légitimes et sûres
# (action/payload 100% construits en Python ici, jamais depuis une requête web/client —
# alarm_control_panel.alarm_* passe le code tapé à Alarmo qui reste seul juge, exactement
# la méthode officiellement recommandée par Alarmo pour un clavier physique ; mqtt.publish
# cible un topic et un payload entièrement fixés par ce code, jamais une valeur entrée par
# l'appelant). Le rejet silencieux (retour False jamais vérifié par ces 2 appelants, cf.
# docstring _handle_ha_command) a fait croire pendant toute une session de debug à un
# problème de détection Zigbee/Z2M, alors que la détection était correcte du début à la fin.
_TRUSTED_WIRING_SERVICES = {
    "alarm_control_panel": {"alarm_disarm", "alarm_arm_home", "alarm_arm_night", "alarm_arm_away", "alarm_trigger"},
    "mqtt": {"publish"},
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

# Flux secondaire ("sous-flux") — même caméra, résolution/débit plus faible, pensé pour
# les connexions faibles (§87, sélection de qualité en direct). Généré depuis le MÊME
# modèle que _RTSP_TEMPLATES ci-dessus, jamais testé en direct au moment de l'ajout —
# contrairement au flux principal (réellement connecté via _probe_rtsp_url), tester
# aussi celui-ci ouvrirait une 2e connexion RTSP juste après la première vers une
# caméra qui n'en accepte peut-être qu'une à la fois (cf. §76/§77) ; la bascule de
# qualité elle-même (côté web, /api/cameras/[id]/quality) ne maintient jamais deux
# connexions en parallèle non plus — un seul flux actif à la fois, reconfiguré et
# reconnecté au changement. axis/vivotek/pelco/tplink/foscam/ezviz ajoutés en §89
# (bis) après vérification de la convention officielle de chaque marque (doc
# fabricant/support officiel — pas une supposition). Toujours absents : flir (le
# support officiel dit explicitement que le chemin varie par modèle, pas de
# convention générique) et dlink (play1.sdp/play2.sdp semblent liés au codec
# MJPEG/H.264, pas clairement à un palier de qualité) — plutôt que de deviner au
# hasard, bascule de qualité simplement indisponible pour ces deux marques.
_RTSP_SUB_TEMPLATES = {
    "hikvision": "rtsp://admin:MOTDEPASSE@{ip}:554/Streaming/Channels/102",
    "dahua":     "rtsp://admin:MOTDEPASSE@{ip}:554/cam/realmonitor?channel=1&subtype=1",
    "amcrest":   "rtsp://admin:MOTDEPASSE@{ip}:554/cam/realmonitor?channel=1&subtype=1",
    "imou":      "rtsp://admin:MOTDEPASSE@{ip}:554/cam/realmonitor?channel=1&subtype=1",
    "lorex":     "rtsp://admin:MOTDEPASSE@{ip}:554/cam/realmonitor?channel=1&subtype=1",
    "reolink":   "rtsp://admin:MOTDEPASSE@{ip}:554/h264Preview_01_sub",
    "uniview":   "rtsp://admin:MOTDEPASSE@{ip}:554/media/video2",
    "hanwha":    "rtsp://admin:MOTDEPASSE@{ip}:554/profile2/media.smp",
    "bosch":     "rtsp://admin:MOTDEPASSE@{ip}:554/video?inst=2",
    "swann":     "rtsp://admin:MOTDEPASSE@{ip}:554/Streaming/Channels/102",
    "annke":     "rtsp://admin:MOTDEPASSE@{ip}:554/Streaming/Channels/102",
    "pelco":     "rtsp://admin:MOTDEPASSE@{ip}:554/stream2",
    "tplink":    "rtsp://admin:MOTDEPASSE@{ip}:554/stream2",                      # Tapo / VIGI
    "foscam":    "rtsp://admin:MOTDEPASSE@{ip}:554/videoSub",
    "ezviz":     "rtsp://admin:MOTDEPASSE@{ip}:554/h264/ch1/sub/av_stream",
    "vivotek":   "rtsp://root:MOTDEPASSE@{ip}:554/live2.sdp",
    # Axis n'a pas de 2e chemin dédié — même endpoint que le flux principal, avec un
    # paramètre de résolution (mécanisme officiel VAPIX). 640x480 est un choix prudent
    # (supporté par la quasi-totalité des modèles Axis), pas garanti optimal partout.
    "axis":      "rtsp://root:MOTDEPASSE@{ip}/axis-media/media.amp?resolution=640x480",
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

        # Courte pause avant la sonde de capacités : cette même caméra vient déjà de
        # recevoir 3-4 appels ONVIF dos-à-dos ci-dessus (GetDeviceInformation,
        # GetCapabilities, GetProfiles, GetStreamUri) — confirmé en conditions réelles
        # le 2026-07-24 (§70) : capabilities=[] alors même que le cache scan a bien été
        # réutilisé au test suivant (donc le problème n'est pas scan-vs-test, déjà
        # corrigé en v2.9.24, mais une collision À L'INTÉRIEUR du scan lui-même, sur
        # une caméra qui n'accepte qu'une session ONVIF à la fois).
        time.sleep(0.5)
        caps = _onvif_capabilities_from_xaddr(xaddr)
        _scan_capabilities_cache[ip] = (time.time(), caps)
        results.append({
            'ip':           ip,
            'manufacturer': manufacturer,
            'model':        model,
            'name':         (f'{manufacturer} {model}'.strip()) or f'Caméra {ip}',
            'rtspUrl':      rtsp_url,
            'capabilities': caps,
        })
    log(f'[onvif-scan] {len(results)} caméra(s) ONVIF confirmée(s) sur {len(xaddrs)} IP(s) scannée(s)')
    return results


# ── Capacités caméra (PTZ, audio bidirectionnel, sortie relais) — pré-remplissage,
# jamais activation automatique : le matériel grand public annonce parfois des
# capacités ONVIF qu'il ne supporte pas réellement (cf. lib/cameras/capabilities.ts
# côté web), donc ceci ne fait que pré-cocher des cases dans le formulaire d'ajout —
# l'installateur confirme.

def _onvif_capabilities_from_xaddr(device_xaddr: str, timeout: float = 3.0, username: str = '', password: str = '') -> list:
    """Détecte PTZ/zoom (axes réellement supportés par le nœud PTZ, cf. ci-dessous) et
    microphone (source audio réelle, cf. GetAudioSources ci-dessous) à partir d'un
    device_service ONVIF déjà connu. Best-effort : liste vide si la caméra ne répond
    pas ou n'expose rien. Parler/haut-parleur/sirène retirés du produit le 2026-07-25
    (décision Hicham) — parler ne fonctionne pas de façon fiable sur RTSP standard
    (cf. §78), haut-parleur seul n'a pas de sens sans lui, sirène jamais vérifiée en
    conditions réelles. Seuls PTZ/zoom et microphone restent proposés à l'ajout.

    username/password optionnels : GetNodes (PTZ) et GetAudioSources (Media) sont tous
    deux Access Class READ_MEDIA dans les spécifications ONVIF officielles (vérifié
    directement dans les PDF PTZ/Media le 2026-07-24, à la demande d'Hicham, après que
    §70/§71/§72 aient épuisé les hypothèses de collision/timing sans jamais trouver la
    vraie cause). Seul GetCapabilities est PRE_AUTH. Sans WS-Security, une caméra qui
    applique correctement ces règles d'accès renvoie un Fault ou un corps vide plutôt
    qu'une erreur réseau franche — indiscernable en pratique d'une caméra qui n'a
    réellement aucun de ces services, d'où les échecs 100% silencieux observés
    jusqu'ici. Le scan réseau (_scan_onvif_cameras), lui, ne peut structurellement
    jamais fournir ces identifiants (aucun mot de passe saisi à ce stade) — la
    sonde à l'ajout/test, quand le mot de passe est connu, est donc la seule à
    pouvoir s'authentifier."""
    caps = set()
    header = _onvif_ws_security_header(username, password) if username and password else ''
    try:
        # Category explicite plutôt qu'omise : le scan (_scan_onvif_cameras) demande
        # déjà explicitement <tds:Category>Media</tds:Category> et obtient une réponse
        # complète pour cette même caméra quelques appels plus tôt — alors que cet
        # appel-ci, sans aucune Category, revenait systématiquement vide (§70/§71 :
        # confirmé en conditions réelles, aucune exception, aucune réponse anormalement
        # courte non plus, donc pas un problème de collision/timeout). La norme ONVIF
        # dit que Category omise doit valoir "All" par défaut, mais du firmware ONVIF
        # bon marché (très répandu, cf. Reolink) l'interprète parfois comme "Device
        # seulement" — explicite = plus fiable que de compter sur un défaut ambigu.
        xml = _onvif_soap(
            device_xaddr,
            '<tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            '<tds:Category>All</tds:Category>'
            '</tds:GetCapabilities>',
            timeout=timeout,
        )
    except Exception as e:
        # Volontairement journalisé (pas juste avalé) : ce best-effort a échoué en
        # silence à plusieurs reprises (§67-§69) sans jamais laisser de trace de LA
        # raison réelle — timeout ? connexion refusée ? réponse SOAP invalide ?
        # Nécessaire pour diagnostiquer objectivement plutôt que par supposition.
        warn(f'[onvif-capabilities] GetCapabilities {device_xaddr}: {e}')
        return []

    # Journalisé même en cas de succès apparent (pas d'exception) : une caméra
    # sous forte charge (juste après une rafale d'appels ONVIF/TCP précédente,
    # cf. _scan_onvif_cameras) peut répondre 200 avec un corps SOAP vide ou
    # tronqué plutôt que lever une erreur réseau — un cas jamais distingué
    # jusqu'ici d'une caméra qui n'a réellement aucun de ces services.
    if len(xml) < 200:
        warn(f'[onvif-capabilities] GetCapabilities {device_xaddr}: réponse suspicieusement courte ({len(xml)} caractères) — {xml!r}')
    elif not _xml_has_tag(xml, 'PTZ'):
        # Réponse "normale" en apparence mais sans section PTZ — utile à voir en clair
        # si le fix Category=All ne suffisait pas : contenu réel plutôt qu'une simple
        # taille, pour juger si la caméra n'a vraiment pas de PTZ ou si la réponse est
        # tronquée/incomplète d'une autre façon.
        log(f'[onvif-capabilities] {device_xaddr}: pas de tag PTZ — extrait réponse : {xml[:400]!r}')

    if _xml_has_tag(xml, 'PTZ'):
        # La présence du service PTZ dans GetCapabilities ne dit rien sur les axes
        # réellement motorisés — des caméras pan/tilt sans zoom optique/numérique
        # exposent quand même ce service, et notre ancien code ajoutait "zoom"
        # aveuglément dans tous les cas, faisant apparaître un bouton zoom inopérant
        # dans l'app (signalé par Hicham le 2026-07-22). GetNodes (lecture seule, pas
        # de token requis contrairement à GetConfigurationOptions) liste les espaces
        # de mouvement réellement supportés par le nœud PTZ — ContinuousPanTiltVelocitySpace
        # et ContinuousZoomVelocitySpace n'apparaissent que si l'axe correspondant existe.
        ptz_xaddr = ''
        for xa in _xml_all(xml, 'XAddr'):
            if 'ptz' in xa.lower():
                ptz_xaddr = xa
                break
        if ptz_xaddr:
            try:
                nxml = _onvif_soap(
                    ptz_xaddr,
                    '<tptz:GetNodes xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"/>',
                    timeout=timeout,
                    header=header,
                )
                if _xml_has_tag(nxml, 'ContinuousPanTiltVelocitySpace'):
                    caps.add('ptz')
                if _xml_has_tag(nxml, 'ContinuousZoomVelocitySpace'):
                    caps.add('zoom')
            except Exception as e:
                # GetNodes non supporté/exige une authentification sur cette caméra —
                # repli conservateur : le service PTZ existe donc on suppose au moins
                # pan/tilt, mais on n'ajoute plus zoom sans confirmation (c'était
                # justement le bug : zoom ajouté sans jamais être vérifié).
                warn(f'[onvif-capabilities] GetNodes {ptz_xaddr}: {e} — repli ptz seul')
                caps.add('ptz')
        else:
            caps.add('ptz')

    media_url = ''
    for xa in _xml_all(xml, 'XAddr'):
        if xa.startswith('http') and 'media' in xa.lower():
            media_url = xa
            break
    if media_url:
        # Micro (écoute du son ambiant) — un flux RTSP peut déclarer une piste audio
        # même sans micro physique réel (constaté en conditions réelles le 2026-07-25 :
        # "Camera exterieur" transmettait un flux audio AAC exploitable — silence ou
        # bruit de fond du capteur — sans micro intégré). GetAudioSources (lecture
        # seule) est le signal ONVIF dédié : liste vide si le device n'a réellement
        # aucune source audio. Comme les autres capacités ONVIF, purement indicatif —
        # le matériel grand public peut mentir dans un sens ou dans l'autre — d'où le
        # pré-remplissage + confirmation manuelle à l'ajout (cf. lib/cameras/capabilities.ts).
        try:
            asxml = _onvif_soap(
                media_url,
                '<trt:GetAudioSources xmlns:trt="http://www.onvif.org/ver10/media/wsdl"/>',
                timeout=timeout,
                header=header,
            )
            # 'AudioSources' (nom du champ réponse, répété une fois par élément selon
            # la convention ONVIF déjà observée sur GetRelayOutputs/RelayOutputs dans
            # ce fichier) plutôt que 'AudioSource' (nom du type) — les deux vérifiés
            # par sécurité, avec log si ni l'un ni l'autre ne matche pour diagnostiquer
            # au lieu de deviner une 3e fois (cf. §70-§73, même discipline).
            if _xml_has_tag(asxml, 'AudioSources') or _xml_has_tag(asxml, 'AudioSource'):
                caps.add('microphone')
            else:
                log(f'[onvif-capabilities] {media_url}: GetAudioSources sans tag AudioSource(s) — extrait réponse : {asxml[:400]!r}')
        except Exception as e:
            warn(f'[onvif-capabilities] GetAudioSources {media_url}: {e}')

    return sorted(caps)


def _probe_onvif_capabilities_by_ip(
    ip: str, timeout: float = 3.0, attempts: int = 2, retry_delay: float = 1.5,
    username: str = '', password: str = '',
) -> list:
    """Variante pour l'ajout manuel (IP connue, device_service ONVIF pas encore
    localisé) — essaie les ports ONVIF courants, sur 2 tentatives avant d'abandonner.
    Une caméra qui vient de répondre à un scan réseau ou un test précédent peut être
    momentanément occupée (connexion ONVIF concurrente, redémarrage Frigate qui vient
    de se produire) et ne pas répondre du premier coup — confirmé en conditions
    réelles le 2026-07-23 : caméra détectée avec succès par le scan quelques secondes
    plus tôt, puis capabilities=[] au test manuel suivant, sans aucune erreur visible
    côté utilisateur (best-effort, échec avalé en silence).

    Limité à 2 tentatives (pas plus) : l'appelant HTTP (route Next.js
    /api/cameras/test) a un maxDuration de 40s côté Vercel — dans le pire cas
    (caméra jamais jointe, 2 ports × ~4 appels ONVIF × timeout à chaque tentative),
    le budget total doit rester compatible avec cette limite, en plus du temps déjà
    consommé par le test RTSP principal qui s'exécute avant. Ne bloque jamais ce
    test principal, qui a son propre chemin — juste la détection de capacités, en
    complément, best-effort."""
    for attempt in range(1, attempts + 1):
        for port in (8000, 80):
            caps = _onvif_capabilities_from_xaddr(
                f'http://{ip}:{port}/onvif/device_service', timeout=timeout,
                username=username, password=password,
            )
            if caps:
                return caps
        if attempt < attempts:
            time.sleep(retry_delay)
    warn(f'[onvif-capabilities] {ip}: aucune capacité détectée après {attempts} tentative(s) — voir les échecs GetCapabilities ci-dessus')
    return []


def _safe_probe_capabilities(ip: str, username: str = '', password: str = '') -> list:
    """Ne doit jamais faire échouer le test de connexion caméra (résultat principal)
    si la sonde ONVIF de capacités plante ou traîne — pure best-effort.

    Si un mot de passe est fourni (ajout/test réel, cf. _handle_camera_test_route),
    une sonde FRAÎCHE ET AUTHENTIFIÉE est toujours relancée plutôt que de réutiliser
    le cache du scan réseau — vérifié dans les spécifications ONVIF officielles
    (2026-07-24) que GetNodes/GetProfiles/GetRelayOutputs sont Access Class
    READ_MEDIA, donc le scan (qui n'a structurellement JAMAIS de mot de passe à ce
    stade) ne peut par nature détecter qu'un sous-ensemble des capacités — le cache
    ne peut pas remplacer une sonde qui, elle, peut s'authentifier (§72).

    Sans mot de passe (aucun moyen de s'authentifier de toute façon), réutilise le
    résultat d'un scan réseau récent pour cette IP plutôt que de relancer une sonde
    ONVIF complète — le scan (_scan_onvif_cameras) vient déjà de faire 5-6 appels
    ONVIF vers cette même caméra quelques secondes plus tôt (pour la lister) ; la
    reprobe depuis zéro juste après crée une collision avec la caméra encore occupée
    par le scan (certaines n'acceptent qu'une connexion ONVIF à la fois) — confirmé
    en conditions réelles le 2026-07-23."""
    if username and password:
        log(f'[onvif-capabilities] {ip}: mot de passe disponible — sonde authentifiée fraîche (pas de réutilisation du cache scan)')
        try:
            return _probe_onvif_capabilities_by_ip(ip, username=username, password=password)
        except Exception as e:
            warn(f'[onvif-capabilities] {ip}: {e}')
            return []

    cached = _scan_capabilities_cache.get(ip)
    if cached and (time.time() - cached[0]) < _SCAN_CAPABILITIES_CACHE_TTL:
        log(f'[onvif-capabilities] {ip}: cache scan réutilisé ({cached[1]})')
        return cached[1]
    log(f'[onvif-capabilities] {ip}: pas de scan récent en cache — sonde ONVIF directe (non authentifiée, pas de mot de passe connu)')
    try:
        return _probe_onvif_capabilities_by_ip(ip)
    except Exception as e:
        warn(f'[onvif-capabilities] {ip}: {e}')
        return []


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

# Durée d'un "cran" de déplacement — bouge à durée FIXE plutôt que de dépendre
# du délai réseau entre le clic (mousedown → move) et le relâchement (mouseup →
# stop) côté navigateur. C'est exactement ce qui rendait le déplacement variable
# par clic (signalé par Hicham en conditions réelles, 2026-08-19, caméra PTZ
# physique) : move et stop étaient deux appels réseau indépendants (navigateur →
# API web avec auth/DB → addon → MQTT → Frigate → ONVIF), sans aucune garantie
# de délai fixe entre les deux — la distance parcourue dépendait entièrement de
# la latence réseau du moment. Un seul appel /camera/ptz gère maintenant tout le
# cycle move→attente→stop côté serveur (cf. _handle_camera_ptz_route),
# _CommandHandler tourne en thread par requête (ThreadingTCPServer) donc ce
# sleep ne bloque aucune autre commande en cours. Valeur de départ raisonnable,
# jamais calibrée sur une vraie caméra motorisée (aucune disponible en session
# de dev) — à ajuster ici si le cran est trop grand/petit une fois testé.
_PTZ_STEP_SECONDS = 0.2


# Audit add-on 2026-09-22 : dernier point de l'audit restant — jusqu'ici
# X-Site-Secret était le secret INGEST_SECRET envoyé TEL QUEL sur chaque appel,
# comparé en temps constant (hmac.compare_digest) mais sans aucune notion de
# fraîcheur : un secret intercepté/exfiltré une seule fois (log, MITM malgré
# TLS, poste compromis côté Vercel) reste rejouable indéfiniment jusqu'à
# rotation manuelle. Bascule vers un jeton signé par requête, même schéma que
# _pi_verify côté Postgres (HMAC + fenêtre de fraîcheur) mais pour le sens
# inverse (cloud → Pi) — jusqu'ici seul le sens Pi → Supabase avait ce
# traitement. Format : "<timestamp>.<hmac_hex>", hmac calculé sur
# "<timestamp>:<method>:<route>:<sha256(corps)>" — lier la route ET le corps
# empêche de rejouer une commande capturée sur une AUTRE route ou avec un
# AUTRE corps (ex: rejouer un "arm_away" capturé comme "disarm" en changeant
# juste le corps serait sinon possible si seul le timestamp était signé).
# Fenêtre à 60s (plus stricte que les 300s de _pi_verify) — délibéré : cette
# direction déclenche de vraies actions (armer/désarmer l'alarme, verrous),
# pas seulement de la télémétrie, la fenêtre de rejeu doit rester courte.
# Pas de cache de nonces en plus de la fenêtre (contrairement à un anti-rejeu
# "parfait") — même niveau de garantie que _pi_verify (déjà accepté comme
# suffisant pour ce projet), et chaque appel réel a de toute façon un
# timestamp+route+corps différent en pratique (aucune fonction de ce fichier
# ne réessaie automatiquement la même commande côté serveur).
_COMMAND_AUTH_WINDOW_SECONDS = 60


# Point 7 (audit add-on 2026-09-22, resté ouvert jusqu'ici) : timeout (15s, cf.
# _CommandHandler.timeout) et plafond de corps (MAX_BODY_BYTES) existaient déjà,
# mais rien ne bornait le DÉBIT de requêtes — légitimes en forme (avec ou sans
# secret valide) ou non. Seau à jetons GLOBAL, pas par IP : ce serveur n'a
# structurellement qu'UN SEUL appelant légitime, le backend Vercel relayé par le
# tunnel Cloudflare dédié au site — `self.client_address[0]` vu ici est toujours
# celui de cloudflared en loopback (127.0.0.1), jamais l'IP réelle de l'appelant
# distant (aucun header CF-Connecting-IP/X-Forwarded-For relayé par le tunnel) ;
# un plafond par IP n'aurait donc qu'un seul compteur de toute façon. Verrouillé
# (ThreadingTCPServer = un thread par requête).
_rate_limit_lock = threading.Lock()
_rate_limit_tokens = 40.0
_rate_limit_last_refill = time.time()
_RATE_LIMIT_MAX_TOKENS = 40.0       # rafale autorisée (ex: sync-now + plusieurs commandes groupées)
_RATE_LIMIT_REFILL_PER_SEC = 4.0    # ~240/min en régime continu — largement au-dessus du trafic légitime observé


def _rate_limit_check() -> bool:
    """True si la requête est autorisée, False si elle doit être rejetée (429)."""
    global _rate_limit_tokens, _rate_limit_last_refill
    with _rate_limit_lock:
        now = time.time()
        elapsed = now - _rate_limit_last_refill
        _rate_limit_last_refill = now
        _rate_limit_tokens = min(_RATE_LIMIT_MAX_TOKENS, _rate_limit_tokens + elapsed * _RATE_LIMIT_REFILL_PER_SEC)
        if _rate_limit_tokens < 1.0:
            return False
        _rate_limit_tokens -= 1.0
        return True


def _verify_site_secret_header(header_value: str, method: str, route: str, body: bytes) -> bool:
    if not header_value or "." not in header_value:
        return False
    ts_str, _, sig = header_value.partition(".")
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    if abs(time.time() - ts) > _COMMAND_AUTH_WINDOW_SECONDS:
        return False
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{ts}:{method}:{route}:{body_hash}"
    expected = hmac.new(INGEST_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


class _CommandHandler(http.server.BaseHTTPRequestHandler):
    # Audit add-on 2026-09-22 : aucun timeout de connexion, aucune limite de
    # taille de corps sur ce serveur — un appelant (même sans secret valide,
    # avant même la vérification d'auth) pouvait garder un thread ouvert
    # indéfiniment (style slowloris, un thread par connexion via
    # ThreadingTCPServer, pas de plafond) ou, une fois authentifié, envoyer un
    # corps de plusieurs centaines de Mo pour épuiser la RAM du Pi. `timeout`
    # est honoré nativement par socketserver.StreamRequestHandler.setup()
    # (ferme la connexion proprement si aucune donnée ne circule pendant ce
    # délai) — pas un correctif maison, un attribut standard jamais renseigné.
    timeout = 15
    MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 Mo — largement au-dessus de la plus grosse commande légitime (upsert d'automatisation)

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
        # `data or {...}` était le bug : un dict VIDE ({}) est falsy en Python,
        # donc une réponse légitimement vide (ex: handle_alarmo_get_users() sans
        # aucun code créé, handle_alarmo_get_sensor_groups() sans aucun groupe)
        # se faisait silencieusement remplacer par {"ok": true} — trouvé en
        # conditions réelles (2026-08-05) : {"users": [true]} côté web au lieu de
        # {"users": []}, qui plantait le rendu (React "missing key" sur un
        # tableau contenant le booléen `true`). Seul `None` (rien fourni du
        # tout par l'appelant) doit déclencher le repli.
        self._respond(200, data if data is not None else {"ok": True})

    def _respond_html(self, code, html):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_ha_bootstrap_route(self):
        """Amorce la session Home Assistant d'un technicien dans son navigateur (Phase 2
        accès distant) : échange un billet à usage unique contre le jeton de session déjà
        créé à l'approbation de sa demande, puis renvoie une page qui dépose ce jeton dans
        le stockage local du navigateur avant de rediriger vers Home Assistant — ainsi
        HA le reconnaît comme déjà connecté, sans jamais lui montrer ni lui demander de
        mot de passe. Cf. mémoire project-remote-ha-access-consent pour le détail complet
        du mécanisme et pourquoi (localStorage["hassTokens"], format AuthData, etc.)."""
        try:
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = urllib.parse.parse_qs(query)
            ticket = (params.get("ticket") or [None])[0]
            if not ticket:
                return self._respond_html(400, self._ha_bootstrap_error_page("Lien invalide."))

            ts = int(time.time())
            message = f"{SITE_PREFIX}:{ts}:ha_bootstrap:{ticket}"
            r = _supabase_rpc("pi_resolve_ha_bootstrap_ticket", {
                "p_mqtt_prefix": SITE_PREFIX,
                "p_timestamp": ts,
                "p_signature": _pi_sign(message),
                "p_ticket": ticket,
            })
            rows = r.json() if r.ok else []
            session_token = rows[0]["refresh_token"] if rows else None
            if not session_token:
                return self._respond_html(403, self._ha_bootstrap_error_page(
                    "Ce lien a expiré ou a déjà été utilisé — redemandez l'accès depuis l'application."))

            exp = _jwt_payload(session_token).get("exp")
            expires_in = max(int(exp - time.time()), 60) if exp else 1800
            # Host vient de l'en-tête HTTP (contrôlable par l'appelant) — la double
            # sérialisation JSON ci-dessous empêche toute injection dans le <script>,
            # mais on valide quand même le format par prudence avant de s'en servir.
            host = self.headers.get("Host", "")
            if not re.fullmatch(r"[a-zA-Z0-9.-]+\.domoticium\.fr", host):
                return self._respond_html(400, self._ha_bootstrap_error_page("Requête invalide."))
            auth_data = {
                "hassUrl": f"https://{host}",
                "clientId": None,
                "access_token": session_token,
                "refresh_token": "",
                "expires_in": expires_in,
                "expires": int(time.time() * 1000) + expires_in * 1000,
            }
            html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Connexion…</title></head><body style="background:#111;color:#eee;
font-family:sans-serif;display:flex;align-items:center;justify-content:center;
height:100vh;margin:0"><p>Connexion à Home Assistant…</p>
<script>
localStorage.setItem("hassTokens", {json.dumps(json.dumps(auth_data))});
location.replace("/");
</script></body></html>"""
            self._respond_html(200, html)
        except Exception as e:
            warn(f"[ha-bootstrap] {e}")
            self._respond_html(500, self._ha_bootstrap_error_page("Erreur inattendue."))

    def _ha_bootstrap_error_page(self, message):
        safe = message.replace("<", "&lt;").replace(">", "&gt;")
        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Accès impossible</title></head><body style="background:#111;color:#eee;
font-family:sans-serif;display:flex;align-items:center;justify-content:center;
height:100vh;margin:0;text-align:center;padding:0 20px"><p>{safe}</p></body></html>"""

    def do_POST(self):
        remote_addr = self.client_address[0]
        # Le tunnel Cloudflare route ce port via le préfixe /addon (hostname unique
        # par site, partagé avec les caméras — cf. lib/cloudflare/tunnel.ts côté Vercel).
        # Calculé une seule fois ici (plutôt qu'après l'auth comme avant) : la
        # signature du header X-Site-Secret est liée à cette route logique — même
        # valeur des deux côtés (client ET add-on), indépendante du préfixe /addon
        # qui est un détail de routage du tunnel, pas connu tel quel par l'appelant.
        route = self.path[len("/addon"):] if self.path.startswith("/addon") else self.path
        route = route.split("?", 1)[0]
        if not _rate_limit_check():
            _audit_command(route, remote_addr, "rejected:rate_limited")
            return self._reject(429, "Trop de requêtes")
        if not INGEST_SECRET:
            return self._reject(503, "ingest_secret non configuré")

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self._reject(400, "Content-Length invalide")
        if length > self.MAX_BODY_BYTES:
            # Draine le corps avant de répondre, par blocs bornés (jamais chargé
            # en mémoire d'un coup — justement ce que cette limite doit éviter).
            # Sans ça, répondre immédiatement ferme la connexion PENDANT que le
            # client (via le tunnel Cloudflare) est encore en train d'envoyer —
            # remonté comme un 502 générique côté Cloudflare plutôt que le 413
            # voulu (trouvé en testant en conditions réelles, pas supposé).
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
            _audit_command(route, remote_addr, "rejected:body_too_large")
            return self._reject(413, "Corps trop volumineux")

        raw = self.rfile.read(length) if length else b""
        # La vérification du secret dépend désormais du corps exact reçu (lié dans
        # la signature, cf. _verify_site_secret_header) — doit donc se faire APRÈS
        # la lecture ci-dessus, plutôt qu'avant comme la simple comparaison
        # statique précédente. Coût borné par MAX_BODY_BYTES (2 Mo) dans tous les
        # cas, authentifié ou non — pas une nouvelle piste de déni de service.
        if not _verify_site_secret_header(self.headers.get("X-Site-Secret") or "", "POST", route, raw):
            _audit_command(route, remote_addr, "rejected:unauthorized")
            return self._reject(401, "Non autorisé")
        try:
            data = json.loads(raw.decode() or "{}") if raw else {}
        except Exception:
            _audit_command(route, remote_addr, "rejected:invalid_json")
            return self._reject(400, "JSON invalide")

        try:
            handlers = {
                "/cmd":                  self._handle_cmd,
                "/matter/commission":    self._handle_matter_commission,
                "/zigbee/permit-join":   self._handle_permit_join,
                "/zigbee/remove-device": self._handle_remove_device,
                "/zigbee/set-attribute": self._handle_set_attribute,
                "/zigbee/reconfigure":   self._handle_zigbee_reconfigure,
                "/zigbee/boost-reporting": self._handle_zigbee_boost_reporting,
                "/ha-command":           self._handle_ha_command_route,
                "/camera/configure":     self._handle_camera_configure_route,
                "/camera/mask":          self._handle_camera_mask_route,
                "/camera/test":          self._handle_camera_test_route,
                "/camera/ptz":           self._handle_camera_ptz_route,
                "/sync-now":             self._handle_sync_now,
                "/alarmo/set-panel-state": self._handle_alarmo_set_panel_state_route,
                "/alarmo/sensor":        self._handle_alarmo_sensor_route,
                "/alarmo/user":          self._handle_alarmo_user_route,
                "/alarmo/automation":    self._handle_alarmo_automation_set_route,
                "/alarmo/area-mode":     self._handle_alarmo_area_mode_set_route,
                "/alarmo/general-config": self._handle_alarmo_general_config_set_route,
                "/alarmo/sensor-group":  self._handle_alarmo_sensor_group_route,
                "/local/matter/merge/confirm": self._handle_local_matter_merge_confirm,
                "/local/matter/merge/reject":  lambda d: self._ok(handle_matter_merge_reject(d)),
                "/wifi/shelly/add":      self._handle_wifi_shelly_add_route,
                "/voice/snapshot":       lambda d: self._ok(handle_voice_snapshot()),
                "/local/entitlement/recheck": lambda d: self._ok(handle_local_entitlement_recheck()),
                "/local/voice/exposure": lambda d: self._ok(handle_voice_exposure_set(d)),
                "/ha/session-token/create": self._handle_ha_session_token_create,
                "/ha/session-token/revoke": self._handle_ha_session_token_revoke,
            }
            handler = handlers.get(route)
            if not handler:
                _audit_command(route, remote_addr, "rejected:unknown_route")
                return self._reject(404, "Route inconnue")
            handler(data)
            # "ok" = dispatchée sans exception, pas forcément un succès métier
            # (un handler peut répondre son propre code d'erreur sans lever) —
            # suffisant pour l'objectif de cet audit (quelles commandes ont été
            # REÇUES et traitées vs. rejetées au niveau transport/auth).
            _audit_command(route, remote_addr, "ok")
        except Exception as e:
            warn(f"[cmd-server] {self.path}: {e}")
            _audit_command(route, remote_addr, f"rejected:error:{type(e).__name__}")
            self._reject(500, str(e))

    def _handle_ha_session_token_create(self, data):
        """Accès distant technicien (2026-09-12) — crée un jeton de session HA (LLAT)
        indépendant pour le technicien, à partir du refresh_token délégué du client.
        Exécuté ICI (addon, process persistant, WS local vers HA) plutôt que depuis
        Vercel : 3 implémentations WebSocket différentes côté cloud (ws, client fait
        main, WebSocket natif Node) ont toutes échoué de façon identique et
        inexplicable spécifiquement sur l'environnement d'exécution Vercel (jamais
        reproduit en local ni depuis une IP résidentielle) — cf. HANDOFF.md côté web.
        Miroir de createHaSessionToken() dans delegatedSession.ts.

        ⚠️ Répond TOUJOURS 200 (jamais 502) — piège réel trouvé le 2026-09-12 après
        des heures de diagnostic (logs sur disque à chaque étape, confirmant que le
        code Python s'exécute et écrit sa réponse sans la moindre erreur) : le tunnel
        Cloudflare (`cloudflared`) intercepte et remplace tout code 502 renvoyé par
        cette origine par SA PROPRE page d'erreur générique (texte brut, "error code:
        502"), perdant le vrai corps JSON — confirmé en comparant avec des routes
        existantes (200 OK, toujours transmis intact) contre cette même route avec un
        502 (toujours remplacé, peu importe la validité de la réponse Python). Le
        succès/échec se lit donc dans le corps JSON (`ok`/`sessionToken`/`error`),
        jamais dans le code HTTP — même patron déjà utilisé ailleurs dans ce fichier
        (haCameraPtz, haAlarmoSetUser).

        ⚠️ 2e piège trouvé le 2026-09-12, celui-ci la VRAIE cause du "Unknown error"
        qui persistait même après le fix ci-dessus — trouvé en lisant le code source
        de Home Assistant Core (auth/__init__.py::async_create_refresh_token) : chaque
        `client_name` ne peut avoir QU'UN SEUL refresh_token de type
        long_lived_access_token actif par utilisateur — une 2e tentative avec le MÊME
        nom lève `ValueError(f"{client_name} already exists")`, jamais rattrapée par le
        handler HA (qui n'attrape que InvalidAuthError), donc remontée telle quelle par
        le dispatcher WS générique sous la forme d'un "Unknown error" opaque. Ancien
        code : `client_name` fixe ("Domoticium — session technicien") — toutes les
        tentatives précédentes de ce chantier (avant les fix de transport) ont créé le
        refresh_token AVANT d'échouer à recevoir la réponse (create_refresh_token
        s'exécute avant l'envoi du résultat WS), laissant des jetons orphelins sous ce
        même nom — chaque nouvelle tentative percutait l'un d'eux. Fix : nom unique par
        session (suffixe aléatoire), aucune collision possible désormais."""
        refresh_token = data.get("delegatedRefreshToken")
        if not refresh_token:
            return self._reject(400, "delegatedRefreshToken requis")
        try:
            access_token = _ha_mint_access_token(refresh_token)
        except Exception as e:
            return self._ok({"ok": False, "error": str(e)})

        ws_send, ws_recv, ws_close = _ha_ws_connect(
            access_token=access_token, host="127.0.0.1", port=_ha_core_port(), path="/api/websocket"
        )
        if not ws_send:
            return self._ok({"ok": False, "error": "Connexion WebSocket HA échouée"})
        try:
            ws_send({
                "id": 1,
                "type": "auth/long_lived_access_token",
                "lifespan": 1,
                "client_name": f"Domoticium — session technicien ({secrets.token_hex(4)})",
            })
            result = ws_recv()
            if not result.get("success"):
                error = (result.get("error") or {}).get("message") or "Erreur Home Assistant"
                return self._ok({"ok": False, "error": error})
            llat = result.get("result")
            if not isinstance(llat, str):
                return self._ok({"ok": False, "error": "Réponse HA inattendue pour long_lived_access_token"})
            self._ok({"ok": True, "sessionToken": llat})
        except Exception as e:
            self._ok({"ok": False, "error": f"Session WebSocket HA échouée: {e}"})
        finally:
            try:
                ws_close()
            except Exception:
                pass

    def _handle_ha_session_token_revoke(self, data):
        """Révoque un jeton de session technicien — se connecte avec le jeton lui-même
        (il s'authentifie comme le même utilisateur délégué) puis demande à HA de
        supprimer son propre refresh_token sous-jacent (identifié via son claim "iss").
        Miroir de revokeHaSessionToken() dans delegatedSession.ts. Répond TOUJOURS 200,
        même raison qu'au-dessus (cf. _handle_ha_session_token_create)."""
        session_token = data.get("sessionToken")
        if not session_token:
            return self._reject(400, "sessionToken requis")
        try:
            refresh_token_id = _jwt_payload(session_token).get("iss")
        except Exception:
            return self._reject(400, "Jeton HA mal formé")
        if not refresh_token_id:
            return self._reject(400, "Jeton HA sans claim iss")

        ws_send, ws_recv, ws_close = _ha_ws_connect(
            access_token=session_token, host="127.0.0.1", port=_ha_core_port(), path="/api/websocket"
        )
        if not ws_send:
            return self._ok({"ok": False, "error": "Connexion WebSocket HA échouée"})
        try:
            ws_send({"id": 1, "type": "auth/delete_refresh_token", "refresh_token_id": refresh_token_id})
            ws_recv()
            self._ok({"ok": True})
        except Exception as e:
            self._ok({"ok": False, "error": f"Révocation WebSocket HA échouée: {e}"})
        finally:
            try:
                ws_close()
            except Exception:
                pass

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

    def _handle_alarmo_set_panel_state_route(self, data):
        entity_id = data.get("entityId")
        action = data.get("action")
        code = data.get("code")
        if not entity_id or not action:
            return self._reject(400, "entityId et action requis")
        result = handle_alarmo_set_panel_state(entity_id, action, code)
        if not result.get("ok"):
            return self._reject(400, result.get("error") or "Échec")
        self._ok()

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
        # force=True : notre app a déjà supprimé sa propre ligne DB avant cet appel
        # (cf. api/devices/[id]/route.ts DELETE) — un retrait "poli" (force=False)
        # attend l'accusé de réception du device lui-même sur le réseau Zigbee, ce
        # qui échoue avec un timeout 15s pour tout appareil à pile endormi au
        # moment de la demande (contrairement aux appareils secteur, toujours
        # éveillés) — vérifié dans la doc officielle Z2M. force=True retire
        # immédiatement l'appareil de la base Z2M sans attendre cet accusé,
        # évitant un fantôme Z2M pour un appareil déjà retiré côté app.
        _local_client.publish(
            "zigbee2mqtt/bridge/request/device/remove",
            json.dumps({"id": ieee, "force": True}),
            qos=1,
        )
        self._ok()

    def _handle_zigbee_reconfigure(self, data):
        """Force Zigbee2MQTT à ré-appliquer le binding + la configuration de
        reporting d'un device (bridge/request/device/configure) — démarche
        officielle Z2M recommandée en cas de rapports lents/absents sur
        certains attributs (ex: puissance/énergie d'une prise), pas une
        action destructive : ne retire rien, ne re-jumelle rien, juste un
        rafraîchissement de la configuration déjà en place.
        (2026-09-01) Ajouté pour diagnostiquer un cas réel signalé par
        Hicham : les attributs power/energy/voltage/current de plusieurs
        prises IKEA E22xx du site de test ne se rafraîchissaient qu'après
        plusieurs dizaines de minutes (jusqu'à ~3h pour l'énergie), largement
        au-delà de ce qu'un reporting Zigbee correctement configuré devrait
        produire — confirmé en observant le trafic MQTT réel (0 événement en
        90s d'écoute directe), pas supposé."""
        ieee = data.get("ieee_address")
        if not ieee:
            return self._reject(400, "ieee_address manquant")
        if not _local_client:
            return self._reject(503, "Mosquitto local non connecté")
        _local_client.publish(
            "zigbee2mqtt/bridge/request/device/configure",
            json.dumps({"id": ieee}),
            qos=1,
        )
        self._ok()

    def _handle_zigbee_boost_reporting(self, data):
        """Route HTTP à la demande pour _boost_device_reporting (cf. définition
        module-level, doc complète là-bas) — appelée aussi AUTOMATIQUEMENT à chaque
        synchro Zigbee pour tout device sur tout site (cf. _sync_zigbee_devices_direct),
        cette route reste utile pour re-déclencher manuellement un device précis sans
        attendre le prochain cycle de synchro (jusqu'à 5 min). `batteryReportingSeconds`
        (optionnel, entier, secondes) permet de forcer un intervalle pour CE device
        précis même si l'option add-on BATTERY_REPORTING_SECONDS est à 0 (désactivée)
        — pratique pour tester sur un seul device à pile avant de régler l'option
        globalement pour le site."""
        ieee = data.get("ieee_address")
        if not ieee:
            return self._reject(400, "ieee_address manquant")
        if not _local_client:
            return self._reject(503, "Mosquitto local non connecté")

        entry = next((d for d in _last_z2m_devices_list if d.get("ieee_address") == ieee), None)
        if not entry:
            return self._reject(404, "device introuvable dans le cache Z2M (bridge/devices)")
        exposes = (entry.get("definition") or {}).get("exposes") or []
        battery_seconds = data.get("batteryReportingSeconds")
        battery_seconds = int(battery_seconds) if battery_seconds is not None else None

        results = _boost_device_reporting(ieee, exposes, entry.get("power_source"), battery_seconds)
        if "error" in results:
            return self._reject(503, results["error"])
        if not results:
            return self._reject(400, "ce device n'expose aucun attribut boostable (électrique, ou pile sans confirmation)")
        _boosted_ieees.add(ieee)
        self._ok({"ieee_address": ieee, "results": results})

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
        # Audit add-on 2026-09-22 : cette route répondait "ok" au client
        # SYSTÉMATIQUEMENT, même quand _handle_ha_command échouait réellement
        # (ex: écriture HA en échec) — un client pouvait croire une
        # automatisation/scène enregistrée alors qu'elle ne l'était pas.
        result = _handle_ha_command(json.dumps(data).encode())
        if result:
            # scene_upsert renvoie un dict ({"ok":True,"entity_id":...}) — transmis
            # tel quel au web, qui en a besoin pour activer la scène plus tard
            # (cf. _entity_id_by_unique_id). Tout le reste renvoie True nu.
            self._ok(result if isinstance(result, dict) else None)
        else:
            self._reject(502, "Échec de la commande HA — voir les logs de l'add-on")

    def _handle_camera_configure_route(self, data):
        action = data.get("action", "add")
        stream_name = data.get("streamName")
        if not stream_name:
            return self._reject(400, "streamName manquant")
        ok = handle_camera_configure(action, stream_name, data.get("rtspUrl"))
        if ok:
            self._ok()
        else:
            self._reject(502, "Échec de configuration Frigate/go2rtc — voir les logs de l'add-on")

    def _handle_camera_mask_route(self, data):
        stream_name = data.get("streamName")
        if not stream_name:
            return self._reject(400, "streamName manquant")
        rects = data.get("maskRects") or []
        if not isinstance(rects, list):
            return self._reject(400, "maskRects doit être une liste")
        for r in rects:
            if not isinstance(r, dict) or not all(
                isinstance(r.get(k), (int, float)) and 0 <= r[k] <= 1 for k in ("x", "y", "w", "h")
            ):
                return self._reject(400, "chaque rectangle doit avoir x/y/w/h numériques entre 0 et 1")
        try:
            ok = handle_camera_mask(stream_name, rects)
        except ValueError as e:
            return self._reject(404, str(e))
        if ok:
            self._ok()
        else:
            self._reject(502, "Échec de mise à jour du masquage — voir les logs de l'add-on")

    def _handle_camera_test_route(self, data):
        # Audit add-on 2026-09-22 : ce test crée/sonde un flux temporaire côté
        # go2rtc (_go2rtc_upsert_stream) sans jamais prendre _camera_configure_lock,
        # contrairement à tous les autres appels qui touchent go2rtc/Frigate —
        # un test lancé pendant un ajout/suppression/masquage concurrent (qui
        # redémarre Frigate entièrement) pouvait échouer avec un message
        # trompeur ("caméra injoignable") alors que la vraie cause est le
        # redémarrage en cours, pas la caméra elle-même. Sérialisé comme le
        # reste — un test attend simplement la fin de l'opération en cours au
        # lieu de donner un faux résultat.
        with _camera_configure_lock:
            rtsp_url = data.get("rtspUrl")
            if rtsp_url:
                # Mode "URL manuelle" — l'utilisateur a fourni l'URL exacte, aucune devinette.
                ok, detail = _go2rtc_test_stream(rtsp_url)
                try:
                    onvif_ip, onvif_user, onvif_pass = _onvif_credentials_from_rtsp(rtsp_url)
                except ValueError:
                    onvif_ip, onvif_user, onvif_pass = '', '', ''
                if not onvif_ip:
                    ip_m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', rtsp_url)
                    onvif_ip = ip_m.group(1) if ip_m else ''
                caps = _safe_probe_capabilities(onvif_ip, username=onvif_user, password=onvif_pass) if onvif_ip else []
                return self._ok({"ok": ok, "detail": detail, "correctedUrl": None, "detectedCapabilities": caps})

            ip = data.get("ip")
            password = data.get("password")
            if not ip or password is None:
                return self._reject(400, "ip et password requis (ou rtspUrl)")
            manufacturer = data.get("manufacturer") or ""
            ok, detail, url, sub_url = _test_camera_by_brand(ip, password, manufacturer)
            # username "admin" : convention constante des templates RTSP de toutes les
            # marques du projet (_RTSP_TEMPLATES) — même hypothèse déjà utilisée ailleurs
            # pour les commandes ONVIF authentifiées (PTZ, vision nocturne).
            caps = _safe_probe_capabilities(ip, username="admin", password=password)
            self._ok({
                "ok": ok, "detail": detail, "correctedUrl": url, "correctedUrlSub": sub_url,
                "detectedCapabilities": caps,
            })

    def _handle_camera_ptz_route(self, data):
        """Relaie la commande au contrôleur ONVIF PTZ natif de Frigate (topic MQTT
        frigate/<camera>/ptz, cf. _generate_frigate_yaml/_FRIGATE_PTZ_COMMANDS) — Frigate
        maintient déjà cette implémentation, pas de raison de la dupliquer. Publication
        MQTT fire-and-forget : Frigate ne renvoie pas d'accusé de réception sur ce
        topic, donc "ok" ici confirme l'envoi, pas l'exécution réelle par la caméra.

        Un "cran" de déplacement (direction ≠ "stop") fait tout le cycle
        move→attente(_PTZ_STEP_SECONDS)→stop DANS cette requête, plutôt que de
        compter sur un futur appel "stop" séparé envoyé par le navigateur au
        relâchement du clic — c'est ce second appel, à latence réseau variable,
        qui causait un déplacement différent à chaque clic (cf. commentaire
        _PTZ_STEP_SECONDS). "stop" explicite reste géré à part (ex: bouton
        d'arrêt d'urgence futur), sans le délai."""
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
        if command == "stop":
            _local_client.publish(f"frigate/{stream_name}/ptz", "stop", qos=1)
            return self._ok({"ok": True, "detail": "stop"})
        _local_client.publish(f"frigate/{stream_name}/ptz", command, qos=1)
        time.sleep(_PTZ_STEP_SECONDS)
        _local_client.publish(f"frigate/{stream_name}/ptz", "stop", qos=1)
        self._ok({"ok": True, "detail": "step"})

    def _handle_sync_now(self, data):
        """Déclenche un cycle d'entretien local immédiat (republication bridge/devices Z2M,
        réconciliation Matter/Wi-Fi/états) au lieu d'attendre le prochain cycle périodique
        (5 min) — bouton "Sync HA"."""
        _sync_requested.set()
        self._ok()

    def _handle_alarmo_sensor_route(self, data):
        entity_id = data.get("entityId", "")
        if data.get("remove"):
            result = handle_alarmo_remove_sensor(entity_id)
        else:
            sensor_type = data.get("type", "other")
            modes = data.get("modes") or []
            always_on = data.get("alwaysOn", False)
            result = handle_alarmo_update_sensor(entity_id, sensor_type, modes, always_on)
        if result.get("ok"):
            self._ok(result)
        else:
            self._reject(400, result.get("detail", "échec"))

    def _handle_alarmo_user_route(self, data):
        result = handle_alarmo_set_user(
            data.get("action", ""),
            data.get("userId"),
            data.get("name"),
            data.get("code"),
            data.get("enabled", True),
            data.get("mode"),
            data.get("validFromTime"),
            data.get("validUntilTime"),
            data.get("expiresAt"),
        )
        if result.get("ok"):
            self._ok(result)
        else:
            self._reject(400, result.get("detail", "échec"))

    def _handle_alarmo_automation_set_route(self, data):
        result = handle_alarmo_set_automation(
            data.get("automationId"),
            data.get("name"),
            data.get("event"),
            data.get("modes"),
            data.get("entities"),
            data.get("service"),
            data.get("enabled"),
            data.get("remove", False),
        )
        if result.get("ok"):
            self._ok(result)
        else:
            self._reject(400, result.get("detail", "échec"))

    def _handle_alarmo_area_mode_set_route(self, data):
        result = handle_alarmo_set_area_mode(
            data.get("mode"), data.get("enabled"),
            data.get("exitTime"), data.get("entryTime"), data.get("triggerTime"),
        )
        if result.get("ok"):
            self._ok(result)
        else:
            self._reject(400, result.get("detail", "échec"))

    def _handle_alarmo_general_config_set_route(self, data):
        result = handle_alarmo_set_general_config(data.get("disarmAfterTrigger"))
        if result.get("ok"):
            self._ok(result)
        else:
            self._reject(400, result.get("detail", "échec"))

    def _handle_alarmo_sensor_group_route(self, data):
        result = handle_alarmo_set_sensor_group(
            data.get("groupId"),
            data.get("name"),
            data.get("entities"),
            data.get("timeout"),
            data.get("remove", False),
        )
        if result.get("ok"):
            self._ok(result)
        else:
            self._reject(400, result.get("detail", "échec"))

    def _handle_local_matter_merge_confirm(self, data):
        result = handle_matter_merge_confirm(data)       # UNE seule exécution (opération destructive)
        if result.get("ok"):
            self._ok(result)
        else:
            self._reject(400, result.get("detail", "échec"))

    def do_GET(self):
        route = self.path[len("/addon"):] if self.path.startswith("/addon") else self.path
        route = route.split("?")[0]

        if not _rate_limit_check():
            _audit_command(route, self.client_address[0], "rejected:rate_limited")
            return self._reject(429, "Trop de requêtes")

        # SEULE route accessible sans X-Site-Secret : conçue pour être ouverte
        # directement par le navigateur d'un technicien (qui ne peut évidemment pas
        # connaître ce secret), pas par notre backend. Sécurisée autrement : billet à
        # usage unique, de courte durée de vie, vérifié par Supabase avant toute
        # livraison — cf. _handle_ha_bootstrap_route et migration 0085. Toutes les
        # autres routes gardent la vérification classique ci-dessous, inchangée.
        if route == "/ha-bootstrap":
            return self._handle_ha_bootstrap_route()

        if not INGEST_SECRET:
            return self._reject(503, "ingest_secret non configuré")
        # GET n'a pas de corps — signature liée à route+méthode seulement (la
        # query string, elle, n'est jamais sensible ici : toutes les routes GET
        # sont des lectures, cf. _verify_site_secret_header).
        if not _verify_site_secret_header(self.headers.get("X-Site-Secret") or "", "GET", route, b""):
            return self._reject(401, "Non autorisé")
        if route == "/camera/scan":
            self._handle_camera_scan()
        elif route == "/alarmo/sensors":
            self._handle_alarmo_sensors_route()
        elif route == "/alarmo/panel":
            self._handle_alarmo_panel_route()
        elif route == "/alarmo/keypad":
            self._handle_alarmo_keypad_route()
        elif route == "/alarmo/users":
            self._handle_alarmo_users_route()
        elif route == "/alarmo/automations":
            self._handle_alarmo_automations_route()
        elif route == "/alarmo/area-modes":
            self._handle_alarmo_area_modes_route()
        elif route == "/alarmo/general-config":
            self._handle_alarmo_general_config_route()
        elif route == "/alarmo/sensor-groups":
            self._handle_alarmo_sensor_groups_route()
        elif route == "/automations/ha":
            self._handle_ha_automations_route()
        elif route == "/scenes/ha":
            self._handle_ha_scenes_route()
        elif route == "/devices/triggers":
            self._handle_device_triggers_route()
        elif route == "/devices/energy-history":
            self._handle_energy_history_route()
        elif route == "/automations/calendars":
            self._handle_calendars_route()
        elif route == "/automations/areas":
            self._handle_areas_route()
        elif route == "/automations/counters":
            self._handle_counters_route()
        elif route == "/automations/timers":
            self._handle_timers_route()
        elif route == "/wifi/shelly/discovered":
            self._handle_wifi_shelly_discovered_route()
        elif route == "/local/devices":
            self._handle_local_devices_route()
        elif route == "/local/events":
            self._handle_local_events_route()
        elif route == "/local/site":
            self._handle_local_site_route()
        elif route == "/local/alerts":
            self._handle_local_alerts_route()
        elif route == "/local/stats":
            self._ok(handle_local_stats())
        elif route == "/local/entitlement":
            self._ok(handle_local_entitlement())
        elif route == "/local/matter/merge":
            try:
                self._ok(handle_matter_merge_suggestions())
            except Exception as e:
                warn(f"[matter-merge] {e}")
                self._reject(500, str(e))
        elif route == "/local/voice/exposure":
            try:
                self._ok(handle_voice_exposure_get())
            except Exception as e:
                warn(f"[voice] {e}")
                self._reject(500, str(e))
        else:
            self._reject(404, "Route inconnue")

    def _sse_client_gone(self) -> bool:
        """True si l'autre bout a fermé la connexion (lecture possible et vide = EOF). Sans
        ça, un flux dont le client est parti ne serait remarqué qu'à la prochaine écriture
        (jusqu'à _SSE_KEEPALIVE_S plus tard) et occuperait un des _SSE_MAX_SUBSCRIBERS créneaux."""
        conn = getattr(self, "connection", None)
        if conn is None:
            return False
        try:
            readable, _, _ = select.select([conn], [], [], 0)
            return bool(readable) and conn.recv(1, socket.MSG_PEEK) == b""
        except (OSError, ValueError):
            return True

    def _handle_local_events_route(self):
        """Flux SSE « quelque chose a changé » pour l'app locale — cf. le bloc _sse_* plus
        haut. Reste ouvert jusqu'à la déconnexion du client. Un thread par flux (serveur
        ThreadingTCPServer), plafonné par _SSE_MAX_SUBSCRIBERS."""
        q = queue.Queue(maxsize=64)
        with _sse_lock:
            if len(_sse_subscribers) >= _SSE_MAX_SUBSCRIBERS:
                return self._reject(429, "Trop de flux temps réel ouverts")
            _sse_subscribers.add(q)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.wfile.write(b"retry: 3000\n: connecte\n\n")
            self.wfile.flush()

            pending = {"fast": False, "slow": False}
            last_sent = {"fast": 0.0, "slow": 0.0}
            min_interval = {"fast": _SSE_FAST_MIN_INTERVAL_S, "slow": _SSE_SLOW_MIN_INTERVAL_S}
            last_write = time.time()
            while True:
                if self._sse_client_gone():
                    break  # le client (ou le relais Next) a fermé : libère le créneau sans attendre une écriture
                now = time.time()
                # Réveil au moins toutes les secondes pour détecter une fermeture côté client.
                wait = min(1.0, _SSE_KEEPALIVE_S - (now - last_write))
                for lane in ("fast", "slow"):
                    if pending[lane]:
                        wait = min(wait, last_sent[lane] + min_interval[lane] - now)
                try:
                    lane = q.get(timeout=max(0.01, wait))
                    pending[lane] = True
                    while True:  # vide la file : les signaux rapprochés se fondent en un seul
                        pending[q.get_nowait()] = True
                except queue.Empty:
                    pass

                now = time.time()
                for lane in ("fast", "slow"):
                    if pending[lane] and now - last_sent[lane] >= min_interval[lane]:
                        self.wfile.write(f'event: change\ndata: {{"lane":"{lane}"}}\n\n'.encode())
                        self.wfile.flush()
                        last_sent[lane] = last_write = now
                        pending[lane] = False
                        if lane == "fast":
                            pending["slow"] = False  # une relecture complète couvre aussi les mesures
                            last_sent["slow"] = now
                        break
                else:
                    if now - last_write >= _SSE_KEEPALIVE_S:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        last_write = now
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass  # client parti — fin normale du flux
        finally:
            with _sse_lock:
                _sse_subscribers.discard(q)

    def _handle_camera_scan(self):
        if not _camera_scan_lock.acquire(blocking=False):
            return self._reject(409, "Un scan caméras est déjà en cours — réessaie dans quelques secondes")
        try:
            cameras = _scan_onvif_cameras(timeout=7.0)
            self._ok({"cameras": cameras})
        except Exception as e:
            warn(f"[camera-scan] {e}")
            self._reject(500, str(e))
        finally:
            _camera_scan_lock.release()

    def _handle_local_devices_route(self):
        try:
            self._ok(handle_local_devices())
        except Exception as e:
            warn(f"[local-devices] {e}")
            self._reject(500, str(e))

    def _handle_local_alerts_route(self):
        try:
            self._ok(handle_local_alerts())
        except Exception as e:
            warn(f"[local-alerts] {e}")
            self._reject(500, str(e))

    def _handle_local_site_route(self):
        try:
            self._ok(handle_local_site())
        except Exception as e:
            warn(f"[local-site] {e}")
            self._reject(500, str(e))

    def _handle_wifi_shelly_discovered_route(self):
        try:
            self._ok({"discovered": handle_wifi_shelly_discovered()})
        except Exception as e:
            warn(f"[wifi-shelly-discovered] {e}")
            self._reject(500, str(e))

    def _handle_wifi_shelly_add_route(self, data):
        flow_id = data.get("flowId")
        host = data.get("host")
        if not flow_id and not host:
            return self._reject(400, "flowId ou host requis")
        try:
            result = handle_wifi_shelly_add(flow_id, host)
        except Exception as e:
            warn(f"[wifi-shelly-add] {e}")
            return self._reject(500, str(e))
        if result.get("ok"):
            self._ok(result)
        else:
            self._reject(502, result.get("error") or "Échec de l'ajout")

    def _handle_alarmo_sensors_route(self):
        try:
            self._ok(handle_alarmo_get_sensors())
        except Exception as e:
            warn(f"[alarmo-sensors] {e}")
            self._reject(500, str(e))

    def _handle_ha_automations_route(self):
        try:
            self._ok(handle_list_ha_automations())
        except Exception as e:
            warn(f"[automations-ha] {e}")
            self._reject(500, str(e))

    def _handle_ha_scenes_route(self):
        try:
            self._ok(handle_list_ha_scenes())
        except Exception as e:
            warn(f"[scenes-ha] {e}")
            self._reject(500, str(e))

    def _handle_device_triggers_route(self):
        """Boutons de télécommande/scène (2026-08-27) — HA modélise leurs pressions
        comme des "MQTT device triggers" (mécanisme par défaut de Zigbee2MQTT, PAS
        une entité consultable), vérifié dans la doc officielle Z2M avant de coder :
        les entités "event" équivalentes sont explicitement expérimentales côté Z2M,
        l'ancien "action sensor" est déprécié — le device trigger natif est la seule
        voie stable. ieee_address (Zigbee) ou matter_node_id (Matter) en query string
        — le web connaît déjà ces identifiants, pas besoin d'un nouvel aller-retour."""
        try:
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = urllib.parse.parse_qs(query)
            ieee_address = (params.get("ieee_address") or [None])[0]
            matter_node_raw = (params.get("matter_node_id") or [None])[0]
            matter_node_id = int(matter_node_raw) if matter_node_raw is not None else None
            self._ok(handle_get_device_triggers(ieee_address, matter_node_id))
        except Exception as e:
            warn(f"[device-triggers] {e}")
            self._reject(500, str(e))

    def _handle_energy_history_route(self):
        """Consommation d'une entité énergie cumulative sur les dernières N
        heures, agrégée par `period` — entity_id déjà résolu côté cloud
        (device_entities), l'addon reste dumb et relaie les statistiques long
        terme de HA (pas l'historique brut, cf. handle_energy_history). hours
        en query string, défaut 24 (graphique énergie 24h, appelant d'origine).
        `period` (2026-10-30, email de clôture de compte — récap mensuel sur 6
        mois) : optionnel, défaut "hour", whitelist stricte des valeurs
        acceptées par recorder/statistics_during_period — jamais transmis tel
        quel à HA sans validation."""
        try:
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = urllib.parse.parse_qs(query)
            entity_id = (params.get("entity_id") or [None])[0]
            if not entity_id:
                return self._reject(400, "entity_id requis")
            hours_raw = (params.get("hours") or ["24"])[0]
            hours = int(hours_raw)
            period = (params.get("period") or ["hour"])[0]
            if period not in ("5minute", "hour", "day", "week", "month"):
                return self._reject(400, "period invalide")
            self._ok(handle_energy_history(entity_id, hours, period))
        except Exception as e:
            warn(f"[energy-history] {e}")
            self._reject(500, str(e))

    def _handle_calendars_route(self):
        try:
            self._ok(handle_list_calendars())
        except Exception as e:
            warn(f"[calendars] {e}")
            self._reject(500, str(e))

    def _handle_areas_route(self):
        try:
            self._ok(handle_list_areas())
        except Exception as e:
            warn(f"[areas] {e}")
            self._reject(500, str(e))

    def _handle_counters_route(self):
        try:
            self._ok(handle_list_counters())
        except Exception as e:
            warn(f"[counters] {e}")
            self._reject(500, str(e))

    def _handle_timers_route(self):
        try:
            self._ok(handle_list_timers())
        except Exception as e:
            warn(f"[timers] {e}")
            self._reject(500, str(e))

    def _handle_alarmo_panel_route(self):
        try:
            self._ok(handle_alarmo_get_panel_state())
        except Exception as e:
            warn(f"[alarmo-panel] {e}")
            self._reject(500, str(e))

    def _handle_alarmo_keypad_route(self):
        try:
            self._ok(handle_alarmo_get_keypad_status())
        except Exception as e:
            warn(f"[alarmo-keypad] {e}")
            self._reject(500, str(e))

    def _handle_alarmo_users_route(self):
        try:
            self._ok(handle_alarmo_get_users())
        except Exception as e:
            warn(f"[alarmo-users] {e}")
            self._reject(500, str(e))

    def _handle_alarmo_automations_route(self):
        try:
            self._ok(handle_alarmo_get_automations())
        except Exception as e:
            warn(f"[alarmo-automations] {e}")
            self._reject(500, str(e))

    def _handle_alarmo_area_modes_route(self):
        try:
            self._ok(handle_alarmo_get_area_modes())
        except Exception as e:
            warn(f"[alarmo-area-modes] {e}")
            self._reject(500, str(e))

    def _handle_alarmo_general_config_route(self):
        try:
            self._ok(handle_alarmo_get_general_config())
        except Exception as e:
            warn(f"[alarmo-general-config] {e}")
            self._reject(500, str(e))

    def _handle_alarmo_sensor_groups_route(self):
        try:
            self._ok(handle_alarmo_get_sensor_groups())
        except Exception as e:
            warn(f"[alarmo-sensor-groups] {e}")
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


_GO2RTC_UPSTREAM_ADDR = ("127.0.0.1", 1984)
_GO2RTC_PROXY_PREFIX = "/cameras"


def _read_http_head(sock: socket.socket) -> bytes:
    """Lit depuis le socket jusqu'à la fin des en-têtes HTTP (\\r\\n\\r\\n inclus), en
    gardant tout ce qui a été lu au-delà (début du corps déjà arrivé sur le fil)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return buf
        buf += chunk
        if len(buf) > 65536:
            break
    return buf


# Authorization Basic précalculée une fois — cf. GO2RTC_API_AUTH (main.py, plus
# haut) : le navigateur (via le tunnel Cloudflare) ne connaît jamais ce mot de
# passe, donc _rewrite_go2rtc_head() doit l'AJOUTER à chaque requête relayée.
# Nécessaire depuis le 2026-09-07 (cf. son commentaire) : Frigate/go2rtc tourne
# en réseau Docker isolé, aucun appelant EXTÉRIEUR à son conteneur — pas même
# celui qui vise "127.0.0.1" côté appelant, comme ce proxy — n'est jamais vu
# "local" par go2rtc (hairpin NAT du pont Docker), donc jamais exempté de mot
# de passe. Toute Authorization déjà présente dans la requête d'origine
# (aucune en pratique — CameraPlayer.tsx n'en envoie pas) est remplacée, pas
# cumulée : un seul schéma d'auth a un sens ici.
_GO2RTC_AUTH_HEADER = b"Authorization: Basic " + base64.b64encode(
    f"{GO2RTC_API_AUTH[0]}:{GO2RTC_API_AUTH[1]}".encode()
)


def _rewrite_go2rtc_head(head: bytes):
    """Retire le préfixe /cameras de la ligne de requête avant de relayer vers go2rtc
    (qui ne connaît que ses routes nues). Force aussi Connection: close sur les requêtes
    HTTP classiques — une connexion gardée en vie (keep-alive) pourrait servir une 2e
    requête à un chemin différent que notre relecture ne reverrait jamais (on ne lit que
    la 1ère ligne de chaque connexion) ; en HTTP simple ça coûte juste une reconnexion TCP
    locale, négligeable. Exception : les upgrades WebSocket (signalisation WebRTC),
    qui doivent rester ouverts — on n'y touche pas. Injecte aussi l'authentification
    go2rtc (cf. _GO2RTC_AUTH_HEADER) — nécessaire pour CE relais comme pour tout
    autre appelant, cf. son commentaire."""
    sep = b"\r\n\r\n"
    idx = head.find(sep)
    head_part, body_start = (head[:idx], head[idx + 4:]) if idx != -1 else (head, b"")
    request_lines = head_part.split(b"\r\n")
    try:
        method, path, proto = request_lines[0].decode("latin-1").split(" ", 2)
    except ValueError:
        return head, False
    if path.startswith(_GO2RTC_PROXY_PREFIX):
        path = path[len(_GO2RTC_PROXY_PREFIX):] or "/"
        if not path.startswith("/"):
            path = "/" + path
    request_lines[0] = f"{method} {path} {proto}".encode("latin-1")
    is_websocket = any(
        line.lower().startswith(b"upgrade:") and b"websocket" in line.lower()
        for line in request_lines[1:]
    )
    if not is_websocket:
        request_lines = [line for line in request_lines if not line.lower().startswith(b"connection:")]
        request_lines.append(b"Connection: close")
    request_lines = [line for line in request_lines if not line.lower().startswith(b"authorization:")]
    request_lines.append(_GO2RTC_AUTH_HEADER)
    return b"\r\n".join(request_lines) + sep + body_start, is_websocket


def _pipe_bytes(src: socket.socket, dst: socket.socket):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


_CAMERA_SESSION_COOKIE = "domoticium_camera_session"


def _verify_camera_session_cookie(head: bytes) -> bool:
    """Vérifie le cookie de session caméra posé par GET /api/cameras/session
    côté web (audit add-on 2026-09-22) — seule protection de ce proxy, qui
    n'en avait AUCUNE jusqu'ici : n'importe qui connaissant l'URL du site
    (hostname du tunnel) avait un accès complet au flux vidéo ET à l'API
    go2rtc, sans le secret du site. Un navigateur ne pouvant pas envoyer
    d'en-tête personnalisé sur une connexion WebSocket native (contrainte du
    navigateur, pas de ce code — cf. CameraPlayer.tsx), l'authentification
    passe par un cookie (envoyé automatiquement par le navigateur pour tout
    sous-domaine de domoticium.fr, contrairement à X-Site-Secret) — signé
    avec le MÊME secret que tout le reste de l'addon (INGEST_SECRET), jamais
    transmis tel quel au navigateur, seul le HMAC en sort côté web."""
    if not INGEST_SECRET:
        return False
    m = re.search(rb"(?im)^Cookie:\s*(.+)$", head)
    if not m:
        return False
    value = None
    for part in m.group(1).decode("latin-1").split(";"):
        k, _, v = part.strip().partition("=")
        if k == _CAMERA_SESSION_COOKIE:
            value = v
            break
    if not value or "." not in value:
        return False
    expiry_str, _, sig = value.partition(".")
    try:
        expiry = int(expiry_str)
    except ValueError:
        return False
    if expiry < time.time():
        return False
    message = f"{SITE_PREFIX}:camera-session:{expiry}"
    expected = hmac.new(INGEST_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


class _Go2rtcProxyHandler(socketserver.BaseRequestHandler):
    """Retire le préfixe /cameras (imposé par le tunnel Cloudflare, qui ne réécrit
    jamais les chemins transmis à l'origine) puis relaie tel quel vers go2rtc
    (127.0.0.1:1984, nu). Nécessaire car mettre ce préfixe directement dans go2rtc
    (api.base_path) casse son propre healthcheck interne — cf. GO2RTC_API_BASE."""

    def handle(self):
        client_sock = self.request
        upstream = None
        try:
            client_sock.settimeout(10)
            head = _read_http_head(client_sock)
            if not head:
                return
            # Abonnement suspendu : le relais caméra À DISTANCE (arrivée par le tunnel Cloudflare, qui ajoute toujours CF-Connecting-IP)
            # est coupé ; les caméras restent utilisables en local.
            if b"cf-connecting-ip:" in head.lower() and _gateway_is_suspended():
                try:
                    client_sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
                return
            if not _verify_camera_session_cookie(head):
                try:
                    client_sock.sendall(
                        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                except OSError:
                    pass
                return
            new_head, _is_websocket = _rewrite_go2rtc_head(head)
            upstream = socket.create_connection(_GO2RTC_UPSTREAM_ADDR, timeout=10)
            upstream.sendall(new_head)
            client_sock.settimeout(None)
            upstream.settimeout(None)
            t = threading.Thread(target=_pipe_bytes, args=(client_sock, upstream), daemon=True)
            t.start()
            _pipe_bytes(upstream, client_sock)
            t.join(timeout=5)
        except OSError:
            pass
        except Exception as e:
            warn(f"[go2rtc-proxy] {e}")
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass


def run_go2rtc_prefix_proxy():
    """Proxy local (127.0.0.1 uniquement) — ingress Cloudflare pour /cameras doit
    pointer ici (127.0.0.1:GO2RTC_PROXY_PORT), pas directement sur go2rtc:1984."""
    try:
        server = _ReusableTCPServer(("127.0.0.1", GO2RTC_PROXY_PORT), _Go2rtcProxyHandler)
        server.daemon_threads = True
        log(f"[go2rtc-proxy] ✓ Proxy /cameras actif sur 127.0.0.1:{GO2RTC_PROXY_PORT} → 127.0.0.1:1984")
        server.serve_forever()
    except Exception as e:
        warn(f"[go2rtc-proxy] Erreur fatale : {e}")


_LOCAL_WEB_UPSTREAM_ADDR = ("127.0.0.1", 8100)


class _LocalTlsRelayHandler(socketserver.BaseRequestHandler):
    """Relaie tel quel (aucune réécriture de chemin, contrairement à
    _Go2rtcProxyHandler) vers l'add-on « Domoticium — Accès local » (port 8100,
    même code source que web/, build local). Pas de vérification applicative
    ici — l'app locale gère sa propre session (même mécanisme qu'un accès
    direct non-TLS à 8100 aujourd'hui), ce relais ne fait que terminer le TLS."""

    def _upstream_addr(self):
        return _LOCAL_WEB_UPSTREAM_ADDR

    def handle(self):
        client_sock = self.request  # déjà un ssl.SSLSocket, cf. _LocalTlsRelayServer.get_request
        upstream = None
        try:
            client_sock.settimeout(10)
            upstream = socket.create_connection(self._upstream_addr(), timeout=10)
            client_sock.settimeout(None)
            upstream.settimeout(None)
            t = threading.Thread(target=_pipe_bytes, args=(client_sock, upstream), daemon=True)
            t.start()
            _pipe_bytes(upstream, client_sock)
            t.join(timeout=5)
        except OSError:
            pass
        except Exception as e:
            warn(f"[local-tls] {e}")
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass


class _LocalHaTlsRelayHandler(_LocalTlsRelayHandler):
    """Même relais TLS, mais vers le frontend de Home Assistant (port RÉEL lu auprès du Supervisor)."""

    def _upstream_addr(self):
        return ("127.0.0.1", _ha_core_port())


class _LocalTlsRelayServer(_ReusableTCPServer):
    """Enveloppe chaque connexion acceptée avec le contexte TLS COURANT
    (relu à chaque accept(), jamais figé à la création du serveur) — permet à
    _fetch_local_cert() de faire tourner un certificat renouvelé sans jamais
    redémarrer ce serveur ni couper les connexions déjà en cours."""

    def get_request(self):
        sock, addr = self.socket.accept()
        if _local_tls_context is None:
            sock.close()
            raise OSError("Aucun certificat local disponible pour l'instant")
        # Le handshake TLS se fait ici, de façon synchrone, dans la boucle
        # d'accept() du serveur (pas dans le thread par connexion) — un délai
        # borné évite qu'une connexion qui traîne (lenteur réseau ou abus)
        # ne bloque l'acceptation des connexions suivantes indéfiniment.
        sock.settimeout(10)
        wrapped = _local_tls_context.wrap_socket(sock, server_side=True)
        wrapped.settimeout(None)
        return wrapped, addr


def _run_tls_relay(port, handler_cls, label):
    """Relais HTTPS local (0.0.0.0:port) — attend qu'un 1er certificat soit chargé
    (_fetch_local_cert, cycle de sync 5 min) avant de se lier : un site tout juste créé
    n'a pas encore de certificat émis côté cloud (cron quotidien), ce n'est jamais une
    erreur à signaler en boucle."""
    while _local_tls_context is None:
        time.sleep(15)
    try:
        server = _LocalTlsRelayServer(("0.0.0.0", port), handler_cls)
        server.daemon_threads = True
        log(f"[local-tls] ✓ Relais HTTPS actif sur 0.0.0.0:{port} → {label}")
        server.serve_forever()
    except Exception as e:
        warn(f"[local-tls] Erreur fatale ({label}) : {e}")


def run_local_tls_relay():
    """0.0.0.0:LOCAL_TLS_PORT → 127.0.0.1:8100 (app « Accès local »)."""
    _run_tls_relay(LOCAL_TLS_PORT, _LocalTlsRelayHandler, "127.0.0.1:8100")


def run_local_ha_tls_relay():
    """0.0.0.0:LOCAL_HA_TLS_PORT → frontend de Home Assistant (connexion HA en HTTPS)."""
    _run_tls_relay(LOCAL_HA_TLS_PORT, _LocalHaTlsRelayHandler, "Home Assistant")


# ── Port réel de Home Assistant Core ─────────────────────────────────────────────────────────────
# Bug réel trouvé au retest (2026-11-21) : depuis HA 2026.8, une installation neuve écoute sur le port 80, plus
# 8123 (Supervisor /core/info → "port": 80, vérifié sur le site de test). Tout ce qui supposait « HA = 127.0.0.1:8123 »
# était donc cassé en silence : l'app locale (500 sur /api/auth/callback), l'accès technicien (WebSocket + /auth/token
# de main.py) et l'ingress du tunnel du site (ha-{slug} → http://127.0.0.1:8123, défini côté Cloudflare).
_ha_core_port_cache = {"at": 0.0, "port": 8123}


def _ha_core_port():
    """Port sur lequel HA Core écoute VRAIMENT, d'après le Supervisor (source de vérité, jamais deviné).
    Gardé 5 s ; si le Supervisor ne répond pas, on garde la dernière valeur connue (8123 au tout début)."""
    now = time.time()
    if now - _ha_core_port_cache["at"] < 5:
        return _ha_core_port_cache["port"]
    try:
        r = requests.get(f"{SUP}/core/info", headers=HDRS, timeout=5)
        port = int((r.json().get("data") or {}).get("port") or 0)
        if 0 < port < 65536:
            _ha_core_port_cache["port"] = port
    except Exception:
        pass
    _ha_core_port_cache["at"] = now
    return _ha_core_port_cache["port"]


# En-têtes posés par un reverse proxy (cloudflared / Cloudflare) que Home Assistant traite à part.
_HA_FORWARD_HEADERS = (b"x-forwarded-for:", b"x-forwarded-proto:", b"x-forwarded-host:", b"x-forwarded-port:", b"forwarded:", b"x-real-ip:")


def _strip_forwarded_head(head: bytes) -> bytes:
    """Retire de la requête les en-têtes de reverse proxy et force Connection: close (hors upgrade WebSocket).

    Bug réel trouvé au retest (2026-11-24) : l'accès technicien (tunnel ha-{slug} → ce relais → HA) renvoyait « 400 Bad
    Request ». HA 2026.11 (port 80) répond à toute requête portant X-Forwarded-For par « A request from a reverse proxy was
    received from …, but your HTTP integration is not set-up for reverse proxies », ALORS QUE le bloc `http:` de
    configuration.yaml (use_x_forwarded_for + trusted_proxies 127.0.0.1) est présent, valide, et que HA a été redémarré
    depuis — vérifié : HA ne l'applique pas sur cette version. Plutôt que de dépendre d'un réglage que HA ignore, le relais
    présente la requête comme locale (HA voit 127.0.0.1, comme pour l'add-on « Accès local »). Connection: close évite qu'une
    connexion réutilisée par cloudflared fasse passer une 2e requête, jamais relue, avec ses propres en-têtes."""
    sep = b"\r\n\r\n"
    idx = head.find(sep)
    head_part, rest = (head[:idx], head[idx + 4:]) if idx != -1 else (head, b"")
    lines = head_part.split(b"\r\n")
    kept = [lines[0]] + [ln for ln in lines[1:] if not ln.lower().startswith(_HA_FORWARD_HEADERS)]
    is_websocket = any(ln.lower().startswith(b"upgrade:") and b"websocket" in ln.lower() for ln in kept[1:])
    if not is_websocket:
        kept = [kept[0]] + [ln for ln in kept[1:] if not ln.lower().startswith(b"connection:")] + [b"Connection: close"]
    return b"\r\n".join(kept) + sep + rest


class _HaPortShimHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client_sock = self.request
        upstream = None
        try:
            client_sock.settimeout(15)
            head = _read_http_head(client_sock)
            if not head:
                return
            upstream = socket.create_connection(("127.0.0.1", _ha_core_port()), timeout=10)
            upstream.sendall(_strip_forwarded_head(head))
            client_sock.settimeout(None)
            upstream.settimeout(None)
            t = threading.Thread(target=_pipe_bytes, args=(client_sock, upstream), daemon=True)
            t.start()
            _pipe_bytes(upstream, client_sock)
            t.join(timeout=5)
        except OSError:
            pass
        except Exception as e:
            warn(f"[ha-shim] {e}")
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass


def _run_ha_port_shim(sleep=None, max_loops=None):
    """Garde 127.0.0.1:8123 joignable quand HA Core écoute ailleurs (port 80 depuis HA 2026.8) : l'ingress du
    tunnel (défini côté Cloudflare, identique pour tous les sites) vise 127.0.0.1:8123 et ne peut pas connaître le
    port de chaque boîtier. Un simple relais TCP loopback uniquement, actif SEULEMENT tant que le Supervisor dit
    que HA n'est pas sur 8123 : si HA est (re)configuré sur 8123, le relais se retire en ≤ 5 s pour lui laisser la
    place. Port déjà occupé (par HA lui-même) : on ne touche à rien."""
    sleep = sleep or time.sleep
    server = None
    warned = False
    n = 0
    while max_loops is None or n < max_loops:
        n += 1
        try:
            port = _ha_core_port()
            want = bool(port) and port != 8123
            if want and server is None:
                try:
                    server = _ReusableTCPServer(("127.0.0.1", 8123), _HaPortShimHandler)
                    server.daemon_threads = True
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                    log(f"[ha-shim] ✓ 127.0.0.1:8123 → 127.0.0.1:{port} (HA Core n'écoute pas sur 8123)")
                    warned = False
                except OSError as e:
                    server = None
                    if not warned:
                        warn(f"[ha-shim] 127.0.0.1:8123 déjà occupé ({e}) — laissé tel quel")
                        warned = True
            elif not want and server is not None:
                server.shutdown()
                server.server_close()
                server = None
                log("[ha-shim] HA Core est (re)passé sur 8123 — relais retiré")
        except Exception as e:
            warn(f"[ha-shim] {e}")
        sleep(5)


# ── Superviseur des add-ons (2026-11-22) ─────────────────────────────────────────────────────────────────────
# Retour d'Hicham au retest : un clavier d'alarme est resté hors ligne parce que Zigbee2MQTT/MQTT était « en erreur »
# jusqu'à un redémarrage MANUEL, alors que le Watchdog du Supervisor est activé. Normal : ce Watchdog ne redémarre qu'un
# add-on dont le process MEURT (cf. _enable_watchdogs_once) ; un service bloqué ou en erreur n'y change rien. Chez un
# client, personne ne sera là pour le redémarrer : le boîtier surveille donc lui-même ses applications.
#
# On surveille les APPLICATIONS, jamais les équipements (une ampoule hors tension est « hors ligne » sans que Zigbee
# y soit pour rien — décision d'Hicham). Une application est « en panne » si : le Supervisor la dit en erreur, ou arrêtée
# alors qu'elle démarre normalement toute seule, ou démarrée mais ne répondant plus (sonde fonctionnelle). En panne en
# continu depuis 5 min → (re)démarrage ciblé de CETTE application seulement. Garde-fous : rien pendant les 10 min qui
# suivent le démarrage de cet add-on, 10 min de pause après un redémarrage, 3 redémarrages par heure au plus par
# application (au-delà : on arrête et on le signale dans les logs, jamais de boucle), et un fichier /data/health_pause
# suspend tout (maintenance volontaire par un technicien).
_HEALTH_PERIOD_S = 60
_HEALTH_FAIL_RESTART_S = 300
_HEALTH_BOOT_GRACE_S = 600
_HEALTH_COOLDOWN_S = 600
_HEALTH_MAX_PER_HOUR = 3
_HEALTH_PAUSE_FILE = "/data/health_pause"
_HEALTH_BOOT_AT = time.time()
_health_state: dict = {}
_z2m_health_event = threading.Event()
_z2m_health_seen = {"ok": False}


def _tcp_ok(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _health_probe_z2m() -> bool:
    """Zigbee2MQTT répond-il ? Son état « online » (bridge/state) est retenu par le broker et reste vrai même si le
    process est bloqué : on lui adresse donc un health_check (réponse attendue sous 8 s ; une réponse d'erreur compte,
    elle prouve qu'il est vivant). Sans connexion MQTT de notre côté, on ne conclut rien (None = pas de sonde)."""
    if _z2m_online is False:
        return False
    if not _local_client or not _local_client.is_connected():
        return None  # notre propre lien MQTT est coupé : c'est la sonde Mosquitto qui tranche, pas celle-ci
    _z2m_health_event.clear()
    try:
        _local_client.publish("zigbee2mqtt/bridge/request/health_check", "", qos=0)
    except Exception:
        return None
    got = _z2m_health_event.wait(timeout=8)
    if got:
        _z2m_health_seen["ok"] = True
        return True
    # Une version de Zigbee2MQTT qui ne connaîtrait pas health_check ne répondrait jamais : tant qu'une réponse n'a pas
    # été vue AU MOINS UNE FOIS, l'absence de réponse ne prouve rien (jamais de redémarrage sur cette seule base).
    return False if _z2m_health_seen["ok"] else None


def _health_probe_local_web() -> bool:
    try:
        return requests.get("http://127.0.0.1:8100/", timeout=6, allow_redirects=False).status_code < 500
    except Exception:
        return False


# (clé, reconnaissance du slug, sonde fonctionnelle ou None = on ne regarde que l'état Supervisor)
_HEALTH_APPS = [
    ("mosquitto", lambda s: s == "core_mosquitto", lambda: _tcp_ok("127.0.0.1", 1883)),
    ("zigbee2mqtt", lambda s: s.endswith("_zigbee2mqtt"), _health_probe_z2m),
    ("matter", lambda s: s == "core_matter_server", lambda: _tcp_ok("127.0.0.1", 5580)),
    ("accès local", lambda s: s.endswith("_domoticium_web") and not s.endswith("_local_web"), _health_probe_local_web),
    # Frigate : état Supervisor seulement (jamais de redémarrage sur une sonde — risque de faux positif documenté).
    ("frigate", lambda s: s.endswith("_frigate") and s != OLD_FRIGATE_SLUG, None),
    ("thread", lambda s: s == "core_openthread_border_router", None),
]


def _health_decide(st: dict, bad: bool, stopped: bool, now: float) -> str:
    """Décision pure pour une application : « none », « restart », « start » ou « give_up » (plafond atteint).
    Met à jour st : since (début de la panne continue), restarts (horodatages), gave_up."""
    if not bad:
        st["since"] = None
        st["gave_up"] = False
        return "none"
    if st.get("since") is None:
        st["since"] = now
    if now - st["since"] < _HEALTH_FAIL_RESTART_S:
        return "none"
    st["restarts"] = [t for t in st.get("restarts", []) if now - t < 3600]
    if st["restarts"] and now - st["restarts"][-1] < _HEALTH_COOLDOWN_S:
        return "none"
    if len(st["restarts"]) >= _HEALTH_MAX_PER_HOUR:
        return "give_up"
    st["restarts"].append(now)
    return "start" if stopped else "restart"


def _health_check_once(now: float | None = None) -> list:
    """Un passage de contrôle ; renvoie la liste des actions entreprises [(application, action)] (pour les tests)."""
    now = time.time() if now is None else now
    done = []
    if now - _HEALTH_BOOT_AT < _HEALTH_BOOT_GRACE_S or os.path.exists(_HEALTH_PAUSE_FILE):
        return done
    r = sup_get("/addons")
    if not r.ok:
        return done
    body = r.json()
    addons = (body.get("data", body) or {}).get("addons", [])
    by_slug = {a.get("slug", ""): a for a in addons if isinstance(a, dict)}
    for key, match, probe in _HEALTH_APPS:
        slug = next((sl for sl in by_slug if match(sl)), None)
        if not slug:
            continue  # application non installée sur ce site
        st = _health_state.setdefault(key, {"since": None, "restarts": [], "gave_up": False})
        state = by_slug[slug].get("state")
        stopped = state in ("stopped", "unknown", None, "")
        if state == "startup":
            continue  # démarrage en cours : ni sain ni en panne
        if stopped:
            info = sup_get(f"/addons/{slug}/info")
            boot = ((info.json().get("data") or {}).get("boot") if info.ok else None)
            bad = boot == "auto"  # arrêtée à la main alors qu'elle devrait tourner : on la relance après 5 min
        elif state == "error":
            bad = True
        else:
            ok = probe() if probe else None
            bad = ok is False
        action = _health_decide(st, bad, stopped, now)
        if action == "give_up":
            if not st["gave_up"]:
                st["gave_up"] = True
                warn(f"[health] {key} : toujours en panne après {_HEALTH_MAX_PER_HOUR} redémarrages en 1 h — abandon (intervention nécessaire)")
            continue
        if action in ("start", "restart"):
            warn(f"[health] {key} ({slug}) en panne depuis ≥ {_HEALTH_FAIL_RESTART_S // 60} min (état Supervisor : {state}) — "
                 f"{'démarrage' if action == 'start' else 'redémarrage'}")
            try:
                rr = sup_post(f"/addons/{slug}/{action}", timeout=120)
                if not rr.ok:
                    warn(f"[health] {key} : échec {action} HTTP {rr.status_code}")
            except Exception as e:
                warn(f"[health] {key} : échec {action} : {e}")
            done.append((key, action))
            st["since"] = None  # nouvelle période d'observation après l'action
            break  # un seul redémarrage par passage : on laisse le temps à l'application de remonter
    return done


def _run_health_supervisor(sleep=None, max_loops=None):
    sleep = sleep or time.sleep
    n = 0
    while max_loops is None or n < max_loops:
        n += 1
        try:
            _health_check_once()
        except Exception as e:
            warn(f"[health] {e}")
        sleep(_HEALTH_PERIOD_S)


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
    _load_camera_masks()
    _load_alarmo_schedules()
    global _turn_ice_servers
    # synchrone — requis avant la 1ère écriture frigate.yml ; repli STUN local si le
    # 1er fetch échoue (pas de restart en jeu ici, juste la valeur initiale)
    _turn_ice_servers = _fetch_turn_ice_servers() or [{"urls": ["stun:stun.cloudflare.com:3478"]}]
    start_cloudflared()
    threading.Thread(target=_remove_legacy_heartbeat_automation_once, daemon=True).start()
    threading.Thread(target=_remove_legacy_rest_commands_once, daemon=True).start()
    threading.Thread(target=_enable_watchdogs_once, daemon=True).start()
    threading.Thread(target=_reenable_frigate_watchdog_if_needed, daemon=True).start()
    threading.Thread(target=_ensure_frigate,       daemon=True).start()
    threading.Thread(target=_turn_refresh_loop,    daemon=True).start()
    threading.Thread(target=_ensure_matter_server, daemon=True).start()
    threading.Thread(target=_check_and_fix_mqtt_broker, daemon=True).start()
    threading.Thread(target=_run_fleet_status_loop, daemon=True).start()
    threading.Thread(target=_ha_sync_loop,   daemon=True).start()
    threading.Thread(target=_alarmo_calendar_loop, daemon=True).start()
    threading.Thread(target=run_local_bridge, daemon=True).start()
    # Bridge HA WebSocket → Supabase (ingest) : seul canal d'état, remplace EMQX
    threading.Thread(target=run_ha_ws_bridge, daemon=True).start()
    # Retry des transitions d'alarme (seul état encore remonté au cloud)
    threading.Thread(target=_flush_alarm_state_batch, daemon=True).start()
    threading.Thread(target=_run_alerts_engine,      daemon=True).start()
    threading.Thread(target=_run_entitlement_loop,   daemon=True, name="entitlement").start()
    # Watchdog caméras : sonde go2rtc toutes les 60s, deltas envoyés dans le batch
    threading.Thread(target=_run_camera_watchdog,    daemon=True).start()
    # Proxy /cameras → go2rtc (retire le préfixe imposé par le tunnel Cloudflare)
    threading.Thread(target=run_go2rtc_prefix_proxy, daemon=True).start()
    # Relais HTTPS local (pastille 3 couleurs) → add-on "Domoticium — Accès local" (8100)
    threading.Thread(target=run_local_tls_relay, daemon=True).start()
    threading.Thread(target=run_local_ha_tls_relay, daemon=True).start()
    threading.Thread(target=_run_ha_port_shim, daemon=True, name="ha-shim").start()
    threading.Thread(target=_run_health_supervisor, daemon=True, name="health").start()

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

    # Tout au début, avant Frigate/Zigbee2MQTT/Matter — idempotent, patch aussi les
    # sites déjà provisionnés. Volontairement AVANT tout le reste (et pas à la fin,
    # première version) : le redémarrage HA que ça peut déclencher la toute première
    # fois doit être réglé avant que des étapes sensibles au timing ne commencent
    # (appairage Zigbee/Matter en cours plus loin dans l'installation) plutôt que de
    # risquer de tomber en plein milieu.
    wait_for_ha()
    _needs_ha_restart = _ensure_ha_trusted_proxy()
    _needs_ha_restart = _remove_ha_debug_logger_once() or _needs_ha_restart
    if _needs_ha_restart:
        log("[setup] Redémarrage HA Core pour appliquer configuration.yaml…")
        try:
            requests.post(f"{SUP}/homeassistant/restart",
                          headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"}, timeout=60)
        except Exception as e:
            warn(f"[setup] Erreur restart HA : {e}")
        wait_for_ha()

    # Écrire la config Frigate AVANT tout le reste.
    # Le prepare script Frigate copie /homeassistant/frigate.yml → addon_config privé
    # (/config/config.yml dans le conteneur Frigate) si ce dernier n'existe pas encore.
    # La config contient version:"0.18-0" → toute migration Frigate est skippée.
    _load_cameras()
    _load_camera_masks()
    write_frigate_config()

    if FORCE_SETUP:
        log("force_setup activé — réinitialisation complète de la configuration")
        if os.path.exists(SETUP_DONE):
            os.remove(SETUP_DONE)
    if not os.path.exists(SETUP_DONE):
        run_setup()
    else:
        log("Déjà configuré — démarrage du service.")

    install_alarmo()  # idempotent — vérifie/installe Alarmo à chaque démarrage
    install_local_web_addon()  # idempotent — vérifie/installe l'add-on "Accès local" à chaque démarrage
    _ensure_alarmo_night_mode()  # idempotent — active le mode nuit + force délais courts présent/nuit
    _ensure_alarmo_area_name()  # idempotent — renomme la zone "Alarmo" → "Habitation"
    _ensure_z2m_availability()  # idempotent — patch les sites déjà provisionnés

    run_bridge()
