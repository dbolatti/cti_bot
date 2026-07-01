import feedparser
import sqlite3
import asyncio
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from groq import Groq
from telegram import Bot
from dotenv import load_dotenv
import time

# Ensure the console handles UTF-8 (Cyrillic, CJK, etc.) without crashing on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Configuración ─────────────────────────────────────────────
load_dotenv()

TELEGRAM_TOKEN    = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID  = os.getenv("TELEGRAM_CHAT_ID")
GROQ_API_KEY      = os.getenv("GROQ_API_KEY")

# chat_ids autorizados a controlar el bot y recibir alertas.
# Por defecto solo el owner (TELEGRAM_CHAT_ID); se puede sumar otros vía ALLOWED_CHAT_IDS.
_allowed_extra    = [c.strip() for c in os.getenv("ALLOWED_CHAT_IDS", "").split(",") if c.strip()]
ALLOWED_CHAT_IDS  = set(filter(None, [TELEGRAM_CHAT_ID] + _allowed_extra))

def validate_config():
    """Verifica que las credenciales obligatorias estén presentes antes de correr el pipeline."""
    missing = [
        name for name, val in (
            ("TELEGRAM_TOKEN", TELEGRAM_TOKEN),
            ("TELEGRAM_CHAT_ID", TELEGRAM_CHAT_ID),
            ("GROQ_API_KEY", GROQ_API_KEY),
        )
        if not val
    ]
    if missing:
        raise SystemExit(
            f"[FATAL] Faltan variables de entorno obligatorias en .env: {', '.join(missing)}"
        )

# ── Configuración de notificaciones ──────────────────────────
SEND_PRIORITY_UP_TO  = int(os.getenv("SEND_PRIORITY_UP_TO", "2"))
NOTIFY_MODE          = os.getenv("NOTIFY_MODE",   "realtime")   # realtime | hourly | daily | both
NOTIFY_DETAIL        = os.getenv("NOTIFY_DETAIL", "compact")    # compact | detailed | minimal
SME_ONLY             = os.getenv("SME_ONLY",      "false").lower() == "true"
CATEGORIES           = [c.strip() for c in os.getenv("CATEGORIES", "").split(",") if c.strip()]
DAILY_SUMMARY_HOUR   = int(os.getenv("DAILY_SUMMARY_HOUR", "8"))

FEEDS = {
    # existentes
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "TheHackerNews":    "https://feeds.feedburner.com/TheHackersNews",
    "ENISA":            "https://www.enisa.europa.eu/topics/cyber-threats/threats-and-trends/rss",
    "Schneier":         "https://www.schneier.com/feed/atom/",
    "SANS ISC":         "https://isc.sans.edu/rssfeed_full.xml",

    # nuevos
    "Krebs on Security":  "https://krebsonsecurity.com/feed/",
    "Recorded Future":    "https://therecord.media/feed",
    "Securelist":         "https://securelist.com/feed/",
    "Malwarebytes Labs":  "https://www.malwarebytes.com/blog/feed/",
    "Cisco Talos":        "https://blog.talosintelligence.com/feeds/posts/default",
    "Unit 42":            "https://unit42.paloaltonetworks.com/feed/",
    
    # nuevos_2
    "ThreatPost":        "https://threatpost.com/feed/",
    "Dark Reading":      "https://www.darkreading.com/rss.xml",
    "CERT/CC":           "https://www.kb.cert.org/feeds/cert-kb-latest.xml",
}

DB_PATH = "cti.db"
# qué prioridades enviar: 1, 2, o 3
SEND_PRIORITY_UP_TO = 2

# Mapeo categoría → controles CIS v8 IG1 relevantes
CIS_MAPPING = {
    "ransomware": [
        ("CIS-11.2", "Recuperación de datos"),
        ("CIS-8.2",  "Antimalware"),
        ("CIS-10.1", "Backups automáticos"),
    ],
    "phishing": [
        ("CIS-9.2",  "Filtros de email"),
        ("CIS-14.1", "Concientización"),
        ("CIS-6.1",  "Gestión de cuentas"),
    ],
    "exploit": [
        ("CIS-7.3",  "Parches de aplicaciones"),
        ("CIS-7.2",  "Parches de SO"),
        ("CIS-4.1",  "Inventario de software"),
    ],
    "malware": [
        ("CIS-8.1",  "Antimalware en endpoints"),
        ("CIS-7.1",  "Gestión de vulnerabilidades"),
        ("CIS-6.2",  "Privilegio mínimo"),
    ],
    "vulnerability": [
        ("CIS-7.1",  "Proceso de gestión de vulns"),
        ("CIS-7.2",  "Parches de SO"),
        ("CIS-7.3",  "Parches de aplicaciones"),
    ],
    "breach": [
        ("CIS-3.1",  "Inventario de datos"),
        ("CIS-6.1",  "Gestión de cuentas"),
        ("CIS-13.1", "Monitoreo de red"),
    ],
    "other": [
        ("CIS-1.1",  "Inventario de activos"),
    ],
}

SOURCE_DEFAULTS = {
    "Ransomware.live":  {
        "category":    "ransomware",
        "severity":    "high",
        "sme_relevant": True,
        "sme_reason":  "Ataque de ransomware activo — riesgo directo de cifrado de datos y extorsión",
        "summary":     "",   # se completa dinámicamente
    },
    "CISA KEV": {
        "category":    "vulnerability",
        "severity":    "high",
        "sme_relevant": True,
        "sme_reason":  "Vulnerabilidad explotada activamente — requiere parcheo inmediato",
        "summary":     "",
    },
    "Abuse.ch URLhaus": {
        "category":    "malware",
        "severity":    "high",
        "sme_relevant": True,
        "sme_reason":  "URL maliciosa activa — riesgo de infección por navegación o email",
        "summary":     "",
    },
    "EPSS/FIRST": {
    "category":     "vulnerability",
    "severity":     "high",
    "sme_relevant":  True,
    "sme_reason":   "CIS-7.1: CVE con alta probabilidad de explotación activa — priorizar parcheo",
    "summary":      "",
    },
    "CERT/CC": {
        "category":     "vulnerability",
        "severity":     "high",
        "sme_relevant":  True,
        "sme_reason":   "CIS-7.3: advisory oficial — verificar aplicabilidad en software instalado",
        "summary":      "",
    },
}

def get_cis_controls(category: str) -> list[tuple]:
    return CIS_MAPPING.get(category, CIS_MAPPING["other"])

# ── Base de datos ─────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id           TEXT PRIMARY KEY,
            title        TEXT,
            source       TEXT,
            category     TEXT,
            severity     TEXT,
            sme_flag     INTEGER,
            sme_reason   TEXT,
            cis_controls TEXT,
            summary      TEXT,
            ts           TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS user_config (
            chat_id      TEXT PRIMARY KEY,
            notify_mode  TEXT DEFAULT 'realtime',
            notify_detail TEXT DEFAULT 'compact',
            priority_max INTEGER DEFAULT 2,
            sme_only     INTEGER DEFAULT 0,
            categories   TEXT DEFAULT '',
            updated_at   TEXT
        )
    """)
    con.commit()
    return con

def get_user_config(con, chat_id: str) -> dict:
    row = con.execute(
        "SELECT * FROM user_config WHERE chat_id=?", (chat_id,)
    ).fetchone()
    if not row:
        # config por defecto
        return {
            "chat_id":      chat_id,
            "notify_mode":  NOTIFY_MODE,
            "notify_detail": NOTIFY_DETAIL,
            "priority_max": SEND_PRIORITY_UP_TO,
            "sme_only":     1 if SME_ONLY else 0,
            "categories":   ",".join(CATEGORIES),
        }
    cols = ["chat_id","notify_mode","notify_detail","priority_max","sme_only","categories","updated_at"]
    return dict(zip(cols, row))

def save_user_config(con, chat_id: str, **kwargs):
    existing = get_user_config(con, chat_id)
    existing.update(kwargs)
    existing["updated_at"] = datetime.now(timezone.utc).isoformat()
    con.execute("""
        INSERT OR REPLACE INTO user_config
        (chat_id, notify_mode, notify_detail, priority_max, sme_only, categories, updated_at)
        VALUES (?,?,?,?,?,?,?)
    """, (
        existing["chat_id"],
        existing["notify_mode"],
        existing["notify_detail"],
        existing["priority_max"],
        existing["sme_only"],
        existing["categories"],
        existing["updated_at"],
    ))
    con.commit()

def should_process_for_user(item: dict, cfg: dict) -> bool:
    if cfg["sme_only"] and not item.get("sme_relevant"):
        return False
    cats = [c.strip() for c in cfg["categories"].split(",") if c.strip()]
    if cats and item.get("category") not in cats:
        return False
    priority = get_priority(item)
    if priority == 0 or priority > cfg["priority_max"]:
        return False
    return True

AYUDA_MSG = """
*Comandos disponibles:*

*Modo de notificación:*
`/modo realtime` — alertas en tiempo real
`/modo daily` — solo resumen diario
`/modo both` — ambos

*Detalle del mensaje:*
`/detalle compact` — 4 líneas + link
`/detalle detailed` — resumen completo + controles CIS
`/detalle minimal` — solo título + link

*Prioridad mínima:*
`/prioridad 1` — solo crítico (P1)
`/prioridad 2` — crítico + importante (P1+P2)
`/prioridad 3` — todo

*Filtros:*
`/filtro ransomware,phishing` — solo esas categorías
`/filtro off` — sin filtro
`/sme on` — solo items con impacto operacional
`/sme off` — todos los items

*Info:*
`/status` — ver tu configuración actual
`/ayuda` — este mensaje
"""

async def handle_commands(bot, con):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        updates = resp.json().get("result", [])

    if not updates:
        return

    last_id = updates[-1]["update_id"]

    for update in updates:
        msg = update.get("message", {})
        if not msg:
            continue
        chat_id = str(msg["chat"]["id"])
        text    = msg.get("text", "").strip().lower()

        if not text.startswith("/"):
            continue

        # solo chat_ids autorizados pueden controlar el bot / quedar suscriptos a alertas
        if chat_id not in ALLOWED_CHAT_IDS:
            print(f"  [SECURITY] comando ignorado de chat_id no autorizado: {chat_id}")
            continue

        parts = text.split()
        cmd   = parts[0]
        arg   = parts[1] if len(parts) > 1 else ""

        reply = None

        if cmd == "/ayuda":
            reply = AYUDA_MSG

        elif cmd == "/status":
            cfg = get_user_config(con, chat_id)
            cats = cfg["categories"] or "todas"
            reply = (
                f"*Tu configuración actual:*\n"
                f"Modo: `{cfg['notify_mode']}`\n"
                f"Detalle: `{cfg['notify_detail']}`\n"
                f"Prioridad máx: `P{cfg['priority_max']}`\n"
                f"Solo relevante: `{'sí' if cfg['sme_only'] else 'no'}`\n"
                f"Categorías: `{cats}`"
            )

        elif cmd == "/modo":
            if arg in ("realtime", "daily", "both"):
                save_user_config(con, chat_id, notify_mode=arg)
                reply = f"✅ Modo cambiado a `{arg}`"
            else:
                reply = "❌ Valores válidos: `realtime`, `daily`, `both`"

        elif cmd == "/detalle":
            if arg in ("compact", "detailed", "minimal"):
                save_user_config(con, chat_id, notify_detail=arg)
                reply = f"✅ Detalle cambiado a `{arg}`"
            else:
                reply = "❌ Valores válidos: `compact`, `detailed`, `minimal`"

        elif cmd == "/prioridad":
            if arg in ("1", "2", "3"):
                save_user_config(con, chat_id, priority_max=int(arg))
                reply = f"✅ Prioridad máxima: `P{arg}`"
            else:
                reply = "❌ Valores válidos: `1`, `2`, `3`"

        elif cmd == "/filtro":
            if arg == "off":
                save_user_config(con, chat_id, categories="")
                reply = "✅ Filtro de categorías desactivado"
            else:
                valid = {"ransomware","phishing","exploit","malware","vulnerability","breach","other"}
                cats  = [c.strip() for c in arg.split(",") if c.strip() in valid]
                if cats:
                    save_user_config(con, chat_id, categories=",".join(cats))
                    reply = f"✅ Filtrando: `{', '.join(cats)}`"
                else:
                    reply = "❌ Categorías válidas: ransomware, phishing, exploit, malware, vulnerability, breach, other"

        elif cmd == "/sme":
            if arg == "on":
                save_user_config(con, chat_id, sme_only=1)
                reply = "✅ Solo items con impacto operacional"
            elif arg == "off":
                save_user_config(con, chat_id, sme_only=0)
                reply = "✅ Mostrando todos los items"
            else:
                reply = "❌ Valores válidos: `on`, `off`"

        if reply:
            await bot.send_message(
                chat_id=chat_id,
                text=reply,
                parse_mode="Markdown"
            )

    # marcar updates como procesados
    if last_id:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.get(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates",
                params={"offset": last_id + 1}
            )

def is_seen(con, item_id: str) -> bool:
    return con.execute(
        "SELECT 1 FROM items WHERE id=?", (item_id,)
    ).fetchone() is not None

def save_item(con, item: dict):
    controls = get_cis_controls(item["category"])
    cis_json = json.dumps([c[0] for c in controls])
    con.execute(
        "INSERT OR IGNORE INTO items VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            item["id"], item["title"], item["source"],
            item["category"], item["severity"],
            1 if item["sme_relevant"] else 0,
            item["sme_reason"], cis_json,
            item["summary"],
            datetime.now(timezone.utc).isoformat()
        )
    )
    con.commit()

# ── Clasificación con Groq ─────────────────────────────────────
client_groq = Groq(api_key=GROQ_API_KEY)

CLASSIFY_PROMPT = """\
Sos un analista de ciberseguridad especializado en pequeñas y medianas empresas.
Clasificá el siguiente evento y respondé ÚNICAMENTE con JSON válido, sin texto adicional.

Título: {title}
Descripción: {desc}

Reglas para sme_reason:
- Explicá el impacto técnico concreto, no menciones "PyME" ni "empresa"
- Referenciá el control CIS v8 IG1 más relevante (ej: CIS-7.3, CIS-9.2)
- Máximo una línea, directo al punto
- Ejemplos buenos:
  "CIS-7.3: parche crítico pendiente en software de uso masivo"
  "CIS-9.2: campaña de phishing activa via email corporativo"
  "CIS-8.1: malware con capacidad de movimiento lateral en red local"
  "CIS-10.1: ransomware activo — evaluar estado de backups offline"

Formato requerido:
{{
  "category": "ransomware|phishing|exploit|malware|vulnerability|breach|other",
  "severity": "high|medium|low",
  "sme_relevant": true|false,
  "sme_reason": "CIS-X.X: impacto técnico concreto en una línea",
  "summary": "resumen en máximo 2 líneas en español"
}}"""

REQUIRED_CLASSIFY_KEYS = {"category", "severity", "sme_relevant", "sme_reason", "summary"}
VALID_CATEGORIES       = set(CIS_MAPPING.keys())
VALID_SEVERITIES       = {"high", "medium", "low"}

def validate_classification(result: dict) -> dict:
    """Normaliza y valida el JSON devuelto por el LLM antes de confiar en él.

    El contenido de los feeds no es confiable (prompt injection indirecto),
    así que acá se acota el resultado a valores conocidos en vez de propagar
    lo que el modelo haya decidido devolver.
    """
    if not REQUIRED_CLASSIFY_KEYS.issubset(result.keys()):
        raise ValueError(f"Respuesta LLM incompleta, faltan claves: {result!r}")

    if result["category"] not in VALID_CATEGORIES:
        result["category"] = "other"
    if result["severity"] not in VALID_SEVERITIES:
        result["severity"] = "low"

    result["sme_relevant"] = bool(result["sme_relevant"])
    result["sme_reason"]   = str(result["sme_reason"])[:200]
    result["summary"]      = str(result["summary"])[:400]
    return result

def classify(title: str, desc: str, source: str = "") -> dict:
    # bypass para fuentes con categoría conocida
    if source in SOURCE_DEFAULTS:
        result = SOURCE_DEFAULTS[source].copy()
        result["summary"] = title[:120]
        return validate_classification(result)

    # resto pasa por Groq
    resp = client_groq.chat.completions.create(
        #model="llama-3.3-70b-versatile",
        model="llama-3.1-8b-instant",
        messages=[
            {
                "role": "user",
                "content": CLASSIFY_PROMPT.format(
                    title=title,
                    desc=desc[:600]
                )
            }
        ],
        max_tokens=300,
        temperature=0.1,
    )
    raw = resp.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    time.sleep(0.3)
    result = json.loads(raw.strip())
    return validate_classification(result)


# ── Fetch RSS ──────────────────────────────────────────────────

import httpx

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

async def fetch_epss_high() -> list[dict]:
    """CVEs con EPSS score > 0.7, enriquecidos con descripción de NVD."""
    epss_url = "https://api.first.org/data/v1/epss?epss-gt=0.7&order=!epss&limit=10"

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(epss_url)
        resp.raise_for_status()
        epss_data = resp.json().get("data", [])

    items = []
    async with httpx.AsyncClient(timeout=15) as client:
        for entry in epss_data[:8]:
            cve   = entry.get("cve", "")
            score = float(entry.get("epss", 0))
            pct   = float(entry.get("percentile", 0))

            # enriquecimiento desde NVD
            vendor   = "N/A"
            product  = "N/A"
            cvss     = "N/A"
            nvd_desc = ""

            if not CVE_RE.match(cve):
                print(f"  [WARN] CVE con formato inválido, se omite enriquecimiento: {cve!r}")
                vid = hashlib.md5(cve.encode()).hexdigest()
                items.append({
                    "id":    vid,
                    "title": f"{cve} — EPSS {score:.1%}",
                    "desc":  f"CVE: {cve} | EPSS: {score:.4f} (percentil {pct:.0%})",
                    "source": "EPSS/FIRST",
                    "link":   "https://nvd.nist.gov/vuln/search",
                })
                continue

            try:
                nvd_url  = "https://services.nvd.nist.gov/rest/json/cves/2.0"

                headers = {}
                nvd_key = os.getenv("NVD_API_KEY")
                if nvd_key:
                    headers["apiKey"] = nvd_key
                nvd_resp = await client.get(nvd_url, params={"cveId": cve}, headers=headers)

                if nvd_resp.status_code == 200:
                    nvd_data = nvd_resp.json()
                    vuln     = nvd_data.get("vulnerabilities", [{}])[0].get("cve", {})

                    # descripción en inglés
                    for d in vuln.get("descriptions", []):
                        if d.get("lang") == "en":
                            nvd_desc = d.get("value", "")[:300]
                            break

                    # vendor y producto
                    cpe_list = (
                        vuln.get("configurations", [{}])[0]
                            .get("nodes", [{}])[0]
                            .get("cpeMatch", [])
                    )
                    if cpe_list:
                        cpe = cpe_list[0].get("criteria", "")
                        # formato: cpe:2.3:a:vendor:product:...
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            vendor  = parts[3].replace("_", " ").title()
                            product = parts[4].replace("_", " ").title()

                    # CVSS score
                    metrics = vuln.get("metrics", {})
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if key in metrics:
                            cvss = metrics[key][0]["cvssData"].get("baseScore", "N/A")
                            break

                await asyncio.sleep(0.7)   # NVD rate limit: ~100 req/min sin API key

            except Exception as e:
                print(f"  [WARN] NVD enrich {cve}: {e}")

            vid = hashlib.md5(cve.encode()).hexdigest()
            items.append({
                "id":    vid,
                "title": f"{cve} — {product} ({vendor}) · EPSS {score:.1%}",
                "desc":  (
                    f"CVE: {cve} | Producto: {product} | Vendor: {vendor} | "
                    f"CVSS: {cvss} | EPSS: {score:.4f} (percentil {pct:.0%}) | "
                    f"{nvd_desc}"
                ),
                "source": "EPSS/FIRST",
                "link":   f"https://nvd.nist.gov/vuln/detail/{cve}",
            })

    return items

async def fetch_cisa_kev() -> list[dict]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url)
        data = resp.json()

    items = []
    for vuln in data["vulnerabilities"][:15]:
        vid = vuln["cveID"]
        items.append({
            "id":     hashlib.md5(vid.encode()).hexdigest(),
            "title":  f"{vid} — {vuln['vulnerabilityName']}",
            "desc":   f"{vuln['shortDescription']} Acción requerida: {vuln['requiredAction']}",
            "source": "CISA KEV",
            "link":   f"https://nvd.nist.gov/vuln/detail/{vid}",
        })
    return items

async def fetch_urlhaus() -> list[dict]:
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data={"limit": 20})
        data = resp.json()

    items = []
    for entry in data.get("urls", []):
        if entry.get("url_status") != "online":
            continue
        uid = entry["id"]
        items.append({
            "id":     hashlib.md5(str(uid).encode()).hexdigest(),
            "title":  f"URL maliciosa activa — {entry.get('threat', 'unknown')}",
            "desc":   f"URL: {entry['url']} | Tags: {', '.join(entry.get('tags') or ['sin tags'])}",
            "source": "Abuse.ch URLhaus",
            "link":   entry.get("urlhaus_reference", ""),
        })
    return items


#async def debug_ransomware_live():
#    url = "https://api.ransomware.live/v1/recentvictims"
#    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
#        resp = await client.get(url)
#        print(f"Status: {resp.status_code}")
#        data = resp.json()
#        print(f"Total items: {len(data)}")
#        if data:
#            print("Primer item:")
#            print(json.dumps(data[0], indent=2))

async def fetch_ransomware_live() -> list[dict]:
    url = "https://api.ransomware.live/v1/recentvictims"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()

    items = []
    for victim in data[:8]:
        group   = victim.get("group_name", "unknown")
        name    = victim.get("post_title", "unknown")
        country = victim.get("country",    "N/A")
        sector  = victim.get("activity",   "N/A")
        desc    = victim.get("description","")
        date    = victim.get("published",  "")

        vid = hashlib.md5(f"{group}_{name}_{date}".encode()).hexdigest()
        items.append({
            "id":     vid,
            "title":  f"Víctima ransomware: {name} — {group}",
            "desc":   f"Grupo: {group} | Sector: {sector} | País: {country} | {desc[:300]}",
            "source": "Ransomware.live",
            "link":   f"https://www.ransomware.live/group/{group.lower()}",
        })
    return items

def fetch_rss(source: str, url: str) -> list[dict]:
    feed = feedparser.parse(url)
    items = []
    for entry in feed.entries[:5]:
        link = entry.get("link", entry.get("id", url))
        items.append({
            "id":    hashlib.md5(link.encode()).hexdigest(),
            "title": entry.get("title", "Sin título"),
            "desc":  entry.get("summary", entry.get("description", ""))[:600],
            "source": source,
            "link":  link,
        })
    return items

# ── Formato Telegram ───────────────────────────────────────────
_MARKDOWN_SPECIAL_CHARS = ("_", "*", "[", "`")

def escape_markdown(text: str) -> str:
    """Escapa caracteres especiales de Markdown legacy de Telegram.

    El título/resumen/descripción viene de feeds y APIs externas no confiables
    (contenido de terceros), así que sin escapar se podría inyectar sintaxis
    Markdown (ej. `[texto](url)`) y renderizar un link falso dentro de una
    alerta que el analista asume legítima por venir de una fuente conocida.
    """
    if not text:
        return text
    for ch in _MARKDOWN_SPECIAL_CHARS:
        text = text.replace(ch, f"\\{ch}")
    return text

SEVERITY_ICON = {"high": "🔴", "medium": "🟡", "low": "🟢"}
CATEGORY_ICON = {
    "ransomware":    "💀",
    "phishing":      "🎣",
    "exploit":       "💥",
    "malware":       "🦠",
    "vulnerability": "🔓",
    "breach":        "🚨",
    "other":         "📌",
}

def get_priority(item: dict) -> int:
    high   = item["severity"] == "high"
    medium = item["severity"] == "medium"
    sme    = item["sme_relevant"]

    if high and sme:
        return 1
    if high or (medium and sme):
        return 2
    if medium:
        return 3
    return 0   # low → no enviar

PRIORITY_ICON = {1: "🔴", 2: "🟠", 3: "🟡"}
CATEGORY_LABEL = {
    "ransomware":    "RANSOMWARE",
    "phishing":      "PHISHING",
    "exploit":       "EXPLOIT",
    "malware":       "MALWARE",
    "vulnerability": "VULN",
    "breach":        "BREACH",
    "other":         "INFO",
}

def should_process(item: dict) -> bool:
    if SME_ONLY and not item.get("sme_relevant"):
        return False
    if CATEGORIES and item.get("category") not in CATEGORIES:
        return False
    priority = get_priority(item)
    if priority == 0 or priority > SEND_PRIORITY_UP_TO:
        return False
    return True

def format_message_for(item: dict, priority: int, detail: str = "compact") -> str:
    icon  = PRIORITY_ICON[priority]
    cat   = CATEGORY_LABEL.get(item["category"], "INFO")
    title = escape_markdown(item["title"][:100])
    link  = item.get("link", "")

    if NOTIFY_DETAIL == "minimal":
        msg = f"{icon} *{title}* — {item['source']}"
        if link:
            msg += f"\n🔗 {link}"
        return msg

    if NOTIFY_DETAIL == "detailed":
        controls = get_cis_controls(item["category"])
        cis_line = "\n".join(f"  • `{c[0]}` {c[1]}" for c in controls)
        sme = "✅ Relevante PyME" if item["sme_relevant"] else "➖ No prioritario"
        summary    = escape_markdown(item.get("summary", "")[:200])
        sme_reason = escape_markdown(item["sme_reason"][:150])
        msg = (
            f"{icon} P{priority} · {cat} · {item['source']}\n"
            f"*{title}*\n\n"
            f"📋 {summary}\n\n"
            f"{sme}\n"
            f"_{sme_reason}_\n\n"
            f"*Controles CIS IG1:*\n{cis_line}"
        )
        if link:
            msg += f"\n\n🔗 {link}"
        return msg

    # compact (default)
    controls = get_cis_controls(item["category"])
    cis_line = " · ".join(f"`{c[0]}`" for c in controls[:2])
    sme      = escape_markdown(item["sme_reason"][:120])
    msg = (
        f"{icon} P{priority} · {cat} · {item['source']}\n"
        f"*{title}*\n"
        f"_{sme}_\n"
        f"CIS: {cis_line}"
    )
    if link:
        msg += f"\n🔗 {link}"
    return msg

def get_daily_summary(con) -> str | None:
    today = datetime.now(timezone.utc).date().isoformat()
    rows = con.execute("""
        SELECT title, source, category, severity, sme_flag,
               sme_reason, cis_controls, summary
        FROM items
        WHERE ts LIKE ?
        ORDER BY
            CASE severity
                WHEN 'high'   THEN 1
                WHEN 'medium' THEN 2
                ELSE 3
            END,
            sme_flag DESC
        LIMIT 5
    """, (f"{today}%",)).fetchall()

    if not rows:
        return None

    lines = ["📋 *Resumen CTI — " + today + "*\n"]
    for i, row in enumerate(rows, 1):
        title, source, category, severity, sme_flag, \
        sme_reason, cis_json, summary = row

        sev_icon = SEVERITY_ICON.get(severity, "⚪")
        cat      = CATEGORY_LABEL.get(category, "INFO")
        controls = json.loads(cis_json) if cis_json else []
        cis_str  = " · ".join(f"`{c}`" for c in controls[:2])
        sme_mark = "✅" if sme_flag else "➖"
        title    = escape_markdown(title[:80])
        summary  = escape_markdown((summary or "")[:100])

        lines.append(
            f"{i}. {sev_icon} *{title}*\n"
            f"   {cat} · {source} · {sme_mark}\n"
            f"   _{summary}_\n"
            f"   CIS: {cis_str}\n"
        )

    lines.append("_Generado automáticamente por cti\\_bot_")
    return "\n".join(lines)

# ── Pipeline ───────────────────────────────────────────────────
async def run():
    validate_config()

    con     = init_db()
    bot     = Bot(token=TELEGRAM_TOKEN)
    sent    = 0
    errors  = 0
    now     = datetime.now(timezone.utc)

    # ── Procesar comandos entrantes ───────────────────────────
    try:
        await handle_commands(bot, con)
    except Exception as e:
        print(f"  [WARN] handle_commands: {e}")

    # ── Fetch todas las fuentes ───────────────────────────────
    all_entries = []

    #Debugging...
    #await debug_ransomware_live()

    for source, url in FEEDS.items():
        print(f"[FETCH] {source}")
        try:
            all_entries.extend(fetch_rss(source, url))
        except Exception as e:
            print(f"  [WARN] {source}: {e}")

    print("[FETCH] CISA KEV")
    try:
        all_entries.extend(await fetch_cisa_kev())
    except Exception as e:
        print(f"  [WARN] CISA KEV: {e}")

    print("[FETCH] Abuse.ch URLhaus")
    try:
        all_entries.extend(await fetch_urlhaus())
    except Exception as e:
        print(f"  [WARN] URLhaus: {e}")

    print("[FETCH] Ransomware.live")
    try:
        all_entries.extend(await fetch_ransomware_live())
    except Exception as e:
        print(f"  [WARN] Ransomware.live: {e}")

    print("[FETCH] EPSS/FIRST")
    try:
        all_entries.extend(await fetch_epss_high())
    except Exception as e:
        print(f"  [WARN] EPSS: {e}")

    # ── Clasificación ─────────────────────────────────────────
    results = []
    for entry in all_entries:
        if is_seen(con, entry["id"]):
            print(f"  [SKIP] {entry['title'][:60]}")
            continue
        try:
            result = classify(entry["title"], entry["desc"], source=entry["source"])
            result["id"]     = entry["id"]
            result["title"]  = entry["title"]
            result["source"] = entry["source"]
            result["link"]   = entry.get("link", "")

            print(f"  [{result['severity'].upper()}] {entry['title'][:60]}")
            save_item(con, result)
            results.append(result)

        except json.JSONDecodeError as e:
            print(f"  [ERROR] JSON inválido: {e}")
            errors += 1
        except Exception as e:
            print(f"  [ERROR] {entry['title'][:50]}: {e}")
            errors += 1

    # ── Envío por usuario ─────────────────────────────────────
    is_summary_hour = (now.hour == DAILY_SUMMARY_HOUR and now.minute < 10)

    # todos los usuarios registrados + owner del .env, restringido al allowlist
    chat_ids = set([TELEGRAM_CHAT_ID])
    rows = con.execute("SELECT chat_id FROM user_config").fetchall()
    for row in rows:
        chat_ids.add(row[0])
    chat_ids &= ALLOWED_CHAT_IDS

    for chat_id in chat_ids:
        cfg  = get_user_config(con, chat_id)
        mode = cfg["notify_mode"]

        if mode in ("realtime", "both"):
            for result in results:
                if not should_process_for_user(result, cfg):
                    continue
                priority = get_priority(result)
                msg = format_message_for(result, priority, cfg["notify_detail"])
                for attempt in range(3):
                    try:
                        await bot.send_message(
                            chat_id=chat_id,
                            text=msg,
                            parse_mode="Markdown"
                        )
                        sent += 1
                        await asyncio.sleep(0.5)
                        break
                    except Exception as e:
                        if attempt < 2:
                            print(f"  [RETRY {attempt+1}] {str(e)[:50]}")
                            await asyncio.sleep(2 ** attempt)
                        else:
                            print(f"  [ERROR] send definitivo: {str(e)[:50]}")
                            errors += 1

        if mode in ("daily", "both") and is_summary_hour:
            summary_msg = get_daily_summary(con)
            if summary_msg:
                await bot.send_message(
                    chat_id=chat_id,
                    text=summary_msg,
                    parse_mode="Markdown"
                )
                print(f"  [SUMMARY] Resumen diario enviado a {chat_id}")

    print(f"\n[DONE] {sent} alertas enviadas, {errors} errores.")
    con.close()

if __name__ == "__main__":
    asyncio.run(run())