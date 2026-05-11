import feedparser
import sqlite3
import asyncio
import hashlib
import json
import os
from datetime import datetime, timezone
from groq import Groq
from telegram import Bot
from dotenv import load_dotenv

# ── Configuración ─────────────────────────────────────────────
load_dotenv()

TELEGRAM_TOKEN    = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID  = os.getenv("TELEGRAM_CHAT_ID")
GROQ_API_KEY      = os.getenv("GROQ_API_KEY")

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
}

def get_cis_controls(category: str) -> list[tuple]:
    return CIS_MAPPING.get(category, CIS_MAPPING["other"])

# ── Base de datos ─────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
    CREATE TABLE IF NOT EXISTS items (
        id          TEXT PRIMARY KEY,
        title       TEXT,
        source      TEXT,
        category    TEXT,
        severity    TEXT,
        sme_flag    INTEGER,
        sme_reason  TEXT,
        cis_controls TEXT,
        summary     TEXT,
        ts          TEXT
        )
    """)
    con.commit()
    return con

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
Sos un analista de ciberseguridad especializado en PyMEs.
Clasificá el siguiente evento de seguridad y respondé ÚNICAMENTE con JSON válido.
No agregues texto antes ni después del JSON.

Título: {title}
Descripción: {desc}

Formato requerido:
{{
  "category": "ransomware|phishing|exploit|malware|vulnerability|breach|other",
  "severity": "high|medium|low",
  "sme_relevant": true|false,
  "sme_reason": "una línea explicando relevancia para PyMEs argentinas",
  "summary": "resumen en máximo 2 líneas en español"
}}"""

def classify(title: str, desc: str, source: str = "") -> dict:
    # bypass para fuentes con categoría conocida
    if source in SOURCE_DEFAULTS:
        result = SOURCE_DEFAULTS[source].copy()
        result["summary"] = title[:120]
        return result

    # resto pasa por Groq
    resp = client_groq.chat.completions.create(
        model="llama-3.3-70b-versatile",
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
    return json.loads(raw.strip())


# ── Fetch RSS ──────────────────────────────────────────────────

import httpx

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

async def fetch_ransomware_live() -> list[dict]:
    url = "https://api.ransomware.live/recentvictims"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()

    items = []
    for victim in data[:15]:
        group   = victim.get("group",    "unknown")
        name    = victim.get("victim",   "unknown")
        country = victim.get("country",  "N/A")
        sector  = victim.get("activity", "N/A")
        date    = victim.get("published", "")

        vid = hashlib.md5(f"{group}_{name}_{date}".encode()).hexdigest()
        items.append({
            "id":     vid,
            "title":  f"Víctima ransomware: {name} — {group}",
            "desc":   (
                f"Grupo: {group} | Víctima: {name} | "
                f"País: {country} | Sector: {sector} | Fecha: {date}"
            ),
            "source": "Ransomware.live",
            "link":   f"https://www.ransomware.live/group/{group.lower()}",
        })
    return items

def fetch_rss(source: str, url: str) -> list[dict]:
    feed = feedparser.parse(url)
    items = []
    for entry in feed.entries[:8]:
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

def format_message(item: dict, priority: int) -> str:
    icon  = PRIORITY_ICON[priority]
    cat   = CATEGORY_LABEL.get(item["category"], "INFO")
    title = item["title"][:100]
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
        msg = (
            f"{icon} P{priority} · {cat} · {item['source']}\n"
            f"*{title}*\n\n"
            f"📋 {item.get('summary', '')[:200]}\n\n"
            f"{sme}\n"
            f"_{item['sme_reason'][:150]}_\n\n"
            f"*Controles CIS IG1:*\n{cis_line}"
        )
        if link:
            msg += f"\n\n🔗 {link}"
        return msg

    # compact (default)
    controls = get_cis_controls(item["category"])
    cis_line = " · ".join(f"`{c[0]}`" for c in controls[:2])
    sme      = item["sme_reason"][:120]
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

        lines.append(
            f"{i}. {sev_icon} *{title[:80]}*\n"
            f"   {cat} · {source} · {sme_mark}\n"
            f"   _{summary[:100]}_\n"
            f"   CIS: {cis_str}\n"
        )

    lines.append("_Generado automáticamente por cti\\_bot_")
    return "\n".join(lines)

# ── Pipeline ───────────────────────────────────────────────────
async def run():
    con      = init_db()
    bot      = Bot(token=TELEGRAM_TOKEN)
    sent     = 0
    errors   = 0
    now      = datetime.now(timezone.utc)

    # ── Fetch todas las fuentes ───────────────────────────────
    all_entries = []

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

    # ── Envío según NOTIFY_MODE ───────────────────────────────
    send_realtime = NOTIFY_MODE in ("realtime", "both")
    send_daily    = NOTIFY_MODE in ("daily", "both")
    is_summary_hour = (now.hour == DAILY_SUMMARY_HOUR and now.minute < 10)

    if send_realtime:
        for result in results:
            if not should_process(result):
                continue
            priority = get_priority(result)
            try:
                await bot.send_message(
                    chat_id=TELEGRAM_CHAT_ID,
                    text=format_message(result, priority),
                    parse_mode="Markdown"
                )
                sent += 1
            except Exception as e:
                print(f"  [ERROR] send: {e}")
                errors += 1

    if send_daily and is_summary_hour:
        summary_msg = get_daily_summary(con)
        if summary_msg:
            await bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=summary_msg,
                parse_mode="Markdown"
            )
            print("[SUMMARY] Resumen diario enviado.")

    print(f"\n[DONE] {sent} alertas enviadas, {errors} errores.")
    con.close()

if __name__ == "__main__":
    asyncio.run(run())