"""Handlers interactivos del bot de Telegram — lógica pura desacoplada de cti_bot.py.

Este módulo contiene toda la lógica de comandos de usuario (/start, /config, /search, /stats, etc.)
y funciones de filtrado por preferencias de usuario. No depende de I/O de red ni de estado global
mutable — solo recibe `con` (conexión SQLite) y `chat_id`/`args` y devuelve strings listos para enviar.

Diseñado para ser testeable unitariamente sin mocks de Telegram.
"""

import csv
import io
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

# ── Constantes de sectores y severidades válidas ──────────────────────────
VALID_SECTORS = {"finance", "gov", "all"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
SECTOR_LABELS = {"finance": "Financiero / Fintech", "gov": "Gobierno / Infraestructura crítica"}
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ── Esquema de BD: migraciones de user_config ─────────────────────────────
def migrate_user_config_schema(con: sqlite3.Connection) -> None:
    """Añade columnas nuevas a user_config si no existen (idempotente)."""
    migrations = [
        ("sectors", "TEXT DEFAULT 'all'"),
        ("min_severity", "TEXT DEFAULT 'HIGH'"),
        ("followed_actors", "TEXT DEFAULT ''"),
    ]
    for col, typ in migrations:
        try:
            con.execute(f"ALTER TABLE user_config ADD COLUMN {col} {typ}")
        except sqlite3.OperationalError:
            pass  # ya existe
    con.commit()


# ── Lectura/escritura de configuración de usuario ─────────────────────────
_USER_CONFIG_COLS = [
    "chat_id", "notify_mode", "notify_detail", "priority_max",
    "sme_only", "categories", "updated_at", "last_daily_summary",
    "sectors", "min_severity", "followed_actors",
]

_DEFAULTS = {
    "notify_mode": "realtime",
    "notify_detail": "compact",
    "priority_max": 2,
    "sme_only": 0,
    "categories": "",
    "sectors": "all",
    "min_severity": "HIGH",
    "followed_actors": "",
    "last_daily_summary": "",
}


def get_user_config(con: sqlite3.Connection, chat_id: str) -> dict:
    """Obtiene config completa del usuario con defaults si no existe fila."""
    row = con.execute(
        f"SELECT {', '.join(_USER_CONFIG_COLS)} FROM user_config WHERE chat_id=?",
        (chat_id,)
    ).fetchone()
    if not row:
        cfg = {"chat_id": chat_id}
        cfg.update(_DEFAULTS)
        cfg["updated_at"] = datetime.now(timezone.utc).isoformat()
        return cfg
    cfg = dict(zip(_USER_CONFIG_COLS, row))
    # Normalizar None a defaults
    for k, v in _DEFAULTS.items():
        if cfg.get(k) is None:
            cfg[k] = v
    return cfg


def save_user_config(con: sqlite3.Connection, chat_id: str, **kwargs) -> None:
    """Actualiza config del usuario (upsert) manteniendo campos no modificados."""
    existing = get_user_config(con, chat_id)
    existing.update(kwargs)
    existing["updated_at"] = datetime.now(timezone.utc).isoformat()
    con.execute(f"""
        INSERT OR REPLACE INTO user_config ({', '.join(_USER_CONFIG_COLS)})
        VALUES ({', '.join(['?'] * len(_USER_CONFIG_COLS))})
    """, tuple(existing[c] for c in _USER_CONFIG_COLS))
    con.commit()


# ── Filtrado de ítems según preferencias de usuario ───────────────────────
def _parse_csv_list(value: str) -> list[str]:
    """Convierte CSV 'a,b, c' -> ['a', 'b', 'c'] (lowercase, stripped, único)."""
    if not value:
        return []
    return list(dict.fromkeys(v.strip().lower() for v in value.split(",") if v.strip()))


def _matches_sector(item: dict, user_sectors: list[str]) -> bool:
    """True si el item coincide con sectores del usuario."""
    if not user_sectors or "all" in user_sectors:
        return True
    item_sector = item.get("critical_sector")
    if not item_sector:
        return False
    # Mapear sector interno a clave de usuario
    sector_key = "finance" if item_sector == "financiero" else "gov" if item_sector == "gobierno" else None
    return sector_key in user_sectors


def _matches_severity(item: dict, min_severity: str) -> bool:
    """True si la severidad del incidente >= umbral del usuario."""
    item_sev = item.get("incident_severity") or item.get("severity", "")
    if not item_sev:
        return False
    return SEVERITY_ORDER.get(item_sev.upper(), 0) >= SEVERITY_ORDER.get(min_severity.upper(), 0)


def _matches_actor(item: dict, followed_actors: list[str]) -> bool:
    """True si el actor del item está en la lista de seguidos del usuario."""
    if not followed_actors:
        return True  # sin filtro de actor = todo pasa
    actor = (item.get("threat_actor") or "").lower()
    return actor in followed_actors


def should_notify_user(item: dict, cfg: dict) -> bool:
    """Decide si un item debe notificarse a este usuario según sus preferencias.

    Combina filtros existentes (categoría, prioridad, sme_only) con los nuevos:
    sectors, min_severity, followed_actors.
    """
    # Filtros legacy
    if cfg.get("sme_only") and not item.get("sme_relevant"):
        return False
    cats = _parse_csv_list(cfg.get("categories", ""))
    if cats and item.get("category") not in cats:
        return False
    # priority_max (P1=1, P2=2, P3=3) — get_priority usa severity+sme_relevant
    from cti_bot import get_priority  # import local para evitar ciclo
    priority = get_priority(item)
    if priority == 0 or priority > cfg.get("priority_max", 3):
        return False

    # Filtros nuevos
    user_sectors = _parse_csv_list(cfg.get("sectors", "all"))
    if not _matches_sector(item, user_sectors):
        return False

    min_sev = cfg.get("min_severity", "HIGH")
    if not _matches_severity(item, min_sev):
        return False

    followed = _parse_csv_list(cfg.get("followed_actors", ""))
    if not _matches_actor(item, followed):
        return False

    return True


# ── Comandos de configuración ─────────────────────────────────────────────
HELP_MSG = """
🤖 *CTI Bot — Comandos disponibles*

*Configuración de alertas:*
`/config` — Ver tu configuración actual
`/set_sector finance,gov|all` — Sectores de interés (finance=🏦, gov=🏛️)
`/set_severity LOW|MEDIUM|HIGH|CRITICAL` — Umbral mínimo de severidad
`/follow <actor>` — Seguir un grupo de amenazas (ej. lockbit)
`/unfollow <actor>` — Dejar de seguir un grupo
`/follow_list` — Ver actores que sigues

*Notificaciones (legacy):*
`/modo realtime|daily|both` — Modo de envío
`/detalle compact|detailed|minimal` — Nivel de detalle
`/prioridad 1|2|3` — Prioridad máxima (P1/P2/P3)
`/filtro cat1,cat2|off` — Filtrar por categoría
`/sme on|off` — Solo items con impacto operacional

*Consultas bajo demanda:*
`/search <término>` — Buscar en últimos incidentes (título/descripción/víctima)
`/stats [24h|7d]` — Resumen estadístico (por defecto 24h)
`/actor <nombre>` — Últimas víctimas y actividad del grupo
`/export [7d|30d]` — Exportar CSV de incidentes (por defecto 7d)

*Ayuda:*
`/help` o `/ayuda` — Este mensaje
`/start` — Inicio y configuración inicial
""".strip()


def cmd_help() -> str:
    return HELP_MSG


def cmd_start() -> str:
    return (
        "👋 *Bienvenido a CTI Bot*\n\n"
        "Este bot te alerta en tiempo real sobre incidentes de seguridad críticos "
        "(ransomware, brechas, exploits activos) con foco en sectores **gobierno** 🏛️ "
        "y **financiero** 🏦.\n\n"
        "⚙️ *Primeros pasos:*\n"
        "1. Usa `/config` para ver tu configuración actual\n"
        "2. Ajusta sectores con `/set_sector finance,gov`\n"
        "3. Define umbral con `/set_severity HIGH`\n"
        "4. Sigue grupos con `/follow lockbit`\n\n"
        "📖 Escribe `/help` para ver todos los comandos."
    )


def cmd_config(con: sqlite3.Connection, chat_id: str) -> str:
    cfg = get_user_config(con, chat_id)
    sectors = cfg.get("sectors", "all")
    min_sev = cfg.get("min_severity", "HIGH")
    actors = cfg.get("followed_actors", "") or "—"
    cats = cfg.get("categories", "") or "todas"
    return (
        f"⚙️ *Tu configuración:*\n"
        f"• Modo: `{cfg['notify_mode']}`\n"
        f"• Detalle: `{cfg['notify_detail']}`\n"
        f"• Prioridad máx: `P{cfg['priority_max']}`\n"
        f"• Solo SME: `{'sí' if cfg['sme_only'] else 'no'}`\n"
        f"• Categorías: `{cats}`\n"
        f"• Sectores: `{sectors}`\n"
        f"• Severidad mín: `{min_sev}`\n"
        f"• Actores seguidos: `{actors}`"
    )


def cmd_set_sector(con: sqlite3.Connection, chat_id: str, arg: str) -> str:
    if not arg:
        return "❌ Uso: `/set_sector finance,gov` o `/set_sector all`"
    parts = [p.strip().lower() for p in arg.split(",") if p.strip()]
    invalid = [p for p in parts if p not in VALID_SECTORS]
    if invalid:
        return f"❌ Sectores inválidos: {', '.join(invalid)}. Válidos: {', '.join(VALID_SECTORS)}"
    if "all" in parts:
        parts = ["all"]
    save_user_config(con, chat_id, sectors=",".join(parts))
    return f"✅ Sectores actualizados: `{', '.join(parts)}`"


def cmd_set_severity(con: sqlite3.Connection, chat_id: str, arg: str) -> str:
    if not arg:
        return "❌ Uso: `/set_severity HIGH` (valores: LOW, MEDIUM, HIGH, CRITICAL)"
    sev = arg.strip().upper()
    if sev not in VALID_SEVERITIES:
        return f"❌ Severidad inválida. Válidas: {', '.join(VALID_SEVERITIES)}"
    save_user_config(con, chat_id, min_severity=sev)
    return f"✅ Severidad mínima: `{sev}`"


def cmd_follow(con: sqlite3.Connection, chat_id: str, arg: str) -> str:
    if not arg:
        return "❌ Uso: `/follow lockbit`"
    actor = arg.strip().lower()
    if len(actor) < 3:
        return "❌ Nombre de actor demasiado corto (mín 3 caracteres)"
    cfg = get_user_config(con, chat_id)
    current = _parse_csv_list(cfg.get("followed_actors", ""))
    if actor in current:
        return f"ℹ️ Ya sigues a `{actor}`"
    current.append(actor)
    save_user_config(con, chat_id, followed_actors=",".join(current))
    return f"✅ Ahora sigues a `{actor}`"


def cmd_unfollow(con: sqlite3.Connection, chat_id: str, arg: str) -> str:
    if not arg:
        return "❌ Uso: `/unfollow lockbit`"
    actor = arg.strip().lower()
    cfg = get_user_config(con, chat_id)
    current = _parse_csv_list(cfg.get("followed_actors", ""))
    if actor not in current:
        return f"ℹ️ No seguías a `{actor}`"
    current.remove(actor)
    save_user_config(con, chat_id, followed_actors=",".join(current))
    return f"✅ Dejaste de seguir a `{actor}`"


def cmd_follow_list(con: sqlite3.Connection, chat_id: str) -> str:
    cfg = get_user_config(con, chat_id)
    actors = _parse_csv_list(cfg.get("followed_actors", ""))
    if not actors:
        return "📭 No sigues a ningún actor. Usa `/follow <nombre>` para añadir."
    return "🎯 *Actores que sigues:*\n" + "\n".join(f"• `{a}`" for a in actors)


# ── Consultas bajo demanda ────────────────────────────────────────────────
def cmd_search(con: sqlite3.Connection, arg: str, limit: int = 5) -> str:
    if not arg:
        return "❌ Uso: `/search <término>`"
    q = f"%{arg.strip()}%"
    rows = con.execute("""
        SELECT title, source, category, severity, critical_sector, incident_severity,
               threat_actor, ts, link
        FROM items
        WHERE title LIKE ? OR desc LIKE ? OR summary LIKE ?
        ORDER BY ts DESC
        LIMIT ?
    """, (q, q, q, limit)).fetchall()

    if not rows:
        return f"🔍 Sin resultados para `{arg}`"

    lines = [f"🔍 *Resultados para `{arg}`* (últimos {limit}):"]
    for i, (title, source, cat, sev, csec, isev, actor, ts, link) in enumerate(rows, 1):
        sector_icon = "🏦" if csec == "financiero" else "🏛️" if csec == "gobierno" else "📌"
        sev_icon = {"HIGH": "🔴", "CRITICAL": "🚨", "MEDIUM": "🟡", "LOW": "🟢"}.get(isev or sev, "⚪")
        actor_str = f" | Actor: {actor}" if actor else ""
        lines.append(
            f"{i}. {sev_icon}{sector_icon} *{title[:80]}*\n"
            f"   {source} | {cat} | {isev or sev}{actor_str}\n"
            f"   📅 {ts[:16].replace('T', ' ')} | 🔗 [Ver]({link})"
        )
    return "\n\n".join(lines)


def cmd_stats(con: sqlite3.Connection, period: str = "24h") -> str:
    if period not in ("24h", "7d"):
        period = "24h"
    cutoff = datetime.now(timezone.utc) - (timedelta(hours=24) if period == "24h" else timedelta(days=7))
    cutoff_str = cutoff.isoformat()

    # Total
    total = con.execute("SELECT COUNT(*) FROM items WHERE ts >= ?", (cutoff_str,)).fetchone()[0]

    # Top actores
    actor_rows = con.execute("""
        SELECT threat_actor, COUNT(*) as c
        FROM items
        WHERE ts >= ? AND threat_actor IS NOT NULL AND threat_actor != ''
        GROUP BY threat_actor
        ORDER BY c DESC
        LIMIT 3
    """, (cutoff_str,)).fetchall()

    # Sectores más impactados
    sector_rows = con.execute("""
        SELECT critical_sector, COUNT(*) as c
        FROM items
        WHERE ts >= ? AND critical_sector IS NOT NULL
        GROUP BY critical_sector
        ORDER BY c DESC
    """, (cutoff_str,)).fetchall()

    # Top categorías
    cat_rows = con.execute("""
        SELECT category, COUNT(*) as c
        FROM items
        WHERE ts >= ?
        GROUP BY category
        ORDER BY c DESC
        LIMIT 5
    """, (cutoff_str,)).fetchall()

    lines = [f"📊 *Estadísticas últimas {period}*"]
    lines.append(f"• Total incidentes: `{total}`")
    if actor_rows:
        lines.append("\n🎯 *Top actores:*")
        for actor, c in actor_rows:
            lines.append(f"  • `{actor}` — {c}")
    if sector_rows:
        lines.append("\n🏷️ *Sectores impactados:*")
        for sec, c in sector_rows:
            label = SECTOR_LABELS.get(sec, sec)
            icon = "🏦" if sec == "financiero" else "🏛️" if sec == "gobierno" else "📌"
            lines.append(f"  • {icon} {label} — {c}")
    if cat_rows:
        lines.append("\n📂 *Top categorías:*")
        for cat, c in cat_rows:
            lines.append(f"  • {cat} — {c}")
    return "\n".join(lines)


def cmd_actor(con: sqlite3.Connection, arg: str, limit: int = 10) -> str:
    if not arg:
        return "❌ Uso: `/actor lockbit`"
    actor = arg.strip().lower()
    rows = con.execute("""
        SELECT title, critical_sector, incident_severity, ts, link
        FROM items
        WHERE LOWER(threat_actor) = ?
        ORDER BY ts DESC
        LIMIT ?
    """, (actor, limit)).fetchall()

    if not rows:
        return f"🔍 Sin registros para actor `{actor}`"

    lines = [f"🎭 *Actividad de `{actor}`* (últimos {len(rows)}):"]
    for title, csec, isev, ts, link in rows:
        sector_icon = "🏦" if csec == "financiero" else "🏛️" if csec == "gobierno" else "📌"
        sev_icon = {"HIGH": "🔴", "CRITICAL": "🚨", "MEDIUM": "🟡", "LOW": "🟢"}.get(isev, "⚪")
        lines.append(
            f"{sev_icon}{sector_icon} *{title[:80]}*\n"
            f"   Severidad: {isev} | 📅 {ts[:16].replace('T', ' ')} | 🔗 [Ver]({link})"
        )
    return "\n\n".join(lines)


def cmd_export(con: sqlite3.Connection, period: str = "7d") -> tuple[str, bytes]:
    """Genera CSV de incidentes. Devuelve (mensaje, csv_bytes)."""
    if period not in ("7d", "30d"):
        period = "7d"
    cutoff = datetime.now(timezone.utc) - (timedelta(days=7) if period == "7d" else timedelta(days=30))
    cutoff_str = cutoff.isoformat()

    rows = con.execute("""
        SELECT id, title, source, category, severity, critical_sector, incident_severity,
               threat_actor, sector_evidence, sme_relevant, sme_reason, ts, link
        FROM items
        WHERE ts >= ?
        ORDER BY ts DESC
    """, (cutoff_str,)).fetchall()

    if not rows:
        return f"📭 Sin incidentes en los últimos {period}", b""

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Título", "Fuente", "Categoría", "Severidad", "Sector",
        "Severidad_Incidente", "Actor", "Evidencia_Sector",
        "Relevante_SME", "Motivo_SME", "Timestamp", "Link"
    ])
    for r in rows:
        writer.writerow(r)

    csv_bytes = output.getvalue().encode("utf-8")
    return f"📤 *Exportación {period}* — {len(rows)} incidentes", csv_bytes


# ── Router principal de comandos ──────────────────────────────────────────
async def handle_user_command(
    bot,
    con: sqlite3.Connection,
    chat_id: str,
    text: str
) -> Optional[str]:
    """Procesa un comando de usuario y devuelve respuesta (o None si no es comando).
    
    Los comandos que envían archivos (export) manejan el envío internamente y devuelven None.
    """
    text = text.strip()
    if not text.startswith("/"):
        return None

    parts = text.split(maxsplit=1)
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    # Comandos que no requieren BD
    if cmd in ("/help", "/ayuda"):
        return cmd_help()
    if cmd == "/start":
        return cmd_start()

    # Asegurar migración de esquema
    migrate_user_config_schema(con)

    # Configuración
    if cmd == "/config":
        return cmd_config(con, chat_id)
    if cmd == "/set_sector":
        return cmd_set_sector(con, chat_id, arg)
    if cmd == "/set_severity":
        return cmd_set_severity(con, chat_id, arg)
    if cmd == "/follow":
        return cmd_follow(con, chat_id, arg)
    if cmd == "/unfollow":
        return cmd_unfollow(con, chat_id, arg)
    if cmd == "/follow_list":
        return cmd_follow_list(con, chat_id)

    # Consultas
    if cmd == "/search":
        return cmd_search(con, arg)
    if cmd == "/stats":
        return cmd_stats(con, arg.strip() or "24h")
    if cmd == "/actor":
        return cmd_actor(con, arg)

    # Export — envía documento directamente
    if cmd == "/export":
        msg, csv_bytes = cmd_export(con, arg.strip() or "7d")
        if csv_bytes:
            await bot.send_document(
                chat_id=chat_id,
                document=("export.csv", io.BytesIO(csv_bytes), "text/csv"),
                caption=msg,
                parse_mode="Markdown"
            )
        else:
            await bot.send_message(chat_id=chat_id, text=msg, parse_mode="Markdown")
        return None  # ya enviado

    # Comandos legacy (delegados a cti_bot.handle_commands original)
    return None  # señal para que el caller maneje los legacy


__all__ = [
    "migrate_user_config_schema",
    "get_user_config",
    "save_user_config",
    "should_notify_user",
    "handle_user_command",
    "HELP_MSG",
    "VALID_SECTORS",
    "VALID_SEVERITIES",
]