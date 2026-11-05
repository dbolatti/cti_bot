"""Clasificador de incidentes en sectores críticos (gobierno / financiero).

Módulo puro, sin dependencias ni red: se usa desde `cti_bot.py` tanto en la
corrida completa (2 h) como en el modo rápido (`--fast-check`). No debe
importar `cti_bot` (evita ciclos) y no debe llamar a LLMs: toda detección es
determinística, con regex sobre título + descripción + fuente, para que
funcione sin API keys y sea testeable de forma aislada.

Contrato
--------
Entrada (lo que ya devuelve cada `fetch_*` de cti_bot):
    title: desglose visible del item
    desc:  texto de apoyo (en Ransomware.live incluye "Grupo: X | Sector: Y | País: Z")
    category: categoría ya clasificada ("ransomware"|"breach"|"exploit"|"phishing"|"malware"|"vulnerability"|"other")
    source:  nombre de la fuente tal cual aparece en cti_bot.FEEDS / fetchers

Salida (None si no hay incidente, o dict):
    {
        "critical_sector":   "gobierno" | "financiero" | None,
        "incident_severity": "CRITICAL" | "HIGH" | "MEDIUM",
        "threat_actor":      str | None,
        "sector_evidence":   str | None,   # término encontrado (transparencia)
        "sector_icon":       "🏛️" | "🏦" | "🚨",
    }

Reglas de severidad (las mismas que documenta la especificación):
    - Ransomware activo (Ransomware.live) en sector gobierno/financiero -> CRITICAL
    - CISA KEV explotado activamente (pruebas de explotación conocidas) -> HIGH
      baseline, CRITICAL si además hay sector crítico + ransomware/breach
    - Ransomware.live sin sector identificado (víctima activa) -> HIGH
    - Cualquier otro sector crítico con amenaza activa (ransomware, breach,
      exploit, phishing, malware) -> HIGH (CRITICAL si ransomware/breach)
    - Sector crítico mencionado pero sin amenaza activa (other/low) -> MEDIUM
      (monitoreo, no fuerza la prioridad máxima en cti_bot)
    - Sin sector ni fuente de alta señal -> None (no es incidente)

`cti_bot` usa el dict para: forzar `severity="high"` + `sme_relevant=True`
cuando es HIGH/CRITICAL y guardar sector/actor/severidad en la tabla `items`.
"""

import re

# ── Sector: gobierno / infraestructura crítica ────────────────────────────
_GOV_TERMS = [
    r"gobierno",
    r"gubernament\w*",
    r"ministerio", r"ministeria", r"ministry",
    r"municip\w*",
    r"ayuntamiento",
    r"alcald\w*",
    r"intendenci\w*",
    r"prefeitura",
    r"gobernaci\w*",
    r"congreso",
    r"parlamento",
    r"senado",
    r"fuerzas?\s+(?:de\s+)?seguridad",
    r"polic[ií]a\s+(?:nacional|federal|local|metropolitana)",
    r"guardia\s+civil",
    r"carabineros",
    r"ej[eé]rcito",
    r"armada\s+(?:nacional|de)",
    r"fuerza\s+(?:a[eé]rea|naval)",
    r"ministerio\s+de\s+defensa",
    r"salud\s+p[úu]blica",
    r"public\s+health",
    r"hospital\s+p[úu]blico",
    r"infraestructura\s+cr[ií]tica",
    r"critical\s+infrastructure",
    r"servicios\s+p[úu]blicos",
    r"public\s+services?",
    r"federal\s+agency",
    r"state\s+agency",
    r"government\s+(?:agency|department|official|sector)",
    r"sector\s+(?:p[úu]blico|gubernamental)",
    r"secretar[ií]a\s+(?:de|del)\s+(?:salud|hacienda|econom[ií]a|seguridad)",
    r"instituto\s+nacional\s+de\s+salud",
    r"national\s+health",
    r"transporte\s+p[úu]blico",
    r"red\s+el[ée]ctrica",
    r"agua\s+potable",
    r"servicios\s+de\s+emergencia",
    r"emergency\s+services",
    r"energy\s+(?:grid|utility|sector)",
    r"sector\s+energ[ée]tico",
]
_GOV_RE = re.compile(r"\b(?:" + "|".join(_GOV_TERMS) + r")", re.IGNORECASE)
# dominios .gov / .gob.* (gob.ar, gob.mx, ..). Se busca como substring porque
# el dominio puede venir dentro de una URL o un email en la descripción.
_GOV_DOMAIN_RE = re.compile(r"[a-z0-9-]+\.(?:gov|gob)(?:\.[a-z]{2,})?\b", re.IGNORECASE)

# ── Sector: financiero / fintech ──────────────────────────────────────────
_FIN_TERMS = [
    r"\bbank(?:s|ing)?\b",
    r"\bbanco(?:s)?\b",
    r"\bbanca\w*\b",
    r"\bsector\s+bancario\b",
    r"\bbanking\s+sector\b",
    r"entidad\s+financier\w*",
    r"institución\s+financier\w*",
    r"financial\s+(?:institution|sector|services?)",
    r"fintech",
    r"pasarela\s+de\s+pago",
    r"payment\s+(?:gateway|processor|platform)",
    r"procesador\s+de\s+pagos?",
    r"payment\s+processor",
    r"billetera\s+virtual",
    r"digital\s+wallet",
    r"cooperativa\s+de\s+cr[eé]dito",
    r"credit\s+union",
    r"banco\s+central",
    r"central\s+bank",
    r"aseguradora",
    r"\binsurer\b",
    r"mercados?\s+financieros",
    r"stock\s+exchange",
    r"bolsa\s+de\s+(?:valores|comercio)",
    r"crypto\s+exchange",
]
_FIN_RE = re.compile(r"\b(?:" + "|".join(_FIN_TERMS) + r")", re.IGNORECASE)

# ── Fuentes de alta señal de incidentes activos ───────────────────────────
_SOURCE_HIGH = {"Ransomware.live", "CISA KEV"}

_ACTIVE_THREAT_CATEGORIES = {"ransomware", "breach", "exploit"}
_THREAT_CATEGORIES = {"ransomware", "breach", "exploit", "phishing", "malware"}
_CRITICAL_THREAT_CATEGORIES = {"ransomware", "breach"}


def detect_sector(title: str, desc: str = "") -> tuple[str | None, str | None]:
    """Devuelve (sector, evidencia) donde sector es "gobierno"|"financiero"|None.

    Ante empate (ej. "Ministerio de Finanzas") se prioriza "gobierno": la
    institución dueña del incidente manda sobre la descripción del sector.
    """
    text = f"{title or ''} {desc or ''}"
    if not text.strip():
        return None, None

    m = _GOV_DOMAIN_RE.search(text)
    if m:
        return "gobierno", m.group(0)
    m = _GOV_RE.search(text)
    if m:
        return "gobierno", m.group(0)
    m = _FIN_RE.search(text)
    if m:
        return "financiero", m.group(0)
    return None, None


def _extract_actor_from_ransomware_live(desc: str) -> str | None:
    m = re.search(r"Grupo:\s*([^|]+?)\s*\|", desc or "")
    if m:
        group = m.group(1).strip()
        # mismo criterio que cti_bot.MIN_RANSOMWARE_GROUP_LEN: nombres de
        # menos de 4 caracteres son propensos a falsos positivos.
        if len(group) >= 4:
            return group
    return None


def extract_threat_actor(title: str, desc: str = "", source: str = "") -> str | None:
    """Actor malicioso cuando se conoce, extraído del texto (sin LLM).

    Fuentes en orden: campo estructurado de Ransomware.live ("Grupo: X |"),
    patrones de atribución explícita y "threat actor X". Nunca inventa: si
    no hay mención, devuelve None y la plantilla lo omite.
    """
    text = f"{title or ''} {desc or ''}"

    if source == "Ransomware.live":
        actor = _extract_actor_from_ransomware_live(desc or "")
        if actor:
            return actor

    patterns = [
        r"(?:atribuid[oa]s?\s+a|attributed\s+to|vinculad[oa]s?\s+a|linked\s+to|"
        r"detr[áa]s\s+de)\s+([A-Za-zÁÉÍÓÚáéíóú][A-Za-z0-9 ._-]{2,40})",
        r"threat\s+actor\s+([A-Za-z0-9 ._-]{2,40})",
        r"(?:ransomware\s+(?:group|gang)|banda\s+)([A-Za-z0-9._-]{3,30})",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            actor = m.group(1).strip(" .:,-;")
            if len(actor) >= 4:
                return actor
    return None


SECTOR_LABELS = {
    "gobierno": "Gobierno / Infraestructura crítica",
    "financiero": "Financiero / Fintech",
    None: "Sector no identificado",
}
SECTOR_ICONS = {"gobierno": "🏛️", "financiero": "🏦", None: "🚨"}


def classify_incident(
    title: str,
    desc: str = "",
    category: str = "",
    source: str = "",
) -> dict | None:
    """Clasifica si un item es un incidente de alto impacto y con qué severidad.

    Nunca lanza: ante entradas vacías o no relacionadas devuelve None.
    """
    try:
        sector, evidence = detect_sector(title, desc)
        actor = extract_threat_actor(title, desc, source)
        cat = (category or "").lower()

        if sector is None and source not in _SOURCE_HIGH:
            return None

        # Sin sector pero fuente de incidente activo: HIGH (no se fuerza
        # CRITICAL porque no sabemos qué sector pega).
        if sector is None:
            return {
                "critical_sector": None,
                "incident_severity": "HIGH",
                "threat_actor": actor,
                "sector_evidence": None,
                "sector_icon": SECTOR_ICONS[None],
            }

        # Con sector, decide por el tipo de amenaza.
        if cat in _CRITICAL_THREAT_CATEGORIES:
            severity = "CRITICAL"
        elif cat in _THREAT_CATEGORIES or source in _SOURCE_HIGH:
            # exploit/malware/phishing sobre sector crítico, o fuente de
            # alta señal (Ransomware.live / CISA KEV): HIGH.
            severity = "HIGH"
        else:
            # Sector mencionado sin amenaza activa: solo monitoreo.
            severity = "MEDIUM"

        return {
            "critical_sector": sector,
            "incident_severity": severity,
            "threat_actor": actor,
            "sector_evidence": evidence,
            "sector_icon": SECTOR_ICONS[sector],
        }
    except Exception:
        return None


# ── Categoría heurística (para --fast-check sin LLM) ──
# El modo rápido no debe llamar al LLM (costo/latencia cada 15-30 min); si
# un RSS dispara como incidente, la categoría se infiere por keywords.
_CATEGORY_KEYWORDS = [
    ("ransomware", r"ransomware|ransom\s*note|cifrado|secuestro\s+de\s+datos"),
    ("breach", r"data\s+breach|filtraci[oó]n|breach|exfiltraci[oó]n|leak|filtra(?:dos?|ci[oó]n)"),
    ("exploit", r"exploit|exploited|explotaci[oó]n|zero[\s-]?day|0day"),
    ("phishing", r"phishing|suplantaci[oó]n|spoofing"),
    ("malware", r"malware|trojan|troyano|backdoor|stealer|banker|esp[ií]a|ransom"),
    ("vulnerability", r"vulnerab|patch|parche|cve-\d{4}-\d{4,}"),
]

def guess_category(title: str, desc: str = "") -> str:
    """Categoría por keywords para items RSS en --fast-check (sin LLM)."""
    text = f"{title or ''} {desc or ''}".lower()
    for cat, pat in _CATEGORY_KEYWORDS:
        if re.search(pat, text):
            return cat
    return "other"


__all__ = [
    "detect_sector",
    "extract_threat_actor",
    "classify_incident",
    "guess_category",
    "SECTOR_LABELS",
    "SECTOR_ICONS",
]
