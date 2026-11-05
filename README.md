# cti_bot

Pipeline de Cyber Threat Intelligence (CTI) personal. Consume feeds RSS y APIs estructuradas de fuentes de alta señal, clasifica cada evento con IA, y envía alertas priorizadas a Telegram. Incluye **modo interactivo completo** con suscripciones por usuario, consultas bajo demanda y alertas diferenciadas para incidentes críticos en sectores gobierno/financiero.

Desarrollado como herramienta de inteligencia operacional en el marco de la investigación sobre ciberseguridad para PyMEs en CINAPTIC / UTN FRRe.

---

## Características

- **Ingesta multi-fuente**: RSS (14 fuentes), CISA KEV, Abuse.ch URLhaus/ThreatFox, Ransomware.live, EPSS/FIRST
- **Clasificación automática con IA** (Groq principal, fallback automático a OpenRouter) con bypass para fuentes de categoría conocida
- **Clasificador de sectores críticos** (sin LLM): detecta menciones a **gobierno** 🏛️ / **financiero** 🏦 y asigna severidad `CRITICAL/HIGH/MEDIUM`
- **Sistema de prioridad P1–P3** con filtro configurable por usuario
- **Razón técnica alineada a controles CIS Controls v8.1 IG1** en cada alerta
- **Deduplicación mediante SQLite** — no se repiten alertas ya procesadas (BD principal + BD ligera para fast-check)
- **Modos de notificación**: tiempo real, resumen diario, o ambos
- **Niveles de detalle**: compacto, detallado o mínimo
- **Filtros por categoría, severidad, sector, actor y relevancia operacional** — configurables por chat
- **Configuración por chat vía comandos de Telegram** — cada usuario personaliza sus preferencias sin tocar `.env`
- **Alertas de configuración**: aviso por Telegram si una API key queda inválida/faltante (throttle 1x/día)
- **Fallback automático de IA**: si Groq falla sostenidamente, cambia solo a OpenRouter
- **Correlación cross-fuentes**: CVEs, IOCs y grupos ransomware confirmados en fuentes estructuradas vs. noticias RSS
- **Remediación priorizada (IA)**: 2-3 acciones concretas para items P1/correlacionados
- **Panorama diario (IA)**: síntesis ejecutiva en el resumen diario
- **Modo fast-check (`--fast-check`)**: polling 15-30 min solo Ransomware.live + CISA KEV, sin LLM

---

## Fuentes monitoreadas

### Feeds RSS

| Fuente | Contenido |
|--------|-----------|
| BleepingComputer | Noticias y análisis de seguridad |
| The Hacker News | Vulnerabilidades y amenazas |
| SANS ISC | Análisis técnico diario |
| Krebs on Security | Investigación periodística |
| Recorded Future | Threat intelligence |
| Securelist (Kaspersky) | Malware y APT |
| Malwarebytes Labs | Malware y campañas activas |
| Cisco Talos | Investigación ofensiva/defensiva |
| Unit 42 (Palo Alto) | Amenazas avanzadas |
| Schneier on Security | Análisis y política de seguridad |
| ThreatPost | Noticias y vulnerabilidades |
| Dark Reading | Vulnerabilidades y defensa |
| CERT/CC | Advisories oficiales |
| INCIBE-CERT | Avisos de vulnerabilidades de producto, en español |

### APIs estructuradas

| Fuente | Contenido | Clasificación |
|--------|-----------|---------------|
| CISA KEV | Vulnerabilidades explotadas activamente | Bypass — siempre `high` |
| Abuse.ch URLhaus | URLs maliciosas activas | Bypass — siempre `high` |
| Abuse.ch ThreatFox | IOCs de malware/C2 con confianza ≥75% | Bypass — siempre `high` |
| Ransomware.live | Víctimas recientes por grupo ransomware | Bypass — siempre `high` |
| EPSS/FIRST | CVEs con alta probabilidad de explotación (score > 0.7) | Bypass — siempre `high` |

> URLhaus y ThreatFox requieren un Auth-Key de cuenta abuse.ch (gratis en [auth.abuse.ch](https://auth.abuse.ch/)) — es la misma key para ambas APIs.

---

## Sistema de prioridad

| Nivel | Criterio | Ícono |
|-------|----------|-------|
| P1 | Severidad alta + relevante operacionalmente | 🔴 |
| P2 | Severidad alta, o severidad media + relevante | 🟠 |
| P3 | Severidad media | 🟡 |
| — | Severidad baja | No se envía |

El umbral se configura con `SEND_PRIORITY_UP_TO` en `.env`.

---

## Comandos de Telegram

Cualquier chat autorizado (el dueño del bot, o los que figuren en `ALLOWED_CHAT_IDS`) puede configurar sus preferencias y hacer consultas escribiéndole al bot:

### Configuración de alertas

| Comando | Ejemplo | Efecto |
|---------|---------|--------|
| `/config` | — | Ver tu configuración completa |
| `/set_sector` | `/set_sector finance,gov` | Sectores de interés: `finance` (🏦), `gov` (🏛️), `all` |
| `/set_severity` | `/set_severity CRITICAL` | Umbral mínimo: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `/follow` | `/follow lockbit` | Seguir un grupo de amenazas |
| `/unfollow` | `/unfollow lockbit` | Dejar de seguir un grupo |
| `/follow_list` | — | Ver actores que seguís |

### Notificaciones (legacy, compatibles)

| Comando | Ejemplo | Efecto |
|---------|---------|--------|
| `/modo` | `/modo daily` | `realtime`, `daily` o `both` |
| `/detalle` | `/detalle minimal` | `compact`, `detailed` o `minimal` |
| `/prioridad` | `/prioridad 1` | Prioridad máxima a recibir (1–3) |
| `/filtro` | `/filtro ransomware,phishing` | Categorías a recibir (`off` = todas) |
| `/sme` | `/sme on` | Solo items con impacto operacional |

### Consultas bajo demanda

| Comando | Ejemplo | Efecto |
|---------|---------|--------|
| `/search` | `/search Banco` | Busca en últimos incidentes (título/desc/víctima) |
| `/stats` | `/stats 7d` | Resumen: total, top 3 actores, sectores, categorías (24h/7d) |
| `/actor` | `/actor lockbit` | Últimas víctimas y actividad del grupo |
| `/export` | `/export 30d` | Envía CSV con incidentes del período (7d/30d) |

### Ayuda

| Comando | Efecto |
|---------|--------|
| `/start` | Bienvenida y primeros pasos |
| `/help` o `/ayuda` | Lista completa de comandos |
| `/status` | Alias de `/config` (legacy) |

Cada chat guarda su config en SQLite (`user_config`) — el `.env` solo define los valores por defecto para chats que nunca escribieron un comando.

---

## Alertas de configuración

Si una fuente que requiere API key (Groq, OpenRouter, NVD, URLhaus, ThreatFox) empieza a fallar por una key inválida o faltante, el bot le manda al dueño (`TELEGRAM_CHAT_ID`) un mensaje explicando qué falló y cómo corregirlo:

```
⚠️ Problemas de configuración detectados

🔑 NVD: la API key configurada es inválida ("Invalid apiKey"). Generá una nueva
en https://nvd.nist.gov/developers/request-an-api-key o dejá NVD_API_KEY vacío
en .env para usar el modo sin key (más lento pero funcional).

Este aviso se repite una vez por día mientras el problema persista.
```

El aviso se repite como máximo una vez por día por problema, y solo cubre fallas de configuración/credenciales — errores transitorios de red no generan alerta.

---

## Correlación entre fuentes

Cada corrida cruza los CVEs, los IOCs (IPs, dominios, hashes) y los grupos de ransomware que trajeron las fuentes estructuradas de alta señal (CISA KEV, EPSS/FIRST, URLhaus, ThreatFox, Ransomware.live) contra el texto de las demás noticias. Si una noticia RSS menciona un CVE, un indicador o un grupo que ya está confirmado como activo en otra fuente, se marca la alerta y se sube su prioridad:

```
🔴🔓 P1 · VULN · BleepingComputer
Atacantes explotan CVE-2026-18577 activamente, alertan investigadores
CIS-7.3: posible explotación activa según fuentes
CIS: CIS-7.1 · CIS-7.2
🎯 Correlaciona con: CVE-2026-18577 (CISA KEV)
🔗 https://...
```

Los nombres de grupo de ransomware llevan un filtro extra: se descartan los de menos de 4 caracteres (ej. "Aurora" es grupo real y nombre común) para reducir falsos positivos. Solo mira la corrida actual (sin historial en `cti.db`).

---

## Remediación priorizada y panorama diario (IA)

- **Qué hacer ahora**: para items P1 o correlacionados, 2-3 acciones concretas + dónde verificar exposición en el entorno propio.
- **Panorama del día**: párrafo generado por IA (1 vez/día) sintetizando amenaza dominante, atención inmediata y controles a reforzar.

Si la IA falla, ambas se omiten en silencio — nunca bloquean el envío de la alerta base.

---

## Formato de alerta

### Alerta estándar (compacto/default)

```
🔴🦠 P1 · MALWARE · BleepingComputer
TrickMo Android banker adopts TON blockchain
CIS-8.1: malware con capacidad de movimiento lateral en red local
CIS-8.1 · CIS-7.1
🔗 https://...
```

### Alerta diferenciada — Incidente CRÍTICO en sector crítico

```
🚨 *CRITICAL* 🏦 P1 · Financiero / Fintech · RANSOMWARE · Ransomware.live
*Víctima ransomware: Banco Nacional de Argentina — LockBit*
_CIS-13.1: incidente critical en financiero / fintech_
CIS: `CIS-8.1` · `CIS-7.1` | Actor: lockbit
🔗 [Ver más](https://www.ransomware.live/group/lockbit)
```

**Elementos distintivos**: badge `🚨 *CRITICAL*`, icono de sector (🏛️/🏦), label de sector, actor si conocido, evidencia de sector, controles CIS.

### Detallado

Incluye resumen completo, motivo SME, actor, evidencia, controles CIS IG1 listados, correlaciones y remediación.

### Mínimo

Solo título + link.

---

## Modo fast-check (`--fast-check`)

Ejecución ligera para polling de alta frecuencia (15-30 min):

- **Fuentes**: solo Ransomware.live + CISA KEV (incidentes confirmados)
- **Sin LLM**: clasificación heurística por keywords (`guess_category`)
- **Deduplicación**: BD ligera separada (`cti_fast.db`, purga 7 días)
- **Respeta preferencias**: sectores, severidad mínima, actores seguidos por usuario
- **Uso**: `python cti_bot.py --fast-check`

---

## Requisitos

- Python 3.10+
- Cuenta en [Groq](https://console.groq.com) (gratuita) y/o [OpenRouter](https://openrouter.ai) — al menos una
- Bot de Telegram creado vía [@BotFather](https://t.me/BotFather)

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/dbolatti/cti_bot.git
cd cti_bot
```

### 2. Crear el entorno virtual

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar credenciales

**Opción recomendada — asistente interactivo:**
```bash
python setup.py
```
Pide token de Telegram (lo valida), detecta `chat_id` automáticamente, valida cada API key con llamada real antes de guardar. Escribe el `.env` por vos.

**Opción manual:**
```bash
cp .env.example .env    # Linux/Mac
copy .env.example .env  # Windows
```
Editá `.env` con tus valores (ver sección Configuración).

---

## Configuración

Todos los parámetros se gestionan desde `.env`:

```ini
# ── Credenciales ──────────────────────────────────────────────
TELEGRAM_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=987654321

# ── Proveedores de IA: hace falta configurar al menos uno ──────
GROQ_API_KEY=gsk_...
GROQ_MODEL=qwen/qwen3.8-27b

# Fallback opcional — generar en https://openrouter.ai/keys
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=meta-llama/llama-3.1-8b-instruct

# chat_ids adicionales autorizados (coma-separados)
ALLOWED_CHAT_IDS=

# ── Filtros de envío ──────────────────────────────────────────
SEND_PRIORITY_UP_TO=2
SME_ONLY=false
CATEGORIES=
NOTIFY_MODE=realtime
NOTIFY_DETAIL=compact
DAILY_SUMMARY_HOUR=8

# ── API keys opcionales ───────────────────────────────────────
NVD_API_KEY=
URLHAUS_API_KEY=
```

### Obtener credenciales

| Credencial | Dónde |
|------------|-------|
| Telegram Bot Token | [@BotFather](https://t.me/BotFather) → `/newbot` |
| Telegram Chat ID | Escribile a tu bot → `https://api.telegram.org/bot<TOKEN>/getUpdates` |
| Groq API Key | [console.groq.com](https://console.groq.com) → API Keys |
| OpenRouter API Key | [openrouter.ai/keys](https://openrouter.ai/keys) |
| abuse.ch Auth-Key | [auth.abuse.ch](https://auth.abuse.ch/) (para URLhaus + ThreatFox) |
| NVD API Key | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) |

---

## Uso

### Ejecución manual

**Windows:**
```powershell
.\venv\Scripts\Activate.ps1
python cti_bot.py
```

**Linux/Mac:**
```bash
source venv/bin/activate
python cti_bot.py
```

### Modo fast-check (polling 15-30 min)

```bash
python cti_bot.py --fast-check
```

### Ejecución automática

**Windows — Task Scheduler (PowerShell admin):**
```powershell
# Normal cada 2h
schtasks /create /tn "CTI_Bot_Normal" `
  /tr "C:\ruta\cti_bot\venv\Scripts\python.exe C:\ruta\cti_bot\cti_bot.py" `
  /sc hourly /mo 2 /st 00:00

# Fast-check cada 15 min
schtasks /create /tn "CTI_Bot_FastCheck" `
  /tr "C:\ruta\cti_bot\venv\Scripts\python.exe C:\ruta\cti_bot\cti_bot.py --fast-check" `
  /sc minute /mo 15 /st 00:00
```

**Linux/Mac — crontab:**
```bash
crontab -e
# Normal cada 2h
0 */2 * * * cd /ruta/cti_bot && venv/bin/python cti_bot.py >> cti.log 2>&1
# Fast-check cada 15 min
*/15 * * * * cd /ruta/cti_bot && venv/bin/python cti_bot.py --fast-check >> cti_fast.log 2>&1
```

### Limpiar base de datos

```powershell
del cti.db cti_fast.db    # Windows
rm cti.db cti_fast.db     # Linux/Mac
python cti_bot.py
```

---

## Estructura del proyecto

```
cti_bot/
├── cti_bot.py              # script principal (pipeline + CLI)
├── bot_handlers.py         # lógica desacoplada de comandos interactivos
├── incident_classifier.py  # detector de sectores/actores/severidad (regex, sin LLM)
├── setup.py                # asistente interactivo de primera configuración
├── tests/                  # tests unitarios (pytest)
│   ├── test_cti_bot.py
│   ├── test_incident_classifier.py
│   ├── test_bot_handlers.py
│   └── test_setup.py
├── scripts/                # helpers de pre-commit
├── .env                    # credenciales local (no se sube)
├── .env.example            # plantilla de configuración
├── .gitignore
├── requirements.txt
├── CLAUDE.md               # guía de arquitectura
└── README.md
```

---

## Tests

```bash
# Suite completa
python -m pytest tests/ -v

# Solo tests nuevos
python -m pytest tests/test_bot_handlers.py tests/test_incident_classifier.py -v
```

**179 tests** cubriendo: escape Markdown, clasificación, prioridad, correlación, IOCs, circuit breaker IA, formato mensajes, clasificador sectores, handlers interactivos (config, filtros, consultas, export), compatibilidad legacy.

---

## Roadmap

- [x] Ingesta RSS de fuentes de alta señal
- [x] Clasificación con IA (Groq) + fallback OpenRouter
- [x] Bypass LLM para fuentes de categoría conocida
- [x] Sistema de prioridad P1/P2/P3
- [x] Mapeo a controles CIS Controls v8.1 IG1
- [x] Resumen diario consolidado
- [x] Modos de notificación configurables
- [x] Niveles de detalle configurables
- [x] EPSS/FIRST para priorización por probabilidad de explotación
- [x] Configuración por chat vía comandos de Telegram
- [x] Fuentes ThreatFox e INCIBE-CERT
- [x] Alertas de configuración (API keys) al dueño del bot
- [x] Correlación de CVEs, IOCs y grupos de ransomware entre fuentes
- [x] Remediación priorizada (IA) para items P1/correlacionados
- [x] Panorama diario generado por IA en el resumen
- [x] Fallback automático a OpenRouter si Groq falla
- [x] Asistente interactivo de primera configuración (`setup.py`)
- [x] **Clasificador de sectores críticos (gobierno/financiero) sin LLM**
- [x] **Modo fast-check (`--fast-check`) para polling alta frecuencia**
- [x] **Suscripciones avanzadas: sectores, severidad mínima, actores seguidos**
- [x] **Consultas bajo demanda: /search, /stats, /actor, /export**
- [x] **Plantilla de alerta diferenciada para incidentes CRITICAL/HIGH**
- [ ] Ingesta desde canales Telegram vía Telethon
- [ ] Dashboard web (Streamlit)
- [ ] Migración a Claude API en producción

---

## Licencia

MIT