# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Qué es este proyecto

Pipeline personal de Cyber Threat Intelligence (CTI): ingesta feeds RSS y APIs de seguridad,
clasifica cada evento con un LLM (Groq/Llama3), y envía alertas priorizadas a Telegram.
Desarrollado en el marco de investigación sobre ciberseguridad para PyMEs (CINAPTIC / UTN FRRe).

Todo el proyecto vive en un único script: `cti_bot.py`. No hay tests, linter ni build configurados.

## Entorno virtual

Existe un venv en `venv/` con todas las dependencias de `requirements.txt` ya instaladas
(`feedparser`, `groq`, `python-telegram-bot`, `httpx`, `python-dotenv`). **Usar siempre el
intérprete del venv para correr o probar código de este repo** — el Python global del sistema
no tiene estas dependencias instaladas.

- PowerShell: activar con `.\venv\Scripts\Activate.ps1`, o invocar directo sin activar:
  `.\venv\Scripts\python.exe cti_bot.py`
- Bash (Git Bash): `source venv/Scripts/activate`, o directo: `./venv/Scripts/python.exe cti_bot.py`

## Comandos

```powershell
# activar entorno virtual (Windows)
.\venv\Scripts\Activate.ps1

# instalar dependencias (solo si se agregan nuevas a requirements.txt)
pip install -r requirements.txt

# ejecución manual (corre una sola pasada del pipeline completo y termina)
python cti_bot.py

# reprocesar todo desde cero (borra dedupe + configs de usuario)
del cti.db
python cti_bot.py
```

No existen tests automatizados ni configuración de lint (`flake8`/`ruff`) en este repo todavía —
si se agregan, seguir la convención del resto del stack de Diego (`python -m pytest`, `ruff check .`).

El bot está pensado para correr en forma programada (Task Scheduler en Windows cada 2 horas,
crontab en Linux) — ver README para el comando exacto. Cada ejecución es una pasada única y
sincrónica del pipeline (`asyncio.run(run())`), no un proceso long-running/daemon.

## Configuración

Todo se controla vía `.env` (plantilla en `.env.example`, nunca commitear `.env` real):

- `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`, `GROQ_API_KEY`, `NVD_API_KEY` (opcional, para enriquecer EPSS)
- `SEND_PRIORITY_UP_TO` (1-3), `NOTIFY_MODE` (realtime|daily|both), `NOTIFY_DETAIL` (compact|detailed|minimal),
  `SME_ONLY`, `CATEGORIES`, `DAILY_SUMMARY_HOUR`

Estos valores de `.env` son solo el **default global** (dueño del bot). Cada chat de Telegram puede
sobreescribir su propia config vía comandos (`/modo`, `/detalle`, `/prioridad`, `/filtro`, `/sme`),
persistida en la tabla `user_config` de SQLite — ver sección Arquitectura.

## Arquitectura

Pipeline síncrono de una sola pasada (`run()` al final del archivo), en este orden:

1. **`handle_commands()`** — hace polling de `getUpdates` de la API de Telegram (no usa
   `python-telegram-bot` para esto, sino `httpx` directo), procesa comandos de usuarios
   (`/modo`, `/detalle`, `/prioridad`, `/filtro`, `/sme`, `/status`, `/ayuda`) y persiste
   cambios en `user_config`. Al final marca los updates como leídos con `offset`.

2. **Fetch de fuentes** — cada fuente es independiente y envuelta en try/except propio en `run()`,
   así que si una falla no tumba el resto del pipeline:
   - `fetch_rss(source, url)` — feeds RSS del dict `FEEDS` (13 fuentes), vía `feedparser`
   - `fetch_cisa_kev()` — JSON de CISA KEV
   - `fetch_urlhaus()` — API de Abuse.ch URLhaus (solo URLs `online`)
   - `fetch_ransomware_live()` — API de Ransomware.live
   - `fetch_epss_high()` — CVEs con EPSS score > 0.7 desde FIRST, enriquecidos con vendor/producto/CVSS
     consultando NVD por cada CVE (rate-limited con `asyncio.sleep`)

   Todas devuelven una lista de dicts homogéneos: `{id, title, desc, source, link}`.
   El `id` es un hash MD5 (del link o de una clave compuesta) usado para deduplicar.

3. **Clasificación (`classify()`)** — por cada item nuevo (no visto en SQLite, `is_seen()`):
   - Si la fuente está en `SOURCE_DEFAULTS` (CISA KEV, URLhaus, Ransomware.live, EPSS/FIRST, CERT/CC),
     se **bypassea el LLM** y se usa una clasificación fija (siempre `severity: high`) — estas fuentes
     ya son de alta señal por diseño y no necesitan al LLM para categorizar.
   - El resto pasa por Groq (`llama3-8b-8192`, elegido para minimizar consumo de tokens) con
     `CLASSIFY_PROMPT`, que exige respuesta JSON estricta con `category`, `severity`, `sme_relevant`,
     `sme_reason` (debe referenciar un control CIS v8.1 IG1 concreto) y `summary`.
   - Cada item clasificado se persiste con `save_item()` en la tabla `items` (incluye los controles
     CIS ya resueltos como JSON, vía `get_cis_controls()` / `CIS_MAPPING`).

4. **Sistema de prioridad (`get_priority()`)** — deriva P1/P2/P3 combinando `severity` + `sme_relevant`
   (no se persiste como columna, se recalcula al vuelo tanto para filtrar como para el ícono del mensaje):
   - P1 🔴: `severity=high` **y** relevante operacionalmente
   - P2 🟠: `severity=high`, o `severity=medium` **y** relevante
   - P3 🟡: `severity=medium` (no relevante)
   - `severity=low` nunca se envía

5. **Envío por usuario** — se itera sobre todos los `chat_id` conocidos (el del `.env` + los que
   escribieron algún comando y quedaron en `user_config`). Por cada chat_id se recalcula su propio
   filtro (`should_process_for_user()`, usa la config de esa fila) y se formatea el mensaje según
   su `notify_detail` (`format_message_for()`, 3 variantes: compact/detailed/minimal). El envío a
   Telegram reintenta hasta 3 veces con backoff exponencial ante error. El resumen diario
   (`get_daily_summary()`) solo se dispara si `notify_mode` incluye `daily`/`both` **y** la hora UTC
   actual coincide con `DAILY_SUMMARY_HOUR` (ventana de los primeros 10 minutos de esa hora, porque
   el scheduler corre cada 2hs y no hay garantía de caer justo en el minuto 0).

### Esquema SQLite (`cti.db`, se crea solo si no existe)

- `items` — historial de todo lo clasificado, PK = hash del link/id de origen → es lo que
  implementa la deduplicación entre corridas (`is_seen()`).
- `user_config` — override de preferencias por `chat_id`, default cuando no hay fila = valores
  globales del `.env` (ver `get_user_config()`).

### Puntos a tener en cuenta al modificar

- Al agregar una fuente nueva a `FEEDS`, si es de alta señal y no necesita pasar por LLM, agregarla
  también a `SOURCE_DEFAULTS` para bypassear la clasificación (patrón ya usado por CERT/CC, KEV, etc).
- `CIS_MAPPING` y `CATEGORY_LABEL`/`CATEGORY_ICON` deben mantenerse en sync con las categorías válidas
  usadas en `CLASSIFY_PROMPT` y en el comando `/filtro` (`ransomware, phishing, exploit, malware,
  vulnerability, breach, other`) — están hardcodeadas en varios lugares del archivo.
- El polling de comandos Telegram (`handle_commands`) no lleva estado de qué `update_id` fue el
  último procesado entre corridas más allá del `offset` que se envía al final — si el proceso corre
  cada 2hs vía scheduler, comandos enviados y no vistos en la ventana de fetch se pierden hasta la
  próxima corrida.
