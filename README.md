# cti_bot

Pipeline de Cyber Threat Intelligence (CTI) personal. Consume feeds RSS y APIs estructuradas de fuentes de alta señal, clasifica cada evento con IA, y envía alertas priorizadas a Telegram.

Desarrollado como herramienta de inteligencia operacional en el marco de la investigación sobre ciberseguridad para PyMEs en CINAPTIC / UTN FRRe.

---

## Características

- Ingesta de múltiples fuentes: RSS, CISA KEV, Abuse.ch URLhaus/ThreatFox, Ransomware.live, EPSS/FIRST
- Clasificación automática con IA (Groq como principal, con fallback automático a OpenRouter si Groq falla) con bypass para fuentes de categoría conocida
- Sistema de prioridad P1–P3 con filtro configurable
- Razón técnica alineada a controles CIS Controls v8.1 IG1 en cada alerta
- Deduplicación mediante SQLite — no se repiten alertas ya procesadas
- Modos de notificación configurables: tiempo real, resumen diario, o ambos
- Niveles de detalle por mensaje: compacto, detallado o mínimo
- Filtros por categoría, severidad y relevancia operacional
- Configuración por chat vía comandos de Telegram (`/modo`, `/detalle`, `/prioridad`, `/filtro`, `/sme`) — cada usuario puede tener sus propias preferencias sin tocar el `.env`
- Alertas de configuración: si una API key queda inválida o falta, el dueño del bot recibe un aviso por Telegram con la causa y cómo corregirla (1 vez por día por problema)
- Fallback automático de IA: si Groq falla de forma sostenida (rate limit agotado, key inválida, o un modelo dado de baja), el bot cambia solo a OpenRouter por el resto de esa corrida, sin intervención manual

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

Cualquier chat autorizado (el dueño del bot, o los que figuren en `ALLOWED_CHAT_IDS`) puede
configurar sus propias preferencias de notificación escribiéndole al bot, sin tocar el `.env`:

| Comando | Ejemplo | Efecto |
|---------|---------|--------|
| `/modo` | `/modo daily` | `realtime`, `daily` o `both` |
| `/detalle` | `/detalle minimal` | `compact`, `detailed` o `minimal` |
| `/prioridad` | `/prioridad 1` | Prioridad máxima a recibir (1–3) |
| `/filtro` | `/filtro ransomware,phishing` | Categorías a recibir (`off` = todas) |
| `/sme` | `/sme on` | Solo items con impacto operacional |
| `/status` | — | Ver la configuración actual del chat |
| `/ayuda` | — | Ver este mismo listado |

Cada chat guarda su config en SQLite (`user_config`) — el `.env` solo define los valores por
defecto para chats que nunca escribieron un comando.

---

## Alertas de configuración

Si una fuente que requiere API key (Groq, OpenRouter, NVD, URLhaus, ThreatFox) empieza a fallar por
una key inválida o faltante, el bot no se queda solo logueando el error: le manda al dueño
(`TELEGRAM_CHAT_ID`) un mensaje explicando qué falló y cómo corregirlo, por ejemplo:

```
⚠️ Problemas de configuración detectados

🔑 NVD: la API key configurada es inválida ("Invalid apiKey"). Generá una nueva
en https://nvd.nist.gov/developers/request-an-api-key o dejá NVD_API_KEY vacío
en .env para usar el modo sin key (más lento pero funcional).

Este aviso se repite una vez por día mientras el problema persista.
```

El aviso se repite como máximo una vez por día por problema (no en cada corrida), y solo cubre
fallas de configuración/credenciales — errores transitorios de red no generan alerta.

---

## Correlación entre fuentes

Cada corrida cruza los CVEs, los IOCs (IPs, dominios, hashes) y los grupos de ransomware que
trajeron las fuentes estructuradas de alta señal (CISA KEV, EPSS/FIRST, URLhaus, ThreatFox,
Ransomware.live) contra el texto de las demás noticias. Si una noticia RSS menciona un CVE, un
indicador o un grupo que ya está confirmado como activo en otra fuente, se marca la alerta y se
sube su prioridad — es una confirmación real, no solo una noticia más:

```
🔴🔓 P1 · VULN · BleepingComputer
Atacantes explotan CVE-2026-18577 activamente, alertan investigadores
CIS-7.3: posible explotación activa según fuentes
CIS: CIS-7.1 · CIS-7.2
🎯 Correlaciona con: CVE-2026-18577 (CISA KEV)
🔗 https://...
```

Los nombres de grupo de ransomware llevan un filtro extra que el resto no necesita: se descartan
los de menos de 4 caracteres, porque a diferencia de un CVE o un hash, un nombre de grupo puede
coincidir con una palabra común del idioma (ej. "Aurora" es a la vez un grupo real y un nombre
propio) — el riesgo de falso positivo es mayor que con el resto de las correlaciones.

Solo mira lo que trajo la corrida actual (no hay historial ni cambios de esquema en `cti.db`).

---

## Remediación priorizada y panorama diario (IA)

Además de clasificar, el bot usa IA (Groq, o el proveedor de fallback si Groq no responde) para dos
cosas más, acotadas para no disparar el costo en tokens con el volumen de la corrida:

- **Qué hacer ahora**: para los items más críticos (P1, o cualquiera que haya correlacionado con
  un CVE/IOC confirmado), un segundo prompt le pide a la IA 2-3 acciones concretas y en qué fijarse
  en el propio entorno para confirmar exposición — no solo el tag de control CIS:

  ```
  🛠️ Qué hacer:
  1. Revisar logs de firewall de los últimos 7 días por conexiones salientes al
     dominio evil-domain.com.
  2. Escanear endpoints con el hash/IOC reportado usando el EDR disponible.
  ```

- **Panorama del día**: el resumen diario (`NOTIFY_MODE=daily` o `both`) arranca con un párrafo
  generado por IA (una sola vez por día, no por item) que sintetiza qué tipo de amenaza dominó,
  qué requiere atención inmediata, y en qué controles conviene enfocarse — antes de la lista de
  siempre con el top 5 del día.

Si la IA falla o no responde (ningún proveedor disponible), ambas mejoras se omiten en silencio y
el mensaje se manda igual sin ellas (nunca bloquean el envío de la alerta base).

---

## Formato de alerta

El ícono de prioridad (🔴🟠🟡) va acompañado del ícono de categoría (💀 ransomware, 🎣 phishing,
💥 exploit, 🦠 malware, 🔓 vulnerability, 🚨 breach, 📌 other) para identificar el tipo de evento
de un vistazo. Los links se envían sin previsualización, para no ensuciar el chat con tarjetas
grandes cuando salen muchas alertas seguidas.

**Compacto (default):**
```
🔴🦠 P1 · MALWARE · BleepingComputer
TrickMo Android banker adopts TON blockchain
CIS-8.1: malware con capacidad de movimiento lateral en red local
CIS-8.1 · CIS-7.1
🔗 https://...
```

**Detallado:**
```
🔴🦠 P1 · MALWARE · BleepingComputer
TrickMo Android banker adopts TON blockchain

Resumen completo del evento en dos líneas...

✅ Relevante operacionalmente
CIS-8.1: malware con capacidad de movimiento lateral en red local

Controles CIS IG1:
  • CIS-8.1 Antimalware en endpoints
  • CIS-7.1 Gestión de vulnerabilidades
  • CIS-6.2 Privilegio mínimo

🔗 https://...
```

**Mínimo:**
```
🔴🦠 TrickMo Android banker adopts TON blockchain — BleepingComputer
🔗 https://...
```

---

## Requisitos

- Python 3.10+
- Cuenta en [Groq](https://console.groq.com) (gratuita) y/o [OpenRouter](https://openrouter.ai) — hace falta al menos una
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

Te pide el token de Telegram (y lo valida), detecta el `chat_id` automáticamente
(solo tenés que escribirle un mensaje a tu bot cuando te lo pida), y valida cada API
key con una llamada real al proveedor antes de guardarla — nada de copiar y pegar a
ciegas en un archivo de texto. Si algo falla, te deja reintentar u omitirlo. Al final
escribe el `.env` por vos. Las preferencias de notificación se pueden ajustar después
en cualquier momento hablándole al bot (`/modo`, `/detalle`, `/prioridad`), así que el
asistente no te las pregunta en detalle.

**Opción manual:**

```bash
cp .env.example .env    # Linux/Mac
copy .env.example .env  # Windows
```

Editá `.env` con tus valores (ver sección Configuración).

---

## Configuración

Todos los parámetros se gestionan desde el archivo `.env`:

```ini
# ── Credenciales ──────────────────────────────────────────────
TELEGRAM_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=987654321

# ── Proveedores de IA: hace falta configurar al menos uno ──────
# Groq es el principal. Si falla de forma sostenida (rate limit agotado, key
# inválida, o un modelo dado de baja), el bot cambia solo a OpenRouter para
# el resto de esa corrida, si está configurado.
GROQ_API_KEY=gsk_...
GROQ_MODEL=qwen/qwen3.8-27b

# Fallback opcional — generar en https://openrouter.ai/keys
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=meta-llama/llama-3.1-8b-instruct

# chat_ids adicionales autorizados a usar comandos del bot y recibir alertas
# (separados por coma). El owner (TELEGRAM_CHAT_ID) siempre está autorizado;
# cualquier otro chat_id que le escriba al bot es ignorado.
ALLOWED_CHAT_IDS=

# ── Filtros de envío ──────────────────────────────────────────
# Prioridad máxima a enviar: 1=solo crítico, 2=crítico+importante, 3=todo
SEND_PRIORITY_UP_TO=2

# Solo enviar items relevantes operacionalmente (true/false)
SME_ONLY=false

# Categorías a monitorear (separadas por coma, vacío = todas)
# Valores: ransomware, phishing, exploit, malware, vulnerability, breach, other
CATEGORIES=

# ── Modo de notificación ──────────────────────────────────────
# realtime = alerta por cada item nuevo
# daily    = solo resumen diario
# both     = alertas en tiempo real + resumen diario
NOTIFY_MODE=realtime

# ── Detalle del mensaje ───────────────────────────────────────
# compact  = 4 líneas + link (recomendado)
# detailed = resumen completo + todos los controles CIS
# minimal  = solo título + link
NOTIFY_DETAIL=compact

# Hora del resumen diario en UTC (0-23)
DAILY_SUMMARY_HOUR=8

# ── API keys opcionales (enriquecen fuentes, no son obligatorias) ─────
# NVD: sin key, EPSS/FIRST igual funciona pero con rate limit más bajo (6s entre requests)
NVD_API_KEY=

# abuse.ch: obligatoria desde jun/2025 para URLhaus y ThreatFox (misma key para ambas)
URLHAUS_API_KEY=
```

### Obtener el Telegram Bot Token

1. Abrí [@BotFather](https://t.me/BotFather) en Telegram
2. Enviá `/newbot` y seguí las instrucciones
3. Copiá el token que te entrega

### Obtener el Telegram Chat ID

1. Iniciá una conversación con tu bot (buscalo por username y enviá `/start`)
2. Abrí en el navegador: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. El Chat ID está en `result[0].message.chat.id`

### Obtener el Groq API Key

1. Registrate en [console.groq.com](https://console.groq.com)
2. Andá a API Keys → Create
3. Copiá la key (empieza con `gsk_`)
4. Los modelos disponibles cambian con el tiempo (Groq ya deprecó `llama3-8b-8192` y después
   `llama-3.1-8b-instant`) — revisá [console.groq.com/docs/models](https://console.groq.com/docs/models)
   y ajustá `GROQ_MODEL` en `.env` si el default deja de funcionar, sin tocar código

### Obtener la OpenRouter API Key (fallback, opcional)

1. Registrate en [openrouter.ai](https://openrouter.ai)
2. Generá una key en [openrouter.ai/keys](https://openrouter.ai/keys) — empieza con `sk-or-v1-`
   (en minúscula, es case-sensitive)
3. Ver modelos disponibles en [openrouter.ai/models](https://openrouter.ai/models) si querés cambiar
   `OPENROUTER_MODEL`

### Obtener el Auth-Key de abuse.ch (URLhaus + ThreatFox)

1. Registrate gratis en [auth.abuse.ch](https://auth.abuse.ch/)
2. En tu perfil, sección "Optional", generá el Auth-Key
3. Usá la misma key para `URLHAUS_API_KEY` — sirve para ambas APIs

### Obtener la NVD API Key (opcional)

1. Solicitala en [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
2. Sin key, el enriquecimiento de CVEs (EPSS/FIRST) igual funciona, solo más lento

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

### Ejecución automática cada 2 horas

**Windows — Task Scheduler** (PowerShell como administrador):

```powershell
schtasks /create /tn "CTI_Bot" /tr "C:\cti_bot\venv\Scripts\python.exe C:\cti_bot\cti_bot.py" /sc hourly /mo 2 /st 00:00
```

**Linux/Mac — crontab:**

```bash
crontab -e
# agregar esta línea:
0 */2 * * * cd /ruta/cti_bot && venv/bin/python cti_bot.py >> cti.log 2>&1
```

### Limpiar la base de datos

Si querés reprocesar todas las fuentes desde cero:

```powershell
del cti.db        # Windows
rm cti.db         # Linux/Mac
python cti_bot.py
```

---

## Estructura del proyecto

```
cti_bot/
├── cti_bot.py        # script principal
├── setup.py          # asistente interactivo de primera configuración
├── tests/            # tests unitarios (pytest) de las funciones puras
├── scripts/          # helpers de pre-commit (chequeo de archivos sensibles)
├── .env              # credenciales y configuración local (no se sube)
├── .env.example      # plantilla de configuración
├── .gitignore
├── requirements.txt
├── CLAUDE.md         # guía de arquitectura para trabajar sobre el código
└── README.md
```

---

## Roadmap

- [x] Ingesta RSS de fuentes de alta señal
- [x] Clasificación con IA (Groq)
- [x] Bypass LLM para fuentes de categoría conocida
- [x] Sistema de prioridad P1/P2/P3
- [x] Mapeo a controles CIS Controls v8.1 IG1
- [x] Resumen diario consolidado
- [x] Modos de notificación configurables
- [x] Niveles de detalle configurables
- [x] EPSS/FIRST para priorización por probabilidad de explotación
- [x] Configuración por chat vía comandos de Telegram
- [x] Fuentes ThreatFox e INCIBE-CERT
- [x] Alertas de configuración (API keys inválidas/faltantes) al dueño del bot
- [x] Correlación de CVEs, IOCs y grupos de ransomware entre fuentes
- [x] Remediación priorizada (IA) para items P1/correlacionados
- [x] Panorama diario generado por IA en el resumen
- [x] Fallback automático a OpenRouter si Groq falla de forma sostenida
- [x] Asistente interactivo de primera configuración (`setup.py`)
- [ ] Ingesta desde canales Telegram vía Telethon
- [ ] Dashboard web (Streamlit)
- [ ] Migración a Claude API en producción

---

## Licencia

MIT
