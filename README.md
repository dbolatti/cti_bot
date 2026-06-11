# cti_bot

Pipeline de Cyber Threat Intelligence (CTI) personal. Consume feeds RSS y APIs estructuradas de fuentes de alta señal, clasifica cada evento con IA, y envía alertas priorizadas a Telegram.

Desarrollado como herramienta de inteligencia operacional en el marco de la investigación sobre ciberseguridad para PyMEs en CINAPTIC / UTN FRRe.

---

## Características

- Ingesta de múltiples fuentes: RSS, CISA KEV, Abuse.ch URLhaus, Ransomware.live, EPSS/FIRST
- Clasificación automática con LLM (Groq / Llama3) con bypass para fuentes de categoría conocida
- Sistema de prioridad P1–P3 con filtro configurable
- Razón técnica alineada a controles CIS Controls v8.1 IG1 en cada alerta
- Deduplicación mediante SQLite — no se repiten alertas ya procesadas
- Modos de notificación configurables: tiempo real, resumen diario, o ambos
- Niveles de detalle por mensaje: compacto, detallado o mínimo
- Filtros por categoría, severidad y relevancia operacional

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

### APIs estructuradas

| Fuente | Contenido | Clasificación |
|--------|-----------|---------------|
| CISA KEV | Vulnerabilidades explotadas activamente | Bypass — siempre `high` |
| Abuse.ch URLhaus | URLs maliciosas activas | Bypass — siempre `high` |
| Ransomware.live | Víctimas recientes por grupo ransomware | Bypass — siempre `high` |
| EPSS/FIRST | CVEs con alta probabilidad de explotación (score > 0.7) | Bypass — siempre `high` |

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

## Formato de alerta

**Compacto (default):**
```
🔴 P1 · MALWARE · BleepingComputer
TrickMo Android banker adopts TON blockchain
CIS-8.1: malware con capacidad de movimiento lateral en red local
CIS-8.1 · CIS-7.1
🔗 https://...
```

**Detallado:**
```
🔴 P1 · MALWARE · BleepingComputer
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
🔴 TrickMo Android banker adopts TON blockchain — BleepingComputer
🔗 https://...
```

---

## Requisitos

- Python 3.10+
- Cuenta en [Groq](https://console.groq.com) (gratuita)
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

Copiá `.env.example` a `.env`:

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
GROQ_API_KEY=gsk_...

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
├── .env              # credenciales y configuración local (no se sube)
├── .env.example      # plantilla de configuración
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Roadmap

- [x] Ingesta RSS de fuentes de alta señal
- [x] Clasificación con LLM (Groq / Llama3)
- [x] Bypass LLM para fuentes de categoría conocida
- [x] Sistema de prioridad P1/P2/P3
- [x] Mapeo a controles CIS Controls v8.1 IG1
- [x] Resumen diario consolidado
- [x] Modos de notificación configurables
- [x] Niveles de detalle configurables
- [x] EPSS/FIRST para priorización por probabilidad de explotación
- [ ] Ingesta desde canales Telegram vía Telethon
- [ ] Dashboard web (Streamlit)
- [ ] Migración a Claude API en producción
- [ ] Correlación de IOCs entre fuentes

---

## Licencia

MIT
