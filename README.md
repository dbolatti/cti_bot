# cti_bot

Pipeline de Cyber Threat Intelligence (CTI) personal. Consume feeds RSS y APIs estructuradas de fuentes de alta señal, clasifica cada evento con IA, y envía alertas priorizadas a Telegram.

## Características

- Ingesta de múltiples fuentes: RSS, CISA KEV, Abuse.ch URLhaus
- Clasificación automática con LLM (Groq / Llama3 en desarrollo, Claude en producción)
- Sistema de prioridad P1–P3 con filtro configurable
- Indicador de relevancia para PyMEs en cada alerta
- Deduplicación mediante SQLite — no se repiten alertas ya vistas
- Mensajes compactos con link directo a la fuente

## Fuentes monitoreadas

| Fuente | Tipo | Contenido |
|--------|------|-----------|
| BleepingComputer | RSS | Noticias de seguridad |
| The Hacker News | RSS | Vulnerabilidades y amenazas |
| SANS ISC | RSS | Análisis técnico diario |
| Krebs on Security | RSS | Investigación periodística |
| Recorded Future | RSS | Threat intelligence |
| Securelist (Kaspersky) | RSS | Malware y APT |
| Malwarebytes Labs | RSS | Malware y campañas |
| Cisco Talos | RSS | Investigación ofensiva/defensiva |
| Unit 42 (Palo Alto) | RSS | Amenazas avanzadas |
| Schneier on Security | RSS | Análisis y política |
| CISA KEV | JSON API | Vulnerabilidades explotadas activamente |
| Abuse.ch URLhaus | REST API | URLs maliciosas activas |
| Ransomware.live | REST API | Víctimas recientes por grupo ransomware |

## Sistema de prioridad

| Nivel | Criterio | Ícono |
|-------|----------|-------|
| P1 | Severidad alta + relevante para PyMEs | 🔴 |
| P2 | Severidad alta, o severidad media + relevante para PyMEs | 🟠 |
| P3 | Severidad media | 🟡 |
| — | Severidad baja | No se envía |

El umbral se configura con `SEND_PRIORITY_UP_TO` en el script.

## Formato de alerta

```
🔴 P1 · MALWARE · BleepingComputer
TrickMo Android banker adopts TON blockchain
_riesgo de robo de credenciales bancarias en dispositivos corporativos_
🔗 https://...
```

## Requisitos

- Python 3.10+
- Cuenta en [Groq](https://console.groq.com) (gratuita)
- Bot de Telegram creado vía [@BotFather](https://t.me/BotFather)

## Instalación

```bash
git clone https://github.com/dbolatti/cti_bot.git
cd cti_bot
python -m venv venv
venv\Scripts\Activate.ps1   # Windows
pip install -r requirements.txt
```

## Configuración

Copiá `.env.example` a `.env` y completá los valores:

```bash
cp .env.example .env
```

```ini
TELEGRAM_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=987654321
GROQ_API_KEY=gsk_...
```

Para obtener tu `TELEGRAM_CHAT_ID`: iniciá una conversación con tu bot y abrí `https://api.telegram.org/bot<TOKEN>/getUpdates` en el navegador.

## Uso

```bash
python cti_bot.py
```

Para ejecución automática cada 2 horas en Windows (PowerShell como administrador):

```powershell
schtasks /create /tn "CTI_Bot" /tr "C:\ruta\venv\Scripts\python.exe C:\ruta\cti_bot.py" /sc hourly /mo 2
```

En Linux/Mac:

```bash
# crontab -e
0 */2 * * * cd /ruta/cti_bot && venv/bin/python cti_bot.py >> cti.log 2>&1
```

## Estructura

```
cti_bot/
├── cti_bot.py        # script principal
├── .env              # credenciales locales (no se sube)
├── .env.example      # plantilla de configuración
├── .gitignore
├── requirements.txt
└── README.md
```

## Roadmap

- [ ] Resumen diario consolidado (top 5 por prioridad)
- [ ] Mapeo de alertas a controles CIS Controls v8 IG1
- [ ] Ingesta desde canales Telegram vía Telethon
- [ ] Dashboard web (Streamlit)
- [ ] Migración a Claude API en producción

## Contexto

Desarrollado como herramienta de inteligencia operacional en el marco de la investigación sobre ciberseguridad para PyMEs en CINAPTIC / UTN FRRe.

## Licencia

MIT
