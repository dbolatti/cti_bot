"""Asistente interactivo de primera configuración para cti_bot.

Reemplaza el paso manual de "copiá .env.example a .env y editalo a mano": pide el
token de Telegram, detecta el chat_id automáticamente, valida cada API key con una
llamada real al proveedor (no solo formato), y escribe el .env por vos.

Uso:
    python setup.py                  # arma ./.env
    python setup.py --output .env.x  # arma otro archivo, para probar sin pisar el real
"""
import argparse
import sys
import time

import httpx

TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"


def header(text: str):
    print(f"\n── {text} " + "─" * max(0, 56 - len(text)))


def ask(prompt: str, default: str | None = None, required: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if not value and required:
            print("  (obligatorio, no puede quedar vacío)")
            continue
        return value


def ask_yes_no(prompt: str, default: bool) -> bool:
    suffix = " [S/n]" if default else " [s/N]"
    while True:
        value = input(f"{prompt}{suffix}: ").strip().lower()
        if not value:
            return default
        if value in ("s", "si", "sí", "y", "yes"):
            return True
        if value in ("n", "no"):
            return False
        print("  Respondé s/n")


def validate_telegram_token(token: str) -> tuple[bool, str]:
    try:
        resp = httpx.get(TELEGRAM_API.format(token=token, method="getMe"), timeout=10)
        data = resp.json()
        if resp.status_code == 200 and data.get("ok"):
            username = data["result"].get("username", "?")
            return True, username
        return False, data.get("description", f"HTTP {resp.status_code}")
    except httpx.RequestError as e:
        return False, str(e)


def detect_chat_id(token: str, bot_username: str) -> str | None:
    print(
        f"\nAbrí Telegram, buscá @{bot_username} y mandale cualquier mensaje "
        f"(por ejemplo /start)."
    )
    try:
        resp = httpx.get(TELEGRAM_API.format(token=token, method="getUpdates"), timeout=10)
        baseline = max(
            (u["update_id"] for u in resp.json().get("result", [])), default=0
        )
    except httpx.RequestError:
        baseline = 0

    print("Esperando tu mensaje (hasta 60s, Ctrl+C para pegarlo a mano)...", end="", flush=True)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(
                TELEGRAM_API.format(token=token, method="getUpdates"),
                params={"offset": baseline + 1},
                timeout=10,
            )
            updates = resp.json().get("result", [])
            for u in updates:
                msg = u.get("message", {})
                chat = msg.get("chat", {})
                if chat.get("id"):
                    print(" detectado!")
                    nombre = chat.get("first_name") or chat.get("title") or "?"
                    print(f"  chat_id: {chat['id']} (chat: {nombre})")
                    return str(chat["id"])
        except httpx.RequestError:
            pass
        print(".", end="", flush=True)
        time.sleep(2)
    print(" nada por ahora.")
    return None


def validate_llm_key(api_key: str, base_url: str, model: str, extra_headers: dict | None = None) -> tuple[bool, str]:
    headers = {"Authorization": f"Bearer {api_key}"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        resp = httpx.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json={
                "model": model,
                "messages": [{"role": "user", "content": "hola"}],
                "max_tokens": 5,
            },
            timeout=20,
        )
        if resp.status_code == 200:
            return True, "OK"
        try:
            detail = resp.json().get("error", {}).get("message", resp.text)
        except Exception:
            detail = resp.text
        return False, f"HTTP {resp.status_code}: {detail[:150]}"
    except httpx.RequestError as e:
        return False, str(e)


def validate_nvd_key(api_key: str) -> tuple[bool, str]:
    try:
        resp = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3400",
            headers={"apiKey": api_key},
            timeout=15,
        )
        if resp.status_code == 200:
            return True, "OK"
        if resp.headers.get("message", "").lower().startswith("invalid apikey"):
            return False, "Invalid apiKey"
        return False, f"HTTP {resp.status_code}"
    except httpx.RequestError as e:
        return False, str(e)


def validate_abusech_key(api_key: str) -> tuple[bool, str]:
    try:
        resp = httpx.get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            params={"limit": 1},
            headers={"Auth-Key": api_key},
            timeout=15,
        )
        if resp.status_code == 200:
            return True, "OK"
        return False, f"HTTP {resp.status_code}"
    except httpx.RequestError as e:
        return False, str(e)


def ask_and_validate_key(prompt: str, help_url: str, validator, *validator_args) -> str:
    print(f"  ({help_url})")
    while True:
        key = ask(prompt, default="")
        if not key:
            return ""
        print("  validando...", end=" ", flush=True)
        ok, detail = validator(key, *validator_args)
        if ok:
            print("OK")
            return key
        print(f"falló ({detail})")
        if not ask_yes_no("  ¿Reintentar?", default=True):
            if ask_yes_no("  ¿Guardar igual sin validar?", default=False):
                return key
            return ""


def build_env_content(v: dict) -> str:
    return f"""TELEGRAM_TOKEN={v['telegram_token']}
TELEGRAM_CHAT_ID={v['chat_id']}

# ── Proveedores de IA: hace falta configurar al menos uno ──────────────
# Groq es el principal. Si falla de forma sostenida (rate limit agotado,
# key inválida, o modelo dado de baja), el bot cambia solo a OpenRouter
# para el resto de esa corrida, si está configurado.
GROQ_API_KEY={v['groq_key']}
# Modelo de Groq (opcional) — cambiar acá si Groq da de baja el modelo actual,
# sin tocar código. Ver modelos disponibles en https://console.groq.com/docs/models
GROQ_MODEL={v['groq_model']}

# Clave de OpenRouter (opcional, fallback) — generar en https://openrouter.ai/keys
OPENROUTER_API_KEY={v['openrouter_key']}
# Modelo de OpenRouter (opcional). Ver alternativas en https://openrouter.ai/models
OPENROUTER_MODEL={v['openrouter_model']}

# chat_ids adicionales autorizados a usar comandos del bot y recibir alertas
# (separados por coma). El owner (TELEGRAM_CHAT_ID) siempre está autorizado.
ALLOWED_CHAT_IDS=

SEND_PRIORITY_UP_TO={v['priority']}
NOTIFY_MODE={v['notify_mode']}
NOTIFY_DETAIL={v['notify_detail']}
SME_ONLY=false
CATEGORIES=
DAILY_SUMMARY_HOUR=8

NVD_API_KEY={v['nvd_key']}

# Auth-Key de cuenta abuse.ch (https://auth.abuse.ch/) — obligatorio desde jun/2025.
# Se usa tanto para URLhaus como para ThreatFox (autenticación unificada por cuenta).
URLHAUS_API_KEY={v['urlhaus_key']}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=".env", help="Archivo a escribir (default: .env)")
    args = parser.parse_args()

    print("=== cti_bot — Asistente de configuración ===")
    print("Te va a llevar 2-3 minutos. Ctrl+C en cualquier momento para cortar sin guardar nada.")

    from pathlib import Path
    out_path = Path(args.output)
    if out_path.exists():
        print(f"\n⚠️  {out_path} ya existe.")
        if not ask_yes_no(f"¿Sobrescribirlo? (se guarda una copia en {out_path}.bak)", default=False):
            print("Cancelado.")
            return
        out_path.rename(out_path.with_suffix(out_path.suffix + ".bak"))

    values = {}

    header("Telegram")
    print("Si todavía no tenés un bot: hablale a @BotFather en Telegram, mandale /newbot")
    print("y seguí las instrucciones. Copiá el token que te entrega.")
    while True:
        token = ask("Pegá tu TELEGRAM_TOKEN", required=True)
        print("  validando...", end=" ", flush=True)
        ok, result = validate_telegram_token(token)
        if ok:
            print(f"OK, tu bot es @{result}")
            values["telegram_token"] = token
            bot_username = result
            break
        print(f"falló ({result})")

    chat_id = detect_chat_id(token, bot_username)
    if not chat_id:
        chat_id = ask("Pegá tu chat_id manualmente (o dejalo vacío para configurarlo después en .env)")
    values["chat_id"] = chat_id

    header("Proveedor de IA (al menos uno)")
    values["groq_key"] = ""
    values["groq_model"] = "qwen/qwen3.8-27b"
    values["openrouter_key"] = ""
    values["openrouter_model"] = "meta-llama/llama-3.1-8b-instruct"

    if ask_yes_no("¿Configurás Groq? (recomendado, es el principal)", default=True):
        values["groq_key"] = ask_and_validate_key(
            "Pegá tu GROQ_API_KEY",
            "generar en https://console.groq.com/keys",
            validate_llm_key, "https://api.groq.com/openai/v1", values["groq_model"],
        )

    openrouter_label = "¿Configurás OpenRouter" + (" como fallback?" if values["groq_key"] else "?")
    if ask_yes_no(openrouter_label, default=not values["groq_key"]):
        values["openrouter_key"] = ask_and_validate_key(
            "Pegá tu OPENROUTER_API_KEY",
            "generar en https://openrouter.ai/keys (empieza con sk-or-v1-, en minúscula)",
            validate_llm_key, "https://openrouter.ai/api/v1", values["openrouter_model"],
            {"HTTP-Referer": "https://github.com/dbolatti/cti_bot", "X-Title": "CTI_BOT"},
        )

    if not values["groq_key"] and not values["openrouter_key"]:
        print("\n⚠️  No configuraste ningún proveedor de IA — el bot no va a poder clasificar")
        print("   eventos hasta que agregues GROQ_API_KEY u OPENROUTER_API_KEY a mano en el .env.")

    header("Fuentes opcionales (podés omitirlas y agregarlas después)")
    values["nvd_key"] = ask_and_validate_key(
        "NVD_API_KEY (mejora el enriquecimiento de CVEs, Enter para omitir)",
        "generar en https://nvd.nist.gov/developers/request-an-api-key",
        validate_nvd_key,
    )
    values["urlhaus_key"] = ask_and_validate_key(
        "URLHAUS_API_KEY (necesaria para URLhaus/ThreatFox, Enter para omitir)",
        "generar en https://auth.abuse.ch/",
        validate_abusech_key,
    )

    header("Preferencias de notificación")
    print("Esto lo podés cambiar después en cualquier momento escribiéndole al bot")
    print("(/modo, /detalle, /prioridad) — no hace falta volver a correr este script.")
    values["notify_mode"] = ask("Modo [realtime/daily/both]", default="realtime")
    values["notify_detail"] = ask("Detalle [compact/detailed/minimal]", default="compact")
    values["priority"] = ask("Prioridad máxima a recibir [1/2/3]", default="2")

    out_path.write_text(build_env_content(values), encoding="utf-8")
    header("Listo")
    print(f"Configuración guardada en {out_path}")
    print("Corré `python cti_bot.py` para probarlo (o esperá a la próxima corrida programada).")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nCancelado, no se guardó nada.")
        sys.exit(1)
