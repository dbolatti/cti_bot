"""Tests para la lógica pura de setup.py (prompts y armado del .env).

Las funciones validate_* llaman a APIs reales (Telegram/Groq/OpenRouter/NVD/abuse.ch)
y no se testean acá — se verificaron manualmente contra las APIs reales durante el
desarrollo, siguiendo la misma convención que classify()/get_remediation() en cti_bot.py.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import setup


class TestAsk:
    def test_returns_typed_value(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "valor")
        assert setup.ask("Campo") == "valor"

    def test_empty_input_returns_default(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "")
        assert setup.ask("Campo", default="default_val") == "default_val"

    def test_empty_input_without_default_returns_empty(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "")
        assert setup.ask("Campo") == ""

    def test_required_reprompts_until_non_empty(self, monkeypatch):
        answers = iter(["", "", "al final"])
        monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
        assert setup.ask("Campo", required=True) == "al final"

    def test_strips_whitespace(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "  con espacios  ")
        assert setup.ask("Campo") == "con espacios"


class TestAskYesNo:
    @pytest.mark.parametrize("answer", ["s", "si", "sí", "S", "y", "yes"])
    def test_yes_variants(self, monkeypatch, answer):
        monkeypatch.setattr("builtins.input", lambda prompt: answer)
        assert setup.ask_yes_no("¿Seguro?", default=False) is True

    @pytest.mark.parametrize("answer", ["n", "no", "N"])
    def test_no_variants(self, monkeypatch, answer):
        monkeypatch.setattr("builtins.input", lambda prompt: answer)
        assert setup.ask_yes_no("¿Seguro?", default=True) is False

    def test_empty_returns_default_true(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "")
        assert setup.ask_yes_no("¿Seguro?", default=True) is True

    def test_empty_returns_default_false(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "")
        assert setup.ask_yes_no("¿Seguro?", default=False) is False

    def test_invalid_answer_reprompts(self, monkeypatch):
        answers = iter(["tal vez", "y"])
        monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
        assert setup.ask_yes_no("¿Seguro?", default=False) is True


class TestBuildEnvContent:
    def _values(self, **overrides) -> dict:
        base = {
            "telegram_token": "123:ABC",
            "chat_id": "999",
            "groq_key": "gsk_x",
            "groq_model": "qwen/qwen3.8-27b",
            "openrouter_key": "",
            "openrouter_model": "meta-llama/llama-3.1-8b-instruct",
            "nvd_key": "",
            "urlhaus_key": "",
            "notify_mode": "realtime",
            "notify_detail": "compact",
            "priority": "2",
        }
        base.update(overrides)
        return base

    def test_contains_all_required_keys(self):
        content = setup.build_env_content(self._values())
        for key in (
            "TELEGRAM_TOKEN", "TELEGRAM_CHAT_ID", "GROQ_API_KEY", "GROQ_MODEL",
            "OPENROUTER_API_KEY", "OPENROUTER_MODEL", "NVD_API_KEY", "URLHAUS_API_KEY",
            "SEND_PRIORITY_UP_TO", "NOTIFY_MODE", "NOTIFY_DETAIL",
        ):
            assert f"{key}=" in content

    def test_values_are_substituted(self):
        content = setup.build_env_content(self._values(chat_id="424242"))
        assert "TELEGRAM_CHAT_ID=424242" in content

    def test_empty_optional_keys_render_blank_not_none(self):
        content = setup.build_env_content(self._values(nvd_key="", urlhaus_key=""))
        assert "NVD_API_KEY=\n" in content
        assert "URLHAUS_API_KEY=\n" in content or content.rstrip().endswith("URLHAUS_API_KEY=")

    def test_output_is_dotenv_parseable(self, tmp_path):
        from dotenv import dotenv_values
        content = setup.build_env_content(self._values())
        env_file = tmp_path / ".env"
        env_file.write_text(content, encoding="utf-8")
        parsed = dotenv_values(env_file)
        assert parsed["TELEGRAM_TOKEN"] == "123:ABC"
        assert parsed["GROQ_MODEL"] == "qwen/qwen3.8-27b"
