"""Tests for pure functions in cti_bot.py.

Run with: python -m pytest tests/ -v
"""
import html
import os
import sys

import pytest

# Set dummy env vars before importing so the Groq client instantiates without a real key
os.environ.setdefault("TELEGRAM_TOKEN", "123456:test_token")
os.environ.setdefault("TELEGRAM_CHAT_ID", "123456")
os.environ.setdefault("GROQ_API_KEY", "test_key")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import cti_bot


# ── escape_markdown ────────────────────────────────────────────

class TestEscapeMarkdown:
    def test_escapes_underscore(self):
        assert cti_bot.escape_markdown("hello_world") == "hello\\_world"

    def test_escapes_asterisk(self):
        assert cti_bot.escape_markdown("**bold**") == "\\*\\*bold\\*\\*"

    def test_escapes_opening_bracket(self):
        # only '[' is escaped; ']' and '()' are not Markdown triggers in legacy mode
        assert cti_bot.escape_markdown("[link](url)") == "\\[link](url)"

    def test_escapes_backtick(self):
        assert cti_bot.escape_markdown("`code`") == "\\`code\\`"

    def test_empty_string_returns_empty(self):
        assert cti_bot.escape_markdown("") == ""

    def test_none_like_falsy_returns_as_is(self):
        # function guards with `if not text`
        assert cti_bot.escape_markdown("") == ""

    def test_no_special_chars_unchanged(self):
        assert cti_bot.escape_markdown("plain text 123") == "plain text 123"

    def test_combined_special_chars(self):
        result = cti_bot.escape_markdown("_italic_ and *bold*")
        assert result == "\\_italic\\_ and \\*bold\\*"

    def test_markdown_injection_link(self):
        # a feed title that could inject a clickable Telegram link
        malicious = "[click me](https://evil.com)"
        assert cti_bot.escape_markdown(malicious) == "\\[click me](https://evil.com)"


# ── validate_classification ────────────────────────────────────

class TestValidateClassification:
    def _valid(self) -> dict:
        return {
            "category":     "malware",
            "severity":     "high",
            "sme_relevant": True,
            "sme_reason":   "CIS-8.1: test reason",
            "summary":      "test summary",
        }

    def test_valid_input_passes_unchanged(self):
        result = cti_bot.validate_classification(self._valid())
        assert result["category"] == "malware"
        assert result["severity"] == "high"
        assert result["sme_relevant"] is True

    def test_unknown_category_becomes_other(self):
        d = self._valid()
        d["category"] = "apt"
        assert cti_bot.validate_classification(d)["category"] == "other"

    def test_unknown_severity_becomes_low(self):
        d = self._valid()
        d["severity"] = "critical"
        assert cti_bot.validate_classification(d)["severity"] == "low"

    def test_all_valid_categories_accepted(self):
        for cat in cti_bot.VALID_CATEGORIES:
            d = self._valid()
            d["category"] = cat
            assert cti_bot.validate_classification(d)["category"] == cat

    def test_all_valid_severities_accepted(self):
        for sev in ("high", "medium", "low"):
            d = self._valid()
            d["severity"] = sev
            assert cti_bot.validate_classification(d)["severity"] == sev

    def test_sme_relevant_int_coerced_to_bool(self):
        d = self._valid()
        d["sme_relevant"] = 1
        assert cti_bot.validate_classification(d)["sme_relevant"] is True

    def test_sme_relevant_zero_coerced_to_false(self):
        d = self._valid()
        d["sme_relevant"] = 0
        assert cti_bot.validate_classification(d)["sme_relevant"] is False

    def test_missing_keys_raise_value_error(self):
        with pytest.raises(ValueError):
            cti_bot.validate_classification({"category": "malware"})

    def test_sme_reason_truncated_to_200(self):
        d = self._valid()
        d["sme_reason"] = "x" * 300
        assert len(cti_bot.validate_classification(d)["sme_reason"]) == 200

    def test_summary_truncated_to_400(self):
        d = self._valid()
        d["summary"] = "y" * 500
        assert len(cti_bot.validate_classification(d)["summary"]) == 400


# ── get_priority ───────────────────────────────────────────────

class TestGetPriority:
    def _item(self, severity: str, sme_relevant: bool) -> dict:
        return {"severity": severity, "sme_relevant": sme_relevant}

    def test_high_and_sme_is_p1(self):
        assert cti_bot.get_priority(self._item("high", True)) == 1

    def test_high_not_sme_is_p2(self):
        assert cti_bot.get_priority(self._item("high", False)) == 2

    def test_medium_and_sme_is_p2(self):
        assert cti_bot.get_priority(self._item("medium", True)) == 2

    def test_medium_not_sme_is_p3(self):
        assert cti_bot.get_priority(self._item("medium", False)) == 3

    def test_low_with_sme_not_sent(self):
        assert cti_bot.get_priority(self._item("low", True)) == 0

    def test_low_without_sme_not_sent(self):
        assert cti_bot.get_priority(self._item("low", False)) == 0


# ── clean_text / HTML entity decoding ─────────────────────────

class TestCleanText:
    def test_question_mark_entity(self):
        assert cti_bot.clean_text("Secret Codes&#x3f;") == "Secret Codes?"

    def test_left_curly_quote(self):
        assert cti_bot.clean_text("&#8220;high paying&#8221;") == "“high paying”"

    def test_ampersand_entity(self):
        assert cti_bot.clean_text("R&amp;D") == "R&D"

    def test_less_than_entity(self):
        assert cti_bot.clean_text("a &lt; b") == "a < b"

    def test_no_entities_unchanged(self):
        assert cti_bot.clean_text("plain text") == "plain text"

    def test_strips_leading_trailing_whitespace(self):
        assert cti_bot.clean_text("  hello  ") == "hello"

    def test_combined_entity_and_whitespace(self):
        assert cti_bot.clean_text("  Title&#x3f;  ") == "Title?"


# ── get_cis_controls ──────────────────────────────────────────

class TestGetCisControls:
    def test_known_category_returns_controls(self):
        controls = cti_bot.get_cis_controls("ransomware")
        assert len(controls) > 0
        assert all(isinstance(c, tuple) and len(c) == 2 for c in controls)

    def test_unknown_category_falls_back_to_other(self):
        controls = cti_bot.get_cis_controls("nonexistent")
        assert controls == cti_bot.CIS_MAPPING["other"]

    def test_all_categories_have_controls(self):
        for cat in cti_bot.CIS_MAPPING:
            assert len(cti_bot.get_cis_controls(cat)) > 0
