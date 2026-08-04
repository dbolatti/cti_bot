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


# ── build_correlation_index / find_cve_correlations ────────────

class TestCorrelation:
    def _entry(self, source: str, title: str, desc: str = "") -> dict:
        return {"id": "x", "title": title, "desc": desc, "source": source, "link": ""}

    def test_index_picks_up_cve_from_cisa_kev(self):
        entries = [self._entry("CISA KEV", "CVE-2024-3400 — Pan-OS RCE")]
        index = cti_bot.build_correlation_index(entries)
        assert "CVE-2024-3400" in index["cve_sources"]

    def test_index_picks_up_cve_from_epss(self):
        entries = [self._entry("EPSS/FIRST", "CVE-2024-3400 — Pan-Os · EPSS 100.0%")]
        index = cti_bot.build_correlation_index(entries)
        assert "CVE-2024-3400" in index["cve_sources"]

    def test_index_ignores_cve_from_regular_rss(self):
        entries = [self._entry("BleepingComputer", "Ataques explotan CVE-2024-3400 en la naturaleza")]
        index = cti_bot.build_correlation_index(entries)
        assert index["cve_sources"] == {}

    def test_index_merges_sources_for_same_cve(self):
        entries = [
            self._entry("CISA KEV", "CVE-2024-3400 — Pan-OS RCE"),
            self._entry("EPSS/FIRST", "CVE-2024-3400 — Pan-Os · EPSS 100.0%"),
        ]
        index = cti_bot.build_correlation_index(entries)
        assert index["cve_sources"]["CVE-2024-3400"] == {"CISA KEV", "EPSS/FIRST"}

    def test_find_correlation_match(self):
        index = {"cve_sources": {"CVE-2024-3400": {"CISA KEV"}}}
        matches = cti_bot.find_cve_correlations(
            "Atacantes explotan CVE-2024-3400 activamente", index
        )
        assert matches == [("CVE-2024-3400", "CISA KEV")]

    def test_find_correlation_no_match(self):
        index = {"cve_sources": {"CVE-2024-3400": {"CISA KEV"}}}
        matches = cti_bot.find_cve_correlations("Noticia sin CVEs conocidos", index)
        assert matches == []

    def test_find_correlation_case_insensitive(self):
        index = {"cve_sources": {"CVE-2024-3400": {"CISA KEV"}}}
        matches = cti_bot.find_cve_correlations("se explota cve-2024-3400 en la naturaleza", index)
        assert matches == [("CVE-2024-3400", "CISA KEV")]

    def test_find_correlation_deduplicates_repeated_mentions(self):
        index = {"cve_sources": {"CVE-2024-3400": {"CISA KEV"}}}
        matches = cti_bot.find_cve_correlations(
            "CVE-2024-3400 es grave. Ver también CVE-2024-3400.", index
        )
        assert matches == [("CVE-2024-3400", "CISA KEV")]

    def test_find_correlation_multiple_different_cves(self):
        index = {
            "cve_sources": {
                "CVE-2024-3400": {"CISA KEV"},
                "CVE-2023-4966": {"EPSS/FIRST"},
            }
        }
        matches = cti_bot.find_cve_correlations(
            "Reporte cubre CVE-2024-3400 y CVE-2023-4966", index
        )
        assert set(matches) == {("CVE-2024-3400", "CISA KEV"), ("CVE-2023-4966", "EPSS/FIRST")}


# ── extract_iocs / find_ioc_correlations ────────────────────────

class TestExtractIocs:
    def test_extracts_ipv4(self):
        assert "203.0.113.7" in cti_bot.extract_iocs("El C2 corre en 203.0.113.7 según el reporte")

    def test_extracts_ipv4_with_port_strips_port(self):
        found = cti_bot.extract_iocs("Beacon hacia 203.0.113.7:8080 cada 60s")
        assert "203.0.113.7" in found
        assert "203.0.113.7:8080" not in found

    def test_rejects_invalid_ipv4_octets(self):
        assert cti_bot.extract_iocs("version 999.999.999.999 no es una IP") == set()

    def test_extracts_domain(self):
        found = cti_bot.extract_iocs("El dominio malicioso xxquzmb.leschatroom.com sirve el payload")
        assert "xxquzmb.leschatroom.com" in found

    def test_extracts_domain_case_insensitive_normalized_lowercase(self):
        found = cti_bot.extract_iocs("Dominio EVIL-DOMAIN.COM detectado")
        assert "evil-domain.com" in found

    def test_extracts_sha256_hash(self):
        h = "a" * 64
        assert h in cti_bot.extract_iocs(f"Hash del payload: {h}")

    def test_extracts_md5_hash(self):
        h = "b" * 32
        assert h in cti_bot.extract_iocs(f"MD5: {h}")

    def test_no_iocs_in_plain_text(self):
        assert cti_bot.extract_iocs("Texto sin ningún indicador técnico") == set()

    def test_extracts_from_url(self):
        found = cti_bot.extract_iocs("URL: http://218.29.22.30:49264/bin.sh | Tags: sin tags")
        assert "218.29.22.30" in found


class TestFindIocCorrelations:
    def _entry(self, source: str, title: str, desc: str = "") -> dict:
        return {"id": "x", "title": title, "desc": desc, "source": source, "link": ""}

    def test_index_picks_up_domain_from_threatfox(self):
        entries = [self._entry(
            "Abuse.ch ThreatFox",
            "IOC activo (domain) — Vidar",
            "IOC: evil-domain.com | Tipo: Domain used for C2 | Malware: Vidar | Confianza: 100%",
        )]
        index = cti_bot.build_correlation_index(entries)
        assert "evil-domain.com" in index["ioc_sources"]

    def test_index_picks_up_ip_from_urlhaus(self):
        entries = [self._entry(
            "Abuse.ch URLhaus",
            "URL maliciosa activa — malware_download",
            "URL: http://203.0.113.7/payload.exe | Tags: sin tags",
        )]
        index = cti_bot.build_correlation_index(entries)
        assert "203.0.113.7" in index["ioc_sources"]

    def test_index_ignores_iocs_from_regular_rss(self):
        entries = [self._entry("BleepingComputer", "Investigadores rastrean C2 en evil-domain.com")]
        index = cti_bot.build_correlation_index(entries)
        assert index["ioc_sources"] == {}

    def test_find_correlation_match(self):
        index = {"cve_sources": {}, "ioc_sources": {"evil-domain.com": {"Abuse.ch ThreatFox"}}}
        matches = cti_bot.find_ioc_correlations(
            "La campaña usa el dominio evil-domain.com para C2", index
        )
        assert matches == [("evil-domain.com", "Abuse.ch ThreatFox")]

    def test_find_correlation_no_match(self):
        index = {"cve_sources": {}, "ioc_sources": {"evil-domain.com": {"Abuse.ch ThreatFox"}}}
        matches = cti_bot.find_ioc_correlations("Noticia sin IOCs conocidos", index)
        assert matches == []

    def test_find_correlation_case_insensitive(self):
        index = {"cve_sources": {}, "ioc_sources": {"evil-domain.com": {"Abuse.ch ThreatFox"}}}
        matches = cti_bot.find_ioc_correlations("Dominio EVIL-DOMAIN.COM usado como C2", index)
        assert matches == [("evil-domain.com", "Abuse.ch ThreatFox")]


# ── find_ransomware_group_correlations ──────────────────────────

class TestFindRansomwareGroupCorrelations:
    def _entry(self, source: str, title: str, desc: str = "") -> dict:
        return {"id": "x", "title": title, "desc": desc, "source": source, "link": ""}

    def test_index_picks_up_group_from_ransomware_live(self):
        entries = [self._entry(
            "Ransomware.live",
            "Víctima ransomware: Acme Corp — dragonforce",
            "Grupo: dragonforce | Sector: Manufacturing | País: US | Datos exfiltrados",
        )]
        index = cti_bot.build_correlation_index(entries)
        assert "dragonforce" in index["ransomware_groups"]

    def test_index_ignores_groups_from_regular_rss(self):
        entries = [self._entry("BleepingComputer", "Ataque atribuido a dragonforce")]
        index = cti_bot.build_correlation_index(entries)
        assert index["ransomware_groups"] == {}

    def test_index_discards_short_group_names(self):
        entries = [self._entry(
            "Ransomware.live",
            "Víctima ransomware: Acme Corp — abc",
            "Grupo: abc | Sector: N/A | País: N/A | ",
        )]
        index = cti_bot.build_correlation_index(entries)
        assert index["ransomware_groups"] == {}

    def test_find_correlation_match_and_title_cased(self):
        index = {"ransomware_groups": {"dragonforce": {"Ransomware.live"}}}
        matches = cti_bot.find_ransomware_group_correlations(
            "La banda dragonforce reivindica el ataque", index
        )
        assert matches == [("Dragonforce", "Ransomware.live")]

    def test_find_correlation_case_insensitive(self):
        index = {"ransomware_groups": {"dragonforce": {"Ransomware.live"}}}
        matches = cti_bot.find_ransomware_group_correlations("Grupo DRAGONFORCE activo", index)
        assert matches == [("Dragonforce", "Ransomware.live")]

    def test_find_correlation_no_match(self):
        index = {"ransomware_groups": {"dragonforce": {"Ransomware.live"}}}
        matches = cti_bot.find_ransomware_group_correlations("Noticia sin grupos conocidos", index)
        assert matches == []

    def test_find_correlation_respects_word_boundary(self):
        index = {"ransomware_groups": {"qilin": {"Ransomware.live"}}}
        matches = cti_bot.find_ransomware_group_correlations("mención de tranqilinidad en el texto", index)
        assert matches == []
