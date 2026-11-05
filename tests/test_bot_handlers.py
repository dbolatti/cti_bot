"""Tests para bot_handlers — lógica pura de comandos y filtrado de usuario.

Run with: python -m pytest tests/test_bot_handlers.py -v
"""
import os
import sys
import sqlite3
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import bot_handlers as bh


# ── Fixture de BD en memoria ──────────────────────────────────────────────
def _make_test_db():
    """Crea una BD SQLite en memoria con esquema completo de test."""
    con = sqlite3.connect(":memory:")
    con.execute("""
        CREATE TABLE user_config (
            chat_id            TEXT PRIMARY KEY,
            notify_mode        TEXT DEFAULT 'realtime',
            notify_detail      TEXT DEFAULT 'compact',
            priority_max       INTEGER DEFAULT 2,
            sme_only           INTEGER DEFAULT 0,
            categories         TEXT DEFAULT '',
            updated_at         TEXT,
            last_daily_summary TEXT DEFAULT '',
            sectors            TEXT DEFAULT 'all',
            min_severity       TEXT DEFAULT 'HIGH',
            followed_actors    TEXT DEFAULT ''
        )
    """)
    con.execute("""
        CREATE TABLE items (
            id           TEXT PRIMARY KEY,
            title        TEXT,
            source       TEXT,
            category     TEXT,
            severity     TEXT,
            sme_flag     INTEGER,
            sme_reason   TEXT,
            cis_controls TEXT,
            summary      TEXT,
            ts           TEXT,
            critical_sector TEXT,
            incident_severity TEXT,
            threat_actor TEXT,
            sector_evidence TEXT,
            link         TEXT DEFAULT '',
            desc         TEXT DEFAULT '',
            sme_relevant INTEGER DEFAULT 0
        )
    """)
    con.commit()
    return con


def _insert_test_items(con):
    """Inserta datos de prueba en items."""
    # Usar timestamp reciente (hoy) para que pase el filtro de 7d
    now = datetime.now(timezone.utc).isoformat()
    items = [
        ("1", "Ransomware en Banco X", "Ransomware.live", "ransomware", "high",
         1, "CIS-13.1...", '["CIS-8.1"]', "Resumen 1", now,
         "financiero", "CRITICAL", "lockbit", "Banking", "https://example.com/1", "Desc 1", 1),
        ("2", "Ataque a Ministerio de Salud", "Ransomware.live", "ransomware", "high",
         1, "CIS-13.1...", '["CIS-8.1"]', "Resumen 2", now,
         "gobierno", "CRITICAL", "blackcat", "Ministerio", "https://example.com/2", "Desc 2", 1),
        ("3", "CVE-2024-1234 explotada", "CISA KEV", "vulnerability", "high",
         1, "CIS-7.3...", '["CIS-7.3"]', "Resumen 3", now,
         None, "HIGH", None, None, "https://example.com/3", "Desc 3", 1),
        ("4", "Phishing genérico", "BleepingComputer", "phishing", "medium",
         0, "CIS-9.2...", '["CIS-9.2"]', "Resumen 4", now,
         None, "MEDIUM", None, None, "https://example.com/4", "Desc 4", 0),
    ]
    for item in items:
        con.execute("""
            INSERT INTO items (id, title, source, category, severity, sme_flag,
                              sme_reason, cis_controls, summary, ts,
                              critical_sector, incident_severity, threat_actor, sector_evidence,
                              link, desc, sme_relevant)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, item)
    con.commit()


class TestUserConfig:
    def test_get_user_config_creates_defaults(self):
        con = _make_test_db()
        cfg = bh.get_user_config(con, "12345")
        assert cfg["chat_id"] == "12345"
        assert cfg["notify_mode"] == "realtime"
        assert cfg["sectors"] == "all"
        assert cfg["min_severity"] == "HIGH"
        assert cfg["followed_actors"] == ""

    def test_save_and_get_user_config(self):
        con = _make_test_db()
        bh.save_user_config(con, "12345", sectors="finance,gov", min_severity="CRITICAL")
        cfg = bh.get_user_config(con, "12345")
        assert cfg["sectors"] == "finance,gov"
        assert cfg["min_severity"] == "CRITICAL"

    def test_migrate_schema_idempotent(self):
        con = _make_test_db()
        # Ejecutar migración varias veces no debe fallar
        bh.migrate_user_config_schema(con)
        bh.migrate_user_config_schema(con)
        # Verificar que las columnas existen
        cols = [r[1] for r in con.execute("PRAGMA table_info(user_config)").fetchall()]
        assert "sectors" in cols
        assert "min_severity" in cols
        assert "followed_actors" in cols


class TestParseCSV:
    def test_parse_csv_list_basic(self):
        assert bh._parse_csv_list("a,b,c") == ["a", "b", "c"]
        assert bh._parse_csv_list(" a , b , c ") == ["a", "b", "c"]

    def test_parse_csv_list_dedupes(self):
        assert bh._parse_csv_list("a,b,a") == ["a", "b"]

    def test_parse_csv_list_empty(self):
        assert bh._parse_csv_list("") == []
        assert bh._parse_csv_list("   ") == []


class TestSectorMatching:
    def _item(self, sector: str | None, severity: str = "CRITICAL", actor: str | None = None):
        return {
            "critical_sector": sector,
            "incident_severity": severity,
            "threat_actor": actor,
            "category": "ransomware",
            "severity": "high",
            "sme_relevant": True,
        }

    def test_matches_all_sectors(self):
        item = self._item("financiero")
        assert bh._matches_sector(item, ["all"]) is True
        assert bh._matches_sector(item, []) is True

    def test_matches_specific_sector(self):
        item = self._item("financiero")
        assert bh._matches_sector(item, ["finance"]) is True
        assert bh._matches_sector(item, ["gov"]) is False

    def test_gobierno_sector(self):
        item = self._item("gobierno")
        assert bh._matches_sector(item, ["gov"]) is True
        assert bh._matches_sector(item, ["finance"]) is False

    def test_no_sector_no_match(self):
        item = self._item(None)
        assert bh._matches_sector(item, ["finance"]) is False


class TestSeverityMatching:
    def _item(self, severity: str):
        return {"incident_severity": severity, "severity": "high"}

    def test_critical_meets_high(self):
        assert bh._matches_severity(self._item("CRITICAL"), "HIGH") is True

    def test_high_meets_high(self):
        assert bh._matches_severity(self._item("HIGH"), "HIGH") is True

    def test_medium_below_high(self):
        assert bh._matches_severity(self._item("MEDIUM"), "HIGH") is False

    def test_low_below_medium(self):
        assert bh._matches_severity(self._item("LOW"), "MEDIUM") is False

    def test_case_insensitive(self):
        assert bh._matches_severity(self._item("critical"), "high") is True


class TestActorMatching:
    def _item(self, actor: str | None):
        return {"threat_actor": actor}

    def test_no_filter_passes_all(self):
        assert bh._matches_actor(self._item("lockbit"), []) is True
        assert bh._matches_actor(self._item(None), []) is True

    def test_matches_followed_actor(self):
        assert bh._matches_actor(self._item("lockbit"), ["lockbit", "akira"]) is True

    def test_no_match_when_not_followed(self):
        assert bh._matches_actor(self._item("lockbit"), ["akira"]) is False

    def test_case_insensitive(self):
        assert bh._matches_actor(self._item("LockBit"), ["lockbit"]) is True


class TestShouldNotifyUser:
    def _base_cfg(self, **overrides):
        base = {
            "sme_only": 0,
            "categories": "",
            "priority_max": 3,
            "sectors": "all",
            "min_severity": "HIGH",
            "followed_actors": "",
        }
        base.update(overrides)
        return base

    def _item(self, sector=None, severity="CRITICAL", actor=None, category="ransomware", sme_relevant=True):
        return {
            "critical_sector": sector,
            "incident_severity": severity,
            "threat_actor": actor,
            "category": category,
            "severity": "high" if severity in ("CRITICAL", "HIGH") else "medium",
            "sme_relevant": sme_relevant,
        }

    def test_all_defaults_pass(self):
        cfg = self._base_cfg()
        item = self._item("financiero", "CRITICAL")
        assert bh.should_notify_user(item, cfg) is True

    def test_sector_filter_blocks(self):
        cfg = self._base_cfg(sectors="finance")
        item = self._item("gobierno", "CRITICAL")
        assert bh.should_notify_user(item, cfg) is False

    def test_sector_filter_allows(self):
        cfg = self._base_cfg(sectors="finance")
        item = self._item("financiero", "CRITICAL")
        assert bh.should_notify_user(item, cfg) is True

    def test_min_severity_blocks(self):
        cfg = self._base_cfg(min_severity="CRITICAL")
        item = self._item("financiero", "HIGH")
        assert bh.should_notify_user(item, cfg) is False

    def test_min_severity_allows(self):
        cfg = self._base_cfg(min_severity="HIGH")
        item = self._item("financiero", "CRITICAL")
        assert bh.should_notify_user(item, cfg) is True

    def test_actor_filter_blocks(self):
        cfg = self._base_cfg(followed_actors="lockbit")
        item = self._item("financiero", "CRITICAL", actor="akira")
        assert bh.should_notify_user(item, cfg) is False

    def test_actor_filter_allows(self):
        cfg = self._base_cfg(followed_actors="lockbit,akira")
        item = self._item("financiero", "CRITICAL", actor="lockbit")
        assert bh.should_notify_user(item, cfg) is True

    def test_priority_max_blocks(self):
        cfg = self._base_cfg(priority_max=1)  # solo P1
        # item con severity=high y sme_relevant=True -> P1
        # pero si sme_relevant=False -> P2
        item = self._item("financiero", "HIGH", sme_relevant=False)
        assert bh.should_notify_user(item, cfg) is False

    def test_category_filter_blocks(self):
        cfg = self._base_cfg(categories="ransomware")
        item = self._item("financiero", "CRITICAL", category="phishing")
        assert bh.should_notify_user(item, cfg) is False

    def test_sme_only_blocks(self):
        cfg = self._base_cfg(sme_only=1)
        item = self._item("financiero", "CRITICAL", sme_relevant=False)
        assert bh.should_notify_user(item, cfg) is False


class TestCommands:
    def test_cmd_help_returns_string(self):
        msg = bh.cmd_help()
        assert isinstance(msg, str)
        assert "/config" in msg
        assert "/search" in msg

    def test_cmd_start_returns_welcome(self):
        msg = bh.cmd_start()
        assert "Bienvenido" in msg

    def test_cmd_config_shows_defaults(self):
        con = _make_test_db()
        msg = bh.cmd_config(con, "999")
        assert "Sectores: `all`" in msg
        assert "Severidad mín: `HIGH`" in msg

    def test_cmd_set_sector_valid(self):
        con = _make_test_db()
        msg = bh.cmd_set_sector(con, "111", "finance,gov")
        assert "✅" in msg
        cfg = bh.get_user_config(con, "111")
        assert cfg["sectors"] == "finance,gov"

    def test_cmd_set_sector_all_normalizes(self):
        con = _make_test_db()
        msg = bh.cmd_set_sector(con, "111", "all,finance")
        cfg = bh.get_user_config(con, "111")
        assert cfg["sectors"] == "all"

    def test_cmd_set_sector_invalid(self):
        con = _make_test_db()
        msg = bh.cmd_set_sector(con, "111", "invalid")
        assert "❌" in msg

    def test_cmd_set_severity_valid(self):
        con = _make_test_db()
        msg = bh.cmd_set_severity(con, "111", "CRITICAL")
        assert "✅" in msg
        cfg = bh.get_user_config(con, "111")
        assert cfg["min_severity"] == "CRITICAL"

    def test_cmd_follow_adds_actor(self):
        con = _make_test_db()
        msg = bh.cmd_follow(con, "111", "lockbit")
        assert "✅" in msg
        cfg = bh.get_user_config(con, "111")
        assert "lockbit" in cfg["followed_actors"]

    def test_cmd_follow_duplicate(self):
        con = _make_test_db()
        bh.cmd_follow(con, "111", "lockbit")
        msg = bh.cmd_follow(con, "111", "lockbit")
        assert "ℹ️" in msg

    def test_cmd_unfollow_removes_actor(self):
        con = _make_test_db()
        bh.cmd_follow(con, "111", "lockbit")
        msg = bh.cmd_unfollow(con, "111", "lockbit")
        assert "✅" in msg
        cfg = bh.get_user_config(con, "111")
        assert "lockbit" not in cfg["followed_actors"]

    def test_cmd_follow_list_empty(self):
        con = _make_test_db()
        msg = bh.cmd_follow_list(con, "111")
        assert "No sigues" in msg

    def test_cmd_follow_list_shows(self):
        con = _make_test_db()
        bh.cmd_follow(con, "111", "lockbit")
        bh.cmd_follow(con, "111", "akira")
        msg = bh.cmd_follow_list(con, "111")
        assert "lockbit" in msg
        assert "akira" in msg


class TestSearchStatsActorExport:
    def setup_method(self):
        self.con = _make_test_db()
        _insert_test_items(self.con)

    def test_cmd_search_finds_results(self):
        msg = bh.cmd_search(self.con, "Banco")
        assert "Banco X" in msg
        assert "🔍" in msg

    def test_cmd_search_no_results(self):
        msg = bh.cmd_search(self.con, "inexistente123")
        assert "Sin resultados" in msg

    def test_cmd_stats_24h(self):
        msg = bh.cmd_stats(self.con, "24h")
        assert "Estadísticas" in msg
        assert "Total incidentes" in msg

    def test_cmd_actor_found(self):
        msg = bh.cmd_actor(self.con, "lockbit")
        assert "lockbit" in msg
        assert "Banco X" in msg

    def test_cmd_actor_not_found(self):
        msg = bh.cmd_actor(self.con, "unknown")
        assert "Sin registros" in msg

    def test_cmd_export_returns_csv(self):
        msg, csv_bytes = bh.cmd_export(self.con, "7d")
        assert "Exportación" in msg
        assert len(csv_bytes) > 0
        # Verificar que es CSV válido
        text = csv_bytes.decode("utf-8")
        lines = text.strip().split("\n")
        assert lines[0].startswith("ID,Título")
        assert len(lines) == 5  # header + 4 items


# ── Tests de integración con cti_bot.get_priority (legacy) ────────────────
class TestLegacyCompatibility:
    def test_priority_max_respected(self):
        con = _make_test_db()
        _insert_test_items(con)
        cfg = bh.get_user_config(con, "111")
        cfg["priority_max"] = 1  # solo P1

        # Item ransomware HIGH + sme_relevant=True -> P1
        item = {
            "critical_sector": "financiero",
            "incident_severity": "HIGH",
            "threat_actor": "lockbit",
            "category": "ransomware",
            "severity": "high",
            "sme_relevant": True,
        }
        assert bh.should_notify_user(item, cfg) is True

        # Item phishing MEDIUM + sme_relevant=False -> P3
        item2 = {
            "critical_sector": None,
            "incident_severity": "MEDIUM",
            "threat_actor": None,
            "category": "phishing",
            "severity": "medium",
            "sme_relevant": False,
        }
        assert bh.should_notify_user(item2, cfg) is False


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])