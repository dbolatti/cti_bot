"""Tests para incident_classifier.

Run with: python -m pytest tests/test_incident_classifier.py -v
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import incident_classifier as ic


class TestDetectSectorGobierno:
    def test_ministerio(self):
        assert ic.detect_sector("Ransomware golpea Ministerio de Hacienda") == ("gobierno", "Ministerio")

    def test_gob_domain(self):
        sector, ev = ic.detect_sector("Filtración en datos de argentina.gob.ar")
        assert sector == "gobierno" and "gob" in ev.lower()

    def test_gov_domain(self):
        assert ic.detect_sector("Brecha en whitehouse.gov")[0] == "gobierno"

    def test_fuerzas_de_seguridad(self):
        assert ic.detect_sector("Ataque a fuerzas de seguridad y policías")[0] == "gobierno"

    def test_municipalidad(self):
        assert ic.detect_sector("Municipalidad víctima de ransomware")[0] == "gobierno"

    def test_salud_publica(self):
        assert ic.detect_sector("Hospital público comprometido por malware")[0] == "gobierno"

    def test_gobierno_beats_financiero(self):
        # "Ministerio de Finanzas" es gobierno, no financiero
        assert ic.detect_sector("Ministerio de Finanzas sufre brecha")[0] == "gobierno"


class TestDetectSectorFinanciero:
    def test_banco(self):
        assert ic.detect_sector("Banco Central afectado por ransomware")[0] == "financiero"

    def test_bank_in_english(self):
        assert ic.detect_sector("US bank hit by LockBit affiliates")[0] == "financiero"

    def test_fintech(self):
        assert ic.detect_sector("Fintech de pagos suspende operaciones")[0] == "financiero"

    def test_pasarela_de_pago(self):
        assert ic.detect_sector("Falla en pasarela de pago de e-commerce")[0] == "financiero"

    def test_cooperativa(self):
        assert ic.detect_sector("Cooperativa de crédito víctima de filtración")[0] == "financiero"

    def test_entidad_financiera(self):
        assert ic.detect_sector("Entidad financiera reporta exfiltración")[0] == "financiero"


class TestDetectSectorNone:
    def test_no_sector_in_plain_news(self):
        assert ic.detect_sector("Nueva versión de Windows publicada")[0] is None

    def test_empty_text(self):
        assert ic.detect_sector("", "") == (None, None)

    def test_false_positive_bank_on_river(self):
        # "bank" aislado no debería matchear (regex con \b no matchea "Bank of America"? sí matchea,
        # pero no materializa sector sin fuente: el matcher con \b sí lo detecta — documentado).
        # El verdadero guardrail es descendente: no fuerza severidad si category es other.
        sector, _ = ic.detect_sector("Una mujer caminaba por el banco del río")
        # "banco" como mueble en español: el detector sí dispara; classify_incident
        # lo degrada a MEDIUM si category == "other"
        assert sector == "financiero"
        result = ic.classify_incident(
            "Una mujer caminaba por el banco del río",
            "Una mujer caminaba por el banco del río",
            category="other",
            source="BleepingComputer",
        )
        assert result["incident_severity"] == "MEDIUM"


class TestClassifySeverity:
    def test_ransomware_banco_critical(self):
        r = ic.classify_incident("Víctima ransomware: Banco X — lockbit", "desc", "ransomware", "Ransomware.live")
        assert r["incident_severity"] == "CRITICAL" and r["critical_sector"] == "financiero"

    def test_ransomware_gobierno_critical(self):
        r = ic.classify_incident("Ministerio de Hacienda víctima de ransomware", "desc", "ransomware", "Ransomware.live")
        assert r["incident_severity"] == "CRITICAL" and r["critical_sector"] == "gobierno"

    def test_ransomware_live_sin_sector_high(self):
        r = ic.classify_incident("Víctima ransomware: Acme — lockbit", "Grupo: lockbit | Sector: N/A", "ransomware", "Ransomware.live")
        assert r["incident_severity"] == "HIGH" and r["critical_sector"] is None

    def test_cisa_kev_high_baseline(self):
        r = ic.classify_incident("CVE-2024-3400 — Pan-OS RCE", "explotada activamente", "vulnerability", "CISA KEV")
        assert r["incident_severity"] == "HIGH"

    def test_cisa_kev_gobierno_ransomware_es_critical(self):
        r = ic.classify_incident("CVE-2024-3400 explotado contra ministerio de gobierno", "ransomware", "ransomware", "CISA KEV")
        assert r["incident_severity"] == "CRITICAL" and r["critical_sector"] == "gobierno"

    def test_other_sector_only_medium(self):
        r = ic.classify_incident("Ministerio de Hacienda anuncia pago de impuestos", "anuncio", "other", "BleepingComputer")
        assert r["incident_severity"] == "MEDIUM"

    def test_rss_sin_sector_ni_fuente_high_none(self):
        assert ic.classify_incident("Noticia general de tecnología", "desc", "malware", "TheHackerNews") is None

    def test_no_lanza_con_entradas_nulas(self):
        assert ic.classify_incident(None, None, None, None) is None


class TestThreatActor:
    def test_actor_from_ransomware_live_group_field(self):
        assert ic.extract_threat_actor("t", "Grupo: dragonforce | Sector: General", "Ransomware.live") == "dragonforce"

    def test_actor_short_group_discarded(self):
        assert ic.extract_threat_actor("t", "Grupo: abc | Sector: N/A", "Ransomware.live") is None

    def test_actor_attributed_to(self):
        actor = ic.extract_threat_actor("Ataque atribuido a LockBit en un banco", "", "BleepingComputer")
        assert actor is not None and "lockbit" in actor.lower()

    def test_actor_none_when_unknown(self):
        assert ic.extract_threat_actor("Banco con ransomware sin atribución", "", "BleepingComputer") is None


class TestGuessCategory:
    def test_ransomware_keyword(self):
        assert ic.guess_category("Ransomware en hospital público", "") == "ransomware"

    def test_breach_keyword(self):
        assert ic.guess_category("Filtración masiva de datos de clientes", "") == "breach"

    def test_fallback_other(self):
        assert ic.guess_category("Noticia general", "") == "other"
