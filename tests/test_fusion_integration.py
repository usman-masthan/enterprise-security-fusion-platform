"""
Integration & Regression Test Suite for Enterprise Security Fusion Platform.
Verifies telemetry adapters, cross-discipline correlation logic, and end-to-end report generation.
"""

import json
import os
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

from core.schemas import FusionAlert, AssetVulnerabilityProfile
from core.vapt_adapter import VAPTAdapter
from core.ids_adapter import IDSAdapter
from core.correlation_engine import CrossCorrelationEngine
from core.fusion_orchestrator import FusionOrchestrator


class TestEnterpriseSecurityFusion(unittest.TestCase):
    """Verifies end-to-end integration across VAPT, IDS, and SOC Triage subsystems."""

    def setUp(self):
        self.output_dir = BASE_DIR / "data" / "test_output"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def test_vapt_adapter_ingestion(self):
        """Verifies VAPT adapter loads confirmed manual findings and eliminates false positives."""
        adapter = VAPTAdapter()
        alerts, profiles = adapter.ingest_findings()

        self.assertGreater(len(alerts), 0)
        self.assertIn("127.0.0.1:3000", profiles)

        profile = profiles["127.0.0.1:3000"]
        self.assertTrue(profile.is_critical_fmi)
        vuln_names = [v["name"] for v in profile.unpatched_vulnerabilities]
        self.assertIn("Authentication Bypass via SQL Injection", vuln_names)

        # Check CVSS 9.8 Critical SQLi alert
        sqli_alert = next((a for a in alerts if "VULN-01" in a.alert_id), None)
        self.assertIsNotNone(sqli_alert)
        self.assertEqual(sqli_alert.severity, "Critical")
        self.assertEqual(sqli_alert.cvss_score, 9.8)

    def test_ids_adapter_ingestion(self):
        """Verifies IDS adapter formats NetFlow anomalies with TreeSHAP justifications."""
        adapter = IDSAdapter()
        alerts = adapter.ingest_anomalies()

        self.assertGreater(len(alerts), 0)
        syn_flood = next((a for a in alerts if "SYN Flood" in a.rule_name), None)
        self.assertIsNotNone(syn_flood)
        self.assertEqual(syn_flood.dest_port, 3000)
        self.assertIn("TreeSHAP Drivers", syn_flood.xai_explanation)
        self.assertIn("T1498", syn_flood.mitre_technique)

    def test_cross_correlation_compound_threat(self):
        """Verifies an active network attack on a vulnerable host triggers compound escalation."""
        # Host with unpatched critical vulnerability
        profiles = {
            "127.0.0.1:3000": AssetVulnerabilityProfile(
                host="127.0.0.1",
                port=3000,
                is_critical_fmi=True,
                service_name="Trading Portal"
            )
        }
        profiles["127.0.0.1:3000"].add_vulnerability(
            vuln_id="VULN-01",
            name="SQL Injection",
            severity="Critical",
            cvss=9.8,
            evidence="Auth bypass"
        )

        # Incoming network attack
        incoming_attack = FusionAlert(
            alert_id="TEST-NET-01",
            timestamp="2026-09-20T12:00:00Z",
            discipline="Cyber Security",
            rule_name="NetFlow Port Scan",
            severity="Medium",  # Originally Medium
            source_ip="198.51.100.10",
            dest_ip="127.0.0.1",
            dest_port=3000,
            source_module="explainable-netflow-ids",
            xai_explanation="TreeSHAP: flow_duration anomaly"
        )

        engine = CrossCorrelationEngine(profiles)
        correlated, compound_events = engine.correlate([incoming_attack])

        self.assertEqual(len(correlated), 1)
        res = correlated[0]
        self.assertTrue(res.is_compound_threat)
        self.assertTrue(res.is_critical_asset)
        self.assertEqual(res.severity, "Critical")  # Promoted to Critical!
        self.assertIn("COMPOUND RISK ESCALATION", res.evidence)
        self.assertEqual(len(compound_events), 1)

    def test_fusion_orchestrator_pipeline_and_exports(self):
        """Verifies full pipeline execution and generation of all 4 enterprise reports."""
        orchestrator = FusionOrchestrator(output_dir=self.output_dir)
        triaged_alerts, insights = orchestrator.run_pipeline()

        self.assertGreater(len(triaged_alerts), 0)
        self.assertIn("total_alerts_ingested", insights)
        self.assertGreaterEqual(insights["tier_distribution"]["Tier 2 (L2)"], 1)

        # Check export files
        alerts_json = self.output_dir / "unified_alerts.json"
        csv_file = self.output_dir / "triage_decision_log.csv"
        insights_json = self.output_dir / "fusion_operational_insights.json"
        splunk_json = self.output_dir / "unified_splunk_cim.json"

        self.assertTrue(alerts_json.exists())
        self.assertTrue(csv_file.exists())
        self.assertTrue(insights_json.exists())
        self.assertTrue(splunk_json.exists())

        # Validate Splunk CIM format
        with open(splunk_json, "r", encoding="utf-8") as f:
            splunk_data = json.load(f)
            self.assertIsInstance(splunk_data, list)
            first_event = splunk_data[0]
            self.assertIn("time", first_event)
            self.assertIn("category", first_event)
            self.assertIn("severity", first_event)
            self.assertIn("signature", first_event)


if __name__ == "__main__":
    unittest.main()
