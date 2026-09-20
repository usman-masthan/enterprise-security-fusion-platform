"""
Unified Security Fusion Orchestrator:
Orchestrates Offensive VAPT, Network Anomaly Detection (NDR), and SOC Triage.
Produces unified Splunk CIM events, auditable CSV logs, and executive analytics.
"""

import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent
SOC_REPO_PATH = BASE_DIR / "projects" / "agentic-soc-triage"

if str(SOC_REPO_PATH) not in sys.path:
    sys.path.insert(0, str(SOC_REPO_PATH))

from core.schemas import FusionAlert
from core.vapt_adapter import VAPTAdapter
from core.ids_adapter import IDSAdapter
from core.correlation_engine import CrossCorrelationEngine


class FusionOrchestrator:
    """
    Master pipeline orchestrator that unifies telemetry from all three subsystems.
    """

    def __init__(self, output_dir: Path = BASE_DIR / "data" / "unified_output"):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.vapt_adapter = VAPTAdapter()
        self.ids_adapter = IDSAdapter()

    def _load_native_soc_alerts(self) -> List[FusionAlert]:
        """Loads baseline multi-discipline alerts from agentic-soc-triage sample_alerts.json."""
        soc_alerts: List[FusionAlert] = []
        sample_path = SOC_REPO_PATH / "sample_alerts.json"

        if sample_path.exists():
            try:
                with open(sample_path, "r", encoding="utf-8") as f:
                    raw_alerts = json.load(f)
                    for item in raw_alerts:
                        soc_alerts.append(FusionAlert(
                            alert_id=item.get("alert_id", "FUS-SOC-UNK"),
                            timestamp=item.get("timestamp", "2026-09-20T12:00:00Z"),
                            discipline=item.get("discipline", "General Security"),
                            rule_name=item.get("rule_name", "Unknown Detection Rule"),
                            severity=item.get("severity", "Medium").capitalize(),
                            source_ip=item.get("source_ip", "0.0.0.0"),
                            dest_ip="127.0.0.1",
                            dest_port=0,
                            target_user=item.get("target_user", "unknown"),
                            is_critical_asset=item.get("is_critical_asset", False),
                            source_module="agentic-soc-triage"
                        ))
            except Exception as e:
                print(f"[!] Warning: Could not load sample_alerts.json: {e}", file=sys.stderr)

        return soc_alerts

    def run_pipeline(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Executes end-to-end multi-project pipeline:
        1. Ingests VAPT findings & models asset vulnerability posture.
        2. Ingests NetFlow IDS anomalies with TreeSHAP explanations.
        3. Ingests native multi-discipline SOC alerts.
        4. Correlates active attacks against unpatched asset vulnerabilities.
        5. Triages and routes through agentic-soc-triage logic.
        6. Exports unified logs, insights, and Splunk CIM datasets.
        """
        print("\n" + "=" * 80)
        print("  ENTERPRISE SECURITY FUSION PLATFORM: END-TO-END PIPELINE")
        print("  Uniting: Offensive VAPT + Explainable NetFlow IDS + Agentic SOC Triage")
        print("=" * 80)

        # 1. Ingest VAPT findings
        print("\n[*] Phase 1: Ingesting Offensive VAPT telemetry from secure-web-vapt-lab...")
        vapt_alerts, asset_profiles = self.vapt_adapter.ingest_findings()
        print(f"    [+] Ingested {len(vapt_alerts)} VAPT alerts across {len(asset_profiles)} target assets.")

        # 2. Ingest IDS findings
        print("[*] Phase 2: Ingesting Network Anomalies & XAI from explainable-netflow-ids...")
        ids_alerts = self.ids_adapter.ingest_anomalies()
        print(f"    [+] Ingested {len(ids_alerts)} NetFlow anomalies with TreeSHAP explainability.")

        # 3. Ingest Native SOC alerts
        print("[*] Phase 3: Ingesting Multi-Discipline alerts from agentic-soc-triage...")
        soc_alerts = self._load_native_soc_alerts()
        print(f"    [+] Ingested {len(soc_alerts)} multi-discipline alerts (FinCrime, Physical, Threat Intel).")

        # 4. Cross-Discipline Threat Correlation
        print("[*] Phase 4: Running Cross-Discipline Threat & Vulnerability Correlation Engine...")
        all_raw_alerts = vapt_alerts + ids_alerts + soc_alerts
        correlation_engine = CrossCorrelationEngine(asset_profiles)
        correlated_alerts, compound_events = correlation_engine.correlate(all_raw_alerts)
        print(f"    [+] Evaluated {len(correlated_alerts)} alerts. Triggered {len(compound_events)} Compound Threat Escalations!")

        # 5. Execute Agentic SOC Triage
        print("[*] Phase 5: Executing Context-Aware SOC Triage & Dynamic SLA Routing...")
        raw_dict_alerts = [a.to_dict() for a in correlated_alerts]

        try:
            import triage_engine
            triaged_alerts = triage_engine.triage_alerts(raw_dict_alerts)
        except ImportError:
            # Fallback triage implementation mirroring agentic-soc-triage logic
            triaged_alerts = self._fallback_triage(raw_dict_alerts)

        # 6. Generate Operational Analytics & Metrics
        print("[*] Phase 6: Generating Executive Operational Analytics & SLA Metrics...")
        insights = self._generate_operational_insights(triaged_alerts, compound_events)

        # 7. Export Unified Artifacts
        print("[*] Phase 7: Exporting Unified Enterprise Reports...")
        self._export_artifacts(triaged_alerts, insights)

        return triaged_alerts, insights

    def _fallback_triage(self, alerts_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fallback triage adhering exactly to agentic-soc-triage rules."""
        triaged = []
        for alert in alerts_list:
            item = alert.copy()
            severity = item.get("severity", "").upper()
            is_critical = item.get("is_critical_asset", False)
            discipline = item.get("discipline", "Cyber Security")

            if severity in ["CRITICAL", "HIGH"]:
                tier = "Tier 2 (L2)"
                reason = f"High/Critical severity {discipline} event requires Tier 2 investigation."
                if is_critical:
                    reason = f"Critical FMI Asset alert ({discipline}): Immediate Tier 2 escalation."
            elif severity == "MEDIUM" and is_critical:
                tier = "Tier 2 (L2)"
                reason = f"Escalated: Medium severity {discipline} impacting critical asset."
            else:
                tier = "Tier 1 (L1)"
                reason = f"Standard baseline triage for {discipline}."

            if severity == "CRITICAL":
                sla = "15 mins"
                sla_mins = 15
            elif severity == "HIGH":
                sla = "30 mins"
                sla_mins = 30
            elif severity == "MEDIUM":
                sla = "60 mins"
                sla_mins = 60
            else:
                sla = "120 mins"
                sla_mins = 120

            item["assigned_tier"] = tier
            item["target_sla"] = sla
            item["sla_minutes"] = sla_mins
            item["triage_reason"] = reason
            triaged.append(item)
        return triaged

    def _generate_operational_insights(
        self, triaged_alerts: List[Dict[str, Any]], compound_events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculates executive SOC metrics, tier splits, and SLA commitments."""
        total = len(triaged_alerts)
        l1_count = sum(1 for a in triaged_alerts if a.get("assigned_tier") == "Tier 1 (L1)")
        l2_count = sum(1 for a in triaged_alerts if a.get("assigned_tier") == "Tier 2 (L2)")
        critical_count = sum(1 for a in triaged_alerts if a.get("severity", "").upper() == "CRITICAL")
        high_count = sum(1 for a in triaged_alerts if a.get("severity", "").upper() == "HIGH")

        sla_counts = {}
        for a in triaged_alerts:
            sla = a.get("target_sla", "120 mins")
            sla_counts[sla] = sla_counts.get(sla, 0) + 1

        module_counts = {}
        for a in triaged_alerts:
            mod = a.get("source_module", "core")
            module_counts[mod] = module_counts.get(mod, 0) + 1

        return {
            "timestamp": "2026-09-20T12:30:00Z",
            "total_alerts_ingested": total,
            "tier_distribution": {
                "Tier 1 (L1)": l1_count,
                "Tier 2 (L2)": l2_count,
                "l2_escalation_rate_pct": round((l2_count / total * 100) if total else 0, 2)
            },
            "severity_distribution": {
                "Critical": critical_count,
                "High": high_count,
                "Medium": sum(1 for a in triaged_alerts if a.get("severity", "").upper() == "MEDIUM"),
                "Low": sum(1 for a in triaged_alerts if a.get("severity", "").upper() == "LOW")
            },
            "sla_commitments": sla_counts,
            "telemetry_source_distribution": module_counts,
            "compound_threat_events": compound_events
        }

    def _export_artifacts(self, triaged_alerts: List[Dict[str, Any]], insights: Dict[str, Any]) -> None:
        """Exports JSON alerts, CSV audit logs, insights, and Splunk CIM events."""
        # 1. Export Full Enriched Alerts JSON
        alerts_json_path = self.output_dir / "unified_alerts.json"
        with open(alerts_json_path, "w", encoding="utf-8") as f:
            json.dump(triaged_alerts, f, indent=2)
        print(f"    [+] Saved Unified Alerts: {alerts_json_path}")

        # 2. Export Triage Decision Log CSV
        csv_path = self.output_dir / "triage_decision_log.csv"
        fieldnames = [
            "alert_id", "timestamp", "discipline", "rule_name", "severity",
            "assigned_tier", "target_sla", "dest_ip", "dest_port",
            "is_critical_asset", "is_compound_threat", "source_module", "triage_reason"
        ]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(triaged_alerts)
        print(f"    [+] Saved Auditable Decision Log (CSV): {csv_path}")

        # 3. Export Operational Insights JSON
        insights_path = self.output_dir / "fusion_operational_insights.json"
        with open(insights_path, "w", encoding="utf-8") as f:
            json.dump(insights, f, indent=2)
        print(f"    [+] Saved Executive Operational Insights: {insights_path}")

        # 4. Export Splunk CIM Unified Log
        splunk_path = self.output_dir / "unified_splunk_cim.json"
        splunk_events = []
        for a in triaged_alerts:
            splunk_events.append({
                "time": a.get("timestamp"),
                "category": "vulnerability" if a.get("source_module") == "secure-web-vapt-lab" else "network_traffic",
                "severity": a.get("severity", "unknown").lower(),
                "src": a.get("source_ip"),
                "dest": a.get("dest_ip"),
                "dest_port": a.get("dest_port"),
                "signature": a.get("rule_name"),
                "status": "escalated" if a.get("assigned_tier") == "Tier 2 (L2)" else "open",
                "action": "blocked" if "SYN Flood" in a.get("rule_name", "") else "allowed",
                "vendor_product": a.get("source_module"),
                "mitre_technique": a.get("mitre_technique"),
                "sla": a.get("target_sla"),
                "xai_justification": a.get("xai_explanation", "")
            })
        with open(splunk_path, "w", encoding="utf-8") as f:
            json.dump(splunk_events, f, indent=2)
        print(f"    [+] Saved Unified Splunk CIM Events: {splunk_path}")

