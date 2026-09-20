"""
Cross-Discipline Correlation Engine:
Correlates Offensive VAPT Vulnerability Intelligence with Real-Time NDR Network Anomalies.
Computes compound threat scores and triggers high-urgency FMI incident escalations.
"""

from typing import List, Dict, Tuple, Any
from core.schemas import FusionAlert, AssetVulnerabilityProfile


class CrossCorrelationEngine:
    """
    Evaluates compound risk across disparate security telemetry domains.
    Detects when an active intrusion attempt targets a known vulnerable asset.
    """

    def __init__(self, asset_profiles: Dict[str, AssetVulnerabilityProfile]):
        self.asset_profiles = asset_profiles

    def correlate(self, alerts: List[FusionAlert]) -> Tuple[List[FusionAlert], List[Dict[str, Any]]]:
        """
        Processes incoming alerts, correlates active attacks with known asset vulnerabilities,
        and generates prioritized compound incident alerts.
        """
        enriched_alerts: List[FusionAlert] = []
        compound_events: List[Dict[str, Any]] = []

        for alert in alerts:
            target_key = f"{alert.dest_ip}:{alert.dest_port}"
            profile = self.asset_profiles.get(target_key) or self.asset_profiles.get(alert.dest_ip)

            # Check if this is an active network alert targeting a vulnerable host
            if profile and alert.source_module == "explainable-netflow-ids" and profile.unpatched_vulnerabilities:
                profile.active_threat_count += 1
                vuln_summary = ", ".join([v["name"] for v in profile.unpatched_vulnerabilities])
                max_cvss = max([v["cvss"] for v in profile.unpatched_vulnerabilities])

                # Elevate severity due to compound risk
                alert.is_compound_threat = True
                alert.is_critical_asset = True
                alert.severity = "Critical"

                compound_narrative = (
                    f"COMPOUND RISK ESCALATION: Active intrusion attempt ({alert.rule_name}) "
                    f"is targeting vulnerable asset {alert.dest_ip}:{alert.dest_port}. "
                    f"Host has {len(profile.unpatched_vulnerabilities)} unpatched vulnerability(ies): [{vuln_summary}]. "
                    f"Highest asset CVSS: {max_cvss}. XAI Evidence: {alert.xai_explanation}"
                )
                alert.evidence = f"{alert.evidence} | {compound_narrative}"

                compound_events.append({
                    "compound_id": f"CMP-{alert.alert_id}",
                    "target": target_key,
                    "active_attack": alert.rule_name,
                    "target_vulns": [v["name"] for v in profile.unpatched_vulnerabilities],
                    "compound_severity": "Critical",
                    "rationale": compound_narrative
                })

            enriched_alerts.append(alert)

        return enriched_alerts, compound_events
