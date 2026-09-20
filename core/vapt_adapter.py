"""
VAPT Adapter: Bridges Offensive Security & DAST Findings into Fusion Schemas.
Integrates telemetry from secure-web-vapt-lab into the enterprise triage pipeline.
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any

# Add the submodule script path dynamically
BASE_DIR = Path(__file__).resolve().parent.parent
VAPT_REPO_PATH = BASE_DIR / "projects" / "secure-web-vapt-lab"
VAPT_SCRIPTS_PATH = VAPT_REPO_PATH / "scripts"

if str(VAPT_SCRIPTS_PATH) not in sys.path:
    sys.path.insert(0, str(VAPT_SCRIPTS_PATH))

from core.schemas import FusionAlert, AssetVulnerabilityProfile


class VAPTAdapter:
    """
    Ingests and normalizes web application vulnerability telemetry from secure-web-vapt-lab.
    Applies heuristic false-positive elimination and models asset vulnerability posture.
    """

    CONFIRMED_MANUAL_VULNS = [
        {
            "id": "VULN-01",
            "name": "Authentication Bypass via SQL Injection",
            "severity": "Critical",
            "cvss": 9.8,
            "host": "127.0.0.1",
            "port": 3000,
            "path": "/rest/user/login",
            "evidence": "Payload: ' OR 1=1-- bypassed authentication into admin@juice-sh.op",
            "cwe_id": "CWE-89",
            "is_critical_fmi": True
        },
        {
            "id": "VULN-02",
            "name": "Sensitive Internal API Exposure",
            "severity": "High",
            "cvss": 7.5,
            "host": "127.0.0.1",
            "port": 3000,
            "path": "/api/Challenges",
            "evidence": "Unauthenticated access exposed full internal challenge state & solutions",
            "cwe_id": "CWE-200",
            "is_critical_fmi": True
        },
        {
            "id": "VULN-03",
            "name": "Overly Permissive CORS Misconfiguration",
            "severity": "Medium",
            "cvss": 6.5,
            "host": "127.0.0.1",
            "port": 3000,
            "path": "/rest/products/search",
            "evidence": "Access-Control-Allow-Origin: * allows cross-origin data theft",
            "cwe_id": "CWE-942",
            "is_critical_fmi": False
        }
    ]

    def __init__(self):
        self.asset_profiles: Dict[str, AssetVulnerabilityProfile] = {}
        self._init_vapt_parser()

    def _init_vapt_parser(self):
        """Attempts to dynamically import helper functions from secure-web-vapt-lab."""
        try:
            import parse_zap_findings as zap_parser
            self.zap_parser = zap_parser
        except ImportError:
            self.zap_parser = None

    def ingest_findings(self) -> Tuple[List[FusionAlert], Dict[str, AssetVulnerabilityProfile]]:
        """
        Executes heuristic triage on ZAP scanner findings and merges confirmed manual vulnerabilities.
        Returns normalized FusionAlert objects and populated AssetVulnerabilityProfiles.
        """
        alerts: List[FusionAlert] = []
        self.asset_profiles.clear()

        # 1. Process Manual Confirmed Findings
        for item in self.CONFIRMED_MANUAL_VULNS:
            asset_key = f"{item['host']}:{item['port']}"
            if asset_key not in self.asset_profiles:
                self.asset_profiles[asset_key] = AssetVulnerabilityProfile(
                    host=item["host"],
                    port=item["port"],
                    is_critical_fmi=item["is_critical_fmi"],
                    service_name="OWASP Juice Shop / Web Application"
                )

            self.asset_profiles[asset_key].add_vulnerability(
                vuln_id=item["id"],
                name=item["name"],
                severity=item["severity"],
                cvss=item["cvss"],
                evidence=item["evidence"]
            )

            alert = FusionAlert(
                alert_id=f"FUS-{item['id']}",
                timestamp="2026-09-20T12:00:00Z",
                discipline="Cyber Security",
                rule_name=f"VAPT: {item['name']}",
                severity=item["severity"],
                source_ip="127.0.0.1",
                dest_ip=item["host"],
                dest_port=item["port"],
                target_user="web_service",
                is_critical_asset=item["is_critical_fmi"],
                cvss_score=item["cvss"],
                evidence=item["evidence"],
                mitre_technique="T1190",
                mitre_name="Exploit Public-Facing Application",
                source_module="secure-web-vapt-lab"
            )
            alerts.append(alert)

        # 2. Process Automated Scanner Findings with Heuristic Triage
        if self.zap_parser:
            raw_findings = getattr(self.zap_parser, "DEFAULT_FINDINGS", [])
            for rf in raw_findings:
                triaged = self.zap_parser.classify_finding_heuristics(rf)
                # Filter out known false positives (30% reduction)
                if triaged.get("triage_status") == "False Positive":
                    continue

                severity = triaged.get("final_risk", "Low").capitalize()
                alert = FusionAlert(
                    alert_id=f"FUS-DAST-{triaged.get('id', 'UNK')}",
                    timestamp="2026-09-20T12:05:00Z",
                    discipline="Cyber Security",
                    rule_name=f"DAST: {triaged.get('name')}",
                    severity=severity,
                    source_ip="127.0.0.1",
                    dest_ip="127.0.0.1",
                    dest_port=3000,
                    target_user="http_daemon",
                    is_critical_asset=False,
                    cvss_score=float(triaged.get("cvss_score", 3.0)),
                    evidence=triaged.get("evidence", ""),
                    mitre_technique="T1190",
                    mitre_name="Exploit Public-Facing Application",
                    source_module="secure-web-vapt-lab"
                )
                alerts.append(alert)

        return alerts, self.asset_profiles

