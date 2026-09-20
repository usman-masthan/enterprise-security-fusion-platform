"""
Unified Schema Definitions for the Enterprise Security Fusion Platform.
Normalizes data contracts across Offensive VAPT, Network IDS (NDR), and SOC Triage.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


@dataclass
class FusionAlert:
    """
    Standardized alert representation ingested by the Fusion Core Triage Engine.
    Extends the baseline schema with cross-discipline correlation and XAI context.
    """
    alert_id: str
    timestamp: str
    discipline: str
    rule_name: str
    severity: str
    source_ip: str = "0.0.0.0"
    dest_ip: str = "127.0.0.1"
    dest_port: int = 0
    target_user: str = "system"
    is_critical_asset: bool = False
    is_compound_threat: bool = False
    cvss_score: float = 0.0
    evidence: str = ""
    mitre_technique: str = "N/A"
    mitre_name: str = "N/A"
    xai_explanation: str = ""
    source_module: str = "core"
    assigned_tier: Optional[str] = None
    target_sla: Optional[str] = None
    sla_minutes: Optional[int] = None
    triage_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converts the dataclass to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FusionAlert":
        """Instantiates a FusionAlert from a dictionary."""
        valid_keys = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class AssetVulnerabilityProfile:
    """
    Tracks confirmed security posture and known unpatched vulnerabilities
    discovered during VAPT assessments for target assets.
    """
    host: str
    port: int
    is_critical_fmi: bool
    service_name: str
    unpatched_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    active_threat_count: int = 0

    def add_vulnerability(self, vuln_id: str, name: str, severity: str, cvss: float, evidence: str) -> None:
        self.unpatched_vulnerabilities.append({
            "vuln_id": vuln_id,
            "name": name,
            "severity": severity,
            "cvss": cvss,
            "evidence": evidence
        })
