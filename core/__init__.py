"""
Core Integration Module for Enterprise Security Fusion Platform.
"""

from core.schemas import FusionAlert, AssetVulnerabilityProfile
from core.vapt_adapter import VAPTAdapter
from core.ids_adapter import IDSAdapter
from core.correlation_engine import CrossCorrelationEngine
from core.fusion_orchestrator import FusionOrchestrator

__all__ = [
    "FusionAlert",
    "AssetVulnerabilityProfile",
    "VAPTAdapter",
    "IDSAdapter",
    "CrossCorrelationEngine",
    "FusionOrchestrator",
]

