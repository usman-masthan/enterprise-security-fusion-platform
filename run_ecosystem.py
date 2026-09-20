#!/usr/bin/env python3
"""
Master CLI Entrypoint: Enterprise Security Fusion Platform.
Orchestrates Offensive VAPT, Explainable NetFlow IDS, and Agentic SOC Triage.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from core.fusion_orchestrator import FusionOrchestrator
from core.vapt_adapter import VAPTAdapter
from core.ids_adapter import IDSAdapter


def print_banner():
    banner = r"""
  ╔══════════════════════════════════════════════════════════════════════════════════════╗
  ║                 ENTERPRISE SECURITY OPERATIONS & FUSION CENTRE                       ║
  ║                   Converged Cyber Defense & Threat Intelligence                      ║
  ║        Offensive VAPT  ───►  Explainable NetFlow IDS  ───►  Agentic SOC Triage       ║
  ╚══════════════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def check_submodule_status():
    """Prints current commit SHAs and remote status of the 3 submodules."""
    print("\n[*] Inspecting Git Submodule Status across Ecosystem:")
    try:
        res = subprocess.run(
            ["git", "submodule", "status"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            check=True
        )
        for line in res.stdout.strip().splitlines():
            print(f"    - {line}")
    except Exception as e:
        print(f"    [!] Error checking submodule status: {e}")


def sync_submodules():
    """Updates all 3 submodules to the latest commits on their upstream main branches."""
    print("\n[*] Synchronizing Submodules to Upstream Repositories...")
    try:
        cmd = ["git", "submodule", "update", "--remote", "--merge"]
        res = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True, check=True)
        print("    [+] Submodules successfully updated!")
        if res.stdout:
            print(res.stdout)
    except subprocess.CalledProcessError as e:
        print(f"    [!] Error updating submodules: {e.stderr}", file=sys.stderr)


def display_dashboard(insights: dict):
    """Renders an executive summary dashboard in the terminal."""
    total = insights.get("total_alerts_ingested", 0)
    tiers = insights.get("tier_distribution", {})
    sevs = insights.get("severity_distribution", {})
    slas = insights.get("sla_commitments", {})
    compounds = insights.get("compound_threat_events", [])

    print("\n" + "=" * 80)
    print("                      EXECUTIVE OPERATIONAL DASHBOARD")
    print("=" * 80)
    print(f" Total Ingested Alerts : {total}")
    print(f" Tier 1 (L1) Queue     : {tiers.get('Tier 1 (L1)', 0):<5} | Standard triage & routine baseline")
    print(f" Tier 2 (L2) Queue     : {tiers.get('Tier 2 (L2)', 0):<5} | Escalated FMI & senior analyst investigation")
    print(f" Escalation Rate       : {tiers.get('l2_escalation_rate_pct', 0.0)}%")
    print("-" * 80)
    print(" SEVERITY PROFILE:")
    print(f"   - Critical : {sevs.get('Critical', 0)}")
    print(f"   - High     : {sevs.get('High', 0)}")
    print(f"   - Medium   : {sevs.get('Medium', 0)}")
    print(f"   - Low      : {sevs.get('Low', 0)}")
    print("-" * 80)
    print(" TARGET SLA COMMITMENTS:")
    for sla, count in sorted(slas.items()):
        print(f"   - {sla:<10} : {count} incidents")
    print("-" * 80)
    print(f" COMPOUND CROSS-DISCIPLINE THREATS: {len(compounds)} DETECTED")
    for idx, c in enumerate(compounds, 1):
        print(f"   [{idx}] Active Attack: {c['active_attack']} on {c['target']}")
        print(f"       Vulnerable Vectors: {', '.join(c['target_vulns'])}")
        print(f"       Action: IMMEDIATE L2 ESCALATION (15-min SLA)")
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Unified Enterprise Security Fusion Orchestrator CLI."
    )
    parser.add_argument("--all", action="store_true", help="Execute end-to-end multi-project pipeline.")
    parser.add_argument("--vapt", action="store_true", help="Ingest and view offensive VAPT telemetry.")
    parser.add_argument("--ids", action="store_true", help="Ingest and view explainable NetFlow IDS telemetry.")
    parser.add_argument("--sync", action="store_true", help="Sync all submodules to latest remote commits.")
    parser.add_argument("--status", action="store_true", help="View status and SHAs of ecosystem submodules.")

    args = parser.parse_args()
    print_banner()

    if args.status:
        check_submodule_status()
        return

    if args.sync:
        sync_submodules()
        return

    if args.vapt:
        print("[*] Ingesting Offensive VAPT telemetry...")
        adapter = VAPTAdapter()
        alerts, profiles = adapter.ingest_findings()
        print(f"[+] Loaded {len(alerts)} alerts across {len(profiles)} asset profiles.")
        for a in alerts:
            print(f"    [{a.alert_id}] {a.severity:<8} {a.rule_name} (CVSS: {a.cvss_score})")
        return

    if args.ids:
        print("[*] Ingesting Explainable NetFlow IDS telemetry...")
        adapter = IDSAdapter()
        alerts = adapter.ingest_anomalies()
        print(f"[+] Loaded {len(alerts)} network anomalies with TreeSHAP explainability.")
        for a in alerts:
            print(f"    [{a.alert_id}] {a.severity:<8} {a.rule_name}")
            print(f"         └─ {a.xai_explanation}")
        return

    # Default to running the full pipeline
    orchestrator = FusionOrchestrator()
    triaged_alerts, insights = orchestrator.run_pipeline()
    display_dashboard(insights)


if __name__ == "__main__":
    main()

