#!/usr/bin/env python3
"""
Interactive planning tool for security remediations.

Usage:
  python scripts/interactive_plan.py --finding-id checkmarx-001
"""

import argparse
import sys
import logging
from datetime import datetime

from src.models.finding import Finding, ScannerType
from src.agents.plan_agent import PlanAgent
from src.services.governance_logger import EvidenceCapture
from src.services.guardrails import Guardrails
from src.utils.logging import setup_logger

logger = setup_logger(__name__)

class InteractivePlanner:
    """Interactive remediation planning in VS Code terminal"""

    def __init__(self):
        self.plan_agent = PlanAgent()
        self.evidence = EvidenceCapture()
        self.guardrails = Guardrails()

    def run(self, finding: Finding):
        """Start interactive planning session"""

        print("\n" + "="*70)
        print("🤖 INTERACTIVE REMEDIATION PLANNER")
        print("="*70 + "\n")

        # Display finding
        self._display_finding(finding)

        # Generate plan with Claude reasoning
        print("\n🧠 Claude is thinking about the best approach...\n")
        workplan, session = self.plan_agent.interactive_planning_session(finding)

        # Display plan
        self._display_plan(workplan)

        # Check guardrails
        tier = workplan.metadata.get('tier', 1)
        confidence = workplan.metadata.get('confidence_score', 0.0)
        can_execute, reason = self.guardrails.check_can_execute(
            tier=tier,
            confidence_score=confidence,
            cwe_id=finding.cwe_id
        )

        print(f"\n✓ Guardrails Check: {reason}")

        # Interactive menu
        self._interactive_menu(finding, workplan, session)

    def _display_finding(self, finding: Finding):
        """Display finding details"""
        print(f"📌 FINDING DETAILS")
        print(f"   ID: {finding.finding_id}")
        print(f"   CWE: {finding.cwe_id}")
        print(f"   File: {finding.file_path}:{finding.line_number}")
        print(f"   Severity: {finding.severity}")
        print(f"   Confidence: {finding.scanner_confidence:.0%}")
        print(f"\n   Code:")
        for line in finding.code_snippet.split('\n'):
            print(f"      {line}")

    def _display_plan(self, workplan):
        """Display remediation plan"""
        print(f"📋 REMEDIATION PLAN")
        print(f"   ID: {workplan.workplan_id}")

        metadata = workplan.metadata if hasattr(workplan, 'metadata') else {}

        tier = metadata.get('tier', 1)
        confidence = metadata.get('confidence_score', 0.0)
        reasoning = metadata.get('reasoning', '')

        print(f"   Tier: {tier} {'(Auto-Fixable)' if tier == 1 else '(Requires Review)' if tier == 2 else '(Architectural)'}")
        print(f"   Confidence: {confidence:.0%}")
        print(f"   Time: ~{workplan.total_estimated_time} minutes")
        print(f"   Approval: {', '.join(workplan.approval_chain)}")

        if reasoning:
            print(f"\n   💡 Claude's Reasoning:")
            for line in reasoning.split('\n')[:5]:  # First 5 lines
                if line.strip():
                    print(f"      {line}")

        print(f"\n   Phases:")
        for phase in workplan.phases:
            print(f"      {phase.step_number}. {phase.description} (~{phase.estimated_time_minutes}min)")

    def _interactive_menu(self, finding: Finding, workplan, session):
        """Interactive menu for user decisions"""

        while True:
            print(f"\n📖 WHAT WOULD YOU LIKE TO DO?")
            print(f"   1) Approve and execute")
            print(f"   2) Ask Claude a question")
            print(f"   3) Request changes to plan")
            print(f"   4) Escalate for human review")
            print(f"   5) Cancel/Exit")

            choice = input(f"\n   Your choice (1-5): ").strip()

            if choice == "1":
                self._approve_and_execute(finding, workplan)
                break

            elif choice == "2":
                question = input(f"   Your question: ").strip()
                if question:
                    answer = self.plan_agent.ask_followup(finding, question, session)
                    print(f"\n   Claude: {answer}\n")

            elif choice == "3":
                request = input(f"   What should change: ").strip()
                print(f"   [Claude would regenerate plan with your changes]")

            elif choice == "4":
                print(f"   ✅ Escalated for human review")
                break

            elif choice == "5":
                print(f"   Cancelled")
                break

    def _approve_and_execute(self, finding: Finding, workplan):
        """Approve and record evidence"""
        print(f"\n✅ APPROVED FOR EXECUTION")

        # Record evidence
        evidence = self.evidence.record_remediation(
            finding_id=finding.finding_id,
            remediation_id=f"rem-{finding.finding_id}",
            policy_applied="cwe_89_sqli.md",
            policy_version="2.1",
            tier=workplan.metadata.get('tier', 1),
            code_before=finding.code_snippet,
            code_after="[To be generated]",
            model_used="claude-sonnet-4.6",
            confidence_score=workplan.metadata.get('confidence_score', 0.0),
            tests_passed=False,  # Will be determined during execution
            sast_passed=False,   # Will be determined during execution
            approval_chain=workplan.approval_chain,
            approval_by=input("Approved by (name): ").strip()
        )

        print(f"   Evidence ID: {evidence['metadata']['remediation_id']}")
        print(f"   [Proceeding to execution phase...]")


def main():
    parser = argparse.ArgumentParser(description="Interactive Remediation Planner")
    parser.add_argument("--finding-id", required=True, help="Finding ID")
    args = parser.parse_args()

    # Create a test finding (in production, load from database)
    finding = Finding(
        finding_id=args.finding_id,
        cwe_id=89,
        severity="CRITICAL",
        cvss_score=9.0,
        file_path="auth/login.py",
        line_number=45,
        code_snippet='query = f"SELECT * FROM users WHERE id={user_id}"',
        scanner=ScannerType.CHECKMARX,
        scanner_rule_id="sqli-001",
        scanner_confidence=0.98,
        title="SQL Injection",
        description="User input in SQL",
        repo_name="juice-shop",
        branch="main",
        found_at=datetime.now()
    )

    planner = InteractivePlanner()
    planner.run(finding)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
