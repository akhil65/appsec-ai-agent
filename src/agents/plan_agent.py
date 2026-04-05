import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from anthropic import Anthropic

from src.models.finding import Finding
from src.models.workplan import Workplan, RemediationStep
from src.services.policy_engine import PolicyEngine
from src.utils.config import ANTHROPIC_API_KEY

logger = logging.getLogger(__name__)

class PlanAgent:
    """Generate remediation workplans using Claude reasoning (extended thinking)"""

    def __init__(self):
        self.client = Anthropic(api_key=ANTHROPIC_API_KEY)
        self.policy_engine = PolicyEngine()
        self.thinking_budget = 5000  # Token budget for Claude's thinking

    def generate_plan(self, finding: Finding) -> Workplan:
        """
        Generate a detailed remediation workplan using Claude's reasoning.

        Claude will:
        1. Analyze the vulnerability
        2. Consider the policy tier
        3. Identify potential risks
        4. Suggest the best approach
        5. Generate a detailed workplan

        Args:
            finding: The security finding

        Returns:
            Workplan with detailed remediation strategy
        """

        logger.info(f"Generating plan for {finding.finding_id} (CWE-{finding.cwe_id})")

        # Load policy for this CWE
        policy = self.policy_engine.get_policy(finding.cwe_id)
        if not policy:
            logger.warning(f"No policy for CWE-{finding.cwe_id}, using default approach")
            return self._create_default_plan(finding)

        # Build context for Claude
        context = self._build_context(finding, policy)

        # Call Claude with extended thinking
        try:
            response = self.client.messages.create(
                model="claude-opus-4-6",
                max_tokens=16000,
                thinking={
                    "type": "enabled",
                    "budget_tokens": self.thinking_budget
                },
                system="""You are an AppSec architect and remediation specialist.

Your role:
1. Analyze security vulnerabilities deeply
2. Consider organizational policies and constraints
3. Identify risks and dependencies
4. Generate detailed remediation workplans
5. Provide clear reasoning for your recommendations

Think through:
- What could go wrong with this fix?
- What dependencies might be affected?
- Is there a safer/better approach?
- What testing is critical?
- Who needs to approve this?

Generate a workplan that is:
- Safe (low risk of regression)
- Efficient (minimal token cost, clear phases)
- Compliant (follows org policies)
- Auditable (clear reasoning and evidence)

Return a JSON workplan with clear phases and reasoning.""",
                messages=[{
                    "role": "user",
                    "content": f"""
Generate a remediation workplan for this security finding:

{context}

Return a JSON object with:
{{
  "workplan_id": "generated_id",
  "cwe_id": {finding.cwe_id},
  "tier": <1-3>,
  "tier_justification": "Why this tier is appropriate",
  "risks": ["Risk 1", "Risk 2"],
  "dependencies": ["Dependency 1"],
  "phases": [
    {{
      "phase_number": 1,
      "description": "...",
      "steps": ["Step 1", "Step 2"],
      "estimated_minutes": 15,
      "validation_required": true
    }}
  ],
  "approval_chain": ["developer", "code_review"],
  "critical_notes": "Any critical considerations",
  "confidence_score": 0.95,
  "reasoning": "Your detailed reasoning"
}}
"""
                }]
            )

            # Parse Claude's response
            workplan = self._parse_response(finding, response)
            logger.info(f"✓ Plan generated: Tier {workplan.total_estimated_time} min")

            return workplan

        except Exception as e:
            logger.error(f"Failed to generate plan: {e}")
            return self._create_default_plan(finding)

    def _build_context(self, finding: Finding, policy) -> str:
        """Build context for Claude"""
        return f"""
VULNERABILITY DETAILS:
- Finding ID: {finding.finding_id}
- CWE: {finding.cwe_id}
- Severity: {finding.severity}
- CVSS Score: {finding.cvss_score}
- File: {finding.file_path}:{finding.line_number}
- Scanner: {finding.scanner}
- Confidence: {finding.scanner_confidence:.0%}

VULNERABLE CODE:
```
{finding.code_snippet}
```

ORGANIZATIONAL POLICY:
- Policy: cwe_{finding.cwe_id}_{policy.metadata.get('name', 'unknown').lower().replace(' ', '_')}.md
- Severity: {policy.metadata.get('severity', 'UNKNOWN')}
- Version: {policy.metadata.get('version', '1.0')}

REPOSITORY CONTEXT:
- Repo: {finding.repo_name}
- Branch: {finding.branch}
- Found At: {finding.found_at}
"""

    def _parse_response(self, finding: Finding, response) -> Workplan:
        """Parse Claude's response into a Workplan"""
        try:
            # Extract the text content
            content = response.content[0].text

            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{[\s\S]*\}', content)
            if not json_match:
                logger.error("Could not extract JSON from response")
                return self._create_default_plan(finding)

            plan_data = json.loads(json_match.group())

            # Convert to RemediationStep objects
            phases = []
            for i, phase in enumerate(plan_data.get('phases', []), 1):
                step = RemediationStep(
                    step_number=i,
                    description=phase.get('description', ''),
                    file_path=finding.file_path,
                    tier=plan_data.get('tier', 1),
                    estimated_time_minutes=phase.get('estimated_minutes', 15),
                    risks=phase.get('risks', [])
                )
                phases.append(step)

            # Create workplan
            workplan = Workplan(
                workplan_id=plan_data.get('workplan_id', f"plan-{finding.finding_id}"),
                finding_ids=[finding.finding_id],
                created_at=datetime.now(),
                phases=phases,
                total_estimated_time=sum(p.estimated_time_minutes for p in phases),
                approval_required=plan_data.get('tier', 1) >= 2,
                approval_chain=plan_data.get('approval_chain', ['developer']),
                validation_checkpoints=plan_data.get('validation_checkpoints', [
                    'Run existing tests',
                    'SAST re-scan',
                    'Security test (injection payload)'
                ]),
                rollback_plan="Revert commits in reverse order"
            )

            # Add metadata for tracking
            workplan.metadata = {
                'tier': plan_data.get('tier', 1),
                'confidence_score': plan_data.get('confidence_score', 0.0),
                'reasoning': plan_data.get('reasoning', ''),
                'risks': plan_data.get('risks', []),
                'dependencies': plan_data.get('dependencies', []),
                'critical_notes': plan_data.get('critical_notes', '')
            }

            return workplan

        except Exception as e:
            logger.error(f"Error parsing response: {e}")
            return self._create_default_plan(finding)

    def _create_default_plan(self, finding: Finding) -> Workplan:
        """Create a safe default plan when Claude fails"""
        tier = self.policy_engine.get_remediation_tier(finding.cwe_id, finding.code_snippet)

        return Workplan(
            workplan_id=f"plan-{finding.finding_id}",
            finding_ids=[finding.finding_id],
            created_at=datetime.now(),
            phases=[
                RemediationStep(
                    step_number=1,
                    description=f"Apply Tier {tier} remediation pattern",
                    file_path=finding.file_path,
                    tier=tier,
                    estimated_time_minutes=15,
                    risks=[]
                ),
                RemediationStep(
                    step_number=2,
                    description="Run test suite",
                    file_path=finding.file_path,
                    tier=tier,
                    estimated_time_minutes=10,
                    risks=[]
                ),
                RemediationStep(
                    step_number=3,
                    description="Run SAST re-scan",
                    file_path=finding.file_path,
                    tier=tier,
                    estimated_time_minutes=5,
                    risks=[]
                )
            ],
            total_estimated_time=30,
            approval_required=tier >= 2,
            approval_chain=['developer'] if tier == 1 else ['code_review'],
            validation_checkpoints=[
                'Run existing tests',
                'SAST re-scan',
                'Security test'
            ],
            rollback_plan="Revert commits"
        )

    def interactive_planning_session(self, finding: Finding) -> tuple[Workplan, Dict[str, Any]]:
        """
        Start an interactive planning session where user can ask questions.

        Returns:
            (workplan, session_data)
        """
        logger.info(f"Starting interactive planning for {finding.finding_id}")

        # Generate initial plan
        workplan = self.generate_plan(finding)

        session_data = {
            'finding_id': finding.finding_id,
            'initial_plan': workplan,
            'conversation_history': [],
            'approved': False,
            'modifications': [],
            'final_plan': None
        }

        return workplan, session_data

    def ask_followup(self, finding: Finding, question: str, session_data: Dict) -> str:
        """
        Ask a follow-up question about the plan during interactive session.

        Args:
            finding: The finding
            question: User's question
            session_data: Session state

        Returns:
            Claude's response
        """
        logger.info(f"Follow-up question: {question}")

        # Build context
        policy = self.policy_engine.get_policy(finding.cwe_id)
        context = self._build_context(finding, policy)

        response = self.client.messages.create(
            model="claude-opus-4-6",
            max_tokens=2000,
            messages=[
                {
                    "role": "user",
                    "content": f"""
{context}

Current plan: {session_data['initial_plan'].model_dump_json(indent=2)}

User question: {question}

Answer the question considering the remediation context and policy.
Be specific and actionable."""
                }
            ]
        )

        answer = response.content[0].text

        # Track conversation
        session_data['conversation_history'].append({
            'question': question,
            'answer': answer,
            'timestamp': datetime.now().isoformat()
        })

        return answer


# Usage example
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)

    from datetime import datetime
    from src.models.finding import Finding, ScannerType

    # Create a test finding
    finding = Finding(
        finding_id="test-plan-001",
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

    # Generate plan
    agent = PlanAgent()
    print("\n=== Generating Remediation Plan ===\n")
    workplan = agent.generate_plan(finding)

    print(f"✓ Plan Generated")
    print(f"  ID: {workplan.workplan_id}")
    print(f"  Phases: {len(workplan.phases)}")
    print(f"  Time: {workplan.total_estimated_time} minutes")
    print(f"  Approval Required: {workplan.approval_required}")
