import os
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class Guardrails:
    """Enforce security guardrails (enterprise + repo-local)"""

    def __init__(self):
        self.enterprise_guardrails = self._load_enterprise_guardrails()
        self.repo_guardrails = self._load_repo_guardrails()

    def _load_enterprise_guardrails(self) -> Dict:
        """Load enterprise-wide guardrails from environment"""
        return {
            "AUTO_APPROVE_TIER_1": os.getenv("AUTO_APPROVE_TIER_1", "false").lower() == "true",
            "REQUIRE_SAST_PASS": os.getenv("REQUIRE_SAST_PASS", "true").lower() == "true",
            "CONFIDENCE_THRESHOLD": float(os.getenv("CONFIDENCE_THRESHOLD", "0.90")),
            "REQUIRE_CODE_REVIEW_TIER_2": os.getenv("REQUIRE_CODE_REVIEW_TIER_2", "true").lower() == "true",
            "ALLOW_AUTO_FIX": os.getenv("ALLOW_AUTO_FIX", "true").lower() == "true",
            "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO")
        }

    def _load_repo_guardrails(self) -> Dict:
        """Load repo-specific guardrails from config file"""
        config_file = "config/guardrails.yaml"

        if not os.path.exists(config_file):
            logger.warning(f"Repo guardrails file not found: {config_file}")
            return {}

        try:
            import yaml
            with open(config_file, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"Failed to load repo guardrails: {e}")
            return {}

    def check_can_execute(self, tier: int, confidence_score: float, cwe_id: int) -> tuple[bool, str]:
        """
        Check if a remediation can be executed based on guardrails.

        Args:
            tier: Remediation tier (1, 2, or 3)
            confidence_score: AI confidence (0.0-1.0)
            cwe_id: CWE ID

        Returns:
            (can_execute, reason)
        """

        # Check confidence threshold
        if confidence_score < self.enterprise_guardrails["CONFIDENCE_THRESHOLD"]:
            return False, f"Confidence {confidence_score:.0%} below threshold {self.enterprise_guardrails['CONFIDENCE_THRESHOLD']:.0%}"

        # Check if CWE is disabled in this repo
        if self._is_cwe_disabled(cwe_id):
            return False, f"CWE-{cwe_id} remediation disabled in this repo"

        # Check Tier 1 auto-approval
        if tier == 1 and not self.enterprise_guardrails["ALLOW_AUTO_FIX"]:
            return False, "Auto-fix disabled by enterprise policy"

        return True, "All guardrails passed"

    def get_approval_requirement(self, tier: int, cwe_id: int) -> str:
        """
        Get approval requirement based on guardrails.

        Args:
            tier: Remediation tier
            cwe_id: CWE ID

        Returns:
            Approval level: "none", "developer", "code_review", "architecture"
        """

        # Check repo overrides
        if "tier_overrides" in self.repo_guardrails:
            if cwe_id in self.repo_guardrails["tier_overrides"]:
                override_tier = self.repo_guardrails["tier_overrides"][cwe_id]
                return self._tier_to_approval(override_tier)

        # Use default based on tier
        return self._tier_to_approval(tier)

    def _is_cwe_disabled(self, cwe_id: int) -> bool:
        """Check if CWE remediation is disabled"""
        disabled_cwes = self.repo_guardrails.get("disabled_cwes", [])
        return cwe_id in disabled_cwes

    def _tier_to_approval(self, tier: int) -> str:
        """Convert tier to approval level"""
        if tier == 1:
            return "developer"
        elif tier == 2:
            return "code_review"
        else:
            return "architecture"

    def to_dict(self) -> Dict:
        """Export guardrails as dict"""
        return {
            "enterprise": self.enterprise_guardrails,
            "repo": self.repo_guardrails
        }


# Test usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    logger.info("Testing Guardrails\n")

    guardrails = Guardrails()

    # Check execution
    can_exec, reason = guardrails.check_can_execute(tier=1, confidence_score=0.97, cwe_id=89)
    print(f"✓ Tier 1 with 97% confidence: {can_exec} ({reason})")

    # Get approval requirement
    approval = guardrails.get_approval_requirement(tier=1, cwe_id=89)
    print(f"✓ Tier 1 requires: {approval}")

    approval = guardrails.get_approval_requirement(tier=2, cwe_id=89)
    print(f"✓ Tier 2 requires: {approval}\n")
