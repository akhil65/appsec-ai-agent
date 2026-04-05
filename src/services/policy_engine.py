import os
import re
from typing import Optional, List, Dict, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class Policy:
    """Represents a remediation policy for a CWE"""

    def __init__(self, cwe_id: int, content: str):
        self.cwe_id = cwe_id
        self.content = content
        self.metadata = self._parse_metadata()
        self.tiers = self._parse_tiers()
        self.detection_patterns = self._parse_patterns()

    def _parse_metadata(self) -> Dict[str, str]:
        """Extract metadata from policy markdown"""
        metadata = {}

        # Extract CWE name from first heading
        match = re.search(r'# CWE-\d+: (.*)', self.content)
        if match:
            metadata['name'] = match.group(1)

        # Extract severity
        match = re.search(r'\*\*Severity\*\*:\s*(CRITICAL|HIGH|MEDIUM|LOW)', self.content)
        if match:
            metadata['severity'] = match.group(1)

        # Extract version
        match = re.search(r'\*\*Policy Version\*\*:\s*([\d.]+)', self.content)
        if match:
            metadata['version'] = match.group(1)

        return metadata

    def _parse_tiers(self) -> Dict[int, Dict[str, Any]]:
        """Extract remediation tiers from policy"""
        tiers = {}

        # Find Tier 1, 2, 3 sections
        tier_pattern = r'### Tier (\d): (.+?)\n(.+?)\n(.+?)\n(.+?)\n'

        # For now, return basic tier info
        # In production, would parse full markdown structure
        tiers[1] = {
            'description': 'Auto-Fixable',
            'approval': 'developer',
            'time_estimate': 5
        }
        tiers[2] = {
            'description': 'Review Required',
            'approval': 'code_review',
            'time_estimate': 20
        }
        tiers[3] = {
            'description': 'Architectural',
            'approval': 'architecture_review',
            'time_estimate': 240
        }

        return tiers

    def _parse_patterns(self) -> List[str]:
        """Extract detection patterns from policy"""
        patterns = []

        # Find detection patterns section
        section_match = re.search(r'## Detection Patterns\n(.*?)(?=\n##|$)', self.content, re.DOTALL)
        if section_match:
            section = section_match.group(1)
            # Extract regex patterns
            pattern_matches = re.findall(r'Regex: (.+)', section)
            patterns.extend(pattern_matches)

        return patterns

    def get_tier(self, tier_num: int) -> Optional[Dict[str, Any]]:
        """Get tier information"""
        return self.tiers.get(tier_num)

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dict"""
        return {
            'cwe_id': self.cwe_id,
            'metadata': self.metadata,
            'tiers': self.tiers,
            'detection_patterns': self.detection_patterns
        }


class PolicyEngine:
    """Load and enforce remediation policies"""

    def __init__(self, policies_dir: str = "src/policies"):
        self.policies_dir = policies_dir
        self.policies: Dict[int, Policy] = {}
        self.load_policies()

    def load_policies(self):
        """Load all policy files from disk"""
        if not os.path.exists(self.policies_dir):
            logger.warning(f"Policies directory not found: {self.policies_dir}")
            return

        for file in os.listdir(self.policies_dir):
            if file.startswith('cwe_') and file.endswith('.md'):
                # Extract CWE ID from filename: cwe_89_sqli.md → 89
                cwe_id = int(file.split('_')[1])

                try:
                    with open(os.path.join(self.policies_dir, file), 'r') as f:
                        content = f.read()

                    policy = Policy(cwe_id, content)
                    self.policies[cwe_id] = policy
                    logger.debug(f"Loaded policy for CWE-{cwe_id}")
                except Exception as e:
                    logger.error(f"Failed to load policy {file}: {e}")

    def get_policy(self, cwe_id: int) -> Optional[Policy]:
        """Get policy for a specific CWE"""
        return self.policies.get(cwe_id)

    def has_policy(self, cwe_id: int) -> bool:
        """Check if policy exists for CWE"""
        return cwe_id in self.policies

    def get_remediation_tier(self, cwe_id: int, code_snippet: str) -> int:
        """
        Determine which remediation tier to use.

        Args:
            cwe_id: CWE ID
            code_snippet: Vulnerable code

        Returns:
            Tier (1, 2, or 3)
        """
        policy = self.get_policy(cwe_id)
        if not policy:
            logger.warning(f"No policy for CWE-{cwe_id}, defaulting to Tier 2")
            return 2

        # Check if code matches simple patterns (Tier 1)
        for pattern in policy.detection_patterns:
            if re.search(pattern, code_snippet):
                # Simple patterns → Tier 1
                if len(code_snippet) < 200 and code_snippet.count('\n') < 5:
                    return 1

        # Complex patterns → Tier 2 or 3
        if len(code_snippet) > 500 or code_snippet.count('\n') > 10:
            return 3

        return 2

    def validate_fix(self, cwe_id: int, tier: int, fixed_code: str) -> tuple[bool, str]:
        """
        Validate that a fix complies with policy.

        Args:
            cwe_id: CWE ID
            tier: Remediation tier (1, 2, or 3)
            fixed_code: The fixed code

        Returns:
            (is_valid, message)
        """
        policy = self.get_policy(cwe_id)
        if not policy:
            return True, "No policy to validate against"

        tier_info = policy.get_tier(tier)
        if not tier_info:
            return False, f"Invalid tier: {tier}"

        # Basic validation: fixed code should not match detection patterns
        for pattern in policy.detection_patterns:
            if re.search(pattern, fixed_code):
                return False, f"Fixed code still matches vulnerable pattern: {pattern}"

        return True, "Fix complies with policy"

    def get_approval_requirement(self, cwe_id: int, tier: int) -> str:
        """Get approval requirement for a fix"""
        policy = self.get_policy(cwe_id)
        if not policy:
            return "security_review"

        tier_info = policy.get_tier(tier)
        if not tier_info:
            return "security_review"

        return tier_info.get('approval', 'security_review')

    def list_policies(self) -> List[Dict[str, Any]]:
        """List all loaded policies"""
        return [policy.to_dict() for policy in self.policies.values()]


# Test usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    engine = PolicyEngine()

    print(f"\n✓ Loaded {len(engine.policies)} policies")

    # Test getting a policy
    if engine.has_policy(89):
        policy = engine.get_policy(89)
        print(f"✓ CWE-89: {policy.metadata.get('name', 'Unknown')}")
        print(f"  Version: {policy.metadata.get('version', 'Unknown')}")

    # Test tier determination
    vulnerable_code = 'query = f"SELECT * FROM users WHERE id={user_id}"'
    tier = engine.get_remediation_tier(89, vulnerable_code)
    print(f"✓ Code matches Tier {tier}")

    # Test fix validation
    fixed_code = 'query = "SELECT * FROM users WHERE id=?"; db.execute(query, [user_id])'
    valid, msg = engine.validate_fix(89, 1, fixed_code)
    print(f"✓ Fix validation: {valid} ({msg})")