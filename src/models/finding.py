from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class ScannerType(str, Enum):
    CHECKMARX = "checkmarx"
    SNYK = "snyk"
    CODEQL = "codeql"

class Finding(BaseModel):
    """Security finding from SAST scanner"""
    finding_id: str
    cwe_id: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    file_path: str
    line_number: int
    code_snippet: str
    scanner: ScannerType
    scanner_rule_id: str
    scanner_confidence: float
    title: str
    description: str
    repo_name: str
    branch: str = "main"
    found_at: datetime

    # Governance & Policy Fields
    policy_applied: Optional[str] = None  # Name of policy applied
    policy_tier: Optional[int] = None     # Tier 1, 2, or 3
    institutional_requirement: Optional[str] = None  # Org requirement

    # Evidence & Audit Fields
    remediation_id: Optional[str] = None
    confidence_score: Optional[float] = None
    tests_passed: Optional[bool] = None
    sast_passed: Optional[bool] = None
    approval_chain: List[str] = []
    approval_status: Optional[str] = None  # pending, approved, rejected
    approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None

    # Governance Tags
    governance_tags: List[str] = []

class Config:
    json_schema_extra = {
        "example": {
            # ... existing example fields ...
            "policy_applied": "cwe_89_sqli.md",
            "policy_tier": 1,
            "institutional_requirement": "All SQL must use parameterized queries"
        }
    }