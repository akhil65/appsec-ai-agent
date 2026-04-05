from pydantic import BaseModel
from typing import Optional
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
    found_at: datetime
    policy_applied: Optional[str] = None  # Name of policy applied
    policy_tier: Optional[int] = None     # Tier 1, 2, or 3
    institutional_requirement: Optional[str] = None  # Org requirement

class Config:
    json_schema_extra = {
        "example": {
            # ... existing example fields ...
            "policy_applied": "cwe_89_sqli.md",
            "policy_tier": 1,
            "institutional_requirement": "All SQL must use parameterized queries"
        }
    }