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