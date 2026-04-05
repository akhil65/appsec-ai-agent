from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum

class RemediationStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ESCALATED = "escalated"

class RemediationResult(BaseModel):
    """Result of a remediation attempt"""
    remediation_id: str
    finding_id: str
    status: RemediationStatus
    
    # Code changes
    fixed_code: Optional[str] = None
    changed_files: List[str] = []
    
    # Validation
    tests_passed: bool
    sast_passed: bool
    confidence_score: float  # 0.0-1.0
    
    # Metadata
    model_used: str  # e.g., "claude-sonnet-4.6"
    execution_time_seconds: float
    created_at: datetime
    error_message: Optional[str] = None

    policy_applied: Optional[str] = None        # Policy filename
    policy_version: Optional[str] = None        # Policy version (e.g., "2.1")
    policy_tier: Optional[int] = None           # Tier 1, 2, or 3
    approval_required: str = "developer"        # developer, code_review, architecture_review
    ai_model_used: str = "claude-sonnet-4.6"   # Which Claude model
    ai_confidence_score: float = 0.0            # 0.0-1.0
    governance_tags: List[str] = []             # Tags for audit trail
    evidence: Optional[Dict[str, Any]] = None   # Evidence dict