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