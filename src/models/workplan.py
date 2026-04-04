from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum

class WorkplanPhase(str, Enum):
    PLANNING = "planning"
    EXECUTION = "execution"
    VALIDATION = "validation"
    REVIEW = "review"

class RemediationStep(BaseModel):
    """One step in the remediation workplan"""
    step_number: int
    description: str
    file_path: str
    tier: int
    estimated_time_minutes: int
    risks: List[str] = []

class Workplan(BaseModel):
    """Plan for remediating a set of findings"""
    workplan_id: str
    finding_ids: List[str]
    created_at: datetime
    
    # Phases
    phases: List[RemediationStep] = []
    
    # Metadata
    total_estimated_time: int  # minutes
    approval_required: bool
    approval_chain: List[str] = []
    
    # Validation
    validation_checkpoints: List[str] = []
    rollback_plan: Optional[str] = None