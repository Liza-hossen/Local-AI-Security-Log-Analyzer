"""Pydantic models for findings and per-chunk results, plus the JSON schema given to Ollama."""
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

import config


class AttackType(str, Enum):
    BRUTE_FORCE = "Brute Force"
    SQL_INJECTION = "SQL Injection"
    UNUSUAL_RATE = "Unusual Request Rate"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    SCANNING = "Scanning/Reconnaissance"
    OTHER = "Other"


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class FindingStatus(str, Enum):
    ATTEMPTED = "Attempted"
    BLOCKED = "Blocked"
    POSSIBLY_SUCCESSFUL = "Possibly Successful"


class Evidence(BaseModel):
    line: int
    description: str


class Finding(BaseModel):
    attack_type: AttackType
    severity: Severity
    source_ip: Optional[str] = None
    evidence: list[Evidence]
    reason: str
    suggested_action: str
    confidence: float = Field(ge=0.0, le=1.0)
    status: FindingStatus
    chunk_index: Optional[int] = None  # filled in by the analyzer, not the model
    # Filled in by correlation (never by the model):
    source: str = "model"              # "model" = from the LLM, "rules" = deterministic detector
    chunk_indexes: list[int] = []      # every chunk this (merged) finding came from
    corroborated: bool = True          # False = no rule-based signal backs it up
    notes: list[str] = []              # what correlation changed and why


class Stage(BaseModel):
    name: str
    count: int
    lines: list[int]


class Correlation(BaseModel):
    """A multi-step story for one IP, built by code from the per-IP state."""
    kind: str                          # e.g. "account_compromise"
    source_ip: str
    severity: Severity
    description: str
    stages: list[Stage]
    users: list[str] = []
    chunk_indexes: list[int] = []      # chunks the stages fall in (shows cross-chunk reach)


class ChunkResult(BaseModel):
    chunk_index: int
    first_line: int
    last_line: int
    ok: bool
    findings: list[Finding] = []
    error: Optional[str] = None
    warnings: list[str] = []       # validator fixes/drops, so nothing is silently changed
    attempts: int = 0
    prompt_tokens: int = 0         # real counts reported by Ollama
    output_tokens: int = 0
    duration_s: float = 0.0


def ollama_output_schema() -> dict:
    """JSON schema passed to Ollama's `format`, which constrains generation to it.

    Written by hand (not model_json_schema()) to keep it flat: no $ref, and length
    limits that keep the answer inside the output token reserve.
    """
    def enum(e):
        return {"type": "string", "enum": [m.value for m in e]}

    finding = {
        "type": "object",
        "properties": {
            "attack_type": enum(AttackType),
            "severity": enum(Severity),
            "source_ip": {"type": "string"},
            "evidence": {
                "type": "array",
                "maxItems": 4,
                "items": {
                    "type": "object",
                    "properties": {"line": {"type": "integer"}, "description": {"type": "string"}},
                    "required": ["line", "description"],
                },
            },
            "reason": {"type": "string"},
            "suggested_action": {"type": "string"},
            "confidence": {"type": "number"},
            "status": enum(FindingStatus),
        },
        "required": ["attack_type", "severity", "source_ip", "evidence", "reason",
                     "suggested_action", "confidence", "status"],
    }
    return {
        "type": "object",
        "properties": {
            "findings": {"type": "array", "maxItems": config.MAX_FINDINGS_PER_CHUNK, "items": finding}
        },
        "required": ["findings"],
    }
