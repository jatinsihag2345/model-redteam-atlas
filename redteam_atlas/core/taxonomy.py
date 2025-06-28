from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    SYCOPHANCY = "sycophancy"
    TOOL_MANIPULATION = "tool_manipulation"
    INSTRUCTION_HIJACK = "instruction_hijack"
    DELIMITER_ESCAPE = "delimiter_escape"


class AttackSeverity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class AdversarialVector:
    id: str
    name: str
    category: ThreatCategory
    severity: AttackSeverity
    prompt: str
    system_prompt: Optional[str] = None
    expected_refusal: bool = True
    canary_tokens: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    vector_id: str
    category: ThreatCategory
    severity: AttackSeverity
    prompt_sent: str
    completion: str
    refused: bool
    vulnerability_detected: bool
    canary_leaked: bool
    score: float  # 1.0 (safe) to 0.0 (vulnerable)
    notes: Optional[str] = None
