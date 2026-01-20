"""
Guardrail Judge:
- Detects intent-shift patterns (ISA-like phrasing)
- Detects potentially harmful domains via coarse keywords
- Returns an explainable decision: ALLOW / SAFE_COMPLETE / REFUSE

This is a demo for security education (no harmful instruction generation).
"""

from dataclasses import dataclass
from enum import Enum
from typing import List
import re


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    SAFE_COMPLETE = "SAFE_COMPLETE"
    REFUSE = "REFUSE"


@dataclass
class JudgeResult:
    risk_level: RiskLevel
    action: PolicyAction
    reasons: List[str]


HARMFUL_DOMAIN_KEYWORDS = [
    "hack", "bypass", "exploit", "malware", "phishing", "steal", "fraud",
    "weapon", "bomb", "poison", "terror", "dox", "ddos",
]

INTENT_SHIFT_PATTERNS = {
    "PERSON_SHIFT": [
        "how do criminals", "how do hackers", "how do attackers", "how do scammers", "how do thieves",
    ],
    "TENSE_SHIFT": [
        "how was", "how were", "historically", "in the past", "used to",
    ],
    "VOICE_SHIFT": [
        "how is", "how are", "is it done", "is it usually done",
    ],
    "MOOD_SHIFT": [
        "hypothetically", "in a movie", "in a thriller", "in a documentary",
        "for a story", "fictional", "roleplay",
    ],
    "QUESTION_SHIFT": [
        "why can", "why is it possible", "what are the reasons",
        "to better understand", "typical example of how it is usually done",
    ],
}

DEFENSIVE_CONTEXT_KEYWORDS = [
    "defend", "prevent", "mitigation", "secure", "protection", "best practices",
    "how to protect", "how to prevent", "incident response",
]

SAFE_TECH_EXCEPTIONS = [
    "kill a process", "terminate process", "stop a service", "python process",
    "ctf", "lab environment", "security audit",
]


def normalize(text: str) -> str:
    text = text.strip()
    return re.sub(r"\s+", " ", text)


def _contains_any(text: str, keywords: List[str]) -> bool:
    t = text.lower()
    return any(k in t for k in keywords)


def _count_any(text: str, keywords: List[str]) -> int:
    t = text.lower()
    return sum(1 for k in keywords if k in t)


def detect_intent_shift(text: str) -> List[str]:
    t = text.lower()
    hits: List[str] = []
    for label, patterns in INTENT_SHIFT_PATTERNS.items():
        if any(p in t for p in patterns):
            hits.append(label)
    return hits


def judge_request(user_text: str) -> JudgeResult:
    text = normalize(user_text)
    t = text.lower()

    if _contains_any(t, SAFE_TECH_EXCEPTIONS) and not _contains_any(t, HARMFUL_DOMAIN_KEYWORDS):
        return JudgeResult(
            risk_level=RiskLevel.LOW,
            action=PolicyAction.ALLOW,
            reasons=["Safe-tech exception: looks like a benign technical request."],
        )

    reasons: List[str] = []

    intent_shift_hits = detect_intent_shift(text)
    if intent_shift_hits:
        reasons.append(f"Detected intent-shift pattern(s): {', '.join(intent_shift_hits)}.")

    harmful_hits = _count_any(t, HARMFUL_DOMAIN_KEYWORDS)
    if harmful_hits > 0:
        reasons.append("Detected potentially harmful domain keyword(s).")

    defensive_context = _contains_any(t, DEFENSIVE_CONTEXT_KEYWORDS)
    if defensive_context:
        reasons.append("Detected defensive/mitigation framing keywords.")

    score = 0
    score += 2 * len(intent_shift_hits)
    score += 2 * harmful_hits
    if defensive_context:
        score -= 2

    if score <= 1:
        return JudgeResult(RiskLevel.LOW, PolicyAction.ALLOW, reasons or ["No risk signals detected."])

    if 2 <= score <= 4:
        return JudgeResult(RiskLevel.MEDIUM, PolicyAction.SAFE_COMPLETE, reasons)

    return JudgeResult(RiskLevel.HIGH, PolicyAction.REFUSE, reasons)
