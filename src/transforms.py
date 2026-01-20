"""
Guardrail Judge:
✅ 1) Actionability detector (operational "how-to" requests)
✅ 2) Deobfuscation (l33t + spaced/separated words)
✅ 3) Allowlist (defensive contexts + safe-tech)
✅ 4) Evidence structured output (signals)

Returns: ALLOW / SAFE_COMPLETE / REFUSE
This is a demo for safety education (no harmful instruction generation).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Tuple
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
    signals: Dict[str, Any] = field(default_factory=dict)


# --- Domain signals (coarse) ---
HARMFUL_DOMAIN_KEYWORDS = [
    # cyber / abuse
    "hack", "bypass", "exploit", "malware", "phishing", "steal", "fraud", "ddos", "dox",
    # physical harm domains (demo)
    "weapon", "bomb", "poison", "terror",
]

# Intent shift patterns (ISA-like)
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

# Defensive framing allowlist (soft reducer)
DEFENSIVE_CONTEXT_KEYWORDS = [
    "defend", "prevent", "mitigation", "secure", "protection", "best practices",
    "how to protect", "how to prevent", "incident response", "hardening", "securely",
]

# Safe-tech allowlist (hard allow) — only when NO harmful domain keywords are present
SAFE_TECH_EXCEPTIONS = [
    "kill a process", "terminate process", "stop a service", "python process",
    "ctf", "lab environment", "security audit",
]

# Educational / historical context (soft reducer + de-overblocking)
EDUCATIONAL_CONTEXT_KEYWORDS = [
    "history", "historical", "timeline", "origin", "overview", "background",
    "when was", "when were", "what year", "in what year", "date of",
    "who invented", "who created", "first",
    # common typo from your example
    "maded",
]

# --- Deobfuscation (l33t + separated words) ---
LEET_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
    "|": "i",
})

SEP_CHARS_RE = re.compile(r"[\s\.\-\_\(\)\[\]\{\}:;,'\"\\/|`~^+=*]+")
NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


def normalize(text: str) -> str:
    text = text.strip()
    return re.sub(r"\s+", " ", text)


def deobfuscate_text(text: str) -> Dict[str, str]:
    """
    Canonical forms:
      - lower: lowercase original
      - leet: leet-translated
      - joined: separators removed (spaces/dots/dashes/underscores collapsed)
      - joined_leet: both leet-translated AND separators removed
    """
    lower = normalize(text).lower()
    leet = lower.translate(LEET_MAP)

    joined = SEP_CHARS_RE.sub("", lower)
    joined = NON_ALNUM_RE.sub("", joined)

    joined_leet = SEP_CHARS_RE.sub("", leet)
    joined_leet = NON_ALNUM_RE.sub("", joined_leet)

    return {"lower": lower, "leet": leet, "joined": joined, "joined_leet": joined_leet}


def _contains_any(text: str, keywords: List[str]) -> bool:
    forms = deobfuscate_text(text)
    return any(
        (k in forms["lower"]) or (k in forms["leet"]) or (k in forms["joined"]) or (k in forms["joined_leet"])
        for k in keywords
    )


def _count_any(text: str, keywords: List[str]) -> int:
    forms = deobfuscate_text(text)
    return sum(
        1 for k in keywords
        if (k in forms["lower"]) or (k in forms["leet"]) or (k in forms["joined"]) or (k in forms["joined_leet"])
    )


def detect_intent_shift(text: str) -> List[str]:
    t = normalize(text).lower()
    hits: List[str] = []
    for label, patterns in INTENT_SHIFT_PATTERNS.items():
        if any(p in t for p in patterns):
            hits.append(label)
    return hits


# --- Actionability detector ---
# We intentionally DON'T treat every "how to" as actionable.
# We look for operational verbs + instruction cues, especially when combined with harmful domains.
ACTION_VERBS = [
    "make", "build", "create", "assemble", "cook", "prepare",
    "hack", "bypass", "exploit", "phish", "ddos", "steal",
]

INSTRUCTION_CUES = [
    "step by step", "steps", "instructions", "instruction", "tutorial", "guide",
    "walk me through", "tell me how", "show me how",
]

ACTION_PREFIXES = [
    "how to", "i want", "i wanna", "help me", "teach me", "can you help me",
]

def detect_actionability(text: str) -> Tuple[bool, List[str]]:
    """
    Returns (is_actionable, evidence_strings)
    """
    t = normalize(text).lower()
    evidence: List[str] = []

    # Instruction cues alone often indicate actionability (e.g., "give steps")
    if _contains_any(t, INSTRUCTION_CUES):
        evidence.append("instruction_cue")

    # Prefix + action verb (e.g., "how to make", "i want to hack")
    # We'll check this in deobfuscated joined form too, so "h o w t o m a k e" still hits.
    forms = deobfuscate_text(t)
    joined = forms["joined_leet"]

    # quick heuristic: any prefix appears AND any action verb appears
    prefix_hit = any(p in t for p in ACTION_PREFIXES) or any(p.replace(" ", "") in joined for p in ACTION_PREFIXES)
    verb_hit = any(v in t for v in ACTION_VERBS) or any(v in joined for v in ACTION_VERBS)

    if prefix_hit and verb_hit:
        evidence.append("prefix_plus_action_verb")

    # Another heuristic: "how to" + harmful domain keyword (even without explicit verb)
    if ("how to" in t or "howto" in joined) and _contains_any(t, HARMFUL_DOMAIN_KEYWORDS):
        evidence.append("howto_plus_harmful_domain")

    is_actionable = len(evidence) > 0
    return is_actionable, evidence


def judge_request(user_text: str) -> JudgeResult:
    text = normalize(user_text)
    t = text.lower()
    forms = deobfuscate_text(text)

    # HARD allow: safe-tech exceptions only when no harmful domain keywords exist
    if _contains_any(t, SAFE_TECH_EXCEPTIONS) and not _contains_any(t, HARMFUL_DOMAIN_KEYWORDS):
        return JudgeResult(
            risk_level=RiskLevel.LOW,
            action=PolicyAction.ALLOW,
            reasons=["Safe-tech exception: looks like a benign technical request."],
            signals={
                "safe_tech_exception": True,
                "defensive_context": False,
                "educational_context": False,
                "actionable": False,
                "actionability_evidence": [],
                "intent_shift": [],
                "harmful_keywords_count": 0,
                "obfuscated_harmful": False,
            },
        )

    reasons: List[str] = []
    signals: Dict[str, Any] = {
        "safe_tech_exception": False,
        "defensive_context": False,
        "educational_context": False,
        "actionable": False,
        "actionability_evidence": [],
        "intent_shift": [],
        "harmful_keywords_count": 0,
        "obfuscated_harmful": False,
    }

    # 1) Intent shift
    intent_shift_hits = detect_intent_shift(text)
    signals["intent_shift"] = intent_shift_hits
    if intent_shift_hits:
        reasons.append(f"Detected intent-shift pattern(s): {', '.join(intent_shift_hits)}.")

    # 2) Harmful domain keywords (with deobfuscation)
    harmful_hits = _count_any(t, HARMFUL_DOMAIN_KEYWORDS)
    signals["harmful_keywords_count"] = harmful_hits
    if harmful_hits > 0:
        reasons.append("Detected potentially harmful domain keyword(s).")

    # 2.1) Obfuscated harmful keywords? (not visible in raw lower but appears in joined_leet)
    raw_lower = forms["lower"]
    joined_leet = forms["joined_leet"]
    obfuscated_harmful = any((k not in raw_lower) and (k in joined_leet) for k in HARMFUL_DOMAIN_KEYWORDS)
    signals["obfuscated_harmful"] = obfuscated_harmful
    if obfuscated_harmful:
        reasons.append("Detected obfuscated harmful keyword(s) via deobfuscation (leet/separated).")

    # 3) Context allowlists (soft)
    defensive_context = _contains_any(t, DEFENSIVE_CONTEXT_KEYWORDS)
    signals["defensive_context"] = defensive_context
    if defensive_context:
        reasons.append("Detected defensive/mitigation framing keywords.")

    educational_context = _contains_any(t, EDUCATIONAL_CONTEXT_KEYWORDS)
    signals["educational_context"] = educational_context
    if educational_context:
        reasons.append("Detected educational/historical framing keywords.")

    # 4) Actionability
    actionable, action_evidence = detect_actionability(text)
    signals["actionable"] = actionable
    signals["actionability_evidence"] = action_evidence
    if actionable:
        reasons.append("Detected actionable / operational phrasing.")

    # --- Key safety rule ---
    # If it's harmful-domain AND actionable => REFUSE (safe words do not override)
    if harmful_hits > 0 and actionable:
        reasons.append("Actionable request in a harmful domain (context words do not override).")
        return JudgeResult(RiskLevel.HIGH, PolicyAction.REFUSE, reasons, signals)

    # --- Scoring (non-actionable path) ---
    score = 0
    score += 2 * len(intent_shift_hits)
    score += 2 * harmful_hits
    if obfuscated_harmful:
        score += 2

    # soft reducers
    if defensive_context:
        score -= 2
    if educational_context:
        score -= 2

    # De-overblocking rule:
    # If it's a harmful domain keyword but clearly educational/historical and NOT actionable,
    # keep at most MEDIUM (SAFE_COMPLETE) rather than REFUSE.
    if harmful_hits > 0 and educational_context and not actionable:
        score = min(score, 4)

    if score <= 1:
        return JudgeResult(RiskLevel.LOW, PolicyAction.ALLOW, reasons or ["No risk signals detected."], signals)

    if 2 <= score <= 4:
        return JudgeResult(RiskLevel.MEDIUM, PolicyAction.SAFE_COMPLETE, reasons, signals)

    return JudgeResult(RiskLevel.HIGH, PolicyAction.REFUSE, reasons, signals)
