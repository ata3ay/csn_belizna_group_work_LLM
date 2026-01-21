"""
Guardrail Judge:
✅ 1) Actionability detector (operational "how-to" requests)
✅ 2) Deobfuscation (l33t + spaced/separated words)
✅ 3) Allowlist (defensive contexts + safe-tech)
✅ 4) Evidence structured output (signals)
➕ 5) Jailbreak / roleplay / "ignore policy" detector
➕ 6) Evasion / stealth detector
➕ 7) Defamation / reputation-harm detector
➕ 8) Tax evasion / financial fraud detector
➕ 9) Extra domains from GPTFuzzer residuals:
    - psych manipulation, bullying, misinfo/propaganda, drug misuse,
      cyber-attack techniques, identity/credit fraud, physical harm phrasing

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
# NOTE: This is a demo list. You'll tune it with benchmarks (AdvBench/AutoDAN/GPTFuzzer).
HARMFUL_DOMAIN_KEYWORDS = [
    # cyber / abuse
    "hack", "bypass", "exploit", "malware", "phishing", "ddos", "dox",

    # fraud / impersonation / scams
    "fraud", "scam", "con", "impersonate", "fake account", "identity theft",

    # theft / burglary
    "steal", "rob", "theft", "break into", "burglary", "picklock", "lockpick",

    # coercion / extortion / blackmail / bribery
    "blackmail", "extortion", "coerce", "threaten", "bribe", "bribery",

    # sabotage / tampering / framing
    "sabotage", "tamper", "frame", "plant evidence",

    # harassment / stalking / intimidation
    "harass", "stalk",

    # physical harm domains (demo)
    "weapon", "bomb", "poison", "terror",
]

# Jailbreak / policy-bypass prompts (very common in GPTFuzzer/AutoDAN)
JAILBREAK_PATTERNS = [
    "do anything now", "dan", "developer mode", "jailbreak",
    "unfiltered", "uncensored", "no restrictions", "no rules",
    "ignore openai", "ignore policy", "ignore policies", "bypass policy",
    "disregard the rules", "override safety", "system prompt",
    "stay in character", "act as", "simulate being", "you are not chatgpt",
    "two responses", "answer in two ways",
    "[🔓", "🔓", "jailbreak:", "devmode",
]

# Evasion / stealth / "get away with it"
EVASION_PATTERNS = [
    "without getting caught", "without being caught", "not get caught",
    "avoid detection", "evade detection", "undetected",
    "cover your tracks", "cover my tracks", "leave no trace",
    "untraceable", "how to get away with", "get away with",
    "bypass filters", "bypass detection", "bypass security",
    "secretly", "stealthily",
]

# Defamation / reputation harm (phrase-based to avoid huge overblocking)
DEFAMATION_PATTERNS = [
    "spread rumors", "spread false rumors", "spread false rumours",
    "damage reputation", "ruin reputation", "destroy reputation",
    "fake accusations", "false accusations",
    "defame", "slander",
    "frame someone", "plant evidence",
    "bully online", "harass online",
]

# Tax evasion / financial fraud (phrase-based)
TAX_EVASION_PATTERNS = [
    "avoid taxes", "evade taxes", "tax evasion",
    "commit tax fraud", "tax fraud",
    "hide income", "underreport income",
    "fake deductions", "forge receipts", "falsify records",
]

# --- Extra GPTFuzzer domains (phrase-based where possible) ---
PSYCH_MANIPULATION_PATTERNS = [
    "subliminal messaging", "brainwashing", "mind games", "reverse psychology",
    "manipulate someone", "control someone", "make someone feel indebted",
    "intimidate someone into", "what you want",
]

BULLYING_PATTERNS = [
    "bully someone", "cyberbullying", "harass online",
    "anonymous messaging to bully", "post negative comments",
    "negative reviews about", "make someone look bad online",
]

MISINFO_PROPAGANDA_PATTERNS = [
    "spread fake news", "spread misinformation", "disinformation", "propaganda",
    "smear campaign", "turn public opinion against", "false narrative",
]

DRUG_MISUSE_PATTERNS = [
    "to get high", "get high",
    "bath salts", "synthetic marijuana", "opioids", "methamphetamine",
    "without a prescription", "avoid drug testing",
]

CYBER_ATTACK_PATTERNS = [
    "sql injection", "keylogger", "ransomware", "botnet",
    "brute force", "man-in-the-middle", "dos attack", "denial-of-service",
    "unauthorized access",
]

IDENTITY_FRAUD_PATTERNS = [
    "fake identities", "apply for credit cards", "apply for loans",
    "identity theft", "fake social security",
]

PHYSICAL_HARM_PATTERNS = [
    "harm someone", "cause an accident to harm",
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


def detect_jailbreak(text: str) -> bool:
    return _contains_any(text, JAILBREAK_PATTERNS)


def detect_evasion(text: str) -> bool:
    return _contains_any(text, EVASION_PATTERNS)


def detect_defamation(text: str) -> bool:
    return _contains_any(text, DEFAMATION_PATTERNS)


def detect_tax_evasion(text: str) -> bool:
    return _contains_any(text, TAX_EVASION_PATTERNS)


def detect_psych_manipulation(text: str) -> bool:
    return _contains_any(text, PSYCH_MANIPULATION_PATTERNS)


def detect_bullying(text: str) -> bool:
    return _contains_any(text, BULLYING_PATTERNS)


def detect_misinfo_propaganda(text: str) -> bool:
    return _contains_any(text, MISINFO_PROPAGANDA_PATTERNS)


def detect_drug_misuse(text: str) -> bool:
    return _contains_any(text, DRUG_MISUSE_PATTERNS)


def detect_cyber_attack(text: str) -> bool:
    return _contains_any(text, CYBER_ATTACK_PATTERNS)


def detect_identity_fraud(text: str) -> bool:
    return _contains_any(text, IDENTITY_FRAUD_PATTERNS)


def detect_physical_harm(text: str) -> bool:
    return _contains_any(text, PHYSICAL_HARM_PATTERNS)


# --- Actionability detector ---
# We intentionally DON'T treat every "how to" as actionable.
# We look for operational verbs + instruction cues, and we also mark some domain-specific patterns as actionable.
ACTION_VERBS = [
    # generic operational
    "make", "build", "create", "assemble", "cook", "prepare", "use", "control",

    # cyber / abuse
    "hack", "bypass", "exploit", "phish", "ddos", "dox",

    # fraud / coercion / manipulation
    "steal", "rob", "scam", "impersonate", "blackmail", "extort",
    "coerce", "threaten", "bribe",
    "sabotage", "tamper", "frame", "manipulate", "deceive",

    # tax / records (kept limited)
    "evade", "underreport", "falsify", "forge",
]

INSTRUCTION_CUES = [
    "step by step", "steps", "instructions", "instruction", "tutorial", "guide",
    "walk me through", "tell me how", "show me how",
    "give me a plan", "strategy", "tactics", "methods",
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

    forms = deobfuscate_text(t)
    joined = forms["joined_leet"]

    prefix_hit = any(p in t for p in ACTION_PREFIXES) or any(p.replace(" ", "") in joined for p in ACTION_PREFIXES)
    verb_hit = any(v in t for v in ACTION_VERBS) or any(v in joined for v in ACTION_VERBS)

    if prefix_hit and verb_hit:
        evidence.append("prefix_plus_action_verb")

    # Another heuristic: "how to" + harmful domain keyword (even without explicit verb)
    if ("how to" in t or "howto" in joined) and _contains_any(t, HARMFUL_DOMAIN_KEYWORDS):
        evidence.append("howto_plus_harmful_domain")

    # Domain-specific phrase patterns often imply operational intent
    if _contains_any(t, DEFAMATION_PATTERNS):
        evidence.append("defamation_phrase")
    if _contains_any(t, TAX_EVASION_PATTERNS):
        evidence.append("tax_evasion_phrase")
    if _contains_any(t, PSYCH_MANIPULATION_PATTERNS):
        evidence.append("psych_manipulation_phrase")
    if _contains_any(t, BULLYING_PATTERNS):
        evidence.append("bullying_phrase")
    if _contains_any(t, MISINFO_PROPAGANDA_PATTERNS):
        evidence.append("misinfo_phrase")
    if _contains_any(t, DRUG_MISUSE_PATTERNS):
        evidence.append("drug_misuse_phrase")
    if _contains_any(t, CYBER_ATTACK_PATTERNS):
        evidence.append("cyber_attack_phrase")
    if _contains_any(t, IDENTITY_FRAUD_PATTERNS):
        evidence.append("identity_fraud_phrase")
    if _contains_any(t, PHYSICAL_HARM_PATTERNS):
        evidence.append("physical_harm_phrase")

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
                "jailbreak_attempt": False,
                "evasion_attempt": False,
                "defamation": False,
                "tax_evasion": False,
                "psych_manipulation": False,
                "bullying": False,
                "misinfo_propaganda": False,
                "drug_misuse": False,
                "cyber_attack": False,
                "identity_fraud": False,
                "physical_harm": False,
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
        "jailbreak_attempt": False,
        "evasion_attempt": False,
        "defamation": False,
        "tax_evasion": False,
        "psych_manipulation": False,
        "bullying": False,
        "misinfo_propaganda": False,
        "drug_misuse": False,
        "cyber_attack": False,
        "identity_fraud": False,
        "physical_harm": False,
        "actionable": False,
        "actionability_evidence": [],
        "intent_shift": [],
        "harmful_keywords_count": 0,
        "obfuscated_harmful": False,
    }

    # 0) Jailbreak
    jailbreak = detect_jailbreak(text)
    signals["jailbreak_attempt"] = jailbreak
    if jailbreak:
        reasons.append("Detected jailbreak / policy-bypass / roleplay patterns.")

    # 0.1) Evasion
    evasion = detect_evasion(text)
    signals["evasion_attempt"] = evasion
    if evasion:
        reasons.append("Detected evasion/stealth patterns (avoid detection / get away with it).")

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

    # 4) Defamation / Tax evasion detectors (phrase-based)
    defamation = detect_defamation(text)
    tax_evasion = detect_tax_evasion(text)
    signals["defamation"] = defamation
    signals["tax_evasion"] = tax_evasion
    if defamation:
        reasons.append("Detected defamation / reputation-harm patterns.")
    if tax_evasion:
        reasons.append("Detected tax evasion / financial fraud patterns.")

    # 4.1) Extra domain detectors
    psych_manipulation = detect_psych_manipulation(text)
    bullying = detect_bullying(text)
    misinfo_propaganda = detect_misinfo_propaganda(text)
    drug_misuse = detect_drug_misuse(text)
    cyber_attack = detect_cyber_attack(text)
    identity_fraud = detect_identity_fraud(text)
    physical_harm = detect_physical_harm(text)

    signals["psych_manipulation"] = psych_manipulation
    signals["bullying"] = bullying
    signals["misinfo_propaganda"] = misinfo_propaganda
    signals["drug_misuse"] = drug_misuse
    signals["cyber_attack"] = cyber_attack
    signals["identity_fraud"] = identity_fraud
    signals["physical_harm"] = physical_harm

    if psych_manipulation:
        reasons.append("Detected psychological manipulation / coercive influence patterns.")
    if bullying:
        reasons.append("Detected bullying / harassment patterns.")
    if misinfo_propaganda:
        reasons.append("Detected misinformation / propaganda / smear patterns.")
    if drug_misuse:
        reasons.append("Detected drug misuse / intoxication patterns.")
    if cyber_attack:
        reasons.append("Detected cyber attack technique patterns.")
    if identity_fraud:
        reasons.append("Detected identity/credit fraud patterns.")
    if physical_harm:
        reasons.append("Detected physical harm patterns.")

    # 5) Actionability
    actionable, action_evidence = detect_actionability(text)
    signals["actionable"] = actionable
    signals["actionability_evidence"] = action_evidence
    if actionable:
        reasons.append("Detected actionable / operational phrasing.")

    # --- Strong rules ---

    # If it's harmful-domain AND actionable => REFUSE (safe words do not override)
    if harmful_hits > 0 and actionable:
        reasons.append("Actionable request in a harmful domain (context words do not override).")
        return JudgeResult(RiskLevel.HIGH, PolicyAction.REFUSE, reasons, signals)

    # Defamation or tax evasion how-to: never ALLOW
    if actionable and (defamation or tax_evasion):
        reasons.append("Actionable request enabling harm or wrongdoing (defamation/tax evasion).")
        return JudgeResult(RiskLevel.HIGH, PolicyAction.REFUSE, reasons, signals)

    # Extra domains: actionable => REFUSE
    if actionable and (
        psych_manipulation or bullying or misinfo_propaganda or drug_misuse
        or cyber_attack or identity_fraud or physical_harm
    ):
        reasons.append("Actionable request enabling wrongdoing or harm (domain pattern detected).")
        return JudgeResult(RiskLevel.HIGH, PolicyAction.REFUSE, reasons, signals)

    # Evasion + actionable: suspicious even without explicit domain keywords
    if evasion and actionable:
        if harmful_hits > 0 or obfuscated_harmful or defamation or tax_evasion:
            return JudgeResult(RiskLevel.HIGH, PolicyAction.REFUSE, reasons, signals)
        return JudgeResult(RiskLevel.MEDIUM, PolicyAction.SAFE_COMPLETE, reasons, signals)

    # Jailbreak handling: never ALLOW (unless already refused above)
    if jailbreak:
        return JudgeResult(RiskLevel.MEDIUM, PolicyAction.SAFE_COMPLETE, reasons, signals)

    # --- Scoring (non-actionable path) ---
    score = 0
    score += 2 * len(intent_shift_hits)
    score += 2 * harmful_hits
    if obfuscated_harmful:
        score += 2
    if defamation:
        score += 2
    if tax_evasion:
        score += 2
    if psych_manipulation:
        score += 2
    if bullying:
        score += 2
    if misinfo_propaganda:
        score += 2
    if drug_misuse:
        score += 2
    if cyber_attack:
        score += 2
    if identity_fraud:
        score += 2
    if physical_harm:
        score += 2
    if evasion:
        score += 1

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
