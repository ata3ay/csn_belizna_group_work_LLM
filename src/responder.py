from __future__ import annotations

from src.transforms import JudgeResult, PolicyAction


def _signals_summary(judge: JudgeResult) -> str:
    s = getattr(judge, "signals", {}) or {}
    # show only compact, useful fields
    keys = [
        "actionable",
        "actionability_evidence",
        "defensive_context",
        "educational_context",
        "harmful_keywords_count",
        "obfuscated_harmful",
        "intent_shift",
    ]
    lines = []
    for k in keys:
        if k in s:
            lines.append(f"- {k}: {s[k]}")
    return "\n".join(lines) if lines else "- (no signals)"


def respond_allow(user_text: str, judge: JudgeResult) -> str:
    return (
        "Answer (ALLOW)\n"
        "I can help with general, non-sensitive information.\n"
        "If you share your goal and context, I can give a clearer answer.\n\n"
        "Signals:\n"
        f"{_signals_summary(judge)}"
    )


def respond_safe_complete(user_text: str, judge: JudgeResult) -> str:
    reasons = "\n".join(f"- {r}" for r in judge.reasons) if judge.reasons else "- (no reasons)"
    return (
        "Answer (SAFE_COMPLETE)\n"
        "I can’t provide step-by-step operational guidance that could enable harm.\n"
        "But I can explain the topic at a high level and focus on safe, defensive, or historical context.\n\n"
        "Why this was flagged:\n"
        f"{reasons}\n\n"
        "Signals:\n"
        f"{_signals_summary(judge)}\n\n"
        "Safe direction:\n"
        "- If this is about security: focus on prevention, hardening, and best practices.\n"
        "- If this is about history: I can summarize key events at a high level (no recipes/steps).\n"
    )


def respond_refuse(user_text: str, judge: JudgeResult) -> str:
    reasons = "\n".join(f"- {r}" for r in judge.reasons) if judge.reasons else "- (no reasons)"
    return (
        "Answer (REFUSE)\n"
        "I can’t help with requests that may enable wrongdoing or unsafe actions.\n\n"
        "Why this was flagged:\n"
        f"{reasons}\n\n"
        "Signals:\n"
        f"{_signals_summary(judge)}\n\n"
        "If your goal is legitimate, I can help with:\n"
        "- defensive best practices\n"
        "- threat modeling\n"
        "- safe historical overview (no operational instructions)\n"
    )


def generate_response(user_text: str, judge: JudgeResult) -> str:
    if judge.action == PolicyAction.ALLOW:
        return respond_allow(user_text, judge)
    if judge.action == PolicyAction.SAFE_COMPLETE:
        return respond_safe_complete(user_text, judge)
    return respond_refuse(user_text, judge)
