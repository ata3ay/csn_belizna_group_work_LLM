from .transforms import JudgeResult, PolicyAction



def respond_allow(user_text: str) -> str:
    return (
        "Answer (ALLOW)\n"
        "I can help with general, non-sensitive information.\n"
        "If you share your goal and context, I can give a clearer answer."
    )


def respond_safe_complete(user_text: str, judge: JudgeResult) -> str:
    reasons = "\n".join(f"- {r}" for r in judge.reasons) if judge.reasons else "- (no reasons)"
    return (
        "Answer (SAFE_COMPLETE)\n"
        "I can’t provide step-by-step operational guidance that could enable harm.\n"
        "But I can explain this topic at a high level and focus on defense.\n\n"
        "Why this was flagged:\n"
        f"{reasons}\n\n"
        "Safe direction (defensive focus):\n"
        "- Clarify what you want to protect (assets, users, data).\n"
        "- Use strong authentication, least privilege, and patching.\n"
        "- Enable logging/monitoring and incident response basics.\n"
        "- Learn via legal labs/CTFs, not real systems.\n"
    )


def respond_refuse(user_text: str, judge: JudgeResult) -> str:
    reasons = "\n".join(f"- {r}" for r in judge.reasons) if judge.reasons else "- (no reasons)"
    return (
        "Answer (REFUSE)\n"
        "I can’t help with requests that may enable wrongdoing or unsafe actions.\n\n"
        "Why this was flagged:\n"
        f"{reasons}\n\n"
        "If your goal is legitimate, I can help with:\n"
        "- defensive best practices\n"
        "- threat modeling\n"
        "- setting up a legal learning lab / CTF plan\n"
    )


def generate_response(user_text: str, judge: JudgeResult) -> str:
    if judge.action == PolicyAction.ALLOW:
        return respond_allow(user_text)
    if judge.action == PolicyAction.SAFE_COMPLETE:
        return respond_safe_complete(user_text, judge)
    return respond_refuse(user_text, judge)
