huila amir 

Vova lox obyelsa bloch
---

# 🛡️ LLM Guardrail Demo: Judge-Then-Answer Pipeline

## 📌 Project Overview

This project demonstrates a **guardrail pipeline for Large Language Models (LLMs)** based on the *judge-then-answer* principle.
The goal is to show how LLM-based systems can **detect security risks caused by intent-shifted prompts** and respond in a **safe and controlled way**.

The demo is inspired by recent research on **Intent Shift Attacks**, where malicious requests are reformulated to look like harmless, informational questions. Instead of generating harmful content, this system focuses on **intent detection and defensive response strategies**.

---

## 🧠 What the Program Does

The program simulates a simplified LLM safety layer that:

1. **Analyzes a user query**
   Detects:

   * potentially harmful domains (e.g. hacking, fraud, exploitation),
   * linguistic intent-shift patterns (e.g. *“How do criminals…”, “Why can it be done…”, passive voice*),
   * defensive or mitigation-oriented framing.

2. **Judges the risk level**
   Each query is classified as:

   * `LOW` – no relevant security risk detected
   * `MEDIUM` – ambiguous or intent-shifted query
   * `HIGH` – strong indicators of misuse

3. **Selects a policy action**
   Based on the risk assessment:

   * `ALLOW` – normal, non-restricted answer
   * `SAFE_COMPLETE` – high-level, non-actionable, defense-focused answer
   * `REFUSE` – refusal with safe alternatives

4. **Generates a safe response**
   The system **never produces operational or harmful instructions**.
   Instead, it demonstrates how a guardrail can:

   * refuse unsafe requests,
   * redirect users to defensive knowledge,
   * preserve usability for benign queries.

---

## 🏗️ Program Architecture

```
User Query
    ↓
[ Judge ]
  - keyword analysis
  - intent-shift detection
  - explainable risk scoring
    ↓
[ Policy Router ]
  - ALLOW / SAFE_COMPLETE / REFUSE
    ↓
[ Response Generator ]
  - normal answer
  - defensive explanation
  - refusal + safe alternatives
```

---

## 📁 Repository Structure

```
llm-friend-or-foe/
  README.md
  src/
    detector.py        # CLI entry point (judge → answer)
    transforms.py     # Judge logic and intent-shift detection
    responder.py      # Safe response generation
  examples.json       # Example queries
  tests/
    test_detector.py  # Unit tests
```

---

## ▶️ How to Run the Program

### 1️⃣ Requirements

* Python **3.9+**
* `pytest` (for tests)

Install dependencies:

```bash
pip install pytest
```

---

### 2️⃣ Run a Single Query

```bash
python -m src.detector --query "How to secure my home Wi-Fi router?"
```

Example output:

```
=== JUDGE ===
Risk:   LOW
Action: ALLOW
Reasons:
- No risk signals detected.

=== RESPONSE ===
Answer (ALLOW)
I can help with general, non-sensitive information.
...
```

---

### 3️⃣ Run Multiple Example Queries

```bash
python -m src.detector --examples examples.json
```

Each query is evaluated independently and prints:

* detected risk level,
* chosen policy action,
* explanation,
* safe response.

---

### 4️⃣ Run Tests

```bash
pytest -q
```

The tests verify that:

* benign queries are not over-blocked,
* intent-shifted queries are detected,
* defensive framing reduces risk.

---

## 🔐 Security & Ethics Notice

This project is **educational only**.

* No real attack techniques are implemented.
* No step-by-step harmful instructions are generated.
* All examples are framed at a high level or defensive perspective.

The purpose is to **demonstrate LLM security risks and guardrail design**, not to exploit vulnerabilities.

---

## 🎯 Relevance to “LLM – Friend or Foe”

* **Foe**: shows how LLMs can be tricked via intent-shifted prompts
* **Friend**: demonstrates how guardrails can mitigate risks through intent analysis and safe response routing

---