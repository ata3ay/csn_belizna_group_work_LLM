---

# 🛡️ LLM Friend or Foe

## Guardrail Pipeline: Judge-Then-Answer for LLM Safety

---

## 📌 Project Description

This project implements a **guardrail pipeline for Large Language Models (LLMs)** that demonstrates how security risks caused by **intent-shifted prompts** can be detected and mitigated **before** an LLM generates a response.

The system follows the **judge-then-answer** paradigm:

> First analyze the user’s intent and risk level →
> then decide *how* (or *if*) the system should respond.

The project is part of the course topic
**“LLM – Friend or Foe: Security Risks & Defences”** and focuses on **LLM safety, misuse prevention, and defensive design**.

---

## 🎯 Motivation

Modern LLMs can be tricked using **Intent Shift Attacks (ISA)**, where harmful requests are rewritten to look:

* educational,
* historical,
* hypothetical,
* third-person or fictional.

Example:

> “How do criminals usually commit X?”
> instead of
> “How do I commit X?”

This project demonstrates:

* why such prompts are dangerous (**LLM as Foe**),
* how guardrails can reduce risk while preserving usability (**LLM as Friend**).

---

## 🧠 What the Program Does

For every input query, the system:

1. **Analyzes the text**

   * detects intent-shift patterns (person shift, tense shift, hypothetical framing),
   * detects harmful domains (cybercrime, fraud, violence, misinformation, etc.),
   * detects **actionability** (step-by-step / operational intent),
   * detects **evasion and jailbreak attempts**,
   * performs **deobfuscation** (e.g. `b0mb`, `m a k e`).

2. **Assigns a risk level**

   * `LOW` – benign request
   * `MEDIUM` – ambiguous or potentially risky
   * `HIGH` – clearly unsafe or actionable harmful intent

3. **Chooses a policy action**

   * `ALLOW` – normal response
   * `SAFE_COMPLETE` – high-level, defensive, non-actionable response
   * `REFUSE` – refusal with safe alternatives

4. **Generates a safe response**

   * never produces step-by-step or operational harmful instructions,
   * explains *why* a request was flagged (explainable AI).

---

## 🏗️ Architecture (Judge-Then-Answer)

```
User Query
    ↓
[ Judge ]
  - intent-shift detection
  - harmful domain detection
  - actionability analysis
  - evasion / jailbreak detection
  - deobfuscation
    ↓
[ Policy Router ]
  - ALLOW / SAFE_COMPLETE / REFUSE
    ↓
[ Response Generator ]
  - safe response
  - refusal + alternatives
  - defensive explanation
```

---

## 📁 Repository Structure

```
├─ README.md
├─ examples.json
├─ datasets/ # benchmark datasets (AdvBench, AutoDAN, GPTFuzzer, malicious variants)
├─ reports/ # generated reports from dataset evaluation
├─ src/
│ ├─ init.py
│ ├─ detector.py # CLI entry point (single / examples / datasets)
│ ├─ transforms.py # judge: detection + policy decision + structured signals
│ ├─ responder.py # safe response generation
│ └─ dataset_loader.py # loads/normalizes many dataset JSON formats into queries
└─ tests/
└─ test_detector.py # unit tests for key behaviors

---

## ▶️ How to Run the Program

### 1️⃣ Requirements

* Python **3.9+**

Install test dependency (optional but recommended):

```bash
pip install pytest
```

---

### 2️⃣ Run a Single Query

```bash
python -m src.detector --query "How to secure my home Wi-Fi router?"
```

Output includes:

* risk level,
* policy decision,
* detected signals,
* safe response.

---

### 3️⃣ Run Demo Examples

```bash
python -m src.detector --examples examples.json
```

Each example is processed independently.

---

### 4️⃣ Run on a Dataset (Research Mode)

You can evaluate **real benchmark datasets** (e.g. AdvBench, AutoDAN, GPTFuzzer):

```bash
python -m src.detector --dataset advbench_how_to_format.json --out reports/advbench.json
```

This:

* extracts all prompt variants,
* runs the judge on each query,
* outputs statistics and a JSON report.

---

### 5️⃣ Run on a Directory of Datasets

```bash
python -m src.detector --dataset_dir datasets/ --out_dir reports/
```

Generates:

* per-dataset statistics,
* aggregated totals,
* per-file JSON reports.

---

### 6️⃣ Run Tests

```bash
pytest -q
```

Tests verify:

* benign queries are not over-blocked,
* actionable harmful prompts are refused,
* educational/historical prompts are handled safely,
* obfuscated attacks are detected.

---

## 🔐 Safety & Ethics

This project is **educational only**.

* ❌ No real attack instructions are generated
* ❌ No operational guidance for wrongdoing
* ✅ Focus on detection, prevention, and explainability

The system is designed to **study LLM security risks**, not to exploit them.

## 🚀 Possible Future Work

* ML-based classifier (hybrid rules + model)
* LLM-as-a-Judge comparison
* Quantitative evaluation (precision/recall on benchmarks)
* Visualization dashboard

---

## 🎓 Relevance to “LLM – Friend or Foe”

* **Foe:** shows how LLMs can be misused via intent-shifted prompts
* **Friend:** demonstrates how guardrails enable safe and responsible deployment

---