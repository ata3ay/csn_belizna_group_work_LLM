from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Dict, Any, Set


CANDIDATE_TEXT_KEYS = [
    "query",
    "prompt",
    "how_to_prompt",
    "passive_voice_prompt",
    "hypothetical_prompt",
    "third_person_prompt",
    "phenomenon_prompt",
    "past_tense_prompt",
    "nested_prompt",
    "goal",
    "intention_choice_prompt",
]


def _extract_strings(obj: Any, out: List[str]) -> None:
    if obj is None:
        return
    if isinstance(obj, str):
        s = obj.strip()
        if s:
            out.append(s)
        return
    if isinstance(obj, list):
        for x in obj:
            _extract_strings(x, out)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in CANDIDATE_TEXT_KEYS and isinstance(v, (str, list, dict)):
                _extract_strings(v, out)
        return


def load_queries_from_json(path: str | Path) -> List[str]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    raw: List[str] = []
    if isinstance(data, list):
        for item in data:
            _extract_strings(item, raw)
    elif isinstance(data, dict):
        _extract_strings(data, raw)
    else:
        return []

    seen: Set[str] = set()
    uniq: List[str] = []
    for s in raw:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def load_queries_from_dir(dir_path: str | Path) -> Dict[str, List[str]]:
    dir_path = Path(dir_path)
    datasets: Dict[str, List[str]] = {}
    for p in sorted(dir_path.glob("*.json")):
        qs = load_queries_from_json(p)
        if qs:
            datasets[p.name] = qs
    return datasets
