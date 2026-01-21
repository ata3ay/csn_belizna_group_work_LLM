import json
import argparse
from pathlib import Path

from src.transforms import judge_request
from src.responder import generate_response
from src.dataset_loader import load_queries_from_json, load_queries_from_dir


def run_single(query: str) -> None:
    judge = judge_request(query)
    print("=== JUDGE ===")
    print(f"Risk:   {judge.risk_level}")
    print(f"Action: {judge.action}")

    print("Reasons:")
    for r in judge.reasons:
        print(f"- {r}")

    print("Signals:")
    print(json.dumps(getattr(judge, "signals", {}) or {}, ensure_ascii=False, indent=2))

    print("\n=== RESPONSE ===")
    print(generate_response(query, judge))


def run_examples(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for idx, item in enumerate(data, start=1):
        query = item.get("query", "").strip()
        if not query:
            continue
        print("\n" + "=" * 60)
        print(f"Example #{idx}")
        run_single(query)


def run_dataset_file(dataset_path: str, out_path: str | None) -> None:
    queries = load_queries_from_json(dataset_path)

    results = []
    counts = {}

    for q in queries:
        r = judge_request(q)
        counts[str(r.action)] = counts.get(str(r.action), 0) + 1
        results.append(
            {
                "query": q,
                "action": str(r.action),
                "risk": str(r.risk_level),
                "signals": getattr(r, "signals", {}) or {},
                "reasons": r.reasons,
            }
        )

    print("=== DATASET STATS ===")
    print(json.dumps(counts, ensure_ascii=False, indent=2))

    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"Saved report to: {out_path}")


def run_dataset_dir(dataset_dir: str, out_dir: str) -> None:
    datasets = load_queries_from_dir(dataset_dir)
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    grand_counts = {}

    for name, queries in datasets.items():
        results = []
        counts = {}

        for q in queries:
            r = judge_request(q)
            counts[str(r.action)] = counts.get(str(r.action), 0) + 1
            results.append(
                {
                    "query": q,
                    "action": str(r.action),
                    "risk": str(r.risk_level),
                    "signals": getattr(r, "signals", {}) or {},
                    "reasons": r.reasons,
                }
            )

        # print per-file stats
        print("\n" + "=" * 60)
        print(f"Dataset: {name}")
        print(json.dumps(counts, ensure_ascii=False, indent=2))

        # aggregate
        for k, v in counts.items():
            grand_counts[k] = grand_counts.get(k, 0) + v

        # write report
        out_path = str(Path(out_dir) / f"{name}.report.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 60)
    print("=== TOTAL STATS (all datasets) ===")
    print(json.dumps(grand_counts, ensure_ascii=False, indent=2))
    print(f"Reports saved to: {out_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardrail pipeline demo (judge-then-answer)")
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("--query", type=str, help="Single user query to evaluate")
    group.add_argument("--examples", type=str, help="Path to JSON examples file")

    # NEW:
    group.add_argument("--dataset", type=str, help="Path to ANY dataset JSON (AdvBench/AutoDAN/GPTFuzzer/...)")
    group.add_argument("--dataset_dir", type=str, help="Directory with many dataset JSON files")

    parser.add_argument("--out", type=str, default=None, help="Output report JSON (for --dataset)")
    parser.add_argument("--out_dir", type=str, default="reports", help="Output dir (for --dataset_dir)")

    args = parser.parse_args()

    if args.query:
        run_single(args.query)
    elif args.examples:
        run_examples(args.examples)
    elif args.dataset:
        run_dataset_file(args.dataset, args.out)
    else:
        run_dataset_dir(args.dataset_dir, args.out_dir)


if __name__ == "__main__":
    main()
