import json
import argparse
from transforms import judge_request
from responder import generate_response


def run_single(query: str) -> None:
    judge = judge_request(query)
    print("=== JUDGE ===")
    print(f"Risk:   {judge.risk_level}")
    print(f"Action: {judge.action}")
    print("Reasons:")
    for r in judge.reasons:
        print(f"- {r}")

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


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardrail pipeline demo (judge-then-answer)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--query", type=str, help="Single user query to evaluate")
    group.add_argument("--examples", type=str, help="Path to JSON examples file")
    args = parser.parse_args()

    if args.query:
        run_single(args.query)
    else:
        run_examples(args.examples)


if __name__ == "__main__":
    main()
