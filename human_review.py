import argparse
import json
from datetime import datetime
from pathlib import Path


INPUT_FILE = "ai_diagnosis_results.json"
LOG_FILE = "human_review_log.json"


def load_json(path, default):
    path = Path(path)

    if not path.exists():
        return default

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def load_ai_results():
    data = load_json(INPUT_FILE, {})

    results = data.get("results", [])

    if not isinstance(results, list):
        raise ValueError(
            f"{INPUT_FILE} does not contain a valid 'results' array."
        )

    return results


def load_review_log():
    data = load_json(
        LOG_FILE,
        {
            "tool": "NetSage AI - Human Review Log",
            "reviewer": "",
            "reviews": []
        }
    )

    if not isinstance(data.get("reviews"), list):
        data["reviews"] = []

    return data


def get_existing_reviews(log):
    return {
        str(review.get("case_id")): review
        for review in log.get("reviews", [])
    }


def print_case(case):
    case_id = case.get("case_id", "Unknown")
    diagnosis = case.get("diagnosis") or {}
    evaluation = case.get("evaluation") or {}
    rule_findings = case.get("rule_checker_findings") or []

    print("\n" + "=" * 80)
    print(f"CASE {case_id}")
    print("=" * 80)

    print("\nAI ROOT CAUSE:")
    print(diagnosis.get("root_cause", "N/A"))

    print("\nAI CONFIDENCE:")
    print(diagnosis.get("confidence", "N/A"))

    print("\nAI EVIDENCE:")
    for evidence in diagnosis.get("evidence", []):
        print(f"  - {evidence}")

    print("\nNEXT COMMAND:")
    print(diagnosis.get("next_command", "N/A"))

    print("\nFIX STEPS:")
    for i, step in enumerate(diagnosis.get("fix_steps", []), start=1):
        print(f"  {i}. {step}")

    print("\nRULE CHECKER FINDINGS:")
    if rule_findings:
        for finding in rule_findings:
            print(f"  - {finding.get('rule')}: {finding.get('fault')}")
    else:
        print("  None")

    print("\nAUTOMATED COMPARISON:")
    print(f"  AI vs expected: {evaluation.get('status', 'N/A')}")


def prompt_multiline(label):
    print(f"\n{label}")
    print("(Press Enter on an empty line to finish.)")

    lines = []

    while True:
        line = input("> ")

        if line == "":
            break

        lines.append(line)

    return lines


def review_case(case, existing_review=None):
    print_case(case)

    if existing_review:
        print("\nExisting review found for this case.")
        print(f"Current status: {existing_review.get('status', 'N/A')}")
        print("Press R to review again or Enter to keep the existing review.")

        choice = input("> ").strip().lower()

        if choice != "r":
            return existing_review

    while True:
        print("\nHuman review decision:")
        print("  A = Accepted")
        print("  E = Edited")
        print("  R = Rejected")

        decision = input("> ").strip().lower()

        if decision in {"a", "e", "r"}:
            break

        print("Please enter A, E, or R.")

    status_map = {
        "a": "Accepted",
        "e": "Edited",
        "r": "Rejected"
    }

    status = status_map[decision]

    reviewer_reason = input(
        "\nReason for decision (one line): "
    ).strip()

    corrected_root_cause = ""
    corrected_fix_steps = []
    correction_summary = ""

    if status == "Edited":
        corrected_root_cause = input(
            "Corrected root cause: "
        ).strip()

        corrected_fix_steps = prompt_multiline(
            "Corrected fix steps:"
        )

        correction_summary = input(
            "\nWhat specifically was wrong with the AI answer? "
        ).strip()

    elif status == "Rejected":
        rejection_reason = input(
            "Why was the AI diagnosis rejected? "
        ).strip()

        correction_summary = rejection_reason

    return {
        "case_id": str(case.get("case_id")),
        "status": status,
        "reviewed_at": datetime.now().isoformat(timespec="seconds"),
        "reviewer_reason": reviewer_reason,
        "ai_root_cause": (
            (case.get("diagnosis") or {}).get("root_cause", "")
        ),
        "corrected_root_cause": corrected_root_cause,
        "corrected_fix_steps": corrected_fix_steps,
        "correction_summary": correction_summary
    }


def print_summary(log, total_cases):
    reviews = log.get("reviews", [])

    accepted = sum(
        review.get("status") == "Accepted"
        for review in reviews
    )

    edited = sum(
        review.get("status") == "Edited"
        for review in reviews
    )

    rejected = sum(
        review.get("status") == "Rejected"
        for review in reviews
    )

    print("\n" + "=" * 80)
    print("NetSage AI - HUMAN REVIEW SUMMARY")
    print("=" * 80)
    print(f"AI cases available       : {total_cases}")
    print(f"Cases reviewed           : {len(reviews)}")
    print(f"Accepted                 : {accepted}")
    print(f"Edited                   : {edited}")
    print(f"Rejected                 : {rejected}")
    print(f"AI corrections recorded  : {edited + rejected}")
    print("=" * 80)

    if edited < 5:
        print(
            f"\nResponsible AI note: {5 - edited} more AI-corrected "
            "case(s) are needed to reach the project's target of at least 5."
        )
    else:
        print(
            "\nResponsible AI target reached: at least 5 edited AI responses "
            "are recorded."
        )


def main():
    parser = argparse.ArgumentParser(
        description="NetSage AI - Human Review Tool"
    )

    parser.add_argument(
        "--cases",
        nargs="+",
        type=int,
        help="Only review selected case numbers, e.g. --cases 10 11 12"
    )

    parser.add_argument(
        "--reviewer",
        default="",
        help="Reviewer name or identifier"
    )

    args = parser.parse_args()

    try:
        ai_results = load_ai_results()
    except Exception as exc:
        print(f"ERROR loading AI results: {exc}")
        return

    if args.cases:
        requested = set(args.cases)

        ai_results = [
            result
            for result in ai_results
            if int(result.get("case_id")) in requested
        ]

        if not ai_results:
            print("ERROR: None of the requested cases were found.")
            return

    review_log = load_review_log()

    if args.reviewer:
        review_log["reviewer"] = args.reviewer

    existing_reviews = get_existing_reviews(review_log)

    print("=" * 80)
    print("NetSage AI - HUMAN REVIEW")
    print("=" * 80)
    print(
        f"Cases available for review: {len(ai_results)}"
    )
    print(
        f"Existing review records: {len(existing_reviews)}"
    )

    reviewed_results = []

    for case in ai_results:
        case_id = str(case.get("case_id"))

        try:
            review = review_case(
                case,
                existing_reviews.get(case_id)
            )

            existing_reviews[case_id] = review
            reviewed_results.append(review)

            review_log["reviews"] = [
                existing_reviews[key]
                for key in sorted(
                    existing_reviews,
                    key=lambda value: int(value)
                )
            ]

            save_json(LOG_FILE, review_log)

            print(
                f"\nSaved human review for Case {case_id}."
            )

        except KeyboardInterrupt:
            print("\nReview interrupted. Progress already saved.")
            break

    print_summary(review_log, len(load_ai_results()))


if __name__ == "__main__":
    main()
