import json
import os
import re
import sys
from pathlib import Path
import argparse

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None


PROMPT_FILE = "diagnose_prompt.md"
CASES_FILE = "cases.json"
OUTPUT_FILE = "ai_diagnosis_results.json"

REQUIRED_FIELDS = {
    "case_id",
    "root_cause",
    "confidence",
    "evidence",
    "next_command",
    "fix_steps",
    "rule_checker_agreement",
    "human_review_required",
}


def load_cases(path):
    """Load the original project case format: a top-level JSON array."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(
            "cases.json must contain a JSON array of cases. "
            "Use the same cases.json format validated by rule_checker.py v2."
        )

    return data


def load_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def run_rule_checker_for_case(case):
    """Use the existing rule checker as evidence for the AI prompt."""
    try:
        import rule_checker
    except ImportError:
        return []

    result = rule_checker.check_case(case)
    findings = []

    for finding in result.get("rule_findings", []):
        findings.append({
            "rule": finding.get("rule"),
            "fault": finding.get("fault"),
            "confidence": finding.get("confidence"),
            "evidence": finding.get("evidence"),
            "next_command": finding.get("next_command"),
            "expected_match": finding.get("expected_match"),
        })

    return findings


def build_case_input(case, rule_findings):
    """
    Deliberately omit expected_fault from the model input.
    This prevents the model from simply copying the known answer.
    """
    payload = {
        "case_id": str(case.get("Cases", "")),
        "symptom": case.get("symptom", ""),
        "topology_note": case.get("topology note", case.get("topology_note", "")),
        "outputs": case.get("outputs", ""),
        "rule_checker_findings": rule_findings,
    }
    return payload


def build_user_prompt(case_input):
    return (
        "Analyze the following networking case using the diagnosis instructions. "
        "Return valid JSON only.\n\n"
        "CASE INPUT:\n"
        + json.dumps(case_input, indent=2, ensure_ascii=False)
    )


def normalize(text):
    return re.sub(r"\s+", " ", str(text).lower()).strip()


def compare_with_expected(root_cause, expected_fault):
    """Simple local evaluation; expected_fault never goes to the model."""
    if not expected_fault:
        return {
            "status": "not_available",
            "reason": "No expected fault supplied for evaluation."
        }

    root = normalize(root_cause)
    expected = normalize(expected_fault)

    # Strong concepts commonly present in these project cases.
    groups = [
        ["duplicate", "ip"],
        ["native", "vlan"],
        ["port", "security"],
        ["subinterface", "vlan"],
        ["parent", "interface", "down"],
        ["etherchannel", "protocol"],
        ["etherchannel", "vlan"],
        ["dhcp", "relay"],
        ["return", "route"],
        ["static", "route"],
        ["administrative", "distance"],
        ["ospf", "hello"],
        ["ospf", "area"],
        ["passive", "interface"],
        ["portfast", "trunk"],
        ["acl", "direction"],
        ["established", "tcp"],
        ["dns", "dhcp", "udp"],
        ["nat", "inside"],
        ["nat", "subnet"],
        ["static", "nat"],
    ]

    for group in groups:
        if all(word in root for word in group) and any(word in expected for word in group):
            return {
                "status": "agree",
                "reason": f"AI root cause matches the expected concept: {'/'.join(group)}."
            }

    # Token overlap fallback.
    stop = {
        "the", "a", "an", "is", "are", "was", "were", "to", "of", "on",
        "for", "and", "with", "in", "from", "configured", "missing", "incorrect",
        "network", "issue", "problem"
    }
    root_tokens = set(re.findall(r"[a-z0-9.-]+", root)) - stop
    expected_tokens = set(re.findall(r"[a-z0-9.-]+", expected)) - stop
    overlap = root_tokens & expected_tokens

    if len(overlap) >= 3:
        return {
            "status": "agree",
            "reason": "AI and expected fault share multiple diagnostic terms."
        }

    return {
        "status": "disagree",
        "reason": "AI root cause does not sufficiently match the expected fault."
    }


def validate_diagnosis(data, case_id):
    if not isinstance(data, dict):
        raise ValueError("AI response is not a JSON object.")

    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ValueError(
            "AI response is missing required field(s): "
            + ", ".join(sorted(missing))
        )

    data["case_id"] = str(data["case_id"])

    if data["confidence"] not in {"high", "medium", "low"}:
        raise ValueError("confidence must be high, medium, or low.")

    if data["rule_checker_agreement"] not in {
        "agree", "disagree", "not_available"
    }:
        raise ValueError(
            "rule_checker_agreement must be agree, disagree, or not_available."
        )

    if not isinstance(data["evidence"], list):
        raise ValueError("evidence must be a JSON array.")

    if not isinstance(data["fix_steps"], list):
        raise ValueError("fix_steps must be a JSON array.")

    if data["human_review_required"] is not True:
        raise ValueError("human_review_required must always be true.")

    return data


def extract_json(text):
    """Extract JSON if the model wrapped it in a markdown fence."""
    text = text.strip()

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)

    return json.loads(text)


def call_model(client, model, system_prompt, user_prompt):
    """Call Gemini with schema-constrained JSON output."""
    full_prompt = system_prompt + "\n\n" + user_prompt

    schema = {
        "type": "object",
        "properties": {
            "case_id": {"type": "string"},
            "root_cause": {"type": "string"},
            "confidence": {
                "type": "string",
                "enum": ["high", "medium", "low"]
            },
            "evidence": {
                "type": "array",
                "items": {"type": "string"}
            },
            "next_command": {"type": "string"},
            "fix_steps": {
                "type": "array",
                "items": {"type": "string"}
            },
            "rule_checker_agreement": {
                "type": "string",
                "enum": ["agree", "disagree", "not_available"]
            },
            "human_review_required": {"type": "boolean"}
        },
        "required": [
            "case_id",
            "root_cause",
            "confidence",
            "evidence",
            "next_command",
            "fix_steps",
            "rule_checker_agreement",
            "human_review_required"
        ]
    }

    response = client.models.generate_content(
        model=model,
        contents=full_prompt,
        config=types.GenerateContentConfig(
            temperature=0,
            response_mime_type="application/json",
            response_schema=schema,
        ),
    )

    content = response.text

    if not content:
        raise ValueError("Gemini returned an empty response.")

    return extract_json(content)


def process_cases(cases, system_prompt, client, model):
    results = []

    for index, case in enumerate(cases, start=1):
        case_id = str(case.get("Cases", index))
        print(f"Processing Case {case_id} ({index}/{len(cases)})...")

        rule_findings = run_rule_checker_for_case(case)
        case_input = build_case_input(case, rule_findings)
        user_prompt = build_user_prompt(case_input)

        try:
            diagnosis = call_model(client, model, system_prompt, user_prompt)
            diagnosis = validate_diagnosis(diagnosis, case_id)

            # Keep the model's own agreement field, but verify it locally.
            local_rule_agreement = "not_available"
            if rule_findings:
                local_rule_agreement = (
                    "agree"
                    if any(f.get("expected_match") for f in rule_findings)
                    else "disagree"
                )

            diagnosis["rule_checker_agreement"] = local_rule_agreement

            evaluation = compare_with_expected(
                diagnosis["root_cause"],
                case.get("expected fault", "")
            )

            results.append({
                "case_id": case_id,
                "diagnosis": diagnosis,
                "evaluation": evaluation,
                "rule_checker_findings": rule_findings,
                "status": "success",
            })

            print(f"  AI root cause: {diagnosis['root_cause']}")
            print(f"  Agreement: {evaluation['status']}")

        except Exception as exc:
            results.append({
                "case_id": case_id,
                "diagnosis": None,
                "evaluation": {
                    "status": "error",
                    "reason": str(exc),
                },
                "rule_checker_findings": rule_findings,
                "status": "error",
            })
            print(f"  ERROR: {exc}")

    return results


def save_results(results, output_path):
    summary = {
        "tool": "NetSage AI - AI Diagnosis Runner",
        "total_cases": len(results),
        "successful_diagnoses": sum(r["status"] == "success" for r in results),
        "failed_diagnoses": sum(r["status"] == "error" for r in results),
        "ai_rule_agreements": sum(
            r.get("diagnosis", {}).get("rule_checker_agreement") == "agree"
            for r in results
            if r["status"] == "success"
        ),
        "expected_fault_agreements": sum(
            r.get("evaluation", {}).get("status") == "agree"
            for r in results
        ),
        "results": results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)


def print_summary(results):
    total = len(results)
    success = sum(r["status"] == "success" for r in results)
    errors = total - success
    agreements = sum(
        r.get("evaluation", {}).get("status") == "agree"
        for r in results
    )

    print("\n" + "=" * 80)
    print("NetSage AI - AI DIAGNOSIS RUNNER")
    print("=" * 80)
    print(f"Total cases             : {total}")
    print(f"Successful diagnoses    : {success}")
    print(f"Failed diagnoses        : {errors}")
    print(f"AI vs expected matches  : {agreements}")

    if total:
        print(f"AI agreement rate       : {(agreements / total) * 100:.2f}%")

    print("=" * 80)



def parse_case_numbers(values):
    """
    Accept both:
        --cases 28 29 30
    and:
        --cases 28,29,30
    """
    case_numbers = []

    for value in values:
        for part in str(value).split(","):
            part = part.strip()

            if not part:
                continue

            try:
                case_numbers.append(int(part))
            except ValueError:
                raise ValueError(
                    f"Invalid case number: '{part}'. "
                    "Use values such as 28 29 30 or 28,29,30."
                )

    return sorted(set(case_numbers))


def load_existing_results(path):
    """
    Load the existing result file.

    The current Gemini runner format is:
        {
            "results": [
                {
                    "case_id": "...",
                    "diagnosis": {...},
                    "evaluation": {...},
                    ...
                }
            ]
        }

    This function also tolerates an older result format that may use
    'case' instead of 'case_id'.
    """
    if not Path(path).exists():
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return []

        results = data.get("results", [])
        return results if isinstance(results, list) else []

    except (json.JSONDecodeError, OSError) as exc:
        print(f"WARNING: Could not load existing results: {exc}")
        return []


def merge_results(existing_results, new_results):
    """
    Merge new results into existing results by case number.

    Existing cases are preserved unless that same case was just processed.
    """
    by_case = {}

    for result in existing_results:
        case_id = result.get("case_id", result.get("case"))

        if case_id is None:
            continue

        try:
            by_case[int(case_id)] = result
        except (TypeError, ValueError):
            continue

    for result in new_results:
        case_id = result.get("case_id", result.get("case"))

        if case_id is None:
            continue

        try:
            by_case[int(case_id)] = result
        except (TypeError, ValueError):
            continue

    return [
        by_case[case_number]
        for case_number in sorted(by_case)
    ]


def save_merged_results(results, output_path):
    successful = [
        result
        for result in results
        if result.get("status") == "success"
    ]

    failed = [
        result
        for result in results
        if result.get("status") == "error"
    ]

    expected_agreements = [
        result
        for result in successful
        if result.get("evaluation", {}).get("status") == "agree"
    ]

    rule_agreements = [
        result
        for result in successful
        if result.get("diagnosis", {}).get("rule_checker_agreement") == "agree"
    ]

    agreement_rate = (
        len(expected_agreements) / len(successful) * 100
        if successful
        else 0
    )

    output = {
        "tool": "NetSage AI - AI Diagnosis Runner",
        "total_cases": len(results),
        "successful_diagnoses": len(successful),
        "failed_diagnoses": len(failed),
        "ai_rule_agreements": len(rule_agreements),
        "expected_fault_agreements": len(expected_agreements),
        "ai_agreement_rate": round(agreement_rate, 2),
        "results": results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    return output


def main():
    parser = argparse.ArgumentParser(
        description="NetSage AI - Gemini AI Diagnosis Runner"
    )

    parser.add_argument(
        "--cases",
        nargs="+",
        help=(
            "Only process the specified case numbers. "
            "Examples: --cases 28 29 30 OR --cases 28,29,30"
        ),
    )

    args = parser.parse_args()

    cases_file = CASES_FILE
    prompt_file = PROMPT_FILE
    results_file = OUTPUT_FILE

    # --------------------------------------------------------
    # Validate Gemini SDK / API key
    # --------------------------------------------------------
    if genai is None or types is None:
        print(
            "ERROR: google-genai is not installed. "
            "Run: pip install -U google-genai"
        )
        return

    if not os.getenv("GEMINI_API_KEY"):
        print(
            "ERROR: GEMINI_API_KEY is not set in this terminal."
        )
        return

    # --------------------------------------------------------
    # Load cases and prompt
    # --------------------------------------------------------
    try:
        cases = load_cases(cases_file)
        system_prompt = load_text(prompt_file)
    except Exception as exc:
        print(f"ERROR loading project files: {exc}")
        return

    # --------------------------------------------------------
    # Select cases
    # --------------------------------------------------------
    try:
        requested_case_numbers = (
            parse_case_numbers(args.cases)
            if args.cases
            else None
        )
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return

    if requested_case_numbers:
        requested_set = set(requested_case_numbers)

        cases_to_process = [
            case
            for case in cases
            if int(case.get("Cases")) in requested_set
        ]

        found_set = {
            int(case.get("Cases"))
            for case in cases_to_process
        }

        missing = requested_set - found_set

        if missing:
            print(
                "WARNING: These case numbers were not found: "
                + ", ".join(map(str, sorted(missing)))
            )

        if not cases_to_process:
            print("ERROR: None of the requested cases were found.")
            return
    else:
        cases_to_process = cases

    selected_case_ids = [
        int(case.get("Cases"))
        for case in cases_to_process
    ]

    print(
        f"Running {len(cases_to_process)} case(s): "
        + ", ".join(map(str, selected_case_ids))
    )

    # --------------------------------------------------------
    # Gemini client
    # --------------------------------------------------------
    client = genai.Client()
    model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

    # --------------------------------------------------------
    # Load existing results BEFORE processing selected cases
    # --------------------------------------------------------
    existing_results = load_existing_results(results_file)

    if existing_results:
        print(
            f"Loaded {len(existing_results)} existing result(s) "
            f"from {results_file}"
        )

    # --------------------------------------------------------
    # Process only the selected cases
    #
    # IMPORTANT:
    # process_cases() is the existing diagnosis function in this
    # file. The previous main() incorrectly called diagnose_case().
    # --------------------------------------------------------
    new_results = process_cases(
        cases_to_process,
        system_prompt,
        client,
        model,
    )

    # --------------------------------------------------------
    # Merge:
    #   - preserve all previous cases
    #   - replace/add only cases just processed
    # --------------------------------------------------------
    merged_results = merge_results(
        existing_results,
        new_results,
    )

    # --------------------------------------------------------
    # Save final merged output
    # --------------------------------------------------------
    save_merged_results(
        merged_results,
        results_file,
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------
    successful = [
        result
        for result in merged_results
        if result.get("status") == "success"
    ]

    failed = [
        result
        for result in merged_results
        if result.get("status") == "error"
    ]

    agreements = [
        result
        for result in successful
        if result.get("evaluation", {}).get("status") == "agree"
    ]

    print("\n" + "=" * 80)
    print("NetSage AI - AI DIAGNOSIS RUNNER")
    print("=" * 80)
    print(f"Total cases             : {len(merged_results)}")
    print(f"Successful diagnoses    : {len(successful)}")
    print(f"Failed diagnoses        : {len(failed)}")
    print(f"AI vs expected matches  : {len(agreements)}")

    if successful:
        print(
            f"AI agreement rate       : "
            f"{(len(agreements) / len(successful)) * 100:.2f}%"
        )
    else:
        print("AI agreement rate       : 0.00%")

    print("=" * 80)
    print(f"\nResults saved to: {results_file}")


if __name__ == "__main__":
    main()