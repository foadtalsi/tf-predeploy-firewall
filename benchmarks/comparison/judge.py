"""Decide, for every case and tool, whether the tool caught the labelled problem.

A tool catches a positive case when it reports, on the case's target, a finding
whose rule is about the labelled problem. The rules that count are listed below
per problem family, by tool; they were chosen by reading each rule's title.
On a near miss, the same rules on the same target are a false alarm.

Findings about anything else (logging, KMS keys, backups, tags) are not scored
either way; they are counted separately as alert volume.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

BENCH = Path(__file__).resolve().parent

# Rule ids that speak to each problem family, per tool. A regex over the rule id.
MATCHES = {
    "destroy": {
        # Only a tool that reads the previous revision can say that a change destroys.
        "ours": r"^force_new_change$",
    },
    "invalid-argument": {
        "ours": r"^unknown_attribute$",
        "validate": r"^Unsupported (argument|block type)",
        "tflint": r"^(aws|azurerm)_.*(invalid|unsupported|deprecated)",
    },
    "secret": {
        "ours": r"^(tutorial_pattern|hardcoded_credential|credential_value_.*)$",
        "checkov": r"^(CKV_SECRET_\d+|CKV_AWS_41|CKV_AWS_46|CKV_AWS_149)$",
        # Trivy's secret scanner names its rules in lower case (aws-access-key-id, github-pat).
        "trivy": r"^[a-z][a-z0-9-]+$",
        "tflint": r"^aws_provider_hardcoded_credentials$",
    },
    "exposure": {
        "ours": r"^(tutorial_pattern|public_exposure)$",
        "checkov": r"^(CKV_AWS_(17|20|24|25|53|54|55|56|57|79|88|260|277)|CKV_GCP_(2|3|28|29|106))$",
        "trivy": r"^(AWS-0(028|086|087|091|092|093|107|180|104)|GCP-00(01|27|71|72))$",
        "tflint": r"^aws_.*(public|imds|metadata)",
    },
    "iam": {
        "ours": r"^(permissive_iam|iam_.*)$",
        "checkov": r"^CKV2?_AWS_(1|40|60|62|63|274|286|287|288|289|290|355|356)$",
        "trivy": r"^AWS-0(057|342|143)$",
    },
    "encryption": {
        "ours": r"^encryption_.*$",
        "checkov": r"^CKV_AWS_(3|16|189)$",
        "trivy": r"^AWS-00(26|79|80)$",
    },
    "data-loss": {
        # Neither Checkov nor Trivy has a rule about skip_final_snapshot or force_destroy.
        "ours": r"^(missing_lifecycle|skip_final_snapshot|s3_force_destroy|destroy_deletes_contents)$",
    },
    "supply-chain": {
        "ours": r"^unpinned_version$",
        "checkov": r"^CKV_TF_(1|2)$",
        "tflint": r"^terraform_module_(pinned_source|version)$",
    },
}

# The case where the protection a resource had is removed: any finding that says the
# resource is no longer protected from deletion counts, whichever tool reports it.
GUARD_RULES = {
    "ours": r"^missing_lifecycle$",
    "checkov": r"^CKV_AWS_139$",
    "trivy": r"^AWS-0343$",
    "tflint": r"_missing_prevent_destroy$",
}

# Messages that make a finding about one rule family when its id is shared by several.
MESSAGE_NEEDS = {
    ("ours", "secret"): r"(?i)credential|secret|hardcoded",
    ("ours", "exposure"): r"(?i)internet|public|IMDS|anyone",
    ("ours", "data-loss"): r"(?i)skip_final_snapshot|force_destroy",
}


def counts(label, tool, finding):
    category = label["category"]
    if label["name"] == "prevent-destroy-removed":
        pattern = GUARD_RULES.get(tool)
    else:
        pattern = MATCHES[category].get(tool)
    if not pattern or not finding["on_target"] or not re.search(pattern, finding["id"]):
        return False
    needs = MESSAGE_NEEDS.get((tool, category))
    return not needs or re.search(needs, finding["message"]) is not None


def main():
    results = json.loads((BENCH / "results.json").read_text())
    labels = json.loads((BENCH / "corpus/labels.json").read_text())
    tools = ["ours", "validate", "tflint", "checkov", "trivy"]
    verdicts = {}
    for label in labels:
        row = {}
        for tool in tools:
            run = results[label["name"]].get(tool)
            if run is None:
                continue
            hits = [finding for finding in run["findings"] if counts(label, tool, finding)]
            row[tool] = {
                "hit": bool(hits),
                "ids": sorted({finding["id"] for finding in hits}),
                "alerts": len(run["findings"]),
                "seconds": run["seconds"],
            }
        verdicts[label["name"]] = row
    (BENCH / "verdicts.json").write_text(json.dumps(verdicts, indent=1))

    if "--cases" in sys.argv:
        for label in labels:
            marks = "  ".join(
                f"{tool}:{'Y' if verdicts[label['name']].get(tool, {}).get('hit') else '.'}"
                for tool in tools
            )
            print(f"{label['kind'][:4]} {label['category']:17} {label['name']:38} {marks}")

    summary = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for label in labels:
        for tool in tools:
            verdict = verdicts[label["name"]].get(tool)
            if verdict is None:
                continue
            key = label["category"] if label["kind"] == "positive" else "near-miss"
            summary[key][tool][0] += verdict["hit"]
            summary[key][tool][1] += 1
    print(f"\n{'':18}" + "".join(f"{tool:>10}" for tool in tools))
    for key, row in summary.items():
        print(f"{key:18}" + "".join(f"{row[tool][0]:>6}/{row[tool][1]:<3}" for tool in tools))
    alerts = {
        tool: sum(verdicts[label["name"]].get(tool, {}).get("alerts", 0) for label in labels)
        for tool in tools
    }
    print(f"{'alerts (any kind)':18}" + "".join(f"{alerts[tool]:>10}" for tool in tools))


if __name__ == "__main__":
    main()
