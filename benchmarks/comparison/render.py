"""Write the benchmark section of the landing page from the benchmark's own results.

The HTML is generated rather than typed so that no number on the page is copied by hand.
It replaces whatever sits between the BENCHMARK markers in the page given as argument.
"""

import json
import sys
from html import escape
from pathlib import Path

BENCH = Path(__file__).resolve().parent
INDEX = Path(sys.argv[1])

TOOLS = [
    ("ours", "This scanner"),
    ("validate", "terraform validate"),
    ("tflint", "TFLint"),
    ("checkov", "Checkov"),
    ("trivy", "Trivy"),
]
FAMILIES = [
    ("destroy", "A change that destroys data on apply"),
    ("invalid-argument", "An argument that does not exist"),
    ("secret", "A secret written into the repository"),
    ("exposure", "Something opened to the internet"),
    ("iam", "IAM that grants everything"),
    ("encryption", "Encryption switched off"),
    ("data-loss", "Nothing kept after a destroy"),
    ("supply-chain", "A module that can change under you"),
]
REPOSITORY_NAMES = {
    "terraform-aws-eks": "terraform-aws-modules/eks",
    "terraform-aws-rds": "terraform-aws-modules/rds",
    "terraform-aws-s3-bucket": "terraform-aws-modules/s3-bucket",
    "terraform-aws-vpc": "terraform-aws-modules/vpc",
    "terraform-azurerm-avm-res-containerservice-managedcluster": "Azure/avm-res-containerservice-managedcluster",
    "terraform-google-kubernetes-engine": "terraform-google-modules/kubernetes-engine",
}
# What went wrong for this scanner, in one sentence each, for every case it got wrong.
WHAT_WENT_WRONG = {
    "security-group-nested-typo": (
        "<code>cidr_block</code> inside a security group's <code>ingress</code> was not reported.",
        "The AWS provider declares <code>ingress</code> as an attribute rather than a block, so the "
        "schema the scanner carried had nothing to check inside it."),
    "provider-access-keys": (
        "AWS keys written in the <code>provider</code> block were not reported.",
        "The scanner did not read <code>provider</code> blocks."),
    "cloud-run-secret-reference": (
        "The name of a Secret Manager secret was reported as a hardcoded password.",
        "Any literal under an argument named <code>secret</code> was treated as one, including the "
        "reference Cloud Run asks for."),
    "efs-creation-token": (
        "EFS's <code>creation_token</code> was reported as a hardcoded credential.",
        "The name ends in <code>_token</code>; the value is an idempotency key."),
}


def us(tool):
    return ' class="us"' if tool == "ours" else ""


def score_cell(tool, caught, total):
    share = round(100 * caught / total) if total else 0
    return (f'<td{us(tool)}><span class="score">{caught}<small>/{total}</small></span>'
            f'<span class="meter" aria-hidden="true"><i style="width:{share}%"></i></span></td>')


def main():
    labels = json.loads((BENCH / "corpus/labels.json").read_text())
    verdicts = json.loads((BENCH / "verdicts.json").read_text())
    repositories = json.loads((BENCH / "repos.json").read_text())
    versions = json.loads((BENCH / "versions.json").read_text())
    positives = [label for label in labels if label["kind"] == "positive"]
    near_misses = [label for label in labels if label["kind"] == "near-miss"]

    def caught(tool, cases):
        return sum(verdicts[label["name"]][tool]["hit"] for label in cases)

    body = []
    for family, title in FAMILIES:
        cases = [label for label in positives if label["category"] == family]
        cells = "".join(score_cell(tool, caught(tool, cases), len(cases)) for tool, _ in TOOLS)
        body.append(f"          <tr><th scope=\"row\">{title}</th>{cells}</tr>")

    total = "".join(score_cell(tool, caught(tool, positives), len(positives)) for tool, _ in TOOLS)
    false_alarms = "".join(f"<td{us(tool)}>{caught(tool, near_misses)}</td>" for tool, _ in TOOLS)
    alerts = "".join(
        f"<td{us(tool)}>{sum(verdicts[label['name']][tool]['alerts'] for label in labels):,}</td>"
        for tool, _ in TOOLS)
    needs = {
        "ours": "nothing",
        "validate": "<code>terraform init</code>: providers and modules downloaded",
        "tflint": "<code>tflint --init</code> for its rulesets",
        "checkov": "nothing",
        "trivy": "nothing",
    }
    needs_row = "".join(f"<td{us(tool)}>{needs[tool]}</td>" for tool, _ in TOOLS)
    head = "".join(f'<th scope="col"{us(tool)}>{name}</th>' for tool, name in TOOLS)

    timed = [(tool, name) for tool, name in TOOLS if tool != "validate"]
    speed_head = "".join(f'<th scope="col"{us(tool)}>{name}</th>' for tool, name in timed)
    speed_rows = []
    for repository, timings in repositories.items():
        cells = "".join(f"<td{us(tool)}>{timings[tool]['seconds']:.1f}&nbsp;s</td>" for tool, _ in timed)
        size = f"{timings['tf_files']} files, {timings['tf_lines']:,} lines"
        speed_rows.append(
            f"          <tr><th scope=\"row\">{escape(REPOSITORY_NAMES.get(repository, repository))}"
            f"<span class=\"repo-size\">{size}</span></th>{cells}</tr>")

    wrong = [label for label in positives if not verdicts[label["name"]]["ours"]["hit"]]
    wrong += [label for label in near_misses if verdicts[label["name"]]["ours"]["hit"]]
    # The run that found them: the cases the previous release got wrong stay listed, with the
    # release that fixed them, so a clean score is not read as a corpus fitted after the fact.
    previous = json.loads((BENCH / "verdicts-1.5.0.json").read_text())
    fixed = [label for label in positives if not previous[label["name"]]["ours"]["hit"]
             and verdicts[label["name"]]["ours"]["hit"]]
    fixed += [label for label in near_misses if previous[label["name"]]["ours"]["hit"]
              and not verdicts[label["name"]]["ours"]["hit"]]
    if wrong:
        wrong_title = "What this scanner got wrong"
        wrong_lead = ""
    else:
        wrong, wrong_title = fixed, "What this benchmark found in this scanner"
        wrong_lead = (f"<p>Version 1.5.0 got {len(fixed)} of these pull requests wrong. "
                      f"{versions['ours']} fixes all {len(fixed)}, and the cases stay in the corpus "
                      "so a regression would show here.</p>")
    wrong_items = "\n".join(
        f"            <li><strong>{WHAT_WENT_WRONG[label['name']][0]}</strong> "
        f"{WHAT_WENT_WRONG[label['name']][1]}</li>" for label in wrong)

    section = f'''<!-- BENCHMARK:START: generated by the comparison benchmark's render.py, do not edit by hand -->
  <section id="benchmark" class="band">
    <div class="wrap">
      <div class="sec-head">
        <h2>{len(labels)} pull requests, five tools, the same files.</h2>
        <p>
          {len(positives)} of the pull requests each carry one known problem. The other
          {len(near_misses)} are correct changes that look like one: a rename that updates in place,
          a password read from a secret store, a rarely used argument that does exist. Every tool
          ran the way a team would run it in CI, and scores when it reports the labelled problem on
          the resource it is about.
        </p>
      </div>

      <div class="scroll-x">
      <table class="bench">
        <thead><tr><th scope="col">The pull request adds</th>{head}</tr></thead>
        <tbody>
{chr(10).join(body)}
        </tbody>
        <tfoot>
          <tr class="bench-total"><th scope="row">Problems caught</th>{total}</tr>
          <tr><th scope="row">False alarms on the {len(near_misses)} correct changes</th>{false_alarms}</tr>
          <tr><th scope="row">Alerts raised in total, of any kind</th>{alerts}</tr>
          <tr><th scope="row">Needs before it can run</th>{needs_row}</tr>
        </tfoot>
      </table>
      </div>

      <div class="bench-notes">
        <div>
          <h3>{wrong_title}</h3>
          {wrong_lead}
          <ul>
{wrong_items}
          </ul>
        </div>
        <div>
          <h3>Read this before quoting it</h3>
          <ul>
            <li>We wrote the pull requests, so they lean towards what this scanner was built for.
              The cases, labels and scripts are public: add the ones we missed.</li>
            <li>Checkov and Trivy ship hundreds of policies this corpus does not score, about
              logging, customer-managed keys, backups and tags. Most of their alerts above are
              those. If you want that coverage, run them as well; this scanner does not replace them.</li>
            <li><code>terraform validate</code> catches every argument that does not exist, once
              <code>terraform init</code> has downloaded the providers and modules. This scanner
              gets the answer from the schema it carries.</li>
            <li>Only this scanner reads the previous revision, so only it can say that a change,
              rather than a configuration, destroys something.</li>
          </ul>
        </div>
      </div>

      <h3 class="bench-speed-title">Scan time on whole public repositories</h3>
      <div class="scroll-x">
      <table class="bench bench-speed">
        <thead><tr><th scope="col">Repository</th>{speed_head}</tr></thead>
        <tbody>
{chr(10).join(speed_rows)}
        </tbody>
      </table>
      </div>
      <p class="bench-fine">
        Run on 26&nbsp;November&nbsp;2026 on one Apple-silicon laptop; times are the median of three
        runs, each tool in its whole-repository mode. This scanner {versions["ours"]}, free, without a
        licence key; Checkov {versions["checkov"]}; Trivy {versions["trivy"]}; TFLint
        {versions["tflint"]} with its AWS and Azure rulesets; Terraform {versions["terraform"]}.
        Cases, labels and scripts:
        <a href="{CORPUS_URL}" target="_blank" rel="noopener">benchmarks/comparison</a> in the scanner's repository.
      </p>

      <div class="plan-note">
        <h3>And <code>terraform plan</code>?</h3>
        <div class="prose-cols">
          <p>
            Only <code>plan</code> knows about the destroy — and running <code>plan</code> means
            handing real cloud credentials to a branch nobody has read yet. That is the gap: the
            pull request most worth planning is the one least safe to plan. This reads the same
            provider schema statically, from one package, with nothing to authenticate to.
          </p>
          <p>
            If your pipeline already runs <code>plan</code> somewhere safe, pass the JSON with
            <code>plan-json</code> and three more checks turn on: a confirmed replace, a sensitive
            attribute drifting that this pull request never touched, and a plan that destroys more
            resources than your threshold allows.
          </p>
          <p>
            And if you want it, one more option. <code>force_destroy = true</code> on a bucket this
            pull request invents and <code>force_destroy = true</code> on the bucket holding your
            backups are the same characters — nothing in the repository tells them apart, so
            the rule has to score both the same. Give the scan a <strong>read-only</strong> role
            and it asks your account which one this is, and says so in the finding. It is the only
            thing it uses the access for.
          </p>
        </div>
      </div>
    </div>
  </section>
  <!-- BENCHMARK:END -->'''

    text = INDEX.read_text()
    start = text.index("<!-- BENCHMARK:START")
    end = text.index("<!-- BENCHMARK:END -->") + len("<!-- BENCHMARK:END -->")
    INDEX.write_text(text[:start] + section + text[end:])
    print(f"section written: {len(positives)} problems, {len(near_misses)} correct changes, "
          f"{len(wrong)} cases this scanner got wrong")


CORPUS_URL = "https://github.com/foadtalsi/tf-predeploy-firewall/tree/main/benchmarks/comparison"

if __name__ == "__main__":
    main()
