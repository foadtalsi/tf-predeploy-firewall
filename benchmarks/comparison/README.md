# Comparison benchmark

How this scanner compares with `terraform validate`, TFLint, Checkov and Trivy on the same
pull requests. The landing page's benchmark section is generated from the files here.

## What is measured

`corpus/` holds 50 small repositories, one per pull request, each with a `base/` (before) and
a `head/` (after). `corpus/labels.json` says what each one is:

- a **positive** carries one known problem, on one resource (`target`);
- a **near miss** is a correct change that looks like a problem; reporting it is a false alarm.

This scanner scans the pull request (base to head), the way its GitHub Action runs. The other
tools scan `head/`, the way they run in CI. A tool scores on a positive when it reports, on the
target, a rule about the labelled problem; `judge.py` lists those rules per tool, chosen by
reading each rule's title. Findings about anything else (logging, customer-managed keys,
backups, tags) are not scored; they are only counted as alert volume.

The cases were written by the maintainers and lean towards what this scanner is built for.
Add the ones that do not.

## Rerun it

```sh
python3 make_corpus.py corpus          # regenerate the cases from make_corpus.py
python3 run_tools.py                   # run every tool on every case -> results.json
python3 judge.py --cases               # score them -> verdicts.json
python3 run_repos.py                   # time the tools on public repositories -> repos.json
python3 render.py ../../../landingpage/index.html
```

`TFPDF_SCANNER` points `run_tools.py` at another build of the scanner, such as a branch
under test; `run_repos.py ours` re-times only this scanner.

The scripts expect, next to them: the scanner installed in `scanner/.venv` (any release,
`pip install` into that virtualenv), TFLint in `bin/tflint` with its rulesets installed from
`tflint.hcl` (`TFLINT_PLUGIN_DIR=tflint-plugins tflint --init --config tflint.hcl`), Checkov
in `~/.local/bin/checkov`, and `trivy` and `terraform` on the PATH. `run_repos.py` reads
shallow clones of the public repositories in `repos/`.

## Runs

The first run, on 26 November 2026, was against 1.5.0: it missed AWS keys in a `provider`
block and `cidr_block` inside a security group's `ingress`, and reported a Secret Manager
reference and EFS's `creation_token` as credentials. Its results are kept in
`results-1.5.0.json`, `verdicts-1.5.0.json` and `repos-1.5.0.json`. The fixes are in 1.5.1,
and `results.json`, `verdicts.json` and `repos.json` are its run, the same day.

Both runs used the free scanner without a licence key, Checkov 3.4.11, Trivy 0.76.2,
TFLint 0.66.0 with tflint-ruleset-aws 0.50.0 and tflint-ruleset-azurerm 0.33.0,
Terraform 1.14.3.
