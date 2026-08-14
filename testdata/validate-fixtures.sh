#!/usr/bin/env bash
# Check every fixture against the real provider schemas.
#
# The Go test TestFixtures_AreValidTerraform catches attributes that exist on
# no provider, because the scanner's own knowledge base knows the argument
# surface. It cannot catch a MISSING required argument — the packs record
# which arguments exist, not which are mandatory — and that is the other half
# of what makes a fixture show up red in an editor.
#
# Not wired into CI on purpose: this downloads the full AWS and Azure
# providers, several hundred megabytes, to check a handful of small files.
# Run it when adding or editing a fixture.
#
#   ./testdata/validate-fixtures.sh
#
# Each fixture is validated ALONE. They share resource names with each other
# (forcenew_base.tf and forcenew_head.tf are the same resource before and
# after a change), so validating the directory as one configuration would
# report duplicates that are not real.
set -euo pipefail

cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/providers.tf" <<'EOF'
terraform {
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 6.0" }
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
    null    = { source = "hashicorp/null", version = "~> 3.0" }
  }
}

provider "aws" {
  region = "eu-west-1"
}

provider "azurerm" {
  features {}
}
EOF

echo "installing providers…"
terraform -chdir="$work" init -input=false -no-color > /dev/null

# Its whole purpose is to carry an argument no provider declares, so a clean
# validate here would mean the fixture had stopped testing anything.
expected_to_fail="unknown_attribute.tf"

status=0
for fixture in testdata/fixtures/*.tf; do
  name=$(basename "$fixture")
  cp "$fixture" "$work/fixture.tf"

  # Warnings are printed before the verdict, so the check looks for the
  # verdict anywhere rather than at the start. One fixture earns a warning on
  # purpose: the AWS provider notices the planted secret key is base64, which
  # is a fair description of a planted secret key.
  if output=$(terraform -chdir="$work" validate -no-color 2>&1) && [[ $output == *"Success!"* ]]; then
    if [[ $name == "$expected_to_fail" ]]; then
      echo "  UNEXPECTEDLY VALID  $name — it is supposed to be rejected"
      status=1
    else
      echo "  ok       $name"
    fi
  else
    if [[ $name == "$expected_to_fail" ]]; then
      echo "  ok       $name (invalid on purpose)"
    else
      echo "  INVALID  $name"
      # `|| true` because grep finding nothing must not abort the run under
      # `set -e` — the remaining fixtures still need checking.
      { echo "$output" | grep -E "An argument named|is required, but|one of |conflicts with" || true; } | sed 's/^/             /'
      status=1
    fi
  fi
  rm -f "$work/fixture.tf"
done

echo
terraform fmt -check -recursive testdata/ && echo "formatting: ok"

exit $status
