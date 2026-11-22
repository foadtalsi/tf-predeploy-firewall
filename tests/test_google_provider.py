"""Google Cloud coverage: the free google base pack, and the routing that keeps google-beta
resources from being judged against the google schema.

google and google-beta describe the same resource type names. A resource picks google-beta
with its `provider` meta-argument, and google-beta accepts arguments the google schema does
not have. Every test about google-beta below guards one consequence of that.
"""

from __future__ import annotations

import gzip
import io
import json
from importlib import resources

import pytest

from tfpdf import parser, providerversion, schema
from tfpdf.cli.providers import detect_providers, resolve_providers, warn_uncovered_providers
from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Category, Finding
from tfpdf.rules import default_rules, run


@pytest.fixture(scope="module")
def kb() -> schema.KnowledgeBase:
    return schema.load()


def _pack(pack_id: str, provider: str, version: str, pack_resources: dict[str, object]) -> bytes:
    document = {
        "format_version": 1,
        "id": pack_id,
        "provider": provider,
        "provider_version": version,
        "resources": pack_resources,
    }
    return gzip.compress(json.dumps(document).encode())


#: A google-beta pack that knows multi_writer on google_compute_disk, as the real one does.
BETA_PACK = _pack(
    "google-beta-full",
    "google-beta",
    "8.12.0",
    {
        "google_compute_disk": {
            "top_level": ["name", "zone", "provider", "lifecycle", "multi_writer"],
            "force_new_top_level": ["name", "zone"],
            "critical": True,
        }
    },
)


def _scan(
    source: str, knowledge_base: schema.KnowledgeBase, base: str | None = None
) -> list[Finding]:
    files = [
        ChangedFile(
            path="main.tf",
            head_content=source.encode(),
            base_content=base.encode() if base is not None else None,
        )
    ]
    return run(files, knowledge_base, default_rules()).findings


def _rules(findings: list[Finding], resource: str) -> set[str]:
    return {finding.rule_name for finding in findings if finding.resource == resource}


# --- the free base pack -----------------------------------------------------------------


def test_the_free_google_pack_ships_exactly_the_curated_types(kb: schema.KnowledgeBase) -> None:
    curated_file = resources.files("tfpdf.schema") / "curated" / "google" / "base_pack_types.json"
    curated = json.loads(curated_file.read_text())["resource_types"]
    shipped_file = resources.files("tfpdf.schema") / "data" / "pack_google_base.json.gz"
    shipped = json.loads(gzip.decompress(shipped_file.read_bytes()))

    assert shipped["provider"] == "google"
    assert shipped["id"] == "google-base"
    assert sorted(shipped["resources"]) == sorted(curated)
    assert len(curated) == 42
    assert all(entry.get("top_level") for entry in shipped["resources"].values())

    assert kb.coverage().version_of("google") == shipped["provider_version"]


def test_google_resources_carry_force_new_and_critical_data(kb: schema.KnowledgeBase) -> None:
    bucket_force_new = kb.force_new("google_storage_bucket")
    assert bucket_force_new is not None
    assert {"name", "location"} <= set(bucket_force_new.top_level)

    assert kb.is_critical("google_sql_database_instance")
    assert kb.is_critical("google_storage_bucket")
    # Recreated from configuration, nothing lost: not critical.
    assert not kb.is_critical("google_compute_instance")


def test_an_invented_google_argument_is_reported(kb: schema.KnowledgeBase) -> None:
    findings = _scan(
        """
resource "google_storage_bucket" "logs" {
  name          = "acme-logs"
  location      = "EU"
  versioning_on = true
}
""",
        kb,
    )
    unknown = [f for f in findings if f.category is Category.UNKNOWN_ATTRIBUTE]
    assert [f.message.split('"')[1] for f in unknown] == ["versioning_on"]
    assert unknown[0].doc_url.startswith(
        "https://registry.terraform.io/providers/hashicorp/google/"
    )
    assert unknown[0].doc_url.endswith("/docs/resources/storage_bucket")


def test_a_google_force_new_change_is_reported(kb: schema.KnowledgeBase) -> None:
    base = """
resource "google_storage_bucket" "logs" {
  name     = "acme-logs"
  location = "EU"
}
"""
    findings = _scan(base.replace('"EU"', '"US"'), kb, base=base)
    force_new = [f for f in findings if f.category is Category.FORCE_NEW_CHANGE]
    assert len(force_new) == 1
    assert '"location" changed from "EU" to "US"' in force_new[0].message


# --- google-beta ----------------------------------------------------------------------------


#: multi_writer only exists in google-beta: the google schema does not declare it.
BETA_DISK = """
resource "google_compute_disk" "data" {
  provider     = google-beta
  name         = "acme-data"
  zone         = "europe-west1-b"
  multi_writer = true
}
"""


def test_a_google_beta_resource_is_not_judged_by_the_google_schema(
    kb: schema.KnowledgeBase,
) -> None:
    """multi_writer is beta-only. Without a google-beta pack the resource is skipped."""
    findings = _scan(BETA_DISK, kb)
    assert "unknown_attribute" not in _rules(findings, "google_compute_disk.data")


def test_the_same_argument_is_reported_without_google_beta(kb: schema.KnowledgeBase) -> None:
    """The control: on the google provider, multi_writer really is unknown."""
    findings = _scan(BETA_DISK.replace("  provider     = google-beta\n", ""), kb)
    assert "unknown_attribute" in _rules(findings, "google_compute_disk.data")


def test_a_google_beta_resource_is_judged_by_the_google_beta_pack() -> None:
    knowledge_base, errors = schema.load_with(BETA_PACK)
    assert errors == []

    valid = _scan(BETA_DISK, knowledge_base)
    assert "unknown_attribute" not in _rules(valid, "google_compute_disk.data")
    invented = BETA_DISK.replace(
        "multi_writer = true", "multi_writer = true\n  turbo        = true"
    )
    findings = _scan(invented, knowledge_base)
    unknown = [f for f in findings if f.category is Category.UNKNOWN_ATTRIBUTE]
    assert [f.message.split('"')[1] for f in unknown] == ["turbo"]
    # The documentation link names the provider that judged the resource.
    assert "/providers/hashicorp/google-beta/8.12.0/docs/resources/compute_disk" in (
        unknown[0].doc_url
    )


def test_the_google_beta_pack_does_not_judge_google_resources() -> None:
    """Loading the beta pack must leave resources on the google provider to the google pack."""
    knowledge_base, _ = schema.load_with(BETA_PACK)
    findings = _scan(BETA_DISK.replace("  provider     = google-beta\n", ""), knowledge_base)
    assert "unknown_attribute" in _rules(findings, "google_compute_disk.data")


def test_an_aliased_google_beta_configuration_is_still_google_beta(
    kb: schema.KnowledgeBase,
) -> None:
    aliased = BETA_DISK.replace("= google-beta", "= google-beta.west")
    assert "unknown_attribute" not in _rules(_scan(aliased, kb), "google_compute_disk.data")


def test_a_google_beta_resource_still_needs_prevent_destroy(kb: schema.KnowledgeBase) -> None:
    """Whether a type holds data does not depend on the provider serving it."""
    findings = _scan(
        """
resource "google_sql_database_instance" "orders" {
  provider         = google-beta
  name             = "orders"
  database_version = "POSTGRES_16"
  region           = "europe-west1"
}
""",
        kb,
    )
    assert "missing_lifecycle" in _rules(findings, "google_sql_database_instance.orders")


def test_a_google_beta_finding_is_held_to_the_google_beta_version_pin() -> None:
    """A google-beta resource is filtered by the google-beta constraint, not the google one."""
    knowledge_base, _ = schema.load_with(BETA_PACK)
    invented = BETA_DISK.replace(
        "multi_writer = true", "multi_writer = true\n  turbo        = true"
    )
    pinned = (
        """
terraform {
  required_providers {
    google      = { source = "hashicorp/google", version = "~> 8.0" }
    google-beta = { source = "hashicorp/google-beta", version = "~> 7.0" }
  }
}
"""
        + invented
    )
    files = [ChangedFile(path="main.tf", head_content=pinned.encode())]
    result = run(files, knowledge_base, default_rules())
    assert "unknown_attribute" not in _rules(result.findings, "google_compute_disk.data")
    assert any(note.startswith('google-beta is pinned to "~> 7.0"') for note in result.notes)


# --- routing ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argument", "reference"),
    [
        ("provider = google-beta", "google-beta"),
        ("provider = google-beta.west", "google-beta"),
        ('provider = "google-beta"', "google-beta"),
        ("provider = google.west", "google"),
        ("", ""),
    ],
)
def test_the_parser_records_the_provider_reference(argument: str, reference: str) -> None:
    source = f'resource "google_compute_instance" "vm" {{\n  {argument}\n  name = "vm"\n}}\n'
    (resource,) = parser.parse_file("main.tf", source.encode())
    assert resource.provider_reference == reference


@pytest.mark.parametrize(
    ("resource_type", "reference", "expected"),
    [
        ("google_container_cluster", "google-beta", "google-beta"),
        ("google_container_cluster", "google", "google"),
        ("google_container_cluster", "", "google"),
        # A variant only applies to the provider it is a variant of.
        ("aws_instance", "google-beta", "aws"),
        ("aws_instance", "aws", "aws"),
    ],
)
def test_schema_provider_of(resource_type: str, reference: str, expected: str) -> None:
    assert providerversion.schema_provider_of(resource_type, reference) == expected


def test_google_beta_is_detected_from_provider_arguments() -> None:
    files = [ChangedFile(path="main.tf", head_content=BETA_DISK.encode())]
    assert detect_providers(files) == ["google", "google-beta"]
    assert resolve_providers("auto", files) == ["google", "google-beta"]


def test_the_free_tier_warns_that_google_beta_resources_skip_schema_checks(
    kb: schema.KnowledgeBase, capsys: pytest.CaptureFixture[str]
) -> None:
    files = [ChangedFile(path="main.tf", head_content=BETA_DISK.encode())]
    warn_uncovered_providers(files, kb.coverage())
    error_output = capsys.readouterr().err
    assert "no rule pack for google-beta" in error_output
    assert "unknown arguments and destroy/recreate traps" in error_output
    # google itself is covered by the free pack and must not be reported.
    assert "no rule pack for google," not in error_output
    assert "no rule pack for google " not in error_output


def test_no_google_beta_warning_once_its_pack_is_loaded(
    capsys: pytest.CaptureFixture[str],
) -> None:
    knowledge_base, _ = schema.load_with(io.BytesIO(BETA_PACK))
    files = [ChangedFile(path="main.tf", head_content=BETA_DISK.encode())]
    warn_uncovered_providers(files, knowledge_base.coverage())
    assert capsys.readouterr().err == ""
