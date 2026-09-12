"""Provider schema, overlay, coverage, and documentation-link tests."""

from __future__ import annotations

import gzip
import io

import pytest

from tfpdf import schema
from tfpdf.schema.loader import PackError


@pytest.fixture(scope="module")
def kb() -> schema.KnowledgeBase:
    return schema.load()


def _make_pack(json_body: str) -> io.BytesIO:
    return io.BytesIO(gzip.compress(json_body.encode()))


@pytest.mark.parametrize(
    "r_type",
    [
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_instance",
        "aws_s3_bucket",
        "aws_security_group",
        "aws_iam_role",
        "aws_lambda_function",
        "aws_eks_cluster",
        "aws_ecs_service",
        "aws_lb",
        "aws_dynamodb_table",
        "aws_elasticache_replication_group",
        "aws_secretsmanager_secret",
    ],
)
def test_load_has_expected_argument_surface(kb: schema.KnowledgeBase, r_type: str) -> None:
    assert kb.resource_schema(r_type) is not None


@pytest.mark.parametrize(
    "r_type",
    [
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_instance",
        "aws_ebs_volume",
        "aws_elasticache_replication_group",
        "aws_kms_key",
        "aws_sqs_queue",
    ],
)
def test_load_has_expected_force_new(kb: schema.KnowledgeBase, r_type: str) -> None:
    assert kb.force_new(r_type) is not None


@pytest.mark.parametrize(
    "r_type",
    [
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_dynamodb_table",
        "aws_elasticache_replication_group",
        "aws_secretsmanager_secret",
    ],
)
def test_load_marks_critical_types(kb: schema.KnowledgeBase, r_type: str) -> None:
    assert kb.is_critical(r_type)


@pytest.mark.parametrize(
    ("r_type", "args"),
    [
        (
            "aws_instance",
            [
                "ami",
                "instance_type",
                "launch_template",
                "cpu_options",
                "hibernation",
                "placement_group",
                "network_interface",
                "capacity_reservation_specification",
                "maintenance_options",
                # Terraform's own meta-arguments are valid in every resource.
                "count",
                "for_each",
                "lifecycle",
                "depends_on",
                "provider",
            ],
        ),
        ("aws_s3_bucket", ["bucket", "force_destroy", "tags"]),
        ("aws_lambda_function", ["function_name", "runtime", "architectures", "logging_config"]),
    ],
)
def test_resource_schema_covers_real_world_arguments(
    kb: schema.KnowledgeBase, r_type: str, args: list[str]
) -> None:
    """Real provider arguments must be covered to avoid blocking valid Terraform as unknown."""
    rs = kb.resource_schema(r_type)
    assert rs is not None
    valid = set(rs.top_level)
    missing = [a for a in args if a not in valid]
    assert not missing, (
        f"{r_type}: {missing} missing from the pack — would be flagged as hallucinated"
    )


@pytest.mark.parametrize(
    ("r_type", "attrs"),
    [
        (
            "aws_db_instance",
            ["engine", "db_name", "username", "storage_encrypted", "availability_zone"],
        ),
        ("aws_instance", ["ami", "availability_zone", "key_name", "placement_group"]),
        ("aws_ebs_volume", ["availability_zone", "encrypted", "snapshot_id"]),
        ("aws_dynamodb_table", ["hash_key", "range_key", "name"]),
    ],
)
def test_force_new_known_attributes(
    kb: schema.KnowledgeBase, r_type: str, attrs: list[str]
) -> None:
    """Verify replacement-triggering attributes against known schema examples."""
    spec = kb.force_new(r_type)
    assert spec is not None
    got = set(spec.top_level)
    missing = [a for a in attrs if a not in got]
    assert not missing, f"{r_type}: {missing} should be ForceNew"


def test_force_new_excludes_in_place_updatable(kb: schema.KnowledgeBase) -> None:
    """Do not report ordinary in-place updates as replacements."""
    spec = kb.force_new("aws_instance")
    assert spec is not None
    for a in ("tags", "instance_type"):
        assert a not in spec.top_level, f"aws_instance: {a!r} is updatable in place"


def test_force_new_references_real_arguments(kb: schema.KnowledgeBase) -> None:
    """Every ForceNew attribute must exist in the same pack's argument schema."""
    problems: list[str] = []
    for pack in kb._packs:
        for r_type in pack.resources:
            spec = kb.force_new(r_type)
            if spec is None:
                continue
            rs = kb.resource_schema(r_type)
            if rs is None:
                problems.append(f"{r_type} has ForceNew data but no argument surface")
                continue
            valid = set(rs.top_level)
            problems.extend(
                f"{r_type}: ForceNew argument {a!r} is not in the argument surface"
                for a in spec.top_level
                if a not in valid
            )
            for path, attrs in spec.nested_blocks.items():
                declared = rs.nested_blocks.get(path)
                if declared is None:
                    problems.append(f"{r_type}: ForceNew block path {path!r} is not in the surface")
                    continue
                valid_nested = set(declared)
                problems.extend(
                    f"{r_type}.{path}: ForceNew argument {a!r} is not declared in that block"
                    for a in attrs
                    if a not in valid_nested
                )
    assert not problems, "\n".join(problems[:20])


def test_load_allowed_attrs_not_empty(kb: schema.KnowledgeBase) -> None:
    empty = [
        r_type
        for pack in kb._packs
        for r_type in pack.resources
        if (rs := kb.resource_schema(r_type)) is None or not rs.top_level
    ]
    assert not empty, f"empty top-level argument list: {empty[:10]}"


def test_coverage_base_pack_only(kb: schema.KnowledgeBase) -> None:
    c = kb.coverage()
    assert not c.extended, "a base-only load must not report extended coverage"
    # One base pack per shipped provider; pinning the exact list here would
    # make every new free-tier provider a test failure, which is backwards.
    assert "aws-base" in c.packs
    assert c.resource_types > 0
    assert c.version_of("aws") != "", "pack does not record which provider version it describes"


def test_load_with_overlay_takes_precedence() -> None:
    """Overlays replace shared resource types and add newly covered types."""
    overlay = _make_pack(
        """{
        "format_version": 1,
        "id": "aws-full",
        "provider": "aws",
        "provider_version": "9.9.9",
        "resources": {
            "aws_instance": {"top_level": ["only_this_one"]},
            "aws_brand_new_type": {"top_level": ["alpha"], "critical": true}
        }
    }"""
    )

    kb, errs = schema.load_with(overlay)
    assert errs == []

    rs = kb.resource_schema("aws_instance")
    assert rs is not None
    assert rs.top_level == ["only_this_one"], "overlay should shadow the base pack"
    assert kb.is_critical("aws_brand_new_type"), "overlay-only type not visible"
    # Types only the base pack knows about are still reachable.
    assert kb.resource_schema("aws_s3_bucket") is not None
    assert kb.coverage().extended


def test_load_with_bad_pack_does_not_break_loading() -> None:
    """Invalid extended packs degrade coverage without preventing embedded-pack loading."""
    kb, errs = schema.load_with(io.BytesIO(b"not a gzip pack"))
    assert len(errs) == 1
    assert kb is not None
    assert kb.resource_schema("aws_instance") is not None
    assert not kb.coverage().extended, "a rejected pack must not count as extended coverage"


def test_parse_pack_rejects_unknown_format_version() -> None:
    _, errs = schema.load_with(
        _make_pack('{"format_version": 99, "id": "future", "resources": {}}')
    )
    assert len(errs) == 1
    assert isinstance(errs[0], PackError)


# --- docs_test.go ---------------------------------------------------------


def test_doc_url_pins_the_provider_version(kb: schema.KnowledgeBase) -> None:
    version = kb.coverage().version_of("aws")
    url = kb.doc_url("aws_db_instance")
    assert url == (
        f"https://registry.terraform.io/providers/hashicorp/aws/{version}"
        "/docs/resources/db_instance"
    )
    assert "latest" not in url, "a doc link must pin the release the pack describes"


def test_doc_url_empty_for_uncovered_type(kb: schema.KnowledgeBase) -> None:
    """Do not invent documentation URLs for uncovered types."""
    assert kb.doc_url("google_storage_bucket") == ""


def test_doc_url_uses_the_overlaid_packs_version() -> None:
    """Link to the provider version from the pack that actually supplied the resource schema."""
    overlay = _make_pack(
        """{
        "format_version": 1, "id": "aws-full", "provider": "aws",
        "provider_version": "9.9.9",
        "resources": {"aws_instance": {"top_level": ["ami"]}}
    }"""
    )
    kb, _ = schema.load_with(overlay)
    assert "/aws/9.9.9/docs/resources/instance" in kb.doc_url("aws_instance")


# --- multiprovider_test.go ------------------------------------------------


def test_multiprovider_lookups_need_no_routing(kb: schema.KnowledgeBase) -> None:
    """Provider-prefixed resource types resolve through one shared knowledge base."""
    assert kb.resource_schema("aws_db_instance") is not None
    assert kb.resource_schema("azurerm_mssql_server") is not None

    c = kb.coverage()
    names = [p.name for p in c.providers]
    assert names == sorted(names), "providers must be sorted by name"
    assert "aws" in names
    assert "azurerm" in names
    assert c.version_of("aws") != c.version_of("azurerm") or c.version_of("aws") != ""
