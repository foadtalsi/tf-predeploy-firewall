"""Parse the JSON output of terraform show -json for optional plan analysis."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Change:
    """A resource change's before/after values and actions."""

    actions: list[str] = field(default_factory=list)

    #: `None` when the plan says `null`, which is not the same as an empty
    #: object: a create has no before-state at all. Go models these as nilable
    #: maps and the cost rule branches on `state == nil` to charge $0 for the
    #: side that does not exist — collapsing both to `{}` would price a
    #: newly-created flat-rate resource at its base cost on *both* sides and
    #: report a delta of zero.
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    before_sensitive: dict[str, Any] | None = None
    after_sensitive: dict[str, Any] | None = None

    def is_sensitive_attr(self, attr_name: str) -> bool:
        """Return whether the attribute is marked sensitive in either state."""
        return _is_masked_true(self.before_sensitive, attr_name) or _is_masked_true(
            self.after_sensitive, attr_name
        )

    def is_replace(self) -> bool:
        """Return whether the change replaces the resource by destroying and recreating it."""
        return "delete" in self.actions and "create" in self.actions

    def is_destroy_only(self) -> bool:
        """Return whether the resource is destroyed without replacement."""
        return self.actions == ["delete"]

    def is_pure_update(self) -> bool:
        """Return whether the change updates the resource in place."""
        return self.actions == ["update"]

    def is_no_op(self) -> bool:
        """Return whether Terraform reports no action for the resource."""
        return self.actions == ["no-op"]


def _is_masked_true(mask: dict[str, Any] | None, attr_name: str) -> bool:
    if not mask:
        return False
    return mask.get(attr_name) is True


@dataclass(slots=True)
class ResourceChange:
    """An entry in resource_changes."""

    address: str = ""
    module_addr: str = ""
    #: "managed" (a real resource) or "data" (a data source read).
    mode: str = ""
    type: str = ""
    name: str = ""
    provider_name: str = ""
    change: Change = field(default_factory=Change)

    def is_managed(self) -> bool:
        """Distinguish managed resources from data-source reads."""
        return self.mode == "managed"


@dataclass(slots=True)
class PlanFile:
    """The supported subset of Terraform plan JSON format_version 1.x."""

    format_version: str = ""
    resource_changes: list[ResourceChange] = field(default_factory=list)


def _as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _as_dict_or_none(v: Any) -> dict[str, Any] | None:
    """Preserve JSON null as absence rather than converting it to an empty mapping."""
    return v if isinstance(v, dict) else None


def parse(data: bytes | str) -> PlanFile:
    """Decode a Terraform plan JSON document."""
    try:
        document = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"parsing plan JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("parsing plan JSON: top level is not an object")

    changes: list[ResourceChange] = []
    for resource_change in document.get("resource_changes") or []:
        if not isinstance(resource_change, dict):
            continue
        c = _as_dict(resource_change.get("change"))
        changes.append(
            ResourceChange(
                address=str(resource_change.get("address", "")),
                module_addr=str(resource_change.get("module_address", "")),
                mode=str(resource_change.get("mode", "")),
                type=str(resource_change.get("type", "")),
                name=str(resource_change.get("name", "")),
                provider_name=str(resource_change.get("provider_name", "")),
                change=Change(
                    actions=[str(a) for a in (c.get("actions") or [])],
                    before=_as_dict_or_none(c.get("before")),
                    after=_as_dict_or_none(c.get("after")),
                    before_sensitive=_as_dict_or_none(c.get("before_sensitive")),
                    after_sensitive=_as_dict_or_none(c.get("after_sensitive")),
                ),
            )
        )

    return PlanFile(
        format_version=str(document.get("format_version", "")), resource_changes=changes
    )


def load(path: str) -> PlanFile:
    """Read and decode a Terraform plan JSON file."""
    try:
        return parse(Path(path).read_bytes())
    except OSError as exc:
        raise ValueError(f"reading plan JSON {path}: {exc}") from exc
