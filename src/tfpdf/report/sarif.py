"""Sortie SARIF 2.1.0, pour envoi vers GitHub Code Scanning.

Port de internal/report/sarif.go.

Seul le sous-ensemble du format que Code Scanning lit réellement est modélisé.
Spécification : https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Chaque dataclass ici se sérialise explicitement plutôt que par un encodeur
générique, parce que l'ordre des clés et le comportement d'omission des valeurs
vides doivent tous deux correspondre à ce que produisent les étiquettes de
structure de Go.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from ._json import marshal_indent
from .finding import Category, Finding, Severity
from .ruledocs import lookup_rule_help, rule_help_uri


@dataclass(slots=True, frozen=True)
class SarifMessage:
    text: str

    def to_json(self) -> dict[str, Any]:
        return {"text": self.text}


@dataclass(slots=True, frozen=True)
class SarifHelp:
    """L'explication longue d'une règle. GitHub Code Scanning rend du Markdown
    sur la page d'alerte et retombe sur le texte brut ailleurs, donc les deux
    sont remplis depuis la même source."""

    text: str
    markdown: str = ""

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"text": self.text}
        if self.markdown:
            out["markdown"] = self.markdown
        return out


@dataclass(slots=True, frozen=True)
class SarifRuleProperties:
    tags: list[str] = field(default_factory=list)
    severity: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"tags": list(self.tags), "severity": self.severity}


@dataclass(slots=True, frozen=True)
class SarifRule:
    id: str
    name: str
    short_description: SarifMessage
    properties: SarifRuleProperties
    full_description: SarifMessage | None = None
    help: SarifHelp | None = None
    help_uri: str = ""

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": str(self.id),
            "name": self.name,
            "shortDescription": self.short_description.to_json(),
        }
        if self.full_description is not None:
            out["fullDescription"] = self.full_description.to_json()
        if self.help is not None:
            out["help"] = self.help.to_json()
        if self.help_uri:
            out["helpUri"] = self.help_uri
        out["properties"] = self.properties.to_json()
        return out


def _location_json(uri: str, start_line: int) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": start_line},
        }
    }


#: The catalogue of categories this scanner can report, with the metadata a
#: Code Scanning alert page shows above the rule's own documentation.
SARIF_RULES: list[SarifRule] = [
    SarifRule(
        id=Category.UNKNOWN_ATTRIBUTE,
        name="UnknownAttribute",
        short_description=SarifMessage("Unknown or hallucinated Terraform attribute"),
        properties=SarifRuleProperties(tags=["terraform", "ai-hallucination"], severity="error"),
    ),
    SarifRule(
        id=Category.UNPINNED_VERSION,
        name="UnpinnedVersion",
        short_description=SarifMessage("Module source or provider requirement with no version pin"),
        properties=SarifRuleProperties(
            tags=["terraform", "supply-chain", "reproducibility"], severity="warning"
        ),
    ),
    SarifRule(
        id=Category.TUTORIAL_PATTERN,
        name="TutorialPattern",
        short_description=SarifMessage(
            "Tutorial copy-paste pattern (hardcoded credential, open CIDR, generic name)"
        ),
        properties=SarifRuleProperties(tags=["terraform", "security", "secrets"], severity="error"),
    ),
    SarifRule(
        id=Category.FORCE_NEW_CHANGE,
        name="ForceNewChange",
        short_description=SarifMessage(
            "Change to a ForceNew attribute will destroy and recreate the resource"
        ),
        properties=SarifRuleProperties(
            tags=["terraform", "destructive-change"], severity="warning"
        ),
    ),
    SarifRule(
        id=Category.MISSING_LIFECYCLE,
        name="MissingLifecycle",
        short_description=SarifMessage(
            "Stateful resource missing lifecycle { prevent_destroy = true }"
        ),
        properties=SarifRuleProperties(tags=["terraform", "data-safety"], severity="warning"),
    ),
    # The insecure_config group. Severity here is SARIF's own notion, not the
    # scanner's: it decides how GitHub Code Scanning ranks the alert, and
    # "error" is what puts an alert above the fold in a dashboard somebody
    # checks weekly. These four earn it because every one of them reports a
    # value that was written down rather than a default left alone.
    SarifRule(
        id=Category.PUBLIC_EXPOSURE,
        name="PublicExposure",
        short_description=SarifMessage(
            "A resource or its data explicitly placed on the public internet"
        ),
        properties=SarifRuleProperties(
            tags=["terraform", "security", "exposure"], severity="error"
        ),
    ),
    SarifRule(
        id=Category.ENCRYPTION_DISABLED,
        name="EncryptionDisabled",
        short_description=SarifMessage(
            "Encryption at rest or in transit switched off, or a TLS policy permitting TLS 1.0/1.1"
        ),
        properties=SarifRuleProperties(
            tags=["terraform", "security", "encryption"], severity="error"
        ),
    ),
    SarifRule(
        id=Category.PERMISSIVE_IAM,
        name="PermissiveIAM",
        short_description=SarifMessage(
            "IAM policy granting every action, or granting to every principal with no condition"
        ),
        properties=SarifRuleProperties(
            tags=["terraform", "security", "iam", "least-privilege"], severity="error"
        ),
    ),
    SarifRule(
        id=Category.AUDIT_DISABLED,
        name="AuditDisabled",
        short_description=SarifMessage("An audit trail or diagnostic setting explicitly disabled"),
        properties=SarifRuleProperties(
            tags=["terraform", "security", "audit", "compliance"], severity="warning"
        ),
    ),
    SarifRule(
        id=Category.CONFIRMED_REPLACE,
        name="ConfirmedReplace",
        short_description=SarifMessage(
            "terraform plan confirms a destroy or destroy+recreate on a stateful resource"
        ),
        properties=SarifRuleProperties(tags=["terraform", "plan", "data-safety"], severity="error"),
    ),
    SarifRule(
        id=Category.UNEXPECTED_DRIFT,
        name="UnexpectedDrift",
        short_description=SarifMessage(
            "terraform plan changes a sensitive attribute not touched by this PR's .tf diff"
        ),
        properties=SarifRuleProperties(tags=["terraform", "plan", "drift"], severity="warning"),
    ),
    SarifRule(
        id=Category.LARGE_BLAST_RADIUS,
        name="LargeBlastRadius",
        short_description=SarifMessage(
            "terraform plan destroys/replaces an unusually large number of resources"
        ),
        properties=SarifRuleProperties(
            tags=["terraform", "plan", "blast-radius"], severity="warning"
        ),
    ),
    SarifRule(
        id=Category.COST_IMPACT,
        name="CostImpact",
        short_description=SarifMessage(
            "terraform plan increases the estimated monthly AWS bill by more than "
            "the configured threshold"
        ),
        properties=SarifRuleProperties(
            tags=["terraform", "plan", "finops", "cost"], severity="warning"
        ),
    ),
]


def described_rules() -> list[SarifRule]:
    """`SARIF_RULES`, chaque entrée voyant son texte d'aide, sa description
    complète et son lien de documentation remplis depuis le pack de règles.

    Gardé comme une dérivation plutôt qu'écrit dans les littéraux ci-dessus pour
    que les deux ne puissent pas diverger : une catégorie ajoutée à l'un et
    oubliée dans l'autre apparaît comme une règle sans explication, ce que le
    test vérifie.

    `replace` plutôt qu'une mutation — le catalogue est un état de module, et un
    rendu qui l'éditerait fuirait dans le suivant.
    """
    out: list[SarifRule] = []
    for r in SARIF_RULES:
        h = lookup_rule_help(r.id)
        if h is None:
            out.append(replace(r, help_uri=rule_help_uri(r.id)))
            continue
        out.append(
            replace(
                r,
                help_uri=rule_help_uri(r.id),
                full_description=SarifMessage(h.full_description),
                help=SarifHelp(text=h.full_description, markdown=h.markdown),
            )
        )
    return out


SEVERITY_TO_SARIF_LEVEL = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

#: Appears as the driver version in SARIF output. The CLI stamps it from the
#: release metadata; "dev" means a from-source build. Module state rather than
#: a parameter because exactly one caller will ever set it and every render
#: site would otherwise thread it through untouched. Set it with
#: `set_tool_version` — rebinding an imported name would not be seen here.
TOOL_VERSION = "dev"


def set_tool_version(v: str) -> None:
    """Estampille la version que cette build rapporte comme version du pilote
    SARIF."""
    global TOOL_VERSION
    TOOL_VERSION = v


def render_sarif(findings: list[Finding]) -> bytes:
    """Sérialise les découvertes en un document JSON SARIF 2.1.0 propre à être
    envoyé vers GitHub Code Scanning via actions/upload-sarif."""
    results: list[dict[str, Any]] = []
    for f in findings:
        result: dict[str, Any] = {
            "ruleId": str(f.category),
            "level": SEVERITY_TO_SARIF_LEVEL.get(f.severity, ""),
            "message": SarifMessage(f.message).to_json(),
            "locations": [_location_json(f.file, f.line)],
        }
        # The provider documentation link is per-result and cannot go on the
        # rule: a rule is one category across every resource type, while the
        # useful link is to the one type this result is about.
        if f.doc_url:
            result["properties"] = {"providerDocs": f.doc_url, "resource": f.resource}
        results.append(result)

    log = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tf-predeploy-firewall",
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/foadtalsi/tf-predeploy-firewall",
                        "rules": [r.to_json() for r in described_rules()],
                    }
                },
                "results": results,
            }
        ],
    }
    return marshal_indent(log)
