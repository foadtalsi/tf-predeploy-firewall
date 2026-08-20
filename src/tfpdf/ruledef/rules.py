"""Le pack de règles intégré : ce que le scanner cherche, comment chaque
découverte est formulée, et ce qu'elle explique ensuite au lecteur.

Deux familles de règles vivent ici :

    match=  — entièrement déclarative. Le moteur parcourt les ressources et
              les attributs et applique les conditions. Tout de la règle, y
              compris son correctif en un clic, est dans ce fichier.

    engine= — le parcours est compilé, parce que c'est quelque chose qu'un
              matcher ne peut pas exprimer : une consultation du schéma du
              fournisseur, une comparaison avec la révision de base, un scan
              à accolades appariées du source brut. La règle déclare quand
              même ici son identité, ses paramètres et sa documentation.

Le vocabulaire qu'une règle peut invoquer (`confirm`, `predicate`,
`fix.action`) est fixe et fourni par le binaire. Il n'y a pas de langage
d'expression et pas d'échappée vers du code : ce scanner tourne dans la CI
d'autres gens, et un format de règles qui peut exécuter est un format qu'on
peut armer.

Ce fichier était du YAML. Il est devenu du Python pour que mypy vérifie la
forme de chaque règle et qu'une faute de frappe dans un nom de champ soit une
erreur de typage plutôt qu'une clé silencieusement ignorée. Le prix est réel
et assumé : corriger une règle demande maintenant une publication du paquet,
là où éditer un fichier de données n'en demandait pas.

Les packs des clients, eux, restent du YAML — voir `ruledef.load`. C'est
délibéré : accepter du Python fourni par un client rendrait exécutable
exactement le format qu'on vient de décrire comme ne l'étant pas.
"""

from __future__ import annotations

from .ruledef import CategoryDoc, Fix, Match, Pack, Rule

FORMAT_VERSION_DECLARED = 1

# Défini une fois et référencé plus bas. Sept règles partagent l'exclusion par
# nom de credential ; sept copies dériveraient dès qu'un fournisseur inventerait
# une nouvelle orthographe.
CREDENTIAL_ATTRIBUTE_NAMES = (
    r"(?i)^(?:.*_)?(password|passwd|secret|secret_key|access_key|api_key|token"
    r"|private_key|client_secret|auth_token|connection_string)$"
)

PLACEHOLDER_NAMES = (
    r"(?i)^(example|test|demo|foo|bar|my[-_]?bucket|my[-_]?app|sample|tmp|temp"
    r"|placeholder)([-_].*)?$"
)


def credential_value_match(**conditions: object) -> Match:
    """Où chaque vérification de credential par la valeur regarde, et ce qu'elle
    ignore.

    Les quatre champs communs sont ici plutôt que sur la première règle qui les
    emploie, pour qu'une fusion de pack n'emporte aucun motif de travers avec
    elle. Chaque appelant n'ajoute que la forme qu'il reconnaît.
    """
    return Match(
        scope="any_attribute",
        literal=True,
        # En dessous il n'y a pas assez de chaîne pour juger.
        min_length=16,
        # Les noms déjà signalés par hardcoded_credential ; sans cette exclusion
        # la même ligne porterait deux découvertes.
        attr_name_not_matches=CREDENTIAL_ATTRIBUTE_NAMES,
        **conditions,  # type: ignore[arg-type]
    )


RULES: list[Rule] = [
    # ---------------------------------------------------------------------
    # tutorial_pattern — values that look copied rather than chosen
    # ---------------------------------------------------------------------
    #
    # Matched by attribute NAME. Suffix-based rather than an exact list because
    # every provider grows its own vocabulary: azurerm alone has
    # administrator_login_password, admin_password and account_password, and a
    # per-provider list would always be one release behind. "key" is
    # deliberately not a bare suffix — public_key, partition_key and kms_key_id
    # are not secrets.
    Rule(
        id="hardcoded_credential",
        category="tutorial_pattern",
        severity="critical",
        message="{location}{attr_q} resolves to a hardcoded string literal{via}, not a secret reference — credentials must not be committed in plain text",
        suggestion=(
            'variable "{var}" {\n'
            "  type      = string\n"
            "  sensitive = true\n"
            "}\n"
            "\n"
            "# in {resource}:\n"
            "{attr} = var.{var}"
        ),
        match=Match(
            # any_attribute, not attribute: nested blocks carry credentials just as
            # often as the top level — service_principal { client_secret },
            # auth { password }, environment { variables { … } }.
            #
            # Top-level-only left a dead zone rather than merely a gap, because the
            # value-pattern group below deliberately skips attributes whose NAME
            # already matches (to avoid reporting the same line twice). A nested
            # `client_secret` was therefore excluded from the value checks for
            # having a credential name, and never checked by name for being nested.
            # A literal AWS key sitting in one was found by nothing at all.
            scope="any_attribute",
            attr_name_matches=CREDENTIAL_ATTRIBUTE_NAMES,
            literal=True,
            # Bools and empties are never credentials.
            # manage_master_user_password = true is the opposite of a leak.
            value_not_one_of=["", "true", "false"],
        ),
        fix=Fix(
            action="replace_attr_line",
            lines=["{attr} = var.{var}"],
            note=(
                "This also needs the variable declared, and its value supplied outside the repository (TF_VAR_{var}, a tfvars file that isn't committed, or your secret manager):\n"
                "\n"
                "```hcl\n"
                'variable "{var}" {\n'
                "  type      = string\n"
                "  sensitive = true\n"
                "}\n"
                "```\n"
                "\n"
                "**The old value is still in this branch's git history — rotate it.**"
            ),
            # Withheld when the literal was reached through a variable default or a
            # local. The line under the finding then already reads
            # `password = var.db_password` and is correct; swapping it for another
            # variable reference would fix nothing while looking like it had.
            skip_when_resolved=True,
        ),
    ),
    # Matched by VALUE, whatever the attribute is called — a key pasted into
    # user_data or a PEM block in an arbitrary field.
    #
    # One group, evaluated in order, first match wins per attribute: a JWT must
    # be reported as a JWT and not as "a high-entropy string", and the entropy
    # fallback at the end must not fire a second time on something already
    # named. Cheapest and most specific shapes come first.
    Rule(
        id="credential_value_aws_access_key",
        category="tutorial_pattern",
        severity="critical",
        group="credential_value",
        label="AWS access key ID (AKIA…)",
        message="{location}{attr_q} value matches pattern: {label}{via} — remove from source and use a secret reference",
        match=credential_value_match(
            value_matches="AKIA[A-Z0-9]{16}",
        ),
    ),
    # 40 characters of base64. The character class alone matches any long run
    # of [a-z0-9/+], which an ordinary file path reaches easily — running this
    # scanner against its own repository reported a `local-exec` build command
    # as a leaked AWS key, at critical severity, on a 41-character path. That
    # is precisely the false positive that gets a scanner switched off.
    # Randomness is what separates the two, so the match is confirmed rather
    # than trusted.
    Rule(
        id="credential_value_aws_secret_key",
        category="tutorial_pattern",
        severity="critical",
        group="credential_value",
        label="possible AWS secret key (40-char base64)",
        message="{location}{attr_q} value matches pattern: {label}{via} — remove from source and use a secret reference",
        match=credential_value_match(
            value_matches="(?i)[a-z0-9/+]{40}",
            confirm="base64_secret",
        ),
    ),
    Rule(
        id="credential_value_pem",
        category="tutorial_pattern",
        severity="critical",
        group="credential_value",
        label="PEM private key",
        message="{location}{attr_q} value matches pattern: {label}{via} — remove from source and use a secret reference",
        match=credential_value_match(
            value_matches="-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        ),
    ),
    Rule(
        id="credential_value_jwt",
        category="tutorial_pattern",
        severity="critical",
        group="credential_value",
        label="JWT token",
        message="{location}{attr_q} value matches pattern: {label}{via} — remove from source and use a secret reference",
        match=credential_value_match(
            value_matches="^ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$",
        ),
    ),
    Rule(
        id="credential_value_github_token",
        category="tutorial_pattern",
        severity="critical",
        group="credential_value",
        label="GitHub personal access token",
        message="{location}{attr_q} value matches pattern: {label}{via} — remove from source and use a secret reference",
        match=credential_value_match(
            value_matches="^(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})$",
        ),
    ),
    # The label claims entropy, so the check measures it: hex tops out at 4
    # bits per character, and a repetitive run like forty a's is a valid hex
    # string with none of it.
    Rule(
        id="credential_value_hex",
        category="tutorial_pattern",
        severity="critical",
        group="credential_value",
        label="high-entropy hex string (possible secret)",
        message="{location}{attr_q} value matches pattern: {label}{via} — remove from source and use a secret reference",
        match=credential_value_match(
            value_matches="^[0-9a-f]{32,}$",
            confirm="hex_entropy",
        ),
    ),
    # Last in the group: no known format matched, so randomness itself is the
    # only signal left. High rather than critical — this is a statistical
    # accusation, not a recognised credential shape.
    Rule(
        id="credential_value_entropy",
        category="tutorial_pattern",
        severity="high",
        group="credential_value",
        message="{location}{attr_q} value is a high-entropy string ({bits} bits/char over {length} chars){via} — this is the statistical signature of a machine-generated secret; if it is one, move it out of source and rotate it",
        match=credential_value_match(
            predicate="looks_like_secret",
        ),
    ),
    # ---------------------------------------------------------------------
    Rule(
        id="open_cidr",
        category="tutorial_pattern",
        severity="high",
        message="{attr_q} includes 0.0.0.0/0 (open to the entire internet) — common tutorial copy-paste, narrow this range",
        match=Match(
            scope="attribute",
            attr_name_contains="cidr",
            literal=True,
            value_contains="0.0.0.0/0",
        ),
    ),
    # ingress and egress only. A CIDR inside some other nested block is far
    # more likely to be a route table or a peering range than a firewall hole.
    Rule(
        id="open_cidr_in_block",
        category="tutorial_pattern",
        severity="high",
        message='"{attr} (inside {block} block)" includes 0.0.0.0/0 (open to the entire internet) — common tutorial copy-paste, narrow this range',
        match=Match(
            scope="block_attribute",
            block_types=["ingress", "egress"],
            attr_name_contains="cidr",
            literal=True,
            value_contains="0.0.0.0/0",
        ),
    ),
    # ---------------------------------------------------------------------
    Rule(
        id="placeholder_resource_name",
        category="tutorial_pattern",
        severity="low",
        message="resource local name {name_q} looks like a tutorial placeholder, not a deliberate identifier",
        match=Match(
            scope="resource_name",
            name_matches=PLACEHOLDER_NAMES,
        ),
    ),
    Rule(
        id="placeholder_attribute_value",
        category="tutorial_pattern",
        severity="low",
        message="{attr} = {value_q} looks like a tutorial placeholder value",
        match=Match(
            scope="attribute",
            attr_names=["name", "bucket", "identifier", "name_prefix", "bucket_prefix"],
            literal=True,
            value_matches=PLACEHOLDER_NAMES,
            value_not_one_of=[""],
        ),
    ),
    # ---------------------------------------------------------------------
    # Compiled traversals. Each needs something no matcher expresses.
    # ---------------------------------------------------------------------
    #
    # Needs the provider's declared attribute surface, plus edit distance to
    # suggest what was meant. Severity is fixed; the message names the
    # near-miss it found.
    Rule(
        id="unknown_attribute",
        category="unknown_attribute",
        severity="high",
        engine="unknown_attribute",
    ),
    # Needs the base revision to compare against: a ForceNew attribute is only
    # a finding when its value actually changed. Severity varies with how
    # destructive replacing that resource type would be.
    Rule(
        id="force_new_change",
        category="force_new_change",
        severity="high",
        engine="force_new_change",
    ),
    # Needs the knowledge base's list of stateful types, and writes its fix by
    # editing HCL source in place.
    Rule(
        id="missing_lifecycle",
        category="missing_lifecycle",
        severity="medium",
        engine="missing_lifecycle",
    ),
    # Needs brace-matched scanning of raw source: terraform { required_providers
    # {} } is not a resource block and never reaches the resource model.
    Rule(
        id="unpinned_version",
        category="unpinned_version",
        severity="medium",
        engine="unpinned_version",
    ),
    # Needs per-type pricing and arithmetic against the base revision.
    Rule(
        id="static_cost",
        category="cost_impact",
        severity="medium",
        engine="static_cost",
        params={"threshold_usd": "0"},
    ),
    # ---------------------------------------------------------------------
    # insecure_config — a guard someone explicitly switched off.
    #
    # Every rule below matches a value that is *written down*, never an
    # absence. That is the whole discipline of this group: `encrypted = false`
    # is a decision somebody made and a reviewer can be asked about, while a
    # missing `encrypted` is the provider default on hundreds of resource
    # types and flagging it would bury the real ones. Absence-based checks are
    # what generic posture scanners do, and they are why those scanners get
    # muted.
    #
    # Severity follows how certain the finding is, not how frightening the
    # subject sounds. `high` blocks at the default threshold, so it is reserved
    # for values with no good reason to exist; `medium` is for settings that
    # are wrong often enough to raise, and legitimate often enough that
    # stopping the merge would be wrong.
    # ---------------------------------------------------------------------
    #
    # Reachable from the internet. The single most-exploited misconfiguration
    # class there is, and one an LLM produces readily because
    # `publicly_accessible = true` is what makes a copy-pasted tutorial work
    # from a laptop.
    #
    # Scoped to the types where it means "on the public internet" rather than
    # "in a public subnet": these four attach a routable address to a data
    # store. High, not critical — a throwaway dev database is a real use, and
    # critical here is reserved for a credential that is definitely leaked.
    Rule(
        id="public_data_store",
        category="public_exposure",
        severity="high",
        message="{resource} sets publicly_accessible = true — this attaches a public IP and puts the data store on the internet, where only its security group stands between it and the world",
        suggestion=(
            "publicly_accessible = false\n"
            "\n"
            "# and reach it from inside the VPC instead — a bastion, VPN, or\n"
            "# SSM Session Manager port-forward."
        ),
        match=Match(
            scope="attribute",
            resource_types=[
                "aws_db_instance",
                "aws_rds_cluster_instance",
                "aws_redshift_cluster",
                "aws_dms_replication_instance",
            ],
            attr_names=["publicly_accessible"],
            literal=True,
            value_matches="^true$",
        ),
        # and reach it from inside the VPC instead — a bastion, VPN, or
        # SSM Session Manager port-forward.
        fix=Fix(
            action="replace_attr_line",
            lines=["publicly_accessible = false"],
        ),
    ),
    # Canned ACLs that grant to AllUsers or AuthenticatedUsers. A public bucket
    # is sometimes deliberate, which is why this is high rather than critical —
    # but the deliberate version is nearly always a static site, and the right
    # shape for that is CloudFront with an origin access identity, not an open
    # bucket that also answers to anyone who finds its name.
    #
    # "authenticated-read" is included and is the least obvious of the three:
    # it reads as a restriction, and it means every authenticated AWS user
    # anywhere, not every user of your account.
    Rule(
        id="public_acl",
        category="public_exposure",
        severity="high",
        message='{location}acl = {value_q} grants access outside this account — "public-read" and "public-read-write" are open to anyone on the internet, and "authenticated-read" is open to every AWS user everywhere, not just yours',
        match=Match(
            scope="any_attribute",
            attr_names=["acl"],
            literal=True,
            value_matches="^(public-read|public-read-write|authenticated-read)$",
        ),
    ),
    # aws_s3_bucket_public_access_block exists to make a bucket un-publishable
    # regardless of what any ACL or policy says. Setting one of its four
    # switches to false is the act of removing that backstop, and it is only
    # ever written deliberately: the resource's whole purpose is to be true.
    Rule(
        id="s3_public_access_block_disabled",
        category="public_exposure",
        severity="high",
        message="{attr} = false on {resource} — this resource exists to stop the bucket being made public by any future ACL or policy, and this switch removes that guarantee",
        match=Match(
            scope="attribute",
            resource_types=["aws_s3_bucket_public_access_block"],
            attr_names=[
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets",
            ],
            literal=True,
            value_matches="^false$",
        ),
        fix=Fix(
            action="replace_attr_line",
            lines=["{attr} = true"],
        ),
    ),
    # IMDSv1. The instance metadata service hands out the role's temporary
    # credentials to anything that can make an HTTP request from the instance —
    # so any server-side request forgery in an application running there
    # becomes credential theft. IMDSv2 requires a PUT to get a token first,
    # which an SSRF cannot perform.
    #
    # Medium rather than high: some agents and older SDKs still speak v1 only,
    # so this is a "justify it" finding, not a "stop the merge" one.
    Rule(
        id="imds_v1_allowed",
        category="public_exposure",
        severity="medium",
        message='metadata_options.http_tokens = "optional" on {resource} allows IMDSv1 — any SSRF in software running on this instance can then read its IAM credentials from 169.254.169.254',
        suggestion=('metadata_options {\n  http_tokens = "required"\n}'),
        match=Match(
            scope="block_attribute",
            block_types=["metadata_options"],
            attr_names=["http_tokens"],
            literal=True,
            value_matches="^optional$",
        ),
        fix=Fix(
            action="replace_attr_line",
            lines=['{attr} = "required"'],
        ),
    ),
    # ---------------------------------------------------------------------
    #
    # Encryption at rest, explicitly turned off. In every provider below the
    # attribute defaults to enabled or the resource is created unencrypted only
    # if asked — so `false` here is always a written decision.
    #
    # These cannot be fixed by flipping the flag on an existing resource: for
    # most of them encryption at rest is ForceNew, which is why the message
    # says so rather than offering a one-line fix that would quietly schedule a
    # replacement.
    Rule(
        id="encryption_at_rest_disabled",
        category="encryption_disabled",
        severity="high",
        message="{location}{attr} = false disables encryption at rest on {resource} — on most types this cannot be turned on later without replacing the resource, so it is decided here or not at all",
        match=Match(
            scope="any_attribute",
            attr_names=[
                "storage_encrypted",
                "encrypted",
                "at_rest_encryption_enabled",
                "encryption_enabled",
                "enable_encryption",
                "infrastructure_encryption_enabled",
            ],
            literal=True,
            value_matches="^false$",
        ),
    ),
    # Encryption in transit, explicitly turned off. Distinct from the at-rest
    # group because the remediation and the exposure are different: this is
    # data readable by anything on the network path, and it is usually a
    # non-destructive flag to flip.
    Rule(
        id="encryption_in_transit_disabled",
        category="encryption_disabled",
        severity="high",
        message="{location}{attr} = false disables encryption in transit on {resource} — traffic to it is readable by anything on the network path between client and service",
        match=Match(
            scope="any_attribute",
            attr_names=[
                "transit_encryption_enabled",
                "encrypt_in_transit",
                "enable_https_traffic_only",
                "https_only",
            ],
            literal=True,
            value_matches="^false$",
        ),
        fix=Fix(
            action="replace_attr_line",
            lines=["{attr} = true"],
        ),
    ),
    # TLS 1.0 and 1.1 are deprecated by the IETF (RFC 8996), removed from the
    # PCI DSS accepted set, and refused by current browsers. A policy naming
    # them is nearly always a value copied from an old example rather than a
    # compatibility requirement someone measured.
    #
    # Medium: a genuinely old client population is a real constraint, and the
    # people who have one know they have one.
    Rule(
        id="weak_tls_policy",
        category="encryption_disabled",
        severity="medium",
        message="{location}{attr} = {value_q} permits TLS 1.0/1.1 on {resource} — both are deprecated by RFC 8996, outside the PCI DSS accepted set, and refused by current browsers",
        match=Match(
            scope="any_attribute",
            attr_names=[
                "ssl_policy",
                "security_policy",
                "min_tls_version",
                "minimum_tls_version",
                "tls_policy",
            ],
            literal=True,
            value_matches="(?i)(TLS-?1[._-]?[01]|TLSv1[._]?[01]?$|^1\\.[01]$)",
        ),
    ),
    # ---------------------------------------------------------------------
    #
    # An audit trail switched off. Unlike a missing log setting — which is a
    # default on most resource types and not worth reporting — writing
    # `enable_logging = false` on a trail is turning off the record of who did
    # what, on the resource whose only job is to keep it.
    #
    # Scoped by resource type on purpose. `enabled = false` appears on hundreds
    # of unrelated blocks, and matching the bare name would report a disabled
    # autoscaling schedule as a compliance failure.
    Rule(
        id="audit_logging_disabled",
        category="audit_disabled",
        severity="high",
        message="{attr} = false on {resource} disables the audit trail itself — this is the record used to answer what happened, and it is being switched off in configuration rather than by an attacker",
        match=Match(
            scope="attribute",
            resource_types=["aws_cloudtrail", "aws_flow_log", "azurerm_monitor_diagnostic_setting"],
            attr_names=["enable_logging", "enabled"],
            literal=True,
            value_matches="^false$",
        ),
        fix=Fix(
            action="replace_attr_line",
            lines=["{attr} = true"],
        ),
    ),
    # ---------------------------------------------------------------------
    #
    # skip_final_snapshot lives under missing_lifecycle rather than in its own
    # category because it is the same concern the reader already has docs for:
    # nothing stands between a destroy and permanent loss. prevent_destroy
    # refuses the destroy; a final snapshot survives it. A resource with
    # neither has no recovery path at all.
    #
    # Medium because throwaway environments legitimately set it, and because it
    # is only a loss when combined with an actual destroy.
    Rule(
        id="skip_final_snapshot",
        category="missing_lifecycle",
        severity="medium",
        message="skip_final_snapshot = true on {resource} — a destroy of this database keeps nothing, so recovery after a mistaken apply is impossible rather than slow",
        suggestion=(
            'skip_final_snapshot       = false\nfinal_snapshot_identifier = "{name}-final"'
        ),
        match=Match(
            scope="attribute",
            resource_types=[
                "aws_db_instance",
                "aws_rds_cluster",
                "aws_docdb_cluster",
                "aws_neptune_cluster",
                "aws_redshift_cluster",
            ],
            attr_names=["skip_final_snapshot"],
            literal=True,
            value_matches="^true$",
        ),
    ),
    # ---------------------------------------------------------------------
    #
    # IAM policy documents with a wildcard. Compiled rather than declarative
    # because the policy body is nearly always jsonencode({…}) — an expression,
    # not a literal, so no matcher can see inside it. See rule_iam_wildcard.go.
    Rule(
        id="iam_wildcard",
        category="permissive_iam",
        severity="high",
        engine="iam_wildcard",
    ),
    # The aws_iam_policy_document data source is the one policy form that IS
    # declarative: its statements are real HCL blocks, so `actions = ["*"]`
    # reaches the resource model as a literal and needs no compiled traversal.
    #
    # A single-element list flattens to its element, which is what makes the
    # anchored pattern below correct: it matches ["*"] and not
    # ["s3:*", "ec2:*"], where each element is a scoped wildcard and the
    # combination is ordinary least-privilege work in progress.
    Rule(
        id="iam_document_wildcard_action",
        category="permissive_iam",
        severity="high",
        message='statement in {resource} sets actions = ["*"] — every action in every AWS service, including the IAM calls that would let a holder grant itself anything else',
        suggestion='actions = ["s3:GetObject", "s3:PutObject"]',
        match=Match(
            scope="block_attribute",
            resource_types=["aws_iam_policy_document"],
            block_types=["statement"],
            attr_names=["actions"],
            literal=True,
            value_matches="^\\*$",
        ),
    ),
    # Deliberately not paired with a resources = ["*"] rule. A wildcard
    # resource alone is unavoidable for the many actions whose API takes no
    # ARN — s3:ListAllMyBuckets, ec2:Describe*, most of iam:List* — so
    # reporting it would fire on a large share of correct policies. It is only
    # a finding next to a wildcard action, and that pair is caught above.
    Rule(
        id="iam_document_wildcard_principal",
        category="permissive_iam",
        severity="high",
        message='principals block in {resource} names identifiers = ["*"] — this grants the statement to every AWS account on earth, not to every principal in yours',
        match=Match(
            scope="block_attribute",
            resource_types=["aws_iam_policy_document"],
            block_types=["principals"],
            attr_names=["identifiers"],
            literal=True,
            value_matches="^\\*$",
        ),
    ),
    # ---------------------------------------------------------------------
    # Plan-based. These read terraform's own JSON plan rather than source, so
    # they have no line to anchor to and no source to match against.
    # ---------------------------------------------------------------------
    Rule(
        id="confirmed_replace",
        category="confirmed_replace",
        severity="critical",
        engine="confirmed_replace",
    ),
    Rule(
        id="unexpected_drift",
        category="unexpected_drift",
        severity="medium",
        engine="unexpected_drift",
    ),
    Rule(
        id="large_blast_radius",
        category="large_blast_radius",
        severity="medium",
        engine="large_blast_radius",
    ),
    Rule(
        id="plan_cost_impact",
        category="cost_impact",
        severity="medium",
        engine="plan_cost_impact",
    ),
]


DOCS: list[CategoryDoc] = [
    CategoryDoc(
        category="unknown_attribute",
        title="Unknown/hallucinated attribute",
        full_description="An argument that the provider does not declare for this resource type. Terraform rejects it at plan time; the value of catching it here is that nobody waits for a plan to find out.",
        markdown=(
            "## What this means\n"
            "\n"
            "The argument isn't part of the resource type's schema in the provider version\n"
            "this scanner checked against. Terraform will reject it with\n"
            '`An argument named "…" is not expected here` — this finding is that\n'
            "error, delivered before CI spends a plan on it.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "This is the most reliable signature of generated Terraform. A model asked for\n"
            "an argument that ought to exist will produce one that sounds exactly right,\n"
            "and it fails only once the plan runs — often after a reviewer has already\n"
            "approved the diff.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "Open the linked provider documentation for the resource type and compare the\n"
            "argument list. Usually it is one of:\n"
            "\n"
            "- a near-miss on a real argument name,\n"
            "- an argument that belongs in a nested block rather than at the top level,\n"
            "- an argument removed in a provider major version.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "The argument surface is generated from the provider's own schema, so a false\n"
            "positive here means the scanner's rule pack is older than your provider.\n"
            "Suppress a single line with `# tf-firewall-ignore: unknown_attribute`,\n"
            "or the whole category with `ignore_rules` in the config."
        ),
    ),
    CategoryDoc(
        category="unpinned_version",
        title="Unpinned module or provider version",
        full_description="A module source or provider requirement with no version pin. The plan that was reviewed and the plan that runs later can differ with no commit in this repository to explain why.",
        markdown=(
            "## What this means\n"
            "\n"
            "A dependency floats instead of naming a version: a registry module with no\n"
            "`version`, a git source with no `?ref=`, or a `?ref=main`\n"
            "that points at a branch someone can push to. Or a provider in\n"
            "`required_providers` with no `version` constraint.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "Two distinct problems, and the second is the serious one:\n"
            "\n"
            "**Reproducibility.** The plan a reviewer approved and the plan that runs an\n"
            "hour later can differ, because a third party published a release or moved a\n"
            "branch. Nothing in this repository records that, so when the apply goes\n"
            "wrong there is no commit to look at.\n"
            "\n"
            "**Supply chain.** Whoever can push to that branch decides what Terraform\n"
            "runs against your cloud account, with your credentials. A pinned tag can\n"
            "still be moved; a commit SHA cannot.\n"
            "\n"
            "This rule sits next to the AI-hallucination checks for a reason: generated\n"
            'Terraform almost never writes a version constraint. A model asked for "a VPC\n'
            'module" emits a source and moves on.\n'
            "\n"
            "## How to fix it\n"
            "\n"
            "```hcl\n"
            'module "vpc" {\n'
            '  source  = "terraform-aws-modules/vpc/aws"\n'
            '  version = "~> 5.0"                          # registry: add version\n'
            "}\n"
            "\n"
            'module "internal" {\n'
            '  source = "git::https://github.com/org/mod.git?ref=v1.4.2"   # tag…\n'
            "}\n"
            "\n"
            'module "critical" {\n'
            '  source = "git::https://github.com/org/mod.git?ref=9f8a1c2"  # …or a SHA\n'
            "}\n"
            "\n"
            "terraform {\n"
            "  required_providers {\n"
            "    aws = {\n"
            '      source  = "hashicorp/aws"\n'
            '      version = "~> 6.0"\n'
            "    }\n"
            "  }\n"
            "}\n"
            "```\n"
            "\n"
            "A `.terraform.lock.hcl` committed alongside pins provider versions\n"
            "exactly, and is worth having regardless of the constraint above.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "A local module (`./modules/vpc`) is versioned by this repository's\n"
            "own history and is never flagged. If you deliberately track a branch — an\n"
            "internal module you also own, released continuously — suppress with\n"
            "`# tf-firewall-ignore: unpinned_version`, or the category with\n"
            "`ignore_rules`."
        ),
    ),
    CategoryDoc(
        category="tutorial_pattern",
        title="Tutorial-copy pattern",
        full_description="A value that looks copied from documentation rather than chosen: a credential written as a string literal, a CIDR open to the whole internet, or a placeholder name.",
        markdown=(
            "## What this means\n"
            "\n"
            "The value matches a pattern that is normal in a tutorial and wrong in a real\n"
            "repository — a hardcoded credential, `0.0.0.0/0`, or a placeholder\n"
            "name like `example` or `test`.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "A credential committed to a repository is disclosed to everyone with read\n"
            "access and stays in git history after it is removed. An ingress rule open to\n"
            "`0.0.0.0/0` is reachable from the entire internet, which is only ever\n"
            "deliberate for a small number of ports.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "**Credentials:** move the value out of the repository — a variable supplied by\n"
            "your secret manager, or the provider's own managed-secret support (for RDS,\n"
            "`manage_master_user_password = true` removes the need for a password\n"
            "in configuration at all). **Then rotate the old value**: removing it from the\n"
            "file does not remove it from history.\n"
            "\n"
            "**Open CIDRs:** narrow to the ranges that actually need access. If a public\n"
            "listener is the intent, that is what a suppression comment is for.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "Suppress one line with `# tf-firewall-ignore: tutorial_pattern`. A\n"
            "deliberately public load balancer is a legitimate reason; a credential is\n"
            "essentially never one."
        ),
    ),
    CategoryDoc(
        category="force_new_change",
        title="ForceNew change on stateful resource",
        full_description="A changed argument that the provider marks ForceNew, meaning apply will destroy and recreate the resource rather than update it in place.",
        markdown=(
            "## What this means\n"
            "\n"
            "The provider marks this argument `ForceNew`: it cannot be changed on\n"
            "an existing resource. Applying this diff destroys the resource and creates a\n"
            "replacement.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "On a stateful resource this is data loss and downtime, and it does not look\n"
            "like either in the diff — a one-line change to a name or an availability zone\n"
            "reads as trivial. This is the finding that most often catches something a\n"
            "human review missed.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "Decide deliberately, then make the decision visible:\n"
            "\n"
            "- If replacement is intended, say so in the PR description, and check whether\n"
            "  a snapshot or backup exists first.\n"
            "- If it is not, revert the argument and reach the goal another way — many\n"
            "  resources have an in-place equivalent (renaming an RDS instance's\n"
            "  `identifier` is in-place; changing its `availability_zone`\n"
            "  is not).\n"
            "- Run `terraform plan` and read the `# forces replacement`\n"
            "  annotations. Supplying the plan JSON to this action upgrades this heuristic\n"
            "  finding into a confirmed one.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "Nothing is wrong with a deliberate replacement — the finding exists so that it\n"
            "is deliberate. Suppress with `# tf-firewall-ignore: force_new_change`\n"
            "once you have decided."
        ),
    ),
    CategoryDoc(
        category="missing_lifecycle",
        title="Missing prevent_destroy",
        full_description="A stateful resource with no lifecycle { prevent_destroy = true } guard, leaving it exposed to accidental deletion by an apply.",
        markdown=(
            "## What this means\n"
            "\n"
            "This resource type holds data that cannot be recreated from configuration —\n"
            "a database, a volume, a bucket — and carries no\n"
            "`lifecycle { prevent_destroy = true }` block.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "`prevent_destroy` makes Terraform refuse to plan a destroy of the\n"
            "resource at all. Without it, the only thing standing between a mistaken\n"
            "`terraform destroy`, a removed block, or a ForceNew change and the\n"
            "loss of production data is somebody reading the plan output carefully.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "```hcl\n"
            'resource "aws_db_instance" "prod" {\n'
            "  # …\n"
            "\n"
            "  lifecycle {\n"
            "    prevent_destroy = true\n"
            "  }\n"
            "}\n"
            "```\n"
            "\n"
            "This scanner posts that as an applicable suggestion on the PR where it can.\n"
            "\n"
            "Note that `prevent_destroy` blocks the plan rather than warning about\n"
            "it: intentionally destroying the resource later means removing the guard in\n"
            "its own commit, which is the point — it makes the deletion an explicit,\n"
            "reviewable act.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "Ephemeral environments are the real exception. Scope the exemption to them\n"
            "with an `ignore_paths` entry rather than turning the rule off\n"
            "everywhere."
        ),
    ),
    CategoryDoc(
        category="confirmed_replace",
        title="Confirmed destroy/replace (from terraform plan)",
        full_description="terraform plan confirms this apply destroys or replaces a stateful resource. Not a heuristic — Terraform's own diff says so.",
        markdown=(
            "## What this means\n"
            "\n"
            "This comes from the plan JSON you supplied, not from reading the `.tf`\n"
            "files: Terraform's own diff engine reports this resource as `delete`\n"
            "or `replace`.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "There is no ambiguity left to argue about. If the resource holds data, this\n"
            "apply loses it.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "Confirm a backup or snapshot exists, then decide whether the replacement is\n"
            "what you meant. If it isn't, `terraform plan` output names the\n"
            "attribute forcing it — the fix is to change that attribute back.\n"
            "\n"
            "A `lifecycle { prevent_destroy = true }` guard would have turned this\n"
            "into a plan-time refusal instead of an approved PR.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "A deliberate replacement of a resource that holds nothing you need is\n"
            "legitimate. Suppress with `# tf-firewall-ignore: confirmed_replace`\n"
            "after checking, not before."
        ),
    ),
    CategoryDoc(
        category="unexpected_drift",
        title="Unexpected drift (from terraform plan)",
        full_description="terraform plan changes a sensitive attribute that this PR's own .tf diff never touched — the change comes from somewhere else.",
        markdown=(
            "## What this means\n"
            "\n"
            "The plan modifies an attribute that nothing in this PR's Terraform diff\n"
            "touches. The change originates elsewhere: a module version bump, a provider\n"
            "upgrade, a variable's value, or infrastructure that was modified outside\n"
            "Terraform.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "It is the change nobody is reviewing. The diff on screen doesn't contain it,\n"
            "so the reviewer's attention is on a different set of lines entirely.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "Work out where it comes from before applying:\n"
            "\n"
            "- `terraform plan` shows the before and after values.\n"
            "- If the resource was changed by hand in the console, the plan is about to\n"
            "  revert that change.\n"
            "- If a module or provider upgrade caused it, read that release's changelog.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "Expected drift after a provider upgrade is common — suppress it for that PR\n"
            "with `# tf-firewall-ignore: unexpected_drift` rather than adding\n"
            "`unexpected_drift` to `ignore_rules` permanently, which\n"
            "turns off the only rule that watches changes nobody is reviewing."
        ),
    ),
    CategoryDoc(
        category="large_blast_radius",
        title="Large blast radius (from terraform plan)",
        full_description="The plan destroys or replaces an unusually large number of resources at once.",
        markdown=(
            "## What this means\n"
            "\n"
            "The count of destroy and replace actions in this plan is above the configured\n"
            "threshold (`plan_blast_radius_threshold`, default 10).\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "Large replacements are usually a symptom rather than an intent — a renamed\n"
            "module, a changed `for_each` key, a moved resource — and they are\n"
            "exactly the plans people approve without reading to the end.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "Check whether the resources are being **moved** rather than replaced. If they\n"
            "are, `moved` blocks (or `terraform state mv`) preserve them\n"
            "and reduce the plan to nothing. If the replacement is real, consider splitting\n"
            "the change into several applies.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "Tearing down a whole environment is a legitimate large plan. Raise\n"
            "`plan_blast_radius_threshold` for a repo where that is routine."
        ),
    ),
    CategoryDoc(
        category="cost_impact",
        title="Estimated cost impact",
        full_description="The change increases the estimated monthly bill by more than the configured threshold. Estimates are coarse and on-demand-only.",
        markdown=(
            "## What this means\n"
            "\n"
            "Summing the coarse per-type prices in the rule pack, this change raises the\n"
            "estimated monthly cost by more than `cost_impact_threshold_usd`.\n"
            "\n"
            "With a plan JSON supplied, the estimate reads Terraform's own diff (counts\n"
            "and for_each included). Without one, a static estimate reads the `.tf`\n"
            "source directly — new resources of priced types, and changes to the\n"
            "attribute that drives a type's price — with no multipliers, since inventing\n"
            "a fleet size would be worse than understating one. When a plan is supplied,\n"
            "only the plan-based estimate runs; the same PR is never billed twice by two\n"
            "estimators that could disagree.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "Cost mistakes in Terraform are silent and recurring. A wrong instance size or\n"
            "a forgotten NAT gateway bills every hour until somebody reads an invoice, and\n"
            "the diff that introduced it looked like one word.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "Check the resource types and sizes the finding names. The most common causes\n"
            "are an oversized instance class copied from an example, a NAT gateway where a\n"
            "gateway endpoint would do, and provisioned capacity left at a default.\n"
            "\n"
            "## Accuracy\n"
            "\n"
            "These are **estimates**, deliberately coarse: on-demand list prices, no\n"
            "reserved instances, no savings plans, no data transfer, no per-request\n"
            "charges. Treat a finding as a prompt to look, not as a quote. Set\n"
            "`cost_impact_threshold_usd: 0` to switch the category off."
        ),
    ),
    CategoryDoc(
        category="public_exposure",
        title="Reachable from the internet",
        full_description="A setting that places a resource, or the data in it, on the public internet — an explicit value, not an omitted default.",
        markdown=(
            "## What this means\n"
            "\n"
            "Something in this resource was set to a value that makes it reachable from\n"
            "outside your network: a database given a public address, a bucket ACL that\n"
            "grants to everyone, a public-access block switched off, or an instance left\n"
            "answering the older metadata service.\n"
            "\n"
            "Each of these is an attribute somebody typed. This category never reports a\n"
            "missing setting — an absent `publicly_accessible` is the safe default on\n"
            "every type here, and flagging defaults is how a scanner gets muted.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "Public exposure is the shortest path there is between a configuration\n"
            "mistake and a breach, and it needs no other bug to be exploitable. A\n"
            "publicly-addressable database is protected by nothing but its security\n"
            "group; a `public-read` bucket is protected by nothing at all. The IMDSv1\n"
            "case is one step longer and just as well-trodden: any server-side request\n"
            "forgery in software on the instance can read the instance role's temporary\n"
            "credentials from 169.254.169.254, which is the shape of the 2019 Capital One\n"
            "breach.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "- `publicly_accessible = true` → set it to `false` and reach the database\n"
            "  from inside the VPC: a bastion, a VPN, or an SSM Session Manager\n"
            "  port-forward.\n"
            '- `acl = "public-read"` → serve the objects through CloudFront with an\n'
            "  origin access identity, and leave the bucket private. Note that\n"
            "  `authenticated-read` means every AWS user anywhere, not every user of\n"
            "  your account.\n"
            "- `block_public_*  = false` → set them back to `true`. This resource exists\n"
            "  to make the bucket un-publishable regardless of any future ACL or policy;\n"
            "  with a switch off, that guarantee is gone.\n"
            '- `http_tokens = "optional"` → `"required"`. IMDSv2 needs a PUT to obtain a\n'
            "  token first, which an SSRF cannot perform.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "A deliberately public bucket or a throwaway database is a real thing to\n"
            "have. Suppress the single line with `# tf-firewall-ignore: public_exposure`,\n"
            "which keeps the decision next to the code that made it, or the whole\n"
            "category with `ignore_rules` in the config."
        ),
    ),
    CategoryDoc(
        category="encryption_disabled",
        title="Encryption switched off",
        full_description="Encryption at rest or in transit explicitly disabled, or a TLS policy that still permits TLS 1.0/1.1.",
        markdown=(
            "## What this means\n"
            "\n"
            "An attribute that turns encryption on was set to `false`, or a TLS policy\n"
            "names a protocol version that is no longer considered secure.\n"
            "\n"
            "As with everything in this group, only written values are reported. A\n"
            "resource with no `encrypted` attribute at all is not a finding here.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "Encryption at rest is the control that makes a stolen disk, a leaked\n"
            "snapshot or a mis-shared backup a non-event rather than a disclosure. On\n"
            "most resource types it is also **ForceNew**: it cannot be turned on later\n"
            "without replacing the resource and moving the data, so it is decided in the\n"
            "commit that creates it or not at all. That is the reason this is worth\n"
            "stopping a merge for and a missing tag is not.\n"
            "\n"
            "Encryption in transit is what stops anything on the network path reading the\n"
            "traffic — inside a VPC that includes any other compromised workload in it.\n"
            "\n"
            "TLS 1.0 and 1.1 are deprecated by RFC 8996, outside the PCI DSS accepted\n"
            "set, and refused by current browsers. A policy naming them is nearly always\n"
            "a value copied from an old example rather than a compatibility requirement\n"
            "somebody measured.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "Set the flag to `true`. If the resource already exists, check the plan\n"
            "before applying: for at-rest encryption on most types, Terraform will show a\n"
            "replacement, and the data has to be migrated deliberately rather than by\n"
            "letting the apply do it.\n"
            "\n"
            "For a TLS policy, move to the current recommended set — on an AWS load\n"
            "balancer that is `ELBSecurityPolicy-TLS13-1-2-2021-06` or later.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "A genuinely old client population is a real constraint, and the teams that\n"
            "have one know they have one. `# tf-firewall-ignore: encryption_disabled` on\n"
            "the line, or `ignore_rules` for the category."
        ),
    ),
    CategoryDoc(
        category="permissive_iam",
        title="Wildcard IAM policy",
        full_description="An IAM policy document granting every action, or granting to every principal with no condition narrowing it.",
        markdown=(
            "## What this means\n"
            "\n"
            'A policy attached to this resource contains `Action: "*"` — every action in\n'
            'every AWS service — or names `Principal: "*"` with no `Condition` limiting\n'
            "who that is.\n"
            "\n"
            "The check reads the policy from source rather than from the resource model,\n"
            "because the form nearly everyone writes is `jsonencode({ … })`: a function\n"
            "call over an object, which no value matcher can see inside. Heredoc and\n"
            "plain-JSON policies are read the same way.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            '`Action: "*"` with `Resource: "*"` is administrator access. It includes the\n'
            "IAM actions, which means a holder can grant itself anything it was not\n"
            "already given — so the blast radius of any compromise of that role is the\n"
            "whole account, and no later tightening of other policies constrains it.\n"
            "\n"
            '`Principal: "*"` on a resource policy means every AWS account on earth, not\n'
            "every principal in yours. It is the difference between an internal bucket\n"
            "and a public one, written in a place people rarely re-read.\n"
            "\n"
            "Both are what a language model produces when it does not know the exact\n"
            "action names, because a wildcard is the answer that always works.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "Name the actions the workload actually performs and the resources it\n"
            "performs them on:\n"
            "\n"
            "```hcl\n"
            'Action   = ["s3:GetObject", "s3:PutObject"]\n'
            'Resource = ["${aws_s3_bucket.data.arn}/*"]\n'
            "```\n"
            "\n"
            "If a public principal is genuinely wanted, narrow it with a condition —\n"
            "`aws:PrincipalOrgID` for org-wide access, `aws:SourceArn` for a specific\n"
            "service:\n"
            "\n"
            "```hcl\n"
            "Condition = {\n"
            '  StringEquals = { "aws:PrincipalOrgID" = "o-example" }\n'
            "}\n"
            "```\n"
            "\n"
            "## What this deliberately does not report\n"
            "\n"
            '`Resource: "*"` on its own. A large family of actions takes no resource ARN\n'
            "at all — `s3:ListAllMyBuckets`, `ec2:Describe*`, most of `iam:List*` — so a\n"
            "rule that flagged it would fire on a large share of correct policies. It is\n"
            "reported only alongside a wildcard action, where the pair means\n"
            "administrator.\n"
            "\n"
            'A `Principal: "*"` in a document that also carries a `Condition`. That is\n'
            "the org-wide pattern and it is correct.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "A break-glass role or a deliberately public read policy is legitimate.\n"
            "`# tf-firewall-ignore: permissive_iam`, or `ignore_rules` for the category."
        ),
    ),
    CategoryDoc(
        category="audit_disabled",
        title="Audit logging switched off",
        full_description="A trail or diagnostic setting whose logging is explicitly disabled — the record of what happened, turned off in configuration.",
        markdown=(
            "## What this means\n"
            "\n"
            "A resource whose only job is to keep a record has `enable_logging = false`\n"
            "or `enabled = false`.\n"
            "\n"
            "Scoped tightly by resource type on purpose. `enabled = false` appears on\n"
            "hundreds of unrelated blocks, and matching the bare attribute name would\n"
            "report a paused autoscaling schedule as a compliance failure.\n"
            "\n"
            "## Why it matters\n"
            "\n"
            "An audit trail is the only thing that can answer what happened, after the\n"
            "fact, when it matters. Its value is entirely retrospective: it has to have\n"
            "been running *before* the incident, so a trail switched off today is a\n"
            "question that becomes unanswerable for every day it stays off. Unlike most\n"
            "findings, this one cannot be fixed retroactively.\n"
            "\n"
            "It is also, in most regulated frameworks, a control that is asserted rather\n"
            "than checked — SOC 2, PCI DSS and ISO 27001 all assume the log exists.\n"
            "\n"
            "## How to fix it\n"
            "\n"
            "Set it back to `true`. If the trail is disabled because it is noisy or\n"
            "expensive, the usual answers are an event selector that narrows what is\n"
            "recorded, or a lifecycle policy on the destination bucket — both keep the\n"
            "record while reducing what it costs.\n"
            "\n"
            "## If you disagree\n"
            "\n"
            "A trail deliberately parked in a sandbox account is reasonable.\n"
            "`# tf-firewall-ignore: audit_disabled` on the line, or `ignore_rules` for\n"
            "the category."
        ),
    ),
]


def build() -> Pack:
    """Construit et valide le pack.

    `index()` fait tout le travail de vérification : il compile chaque
    expression régulière, vérifie chaque énumération et rejette les doublons
    d'identifiant — le même code que pour un pack YAML chargé depuis un
    fichier, pour qu'un pack écrit ici ne bénéficie d'aucune indulgence.
    """
    pack = Pack(version=FORMAT_VERSION_DECLARED, rules=RULES, docs=DOCS)
    pack.index()
    return pack
