"""Les trois bugs qu'une campagne de prospection a trouvés sur du vrai code.

Aucun n'a été inventé ici. Chacun vient d'un dépôt public réel, et chacun est
d'une famille que la suite ne couvrait pas : elle vérifiait que les règles
détectent, jamais qu'elles se taisent quand il faut.

Nommés d'après le dépôt qui les a révélés, pour qu'on sache d'où vient le cas
le jour où quelqu'un voudra l'assouplir.
"""

from __future__ import annotations

import pytest

from tfpdf import providerversion
from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Finding
from tfpdf.rules import default_rules, run
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_schema()


def _scan(kb: KnowledgeBase, source: str, path: str = "main.tf", **extra: str) -> list[Finding]:
    """Scanne un module d'un ou plusieurs fichiers, sans toucher au disque.

    Les fichiers supplémentaires comptent : une contrainte de version vit
    presque toujours dans versions.tf, pas dans le fichier qui porte la
    ressource.
    """
    files = [ChangedFile(path=path, head_content=source.encode())]
    files += [ChangedFile(path=p, head_content=c.encode()) for p, c in extra.items()]
    return run(files, kb, default_rules()).findings


# --- Rootly : la suggestion inventait l'adresse du fournisseur ---------------


ROOTLY = """terraform {
  required_providers {
    rootly = {
      source = "rootlyhq/rootly"
    }
  }
}
"""


def test_the_fix_never_invents_a_provider_address(kb: KnowledgeBase) -> None:
    """Rootly publie `rootlyhq/rootly`, et l'écrit dans l'entrée elle-même. La
    suggestion proposait `hashicorp/rootly` — une adresse qui n'existe pas —
    dans un bloc ```suggestion, c'est-à-dire derrière un bouton « Commit
    suggestion ». Envoyer ça à l'équipe qui publie le fournisseur est le pire
    résultat possible d'un outil vendu sur l'exactitude."""
    findings = [f for f in _scan(kb, ROOTLY) if f.rule_name == "unpinned_version"]
    assert len(findings) == 1, "la découverte elle-même reste juste et doit rester"
    assert "hashicorp/rootly" not in findings[0].suggestion
    assert findings[0].suggestion == "", (
        "sans savoir quelle version existe, il n'y a rien à suggérer — "
        "la découverte suffit à dire ce qui manque"
    )


def test_a_known_provider_still_gets_a_real_pin(kb: KnowledgeBase) -> None:
    """L'inverse : pour un fournisseur dont on porte le schéma, la suggestion
    reprend l'adresse déclarée telle quelle et propose le majeur qu'on connaît
    réellement — pas la constante « ~> 5.0 » qui traînait là."""
    source = ROOTLY.replace(
        'rootly = {\n      source = "rootlyhq/rootly"', 'aws = {\n      source = "hashicorp/aws"'
    )
    finding = next(f for f in _scan(kb, source) if f.rule_name == "unpinned_version")
    version = next(p.version for p in kb.coverage().providers if p.name == "aws")
    assert 'source  = "hashicorp/aws"' in finding.suggestion
    assert f'version = "~> {version.split(".")[0]}.0"' in finding.suggestion


# --- wandb : un ARN de policy managée rapporté comme clé AWS ----------------


def test_a_managed_policy_arn_is_not_a_leaked_secret(kb: KnowledgeBase) -> None:
    """Le seul critical d'un lot entier, et un faux positif.

    `[a-z0-9/+]{40}` n'est pas ancré : il trouve sa fenêtre à l'intérieur du nom
    de la policy, la confirmation ne juge que cette fenêtre, et la valeur
    entière — qui commence par `arn:` — n'était regardée par personne.
    """
    source = """resource "aws_iam_role_policy_attachment" "ecr" {
  role       = "some-role"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}
"""
    assert not [f for f in _scan(kb, source) if f.rule_name.startswith("credential_value")]


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        # Une clé publique SSH : le mot « publique » est dans le nom.
        ("public_key", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA8sX2Y1mZ0kQnJ8"),
        # L'empreinte OIDC d'un cluster EKS, publiée par le fournisseur d'identité.
        ("thumbprint", "9e99a48a9960b14926bb7f3b02e22da2b0ab7280"),
        # Un enregistrement DNS, servi au monde entier par construction.
        ("records", "gv-9f8Hs2kLmQpR4tYuVwXzAbCdEfGhIjKlMnOpQrStUv"),
    ],
)
def test_values_that_are_public_by_definition_are_not_accused(
    kb: KnowledgeBase, attribute: str, value: str
) -> None:
    """Ces trois-là portent de la haute entropie sans qu'aucun secret ne soit en
    jeu. La forme ne peut pas les distinguer d'un jeton ; seul le nom le peut.
    Sur un lot de dépôts publics, ils expliquaient l'essentiel du bruit."""
    source = f'resource "aws_thing" "t" {{\n  {attribute} = "{value}"\n}}\n'
    assert not [f for f in _scan(kb, source) if f.rule_name.startswith("credential_value")]


def test_a_secret_buried_in_a_larger_value_is_still_found(kb: KnowledgeBase) -> None:
    """La garde de la garde.

    Une première version de l'exclusion écartait toute valeur contenant un
    espace, ce qui est juste pour l'entropie et faux pour les motifs : une clé
    AWS au milieu d'un script `user_data` est précisément la fuite qu'on
    cherche. Le corpus doré l'a attrapée, avec une clé PEM.
    """
    source = """resource "aws_instance" "app" {
  ami       = "ami-0abcdef1234567890"
  user_data = "#!/bin/bash\\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\\necho ok\\n"
}
"""
    assert [f for f in _scan(kb, source) if f.rule_name == "credential_value_aws_access_key"]


# --- binbashar : jugé contre une version que le dépôt n'utilise pas ----------


PINNED_3 = """terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}
"""

EIP = """resource "aws_eip" "nat" {
  vpc = true
}
"""


def test_an_attribute_valid_in_the_pinned_version_is_not_called_hallucinated(
    kb: KnowledgeBase,
) -> None:
    """Le bug qui touche la promesse centrale.

    `vpc = true` sur `aws_eip` est valide en AWS 3.x — l'attribut n'a disparu
    qu'en 6.x. Le scanner le rapportait en « attribut inconnu », severity high,
    avec un lien vers la documentation 6.59.0. C'est la différence entre ce
    produit et `terraform validate`, et elle jouait à l'envers.
    """
    findings = _scan(kb, EIP, **{"versions.tf": PINNED_3})
    assert not [f for f in findings if f.rule_name == "unknown_attribute"]


def test_the_scan_says_which_provider_it_stayed_silent_about(kb: KnowledgeBase) -> None:
    """Se taire sans le dire ferait lire « aucune découverte » comme « rien à
    signaler »."""
    files = [
        ChangedFile(path="main.tf", head_content=EIP.encode()),
        ChangedFile(path="versions.tf", head_content=PINNED_3.encode()),
    ]
    notes = run(files, kb, default_rules()).notes
    assert len(notes) == 1
    assert "~> 3.0" in notes[0] and "aws" in notes[0]


def test_a_pin_that_covers_our_schema_is_still_judged(kb: KnowledgeBase) -> None:
    """L'autre sens, sans quoi le correctif serait juste un aveuglement : un
    dépôt épinglé sur la version qu'on porte doit toujours être jugé."""
    pinned_6 = PINNED_3.replace("~> 3.0", "~> 6.0")
    findings = _scan(kb, EIP, **{"versions.tf": pinned_6})
    assert [f for f in findings if f.rule_name == "unknown_attribute"]


def test_a_pinned_provider_does_not_silence_value_rules(kb: KnowledgeBase) -> None:
    """Un mot de passe en clair est un mot de passe en clair sur toutes les
    versions d'AWS. Seules les deux règles tirées du SCHÉMA se taisent."""
    source = """resource "aws_db_instance" "prod" {
  identifier = "prod"
  password   = "hunter2correcthorsebattery"
}
"""
    findings = _scan(kb, source, **{"versions.tf": PINNED_3})
    assert [f for f in findings if f.rule_name == "hardcoded_credential"]


# --- la lecture des contraintes elle-même ------------------------------------


@pytest.mark.parametrize(
    ("constraint", "version", "allowed"),
    [
        ("~> 3.0", "3.75.2", True),
        ("~> 3.0", "4.0.0", False),
        ("~> 3.0.1", "3.0.9", True),
        ("~> 3.0.1", "3.1.0", False),
        # Le cas dbl-works : une borne basse sans borne haute laisse passer le
        # majeur suivant, ce qui est exactement leur problème et pas le nôtre.
        (">= 3.93.0", "4.81.0", True),
        (">= 4.0, < 5.0", "4.81.0", True),
        (">= 4.0, < 5.0", "5.0.0", False),
        ("= 6.59.0", "6.59.0", True),
        ("!= 6.59.0", "6.59.0", False),
        # Sans contrainte, le schéma le plus récent est le bon pari.
        ("", "6.59.0", True),
        # Illisible : on autorise, plutôt que de faire taire des découvertes
        # justes sur une contrainte mal comprise.
        ("something odd", "6.59.0", True),
    ],
)
def test_terraform_version_constraints(constraint: str, version: str, allowed: bool) -> None:
    assert providerversion.allows(constraint, version) is allowed


def test_constraints_are_read_from_the_short_form_too() -> None:
    """Terraform accepte encore `aws = "~> 5.0"` sans bloc."""
    source = b'terraform {\n  required_providers {\n    aws = "~> 5.0"\n  }\n}\n'
    assert providerversion.constraints_in(source) == {"aws": "~> 5.0"}
