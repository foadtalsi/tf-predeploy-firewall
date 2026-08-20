"""Détection des chaînes à forte entropie : le repli pour les secrets qui ne
correspondent à aucun format connu.

Port de internal/rules/entropy.go.

Une clé AWS a un préfixe, un JWT a des points, un PEM a un en-tête — mais un
jeton d'API aléatoire d'un SaaS quelconque n'est que quarante caractères de
base64 sans aucune forme, et des motifs fondés sur la forme n'énuméreront jamais
tous les fournisseurs. Le hasard lui-même est la seule propriété qu'ils
partagent tous.

Tout ici est réglé contre les faux positifs plutôt que pour le rappel, parce que
cette vérification tourne sur chaque littéral de chaîne de chaque fichier scanné
et que son mode de défaillance — signaler un ARN ou un identifiant de ressource
comme un secret fuité — est exactement ce qui apprend aux gens à ignorer une
règle.
"""

from __future__ import annotations

import math

#: The shortest literal worth measuring. Below this, even a genuinely random
#: string's entropy estimate is too noisy to accuse anyone over.
ENTROPY_MIN_LENGTH = 24

#: Bits per character. Notable calibration points: English prose sits around 3,
#: hex maxes out at 4 (16 symbols), UUIDs land ~3.6 because of their fixed
#: dashes, and random base64 runs ~5.2. The threshold sits above every
#: identifier format cloud providers emit and below what actual random tokens
#: produce.
ENTROPY_THRESHOLD = 4.4

#: Shapes that can carry high entropy while being public by design. Cloud
#: identifiers, URLs and paths are the usual suspects; interpolations never
#: reach this code because they aren't literals.
BENIGN_PREFIXES = (
    "arn:",
    "ami-",
    "subnet-",
    "sg-",
    "vpc-",
    "vol-",
    "snap-",
    "eni-",
    "eip-",
    "i-",
    "rtb-",
    "igw-",
    "nat-",
    "acl-",
    "dopt-",
    "pcx-",
    "tgw-",
    "fs-",
    "http://",
    "https://",
    "s3://",
    "ssh-rsa ",
    "ssh-ed25519 ",
    "/",
    "./",
    "../",
    # Azure resource IDs and the GUID-heavy strings around them.
    "/subscriptions/",
    "urn:",
)

_WHITESPACE = (" ", "\t", "\n")


def shannon_entropy(s: str) -> float:
    """L'entropie par caractère de `s`, en bits.

    Mesurée sur les **octets UTF-8**, et non sur les caractères Python, parce que
    l'original Go indexe `s[i]` sur une chaîne — ce qui en Go est un octet — et
    compte dans une table de 256 cases. Pour l'ASCII les deux coïncident
    exactement ; pour tout le reste non, et la différence tombe sur un seuil qui
    décide si une valeur est rapportée comme un secret fuité. Compter des
    caractères ici ferait diverger les deux scanners précisément sur les entrées
    les moins susceptibles de figurer dans une suite de tests.
    """
    if not s:
        return 0.0
    data = s.encode("utf-8")
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = float(len(data))
    h = 0.0
    for n in freq:
        if n == 0:
            continue
        p = n / total
        h -= p * math.log2(p)
    return h


def looks_like_secret(value: str) -> tuple[float, bool]:
    """Dit si une valeur littérale de chaîne a la signature statistique d'un
    secret généré par machine, avec l'entropie mesurée pour le message de la
    découverte.

    Exportée aux côtés de `is_credential_attr_name`,
    `match_credential_value_pattern` et `is_open_cidr` pour que les scanners
    hors ressources (`tfpdf.tfvars`, `tfpdf.terragrunt`) jugent une valeur au
    même standard exact qu'un attribut de ressource. Un secret n'est pas moins
    commité parce qu'il siège dans un fichier .tfvars, et deux définitions
    divergentes de « ressemble à un secret » seraient un bug en germe.
    """
    if byte_len(value) < ENTROPY_MIN_LENGTH:
        return 0.0, False
    # Anything with spaces is prose, a command line, or a key file's
    # human-readable armor — all of which other checks handle better.
    if any(c in value for c in _WHITESPACE):
        return 0.0, False
    lower = value.lower()
    if lower.startswith(BENIGN_PREFIXES):
        return 0.0, False

    h = shannon_entropy(value)
    if h < ENTROPY_THRESHOLD:
        return 0.0, False
    return h, True


def byte_len(s: str) -> int:
    """La longueur en octets UTF-8, c'est-à-dire ce que rend le `len(string)`
    de Go.

    Sert aux seuils de longueur minimale et à la clause « over %d chars » des
    découvertes d'entropie, pour que les deux scanners citent le même nombre au
    lecteur.
    """
    return len(s.encode("utf-8"))
