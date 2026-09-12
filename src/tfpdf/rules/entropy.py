"""Détection des chaînes à forte entropie : le repli pour les secrets qui ne correspondent à
aucun format connu."""

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


def is_public_by_shape(value: str) -> bool:
    """Dit si une valeur est publique par construction, quelle que soit son entropie."""
    return value.lower().startswith(BENIGN_PREFIXES)


def shannon_entropy(s: str) -> float:
    """L'entropie par caractère de `s`, en bits."""
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
    """Dit si une valeur littérale de chaîne a la signature statistique d'un secret généré par
    machine, avec l'entropie mesurée pour le message de la découverte."""
    if byte_len(value) < ENTROPY_MIN_LENGTH:
        return 0.0, False
    # Propre à l'entropie, et NON à `is_public_by_shape` : mesurer le hasard
    # d'un blob de prose ne veut rien dire, mais une clé AWS posée au milieu
    # d'un script `user_data` — donc au milieu d'espaces — est exactement ce
    # qu'il faut trouver. Confondre les deux a coûté deux découvertes du corpus
    # doré, dont une clé PEM.
    if any(c in value for c in _WHITESPACE):
        return 0.0, False
    if is_public_by_shape(value):
        return 0.0, False

    h = shannon_entropy(value)
    if h < ENTROPY_THRESHOLD:
        return 0.0, False
    return h, True


def byte_len(s: str) -> int:
    """La longueur en octets UTF-8, c'est-à-dire ce que rend le `len(string)` de Go."""
    return len(s.encode("utf-8"))
