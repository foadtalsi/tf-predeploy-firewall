"""Detect high-entropy strings that do not match known credential formats."""

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


#: Words that mark a value as a stand-in for a secret rather than a secret. They are looked for in
#: the value lowercased with everything but letters and digits removed, so "REPLACE ME",
#: "change_me", "not-a-real" and "your-api-key-here" all match.
#:
#: A weak password written in full (password123, secret, default-password) is not on this
#: list: it is a real credential in source, however poor.
PLACEHOLDER_WORDS = (
    "dummy",
    "example",
    "placeholder",
    "replace",
    "changeme",
    "changeit",
    "notareal",
    "your",
    "insert",
    "redacted",
    "todo",
    "fake",
    "sample",
    "xxxx",
)

#: Characters a masked value is made of: "********", "••••••••".
_MASK_CHARACTERS = frozenset("*•")


def looks_like_placeholder(value: str) -> bool:
    """Recognize a value written to be replaced: REPLACE ME, <YOUR_API_KEY>, changeme, xxxxxxxx,
    ********, sk-placeholder-..., the AWS documentation keys (AKIAIOSFODNN7EXAMPLE)."""
    stripped = value.strip()
    if not stripped:
        return False
    # <YOUR_API_KEY>, <redacted>: a name in angle brackets is a slot to fill in.
    if stripped.startswith("<") and stripped.endswith(">"):
        return True
    if set(stripped) <= _MASK_CHARACTERS:
        return True
    letters_and_digits = "".join(character for character in stripped.lower() if character.isalnum())
    return any(word in letters_and_digits for word in PLACEHOLDER_WORDS)


def is_public_by_shape(value: str) -> bool:
    """Recognize values that are public by structure, regardless of entropy."""
    return value.lower().startswith(BENIGN_PREFIXES)


def shannon_entropy(s: str) -> float:
    """Return Shannon entropy in bits per character."""
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
    """Check whether a literal resembles a generated secret and return its measured entropy."""
    if byte_len(value) < ENTROPY_MIN_LENGTH:
        return 0.0, False
    # Whitespace excludes prose only from entropy checks. Known credentials embedded in scripts
    # must still be detected.
    if any(c in value for c in _WHITESPACE):
        return 0.0, False
    if is_public_by_shape(value):
        return 0.0, False

    h = shannon_entropy(value)
    if h < ENTROPY_THRESHOLD:
        return 0.0, False
    return h, True


def byte_len(s: str) -> int:
    """Return UTF-8 byte length, matching Go's len(string)."""
    return len(s.encode("utf-8"))
