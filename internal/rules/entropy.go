package rules

import (
	"math"
	"strings"
)

// High-entropy string detection: the fallback for secrets that match no
// known format. An AWS key has a prefix, a JWT has dots, a PEM has a header
// — but a random API token from some SaaS is just 40 characters of base64
// with no shape at all, and shape-based patterns will never enumerate every
// vendor. Randomness itself is the one property they all share.
//
// Everything here is tuned against false positives rather than for recall,
// because this check runs on every string literal in every scanned file and
// its failure mode — flagging an ARN or a resource ID as a leaked secret —
// is how a rule teaches people to ignore it.

// entropyMinLength is the shortest literal worth measuring. Below this,
// even a genuinely random string's entropy estimate is too noisy to accuse
// anyone over.
const entropyMinLength = 24

// entropyThreshold is bits per character. Notable calibration points:
// English prose sits around 3, hex maxes out at 4 (16 symbols), UUIDs land
// ~3.6 because of their fixed dashes, and random base64 runs ~5.2. The
// threshold sits above every identifier format cloud providers emit and
// below what actual random tokens produce.
const entropyThreshold = 4.4

// shannonEntropy returns the per-character entropy of s in bits.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	total := float64(len(s))
	var h float64
	for _, n := range freq {
		if n == 0 {
			continue
		}
		p := float64(n) / total
		h -= p * math.Log2(p)
	}
	return h
}

// benignPrefixes are shapes that can carry high entropy while being
// public by design. Cloud identifiers, URLs and paths are the usual
// suspects; interpolations never reach this code because they aren't
// literals.
var benignPrefixes = []string{
	"arn:", "ami-", "subnet-", "sg-", "vpc-", "vol-", "snap-", "eni-", "eip-",
	"i-", "rtb-", "igw-", "nat-", "acl-", "dopt-", "pcx-", "tgw-", "fs-",
	"http://", "https://", "s3://", "ssh-rsa ", "ssh-ed25519 ",
	"/", "./", "../",
	// Azure resource IDs and the GUID-heavy strings around them.
	"/subscriptions/", "urn:",
}

// LooksLikeSecret reports whether a literal string value has the statistical
// signature of a machine-generated secret, along with the measured entropy
// for the finding message.
//
// Exported alongside IsCredentialAttrName, MatchCredentialValuePattern and
// IsOpenCIDR so the non-resource scanners (internal/tfvars,
// internal/terragrunt) judge a value by exactly the same standard as a
// resource attribute. A secret is no less committed for sitting in a
// .tfvars file, and two divergent definitions of "looks like a secret"
// would be a bug waiting to happen.
func LooksLikeSecret(value string) (float64, bool) {
	return looksLikeSecret(value)
}

func looksLikeSecret(value string) (float64, bool) {
	if len(value) < entropyMinLength {
		return 0, false
	}
	// Anything with spaces is prose, a command line, or a key file's
	// human-readable armor — all of which other checks handle better.
	if strings.ContainsAny(value, " \t\n") {
		return 0, false
	}
	lower := strings.ToLower(value)
	for _, p := range benignPrefixes {
		if strings.HasPrefix(lower, p) {
			return 0, false
		}
	}

	h := shannonEntropy(value)
	if h < entropyThreshold {
		return 0, false
	}
	return h, true
}
