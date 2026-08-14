package rules

// The predicate vocabulary a rule file may invoke.
//
// This is the boundary between data and code. A rule declares *what* it
// looks for; when deciding needs more than a pattern — measuring randomness,
// telling base64 output from a file path — it names one of these, and this
// map is the complete list of what naming can reach. There is no registration
// hook and no plugin path, so the set of things a rule can cause to happen is
// exactly what is written here and auditable in one screen.

// confirmPredicates run against the substring a rule's value_matches found,
// not the whole value: the point is to judge the candidate the regex picked
// out. This is what separates a 40-character secret from a 40-character path.
var confirmPredicates = map[string]func(match string) bool{
	// Mixed case with digits is what base64 of random bytes looks like and
	// what a lowercase file path never is; the entropy floor then rejects the
	// structured strings that happen to mix case anyway.
	"base64_secret": looksLikeBase64Secret,

	// Hex tops out at 4 bits per character, so this floor is low by design —
	// it exists to reject the degenerate runs (forty a's) that satisfy a hex
	// character class while carrying no randomness at all.
	"hex_entropy": func(m string) bool { return shannonEntropy(m) >= 3.0 },
}

// valuePredicates run against the whole value and return a measurement the
// message can quote back. A rule that accuses someone on a statistic has to
// be able to show the statistic.
var valuePredicates = map[string]func(value string) (float64, bool){
	"looks_like_secret": looksLikeSecret,
}

// looksLikeBase64Secret reports whether a 40-char base64 run is plausibly
// random output rather than a path or an identifier.
//
// Two conditions, both cheap and both necessary. The canonical AWS example
// secret (wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY) clears both comfortably;
// the build command that once got reported as a leaked key clears neither.
func looksLikeBase64Secret(match string) bool {
	var hasUpper, hasLower, hasDigit bool
	for _, r := range match {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return false
	}
	return shannonEntropy(match) >= 4.2
}

// knownPredicates lists every name a rule file may use, for the validation
// pass that runs at load. A rule naming a predicate this binary does not
// have must fail loudly: silently skipping it would disable a detector while
// the scan still reported success.
func knownPredicates() (confirm []string, value []string) {
	for name := range confirmPredicates {
		confirm = append(confirm, name)
	}
	for name := range valuePredicates {
		value = append(value, name)
	}
	return confirm, value
}
