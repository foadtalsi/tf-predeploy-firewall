package rules

import "testing"

// The 40-char base64 class matches any long run of [a-z0-9/+], which
// ordinary file paths reach easily. Running the scanner against this
// project's own Terraform reported a `local-exec` build command as a leaked
// AWS secret key, at critical severity — the exact false positive that gets
// a scanner switched off. Randomness is what separates the two.
func TestMatchCredentialValuePattern_AWSSecretKey(t *testing.T) {
	secrets := []string{
		// AWS's own canonical example secret key.
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		// A secret embedded in a larger value still counts.
		"export AWS_SECRET_ACCESS_KEY=Xy7Qm2Vt5wYq2Jn8RkLp3zXcB7dHm4gFa9eSu6Tb",
	}
	notSecrets := []string{
		// The finding that prompted this: a build command whose path run is
		// 41 characters of [a-z/].
		"GOOS=linux go build -o infra/terraform/build/dashboard-bootstrap ./cmd/dashboard-lambda && cp infra/terraform/build/dashboard/bootstrap x",
		"infra/terraform/build/dashboard/bootstrap",
		// Long lowercase paths and identifiers generally.
		"modules/networking/environments/production/eu-west-one/vpc",
		// Valid hex, 42 chars, and no entropy at all — the "high-entropy hex
		// string" pattern has to mean what its label says.
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	for _, s := range secrets {
		if label, ok := MatchCredentialValuePattern(s); !ok {
			t.Errorf("missed a secret in %.50q", s)
		} else if label == "" {
			t.Errorf("no label for %.50q", s)
		}
	}
	for _, s := range notSecrets {
		if label, ok := MatchCredentialValuePattern(s); ok {
			t.Errorf("false positive %q on %.60q — a path is not a key", label, s)
		}
	}
}

// The confirmation applies to the matched substring, not the whole value:
// a secret inside a longer string must still be found, and a long benign
// string must not be rescued by its benign parts.
func TestLooksLikeBase64Secret(t *testing.T) {
	if !looksLikeBase64Secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") {
		t.Error("the canonical AWS example secret must be confirmed")
	}
	for _, s := range []string{
		"infra/terraform/build/dashboard/bootstrap", // no uppercase, no digits
		"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN",  // no lowercase, no digits
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  // no entropy
	} {
		if looksLikeBase64Secret(s) {
			t.Errorf("%.45q must not be confirmed as a secret", s)
		}
	}
}

// Patterns without a confirm function keep matching exactly as before.
func TestMatchCredentialValuePattern_OtherFormatsUnaffected(t *testing.T) {
	for _, s := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"-----BEGIN RSA PRIVATE KEY-----",
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"5d41402abc4b2a76b9719d911017c592",
	} {
		if _, ok := MatchCredentialValuePattern(s); !ok {
			t.Errorf("%q should still be detected", s)
		}
	}
}
