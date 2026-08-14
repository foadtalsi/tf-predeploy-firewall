package rules

import "testing"

// The name matcher is suffix-based because every provider grows its own
// credential vocabulary. This test is the contract for both directions: what
// must be caught, and — just as load-bearing — what must not be, because a
// scanner that flags public_key as a leaked secret trains people to ignore
// the rule before it ever catches a real one.
func TestIsCredentialAttrName(t *testing.T) {
	shouldMatch := []string{
		// The AWS vocabulary the original exact-match list grew up on.
		"password", "secret", "api_key", "access_key", "token", "master_password",
		// The azurerm vocabulary that exposed the exact-match list as a gap:
		// administrator_login_password went unflagged while carrying "Hunter2!".
		"administrator_login_password", "admin_password", "account_password",
		"primary_connection_string", "client_secret", "sas_token", "auth_token",
	}
	shouldNotMatch := []string{
		// Key-ish names that are not secrets. "key" is deliberately not a
		// bare suffix for exactly these.
		"public_key", "kms_key_id", "partition_key", "sort_key", "ssh_key_name",
		// Near-misses.
		"password_policy", "secret_rotation_days", "tokenizer",
	}

	for _, name := range shouldMatch {
		if !IsCredentialAttrName(name) {
			t.Errorf("%q must be treated as a credential attribute", name)
		}
	}
	for _, name := range shouldNotMatch {
		if IsCredentialAttrName(name) {
			t.Errorf("%q must NOT be treated as a credential attribute", name)
		}
	}
}
