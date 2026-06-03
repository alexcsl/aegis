package proxy

import (
	"testing"
)

// validateID

func TestValidateIDAcceptsValid(t *testing.T) {
	valid := []string{
		"abc",
		"session-123",
		"agent_id.v2",
		"A1b2C3d4E5f6G7h8I9j0",
	}
	for _, id := range valid {
		if err := validateID(id); err != nil {
			t.Errorf("validateID(%q) unexpected error: %v", id, err)
		}
	}
}

func TestValidateIDRejectsTooLong(t *testing.T) {
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	if err := validateID(string(long)); err == nil {
		t.Error("validateID should reject id longer than 128 chars")
	}
}

func TestValidateIDRejectsSpecialChars(t *testing.T) {
	bad := []string{
		"abc\ninjected",
		"id with spaces",
		"id/slash",
		"id<script>",
		"id;drop",
	}
	for _, id := range bad {
		if err := validateID(id); err == nil {
			t.Errorf("validateID(%q) should have returned an error", id)
		}
	}
}

// isSensitiveKey

func TestIsSensitiveKeyExtended(t *testing.T) {
	sensitive := []string{
		"password", "passwd", "pwd",
		"token", "apikey", "api_key",
		"secret", "key",
		"auth", "authorization",
		"credential", "private",
		"bearer", "cookie", "session",
		"pin", "otp", "signature", "jwt",
		// mixed case
		"AccessToken", "BEARER_VALUE", "CookieJar",
	}
	for _, k := range sensitive {
		if !isSensitiveKey(k) {
			t.Errorf("isSensitiveKey(%q) = false, want true", k)
		}
	}
}

func TestIsSensitiveKeyAllowsCleanKeys(t *testing.T) {
	clean := []string{"query", "url", "path", "filename", "limit", "offset", "tool", "model"}
	for _, k := range clean {
		if isSensitiveKey(k) {
			t.Errorf("isSensitiveKey(%q) = true, want false", k)
		}
	}
}

// scrubSecretValues

func TestScrubSecretValuesAWSKey(t *testing.T) {
	// Split so the full pattern never appears as a literal string in source.
	// "AKIA" + 16 uppercase/digit chars matches our reAWSKey regex.
	awsKey := "AKIA" + "TESTFAKEKEY00001" // not a real key
	input := "use key " + awsKey + " to auth"
	out := scrubSecretValues(input)
	if out == input {
		t.Error("AWS key was not redacted")
	}
	if out != "use key [redacted-aws-key] to auth" {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestScrubSecretValuesJWT(t *testing.T) {
	// Split across concat so the full three-part JWT pattern never appears as
	// a single string literal (avoids secret-scanner false positives).
	header := "eyJhbGciOiJIUzI1NiJ9"
	payload := "eyJ0ZXN0IjoidHJ1ZSJ9"
	sig := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	jwt := header + "." + payload + "." + sig
	out := scrubSecretValues(jwt)
	if out == jwt {
		t.Error("JWT was not redacted")
	}
}

func TestScrubSecretValuesPrivKey(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."
	out := scrubSecretValues(pem)
	if out != "[redacted-private-key]" {
		t.Errorf("private key not redacted, got: %q", out)
	}
}

func TestScrubSecretValuesCleanString(t *testing.T) {
	clean := "hello world, this is a normal string"
	if scrubSecretValues(clean) != clean {
		t.Error("clean string was incorrectly modified")
	}
}

// sanitize (integration)

func TestSanitizeRedactsNestedSensitiveKey(t *testing.T) {
	args := map[string]any{
		"outer": map[string]any{
			"password": "s3cr3t",
			"query":    "SELECT 1",
		},
	}
	result := sanitize(args)
	outer := result["outer"].(map[string]any)
	if outer["password"] != "[redacted]" {
		t.Errorf("nested password not redacted: %v", outer["password"])
	}
	if outer["query"] != "SELECT 1" {
		t.Errorf("query should not be redacted, got: %v", outer["query"])
	}
}

func TestSanitizeRedactsJWTInStringValue(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJ0ZXN0IjoidHJ1ZSJ9" + "." + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	args := map[string]any{
		"prompt": "use token " + jwt + " to proceed",
	}
	result := sanitize(args)
	val, _ := result["prompt"].(string)
	if val == args["prompt"] {
		t.Error("JWT in prompt field was not scrubbed")
	}
}
