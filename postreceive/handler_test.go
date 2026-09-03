package postreceive

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"net/http"
	"testing"
)

const testSecret = "s3cret"

var testPayload = []byte(`{"ref":"refs/heads/master"}`)

func sign(secret string, payload []byte, sha256Alg bool) string {
	if sha256Alg {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		return fmt.Sprintf("sha256=%x", mac.Sum(nil))
	}
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(payload)
	return fmt.Sprintf("sha1=%x", mac.Sum(nil))
}

func requestWith(headers map[string]string) *http.Request {
	req, _ := http.NewRequest("POST", "/postreceive", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestValidateSignatureRejectsEmptySecret(t *testing.T) {
	req := requestWith(map[string]string{
		X_HUB_SIGNATURE:     sign("", testPayload, false),
		X_HUB_SIGNATURE_256: sign("", testPayload, true),
	})
	if validateSignature(testPayload, "", req) {
		t.Fatal("expected empty secret to fail closed")
	}
	if validateSignature(testPayload, "", requestWith(nil)) {
		t.Fatal("expected empty secret with no signature to fail closed")
	}
}

func TestValidateSignatureRejectsMissingSignature(t *testing.T) {
	if validateSignature(testPayload, testSecret, requestWith(nil)) {
		t.Fatal("expected missing signature to be rejected")
	}
}

func TestValidateSignatureAcceptsSha256(t *testing.T) {
	req := requestWith(map[string]string{X_HUB_SIGNATURE_256: sign(testSecret, testPayload, true)})
	if !validateSignature(testPayload, testSecret, req) {
		t.Fatal("expected valid sha256 signature to be accepted")
	}
}

func TestValidateSignatureAcceptsSha1(t *testing.T) {
	req := requestWith(map[string]string{X_HUB_SIGNATURE: sign(testSecret, testPayload, false)})
	if !validateSignature(testPayload, testSecret, req) {
		t.Fatal("expected valid sha1 signature to be accepted")
	}
}

func TestValidateSignatureRejectsWrongSecretOrTamperedPayload(t *testing.T) {
	req := requestWith(map[string]string{X_HUB_SIGNATURE_256: sign("other", testPayload, true)})
	if validateSignature(testPayload, testSecret, req) {
		t.Fatal("expected signature from wrong secret to be rejected")
	}
	req = requestWith(map[string]string{X_HUB_SIGNATURE_256: sign(testSecret, testPayload, true)})
	if validateSignature([]byte(`{}`), testSecret, req) {
		t.Fatal("expected tampered payload to be rejected")
	}
}

func TestValidateSignaturePrefersSha256OverSha1(t *testing.T) {
	req := requestWith(map[string]string{
		X_HUB_SIGNATURE:     sign(testSecret, testPayload, false),
		X_HUB_SIGNATURE_256: "sha256=deadbeef",
	})
	if validateSignature(testPayload, testSecret, req) {
		t.Fatal("expected invalid sha256 header to be rejected even with valid sha1 header")
	}
}

func TestValidateSignatureRejectsMalformedHeader(t *testing.T) {
	for _, sig := range []string{"sha1=", "sha256=zz", "md5=abc", "deadbeef"} {
		req := requestWith(map[string]string{X_HUB_SIGNATURE_256: sig, X_HUB_SIGNATURE: sig})
		if validateSignature(testPayload, testSecret, req) {
			t.Fatalf("expected malformed signature %q to be rejected", sig)
		}
	}
}
