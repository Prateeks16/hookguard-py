package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
)

func init() {
	registerProvider("github", func(_ Route, secret string, _ verifierDeps) (Verifier, error) {
		if secret == "" {
			return nil, errors.New("empty secret")
		}
		return GitHubVerifier{Secret: []byte(secret)}, nil
	})
}

// GitHubVerifier implements the GitHub signature shape: an X-Hub-Signature-256
// header of the form "sha256=<hex>", where the HMAC-SHA256 is computed over the
// raw body bytes. GitHub carries no timestamp, so there is no replay window.
type GitHubVerifier struct {
	Secret []byte
}

func (v GitHubVerifier) Verify(rawBody []byte, h http.Header, _ time.Time) error {
	header := h.Get("X-Hub-Signature-256")
	if header == "" {
		return errors.New("missing X-Hub-Signature-256 header")
	}
	hexSig, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return errors.New("malformed X-Hub-Signature-256 header")
	}
	got, err := hex.DecodeString(hexSig)
	if err != nil {
		return errors.New("invalid signature encoding")
	}

	mac := hmac.New(sha256.New, v.Secret)
	mac.Write(rawBody)
	expected := mac.Sum(nil)

	if !hmac.Equal(got, expected) {
		return errors.New("signature mismatch")
	}
	return nil
}
