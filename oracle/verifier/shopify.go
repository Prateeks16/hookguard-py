package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

func init() {
	registerProvider("shopify", func(_ Route, secret string, _ verifierDeps) (Verifier, error) {
		if secret == "" {
			return nil, errors.New("empty secret")
		}
		return ShopifyVerifier{Secret: []byte(secret)}, nil
	})
}

// ShopifyVerifier implements the Shopify signature shape: an X-Shopify-Hmac-SHA256
// header whose value is the HMAC-SHA256 of the raw body, encoded as standard
// base64 (not hex — the one twist versus Stripe/GitHub). No timestamp, so no
// replay window.
type ShopifyVerifier struct {
	Secret []byte
}

func (v ShopifyVerifier) Verify(rawBody []byte, h http.Header, _ time.Time) error {
	header := h.Get("X-Shopify-Hmac-SHA256")
	if header == "" {
		return errors.New("missing X-Shopify-Hmac-SHA256 header")
	}
	got, err := base64.StdEncoding.DecodeString(header)
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
