// Package gatewaysig computes and verifies the Gateway signature: the single
// internal HMAC HookGuard adds to a verified webhook before forwarding, so the
// Upstream can authenticate the gateway with one check instead of re-running
// every Provider's verification. The signature binds the verified provider name
// to the body, so the Upstream learns which Provider was verified and an attacker
// cannot relabel a payload without breaking the signature.
package gatewaysig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Header carries the hex HMAC; ProviderHeader carries the verified provider name.
const (
	Header         = "X-HookGuard-Signature"
	ProviderHeader = "X-HookGuard-Provider"
)

// Sign returns the hex HMAC-SHA256 over "<provider>.<body>" keyed by secret.
func Sign(secret []byte, provider string, body []byte) string {
	return hex.EncodeToString(mac(secret, provider, body))
}

// Verify reports whether sigHex matches Sign(secret, provider, body), comparing
// in constant time.
func Verify(secret []byte, provider string, body []byte, sigHex string) error {
	got, err := hex.DecodeString(sigHex)
	if err != nil {
		return errors.New("invalid gateway signature encoding")
	}
	if !hmac.Equal(got, mac(secret, provider, body)) {
		return errors.New("gateway signature mismatch")
	}
	return nil
}

func mac(secret []byte, provider string, body []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(provider))
	m.Write([]byte("."))
	m.Write(body)
	return m.Sum(nil)
}
