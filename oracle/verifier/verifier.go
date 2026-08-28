package verifier

import (
	"fmt"
	"net/http"
	"time"
)

// Verifier authenticates a raw webhook body against one Provider's signature
// shape. Verify returns nil iff the signature is valid and — where the shape
// carries a timestamp — fresh within the replay window. rawBody must be the
// exact bytes received; never parse or re-serialize it before verifying.
type Verifier interface {
	Verify(rawBody []byte, h http.Header, now time.Time) error
}

// verifierDeps holds shared, non-secret dependencies a provider's factory
// branch may need beyond the route's own config. Currently just the HTTP
// client PayPal uses to fetch its public certificate; widen this struct
// rather than adding more buildVerifier scalars as providers grow.
type verifierDeps struct {
	Client *http.Client
}

// providerFactory builds a Verifier for one provider from an already-resolved
// secret and shared deps — the same contract each switch branch used to have.
type providerFactory func(r Route, secret string, deps verifierDeps) (Verifier, error)

// registry maps a provider name to its factory. Each provider file registers
// itself from init(), so adding a provider is one new file with no edit here.
var registry = map[string]providerFactory{}

// registerProvider records a provider's factory. It panics on a duplicate name
// because that can only be a programming error — two files claiming the same
// provider — and it surfaces at init time, before any traffic.
func registerProvider(name string, f providerFactory) {
	if _, dup := registry[name]; dup {
		panic("duplicate provider registration: " + name)
	}
	registry[name] = f
}

// buildVerifier constructs the Verifier for a Route from an already-resolved
// secret. It is pure — no environment access, no I/O — so it stays
// unit-testable. The caller (main) resolves the secret from the environment
// and passes it in. Dispatch is a registry lookup; each provider's factory
// validates that provider's own required config.
func buildVerifier(r Route, secret string, deps verifierDeps) (Verifier, error) {
	f, ok := registry[r.Provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", r.Provider)
	}
	return f(r, secret, deps)
}

func parseWindow(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}
