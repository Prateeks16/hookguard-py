// The Go leg of the three-way differential harness.
//
// This file and tests/gateway/test_differential.py read the SAME committed
// vector file and assert against the SAME expected column. Neither suite talks
// to the other; agreement between the two implementations is transitive
// through the file rather than coordinated at runtime.
//
// Two things are being checked here:
//
//  1. This (the original Go implementation) returns the expected verdict for
//     every vector. Since the Python suite asserts the same thing against the
//     same column, the two implementations are pinned to each other.
//
//  2. Where an official library exists, its verdict matches ours. stripe-go
//     verifies Stripe; go-github verifies GitHub. This is the leg Python
//     cannot supply on its own -- PyGithub has no signature-verification
//     helper -- and it is most of the reason this module is kept.
//
// Shopify has no official library in either language (the Python SDK's
// validate_hmac is for OAuth query parameters, a different algorithm), so its
// vectors carry oracle "none" and are covered by the cross-language leg alone.
// That is the same honest caveat the original Go report carried.
package verifier

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	gh "github.com/google/go-github/v66/github"
	"github.com/stripe/stripe-go/v82/webhook"
)

const vectorPath = "../../tests/vectors/signatures.json"

type vector struct {
	Name          string            `json:"name"`
	Provider      string            `json:"provider"`
	Secret        string            `json:"secret"`
	Window        string            `json:"replay_window"`
	BodyB64       string            `json:"body_b64"`
	Headers       map[string]string `json:"headers"`
	NowUnix       int64             `json:"now_unix"`
	Expected      bool              `json:"expected"`
	TimeSensitive bool              `json:"time_sensitive"`
	Oracle        string            `json:"oracle"`
}

type vectorFile struct {
	ReferenceTime string   `json:"reference_time"`
	Vectors       []vector `json:"vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f vectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("vector file is empty; the harness would pass vacuously")
	}
	return f
}

func (v vector) body(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(v.BodyB64)
	if err != nil {
		t.Fatalf("%s: bad body_b64: %v", v.Name, err)
	}
	return b
}

func (v vector) header() http.Header {
	h := http.Header{}
	for k, val := range v.Headers {
		h.Set(k, val)
	}
	return h
}

// ours runs the vector through this implementation.
func (v vector) ours(t *testing.T) bool {
	t.Helper()
	route := Route{
		Path:         "/hook/" + v.Provider,
		Provider:     v.Provider,
		Upstream:     "http://upstream",
		ReplayWindow: v.Window,
	}
	if v.Provider == "paypal" {
		route.WebhookID = "unused"
	} else {
		route.SecretEnv = "UNUSED"
	}
	ver, err := buildVerifier(route, v.Secret, verifierDeps{Client: http.DefaultClient})
	if err != nil {
		t.Fatalf("%s: build verifier: %v", v.Name, err)
	}
	return ver.Verify(v.body(t), v.header(), time.Unix(v.NowUnix, 0)) == nil
}

// TestDifferentialVerdicts is the cross-language leg: this implementation must
// return the expected verdict for every vector. The Python suite asserts the
// same against the same file.
func TestDifferentialVerdicts(t *testing.T) {
	f := loadVectors(t)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if got := v.ours(t); got != v.Expected {
				t.Errorf("verdict=%v want=%v", got, v.Expected)
			}
		})
	}
}

// TestDifferentialAgainstOfficialLibraries is the vendor-oracle leg: where an
// official library verifies this provider's shape, its verdict must match
// ours.
func TestDifferentialAgainstOfficialLibraries(t *testing.T) {
	f := loadVectors(t)
	checked := 0

	for _, v := range f.Vectors {
		if v.Oracle == "none" {
			continue
		}
		// The official libraries read the system clock and cannot be handed
		// our fixed reference time, so replay-window cases are out of scope
		// for this leg. The cross-language leg above still covers them.
		if v.TimeSensitive {
			continue
		}

		t.Run(v.Name, func(t *testing.T) {
			body := v.body(t)
			var oracle bool

			switch v.Oracle {
			case "stripe":
				// ValidatePayloadIgnoringTolerance, not ConstructEvent.
				// ConstructEvent also deserializes the body into an Event, so
				// it rejects an empty or non-UTF-8 payload for a reason that
				// has nothing to do with signatures -- the harness caught
				// exactly that disagreement on a correctly signed empty body.
				// The original Go harness worked around it by restricting
				// payloads to valid JSON; the signature-only API lets us keep
				// the adversarial bodies instead, and asks the same question
				// as the Python oracle's verify_header(tolerance=None).
				oracle = webhook.ValidatePayloadIgnoringTolerance(
					body, v.Headers["Stripe-Signature"], v.Secret) == nil
			case "go-github":
				oracle = gh.ValidateSignature(v.Headers["X-Hub-Signature-256"], body, []byte(v.Secret)) == nil
			default:
				// Deliberately fatal rather than skipped: a vector added on
				// the Python side with an oracle this file does not know about
				// must break the build, not quietly lose Go coverage.
				t.Fatalf("unrecognized oracle %q -- update this file", v.Oracle)
			}

			ours := v.ours(t)
			if ours != oracle {
				t.Errorf("ours=%v oracle(%s)=%v -- the verdicts must agree", ours, v.Oracle, oracle)
			}
			if ours != v.Expected {
				t.Errorf("verdict=%v want=%v", ours, v.Expected)
			}
		})
		checked++
	}

	if checked == 0 {
		t.Fatal("no vector reached an official library; the oracle leg is not running")
	}
	t.Logf("%d vectors checked against an official library", checked)
}

// TestEveryProviderIsRecognized fails on a vector this file cannot run, rather
// than skipping it. Without this, a provider added on the Python side would
// silently have no Go coverage -- the exact way a retained oracle rots.
func TestEveryProviderIsRecognized(t *testing.T) {
	f := loadVectors(t)
	for _, v := range f.Vectors {
		if _, ok := registry[v.Provider]; !ok {
			t.Errorf("%s: provider %q is not registered in this implementation", v.Name, v.Provider)
		}
		switch v.Oracle {
		case "stripe", "go-github", "none":
		default:
			t.Errorf("%s: unrecognized oracle %q", v.Name, v.Oracle)
		}
	}
}

// TestVectorFileIsBalanced guards against a harness that only ever sees inputs
// it accepts. A file of nothing but valid signatures would pass against a
// verifier that returned nil unconditionally.
func TestVectorFileIsBalanced(t *testing.T) {
	f := loadVectors(t)
	var accept, reject int
	for _, v := range f.Vectors {
		if v.Expected {
			accept++
		} else {
			reject++
		}
	}
	if accept < 5 || reject < 5 {
		t.Fatalf("need both verdicts well represented: accept=%d reject=%d", accept, reject)
	}
	t.Logf("%d vectors: %d accepted, %d rejected", len(f.Vectors), accept, reject)
}
