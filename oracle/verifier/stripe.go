package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func init() {
	registerProvider("stripe", func(r Route, secret string, _ verifierDeps) (Verifier, error) {
		if secret == "" {
			return nil, errors.New("empty secret")
		}
		window, err := parseWindow(r.ReplayWindow)
		if err != nil {
			return nil, fmt.Errorf("replay_window: %w", err)
		}
		return StripeVerifier{Secret: []byte(secret), ReplayWindow: window}, nil
	})
}

// StripeVerifier implements the Stripe signature shape: a Stripe-Signature
// header of the form "t=<unix>,v1=<hex>[,v1=<hex>...]", where the HMAC-SHA256 is
// computed over "<t>.<rawBody>". A timestamp outside ReplayWindow is rejected
// even when the HMAC matches.
type StripeVerifier struct {
	Secret       []byte
	ReplayWindow time.Duration
}

func (v StripeVerifier) Verify(rawBody []byte, h http.Header, now time.Time) error {
	header := h.Get("Stripe-Signature")
	if header == "" {
		return errors.New("missing Stripe-Signature header")
	}
	ts, sigs := parseStripeSig(header)
	if ts == "" || len(sigs) == 0 {
		return errors.New("malformed Stripe-Signature header")
	}

	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	if v.ReplayWindow > 0 {
		delta := now.Sub(time.Unix(tsInt, 0))
		if delta < 0 {
			delta = -delta
		}
		if delta > v.ReplayWindow {
			return errors.New("timestamp outside replay window")
		}
	}

	mac := hmac.New(sha256.New, v.Secret)
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	expected := mac.Sum(nil)

	for _, s := range sigs {
		got, err := hex.DecodeString(s)
		if err != nil {
			continue
		}
		if hmac.Equal(got, expected) {
			return nil
		}
	}
	return errors.New("no matching signature")
}

func parseStripeSig(header string) (ts string, sigs []string) {
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1":
			sigs = append(sigs, kv[1])
		}
	}
	return ts, sigs
}
