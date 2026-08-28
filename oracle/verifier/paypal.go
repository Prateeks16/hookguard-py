package verifier

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	paypalAuthAlgo     = "SHA256withRSA"
	paypalCertTTL      = time.Hour
	paypalCertMaxBytes = 1 << 20 // PayPal's certs are a few KB; cap well above that
)

// paypalCertHostAllowlist pins which hosts we will ever fetch a certificate
// from. paypal-cert-url is attacker-controlled input; without this pin an
// attacker supplies their own cert URL and forges any signature this verifier
// would otherwise accept.
var paypalCertHostAllowlist = []string{"paypal.com"}

func init() {
	registerProvider("paypal", func(r Route, _ string, deps verifierDeps) (Verifier, error) {
		if r.WebhookID == "" {
			return nil, errors.New("missing webhook_id")
		}
		return NewPayPalVerifier(r.WebhookID, deps.Client), nil
	})
}

// PayPalVerifier implements PayPal's webhook signature shape: asymmetric
// RSA-SHA256 over "transmissionId|transmissionTime|webhookId|crc32(body)",
// verified against a certificate PayPal serves at paypal-cert-url. WebhookID
// identifies the configured webhook subscription — it is config, not a
// secret. The certificate is fetched once per cert URL and cached.
type PayPalVerifier struct {
	WebhookID string
	Client    *http.Client
	certs     *paypalCertCache
}

func NewPayPalVerifier(webhookID string, client *http.Client) *PayPalVerifier {
	return &PayPalVerifier{WebhookID: webhookID, Client: client, certs: newPaypalCertCache()}
}

func (v *PayPalVerifier) Verify(rawBody []byte, h http.Header, _ time.Time) error {
	transmissionID := h.Get("paypal-transmission-id")
	transmissionTime := h.Get("paypal-transmission-time")
	sigB64 := h.Get("paypal-transmission-sig")
	certURL := h.Get("paypal-cert-url")
	authAlgo := h.Get("paypal-auth-algo")

	if transmissionID == "" || transmissionTime == "" || sigB64 == "" || certURL == "" {
		return errors.New("missing PayPal signature headers")
	}
	if !strings.EqualFold(authAlgo, paypalAuthAlgo) {
		return fmt.Errorf("unsupported paypal-auth-algo %q", authAlgo)
	}

	cert, err := v.cert(certURL)
	if err != nil {
		return fmt.Errorf("paypal cert: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("paypal cert: not an RSA key")
	}

	return verifyPaypalSignature(pub, transmissionID, transmissionTime, v.WebhookID, rawBody, sigB64)
}

// paypalSigMessage builds PayPal's signed message: transmissionId, time, the
// configured webhook ID, and an unsigned-decimal CRC32 of the raw body,
// joined by "|".
func paypalSigMessage(transmissionID, transmissionTime, webhookID string, body []byte) string {
	crc := crc32.ChecksumIEEE(body)
	return fmt.Sprintf("%s|%s|%s|%d", transmissionID, transmissionTime, webhookID, crc)
}

// verifyPaypalSignature checks the RSA-SHA256 signature over the PayPal
// message against pub. Split out from Verify so it can be unit-tested with a
// locally generated keypair, with no cert fetch or network access involved.
func verifyPaypalSignature(pub *rsa.PublicKey, transmissionID, transmissionTime, webhookID string, body []byte, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return errors.New("invalid paypal-transmission-sig encoding")
	}
	digest := sha256.Sum256([]byte(paypalSigMessage(transmissionID, transmissionTime, webhookID, body)))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return errors.New("signature mismatch")
	}
	return nil
}

// cert returns the parsed, chain-validated certificate for certURL, fetching
// and caching it on first use (or after paypalCertTTL has elapsed).
func (v *PayPalVerifier) cert(certURL string) (*x509.Certificate, error) {
	if cert, ok := v.certs.get(certURL); ok {
		return cert, nil
	}
	if err := checkPaypalCertHost(certURL); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, certURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cert fetch: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, paypalCertMaxBytes))
	if err != nil {
		return nil, err
	}

	cert, err := parsePaypalCertChain(body)
	if err != nil {
		return nil, err
	}
	v.certs.set(certURL, cert)
	return cert, nil
}

// checkPaypalCertHost pins paypal-cert-url to a PayPal-owned host, and
// requires https, before any network fetch happens.
func checkPaypalCertHost(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid paypal-cert-url: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("paypal-cert-url must be https")
	}
	host := strings.ToLower(u.Hostname())
	for _, domain := range paypalCertHostAllowlist {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return nil
		}
	}
	return fmt.Errorf("paypal-cert-url host %q is not a trusted PayPal host", host)
}

// parsePaypalCertChain parses one or more PEM-encoded certificates (PayPal
// serves the leaf certificate, optionally followed by intermediates) and
// verifies the leaf chains to a trusted root before returning it.
func parsePaypalCertChain(pemData []byte) (*x509.Certificate, error) {
	var leaf *x509.Certificate
	intermediates := x509.NewCertPool()

	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		if leaf == nil {
			leaf = c
		} else {
			intermediates.AddCert(c)
		}
	}
	if leaf == nil {
		return nil, errors.New("no certificate found in response")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: intermediates}); err != nil {
		return nil, fmt.Errorf("certificate chain: %w", err)
	}
	return leaf, nil
}

// paypalCertCache is a thread-safe, TTL'd cache of fetched PayPal
// certificates, keyed by cert URL, so concurrent webhooks don't each refetch.
type paypalCertCache struct {
	mu    sync.RWMutex
	certs map[string]paypalCachedCert
}

type paypalCachedCert struct {
	cert      *x509.Certificate
	fetchedAt time.Time
}

func newPaypalCertCache() *paypalCertCache {
	return &paypalCertCache{certs: make(map[string]paypalCachedCert)}
}

func (c *paypalCertCache) get(certURL string) (*x509.Certificate, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.certs[certURL]
	if !ok || time.Since(entry.fetchedAt) > paypalCertTTL {
		return nil, false
	}
	return entry.cert, true
}

func (c *paypalCertCache) set(certURL string, cert *x509.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs[certURL] = paypalCachedCert{cert: cert, fetchedAt: time.Now()}
}
