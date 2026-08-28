package verifier

import (
	"encoding/json"
	"os"
)

// Route binds an inbound path to one Provider verifier, an Upstream URL, a
// replay window, and the env var naming that Provider's secret.
type Route struct {
	Path         string `json:"path"`
	Provider     string `json:"provider"`
	Upstream     string `json:"upstream"`
	ReplayWindow string `json:"replay_window"`        // time.ParseDuration syntax; "" means no replay check
	SecretEnv    string `json:"secret_env"`           // the NAME of the env var holding the secret, never the secret
	WebhookID    string `json:"webhook_id,omitempty"` // PayPal only: webhook subscription ID, not a secret
}

type Config struct {
	Routes []Route `json:"routes"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
