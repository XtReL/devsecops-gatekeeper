package config

import (
	"fmt"
	"os"
	"strings"
)

// Config centralizes environment-driven settings for the API and scanner services.
type Config struct {
	Port                 string
	WebhookSecret        string
	NATSURL              string
	DatabaseURL          string
	SpiceDBEndpoint      string
	SpiceDBToken         string
	GitHubAppID          string
	GitHubPrivateKeyPath string
	GitHubOwner          string
}

func Load() Config {
	return Config{
		Port:                 getenv("PORT", "8080"),
		WebhookSecret:        os.Getenv("WEBHOOK_SECRET"),
		NATSURL:              getenv("NATS_URL", "nats://nats:4222"),
		DatabaseURL:          getenv("DATABASE_URL", "postgres://postgres:supersecretpassword@postgres:5432/gatekeeper?sslmode=disable"),
		SpiceDBEndpoint:      getenv("SPICEDB_ENDPOINT", "spicedb:50051"),
		SpiceDBToken:         os.Getenv("SPICEDB_TOKEN"),
		GitHubAppID:          getenv("GITHUB_APP_ID", "4051135"),
		GitHubPrivateKeyPath: getenv("GITHUB_PRIVATE_KEY_PATH", "./key.pem"),
		GitHubOwner:          getenv("GITHUB_OWNER", "XtReL"),
	}
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.WebhookSecret) == "" {
		return fmt.Errorf("WEBHOOK_SECRET must be configured")
	}
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("DATABASE_URL must be configured")
	}
	if strings.TrimSpace(c.NATSURL) == "" {
		return fmt.Errorf("NATS_URL must be configured")
	}
	if strings.TrimSpace(c.SpiceDBEndpoint) == "" {
		return fmt.Errorf("SPICEDB_ENDPOINT must be configured")
	}
	if strings.TrimSpace(c.SpiceDBToken) == "" {
		return fmt.Errorf("SPICEDB_TOKEN must be configured")
	}
	if strings.TrimSpace(c.GitHubPrivateKeyPath) == "" {
		return fmt.Errorf("GITHUB_PRIVATE_KEY_PATH must be configured")
	}
	return nil
}

func getenv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
