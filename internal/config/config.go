// Package config loads the agent configuration from disk.
// The config is small and intentionally hand-editable in /etc/963causal/agent.yaml.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ControlPlaneURL       string `yaml:"control_plane_url"`
	LicenseKey            string `yaml:"license_key"`
	KeystorePath          string `yaml:"keystore_path"`
	EncryptedPayloadPath  string `yaml:"encrypted_payload_path"`
	InsecureSkipTLSVerify bool   `yaml:"insecure_skip_tls_verify"`
	LogLevel              string `yaml:"log_level"`
}

const DefaultPath = "/etc/963causal/agent.yaml"

func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	cfg := &Config{
		KeystorePath:         "/var/lib/963causal/host.key",
		EncryptedPayloadPath: "/usr/lib/963causal/payload.enc",
		LogLevel:             "info",
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.ControlPlaneURL == "" {
		return nil, fmt.Errorf("control_plane_url is required")
	}
	if cfg.LicenseKey == "" {
		return nil, fmt.Errorf("license_key is required")
	}
	return cfg, nil
}
