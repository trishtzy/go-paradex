// Package goparadex provides a Go client for the Paradex API.
package goparadex

import (
	"fmt"

	"github.com/caarlos0/env/v11"
)

// Config is the configuration for the Paradex API.
type Config struct {
	EthereumPrivateKey string `env:"ETHEREUM_PRIVATE_KEY"`
	Env                string `env:"ENV" envDefault:"testnet"` // nightly, testnet, mainnet
	ParadexVersion     string `env:"PARADEX_VERSION" envDefault:"1"`
}

// NewConfig creates a new Config.
func NewConfig() (*Config, error) {
	config := &Config{}
	err := env.Parse(config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse environment variables: %v", err)
	}

	return config, nil
}
