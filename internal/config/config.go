package config

import (
	"log"
	"math/big"
	"strconv"

	"github.com/caarlos0/env/v11"
	"github.com/ethereum/go-ethereum/common/math"
)

type config struct {
	EthereumPrivateKey string `env:"ETHEREUM_PRIVATE_KEY"`
	Env                string `env:"ENV" envDefault:"testnet"` // nightly, testnet, mainnet
	ChainID            string `env:"PARADEX_CHAIN_ID" envDefault:"11155111"`
	ParadexVersion     string `env:"PARADEX_VERSION" envDefault:"1"`
}

var App config

func LoadEnv() {
	err := env.Parse(&App)
	if err != nil {
		log.Fatalf("Failed to parse environment variables: %v", err)
	}
}

func (cfg config) GetChainID() int64 {
	chainID, _ := strconv.ParseInt(cfg.ChainID, 10, 64)
	return chainID
}

func (cfg config) GetChainIDBigInt() *math.HexOrDecimal256 {
	chainID := big.NewInt(cfg.GetChainID())
	return (*math.HexOrDecimal256)(chainID)
}

func (cfg config) GetChainIDName() string {
	switch cfg.Env {
	case "nightly":
		return "PRIVATE_SN_POTC_MOCK_SEPOLIA"
	case "testnet":
		return "PRIVATE_SN_POTC_SEPOLIA"
	case "mainnet":
		return "PRIVATE_SN_PARACLEAR_MAINNET"
	default:
		return ""
	}
}
