// Package auth provides utilities for signing and verifying messages using EIP-712 and Starknet.
//
// It includes functions for generating Ethereum account addresses from private keys,
// creating Starknet private keys from Ethereum private keys, and signing and verifying
// messages using EIP-712.
package auth

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

var typesStandard = apitypes.Types{
	"EIP712Domain": {
		{
			Name: "name",
			Type: "string",
		},
		{
			Name: "version",
			Type: "string",
		},
		{
			Name: "chainId",
			Type: "uint256",
		},
	},
	"Constant": {
		{
			Name: "action",
			Type: "string",
		},
	},
}

const primaryType = "Constant"

var domainStandard = apitypes.TypedDataDomain{
	Name:    "Paradex",
	Version: "1",
	ChainId: (*math.HexOrDecimal256)(big.NewInt(1)), // unused
}

var messageStandard = map[string]interface{}{
	"action": "STARK Key",
}

var typedData = apitypes.TypedData{
	Types:       typesStandard,
	PrimaryType: primaryType,
	Domain:      domainStandard,
	Message:     messageStandard,
}

// SignTypedData signs a typed data object using the provided private key.
// chainID refers to the chain ID of the L1 chain.
// It returns the signature as a byte slice and an error if the signing fails.
func SignTypedData(typedData apitypes.TypedData, privateKey *ecdsa.PrivateKey, chainID string) ([]byte, error) {
	var signature []byte

	hash, err := EncodeForSigning(typedData, chainID)
	if err != nil {
		return signature, err
	}
	signature, err = crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return signature, err
	}
	signature[64] += 27

	return signature, nil
}

// EncodeForSigning encodes a typed data object for EIP-712 signing.
// chainID refers to the chain ID of the L1 chain.
// It returns the encoded data as a common.Hash and an error if the encoding fails.
func EncodeForSigning(typedData apitypes.TypedData, chainID string) (common.Hash, error) {
	var hash common.Hash

	domainDataPayload := typedData.Domain.Map()
	// TODO: Check if serialised value is in hex. If yes, replace it with decimal
	domainDataPayload["chainId"] = chainID // override with chainId from config

	domainSeparator, err := typedData.HashStruct("EIP712Domain", domainDataPayload)
	if err != nil {
		return hash, err
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return hash, err
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	hash = common.BytesToHash(crypto.Keccak256(rawData))
	return hash, nil
}
