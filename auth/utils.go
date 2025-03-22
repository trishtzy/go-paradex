package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	starkcurve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	"github.com/consensys/gnark-crypto/ecc/stark-curve/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/stark-curve/fr"
	"github.com/dontpanicdao/caigo"
	"github.com/dontpanicdao/caigo/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/trishtzy/go-paradex/internal/config"
	"github.com/trishtzy/go-paradex/models"
)

func Print(str ...any) {
	s := fmt.Sprintln(str...)
	io.WriteString(os.Stdout, s)
}

func GetSignatureStr(r, s *big.Int) string {
	signature := []string{r.String(), s.String()}
	signatureByte, _ := json.Marshal(signature)
	return string(signatureByte)
}

func ComputeAddress(config models.ResponsesSystemConfigResponse, publicKey string) string {
	publicKeyBN := types.HexToBN(publicKey)

	paraclearAccountHashBN := types.HexToBN(config.ParaclearAccountHash)
	paraclearAccountProxyHashBN := types.HexToBN(config.ParaclearAccountProxyHash)

	zero := big.NewInt(0)
	initializeBN := types.GetSelectorFromName("initialize")

	contractAddressPrefix := types.StrToFelt("STARKNET_CONTRACT_ADDRESS").Big()

	constructorCalldata := []*big.Int{
		paraclearAccountHashBN,
		initializeBN,
		big.NewInt(2),
		publicKeyBN,
		zero,
	}
	constructorCalldataHash, _ := caigo.Curve.ComputeHashOnElements(constructorCalldata)

	address := []*big.Int{
		contractAddressPrefix,
		zero,        // deployer address
		publicKeyBN, // salt
		paraclearAccountProxyHashBN,
		constructorCalldataHash,
	}
	addressHash, _ := caigo.Curve.ComputeHashOnElements(address)
	return types.BigToHex(addressHash)
}

func GrindKey(keySeed string, keyValLimit *big.Int) string {
	sha256EcMaxDigest := new(big.Int)
	sha256EcMaxDigest.SetString("1 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000", 16)
	maxAllowedVal := new(big.Int).Sub(sha256EcMaxDigest, new(big.Int).Mod(sha256EcMaxDigest, keyValLimit))

	i := 0
	key := hashKeyWithIndex(keySeed, i)
	i++

	// Make sure the produced key is divided by the Stark EC order, and falls within the range
	// [0, maxAllowedVal).
	for key.Cmp(maxAllowedVal) < 0 {
		key = hashKeyWithIndex(keySeed, i)
		i++
	}

	// Should this be unsignedMod?
	result := new(big.Int).Mod(key, keyValLimit)
	return fmt.Sprintf("0x%x", result)
}

func hashKeyWithIndex(keySeed string, index int) *big.Int {
	// Remove '0x' prefix if present
	key := strings.TrimPrefix(keySeed, "0x")

	// Convert index to hex and pad to 2 bytes
	indexHex := fmt.Sprintf("%02x", index)

	// Combine key and index
	data := key + indexHex

	// Decode hex string to bytes
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256(dataBytes)

	// Convert hash to big.Int
	return new(big.Int).SetBytes(hash[:])
}

// Generate Ethereum public key from Ethereum private key
func GetEthereumAccount() (string, string) {
	if config.App.EthereumPrivateKey == "" {
		panic("ETHEREUM_PRIVATE_KEY is not set")
	}
	ethPrivateKey := strings.TrimPrefix(config.App.EthereumPrivateKey, "0x")
	privateKeyBytes, _ := crypto.HexToECDSA(ethPrivateKey)
	publicKeyECDSA := &privateKeyBytes.PublicKey
	ethAddress := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	return config.App.EthereumPrivateKey, ethAddress
}

// Generate Paradex private key from Ethereum private key
func GenerateParadexAccount(sysConfig models.ResponsesSystemConfigResponse, ethPrivateKey string) (string, string, string) {
	ethPrivateKey = strings.TrimPrefix(ethPrivateKey, "0x")
	privateKey, _ := crypto.HexToECDSA(ethPrivateKey)
	ethSignature, _ := SignTypedData(typedData, privateKey)
	// Convert the first 32 bytes of ethSignature to a hex string
	r := hex.EncodeToString(ethSignature[:32])
	// Get Starknet curve order
	n := ecc.STARK_CURVE.ScalarField()
	dexPrivateKey := GrindKey(r, n)
	dexPrivateKeyBN := types.HexToBN(dexPrivateKey)
	dexPublicKeyBN, _, _ := caigo.Curve.PrivateToPoint(dexPrivateKeyBN)
	dexPublicKey := types.BigToHex(dexPublicKeyBN)
	dexAccountAddress := ComputeAddress(sysConfig, dexPublicKey)
	return dexPrivateKey, dexPublicKey, dexAccountAddress
}

// Get ECDSA private key from string
func GetEcdsaPrivateKey(pk string) *ecdsa.PrivateKey {
	privateKey := types.StrToFelt(pk).Big()

	// Generate public key
	_, g := starkcurve.Generators()
	ecdsaPublicKey := new(ecdsa.PublicKey)
	ecdsaPublicKey.A.ScalarMultiplication(&g, privateKey)

	// Generate private key
	pkBytes := privateKey.FillBytes(make([]byte, fr.Bytes))
	buf := append(ecdsaPublicKey.Bytes(), pkBytes...)
	ecdsaPrivateKey := new(ecdsa.PrivateKey)
	ecdsaPrivateKey.SetBytes(buf)
	return ecdsaPrivateKey
}

func GnarkSign(messageHash *big.Int, privateKey string) (r, s *big.Int, err error) {
	ecdsaPrivateKey := GetEcdsaPrivateKey(privateKey)
	sigBin, err := ecdsaPrivateKey.Sign(messageHash.Bytes(), nil)
	if err != nil {
		return nil, nil, err
	}
	r = new(big.Int).SetBytes(sigBin[:fr.Bytes])
	s = new(big.Int).SetBytes(sigBin[fr.Bytes:])
	return r, s, nil
}

func GetChainID(env string) string {
	if env == "testnet" {
		return "11155111"
	}
	return "1"
}

func GetChainIDName(env string) string {
	switch env {
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
