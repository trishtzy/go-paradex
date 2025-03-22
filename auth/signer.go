package auth

import (
	"github.com/dontpanicdao/caigo"
	"github.com/dontpanicdao/caigo/types"
	"github.com/trishtzy/go-paradex/models"
)

// DEFAULT_EXPIRY_IN_SECONDS is the default expiry time for a signature in seconds.
const DEFAULT_EXPIRY_IN_SECONDS = int64(30)

// SignerParams represents the parameters for signing a message.
type SignerParams struct {
	// MessageType is the type of message to sign.
	MessageType string
	// DexAccountAddress is the address of the Paradex account.
	DexAccountAddress string
	// DexPrivateKey is the private key of the Paradex account.
	DexPrivateKey string
	// SysConfig is the system configuration. This is a required field.
	SysConfig models.ResponsesSystemConfigResponse
	// Params is the parameters for the message.
	Params map[string]interface{}
}

// SignSNTypedData signs a typed data message using the StarkNet curve.
// It returns the signature as a string in "[r, s]" format.
func SignSNTypedData(signerParams SignerParams) string {
	dexAccountAddressBN := types.HexToBN(signerParams.DexAccountAddress)

	sc := caigo.StarkCurve{}
	message := typedMessage(signerParams)
	typedData := verificationTypedData(signerParams.MessageType, signerParams.SysConfig.StarknetChainID)
	domEnc, _ := typedData.GetTypedMessageHash("StarkNetDomain", typedData.Domain, sc)
	messageHash, _ := GnarkGetMessageHash(typedData, domEnc, dexAccountAddressBN, message, sc)
	r, s, _ := GnarkSign(messageHash, signerParams.DexPrivateKey)

	return GetSignatureStr(r, s)
}

func typedMessage(signerParams SignerParams) caigo.TypedMessage {
	switch signerParams.MessageType {
	case "onboarding":
		return &OnboardingPayload{Action: "Onboarding"}
	case "auth":
		return &AuthPayload{
			Method:     "POST",
			Path:       "/v1/auth",
			Body:       "",
			Timestamp:  signerParams.Params["timestamp"].(string),
			Expiration: signerParams.Params["expiration"].(string),
		}
	case "order":
		return &OrderPayload{
			Timestamp: signerParams.Params["timestamp"].(int64),
			Market:    signerParams.Params["market"].(string),
			Side:      signerParams.Params["side"].(string),
			OrderType: signerParams.Params["orderType"].(string),
			Size:      signerParams.Params["size"].(string),
			Price:     signerParams.Params["price"].(string),
		}
	default:
		return nil
	}
}

// verificationTypedData returns the typed data for a given message type and chain ID.
// chainID refers to the chain ID of the L2 chain.
func verificationTypedData(messageType string, chainID string) *caigo.TypedData {
	var typedData *caigo.TypedData
	var verificationType VerificationType
	switch messageType {
	case "onboarding":
		verificationType = VerificationTypeOnboarding
	case "auth":
		verificationType = VerificationTypeAuth
	case "order":
		verificationType = VerificationTypeOrder
	}

	typedData, _ = NewVerificationTypedData(verificationType, chainID)
	return typedData
}
