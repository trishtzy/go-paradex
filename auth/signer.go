package auth

import (
	"github.com/dontpanicdao/caigo"
	"github.com/dontpanicdao/caigo/types"
	"github.com/trishtzy/go-paradex/internal/config"
)

// DEFAULT_EXPIRY_IN_SECONDS is the default expiry time for a signature in seconds.
const DEFAULT_EXPIRY_IN_SECONDS = int64(30)

// SignerParams represents the parameters for signing a message.
type SignerParams struct {
	MessageType       string
	DexAccountAddress string
	DexPrivateKey     string
	Params            map[string]interface{}
}

// SignSNTypedData signs a typed data message using the StarkNet curve.
// It returns the signature as a string in "[r, s]" format.
func SignSNTypedData(signerParams SignerParams) string {
	dexAccountAddressBN := types.HexToBN(signerParams.DexAccountAddress)

	sc := caigo.StarkCurve{}
	message := typedMessage(signerParams)
	typedData := verificationTypedData(signerParams.MessageType)
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

func verificationTypedData(messageType string) *caigo.TypedData {
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

	typedData, _ = NewVerificationTypedData(verificationType, config.App.GetChainIDName())
	return typedData
}
