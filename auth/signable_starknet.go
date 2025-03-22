package auth

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/stark-curve/fp"
	"github.com/dontpanicdao/caigo"
	"github.com/dontpanicdao/caigo/types"
	"github.com/shopspring/decimal"

	pedersenhash "github.com/consensys/gnark-crypto/ecc/stark-curve/pedersen-hash"
)

var scaleX8Decimal = decimal.RequireFromString("100000000")
var snMessageBigInt = types.UTF8StrToBig("StarkNet Message")

// OnboardingPayload represents the payload for onboarding a new user.
// It contains a single field, "Action", which is a string representing the action to be performed.
type OnboardingPayload struct {
	Action string
}

// FmtDefinitionEncoding encodes the OnboardingPayload for StarkNet signing.
// It returns a slice of big.Int values representing the encoded payload.
func (o *OnboardingPayload) FmtDefinitionEncoding(field string) (fmtEnc []*big.Int) {
	if field == "action" {
		fmtEnc = append(fmtEnc, types.StrToFelt(o.Action).Big())
	}

	return
}

// AuthPayload represents the payload for authenticating a user.
type AuthPayload struct {
	Method     string
	Path       string
	Body       string
	Timestamp  string
	Expiration string
}

// FmtDefinitionEncoding encodes the AuthPayload for StarkNet signing.
// It returns a slice of big.Int values representing the encoded payload.
func (o *AuthPayload) FmtDefinitionEncoding(field string) (fmtEnc []*big.Int) {
	switch field {
	case "method":
		fmtEnc = append(fmtEnc, types.StrToFelt(o.Method).Big())
	case "path":
		fmtEnc = append(fmtEnc, types.StrToFelt(o.Path).Big())
	case "body":
		// this is required as types.StrToFelt("") returns nil, which seems to be an SN bug
		fmtEnc = append(fmtEnc, big.NewInt(0))
	case "timestamp":
		fmtEnc = append(fmtEnc, types.StrToFelt(o.Timestamp).Big())
	case "expiration":
		if o.Expiration != "" {
			fmtEnc = append(fmtEnc, types.StrToFelt(o.Expiration).Big())
		}
	}
	return fmtEnc
}

// OrderSide represents the side of an order in the order book.
type OrderSide string

// OrderType represents the type of an order in the order book.
type OrderType string

// OrderStatus represents the status of an order in the order book.
type OrderStatus string

// OrderFlag represents the flag of an order in the order book.
type OrderFlag string

const (
	// OrderTypeMarket represents a market order.
	OrderTypeMarket OrderType = "MARKET"
	// OrderTypeLimit represents a limit order.
	OrderTypeLimit OrderType = "LIMIT"
)

// OrderPayload represents the payload for placing an order.
type OrderPayload struct {
	Timestamp int64  // Unix timestamp in milliseconds when signature was created
	Market    string // Market name - ETH-USD-PERP
	Side      string // 1 for buy, 2 for sell
	OrderType string // MARKET or LIMIT
	Size      string // Size scaled by 1e8
	Price     string // Price scaled by 1e8 (Price is 0 for MARKET orders)
}

const (
	// ORDER_SIDE_BUY represents a buy order.
	ORDER_SIDE_BUY OrderSide = "BUY"
	// ORDER_SIDE_SELL represents a sell order.
	ORDER_SIDE_SELL OrderSide = "SELL"
)

// String returns the string representation of the OrderSide.
func (s OrderSide) String() string {
	return string(s)
}

// Get returns the integer enum representation of the OrderSide.
func (s OrderSide) Get() string {
	if s == ORDER_SIDE_BUY {
		return "1"
	} else {
		return "2"
	}
}

// GetScaledSize multiplies size by decimal precision of 8
// e.g. 0.2 is converted to 20_000_000 (0.2 * 10^8)
func (o *OrderPayload) GetScaledSize() string {
	return decimal.RequireFromString(o.Size).Mul(scaleX8Decimal).String()
}

// GetScaledPrice multiplies price by decimal precision of 8
// e.g. 3_309.33 is converted to 330_933_000_000 (3_309.33 * 10^8)
func (o *OrderPayload) GetScaledPrice() string {
	price := o.Price
	if OrderType(o.OrderType) == OrderTypeMarket {
		return "0"
	} else {
		return decimal.RequireFromString(price).Mul(scaleX8Decimal).String()
	}
}

// FmtDefinitionEncoding encodes the OrderPayload for StarkNet signing.
// It returns a slice of big.Int values representing the encoded payload.
func (o *OrderPayload) FmtDefinitionEncoding(field string) (fmtEnc []*big.Int) {
	switch field {
	case "timestamp":
		fmtEnc = append(fmtEnc, big.NewInt(o.Timestamp))
	case "market":
		fmtEnc = append(fmtEnc, types.StrToFelt(o.Market).Big())
	case "side":
		side := OrderSide(o.Side).Get()
		fmtEnc = append(fmtEnc, types.StrToFelt(side).Big())
	case "orderType":
		fmtEnc = append(fmtEnc, types.StrToFelt(o.OrderType).Big())
	case "size":
		size := o.GetScaledSize()
		fmtEnc = append(fmtEnc, types.StrToFelt(size).Big())
	case "price":
		price := o.GetScaledPrice()
		fmtEnc = append(fmtEnc, types.StrToFelt(price).Big())
	}

	return fmtEnc
}

type ModifyOrderPayload struct {
	OrderPayload
	Id string
}

// FmtDefinitionEncoding encodes the ModifyOrderPayload for StarkNet signing.
// It returns a slice of big.Int values representing the encoded payload.
func (mo *ModifyOrderPayload) FmtDefinitionEncoding(field string) (fmtEnc []*big.Int) {
	fmtEnc = append(fmtEnc, mo.OrderPayload.FmtDefinitionEncoding(field)...)
	if field == "id" {
		fmtEnc = append(fmtEnc, types.StrToFelt(mo.Id).Big())
	}
	return fmtEnc
}

func domainDefinition() *caigo.TypeDef {
	return &caigo.TypeDef{Definitions: []caigo.Definition{
		{Name: "name", Type: "felt"},
		{Name: "chainId", Type: "felt"},
		{Name: "version", Type: "felt"}}}
}

func domain(chainId string) *caigo.Domain {
	return &caigo.Domain{
		Name:    "Paradex",
		Version: "1",
		ChainId: chainId,
	}
}

func onboardingPayloadDefinition() *caigo.TypeDef {
	return &caigo.TypeDef{Definitions: []caigo.Definition{
		{Name: "action", Type: "felt"}}}
}

func authPayloadDefinition() *caigo.TypeDef {
	return &caigo.TypeDef{Definitions: []caigo.Definition{
		{Name: "method", Type: "felt"},
		{Name: "path", Type: "felt"},
		{Name: "body", Type: "felt"},
		{Name: "timestamp", Type: "felt"},
		{Name: "expiration", Type: "felt"}}}
}

func orderPayloadDefinition() *caigo.TypeDef {
	return &caigo.TypeDef{Definitions: []caigo.Definition{
		{Name: "timestamp", Type: "felt"},
		{Name: "market", Type: "felt"},
		{Name: "side", Type: "felt"},
		{Name: "orderType", Type: "felt"},
		{Name: "size", Type: "felt"},
		{Name: "price", Type: "felt"}}}
}

func modifyOrderPayloadDefinition() *caigo.TypeDef {
	return &caigo.TypeDef{Definitions: []caigo.Definition{
		{Name: "timestamp", Type: "felt"},
		{Name: "market", Type: "felt"},
		{Name: "side", Type: "felt"},
		{Name: "orderType", Type: "felt"},
		{Name: "size", Type: "felt"},
		{Name: "price", Type: "felt"},
		{Name: "id", Type: "felt"}}}
}

func onboardingTypes() map[string]caigo.TypeDef {
	return map[string]caigo.TypeDef{
		"StarkNetDomain": *domainDefinition(),
		"Constant":       *onboardingPayloadDefinition(),
	}
}

func authTypes() map[string]caigo.TypeDef {
	return map[string]caigo.TypeDef{
		"StarkNetDomain": *domainDefinition(),
		"Request":        *authPayloadDefinition(),
	}
}

func orderTypes() map[string]caigo.TypeDef {
	return map[string]caigo.TypeDef{
		"StarkNetDomain": *domainDefinition(),
		"Order":          *orderPayloadDefinition(),
	}
}

func modifyOrderTypes() map[string]caigo.TypeDef {
	return map[string]caigo.TypeDef{
		"StarkNetDomain": *domainDefinition(),
		"ModifyOrder":    *modifyOrderPayloadDefinition(),
	}
}

// VerificationType represents the type of verification to be performed.
type VerificationType string

var (
	// VerificationTypeOnboarding represents the type of verification for onboarding a new user.
	VerificationTypeOnboarding VerificationType = "Onboarding"
	// VerificationTypeAuth represents the type of verification for authenticating a user.
	VerificationTypeAuth VerificationType = "Auth"
	// VerificationTypeOrder represents the type of verification for placing an order.
	VerificationTypeOrder VerificationType = "Order"
	// VerificationTypeModifyOrder represents the type of verification for modifying an order.
	VerificationTypeModifyOrder VerificationType = "ModifyOrder"
)

// NewVerificationTypedData creates a new typed data for a given verification type and chain ID.
// It returns a caigo TypedData and an error if the type is invalid.
func NewVerificationTypedData(vType VerificationType, chainId string) (*caigo.TypedData, error) {
	if vType == VerificationTypeOnboarding {
		return NewTypedData(onboardingTypes(), domain(chainId), "Constant")
	}
	if vType == VerificationTypeAuth {
		return NewTypedData(authTypes(), domain(chainId), "Request")
	}
	if vType == VerificationTypeOrder {
		return NewTypedData(orderTypes(), domain(chainId), "Order")
	}
	if vType == VerificationTypeModifyOrder {
		return NewTypedData(modifyOrderTypes(), domain(chainId), "ModifyOrder")
	}
	return nil, errors.New("invalid validation type")
}

// NewTypedData returns a caigo typed data that
// will be used to hash the message. It needs to be the same
// structure the FE sends to metamask snap when signing
func NewTypedData(types map[string]caigo.TypeDef, domain *caigo.Domain, pType string) (*caigo.TypedData, error) {
	typedData, err := caigo.NewTypedData(
		types,
		pType,
		*domain,
	)

	if err != nil {
		return nil, errors.New("failed to create typed data with caigo")
	}

	return &typedData, nil
}

// PedersenArray computes the Pedersen hash of an array of big.Int values.
func PedersenArray(elems []*big.Int) *big.Int {
	fpElements := make([]*fp.Element, len(elems))
	for i, elem := range elems {
		fpElements[i] = new(fp.Element).SetBigInt(elem)
	}
	hash := pedersenhash.PedersenArray(fpElements...)
	return hash.BigInt(new(big.Int))
}

// GetMessageHash computes the hash of a message for a given typed data, domain, account, and stark curve.
func GetMessageHash(td *caigo.TypedData, domEnc *big.Int, account *big.Int, msg caigo.TypedMessage, sc caigo.StarkCurve) (hash *big.Int, err error) {
	elements := []*big.Int{snMessageBigInt, domEnc, account, nil}

	msgEnc, err := td.GetTypedMessageHash(td.PrimaryType, msg, sc)
	if err != nil {
		return hash, fmt.Errorf("could not hash message: %w", err)
	}
	elements[3] = msgEnc
	hash, err = sc.ComputeHashOnElements(elements)
	return hash, err
}

// GnarkGetMessageHash computes the hash of a message for a given typed data, domain, account, and stark curve using the Gnark library.
func GnarkGetMessageHash(td *caigo.TypedData, domEnc *big.Int, account *big.Int, msg caigo.TypedMessage, sc caigo.StarkCurve) (hash *big.Int, err error) {
	msgEnc, err := GnarkGetTypedMessageHash(td, td.PrimaryType, msg)
	if err != nil {
		return nil, fmt.Errorf("could not hash message: %w", err)
	}
	elements := []*big.Int{snMessageBigInt, domEnc, account, msgEnc}
	hash = PedersenArray(elements)
	return hash, err
}

// GnarkGetTypedMessageHash computes the hash of a message for a given typed data, input type, and message using the Gnark library.
func GnarkGetTypedMessageHash(td *caigo.TypedData, inType string, msg caigo.TypedMessage) (hash *big.Int, err error) {
	prim := td.Types[inType]
	elements := make([]*big.Int, 0, len(prim.Definitions)+1)
	elements = append(elements, prim.Encoding)

	for _, def := range prim.Definitions {
		if def.Type == "felt" {
			fmtDefinitions := msg.FmtDefinitionEncoding(def.Name)
			elements = append(elements, fmtDefinitions...)
		} else {
			panic("not felt")
		}
	}
	hash = PedersenArray(elements)
	return hash, err
}
