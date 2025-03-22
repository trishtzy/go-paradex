package main

import (
	"fmt"
	"strconv"
	"time"

	httptransport "github.com/go-openapi/runtime/client"
	goparadex "github.com/trishtzy/go-paradex"
	"github.com/trishtzy/go-paradex/auth"
	"github.com/trishtzy/go-paradex/client"
	"github.com/trishtzy/go-paradex/client/account"
	"github.com/trishtzy/go-paradex/client/authentication"
	"github.com/trishtzy/go-paradex/client/orders"
	"github.com/trishtzy/go-paradex/client/system"
	"github.com/trishtzy/go-paradex/models"
)

func main() {
	config, err := goparadex.NewConfig()
	if err != nil {
		fmt.Printf("Failed to get config: %v\n", err)
	}
	fmt.Printf("Config: %+v\n", config)

	// Create a client configuration
	clientConfig := client.DefaultTransportConfig().
		WithHost("api.testnet.paradex.trade").
		WithBasePath("/v1").
		WithSchemes([]string{"https"})

	// Create the main API client
	api := client.NewHTTPClientWithConfig(nil, clientConfig)

	// Step 1: Get system config
	configParams := system.NewGetSystemConfigParams()
	configResp, err := api.System.GetSystemConfig(configParams)
	if err != nil {
		fmt.Printf("Failed to get system config: %v\n", err)
	}

	// Step 1.1: Generate paradex L2 account
	dexPrivateKey, dexPublicKey, dexAccountAddress := auth.GenerateParadexAccount(
		*configResp.GetPayload(), config.EthereumPrivateKey)
	fmt.Printf("Paradex L2 account: %s\n", dexAccountAddress)
	fmt.Printf("Paradex L2 private key: %s\n", dexPrivateKey)
	fmt.Printf("Paradex L2 public key: %s\n", dexPublicKey)

	// Step 1.2: Generate Ethereum public key
	_, ethereumAddress := auth.GetEthereumAccount(config.EthereumPrivateKey)
	fmt.Printf("Ethereum address: %s\n", ethereumAddress)

	// Step 2: Onboarding
	onboardingParams := authentication.NewOnboardingParams()
	starknetSignature := auth.SignSNTypedData(auth.SignerParams{
		MessageType:       "onboarding",
		DexAccountAddress: dexAccountAddress,
		DexPrivateKey:     dexPrivateKey,
		SysConfig:         *configResp.GetPayload(),
	})
	// Set request headers for onboarding
	onboardingParams.SetPARADEXETHEREUMACCOUNT(ethereumAddress)
	onboardingParams.SetPARADEXSTARKNETACCOUNT(dexAccountAddress)
	onboardingParams.SetPARADEXSTARKNETSIGNATURE(starknetSignature)
	// Set request body for onboarding
	onboardingParams.SetRequest(&models.RequestsOnboarding{
		PublicKey: dexPublicKey,
	})

	onboardingResp, err := api.Authentication.Onboarding(onboardingParams)
	if err != nil {
		fmt.Printf("Onboarding failed: %v\n", err)
	}
	fmt.Printf("Onboarding successful: %v\n", onboardingResp.Code())

	// Step 3: Authenticate to get JWT token
	authParams := authentication.NewAuthParams()
	// Set necessary headers or body parameters for authentication
	now := time.Now().Unix()
	timestampStr := strconv.FormatInt(now, 10)
	expirationStr := strconv.FormatInt(now+auth.DEFAULT_EXPIRY_IN_SECONDS, 10)
	starknetJwtSignature := auth.SignSNTypedData(auth.SignerParams{
		MessageType:       "auth",
		DexAccountAddress: dexAccountAddress,
		DexPrivateKey:     dexPrivateKey,
		SysConfig:         *configResp.GetPayload(),
		Params: map[string]interface{}{
			"timestamp":  timestampStr,
			"expiration": expirationStr,
		},
	})
	authParams.SetPARADEXSTARKNETSIGNATURE(starknetJwtSignature)
	authParams.SetPARADEXSTARKNETACCOUNT(dexAccountAddress)
	authParams.SetPARADEXTIMESTAMP(timestampStr)
	authParams.SetPARADEXSIGNATUREEXPIRATION(&expirationStr)

	authResp, err := api.Authentication.Auth(authParams)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
	}
	jwt := authResp.Payload.JwtToken
	fmt.Printf("JWT token: %s\n", jwt)

	// Create bearer token authentication for subsequent calls
	bearerAuth := httptransport.BearerToken(jwt)

	// Example 1: Get account balance
	balanceParams := account.NewGetBalanceParams()
	balance, err := api.Account.GetBalance(balanceParams, bearerAuth)
	if err != nil {
		fmt.Printf("Failed to get balance: %v\n", err)
	}
	fmt.Println("Account Balance:")
	fmt.Printf("  Balance details: %+v\n", balance.GetPayload().Results[0])
	fmt.Println()

	// Example 2: Place an order
	orderParams := orders.NewOrdersNewParams()
	market := "ETH-USD-PERP"
	price := "1000"
	size := "1"
	now = time.Now().UnixMilli()
	orderSignature := auth.SignSNTypedData(auth.SignerParams{
		MessageType:       "order",
		DexAccountAddress: dexAccountAddress,
		DexPrivateKey:     dexPrivateKey,
		SysConfig:         *configResp.GetPayload(),
		Params: map[string]interface{}{
			"timestamp": now,
			"market":    market,
			"side":      "BUY",
			"orderType": "LIMIT",
			"size":      size,
			"price":     price,
		},
	})
	orderParams.SetParams(&models.RequestsOrderRequest{
		ClientID:           "client-id",
		Type:               struct{ models.ResponsesOrderType }{models.ResponsesOrderType("LIMIT")},
		Side:               struct{ models.ResponsesOrderSide }{models.ResponsesOrderSide("BUY")},
		Market:             &market,
		Price:              &price,
		Size:               &size,
		Signature:          &orderSignature,
		SignatureTimestamp: &now,
	})

	orderResp, err := api.Orders.OrdersNew(orderParams, bearerAuth)
	if err != nil {
		fmt.Printf("Failed to place order: %v\n", err)
	}
	fmt.Printf("Order placed successfully: %v\n", orderResp.Code())
}
