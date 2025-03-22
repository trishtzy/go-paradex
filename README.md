[![Go Reference](https://pkg.go.dev/badge/github.com/trishtzy/go-paradex.svg)](https://pkg.go.dev/github.com/trishtzy/go-paradex)
# Paradex REST API Client

A Go client to interact with Paradex API, generated using go-swagger.

## Documentation

For detailed API documentation, visit:
- Production API: https://docs.api.prod.paradex.trade/
- Testnet API: https://docs.api.testnet.paradex.trade/


## Installation

```bash
go get github.com/trishtzy/paradex-go
```

## Examples


### Basic Client Setup

```go
// Create a client configuration
clientConfig := client.DefaultTransportConfig().
  WithHost("api.testnet.paradex.trade").
  WithBasePath("/v1").
  WithSchemes([]string{"https"})

// Create the main API client
api := client.NewHTTPClientWithConfig(nil, clientConfig)
```

### Onboarding

```go
// Step 1: Get system config
configParams := system.NewGetSystemConfigParams()
configResp, err := api.System.GetSystemConfig(configParams)
if err != nil {
  fmt.Printf("Failed to get system config: %v\n", err)
}

// Step 1.1: Generate paradex L2 account
dexPrivateKey, dexPublicKey, dexAccountAddress := auth.GenerateParadexAccount(
  *configResp.GetPayload(), config.App.EthereumPrivateKey)
fmt.Printf("Paradex L2 account: %s\n", dexAccountAddress)
fmt.Printf("Paradex L2 private key: %s\n", dexPrivateKey)
fmt.Printf("Paradex L2 public key: %s\n", dexPublicKey)

// Step 1.2: Generate Ethereum public key
_, ethereumAddress := auth.GetEthereumAccount()
fmt.Printf("Ethereum address: %s\n", ethereumAddress)

// Step 2: Onboarding
onboardingParams := authentication.NewOnboardingParams()
starknetSignature := auth.SignSNTypedData(auth.SignerParams{
  MessageType:       "onboarding",
  DexAccountAddress: dexAccountAddress,
  DexPrivateKey:     dexPrivateKey,
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
```


### Authentication

To get a JWT token for authenticated calls, you will need a starknet signature:

```go
authParams := authentication.NewAuthParams()
// Set necessary headers or body parameters for authentication
now := time.Now().Unix()
timestampStr := strconv.FormatInt(now, 10)
expirationStr := strconv.FormatInt(now+auth.DEFAULT_EXPIRY_IN_SECONDS, 10)
starknetJwtSignature := auth.SignSNTypedData(auth.SignerParams{
  MessageType:       "auth",
  DexAccountAddress: dexAccountAddress,
  DexPrivateKey:     dexPrivateKey,
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
fmt.Println("JWT_TOKEN:", jwt)
```

### Get Account Balance

```go
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
```

### Place an Order

```go
orderParams := orders.NewOrdersNewParams()
market := "ETH-USD-PERP"
price := "1000"
size := "1"
now = time.Now().UnixMilli()
orderSignature := auth.SignSNTypedData(auth.SignerParams{
  MessageType:       "order",
  DexAccountAddress: dexAccountAddress,
  DexPrivateKey:     dexPrivateKey,
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
```

## Available Services

The client provides access to various API services:

- Account
- Authentication
- Orders
- Trades
- Markets
- Vaults
- Insurance
- Liquidations
- Transfers
- System
- Algos
- Referrals

Each service has its own set of methods for interacting with different endpoints.

## Configuration

The default configuration uses:


```30:40:client/paradex_r_e_s_t_api_client.go
const (
	// DefaultHost is the default Host
	// found in Meta (info) section of spec file
	DefaultHost string = "api.testnet.paradex.trade"
	// DefaultBasePath is the default BasePath
	// found in Meta (info) section of spec file
	DefaultBasePath string = "/v1"
)

// DefaultSchemes are the default schemes found in Meta (info) section of spec file
var DefaultSchemes = []string{"https"}
```


You can customize these values using the `TransportConfig` methods when creating a new client.
