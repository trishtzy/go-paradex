// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ResponsesMarketSummaryResp responses market summary resp
//
// swagger:model responses.MarketSummaryResp
type ResponsesMarketSummaryResp struct {

	// Best ask price
	// Example: 30130.15
	Ask string `json:"ask,omitempty"`

	// Ask implied volatility, for options
	// Example: 0.2
	AskIv string `json:"ask_iv,omitempty"`

	// Best bid price
	// Example: 30112.22
	Bid string `json:"bid,omitempty"`

	// Bid implied volatility, for options
	// Example: 0.2
	BidIv string `json:"bid_iv,omitempty"`

	// Market summary creation time
	CreatedAt int64 `json:"created_at,omitempty"`

	// Deprecated: Use greeks.delta instead
	// Example: 1
	Delta string `json:"delta,omitempty"`

	// [8 hour funding rate](https://docs.paradex.trade/risk-system/funding-mechanism#funding-rate)
	// Example: 0.3
	FundingRate string `json:"funding_rate,omitempty"`

	// Future funding rate, for options
	// Example: 0.3
	FutureFundingRate string `json:"future_funding_rate,omitempty"`

	// Greeks
	Greeks struct {
		ResponsesGreeks
	} `json:"greeks,omitempty"`

	// Last traded price implied volatility, for options
	// Example: 0.2
	LastIv string `json:"last_iv,omitempty"`

	// Last traded price
	// Example: 30109.53
	LastTradedPrice string `json:"last_traded_price,omitempty"`

	// Mark implied volatility, for options
	// Example: 0.2
	MarkIv string `json:"mark_iv,omitempty"`

	// [Mark price](https://docs.paradex.trade/risk-system/mark-price-calculation)
	// Example: 29799.70877478
	MarkPrice string `json:"mark_price,omitempty"`

	// Open interest in base currency
	// Example: 6100048.3
	OpenInterest string `json:"open_interest,omitempty"`

	// Price change rate in the last 24 hours
	// Example: 0.05
	PriceChangeRate24h string `json:"price_change_rate_24h,omitempty"`

	// Market symbol
	// Example: BTC-USD-PERP
	Symbol string `json:"symbol,omitempty"`

	// Lifetime total traded volume in USD
	// Example: 141341.0424
	TotalVolume string `json:"total_volume,omitempty"`

	// Underlying asset price (spot oracle price)
	// Example: 29876.3
	UnderlyingPrice string `json:"underlying_price,omitempty"`

	// 24 hour volume in USD
	// Example: 47041.0424
	Volume24h string `json:"volume_24h,omitempty"`
}

// Validate validates this responses market summary resp
func (m *ResponsesMarketSummaryResp) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateGreeks(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ResponsesMarketSummaryResp) validateGreeks(formats strfmt.Registry) error {
	if swag.IsZero(m.Greeks) { // not required
		return nil
	}

	return nil
}

// ContextValidate validate this responses market summary resp based on the context it is used
func (m *ResponsesMarketSummaryResp) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateGreeks(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ResponsesMarketSummaryResp) contextValidateGreeks(ctx context.Context, formats strfmt.Registry) error {

	return nil
}

// MarshalBinary interface implementation
func (m *ResponsesMarketSummaryResp) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ResponsesMarketSummaryResp) UnmarshalBinary(b []byte) error {
	var res ResponsesMarketSummaryResp
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
