// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ResponsesPositionResp responses position resp
//
// swagger:model responses.PositionResp
type ResponsesPositionResp struct {

	// Account ID of the position
	Account string `json:"account,omitempty"`

	// Average entry price
	// Example: 29001.34
	AverageEntryPrice string `json:"average_entry_price,omitempty"`

	// Average entry price in USD
	// Example: 29001.34
	AverageEntryPriceUsd string `json:"average_entry_price_usd,omitempty"`

	// Average exit price
	// Example: 29001.34
	AverageExitPrice string `json:"average_exit_price,omitempty"`

	// Position cached funding index
	// Example: 1234.3
	CachedFundingIndex string `json:"cached_funding_index,omitempty"`

	// Position closed time
	// Example: 1681493939981
	ClosedAt int64 `json:"closed_at,omitempty"`

	// Position cost
	// Example: -10005.4623
	Cost string `json:"cost,omitempty"`

	// Position cost in USD
	// Example: -10005.4623
	CostUsd string `json:"cost_usd,omitempty"`

	// Position creation time
	// Example: 1681493939981
	CreatedAt int64 `json:"created_at,omitempty"`

	// Unique string ID for the position
	// Example: 1234234
	ID string `json:"id,omitempty"`

	// Last fill ID to which the position is referring
	// Example: 1234234
	LastFillID string `json:"last_fill_id,omitempty"`

	// Position last update time
	// Example: 1681493939981
	LastUpdatedAt int64 `json:"last_updated_at,omitempty"`

	// Leverage of the position
	Leverage string `json:"leverage,omitempty"`

	// Liquidation price of the position
	LiquidationPrice string `json:"liquidation_price,omitempty"`

	// Market for position
	// Example: BTC-USD-PERP
	Market string `json:"market,omitempty"`

	// Realized Funding PnL for the position. Reset to 0 when position is closed or flipped.
	RealizedPositionalFundingPnl string `json:"realized_positional_funding_pnl,omitempty"`

	// Realized PnL including both positional PnL and funding payments. Reset to 0 when position is closed or flipped.
	RealizedPositionalPnl string `json:"realized_positional_pnl,omitempty"`

	// Unique increasing number (non-sequential) that is assigned to this position update. Can be used to deduplicate multiple feeds
	// Example: 1681471234972000000
	SeqNo int64 `json:"seq_no,omitempty"`

	// Position Side : Long or Short
	// Enum: ["SHORT","LONG"]
	Side string `json:"side,omitempty"`

	// Size of the position with sign (positive if long or negative if short)
	// Example: -0.345
	Size string `json:"size,omitempty"`

	// Status of Position : Open or Closed
	// Enum: ["OPEN","CLOSED"]
	Status string `json:"status,omitempty"`

	// Unrealized running funding P&L for the position
	// Example: 12.234
	UnrealizedFundingPnl string `json:"unrealized_funding_pnl,omitempty"`

	// Unrealized P&L of the position in the quote asset
	// Example: -123.23
	UnrealizedPnl string `json:"unrealized_pnl,omitempty"`
}

// Validate validates this responses position resp
func (m *ResponsesPositionResp) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSide(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var responsesPositionRespTypeSidePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["SHORT","LONG"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		responsesPositionRespTypeSidePropEnum = append(responsesPositionRespTypeSidePropEnum, v)
	}
}

const (

	// ResponsesPositionRespSideSHORT captures enum value "SHORT"
	ResponsesPositionRespSideSHORT string = "SHORT"

	// ResponsesPositionRespSideLONG captures enum value "LONG"
	ResponsesPositionRespSideLONG string = "LONG"
)

// prop value enum
func (m *ResponsesPositionResp) validateSideEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, responsesPositionRespTypeSidePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *ResponsesPositionResp) validateSide(formats strfmt.Registry) error {
	if swag.IsZero(m.Side) { // not required
		return nil
	}

	// value enum
	if err := m.validateSideEnum("side", "body", m.Side); err != nil {
		return err
	}

	return nil
}

var responsesPositionRespTypeStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["OPEN","CLOSED"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		responsesPositionRespTypeStatusPropEnum = append(responsesPositionRespTypeStatusPropEnum, v)
	}
}

const (

	// ResponsesPositionRespStatusOPEN captures enum value "OPEN"
	ResponsesPositionRespStatusOPEN string = "OPEN"

	// ResponsesPositionRespStatusCLOSED captures enum value "CLOSED"
	ResponsesPositionRespStatusCLOSED string = "CLOSED"
)

// prop value enum
func (m *ResponsesPositionResp) validateStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, responsesPositionRespTypeStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *ResponsesPositionResp) validateStatus(formats strfmt.Registry) error {
	if swag.IsZero(m.Status) { // not required
		return nil
	}

	// value enum
	if err := m.validateStatusEnum("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this responses position resp based on context it is used
func (m *ResponsesPositionResp) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ResponsesPositionResp) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ResponsesPositionResp) UnmarshalBinary(b []byte) error {
	var res ResponsesPositionResp
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
