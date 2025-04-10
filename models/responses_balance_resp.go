// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ResponsesBalanceResp responses balance resp
//
// swagger:model responses.BalanceResp
type ResponsesBalanceResp struct {

	// Balance last updated time
	// Example: 1681462770114
	LastUpdatedAt int64 `json:"last_updated_at,omitempty"`

	// Balance amount of settlement token (includes deposits, withdrawals, realized PnL, realized funding, and fees)
	// Example: 123003.620
	Size string `json:"size,omitempty"`

	// Name of the token
	// Example: USDC
	Token string `json:"token,omitempty"`
}

// Validate validates this responses balance resp
func (m *ResponsesBalanceResp) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this responses balance resp based on context it is used
func (m *ResponsesBalanceResp) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ResponsesBalanceResp) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ResponsesBalanceResp) UnmarshalBinary(b []byte) error {
	var res ResponsesBalanceResp
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
