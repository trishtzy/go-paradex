// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ResponsesTradebustResult responses tradebust result
//
// swagger:model responses.TradebustResult
type ResponsesTradebustResult struct {

	// Starknet Account from which fill was created
	// Example: 0x495d2eb5236a12b8b4ad7d3849ce6a203ce21c43f473c248dfd5ce70d9454fa
	Account string `json:"account,omitempty"`

	// Unique string ID of the busted fill
	// Example: 12342345
	BustedFillID string `json:"busted_fill_id,omitempty"`

	// Unix Millis timestamp when bust was created
	// Example: 1681497002041
	CreatedAt int64 `json:"created_at,omitempty"`
}

// Validate validates this responses tradebust result
func (m *ResponsesTradebustResult) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this responses tradebust result based on context it is used
func (m *ResponsesTradebustResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ResponsesTradebustResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ResponsesTradebustResult) UnmarshalBinary(b []byte) error {
	var res ResponsesTradebustResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
