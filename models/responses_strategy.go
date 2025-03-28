// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ResponsesStrategy responses strategy
//
// swagger:model responses.Strategy
type ResponsesStrategy struct {

	// Contract address of the sub-operator
	// Example: 0x1234567890abcdef
	Address string `json:"address,omitempty"`

	// Strategy name
	// Example: Alpha Strategy
	Name string `json:"name,omitempty"`
}

// Validate validates this responses strategy
func (m *ResponsesStrategy) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this responses strategy based on context it is used
func (m *ResponsesStrategy) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ResponsesStrategy) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ResponsesStrategy) UnmarshalBinary(b []byte) error {
	var res ResponsesStrategy
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
