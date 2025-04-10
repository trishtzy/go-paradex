// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RequestsCreateVault requests create vault
//
// swagger:model requests.CreateVault
type RequestsCreateVault struct {

	// Initial deposit transfer by vault owner
	// Example: [
	DepositTxSignature string `json:"deposit_tx_signature,omitempty"`

	// Description for the vault
	// Example: My vault description
	Description string `json:"description,omitempty"`

	// User's deposits lockup period in days
	// Example: 1
	LockupPeriod int64 `json:"lockup_period,omitempty"`

	// Max TVL locked by the Vault, if any. 0 for unlimited
	// Example: 1000000
	MaxTvl int64 `json:"max_tvl,omitempty"`

	// Unique name for the vault
	// Example: MyVault
	Name string `json:"name,omitempty"`

	// Vault owner profit share (percentage)
	// Example: 10
	ProfitShare int64 `json:"profit_share,omitempty"`

	// Public key of vault operator
	// Example: 0x1234567890abcdef
	PublicKey string `json:"public_key,omitempty"`
}

// Validate validates this requests create vault
func (m *RequestsCreateVault) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this requests create vault based on context it is used
func (m *RequestsCreateVault) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RequestsCreateVault) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RequestsCreateVault) UnmarshalBinary(b []byte) error {
	var res RequestsCreateVault
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
