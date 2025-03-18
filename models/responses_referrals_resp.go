// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ResponsesReferralsResp responses referrals resp
//
// swagger:model responses.ReferralsResp
type ResponsesReferralsResp struct {

	// referee address
	Address string `json:"address,omitempty"`

	// Joined at timestamp in milliseconds
	// Example: 1715592690488
	CreatedAt int64 `json:"created_at,omitempty"`

	// Referral code used to onboard the referee
	// Example: maxdegen01
	ReferralCode string `json:"referral_code,omitempty"`

	// Total referral commission earned from the fee of referee
	// Example: 0.123
	ReferralRewards string `json:"referral_rewards,omitempty"`

	// Total volume traded by referee
	// Example: 0.123
	VolumeTraded string `json:"volume_traded,omitempty"`
}

// Validate validates this responses referrals resp
func (m *ResponsesReferralsResp) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this responses referrals resp based on context it is used
func (m *ResponsesReferralsResp) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ResponsesReferralsResp) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ResponsesReferralsResp) UnmarshalBinary(b []byte) error {
	var res ResponsesReferralsResp
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
