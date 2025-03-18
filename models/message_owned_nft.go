// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// MessageOwnedNft message owned nft
//
// swagger:model message.OwnedNft
type MessageOwnedNft struct {

	// collection address
	CollectionAddress string `json:"collection_address,omitempty"`

	// collection name
	CollectionName string `json:"collection_name,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// id
	ID string `json:"id,omitempty"`

	// image url
	ImageURL string `json:"image_url,omitempty"`

	// name
	Name string `json:"name,omitempty"`
}

// Validate validates this message owned nft
func (m *MessageOwnedNft) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this message owned nft based on context it is used
func (m *MessageOwnedNft) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MessageOwnedNft) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MessageOwnedNft) UnmarshalBinary(b []byte) error {
	var res MessageOwnedNft
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
