// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// ResponsesTraderRole responses trader role
//
// swagger:model responses.TraderRole
type ResponsesTraderRole string

func NewResponsesTraderRole(value ResponsesTraderRole) *ResponsesTraderRole {
	return &value
}

// Pointer returns a pointer to a freshly-allocated ResponsesTraderRole.
func (m ResponsesTraderRole) Pointer() *ResponsesTraderRole {
	return &m
}

const (

	// ResponsesTraderRoleTAKER captures enum value "TAKER"
	ResponsesTraderRoleTAKER ResponsesTraderRole = "TAKER"

	// ResponsesTraderRoleMAKER captures enum value "MAKER"
	ResponsesTraderRoleMAKER ResponsesTraderRole = "MAKER"
)

// for schema
var responsesTraderRoleEnum []interface{}

func init() {
	var res []ResponsesTraderRole
	if err := json.Unmarshal([]byte(`["TAKER","MAKER"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		responsesTraderRoleEnum = append(responsesTraderRoleEnum, v)
	}
}

func (m ResponsesTraderRole) validateResponsesTraderRoleEnum(path, location string, value ResponsesTraderRole) error {
	if err := validate.EnumCase(path, location, value, responsesTraderRoleEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this responses trader role
func (m ResponsesTraderRole) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateResponsesTraderRoleEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this responses trader role based on context it is used
func (m ResponsesTraderRole) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
