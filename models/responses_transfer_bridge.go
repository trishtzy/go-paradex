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

// ResponsesTransferBridge responses transfer bridge
//
// swagger:model responses.TransferBridge
type ResponsesTransferBridge string

func NewResponsesTransferBridge(value ResponsesTransferBridge) *ResponsesTransferBridge {
	return &value
}

// Pointer returns a pointer to a freshly-allocated ResponsesTransferBridge.
func (m ResponsesTransferBridge) Pointer() *ResponsesTransferBridge {
	return &m
}

const (

	// ResponsesTransferBridgeEmpty captures enum value ""
	ResponsesTransferBridgeEmpty ResponsesTransferBridge = ""

	// ResponsesTransferBridgeSTARKGATE captures enum value "STARKGATE"
	ResponsesTransferBridgeSTARKGATE ResponsesTransferBridge = "STARKGATE"

	// ResponsesTransferBridgeLAYERSWAP captures enum value "LAYERSWAP"
	ResponsesTransferBridgeLAYERSWAP ResponsesTransferBridge = "LAYERSWAP"

	// ResponsesTransferBridgeRHINOFI captures enum value "RHINOFI"
	ResponsesTransferBridgeRHINOFI ResponsesTransferBridge = "RHINOFI"
)

// for schema
var responsesTransferBridgeEnum []interface{}

func init() {
	var res []ResponsesTransferBridge
	if err := json.Unmarshal([]byte(`["","STARKGATE","LAYERSWAP","RHINOFI"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		responsesTransferBridgeEnum = append(responsesTransferBridgeEnum, v)
	}
}

func (m ResponsesTransferBridge) validateResponsesTransferBridgeEnum(path, location string, value ResponsesTransferBridge) error {
	if err := validate.EnumCase(path, location, value, responsesTransferBridgeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this responses transfer bridge
func (m ResponsesTransferBridge) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateResponsesTransferBridgeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this responses transfer bridge based on context it is used
func (m ResponsesTransferBridge) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
