// Code generated by go-swagger; DO NOT EDIT.

package vaults

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/trishtzy/go-paradex/models"
)

// VaultsGetConfigReader is a Reader for the VaultsGetConfig structure.
type VaultsGetConfigReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *VaultsGetConfigReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewVaultsGetConfigOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewVaultsGetConfigBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /vaults/config] vaults-get-config", response, response.Code())
	}
}

// NewVaultsGetConfigOK creates a VaultsGetConfigOK with default headers values
func NewVaultsGetConfigOK() *VaultsGetConfigOK {
	return &VaultsGetConfigOK{}
}

/*
VaultsGetConfigOK describes a response with status code 200, with default header values.

OK
*/
type VaultsGetConfigOK struct {
	Payload *models.ResponsesVaultsConfigResponse
}

// IsSuccess returns true when this vaults get config o k response has a 2xx status code
func (o *VaultsGetConfigOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this vaults get config o k response has a 3xx status code
func (o *VaultsGetConfigOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this vaults get config o k response has a 4xx status code
func (o *VaultsGetConfigOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this vaults get config o k response has a 5xx status code
func (o *VaultsGetConfigOK) IsServerError() bool {
	return false
}

// IsCode returns true when this vaults get config o k response a status code equal to that given
func (o *VaultsGetConfigOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the vaults get config o k response
func (o *VaultsGetConfigOK) Code() int {
	return 200
}

func (o *VaultsGetConfigOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /vaults/config][%d] vaultsGetConfigOK %s", 200, payload)
}

func (o *VaultsGetConfigOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /vaults/config][%d] vaultsGetConfigOK %s", 200, payload)
}

func (o *VaultsGetConfigOK) GetPayload() *models.ResponsesVaultsConfigResponse {
	return o.Payload
}

func (o *VaultsGetConfigOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesVaultsConfigResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewVaultsGetConfigBadRequest creates a VaultsGetConfigBadRequest with default headers values
func NewVaultsGetConfigBadRequest() *VaultsGetConfigBadRequest {
	return &VaultsGetConfigBadRequest{}
}

/*
VaultsGetConfigBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type VaultsGetConfigBadRequest struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this vaults get config bad request response has a 2xx status code
func (o *VaultsGetConfigBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this vaults get config bad request response has a 3xx status code
func (o *VaultsGetConfigBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this vaults get config bad request response has a 4xx status code
func (o *VaultsGetConfigBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this vaults get config bad request response has a 5xx status code
func (o *VaultsGetConfigBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this vaults get config bad request response a status code equal to that given
func (o *VaultsGetConfigBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the vaults get config bad request response
func (o *VaultsGetConfigBadRequest) Code() int {
	return 400
}

func (o *VaultsGetConfigBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /vaults/config][%d] vaultsGetConfigBadRequest %s", 400, payload)
}

func (o *VaultsGetConfigBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /vaults/config][%d] vaultsGetConfigBadRequest %s", 400, payload)
}

func (o *VaultsGetConfigBadRequest) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *VaultsGetConfigBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
