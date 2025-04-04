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

// VaultsGetHistoricalDataReader is a Reader for the VaultsGetHistoricalData structure.
type VaultsGetHistoricalDataReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *VaultsGetHistoricalDataReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewVaultsGetHistoricalDataOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewVaultsGetHistoricalDataBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /vaults/history] vaults-get-historical-data", response, response.Code())
	}
}

// NewVaultsGetHistoricalDataOK creates a VaultsGetHistoricalDataOK with default headers values
func NewVaultsGetHistoricalDataOK() *VaultsGetHistoricalDataOK {
	return &VaultsGetHistoricalDataOK{}
}

/*
VaultsGetHistoricalDataOK describes a response with status code 200, with default header values.

OK
*/
type VaultsGetHistoricalDataOK struct {
	Payload *models.ResponsesGetVaultHistoricalDataResp
}

// IsSuccess returns true when this vaults get historical data o k response has a 2xx status code
func (o *VaultsGetHistoricalDataOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this vaults get historical data o k response has a 3xx status code
func (o *VaultsGetHistoricalDataOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this vaults get historical data o k response has a 4xx status code
func (o *VaultsGetHistoricalDataOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this vaults get historical data o k response has a 5xx status code
func (o *VaultsGetHistoricalDataOK) IsServerError() bool {
	return false
}

// IsCode returns true when this vaults get historical data o k response a status code equal to that given
func (o *VaultsGetHistoricalDataOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the vaults get historical data o k response
func (o *VaultsGetHistoricalDataOK) Code() int {
	return 200
}

func (o *VaultsGetHistoricalDataOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /vaults/history][%d] vaultsGetHistoricalDataOK %s", 200, payload)
}

func (o *VaultsGetHistoricalDataOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /vaults/history][%d] vaultsGetHistoricalDataOK %s", 200, payload)
}

func (o *VaultsGetHistoricalDataOK) GetPayload() *models.ResponsesGetVaultHistoricalDataResp {
	return o.Payload
}

func (o *VaultsGetHistoricalDataOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesGetVaultHistoricalDataResp)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewVaultsGetHistoricalDataBadRequest creates a VaultsGetHistoricalDataBadRequest with default headers values
func NewVaultsGetHistoricalDataBadRequest() *VaultsGetHistoricalDataBadRequest {
	return &VaultsGetHistoricalDataBadRequest{}
}

/*
VaultsGetHistoricalDataBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type VaultsGetHistoricalDataBadRequest struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this vaults get historical data bad request response has a 2xx status code
func (o *VaultsGetHistoricalDataBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this vaults get historical data bad request response has a 3xx status code
func (o *VaultsGetHistoricalDataBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this vaults get historical data bad request response has a 4xx status code
func (o *VaultsGetHistoricalDataBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this vaults get historical data bad request response has a 5xx status code
func (o *VaultsGetHistoricalDataBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this vaults get historical data bad request response a status code equal to that given
func (o *VaultsGetHistoricalDataBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the vaults get historical data bad request response
func (o *VaultsGetHistoricalDataBadRequest) Code() int {
	return 400
}

func (o *VaultsGetHistoricalDataBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /vaults/history][%d] vaultsGetHistoricalDataBadRequest %s", 400, payload)
}

func (o *VaultsGetHistoricalDataBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /vaults/history][%d] vaultsGetHistoricalDataBadRequest %s", 400, payload)
}

func (o *VaultsGetHistoricalDataBadRequest) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *VaultsGetHistoricalDataBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
