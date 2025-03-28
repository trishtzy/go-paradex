// Code generated by go-swagger; DO NOT EDIT.

package liquidations

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

// GetLiquidationsReader is a Reader for the GetLiquidations structure.
type GetLiquidationsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetLiquidationsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetLiquidationsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetLiquidationsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /liquidations] get-liquidations", response, response.Code())
	}
}

// NewGetLiquidationsOK creates a GetLiquidationsOK with default headers values
func NewGetLiquidationsOK() *GetLiquidationsOK {
	return &GetLiquidationsOK{}
}

/*
GetLiquidationsOK describes a response with status code 200, with default header values.

OK
*/
type GetLiquidationsOK struct {
	Payload *models.ResponsesGetLiquidations
}

// IsSuccess returns true when this get liquidations o k response has a 2xx status code
func (o *GetLiquidationsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get liquidations o k response has a 3xx status code
func (o *GetLiquidationsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get liquidations o k response has a 4xx status code
func (o *GetLiquidationsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get liquidations o k response has a 5xx status code
func (o *GetLiquidationsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get liquidations o k response a status code equal to that given
func (o *GetLiquidationsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get liquidations o k response
func (o *GetLiquidationsOK) Code() int {
	return 200
}

func (o *GetLiquidationsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /liquidations][%d] getLiquidationsOK %s", 200, payload)
}

func (o *GetLiquidationsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /liquidations][%d] getLiquidationsOK %s", 200, payload)
}

func (o *GetLiquidationsOK) GetPayload() *models.ResponsesGetLiquidations {
	return o.Payload
}

func (o *GetLiquidationsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesGetLiquidations)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLiquidationsBadRequest creates a GetLiquidationsBadRequest with default headers values
func NewGetLiquidationsBadRequest() *GetLiquidationsBadRequest {
	return &GetLiquidationsBadRequest{}
}

/*
GetLiquidationsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetLiquidationsBadRequest struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this get liquidations bad request response has a 2xx status code
func (o *GetLiquidationsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get liquidations bad request response has a 3xx status code
func (o *GetLiquidationsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get liquidations bad request response has a 4xx status code
func (o *GetLiquidationsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get liquidations bad request response has a 5xx status code
func (o *GetLiquidationsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get liquidations bad request response a status code equal to that given
func (o *GetLiquidationsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get liquidations bad request response
func (o *GetLiquidationsBadRequest) Code() int {
	return 400
}

func (o *GetLiquidationsBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /liquidations][%d] getLiquidationsBadRequest %s", 400, payload)
}

func (o *GetLiquidationsBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /liquidations][%d] getLiquidationsBadRequest %s", 400, payload)
}

func (o *GetLiquidationsBadRequest) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *GetLiquidationsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
