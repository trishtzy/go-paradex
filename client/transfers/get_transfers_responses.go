// Code generated by go-swagger; DO NOT EDIT.

package transfers

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

// GetTransfersReader is a Reader for the GetTransfers structure.
type GetTransfersReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetTransfersReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetTransfersOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetTransfersBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /transfers] get-transfers", response, response.Code())
	}
}

// NewGetTransfersOK creates a GetTransfersOK with default headers values
func NewGetTransfersOK() *GetTransfersOK {
	return &GetTransfersOK{}
}

/*
GetTransfersOK describes a response with status code 200, with default header values.

OK
*/
type GetTransfersOK struct {
	Payload *models.ResponsesGetTransfersResponse
}

// IsSuccess returns true when this get transfers o k response has a 2xx status code
func (o *GetTransfersOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get transfers o k response has a 3xx status code
func (o *GetTransfersOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get transfers o k response has a 4xx status code
func (o *GetTransfersOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get transfers o k response has a 5xx status code
func (o *GetTransfersOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get transfers o k response a status code equal to that given
func (o *GetTransfersOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get transfers o k response
func (o *GetTransfersOK) Code() int {
	return 200
}

func (o *GetTransfersOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /transfers][%d] getTransfersOK %s", 200, payload)
}

func (o *GetTransfersOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /transfers][%d] getTransfersOK %s", 200, payload)
}

func (o *GetTransfersOK) GetPayload() *models.ResponsesGetTransfersResponse {
	return o.Payload
}

func (o *GetTransfersOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesGetTransfersResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTransfersBadRequest creates a GetTransfersBadRequest with default headers values
func NewGetTransfersBadRequest() *GetTransfersBadRequest {
	return &GetTransfersBadRequest{}
}

/*
GetTransfersBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetTransfersBadRequest struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this get transfers bad request response has a 2xx status code
func (o *GetTransfersBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get transfers bad request response has a 3xx status code
func (o *GetTransfersBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get transfers bad request response has a 4xx status code
func (o *GetTransfersBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get transfers bad request response has a 5xx status code
func (o *GetTransfersBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get transfers bad request response a status code equal to that given
func (o *GetTransfersBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get transfers bad request response
func (o *GetTransfersBadRequest) Code() int {
	return 400
}

func (o *GetTransfersBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /transfers][%d] getTransfersBadRequest %s", 400, payload)
}

func (o *GetTransfersBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /transfers][%d] getTransfersBadRequest %s", 400, payload)
}

func (o *GetTransfersBadRequest) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *GetTransfersBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
