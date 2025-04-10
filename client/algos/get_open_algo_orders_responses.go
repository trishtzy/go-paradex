// Code generated by go-swagger; DO NOT EDIT.

package algos

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

// GetOpenAlgoOrdersReader is a Reader for the GetOpenAlgoOrders structure.
type GetOpenAlgoOrdersReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetOpenAlgoOrdersReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetOpenAlgoOrdersOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetOpenAlgoOrdersBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /algo/orders] get-open-algo-orders", response, response.Code())
	}
}

// NewGetOpenAlgoOrdersOK creates a GetOpenAlgoOrdersOK with default headers values
func NewGetOpenAlgoOrdersOK() *GetOpenAlgoOrdersOK {
	return &GetOpenAlgoOrdersOK{}
}

/*
GetOpenAlgoOrdersOK describes a response with status code 200, with default header values.

OK
*/
type GetOpenAlgoOrdersOK struct {
	Payload *models.ResponsesGetOpenAlgoOrders
}

// IsSuccess returns true when this get open algo orders o k response has a 2xx status code
func (o *GetOpenAlgoOrdersOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get open algo orders o k response has a 3xx status code
func (o *GetOpenAlgoOrdersOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get open algo orders o k response has a 4xx status code
func (o *GetOpenAlgoOrdersOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get open algo orders o k response has a 5xx status code
func (o *GetOpenAlgoOrdersOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get open algo orders o k response a status code equal to that given
func (o *GetOpenAlgoOrdersOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get open algo orders o k response
func (o *GetOpenAlgoOrdersOK) Code() int {
	return 200
}

func (o *GetOpenAlgoOrdersOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /algo/orders][%d] getOpenAlgoOrdersOK %s", 200, payload)
}

func (o *GetOpenAlgoOrdersOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /algo/orders][%d] getOpenAlgoOrdersOK %s", 200, payload)
}

func (o *GetOpenAlgoOrdersOK) GetPayload() *models.ResponsesGetOpenAlgoOrders {
	return o.Payload
}

func (o *GetOpenAlgoOrdersOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesGetOpenAlgoOrders)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOpenAlgoOrdersBadRequest creates a GetOpenAlgoOrdersBadRequest with default headers values
func NewGetOpenAlgoOrdersBadRequest() *GetOpenAlgoOrdersBadRequest {
	return &GetOpenAlgoOrdersBadRequest{}
}

/*
GetOpenAlgoOrdersBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetOpenAlgoOrdersBadRequest struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this get open algo orders bad request response has a 2xx status code
func (o *GetOpenAlgoOrdersBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get open algo orders bad request response has a 3xx status code
func (o *GetOpenAlgoOrdersBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get open algo orders bad request response has a 4xx status code
func (o *GetOpenAlgoOrdersBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get open algo orders bad request response has a 5xx status code
func (o *GetOpenAlgoOrdersBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get open algo orders bad request response a status code equal to that given
func (o *GetOpenAlgoOrdersBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get open algo orders bad request response
func (o *GetOpenAlgoOrdersBadRequest) Code() int {
	return 400
}

func (o *GetOpenAlgoOrdersBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /algo/orders][%d] getOpenAlgoOrdersBadRequest %s", 400, payload)
}

func (o *GetOpenAlgoOrdersBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /algo/orders][%d] getOpenAlgoOrdersBadRequest %s", 400, payload)
}

func (o *GetOpenAlgoOrdersBadRequest) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *GetOpenAlgoOrdersBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
