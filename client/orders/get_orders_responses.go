// Code generated by go-swagger; DO NOT EDIT.

package orders

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

// GetOrdersReader is a Reader for the GetOrders structure.
type GetOrdersReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetOrdersReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetOrdersOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetOrdersBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /orders-history] get-orders", response, response.Code())
	}
}

// NewGetOrdersOK creates a GetOrdersOK with default headers values
func NewGetOrdersOK() *GetOrdersOK {
	return &GetOrdersOK{}
}

/*
GetOrdersOK describes a response with status code 200, with default header values.

OK
*/
type GetOrdersOK struct {
	Payload *models.ResponsesGetOrders
}

// IsSuccess returns true when this get orders o k response has a 2xx status code
func (o *GetOrdersOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get orders o k response has a 3xx status code
func (o *GetOrdersOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get orders o k response has a 4xx status code
func (o *GetOrdersOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get orders o k response has a 5xx status code
func (o *GetOrdersOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get orders o k response a status code equal to that given
func (o *GetOrdersOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get orders o k response
func (o *GetOrdersOK) Code() int {
	return 200
}

func (o *GetOrdersOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /orders-history][%d] getOrdersOK %s", 200, payload)
}

func (o *GetOrdersOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /orders-history][%d] getOrdersOK %s", 200, payload)
}

func (o *GetOrdersOK) GetPayload() *models.ResponsesGetOrders {
	return o.Payload
}

func (o *GetOrdersOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesGetOrders)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrdersBadRequest creates a GetOrdersBadRequest with default headers values
func NewGetOrdersBadRequest() *GetOrdersBadRequest {
	return &GetOrdersBadRequest{}
}

/*
GetOrdersBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetOrdersBadRequest struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this get orders bad request response has a 2xx status code
func (o *GetOrdersBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get orders bad request response has a 3xx status code
func (o *GetOrdersBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get orders bad request response has a 4xx status code
func (o *GetOrdersBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get orders bad request response has a 5xx status code
func (o *GetOrdersBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get orders bad request response a status code equal to that given
func (o *GetOrdersBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get orders bad request response
func (o *GetOrdersBadRequest) Code() int {
	return 400
}

func (o *GetOrdersBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /orders-history][%d] getOrdersBadRequest %s", 400, payload)
}

func (o *GetOrdersBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /orders-history][%d] getOrdersBadRequest %s", 400, payload)
}

func (o *GetOrdersBadRequest) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *GetOrdersBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
