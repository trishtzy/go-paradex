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

// OrdersCancelReader is a Reader for the OrdersCancel structure.
type OrdersCancelReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *OrdersCancelReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewOrdersCancelNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewOrdersCancelBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /orders/{order_id}] orders-cancel", response, response.Code())
	}
}

// NewOrdersCancelNoContent creates a OrdersCancelNoContent with default headers values
func NewOrdersCancelNoContent() *OrdersCancelNoContent {
	return &OrdersCancelNoContent{}
}

/*
OrdersCancelNoContent describes a response with status code 204, with default header values.

No Content
*/
type OrdersCancelNoContent struct {
}

// IsSuccess returns true when this orders cancel no content response has a 2xx status code
func (o *OrdersCancelNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this orders cancel no content response has a 3xx status code
func (o *OrdersCancelNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this orders cancel no content response has a 4xx status code
func (o *OrdersCancelNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this orders cancel no content response has a 5xx status code
func (o *OrdersCancelNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this orders cancel no content response a status code equal to that given
func (o *OrdersCancelNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the orders cancel no content response
func (o *OrdersCancelNoContent) Code() int {
	return 204
}

func (o *OrdersCancelNoContent) Error() string {
	return fmt.Sprintf("[DELETE /orders/{order_id}][%d] ordersCancelNoContent", 204)
}

func (o *OrdersCancelNoContent) String() string {
	return fmt.Sprintf("[DELETE /orders/{order_id}][%d] ordersCancelNoContent", 204)
}

func (o *OrdersCancelNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewOrdersCancelBadRequest creates a OrdersCancelBadRequest with default headers values
func NewOrdersCancelBadRequest() *OrdersCancelBadRequest {
	return &OrdersCancelBadRequest{}
}

/*
OrdersCancelBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type OrdersCancelBadRequest struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this orders cancel bad request response has a 2xx status code
func (o *OrdersCancelBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this orders cancel bad request response has a 3xx status code
func (o *OrdersCancelBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this orders cancel bad request response has a 4xx status code
func (o *OrdersCancelBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this orders cancel bad request response has a 5xx status code
func (o *OrdersCancelBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this orders cancel bad request response a status code equal to that given
func (o *OrdersCancelBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the orders cancel bad request response
func (o *OrdersCancelBadRequest) Code() int {
	return 400
}

func (o *OrdersCancelBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /orders/{order_id}][%d] ordersCancelBadRequest %s", 400, payload)
}

func (o *OrdersCancelBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /orders/{order_id}][%d] ordersCancelBadRequest %s", 400, payload)
}

func (o *OrdersCancelBadRequest) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *OrdersCancelBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
