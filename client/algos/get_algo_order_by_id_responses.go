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

// GetAlgoOrderByIDReader is a Reader for the GetAlgoOrderByID structure.
type GetAlgoOrderByIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAlgoOrderByIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAlgoOrderByIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 404:
		result := NewGetAlgoOrderByIDNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /algo/orders/{algo_id}] get-algo-order-by-id", response, response.Code())
	}
}

// NewGetAlgoOrderByIDOK creates a GetAlgoOrderByIDOK with default headers values
func NewGetAlgoOrderByIDOK() *GetAlgoOrderByIDOK {
	return &GetAlgoOrderByIDOK{}
}

/*
GetAlgoOrderByIDOK describes a response with status code 200, with default header values.

OK
*/
type GetAlgoOrderByIDOK struct {
	Payload *models.ResponsesAlgoOrderResp
}

// IsSuccess returns true when this get algo order by Id o k response has a 2xx status code
func (o *GetAlgoOrderByIDOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get algo order by Id o k response has a 3xx status code
func (o *GetAlgoOrderByIDOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get algo order by Id o k response has a 4xx status code
func (o *GetAlgoOrderByIDOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get algo order by Id o k response has a 5xx status code
func (o *GetAlgoOrderByIDOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get algo order by Id o k response a status code equal to that given
func (o *GetAlgoOrderByIDOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get algo order by Id o k response
func (o *GetAlgoOrderByIDOK) Code() int {
	return 200
}

func (o *GetAlgoOrderByIDOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /algo/orders/{algo_id}][%d] getAlgoOrderByIdOK %s", 200, payload)
}

func (o *GetAlgoOrderByIDOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /algo/orders/{algo_id}][%d] getAlgoOrderByIdOK %s", 200, payload)
}

func (o *GetAlgoOrderByIDOK) GetPayload() *models.ResponsesAlgoOrderResp {
	return o.Payload
}

func (o *GetAlgoOrderByIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAlgoOrderResp)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAlgoOrderByIDNotFound creates a GetAlgoOrderByIDNotFound with default headers values
func NewGetAlgoOrderByIDNotFound() *GetAlgoOrderByIDNotFound {
	return &GetAlgoOrderByIDNotFound{}
}

/*
GetAlgoOrderByIDNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetAlgoOrderByIDNotFound struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this get algo order by Id not found response has a 2xx status code
func (o *GetAlgoOrderByIDNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get algo order by Id not found response has a 3xx status code
func (o *GetAlgoOrderByIDNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get algo order by Id not found response has a 4xx status code
func (o *GetAlgoOrderByIDNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get algo order by Id not found response has a 5xx status code
func (o *GetAlgoOrderByIDNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get algo order by Id not found response a status code equal to that given
func (o *GetAlgoOrderByIDNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get algo order by Id not found response
func (o *GetAlgoOrderByIDNotFound) Code() int {
	return 404
}

func (o *GetAlgoOrderByIDNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /algo/orders/{algo_id}][%d] getAlgoOrderByIdNotFound %s", 404, payload)
}

func (o *GetAlgoOrderByIDNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /algo/orders/{algo_id}][%d] getAlgoOrderByIdNotFound %s", 404, payload)
}

func (o *GetAlgoOrderByIDNotFound) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *GetAlgoOrderByIDNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
