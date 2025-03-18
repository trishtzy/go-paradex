// Code generated by go-swagger; DO NOT EDIT.

package markets

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

// GetMarketsReader is a Reader for the GetMarkets structure.
type GetMarketsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetMarketsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetMarketsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 404:
		result := NewGetMarketsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /markets] get-markets", response, response.Code())
	}
}

// NewGetMarketsOK creates a GetMarketsOK with default headers values
func NewGetMarketsOK() *GetMarketsOK {
	return &GetMarketsOK{}
}

/*
GetMarketsOK describes a response with status code 200, with default header values.

OK
*/
type GetMarketsOK struct {
	Payload *models.ResponsesGetMarkets
}

// IsSuccess returns true when this get markets o k response has a 2xx status code
func (o *GetMarketsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get markets o k response has a 3xx status code
func (o *GetMarketsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get markets o k response has a 4xx status code
func (o *GetMarketsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get markets o k response has a 5xx status code
func (o *GetMarketsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get markets o k response a status code equal to that given
func (o *GetMarketsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get markets o k response
func (o *GetMarketsOK) Code() int {
	return 200
}

func (o *GetMarketsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /markets][%d] getMarketsOK %s", 200, payload)
}

func (o *GetMarketsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /markets][%d] getMarketsOK %s", 200, payload)
}

func (o *GetMarketsOK) GetPayload() *models.ResponsesGetMarkets {
	return o.Payload
}

func (o *GetMarketsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesGetMarkets)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMarketsNotFound creates a GetMarketsNotFound with default headers values
func NewGetMarketsNotFound() *GetMarketsNotFound {
	return &GetMarketsNotFound{}
}

/*
GetMarketsNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetMarketsNotFound struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this get markets not found response has a 2xx status code
func (o *GetMarketsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get markets not found response has a 3xx status code
func (o *GetMarketsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get markets not found response has a 4xx status code
func (o *GetMarketsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get markets not found response has a 5xx status code
func (o *GetMarketsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get markets not found response a status code equal to that given
func (o *GetMarketsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get markets not found response
func (o *GetMarketsNotFound) Code() int {
	return 404
}

func (o *GetMarketsNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /markets][%d] getMarketsNotFound %s", 404, payload)
}

func (o *GetMarketsNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /markets][%d] getMarketsNotFound %s", 404, payload)
}

func (o *GetMarketsNotFound) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *GetMarketsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
