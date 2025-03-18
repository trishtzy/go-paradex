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

// GetFundingDataReader is a Reader for the GetFundingData structure.
type GetFundingDataReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetFundingDataReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetFundingDataOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetFundingDataBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /funding/data] get-funding-data", response, response.Code())
	}
}

// NewGetFundingDataOK creates a GetFundingDataOK with default headers values
func NewGetFundingDataOK() *GetFundingDataOK {
	return &GetFundingDataOK{}
}

/*
GetFundingDataOK describes a response with status code 200, with default header values.

OK
*/
type GetFundingDataOK struct {
	Payload *models.ResponsesFundingDataResp
}

// IsSuccess returns true when this get funding data o k response has a 2xx status code
func (o *GetFundingDataOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get funding data o k response has a 3xx status code
func (o *GetFundingDataOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get funding data o k response has a 4xx status code
func (o *GetFundingDataOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get funding data o k response has a 5xx status code
func (o *GetFundingDataOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get funding data o k response a status code equal to that given
func (o *GetFundingDataOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get funding data o k response
func (o *GetFundingDataOK) Code() int {
	return 200
}

func (o *GetFundingDataOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /funding/data][%d] getFundingDataOK %s", 200, payload)
}

func (o *GetFundingDataOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /funding/data][%d] getFundingDataOK %s", 200, payload)
}

func (o *GetFundingDataOK) GetPayload() *models.ResponsesFundingDataResp {
	return o.Payload
}

func (o *GetFundingDataOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesFundingDataResp)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFundingDataBadRequest creates a GetFundingDataBadRequest with default headers values
func NewGetFundingDataBadRequest() *GetFundingDataBadRequest {
	return &GetFundingDataBadRequest{}
}

/*
GetFundingDataBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetFundingDataBadRequest struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this get funding data bad request response has a 2xx status code
func (o *GetFundingDataBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get funding data bad request response has a 3xx status code
func (o *GetFundingDataBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get funding data bad request response has a 4xx status code
func (o *GetFundingDataBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get funding data bad request response has a 5xx status code
func (o *GetFundingDataBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get funding data bad request response a status code equal to that given
func (o *GetFundingDataBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get funding data bad request response
func (o *GetFundingDataBadRequest) Code() int {
	return 400
}

func (o *GetFundingDataBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /funding/data][%d] getFundingDataBadRequest %s", 400, payload)
}

func (o *GetFundingDataBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /funding/data][%d] getFundingDataBadRequest %s", 400, payload)
}

func (o *GetFundingDataBadRequest) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *GetFundingDataBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
