// Code generated by go-swagger; DO NOT EDIT.

package account

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

// UpdateAccountProfileUsernameReader is a Reader for the UpdateAccountProfileUsername structure.
type UpdateAccountProfileUsernameReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateAccountProfileUsernameReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateAccountProfileUsernameOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateAccountProfileUsernameBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateAccountProfileUsernameUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /account/profile/username] update-account-profile-username", response, response.Code())
	}
}

// NewUpdateAccountProfileUsernameOK creates a UpdateAccountProfileUsernameOK with default headers values
func NewUpdateAccountProfileUsernameOK() *UpdateAccountProfileUsernameOK {
	return &UpdateAccountProfileUsernameOK{}
}

/*
UpdateAccountProfileUsernameOK describes a response with status code 200, with default header values.

OK
*/
type UpdateAccountProfileUsernameOK struct {
	Payload *models.ResponsesAccountProfileResp
}

// IsSuccess returns true when this update account profile username o k response has a 2xx status code
func (o *UpdateAccountProfileUsernameOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update account profile username o k response has a 3xx status code
func (o *UpdateAccountProfileUsernameOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update account profile username o k response has a 4xx status code
func (o *UpdateAccountProfileUsernameOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update account profile username o k response has a 5xx status code
func (o *UpdateAccountProfileUsernameOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update account profile username o k response a status code equal to that given
func (o *UpdateAccountProfileUsernameOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update account profile username o k response
func (o *UpdateAccountProfileUsernameOK) Code() int {
	return 200
}

func (o *UpdateAccountProfileUsernameOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /account/profile/username][%d] updateAccountProfileUsernameOK %s", 200, payload)
}

func (o *UpdateAccountProfileUsernameOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /account/profile/username][%d] updateAccountProfileUsernameOK %s", 200, payload)
}

func (o *UpdateAccountProfileUsernameOK) GetPayload() *models.ResponsesAccountProfileResp {
	return o.Payload
}

func (o *UpdateAccountProfileUsernameOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAccountProfileResp)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAccountProfileUsernameBadRequest creates a UpdateAccountProfileUsernameBadRequest with default headers values
func NewUpdateAccountProfileUsernameBadRequest() *UpdateAccountProfileUsernameBadRequest {
	return &UpdateAccountProfileUsernameBadRequest{}
}

/*
UpdateAccountProfileUsernameBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type UpdateAccountProfileUsernameBadRequest struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this update account profile username bad request response has a 2xx status code
func (o *UpdateAccountProfileUsernameBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update account profile username bad request response has a 3xx status code
func (o *UpdateAccountProfileUsernameBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update account profile username bad request response has a 4xx status code
func (o *UpdateAccountProfileUsernameBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update account profile username bad request response has a 5xx status code
func (o *UpdateAccountProfileUsernameBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update account profile username bad request response a status code equal to that given
func (o *UpdateAccountProfileUsernameBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update account profile username bad request response
func (o *UpdateAccountProfileUsernameBadRequest) Code() int {
	return 400
}

func (o *UpdateAccountProfileUsernameBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /account/profile/username][%d] updateAccountProfileUsernameBadRequest %s", 400, payload)
}

func (o *UpdateAccountProfileUsernameBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /account/profile/username][%d] updateAccountProfileUsernameBadRequest %s", 400, payload)
}

func (o *UpdateAccountProfileUsernameBadRequest) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *UpdateAccountProfileUsernameBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAccountProfileUsernameUnauthorized creates a UpdateAccountProfileUsernameUnauthorized with default headers values
func NewUpdateAccountProfileUsernameUnauthorized() *UpdateAccountProfileUsernameUnauthorized {
	return &UpdateAccountProfileUsernameUnauthorized{}
}

/*
UpdateAccountProfileUsernameUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateAccountProfileUsernameUnauthorized struct {
	Payload *models.ResponsesAPIError
}

// IsSuccess returns true when this update account profile username unauthorized response has a 2xx status code
func (o *UpdateAccountProfileUsernameUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update account profile username unauthorized response has a 3xx status code
func (o *UpdateAccountProfileUsernameUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update account profile username unauthorized response has a 4xx status code
func (o *UpdateAccountProfileUsernameUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update account profile username unauthorized response has a 5xx status code
func (o *UpdateAccountProfileUsernameUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update account profile username unauthorized response a status code equal to that given
func (o *UpdateAccountProfileUsernameUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update account profile username unauthorized response
func (o *UpdateAccountProfileUsernameUnauthorized) Code() int {
	return 401
}

func (o *UpdateAccountProfileUsernameUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /account/profile/username][%d] updateAccountProfileUsernameUnauthorized %s", 401, payload)
}

func (o *UpdateAccountProfileUsernameUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /account/profile/username][%d] updateAccountProfileUsernameUnauthorized %s", 401, payload)
}

func (o *UpdateAccountProfileUsernameUnauthorized) GetPayload() *models.ResponsesAPIError {
	return o.Payload
}

func (o *UpdateAccountProfileUsernameUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResponsesAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
