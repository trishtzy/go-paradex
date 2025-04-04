// Code generated by go-swagger; DO NOT EDIT.

package algos

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetOpenAlgoOrdersParams creates a new GetOpenAlgoOrdersParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetOpenAlgoOrdersParams() *GetOpenAlgoOrdersParams {
	return &GetOpenAlgoOrdersParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetOpenAlgoOrdersParamsWithTimeout creates a new GetOpenAlgoOrdersParams object
// with the ability to set a timeout on a request.
func NewGetOpenAlgoOrdersParamsWithTimeout(timeout time.Duration) *GetOpenAlgoOrdersParams {
	return &GetOpenAlgoOrdersParams{
		timeout: timeout,
	}
}

// NewGetOpenAlgoOrdersParamsWithContext creates a new GetOpenAlgoOrdersParams object
// with the ability to set a context for a request.
func NewGetOpenAlgoOrdersParamsWithContext(ctx context.Context) *GetOpenAlgoOrdersParams {
	return &GetOpenAlgoOrdersParams{
		Context: ctx,
	}
}

// NewGetOpenAlgoOrdersParamsWithHTTPClient creates a new GetOpenAlgoOrdersParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetOpenAlgoOrdersParamsWithHTTPClient(client *http.Client) *GetOpenAlgoOrdersParams {
	return &GetOpenAlgoOrdersParams{
		HTTPClient: client,
	}
}

/*
GetOpenAlgoOrdersParams contains all the parameters to send to the API endpoint

	for the get open algo orders operation.

	Typically these are written to a http.Request.
*/
type GetOpenAlgoOrdersParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get open algo orders params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetOpenAlgoOrdersParams) WithDefaults() *GetOpenAlgoOrdersParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get open algo orders params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetOpenAlgoOrdersParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get open algo orders params
func (o *GetOpenAlgoOrdersParams) WithTimeout(timeout time.Duration) *GetOpenAlgoOrdersParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get open algo orders params
func (o *GetOpenAlgoOrdersParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get open algo orders params
func (o *GetOpenAlgoOrdersParams) WithContext(ctx context.Context) *GetOpenAlgoOrdersParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get open algo orders params
func (o *GetOpenAlgoOrdersParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get open algo orders params
func (o *GetOpenAlgoOrdersParams) WithHTTPClient(client *http.Client) *GetOpenAlgoOrdersParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get open algo orders params
func (o *GetOpenAlgoOrdersParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetOpenAlgoOrdersParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
