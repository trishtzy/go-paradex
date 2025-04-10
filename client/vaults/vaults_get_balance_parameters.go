// Code generated by go-swagger; DO NOT EDIT.

package vaults

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

// NewVaultsGetBalanceParams creates a new VaultsGetBalanceParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewVaultsGetBalanceParams() *VaultsGetBalanceParams {
	return &VaultsGetBalanceParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewVaultsGetBalanceParamsWithTimeout creates a new VaultsGetBalanceParams object
// with the ability to set a timeout on a request.
func NewVaultsGetBalanceParamsWithTimeout(timeout time.Duration) *VaultsGetBalanceParams {
	return &VaultsGetBalanceParams{
		timeout: timeout,
	}
}

// NewVaultsGetBalanceParamsWithContext creates a new VaultsGetBalanceParams object
// with the ability to set a context for a request.
func NewVaultsGetBalanceParamsWithContext(ctx context.Context) *VaultsGetBalanceParams {
	return &VaultsGetBalanceParams{
		Context: ctx,
	}
}

// NewVaultsGetBalanceParamsWithHTTPClient creates a new VaultsGetBalanceParams object
// with the ability to set a custom HTTPClient for a request.
func NewVaultsGetBalanceParamsWithHTTPClient(client *http.Client) *VaultsGetBalanceParams {
	return &VaultsGetBalanceParams{
		HTTPClient: client,
	}
}

/*
VaultsGetBalanceParams contains all the parameters to send to the API endpoint

	for the vaults get balance operation.

	Typically these are written to a http.Request.
*/
type VaultsGetBalanceParams struct {

	/* Address.

	   Vault Address
	*/
	Address string

	/* Strategy.

	   Vault Strategy Address
	*/
	Strategy *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the vaults get balance params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *VaultsGetBalanceParams) WithDefaults() *VaultsGetBalanceParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the vaults get balance params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *VaultsGetBalanceParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the vaults get balance params
func (o *VaultsGetBalanceParams) WithTimeout(timeout time.Duration) *VaultsGetBalanceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the vaults get balance params
func (o *VaultsGetBalanceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the vaults get balance params
func (o *VaultsGetBalanceParams) WithContext(ctx context.Context) *VaultsGetBalanceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the vaults get balance params
func (o *VaultsGetBalanceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the vaults get balance params
func (o *VaultsGetBalanceParams) WithHTTPClient(client *http.Client) *VaultsGetBalanceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the vaults get balance params
func (o *VaultsGetBalanceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAddress adds the address to the vaults get balance params
func (o *VaultsGetBalanceParams) WithAddress(address string) *VaultsGetBalanceParams {
	o.SetAddress(address)
	return o
}

// SetAddress adds the address to the vaults get balance params
func (o *VaultsGetBalanceParams) SetAddress(address string) {
	o.Address = address
}

// WithStrategy adds the strategy to the vaults get balance params
func (o *VaultsGetBalanceParams) WithStrategy(strategy *string) *VaultsGetBalanceParams {
	o.SetStrategy(strategy)
	return o
}

// SetStrategy adds the strategy to the vaults get balance params
func (o *VaultsGetBalanceParams) SetStrategy(strategy *string) {
	o.Strategy = strategy
}

// WriteToRequest writes these params to a swagger request
func (o *VaultsGetBalanceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param address
	qrAddress := o.Address
	qAddress := qrAddress
	if qAddress != "" {

		if err := r.SetQueryParam("address", qAddress); err != nil {
			return err
		}
	}

	if o.Strategy != nil {

		// query param strategy
		var qrStrategy string

		if o.Strategy != nil {
			qrStrategy = *o.Strategy
		}
		qStrategy := qrStrategy
		if qStrategy != "" {

			if err := r.SetQueryParam("strategy", qStrategy); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
