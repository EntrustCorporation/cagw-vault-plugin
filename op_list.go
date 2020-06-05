/*
 * Copyright (c) 2020 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) opList(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {

	serial := data.Get("serial").(string)

	if len(serial) > 0 {
		return b.opGet(ctx, req, data)
	}

	caId := data.Get("caId").(string)
	entries, err := req.Storage.List(ctx, "certs/"+caId+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) opGet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	caId := data.Get("caId").(string)
	serial := data.Get("serial").(string)

	storageEntry, err := req.Storage.Get(ctx, "certs/"+caId+"/"+serial)
	if err != nil {
		return logical.ErrorResponse("could not read certificate with the serial number: " + serial), err
	}
	if storageEntry == nil {
		return logical.ErrorResponse("could not find certificate with the serial number: " + serial), nil
	}

	var rawData map[string]interface{}
	err = storageEntry.DecodeJSON(&rawData)

	if err != nil {
		return logical.ErrorResponse("json decoding failed for certificate: " + serial), err
	}

	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}
