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

func opListCerts(ctx context.Context, req *logical.Request, data *framework.FieldData, path string) (response *logical.Response, retErr error) {

	roleName := data.Get("roleName").(string)

	entries, err := req.Storage.List(ctx, path+"/"+roleName+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func opReadCert(ctx context.Context, req *logical.Request, data *framework.FieldData, path string) (*logical.Response, error) {

	roleName := data.Get("roleName").(string)
	serial := data.Get("serial").(string)

	storageEntry, err := req.Storage.Get(ctx, path+"/"+roleName+"/"+serial)
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
