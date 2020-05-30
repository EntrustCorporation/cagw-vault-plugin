/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"context"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) opConfigProfile(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	maxTtl := time.Duration(data.Get("max_ttl").(int)) * time.Second
	commonNameVar := data.Get("common_name_variable").(string)

	profileID := data.Get("profile").(string)

	entry := &CAGWConfigProfileEntry{
		commonNameVar,
		ttl,
		maxTtl,
	}

	storageEntry, err := logical.StorageEntryJSON("config/profile/"+profileID, entry)

	if err != nil {
		return logical.ErrorResponse("error creating config storage entry"), err
	}

	err = req.Storage.Put(ctx, storageEntry)
	if err != nil {
		return logical.ErrorResponse("could not store configuration"), err
	}

	respData := map[string]interface{}{
		"Message":            "Configuration successful",
		"CommonVariableName": commonNameVar,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) opReadConfigProfile(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	profileID := data.Get("profile").(string)

	if len(profileID) == 0 {
		return logical.ErrorResponse("missing the profile ID"), nil
	}

	storageEntry, err := req.Storage.Get(ctx, "config/profile/"+profileID)
	if err != nil {
		return logical.ErrorResponse("could not read configuration"), err
	}
	if storageEntry == nil {
		return logical.ErrorResponse("could not find configuration"), nil
	}

	var rawData map[string]interface{}
	error := storageEntry.DecodeJSON(&rawData)

	if error != nil {
		return logical.ErrorResponse("json decoding failed"), err
	}

	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}
