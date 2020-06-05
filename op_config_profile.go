/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) opConfigProfile(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	caId := data.Get("caId").(string)
	id := data.Get("profile").(string)
	profileID := CAGWProfileID{id}
	entry, err := profileID.Entry(ctx, req, data)

	if err != nil {
		return logical.ErrorResponse("Error retrieving the profile properties from CAGW"), err
	}

	storageEntry, err := logical.StorageEntryJSON("config/"+caId+"/profiles/"+id, entry)

	if err != nil {
		return logical.ErrorResponse("error creating config storage entry"), err
	}

	err = req.Storage.Put(ctx, storageEntry)
	if err != nil {
		return logical.ErrorResponse("could not store configuration"), err
	}

	respData := map[string]interface{}{
		"Message":                       "Configuration successful",
		"Profile ID":                    entry.Id,
		"Profile Name":                  entry.Name,
		"Subject Variable Requirements": entry.SubjectVariableRequirements,
		"Subject Alt Name Requirements": entry.SubjectAltNameRequirements,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) opReadConfigProfile(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	caId := data.Get("caId").(string)
	profileID := data.Get("profile").(string)

	if len(profileID) == 0 {
		return logical.ErrorResponse("missing the profile ID"), nil
	}

	storageEntry, err := req.Storage.Get(ctx, "config/"+caId+"/profiles/"+profileID)
	if err != nil {
		return logical.ErrorResponse("could not read configuration"), err
	}
	if storageEntry == nil {
		return logical.ErrorResponse("could not find configuration"), nil
	}

	var rawData map[string]interface{}
	err = storageEntry.DecodeJSON(&rawData)

	if err != nil {
		return logical.ErrorResponse("json decoding failed"), err
	}

	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}
