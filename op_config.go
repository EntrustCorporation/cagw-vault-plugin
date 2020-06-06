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

func (b *backend) opConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	caId := data.Get("caId").(string)

	certPem := data.Get("pem_bundle").(string)
	url := data.Get("url").(string)
	caCertPem := data.Get("cacerts").(string)

	if len(certPem) == 0 {
		return logical.ErrorResponse("must provide PEM encoded certificate"), nil
	}
	if len(caId) == 0 {
		return logical.ErrorResponse("must provide CA identifier"), nil
	}
	if len(url) == 0 {
		return logical.ErrorResponse("must provide gateway URL"), nil
	}
	if len(caCertPem) == 0 {
		return logical.ErrorResponse("must provide gateway CA certificate"), nil
	}

	entry := &CAGWEntry{
		certPem,
		url,
		caCertPem,
	}

	profiles, err := entry.Profiles(ctx, req, data)
	if err != nil {
		return logical.ErrorResponse("error fetching profile configurations from CAGW"), err
	}

	caAndProfiles := CAGWEntryCAGWProfileIDs{
		*entry,
		profiles,
	}

	storageEntry, err := logical.StorageEntryJSON("config/"+caId, caAndProfiles)

	if err != nil {
		return logical.ErrorResponse("error creating config storage entry"), err
	}

	err = req.Storage.Put(ctx, storageEntry)
	if err != nil {
		return logical.ErrorResponse("could not store configuration"), err
	}

	respData := map[string]interface{}{
		"Message": "Configuration successful",
		"CaId":    caId,
		"URL":     url,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) opReadConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	caId := data.Get("caId").(string)

	storageEntry, err := req.Storage.Get(ctx, "config/"+caId)
	if err != nil {
		return logical.ErrorResponse("could not read configuration"), err
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
