package main

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"time"
)

func (b *backend) opConfigProfile(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	maxTtl := time.Duration(data.Get("max_ttl").(int)) * time.Second
	commonNameVar := data.Get("common_name_variable").(string)

	profileId := req.GetString("profile")

	entry := &CAGWConfigProfileEntry{
		commonNameVar,
		ttl,
		maxTtl,
	}

	storageEntry, err := logical.StorageEntryJSON("config/profile/"+profileId, entry)

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
