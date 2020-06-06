/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
)

func getConfigCA(ctx context.Context, req *logical.Request, caId string) (*CAGWConfigCA, error) {
	storageEntry, err := req.Storage.Get(ctx, "config/"+caId)

	if err != nil {
		return nil, errors.Wrap(err, "CAGW configuration could not be loaded")
	}

	configCa := CAGWConfigCA{}
	err = storageEntry.DecodeJSON(&configCa)

	if err != nil {
		return nil, errors.Wrap(err, "CAGW configuration could not be parsed")
	}

	return &configCa, nil
}

func getConfigProfile(ctx context.Context, req *logical.Request, caId string, profileId string) (*CAGWConfigProfile, error) {
	profileStorageEntry, err := req.Storage.Get(ctx, "config/"+caId+"/profiles/"+profileId)

	if err != nil {
		return nil, errors.Wrap(err, "CAGW profile configuration could not be loaded")
	}

	configProfile := CAGWConfigProfile{}

	// If there is a storage entry, decode it, else use defaults
	if profileStorageEntry != nil {
		err = profileStorageEntry.DecodeJSON(&configProfile)
		if err != nil {
			return nil, errors.Wrap(err, "CAGW profile configuration could not be parsed")
		}
	} else {
		return nil, errors.Wrap(err, "CAGW profile configuration could not be found")
	}

	return &configProfile, nil
}

func getFormat(data *framework.FieldData) (*string, error) {
	format := data.Get("format").(string)
	if len(format) <= 0 {
		format = "pem"
	}
	if format != "pem" && format != "pem_bundle" && format != "der" {
		return nil, errors.New(fmt.Sprintf("Invalid format specified: %s", format))
	}

	return &format, nil
}

func getTTL(data *framework.FieldData, configProfile *CAGWConfigProfile) time.Duration {
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	if ttl <= 0 {
		ttl = configProfile.TTL
	}
	if configProfile.MaxTTL > 0 && ttl > configProfile.MaxTTL {
		ttl = configProfile.MaxTTL
	}
	return ttl
}
