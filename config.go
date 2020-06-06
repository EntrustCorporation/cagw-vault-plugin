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

func getConfigEntry(ctx context.Context, req *logical.Request, caId string) (*CAGWEntry, error) {
	storageEntry, err := req.Storage.Get(ctx, "config/"+caId)

	if err != nil {
		return nil, errors.Wrap(err, "CAGW configuration could not be loaded")
	}

	configEntry := CAGWEntry{}
	err = storageEntry.DecodeJSON(&configEntry)

	if err != nil {
		return nil, errors.Wrap(err, "CAGW configuration could not be parsed")
	}

	return &configEntry, nil
}

func getProfileConfig(ctx context.Context, req *logical.Request, caId string, profileName string) (*CAGWProfileEntry, error) {
	profileStorageEntry, err := req.Storage.Get(ctx, "config/"+caId+"/profiles/"+profileName)

	if err != nil {
		return nil, errors.Wrap(err, "CAGW profile configuration could not be loaded")
	}

	configProfileEntry := CAGWProfileEntry{}

	// If there is a storage entry, decode it, else use defaults
	if profileStorageEntry != nil {
		err = profileStorageEntry.DecodeJSON(&configProfileEntry)
		if err != nil {
			return nil, errors.Wrap(err, "CAGW profile configuration could not be parsed")
		}
	} else {
		return nil, errors.Wrap(err, "CAGW profile configuration could not be found")
	}

	return &configProfileEntry, nil
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

func getTTL(data *framework.FieldData, configProfileEntry *CAGWProfileEntry) time.Duration {
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	if ttl <= 0 {
		ttl = configProfileEntry.TTL
	}
	if configProfileEntry.MaxTTL > 0 && ttl > configProfileEntry.MaxTTL {
		ttl = configProfileEntry.MaxTTL
	}
	return ttl
}
