/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/pkg/errors"
)

func getConfigEntry(ctx context.Context, req *logical.Request) (*CAGWConfigEntry, error) {
	storageEntry, err := req.Storage.Get(ctx, "config/cagw")

	if err != nil {
		return nil, errors.Wrap(err, "CAGW configuration could not be loaded")
	}

	configEntry := CAGWConfigEntry{}
	err = storageEntry.DecodeJSON(&configEntry)

	if err != nil {
		return nil, errors.Wrap(err, "CAGW configuration could not be parsed")
	}

	return &configEntry, nil
}

func getProfileConfig(ctx context.Context, req *logical.Request, profileName string) (*CAGWProfileEntry, error) {
	profileStorageEntry, err := req.Storage.Get(ctx, "config/profile/"+profileName)

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
