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

func getConfigRole(ctx context.Context, req *logical.Request, roleName string) (*CAGWConfigRole, error) {
	storageEntry, err := req.Storage.Get(ctx, "config/"+roleName)

	if err != nil {
		return nil, errors.Wrapf(err, "config/%s configuration could not be loaded", roleName)
	}

	configRole := CAGWConfigRole{}
	if storageEntry != nil {
		err = storageEntry.DecodeJSON(&configRole)
		if err != nil {
			return nil, errors.Wrapf(err, "config/%s configuration could not be parsed", roleName)
		}
	} else {
		return nil, errors.Errorf("config/%s could not be found", roleName)
	}
	return &configRole, nil
}

func getConfigProfile(ctx context.Context, req *logical.Request, roleName string, profileId string) (*CAGWConfigProfile, error) {
	profileStorageEntry, err := req.Storage.Get(ctx, "config/"+roleName+"/profiles/"+profileId)

	if err != nil {
		return nil, errors.Wrapf(err, "config/%s/profiles/%s could not be loaded", roleName, profileId)
	}

	configProfile := CAGWConfigProfile{}

	// If there is a storage entry, decode it, else use defaults
	if profileStorageEntry != nil {
		err = profileStorageEntry.DecodeJSON(&configProfile)
		if err != nil {
			return nil, errors.Wrapf(err, "config/%s/profiles/%s could not be parsed", roleName, profileId)
		}
	} else {
		return nil, errors.Errorf("config/%s/profiles/%s could not be found", roleName, profileId)
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
