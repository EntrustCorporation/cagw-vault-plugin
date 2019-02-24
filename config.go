package main

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"github.com/pkg/errors"
	"time"
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

func getProfileConfig(ctx context.Context, req *logical.Request, profileName string) (*CAGWConfigProfileEntry, error) {
	profileStorageEntry, err := req.Storage.Get(ctx, "config/profile/"+profileName)

	if err != nil {
		return nil, errors.Wrap(err, "CAGW profile configuration could not be loaded")
	}

	configProfileEntry := CAGWConfigProfileEntry{}

	// If there is a storage entry, decode it, else use defaults
	if profileStorageEntry != nil {
		err = profileStorageEntry.DecodeJSON(&configProfileEntry)
		if err != nil {
			return nil, errors.Wrap(err, "CAGW profile configuration could not be parsed")
		}
	} else {
		configProfileEntry.CommonNameVariable = "cn"
		configProfileEntry.TTL, _ = time.ParseDuration("2160h") // 90 days
		configProfileEntry.MaxTTL = 0
	}

	return &configProfileEntry, nil
}
