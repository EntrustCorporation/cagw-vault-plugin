/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"context"
	"fmt"
	"github.com/pkg/errors"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) opWriteConfigRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("roleName").(string)
	caId := data.Get("ca_id").(string)
	profileId := data.Get("profile_id").(string)
	certPem := data.Get("pem_bundle").(string)
	url := data.Get("url").(string)
	caCertPem := data.Get("cacerts").(string)

	b.Logger().Info(fmt.Sprintf(`
Configuring new CA role configuration
role name:  %s
ca id:      %s
profile id: %s
url:        %s
`,
		roleName, caId, profileId, url))

	if len(roleName) == 0 {
		return logical.ErrorResponse("must provide name for role configuration"), nil
	}
	if len(certPem) == 0 {
		return logical.ErrorResponse("must provide PEM encoded certificate"), nil
	}
	if len(caId) == 0 {
		caId = roleName
	}
	if len(url) == 0 {
		return logical.ErrorResponse("must provide gateway URL"), nil
	}
	if len(caCertPem) == 0 {
		return logical.ErrorResponse("must provide gateway CA certificate"), nil
	}

	configCa := &CAGWConfigRole{
		certPem,
		url,
		caCertPem,
		caId,
		profileId,
	}

	profiles, err := configCa.ProfileIDs(ctx, req, data, caId)
	if err != nil {
		return logical.ErrorResponse("error fetching profile configurations from CAGW: " + err.Error()), err
	}

	caAndProfiles := CAGWConfigCAConfigProfileIDs{
		*configCa,
		profiles,
	}

	if len(profileId) > 0 {
		profile, err := findProfile(profiles, profileId)
		if err != nil {
			return logical.ErrorResponse("Profile with ID " + profileId + " not found for CA " + caId), nil
		}
		caAndProfiles.Profiles = []CAGWConfigProfileID{*profile}
	} else {
		caAndProfiles.Profiles = profiles
	}

	storageEntry, err := logical.StorageEntryJSON("config/"+roleName, caAndProfiles)

	if err != nil {
		return logical.ErrorResponse("error creating config storage entry: " + err.Error()), err
	}

	err = req.Storage.Put(ctx, storageEntry)
	if err != nil {
		return logical.ErrorResponse("could not store configuration: " + err.Error()), err
	}

	respData := map[string]interface{}{
		"Message":  "Configuration successful",
		"RoleName": roleName,
		"CaId":     caId,
		"URL":      url,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) opReadConfigRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("roleName").(string)

	storageEntry, err := req.Storage.Get(ctx, "config/"+roleName)
	if err != nil {
		return logical.ErrorResponse("could not read configuration: " + err.Error()), err
	}

	var rawData map[string]interface{}
	err = storageEntry.DecodeJSON(&rawData)

	if err != nil {
		return logical.ErrorResponse("json decoding failed: " + err.Error()), err
	}

	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}

func findProfile(profiles []CAGWConfigProfileID, profileId string) (*CAGWConfigProfileID, error) {
	for _, v := range profiles {
		if v.Id == profileId {
			return &v, nil
		}
	}
	return nil, errors.New("Could not find profile")
}
