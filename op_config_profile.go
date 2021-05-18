/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) opWriteConfigProfile(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("roleName").(string)

	id := getProfileId(data)

	profileId := CAGWConfigProfileID{id, ""}
	profile, err := profileId.Profile(ctx, req, data)

	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Error retrieving the profile properties from CAGW: %s", err)), err
	}

	storageEntry, err := logical.StorageEntryJSON("config/"+roleName+"/profiles/"+profile.Id, profile)

	if err != nil {
		return logical.ErrorResponse("error creating config storage entry for profile"), err
	}

	err = req.Storage.Put(ctx, storageEntry)
	if err != nil {
		return logical.ErrorResponse("could not store configuration"), err
	}

	respData := map[string]interface{}{
		"Message":                       "Configuration successful",
		"Profile ID":                    profile.Id,
		"Profile Name":                  profile.Name,
		"Subject Variable Requirements": profile.SubjectVariableRequirements,
		"Subject Alt Name Requirements": profile.SubjectAltNameRequirements,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) opReadConfigProfile(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("roleName").(string)
	profileId := getProfileId(data)

	configCa, err := getConfigRole(ctx, req, roleName)
	if err != nil {
		return logical.ErrorResponse("invalid CAGW role configuration"), err
	}

	if len(profileId) <= 0 {
		profileId = configCa.ProfileId
		if len(profileId) <= 0 {
			return logical.ErrorResponse("missing the profile ID"), nil
		}
	}

	storageEntry, err := req.Storage.Get(ctx, "config/"+roleName+"/profiles/"+profileId)
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

func getProfileId(data *framework.FieldData) string {
	idInt, flag := data.GetOk("profile")
	var id string
	if !flag {
		id = ""
	} else {
		id = idInt.(string)
	}
	return id
}
