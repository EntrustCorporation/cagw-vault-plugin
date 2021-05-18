/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfigProfiles(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "config/" + framework.GenericNameRegex("roleName") + "/profiles/" + framework.GenericNameRegex("profile"),

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.opReadConfigProfile},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.opWriteConfigProfile},
		},

		HelpSynopsis:    "CAGW Profile Configuration",
		HelpDescription: "Configures CAGW parameters for a profile",
		Fields:          addConfigProfileCommonFields(map[string]*framework.FieldSchema{}),
	}

	ret.Fields["profile"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Specifies the certificates profile.",
	}

	return ret
}

func pathConfigProfile(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "config/" + framework.GenericNameRegex("roleName") + "/profile",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.opReadConfigProfile},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.opWriteConfigProfile},
		},

		HelpSynopsis:    "CAGW Profile Configuration",
		HelpDescription: "Configures CAGW parameters for a profile",
		Fields:          addConfigProfileCommonFields(map[string]*framework.FieldSchema{}),
	}

	return ret
}
