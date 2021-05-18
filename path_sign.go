/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathSign(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("roleName") + "/?$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.opReadSign},
			logical.ListOperation:   &framework.PathOperation{Callback: b.opListSign},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.opWriteSign},
		},

		HelpSynopsis:    "CSR Enrollment",
		HelpDescription: "Enroll with a CSR",
		Fields:          addIssueAndSignCommonFields(map[string]*framework.FieldSchema{}),
	}

	ret.Fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: "PEM-encoded CSR to be signed.",
		Required:    true,
	}

	return ret
}
