/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathIssue(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "issue/" + framework.GenericNameRegex("caId"),

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.opList},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.opIssue},
		},

		HelpSynopsis:    "Certificate Enrollment",
		HelpDescription: "Enroll for certificate.",
		Fields:          addIssueAndSignCommonFields(map[string]*framework.FieldSchema{}),
	}

	return ret
}
