/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfigProfile(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "config/profiles/" + framework.GenericNameRegex("profile"),

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.opConfigProfile},
		},

		HelpSynopsis:    "CAGW Profile Configuration",
		HelpDescription: "Configures CAGW parameters for a profile (role)",
		Fields:          map[string]*framework.FieldSchema{},
	}

	ret.Fields["common_name_variable"] = &framework.FieldSchema{
		Type:    framework.TypeString,
		Default: "cn",
		Description: "The name of the subject variable to used to supply the common " +
			"name to the gateway.",
	}

	ret.Fields["ttl"] = &framework.FieldSchema{
		Type: framework.TypeDurationSecond,
		Description: "The lease duration if no specific lease duration is requested. " +
			"The lease duration controls the expiration of certificates issued by this " +
			"backend. Defaults to the value of max_ttl.",
	}

	ret.Fields["max_ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Description: "The maximum allowed lease duration",
	}

	return ret
}
