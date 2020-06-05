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
		Pattern: "config/" + framework.GenericNameRegex("caId") + "/profiles/" + framework.GenericNameRegex("profile"),

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.opReadConfigProfile},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.opConfigProfile},
		},

		HelpSynopsis:    "CAGW Profile Configuration",
		HelpDescription: "Configures CAGW parameters for a profile (role)",
		Fields: map[string]*framework.FieldSchema{
			"profile": {
				Type:        framework.TypeString,
				Description: "Specifies the certificates profile.",
			},
		},
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

	ret.Fields["caId"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `The CA Id as defined in CAGW configuration.`,
	}

	return ret
}
