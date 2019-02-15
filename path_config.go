package main

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfig(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "config",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.opConfig},
		},

		HelpSynopsis:    "CAGW Configuration",
		HelpDescription: "Configures CAGW parameters including client cert and key.",
		Fields: map[string]*framework.FieldSchema{},
	}

	ret.Fields["cert"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `PEM encoded certificate`,
	}

	ret.Fields["key"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `PEM encoded private key`,
	}

	ret.Fields["caId"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `CA identifier`,
	}

	ret.Fields["url"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `URL for CAGW including base context path`,
	}

	return ret
}

