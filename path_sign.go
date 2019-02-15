package main

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathSign(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("profile"),

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.opSign},
		},


		HelpSynopsis:    "CSR Enrollment",
		HelpDescription: "Enroll with a CSR",
		Fields: map[string]*framework.FieldSchema{},
	}

	ret.Fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `PEM-format CSR to be signed.`,
	}

	return ret
}


