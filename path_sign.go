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
		Fields:          map[string]*framework.FieldSchema{},
	}

	ret.Fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: "PEM-encoded CSR to be signed.",
		Required:    true,
	}

	ret.Fields["common_name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: "",
		Required:    true,
	}

	ret.Fields["format"] = &framework.FieldSchema{
		Type:    framework.TypeString,
		Default: "pem",
		Description: "Specifies the format for the returned data. Can be pem, der, or pem_bundle. " +
			"If der, the output is base64 encoded. If pem_bundle, the certificate field will contain " +
			"the certificate and CA certificate concatenated.",
	}

	ret.Fields["alt_names"] = &framework.FieldSchema{
		Type:    framework.TypeCommaStringSlice,
		Default: "",
		Description: "Specifies the requested Subject Alternative Names in a comma delimited list. " +
			"These can be host names or email addresses; they will be parsed into their respective fields.",
	}

	return ret
}
