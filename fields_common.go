/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import "github.com/hashicorp/vault/logical/framework"

func addIssueAndSignCommonFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {

	fields["format"] = &framework.FieldSchema{
		Type:    framework.TypeString,
		Default: "pem",
		Description: `Format for returned data. Can be "pem", "der",
or "pem_bundle". If "pem_bundle" any private
key and issuing cert will be appended to the
certificate pem. Defaults to "pem".`,
	}

	fields["subject_variables"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `The requested subject variables; this is a comma separated list
of subject variable types and values. The types should match the profile's
configuration.`,
	}

	fields["alt_names"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `The requested Subject Alternative Names (SAN), if any,
in a comma-delimited list. Each SAN must have the type and value separated by the
equal sign.`,
	}

	fields["ttl"] = &framework.FieldSchema{
		Type: framework.TypeDurationSecond,
		Description: `The requested Time To Live for the certificate;
sets the expiration date. If not specified
the role default, backend default, or system
default TTL is used, in that order. Cannot
be larger than the role max TTL.`,
	}

	fields["profile"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `The CAGW profile to use for enrollment`,
	}

	fields["serial"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `The certificate serial number to use for fetching
		the certificate and any private key.`,
	}

	fields["roleName"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `The name of the CAGW configuration.`,
	}

	return fields
}

func addConfigProfileCommonFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {

	fields["ttl"] = &framework.FieldSchema{
		Type: framework.TypeDurationSecond,
		Description: "The lease duration if no specific lease duration is requested. " +
			"The lease duration controls the expiration of certificates issued by this " +
			"backend. Defaults to the value of max_ttl.",
	}

	fields["max_ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Description: "The maximum allowed lease duration",
	}

	fields["roleName"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `The name of the configured CAGW role`,
	}

	return fields
}
