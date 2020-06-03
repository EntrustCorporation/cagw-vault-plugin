/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import "github.com/hashicorp/vault/logical/framework"

func addIssueAndSignCommonFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	fields["exclude_cn_from_sans"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: false,
		Description: `If true, the Common Name will not be
included in DNS or Email Subject Alternate Names.
Defaults to false (CN is included).`,
	}

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

	return fields
}
