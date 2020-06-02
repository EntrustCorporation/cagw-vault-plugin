/*
 * Copyright (c) 2020 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"fmt"

	"gopkg.in/ldap.v2"
)

func processSubjectVariables(subjectVars string) ([]SubjectVariable, error) {
	dn, err := ldap.ParseDN(subjectVars)

	if err != nil {
		return nil, fmt.Errorf("error parsing the subject variables: %s", err)
	}

	var subjectVariables []SubjectVariable
	for _, v := range (*dn).RDNs {
		var attributes []*ldap.AttributeTypeAndValue = v.Attributes
		for _, a := range attributes {
			subjectVariables = append(subjectVariables, SubjectVariable{a.Type, a.Value})
		}
	}

	return subjectVariables, nil
}
