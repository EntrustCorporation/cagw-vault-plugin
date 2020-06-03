/*
 * Copyright (c) 2020 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"fmt"
	"strings"

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

func processSubjectAltNames(subjectAltNames []string) ([]SubjectAltName, error) {
	var altNames []SubjectAltName

	for _, tv := range subjectAltNames {
		out := strings.SplitN(tv, "=", 2)
		if len(out) != 2 {
			return nil, fmt.Errorf("error parsing the subject alt names: %s", subjectAltNames)
		}
		altNames = append(altNames, SubjectAltName{Type: out[0], Value: out[1]})
	}

	return altNames, nil
}
