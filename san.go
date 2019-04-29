/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"github.com/hashicorp/vault/logical/framework"
	"strings"
)

func processDNSAndRFC822Names(subjectAltNAmes []SubjectAltName, commonName string, names []string) []SubjectAltName {
	if strings.Contains(commonName, "@") {
		subjectAltNAmes = append(subjectAltNAmes, SubjectAltName{Type: "rfc822Name", Value: commonName})
	} else {
		subjectAltNAmes = append(subjectAltNAmes, SubjectAltName{Type: "dNSName", Value: commonName})
	}
	if names != nil && len(names) > 0 {
		for _, name := range names {
			if strings.Contains(name, "@") {
				subjectAltNAmes = append(subjectAltNAmes, SubjectAltName{Type: "rfc822Name", Value: name})
			} else {
				subjectAltNAmes = append(subjectAltNAmes, SubjectAltName{Type: "dNSName", Value: name})
			}
		}
	}
	return subjectAltNAmes
}

func processAltNames(subjectAltNames []SubjectAltName, names []string, nameType string) []SubjectAltName {
	if names != nil && len(names) > 0 {
		for _, name := range names {
			subjectAltNames = append(subjectAltNames, SubjectAltName{Type: nameType, Value: name})
		}
	}
	return subjectAltNames
}

func processAllAltNames(data *framework.FieldData, commonName string) []SubjectAltName {
	subjectAltNames := data.Get("alt_names").([]string)
	ipAltNames := data.Get("ip_sans").([]string)
	uriAltNames := data.Get("uri_sans").([]string)

	var altNames []SubjectAltName
	altNames = processDNSAndRFC822Names(altNames, commonName, subjectAltNames)
	altNames = processAltNames(altNames, ipAltNames, "iPAddress")
	altNames = processAltNames(altNames, uriAltNames, "uniformResourceIdentifier")

	return altNames
}
