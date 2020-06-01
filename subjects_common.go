/*
 * Copyright (c) 2020 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"log"
	"strings"
)

func processSubjectVariables(subjectVar string) []SubjectVariable {
	vars := strings.Split(subjectVar, ",")

	var subjectVariables []SubjectVariable
	for _, v := range vars {
		typeValue := strings.SplitN(v, "=", 2)
		if len(typeValue) != 2 {
			log.Printf("Invalid subject variable: %s. Subject variables must use = to separate type from value.", v)
			continue
		}
		subjectVariables = append(subjectVariables, SubjectVariable{typeValue[0], typeValue[1]})
	}

	return subjectVariables
}
