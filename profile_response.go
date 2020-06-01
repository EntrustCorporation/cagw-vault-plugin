/*
 * Copyright (c) 2020 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

type ProfileResponse struct {
	Profile Profile `json:"profile"`
	Message Message `json:"message"`
}

type Profile struct {
	Id                          string                       `json:"id"`
	Name                        string                       `json:"name"`
	SubjectVariableRequirements []SubjectVariableRequirement `json:"subjectVariableRequirements"`
	SubjectAltNameRequirements  []SubjectAltNameRequirement  `json:"subjectAltNameRequirements"`
}

type SubjectVariableRequirement struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

type SubjectAltNameRequirement struct {
	Type     string `json:"type"`
	Required bool   `json:"required"`
}
