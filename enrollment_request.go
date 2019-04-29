/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

type EnrollmentRequest struct {
	ProfileId                         string                    `json:"profileId"`
	RequiredFormat                    RequiredFormat            `json:"requiredFormat"`
	CSR                               string                    `json:"csr"`
	SubjectVariables                  []SubjectVariable         `json:"subjectVariables"`
	SubjectAltNames                   []SubjectAltName          `json:"subjectAltNames"`
	OptionalCertificateRequestDetails CertificateRequestDetails `json:"optionalCertificateRequestDetails"`
}

type RequiredFormat struct {
	Format     string      `json:"format"`
	Protection *Protection `json:"protection"`
}

type SubjectVariable struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Protection struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type SubjectAltName struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type CertificateRequestDetails struct {
	ValidityPeriod string `json:"validityPeriod"`
}
