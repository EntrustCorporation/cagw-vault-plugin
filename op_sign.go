/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) opWriteSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("roleName").(string)
	if len(roleName) <= 0 {
		return logical.ErrorResponse("a role name must be specified"), nil
	}

	var err error

	format, err := getFormat(data)
	if err != nil {
		return logical.ErrorResponse("%v", err), err
	}

	// Comma separated list of subject variables: cn=Test,o=Entrust,c=CA
	subjectVariables := data.Get("subject_variables").(string)
	var subjectVars []SubjectVariable
	if len(subjectVariables) > 0 {
		subjectVars, err = processSubjectVariables(subjectVariables)
		if err != nil {
			return logical.ErrorResponse("Failed parsing the subject_variables"), err
		}
	}

	altNames := data.Get("alt_names").([]string)
	var subjAltNames []SubjectAltName
	if len(altNames) > 0 {
		subjAltNames, err = processSubjectAltNames(altNames)
		if err != nil {
			return logical.ErrorResponse("Failed parsing the subject alt names: %s", altNames), err
		}
	}

	csrPem := data.Get("csr").(string)
	// Just decode a single block, omit any subsequent blocks
	csrBlock, _ := pem.Decode([]byte(csrPem))
	if csrBlock == nil {
		return logical.ErrorResponse("CSR could not be decoded"), nil
	}

	csrBase64 := base64.StdEncoding.EncodeToString(csrBlock.Bytes)

	configRole, err := getConfigRole(ctx, req, roleName)
	if err != nil {
		return logical.ErrorResponse("Error fetching config"), err
	}

	caId := configRole.CAId
	if len(caId) <= 0 {
		caId = roleName
	}

	profileId := configRole.ProfileId
	if len(profileId) <= 0 {
		profileId = data.Get("profile").(string)
		if len(profileId) <= 0 {
			return logical.ErrorResponse("a profile must be specified for this CA role configuration"), nil
		}
	}

	configProfile, err := getConfigProfile(ctx, req, roleName, profileId)
	if err != nil {
		return logical.ErrorResponse("Could not get profile configuration for profile " + profileId + ": " + err.Error()), err
	}

	ttl := getTTL(data, configProfile)

	// Construct enrollment request
	enrollmentRequest := EnrollmentRequest{
		ProfileId: profileId,
		RequiredFormat: RequiredFormat{
			Format:     "X509",
			Protection: nil,
		},
		CSR:              csrBase64,
		SubjectVariables: subjectVars,
		SubjectAltNames:  subjAltNames,
		OptionalCertificateRequestDetails: CertificateRequestDetails{
			ValidityPeriod: fmt.Sprintf("PT%dM", int64(ttl.Minutes())),
		},
	}

	body, err := json.Marshal(enrollmentRequest)
	if err != nil {
		return logical.ErrorResponse("Error constructing enrollment request: %v", err), err
	}

	if b.Logger().IsDebug() {
		b.Logger().Debug(fmt.Sprintf("Enrollment request body: %v", string(body)))
	}

	tlsClientConfig, err := getTLSConfig(ctx, req, configRole)
	if err != nil {
		return logical.ErrorResponse("Error retrieving TLS configuration: %v", err), err
	}

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsClientConfig,
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Post(configRole.URL+"/v1/certificate-authorities/"+caId+"/enrollments", "application/json", bytes.NewReader(body))
	if err != nil {
		return logical.ErrorResponse("Error response: %v", err), err
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return logical.ErrorResponse("CAGW response could not be read: %v", err), err
	}

	if b.Logger().IsTrace() {
		b.Logger().Trace("response body: " + string(responseBody))
	}

	err = CheckForError(b, responseBody, resp.StatusCode)
	if err != nil {
		return logical.ErrorResponse("Error response received from gateway: %v", err), err
	}

	var enrollmentResponse EnrollmentResponse
	err = json.Unmarshal(responseBody, &enrollmentResponse)
	if err != nil {
		return logical.ErrorResponse("CAGW enrollment response could not be parsed: %v", err), err
	}

	var respData map[string]interface{}
	switch *format {
	case "der":
		respData = map[string]interface{}{
			"certificate": enrollmentResponse.Enrollment.Body,
		}

	case "pem", "pem_bundle":
		data, err := base64.StdEncoding.DecodeString(enrollmentResponse.Enrollment.Body)
		if err != nil {
			return logical.ErrorResponse("Error decoding base64 response from CAGW: %v", err), err
		}
		block := pem.Block{Type: "CERTIFICATE", Bytes: data}

		certificate, err := x509.ParseCertificate(data)
		if err != nil {
			return logical.ErrorResponse("Failed to parse the certificate: %v", err), err
		}

		respData = map[string]interface{}{
			"certificate":   string(pem.EncodeToMemory(&block)),
			"serial_number": certificate.SerialNumber,
		}
	}

	storageEntry, err := logical.StorageEntryJSON("sign/"+roleName+"/"+respData["serial_number"].(*big.Int).String(), respData)

	if err != nil {
		return logical.ErrorResponse("error creating certificate storage entry"), err
	}

	err = req.Storage.Put(ctx, storageEntry)
	if err != nil {
		return logical.ErrorResponse("could not store certificate"), err
	}

	return &logical.Response{
		Data: respData,
	}, nil

}

func (b *backend) opReadSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return opReadCert(ctx, req, data, "sign")
}

func (b *backend) opListSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return opListCerts(ctx, req, data, "sign")
}
