/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"math/big"

	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"software.sslmate.com/src/go-pkcs12"
)

func (b *backend) opWriteIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("roleName").(string)
	subjectVariables := data.Get("subject_variables").(string)
	format := data.Get("format").(string)

	if strings.EqualFold(format, "pem") != true {
		return logical.ErrorResponse("Unsupported format: %s", format), nil
	}

	if len(subjectVariables) <= 0 {
		return logical.ErrorResponse("subject_variables is empty"), nil
	}

	subjectVars, err := processSubjectVariables(subjectVariables)
	if err != nil {
		return logical.ErrorResponse("Failed parsing the subject_variables"), err
	}

	altNames := data.Get("alt_names").([]string)
	var subjAltNames []SubjectAltName
	if len(altNames) > 0 {
		subjAltNames, err = processSubjectAltNames(altNames)
		if err != nil {
			return logical.ErrorResponse("Failed parsing the subject alt names: %s", altNames), err
		}
	}

	configRole, err := getConfigRole(ctx, req, roleName)
	if err != nil {
		return logical.ErrorResponse("Error fetching config"), err
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

	password, err := GenerateRandomString(32)
	if err != nil {
		return logical.ErrorResponse("Error generating random password: " + err.Error()), err
	}

	// Construct enrollment request
	enrollmentRequest := EnrollmentRequest{
		ProfileId: profileId,
		RequiredFormat: RequiredFormat{
			Format: "PKCS12",
			Protection: &Protection{
				Type:     "PasswordProtection",
				Password: password,
			},
		},
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

	caId := configRole.CAId
	if len(caId) == 0 {
		caId = roleName
	}

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

	b.Logger().Debug(string(enrollmentResponse.Enrollment.Body))
	base64P12 := enrollmentResponse.Enrollment.Body
	p12, err := base64.StdEncoding.DecodeString(base64P12)
	if err != nil {
		return logical.ErrorResponse("base64 could not be decoded: %v", err), err
	}

	respData, err := Pkcs12ToPem(p12, password)

	if err != nil {
		return logical.ErrorResponse("error parsing the PKCS12: %v", err), err
	}

	storageEntry, err := logical.StorageEntryJSON("issue/"+roleName+"/"+respData["serial_number"].(*big.Int).String(), respData)

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

func (b *backend) opReadIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return opReadCert(ctx, req, data, "issue")
}

func (b *backend) opListIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return opListCerts(ctx, req, data, "issue")
}

func Pkcs12ToPem(p12 []byte, password string) (map[string]interface{}, error) {
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain([]byte(p12), password)
	if err != nil {
		return nil, fmt.Errorf("error decoding PKCS12: %s", err)
	}

	respData := map[string]interface{}{}

	var keyPemBlock *pem.Block
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes := x509.MarshalPKCS1PrivateKey(k)
		keyPemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		}
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("error encoding EC key to PEM: %s", err)
		}
		keyPemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
	respData["private_key"] = string(pem.EncodeToMemory(keyPemBlock))

	var certPemBlock *pem.Block = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	}
	respData["certificate"] = string(pem.EncodeToMemory(certPemBlock))

	respData["serial_number"] = certificate.SerialNumber

	var caCertsBlocks string
	for _, c := range caCerts {
		var caCertPemBlock *pem.Block = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}
		caCertsBlocks = caCertsBlocks + "\n" + string(pem.EncodeToMemory(caCertPemBlock))
	}
	respData["chain"] = caCertsBlocks

	return respData, nil
}

func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}
