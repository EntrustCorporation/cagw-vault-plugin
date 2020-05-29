/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/crypto/pkcs12"
)

func (b *backend) opIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	commonName := data.Get("common_name").(string)
	format := data.Get("format").(string)

	if len(commonName) <= 0 {
		return logical.ErrorResponse("common_name is empty"), nil
	}

	configEntry, err := getConfigEntry(ctx, req)
	if err != nil {
		return logical.ErrorResponse("Error fetching config"), err
	}

	profileName := data.Get("profile").(string)
	configProfileEntry, err := getProfileConfig(ctx, req, profileName)

	// Construct enrollment request
	enrollmentRequest := EnrollmentRequest{
		ProfileId: profileName,
		RequiredFormat: RequiredFormat{
			Format: "PKCS12",
			Protection: &Protection{
				Type:     "PasswordProtection",
				Password: "ChangeMe2",
			},
		},
		SubjectVariables: []SubjectVariable{
			{configProfileEntry.CommonNameVariable, commonName},
		},
	}

	body, err := json.Marshal(enrollmentRequest)
	if err != nil {
		return logical.ErrorResponse("Error constructing enrollment request: %v", err), err
	}

	if b.Logger().IsDebug() {
		b.Logger().Debug(fmt.Sprintf("Enrollment request body: %v", string(body)))
	}

	tlsClientConfig, err := getTLSConfig(ctx, req, configEntry)
	if err != nil {
		return logical.ErrorResponse("Error retrieving TLS configuration: %v", err), err
	}

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsClientConfig,
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Post(configEntry.URL+"/v1/certificate-authorities/"+configEntry.CaId+"/enrollments", "application/json", bytes.NewReader(body))
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

	blocks, err := pkcs12.ToPEM([]byte(p12), "ChangeMe2")
	if err != nil {
		return logical.ErrorResponse("PKCS12 could not be parsed: %v", err), err
	}

	respData := map[string]interface{}{}

	switch format {
	case "pem":
		for _, block := range blocks {
			b.Logger().Debug(fmt.Sprintf("Found block: %s", block.Type))
			if block.Type == "CERTIFICATE" {
				b.Logger().Debug("Found CERTIFICATE in P12")
				respData["certificate"] = pem.EncodeToMemory(block)
			}
			if block.Type == "PRIVATE KEY" {
				b.Logger().Debug("Found PRIVATE KEY in P12")
				respData["private_key"] = pem.EncodeToMemory(block)
			}
		}

	default:
		return logical.ErrorResponse("Unsupported format: %s", format), nil
	}

	return &logical.Response{
		Data: respData,
	}, nil

}
