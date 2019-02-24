package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"io/ioutil"
	"net/http"
)

func (b *backend) opIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	commonName := data.Get("common_name").(string)

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

	respData := map[string]interface{}{
		"certificate": enrollmentResponse.Enrollment.Body,
	}

	return &logical.Response{
		Data: respData,
	}, nil

}
