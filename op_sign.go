package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"time"
)

func (b *backend) opSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error

	format, err := getFormat(data)
	if err != nil {
		return logical.ErrorResponse("%v", err), err
	}

	commonName := data.Get("common_name").(string)
	if len(commonName) <= 0 {
		return logical.ErrorResponse("common_name is empty"), nil
	}

	altNames := processAllAltNames(data, commonName)

	csrPem := data.Get("csr").(string)
	// Just decode a single block, omit any subsequent blocks
	csrBlock, _ := pem.Decode([]byte(csrPem))
	if csrBlock == nil {
		return logical.ErrorResponse("CSR could not be decoded"), nil
	}

	csrBase64 := base64.StdEncoding.EncodeToString(csrBlock.Bytes)

	configEntry, err := getConfigEntry(ctx, req)
	if err != nil {
		return logical.ErrorResponse("Error fetching config"), err
	}

	profileName := data.Get("profile").(string)
	configProfileEntry, err := getProfileConfig(ctx, req, profileName)

	ttl := getTTL(data, configProfileEntry)

	// Construct enrollment request
	enrollmentRequest := EnrollmentRequest{
		ProfileId: profileName,
		RequiredFormat: RequiredFormat{
			Format:     "X509",
			Protection: nil,
		},
		CSR: csrBase64,
		SubjectVariables: []SubjectVariable{
			{configProfileEntry.CommonNameVariable, commonName},
		},
		SubjectAltNames: altNames,
		OptionalCertificateRequestDetails: CertificateRequestDetails{
			ValidityPeriod: fmt.Sprintf("P%dM", int64(ttl.Minutes())),
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

		respData = map[string]interface{}{
			"certificate": string(pem.EncodeToMemory(&block)),
		}
	}

	return &logical.Response{
		Data: respData,
	}, nil

}

func getFormat(data *framework.FieldData) (*string, error) {
	format := data.Get("format").(string)
	if len(format) <= 0 {
		format = "pem"
	}
	if format != "pem" && format != "pem_bundle" && format != "der" {
		return nil, errors.New(fmt.Sprintf("Invalid format specified: %s", format))
	}

	return &format, nil
}

func getTTL(data *framework.FieldData, configProfileEntry *CAGWConfigProfileEntry) time.Duration {
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	if ttl <= 0 {
		ttl = configProfileEntry.TTL
	}
	if configProfileEntry.MaxTTL > 0 && ttl > configProfileEntry.MaxTTL {
		ttl = configProfileEntry.MaxTTL
	}
	return ttl
}
