package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"io/ioutil"
	"net/http"
	"time"
)

func (b *backend) opSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	csrPem := data.Get("csr").(string)
	commonName := data.Get("common_name").(string)

	if len(commonName) <= 0 {
		return logical.ErrorResponse("common_name is empty"), nil
	}

	csrBlock, _ := pem.Decode([]byte(csrPem))
	if csrBlock == nil {
		return logical.ErrorResponse("CSR could not be decoded"), nil
	}

	csrBase64 := base64.StdEncoding.EncodeToString(csrBlock.Bytes)

	storageEntry, err := req.Storage.Get(ctx, "config/cagw")

	if err != nil {
		return logical.ErrorResponse("CAGW configuration could not be loaded: %v", err), err
	}

	configEntry := CAGWConfigEntry{}
	err = storageEntry.DecodeJSON(&configEntry)

	if err != nil {
		return logical.ErrorResponse("CAGW configuration could not be parsed: %v", err), err
	}

	profileName := data.Get("profile").(string)

	profileStorageEntry, err := req.Storage.Get(ctx, "config/profile/"+profileName)

	if err != nil {
		return logical.ErrorResponse("CAGW profile configuration could not be loaded: %v", err), err
	}

	configProfileEntry := CAGWConfigProfileEntry{}

	// If there is a storage entry, decode it, else use defaults
	if profileStorageEntry != nil {
		err = profileStorageEntry.DecodeJSON(&configProfileEntry)
		if err != nil {
			return logical.ErrorResponse("CAGW profile configuration could not be parsed: %v", err), err
		}
	} else {
		configProfileEntry.CommonNameVariable = "cn"
		configProfileEntry.TTL, _ = time.ParseDuration("2160h")
		configProfileEntry.MaxTTL = 0
	}

	// Construct enrollment request
	enrollmentRequest := EnrollmentRequest{
		ProfileId: profileName,
		RequiredFormat: RequiredFormat{
			Format: "X509",
		},
		CSR: csrBase64,
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

	certificate, err := tls.X509KeyPair([]byte(configEntry.Cert), []byte(configEntry.Cert))
	if err != nil {
		return logical.ErrorResponse("Error parsing client certificate and key: %v", err), err
	}

	certPool, _ := x509.SystemCertPool()
	if certPool == nil {
		certPool = x509.NewCertPool()
	}

	if ok := certPool.AppendCertsFromPEM([]byte(configEntry.CACerts)); !ok {
		return logical.ErrorResponse("Error appending CA certs."), nil
	}

	tlsClientConfig := &tls.Config{
		Certificates: []tls.Certificate{
			certificate,
		},
		RootCAs: certPool,
	}

	tlsClientConfig.BuildNameToCertificate()

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

	if resp.StatusCode != 200 {

		if b.Logger().IsDebug() {
			if resp.StatusCode >= 400 {
				b.Logger().Debug(fmt.Sprintf("Received failure response code: %d", resp.StatusCode))
			} else {
				b.Logger().Debug(fmt.Sprintf("Received response code: %d", resp.StatusCode))
			}
		}

		var errorResponse ErrorResponse
		err = json.Unmarshal(responseBody, &errorResponse)
		if err != nil {
			return logical.ErrorResponse("CAGW error response could not be parsed: %v (%d)", err, resp.StatusCode), err
		}
		return logical.ErrorResponse("Error from gateway: %s (%d)", errorResponse.Error.Message, resp.StatusCode), nil
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
