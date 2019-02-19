package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"io/ioutil"
	"net/http"
)

func (b *backend) opSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	csrPem := data.Get("csr").(string)

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

	enrollmentRequest := EnrollmentRequest{
		profileId: req.GetString("profile"),
		requiredFormat: RequiredFormat{
			format: "X509",
		},
		csr: csrBase64,
	}

	body, err := json.Marshal(enrollmentRequest)

	certificate, err := tls.X509KeyPair(configEntry.Cert, configEntry.PrivateKey)
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

	respbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return logical.ErrorResponse("CAGW response could not be read: %v", err), err
	}

	if resp.StatusCode != 200 {
		var errorRespnse ErrorResponse
		json.Unmarshal(respbody, errorRespnse)
		// TODO: Handle error response
	}

	var enrollmentResponse EnrollmentResponse
	json.Unmarshal(respbody, enrollmentResponse)

	respData := map[string]interface{}{
		"certificate": enrollmentResponse.enrollment.body,
	}

	return &logical.Response{
		Data: respData,
	}, nil

}
