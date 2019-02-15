package main

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"encoding/pem"
	"encoding/base64"
	"encoding/json"
	"crypto/tls"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) opSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	csrPem := data.Get("csr").([]byte)

	csrBlock, _ := pem.Decode(csrPem)
	if csrBlock == nil {
		return logical.ErrorResponse("CSR could not be decoded"), nil
	}

	csrBase64 := base64.StdEncoding.EncodeToString(csrBlock.Bytes)

	storageEntry, err := req.Storage.Get(ctx, "config/cagw")

	if err != nil {
		return logical.ErrorResponse("CAGW configuration could not be loaded"), err
	}

	var configEntry CAGWConfigEntry
	err = storageEntry.DecodeJSON(configEntry)

	if err != nil {
		return logical.ErrorResponse("CAGW configuration could not be parsed"), err
	}

	enrollmentRequest := EnrollmentRequest{
		profileId: req.GetString("profilr"),
		requiredFormat: RequiredFormat{
			format: "X509",
		},
		csr: csrBase64,
	}

	body, err := json.Marshal(enrollmentRequest)
	array := make([][]byte, 1)
	array[0] = configEntry.Cert

	certificate := tls.Certificate{
		Certificate: array,
		PrivateKey: configEntry.PrivateKey,
	}

	tlsClientConfig := tls.Config{
		Certificates: []tls.Certificate{
			certificate,
		},
	}


	tr := &http.Transport{
		TLSClientConfig: &tlsClientConfig,
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Post("", "application/json", bytes.NewReader(body))

	respbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return logical.ErrorResponse("CAGW response could not be read"), err
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