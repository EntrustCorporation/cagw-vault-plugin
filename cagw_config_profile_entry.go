/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
)

type CAGWProfileEntry struct {
	Id                          string                       `json:"id"`
	Name                        string                       `json:"name"`
	SubjectVariableRequirements []SubjectVariableRequirement `json:"subjectVariableRequirements"`
	SubjectAltNameRequirements  []SubjectAltNameRequirement  `json:"subjectAltNameRequirements"`
	TTL                         time.Duration                `json:"ttl_duration" mapstructure:"ttl_duration"`
	MaxTTL                      time.Duration                `json:"max_ttl_duration" mapstructure:"max_ttl_duration"`
}

type CAGWProfileID struct {
	Id string
}

func (p CAGWProfileID) Entry(ctx context.Context, req *logical.Request, data *framework.FieldData) (*CAGWProfileEntry, error) {

	if len(p.Id) == 0 {
		return nil, errors.New("Missing the profile ID")
	}

	configEntry, err := getConfigEntry(ctx, req)
	if err != nil {
		return nil, errors.New("Error fetching config")
	}

	tlsClientConfig, err := getTLSConfig(ctx, req, configEntry)
	if err != nil {
		return nil, fmt.Errorf("Error retrieving TLS configuration: %g", err)
	}

	profileResp, err := getResponse(tlsClientConfig, configEntry, p.Id)

	if err != nil {
		return nil, fmt.Errorf("Error response received from gateway: %g", err)
	}

	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	maxTtl := time.Duration(data.Get("max_ttl").(int)) * time.Second

	entry := &CAGWProfileEntry{
		profileResp.Profile.Id,
		profileResp.Profile.Name,
		profileResp.Profile.SubjectVariableRequirements,
		profileResp.Profile.SubjectAltNameRequirements,
		ttl,
		maxTtl,
	}

	return entry, nil

}

func getResponse(tlsClientConfig *tls.Config, configEntry *CAGWConfigEntry, profileID string) (*ProfileResponse, error) {
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsClientConfig,
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Get(configEntry.URL + "/v1/certificate-authorities/" + configEntry.CaId + "/profiles/" + profileID)
	if err != nil {
		return nil, fmt.Errorf("Error response: %g", err)
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("CAGW response could not be read: %g", err)
	}

	if resp.StatusCode != 200 {
		var errorResponse *ErrorResponse
		err := json.Unmarshal(responseBody, &errorResponse)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("CAGW error response could not be parsed (%d)", resp.StatusCode))
		}
		return nil, errors.New(fmt.Sprintf("Error from gateway: %s (%d)", errorResponse.Error.Message, resp.StatusCode))
	}

	var profileResp *ProfileResponse
	err = json.Unmarshal(responseBody, &profileResp)
	if err != nil {
		return nil, fmt.Errorf("CAGW enrollment response could not be parsed: %g", err)
	}

	return profileResp, nil
}
