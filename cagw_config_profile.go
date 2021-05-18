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

type CAGWConfigProfile struct {
	Id                          string                       `json:"id"`
	Name                        string                       `json:"name"`
	SubjectVariableRequirements []SubjectVariableRequirement `json:"subjectVariableRequirements"`
	SubjectAltNameRequirements  []SubjectAltNameRequirement  `json:"subjectAltNameRequirements"`
	TTL                         time.Duration                `json:"ttl_duration" mapstructure:"ttl_duration"`
	MaxTTL                      time.Duration                `json:"max_ttl_duration" mapstructure:"max_ttl_duration"`
}

type CAGWConfigProfileID struct {
	Id   string
	Name string
}

func (p CAGWConfigProfileID) Profile(ctx context.Context, req *logical.Request, data *framework.FieldData) (*CAGWConfigProfile, error) {

	roleName := data.Get("roleName").(string)
	configRole, err := getConfigRole(ctx, req, roleName)

	if len(p.Id) <= 0 {
		p.Id = configRole.ProfileId
		if len(p.Id) <= 0 {
			return nil, errors.New("Missing the profile ID")
		}
	}

	if err != nil {
		return nil, errors.New("Error fetching config")
	}

	tlsClientConfig, err := getTLSConfig(ctx, req, configRole)
	if err != nil {
		return nil, fmt.Errorf("Error retrieving TLS configuration: %w", err)
	}

	profileResp, err := p.getProfile(tlsClientConfig, configRole, roleName)

	if err != nil {
		return nil, fmt.Errorf("Error response received from gateway: %w", err)
	}

	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	maxTtl := time.Duration(data.Get("max_ttl").(int)) * time.Second

	profile := &CAGWConfigProfile{
		profileResp.Profile.Id,
		profileResp.Profile.Name,
		profileResp.Profile.SubjectVariableRequirements,
		profileResp.Profile.SubjectAltNameRequirements,
		ttl,
		maxTtl,
	}

	return profile, nil

}

func (p CAGWConfigProfileID) getProfile(tlsClientConfig *tls.Config, configRole *CAGWConfigRole, roleName string) (*ProfileResponse, error) {
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsClientConfig,
	}

	client := &http.Client{Transport: tr}

	caId := configRole.CAId
	if len(caId) <= 0 {
		caId = roleName
	}
	resp, err := client.Get(configRole.URL + "/v1/certificate-authorities/" + caId + "/profiles/" + p.Id)
	if err != nil {
		return nil, fmt.Errorf("Error response: %w", err)
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("CAGW response could not be read: %w", err)
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
		return nil, fmt.Errorf("CAGW enrollment response could not be parsed: %w", err)
	}

	return profileResp, nil
}
