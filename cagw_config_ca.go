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

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
)

type CAGWConfigRole struct {
	PEMBundle string
	URL       string
	CACerts   string
	CAId      string
	ProfileId string
}

type CAGWConfigCAConfigProfileIDs struct {
	CAGWConfigRole
	Profiles []CAGWConfigProfileID
}

func (c CAGWConfigRole) ProfileIDs(ctx context.Context, req *logical.Request, data *framework.FieldData, caId string) ([]CAGWConfigProfileID, error) {

	if len(caId) == 0 {
		return nil, errors.New("Missing the caId")
	}

	tlsClientConfig, err := getTLSConfig(ctx, req, &c)
	if err != nil {
		return nil, fmt.Errorf("Error retrieving TLS configuration: %w", err)
	}

	profilesResp, err := c.getProfiles(tlsClientConfig, caId)
	if err != nil {
		return nil, fmt.Errorf("Error response received from gateway: %w", err)
	}

	profiles := profilesResp.Profiles
	var entries []CAGWConfigProfileID
	for _, p := range profiles {
		entries = append(entries, CAGWConfigProfileID{
			p.Id,
			p.Name,
		})
	}

	return entries, nil

}

func (c CAGWConfigRole) getProfiles(tlsClientConfig *tls.Config, caId string) (*ProfilesResponse, error) {
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsClientConfig,
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Get(c.URL + "/v1/certificate-authorities/" + caId + "/profiles")
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

	var profilesResp *ProfilesResponse
	err = json.Unmarshal(responseBody, &profilesResp)
	if err != nil {
		return nil, fmt.Errorf("CAGW enrollment response could not be parsed: %w", err)
	}

	return profilesResp, nil
}
