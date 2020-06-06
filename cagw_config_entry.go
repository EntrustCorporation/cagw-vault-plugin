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

type CAGWEntry struct {
	PEMBundle string
	URL       string
	CACerts   string
}

type CAGWEntryCAGWProfileIDs struct {
	Ca       CAGWEntry
	Profiles []CAGWProfileID
}

func (c CAGWEntry) Profiles(ctx context.Context, req *logical.Request, data *framework.FieldData) ([]CAGWProfileID, error) {

	caId := data.Get("caId").(string)

	if len(caId) == 0 {
		return nil, errors.New("Missing the caId")
	}

	tlsClientConfig, err := getTLSConfig(ctx, req, &c)
	if err != nil {
		return nil, fmt.Errorf("Error retrieving TLS configuration: %g", err)
	}

	profilesResp, err := c.getProfiles(tlsClientConfig, caId)

	if err != nil {
		return nil, fmt.Errorf("Error response received from gateway: %g", err)
	}

	profiles := profilesResp.Profiles
	var entries []CAGWProfileID
	for _, p := range profiles {
		entries = append(entries, CAGWProfileID{
			p.Id,
			p.Name,
		})
	}

	return entries, nil

}

func (c CAGWEntry) getProfiles(tlsClientConfig *tls.Config, caId string) (*ProfilesResponse, error) {
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsClientConfig,
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Get(c.URL + "/v1/certificate-authorities/" + caId + "/profiles")
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

	var profilesResp *ProfilesResponse
	err = json.Unmarshal(responseBody, &profilesResp)
	if err != nil {
		return nil, fmt.Errorf("CAGW enrollment response could not be parsed: %g", err)
	}

	return profilesResp, nil
}
