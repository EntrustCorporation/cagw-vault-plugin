package main

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) opConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	certPem := data.Get("pem_bundle").(string)
	caId := data.Get("caid").(string)
	url := data.Get("url").(string)
	caCertPem := data.Get("cacerts").(string)

	if len(certPem) == 0 {
		return logical.ErrorResponse("must provide PEM encoded certificate"), nil
	}
	if len(caId) == 0 {
		return logical.ErrorResponse("must provide CA identifier"), nil
	}
	if len(url) == 0 {
		return logical.ErrorResponse("must provide gateway URL"), nil
	}
	if len(caCertPem) == 0 {
		return logical.ErrorResponse("must provide gateway CA certificate"), nil
	}

	entry := &CAGWConfigEntry{
		certPem,
		caId,
		url,
		caCertPem,
	}

	storageEntry, err := logical.StorageEntryJSON("config/cagw", entry)

	if err != nil {
		return logical.ErrorResponse("error creating config storage entry"), err
	}

	err = req.Storage.Put(ctx, storageEntry)
	if err != nil {
		return logical.ErrorResponse("could not store configuration"), err
	}

	respData := map[string]interface{}{
		"Message": "Configuration successful",
		"CaId":    caId,
		"URL":     url,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}
