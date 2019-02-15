package main

import (
	"context"
	"encoding/pem"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) opConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	certPem := data.Get("cert").([]byte)
	keyPem := data.Get("key").([]byte)
	caId := data.Get("caid").(string)
	url := data.Get("url").(string)

	if len(certPem) == 0 {
		return logical.ErrorResponse("must provide PEM encoded certificate"), nil
	}
	if len(keyPem) == 0 {
		return logical.ErrorResponse("must provide PEM encoded key"), nil
	}
	if len(caId) == 0 {
		return logical.ErrorResponse("must provide CA identifier"), nil
	}
	if len(url) == 0 {
		return logical.ErrorResponse("must provide gateway URL"), nil
	}

	certBlock, _ := pem.Decode(certPem)
	if certBlock == nil {
		return logical.ErrorResponse("certificate could not be decoded"), nil
	}

	keyBlock, _ := pem.Decode(keyPem)
	if certBlock == nil {
		return logical.ErrorResponse("key could not be decoded"), nil
	}

	entry := &CAGWConfigEntry{
		certBlock.Bytes,
		keyBlock.Bytes,
		caId,
		url,
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
		"CaId": caId,
		"URL": url,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

