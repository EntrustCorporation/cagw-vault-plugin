package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/hashicorp/vault/logical"
	"github.com/pkg/errors"
)

func getTLSConfig(ctx context.Context, req *logical.Request, configEntry *CAGWConfigEntry) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair([]byte(configEntry.Cert), []byte(configEntry.Cert))
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing client certificate and key")
	}

	certPool, _ := x509.SystemCertPool()
	if certPool == nil {
		certPool = x509.NewCertPool()
	}

	if ok := certPool.AppendCertsFromPEM([]byte(configEntry.CACerts)); !ok {
		return nil, errors.New("Error appending CA certs.")
	}

	tlsClientConfig := tls.Config{
		Certificates: []tls.Certificate{
			certificate,
		},
		RootCAs: certPool,
	}

	tlsClientConfig.BuildNameToCertificate()

	return &tlsClientConfig, nil
}
