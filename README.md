# Entrust Datacard CA Gateway Vault plugin

The Entrust Datacard CA Gateway Vault plugin allows Vault to issue certificates that come from the CA Gateway.

The plugin is designed to be a drop in replacement for Vault's built in PKI plugin.  But, currently only a subset of the functionality is implemented.

## Configuration

You can configure the CA Gateway plugin by writing to the `/config` endpoint. The configuration accepts four properties:
* pem_bundle - The certificate and key to login to the CA Gateway with in PEM format.
* caid - The CA identifier of the CA to user
* url - The URL for the CA Gateway server including the context path.
* cacerts - The complete certificate chain for the CA in PEM format.

### Example
>`vault write pki/config pem_bundle=@user.pem caid=CA_1001 url=https://cagateway:8080/cagw cacerts=@cagw.root.pem`


## Usage

To issue a new certificate, write a CSR and common name to the sign endpoint with the profile identifier at the end of the path.

>`vault write pki/sign/CA-PROF-1001 csr=@csr.pem common_name=example.com`
