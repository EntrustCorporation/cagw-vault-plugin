# Entrust Datacard CA Gateway Vault plugin

The Entrust Datacard CA Gateway Vault plugin allows Vault to issue certificates that come through the CA Gateway from the underlying exernal Certificate Authority.
Vault comes with a built-in CA as part of its Secrets Engine, but using that internal CA will often not meet regulatory or company security requirements.  If this is the case, then you have two options:
* Use the Vault provisions to root to an external CA rather than self-sign its own CA certificate,
* Or, plug into your own issuing CA.

Doing the latter has the advantage that the certificates you create will be visible in the Entrust Datacard management console and subject to the policies and controls set up by your organization.  This CA may be either one that you self-manage and host in your own private/public cloud or one that is managed and hosted by Entrust Datacard.

The plugin is designed to be a drop in replacement for Vault's built in PKI plugin, implementing the capability necessary to support the certificate issuance.

## Build

You can build the plugin using Go by executing the following command in the project directory:

```
> go build -o cagw-vault-plugin
```

This will build the plugin and store the resulting executable as `cagw_vault_plugin`

The Go programming language can be downloaded from here: https://golang.org/dl/

General information about using Go can be found at: https://golang.org/

Information on building Go modules can be found here: https://github.com/golang/go/wiki/Modules

## Installation

The CAGW Vault plugin is install like any normal Vault plugin. First the plugin executable must be copied to the Vault 
plugin directory. Then the plugin must be registered with a command like the following:

```
> vault write sys/plugins/catalog/cagw-vault-plugin sha256=$hash command="cagw-vault-plugin"
```

`$hash` must be the SHA256 of the CAGW Vault plugin executable. An example of how to compute the hash and install the 
plugin can be found in the `deploy.sh` file in this repo.

More information about Vault plugins can be found here: https://vaultproject.io/docs/internals/plugins.html

## Configuration

### Base Configuration

You can configure the CA Gateway plugin by writing to the `/config` endpoint. The configuration accepts four properties:
* **pem_bundle** - The certificate and key to login to the CA Gateway with in PEM format.
* **caid** - The CA identifier of the CA to user
* **url** - The URL for the CA Gateway server including the context path.
* **cacerts** - The complete certificate chain for the CA in PEM format.

#### Example
>`vault write pki/config pem_bundle=@user.pem caid=CA_1001 url=https://cagateway:8080/cagw cacerts=@cagw.root.pem`

>`vault read pki/config`

>`vault read -field=CACerts pki/config`

>`vault read -field=URL pki/config`

>`vault read -field=CaId pki/config`

### Profile Configuration

* **common_name_variable** - The name of the subject variable to used to supply the common name to the gateway. The default is 'cn'.
* **ttl** - The lease duration if no specific lease duration is requested. The lease duration controls the expiration of certificates issued by this backend. Defaults to the value of max_ttl.  Value is in seconds.
* **max_ttl** - The maximum allowed lease duration. Value is in seconds.

#### Example

>`vault write pki/config/profiles/PROF-101 common_name=cn ttl=15552000 max_ttl=31104000`

>`vault read pki/config/profiles/PROF-101`

## Usage

To issue a new certificate, write a CSR and common name to the sign endpoint with the profile identifier at the end of the path.

>`vault write pki/sign/CA-PROF-1001 csr=@csr.pem common_name=example.com`
