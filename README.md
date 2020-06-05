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

You can configure the CA Gateway plugin by writing to the `/config/{caId}` endpoint where {caId} is the CA Gateway identifier of the managed CA. The configuration accepts three properties:
* **pem_bundle** - The certificate and key to login to the CA Gateway with in PEM format.
* **url** - The URL for the CA Gateway server including the context path.
* **cacerts** - The complete certificate chain for the CA in PEM format.

#### Example
>`vault write cagw/config/CA_1001 pem_bundle=@user.pem url=https://cagateway:8080/cagw cacerts=@cagw.root.pem`

>`vault read cagw/config/CA_1001`

>`vault read -field=CACerts cagw/config/CA_1001`

>`vault read -field=URL cagw/config/CA_1001`

>`vault read -field=CaId cagw/config`

### Profile Configuration

* **ttl** - The lease duration if no specific lease duration is requested. The lease duration controls the expiration of certificates issued by this backend. Defaults to the value of max_ttl.  Value is in seconds.
* **max_ttl** - The maximum allowed lease duration. Value is in seconds.

#### Example

>`vault write cagw/config/CA_1001/profiles/PROF-101 ttl=15552000 max_ttl=31104000`

The profile write operation will connect to CAGW to get the profile properties. The profile properties include the subject variable requirements and subject alternative name requirements if available. These requirements must be provided for the sign or issue operations. The read operation will display these properties.

>`vault read cagw/config/CA_1001/profiles/PROF-101`

## Usage

* **subject_variables** - A comma separated list of the subject variable types and values to use. The types should match with the profile configuration.

* **alt_names** - A comma-separated list of the subject alternative names (SAN). Each SAN must have the type and value separated by the equal sign.

To issue a new certificate, write a CSR to the sign endpoint with the managed CA identifier at the end of the path.

>`vault write cagw/sign/CA_1001 profile=CA-PROF-1001 csr=@csr.pem subject_variables=cn=example.com,o=Entrust,c=CA`

To issue a new PKCS12 (generate the private key with the certificate), write to the issue endpoint with the managed CA identifier at the end of the path.

>`vault write cagw/issue/CA_1001 profile=CA-PROF-1002 subject_variables=cn=example.com,o=Entrust,c=CA`

Subject variables can be template variables as defined in the profile.

>`vault write cagw/issue/CA_1001 profile=CA-PROF-1002 subject_variables="firstname=Atul,lastname=Gawande"`

To include SAN in the request, use the alt_names option.

>`vault write cagw/issue/CA_1001 profile=CA-PROF-1002 subject_variables="firstname=Tim,lastname=Marshal" alt_names="dNSName=www.entrust.com,iPAddress=10.10.10.10,rfc822Name=tim@enttrust.com"`

All the certificates with any private keys can be fetched from the secrets engine with the read operation. Using the serial option will return the certificate with any private keys. Not using the serial option will list the serial numbers of all the certificates in the secrets engine.

>`vault read cagw/issue/CA_1001`

>`vault read cagw/issue/CA_1001 serial=1488848948`

>`vault read -field=private_key cagw/issue/CA_1001 serial=1488848948`

>`vault read -field=certificate cagw/issue/CA_1001 serial=1488848948` 

>`vault read -field=chain cagw/issue/CA_1001 serial=1488848948`
