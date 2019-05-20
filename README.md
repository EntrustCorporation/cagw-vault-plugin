# Entrust Datacard CA Gateway Vault plugin

The Entrust Datacard CA Gateway Vault plugin allows Vault to issue certificates that come through the CA Gateway from the underlying exernal Certificate Authority.
Vault comes with a built-in CA as part of its Secrets Engine, but using that internal CA will often not meet regulatory or company security requirements.  If this is the case, then you have two options:
* Use the Vault provisions to root to an external CA rather than self-sign its own CA certificate,
* Or, plug into your own issuing CA.

Doing the latter has the advantage that the certificates you create will be visible in the Entrust Datacard management console and subject to the policies and controls set up by your organization.  This CA may be either one that you self-manage and host in your own private/public cloud or one that is managed and hosted by Entrust Datacard.

The plugin is designed to be a drop in replacement for Vault's built in PKI plugin, implementing the capability necessary to support the certificate issuance.

## Build

You can build the plugin using Gradle by executing the following command:

Windows:
```
> gradlew.bat build
```
Linux:
```
# ./gradlew build
```

Currently, the build will only target the architecture of the host machine.

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
