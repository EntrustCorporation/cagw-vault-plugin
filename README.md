# Entrust CA Gateway Vault plugin

## Summary

Entrust CA Gateway Vault plugin allows you to issue certificates from an external Certificate Authority. Certificates created in Vault are visible in Entrust management console & subject to your organization’s policies and controls, whether the CA is self-managed, hosted in your own cloud or managed & hosted by Entrust’s Managed PKI Service.

## Details

The Entrust CA Gateway Vault plugin allows Vault to issue certificates that come through the CA Gateway from the 
underlying external Certificate Authority. Vault comes with a built-in CA as part of its Secrets Engine, but using 
that internal CA will often not meet regulatory or company security requirements. If this is the case, then you have 
two options:
* Use the Vault provisions to root to an external CA rather than self-sign its own CA certificate,
* Or, plug into your own issuing CA.

Doing the latter has the advantage that the certificates you create will be visible in the Entrust management console 
and subject to the policies and controls set up by your organization. This CA may be either one that you self-manage 
and host in your own private/public cloud or one that is managed and hosted by Entrust.

This plugin is designed to be a drop in replacement for Vault's built in PKI plugin, implementing the capability 
necessary to support the certificate issuance.


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

### CAGW Role Configuration

The CAGW plugin is configured by defining role configurations. Each role configuration contains the credentials and url
for a specific CAGW. The role configuration also contains a CA identifier for the CA to associate the role
configuration to and a profile identifier to associate the role configuration with a profile for that CA.

You can configure the CA Gateway plugin by writing to the `/config/{roleName}` endpoint. The configuration accepts 
these properties:
* **pem_bundle** - The certificate and key to login to the CA Gateway with in PEM format.
* **url** - The URL for the CA Gateway server including the context path.
* **cacerts** - The complete certificate chain for the CA in PEM format.
* **ca_id** - The CA identifier
* **profile_id** - The profile identifier

If a **ca_id** is not provided during configuration, the role configuration's name is used as the CA identifier.

If a **profile_id** is not provided during configuration, the role configuration is associated with all profiles for
the corresponding CA. In this case a profile identifier must be provided during all operations with that role
configuration.

#### Examples

##### Configure a Role With a CA and Profile

>`vault write cagw/config/CA01_profile01_role ca_id=CA01 profile_id=profile01 pem_bundle=@user.pem
> url=https://cagateway:8080/cagw cacerts=@cagw.root.pem`

The write operation will connect to CAGW to get the profile IDs for the managed CA.

##### Configure a Role With a CA and All Profiles (legacy)

>`vault write cagw/config/CA01_role ca_id=CA01 pem_bundle=@user.pem url=https://cagateway:8080/cagw
> cacerts=@cagw.root.pem`

##### Configure a Role With a Default CA ID (legacy)

>`vault write cagw/config/CA01 pem_bundle=@user.pem url=https://cagateway:8080/cagw cacerts=@cagw.root.pem`

##### Read a Role Configuration

The below read operation will display the role configuration 

>`vault read cagw/config/CA01_profile01_role`

The three operations below will display individual fields of the role configuration.

>`vault read -field=CACerts cagw/config/CA01_profile01_role`

>`vault read -field=CAId cagw/config/CA01_profile01_role`

>`vault read -field=URL cagw/config/CA01_profile01_role`

The below read operation will display the profile IDs which are available for the role configuration. If the role
configuration has a profile specified this command will only show that profile. If the role configuration is not
associated with a profile all the available profiles for that CA will be listed.

>`vault read -field=Profiles cagw/config/CA01_profile01_role`

### Profile Configuration

A configuration for each profile to be used with a role configuration must be created before any actions can be
performed with that role configuration and profile.

You can configure a role configuration's profile by writing to the `/config/{roleName}/profile` endpoint. The profile 
write operation will connect to CAGW to get additional profile properties. The configuration accepts these properties:
* **ttl** - The lease duration if no specific lease duration is requested. The lease duration controls the expiration 
  of certificates issued by this backend. Defaults to the value of max_ttl.  Value is in seconds.
* **max_ttl** - The maximum allowed lease duration. Value is in seconds.

#### Examples

##### Configure Profile

This command will configure a role configuration's profile.

>`vault write cagw/config/CA01_profile01_role/profile ttl=15552000 max_ttl=31104000`

##### Configure Profile For Role With Multiple Profiles (legacy)

This type of command must be used for role configurations not associated to a single profile.

>`vault write cagw/config/CA01/profiles/profile01 ttl=15552000 max_ttl=31104000`

##### Read Profile Configuration

The following command reads a profile configuration for the specified role configuration.

>`vault read cagw/config/CA01_profile01_role/profile`

The profile properties include the subject variable requirements and subject alternative name requirements if
available. These requirements must be provided for the sign or issue operations. The read operation will display
these properties.

## Usage

The issue and sign endpoints accept the following parameters.

* **subject_variables** - A comma separated list of the subject variable types and values to use. The types should 
  match with the profile configuration.

* **alt_names** - A comma-separated list of the subject alternative names (SAN). Each SAN must have the type and value 
  separated by the equal sign.
  
* **ttl** - The lease duration to request. The value is in seconds. 

To issue a new certificate, write a CSR to the sign endpoint with the managed CA identifier at the end of the path.

>`vault write cagw/sign/CA01_profile01_role csr=@csr.pem subject_variables=cn=example.com,o=Entrust,c=CA`

To issue a new PKCS12 (generate the private key with the certificate), write to the issue endpoint with the managed CA 
identifier at the end of the path.

>`vault write cagw/issue/CA01_profile01_role subject_variables=cn=example.com,o=Entrust,c=CA`

Subject variables can be template variables as defined in the profile.

>`vault write cagw/issue/CA01_profile01_role subject_variables="firstname=Atul,lastname=Gawande"`

To include SAN in the request, use the alt_names option.

>`vault write cagw/issue/CA01_profile01_role subject_variables="firstname=Tim,lastname=Marshal" 
> alt_names="dNSName=www.entrust.com,iPAddress=10.10.10.10,rfc822Name=tim@entrust.com"`

The list operation will return the serial numbers of all the certificates in the secrets engine for the specific CA. 
The read operation with the required serial value will return the certificate and its private key if available.

>`vault list cagw/issue/CA01_profile01_role`

>`vault read cagw/issue/CA01_profile01_role serial=1488848948`

>`vault read -field=private_key cagw/issue/CA01_profile01_role serial=1488848948`

>`vault read -field=certificate cagw/issue/CA01_profile01_role serial=1488848948` 

>`vault read -field=chain cagw/issue/CA01_profile01_role serial=1488848948`
