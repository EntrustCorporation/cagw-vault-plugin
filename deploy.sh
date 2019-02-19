#!/bin/bash

echo "Plugin directory: $VAULT_PLUGIN_DIR"

echo "Building..."
go build -o cagw-vault-plugin
echo "Built."

sudo cp cagw-vault-plugin $VAULT_PLUGIN_DIR

hash=`shasum -a 256 $VAULT_PLUGIN_DIR/cagw-vault-plugin | awk '{ print $1 }'`

echo "SHA256: $hash"

vault write sys/plugins/catalog/cagw-vault-plugin sha256=$hash command="cagw-vault-plugin"

vault secrets enable -path=pki cagw-vault-plugin

echo "Done."
