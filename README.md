# Azure Key Vault

[![IaC Bazaar: live-tested](https://www.iac-bazaar.com/api/artifacts/azure-key-vault/badge)](https://www.iac-bazaar.com/catalog/azure-key-vault?utm_source=syndication&utm_medium=readme&utm_campaign=artifact)

RBAC-mode Key Vault with private endpoint, diagnostics, and managed keys/secrets/certificates scaffolding.

This module was **applied to a real Azure account, verified, and destroyed** on 2026-06-29 - not just `terraform validate`d.

Check it yourself, no account needed:

```
curl -s https://www.iac-bazaar.com/api/artifacts/azure-key-vault/verification
```

The receipt names every check that ran, when it ran, and the SHA-256 of the
archive it describes. Full detail: [www.iac-bazaar.com/catalog/azure-key-vault](https://www.iac-bazaar.com/catalog/azure-key-vault)

## Usage

```hcl
module "key_vault" {
  source  = "registry.terraform.io/CyberCoreSystems/key-vault/azurerm"
  version = "~> 1.0"

  # See variables.tf for the full input contract.
}
```

## Why this module

Every module we publish goes through the same checks before release:

| check | what it means |
|---|---|
| `tofu validate` + `tflint` | it parses and lints clean |
| `checkov` | scanned for insecure defaults |
| **live test** | **really applied to a cloud account, outputs verified, then destroyed** |

That last row is the one most module catalogues skip. A module that has never
been applied has never been proven.

## Provider compatibility

```
azurerm >= 4.0, < 5.0
```

## More modules

This is one of **673 Terraform modules across 19 cloud platforms** on
IaC Bazaar, 113 of them live-tested:
AWS, Azure, GCP, Oracle OCI, Cloudflare, Akamai, DigitalOcean, Linode, Hetzner,
Vultr, Scaleway, Alibaba, IBM, UpCloud, Civo, Exoscale, OVH, Tencent and Huawei.

Browse the full catalogue at **[www.iac-bazaar.com](https://www.iac-bazaar.com)**, including
production landing zones for AWS, Azure and GCP that have each been live-tested
as a single composed apply.

- Terraform module 1.0.0, live-tested on IaC Bazaar: [Azure Key Vault](https://www.iac-bazaar.com/catalog/azure-key-vault?utm_source=syndication&utm_medium=readme&utm_campaign=artifact)
- How verification works: [https://www.iac-bazaar.com/verified](https://www.iac-bazaar.com/verified)

## Licence

See [LICENSE](./LICENSE).
