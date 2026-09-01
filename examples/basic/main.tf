terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0, < 5.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = "00000000-0000-0000-0000-000000000000"
}

module "key_vault" {
  source = "../../"

  name                = "kv-iacbazaar-ex-001"
  resource_group_name = "rg-security-example"
  location            = "westeurope"

  # Ephemeral example settings — keep purge protection ON in production.
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  role_assignments = {
    platform_admins = {
      principal_id         = "00000000-0000-0000-0000-000000000001"
      role_definition_name = "Key Vault Administrator"
      principal_type       = "Group"
    }
    app_secrets_reader = {
      principal_id         = "00000000-0000-0000-0000-000000000002"
      role_definition_name = "Key Vault Secrets User"
      principal_type       = "ServicePrincipal"
    }
  }

  keys = {
    "cmk-storage" = {
      rotation_policy = {}
    }
  }

  secrets = {
    "example-api-key" = {
      value        = "placeholder-rotate-me"
      content_type = "text/plain"
    }
  }

  network_acls = {
    default_action = "Allow" # tighten to "Deny" + ip_rules in production
  }

  tags = {
    environment = "example"
    managed_by  = "iac-bazaar"
  }
}

output "vault_uri" {
  value = module.key_vault.vault_uri
}

output "key_versionless_ids" {
  value = module.key_vault.key_versionless_ids
}
