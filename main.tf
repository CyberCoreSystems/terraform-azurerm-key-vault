# RBAC-mode Azure Key Vault with purge protection, network default-deny,
# scoped role assignments, managed keys (with rotation policies), secrets and
# self-signed certificate scaffolding, optional diagnostics and a private
# endpoint. Access policies are deliberately not supported — RBAC only.

data "azurerm_client_config" "current" {}

locals {
  tenant_id = coalesce(var.tenant_id, data.azurerm_client_config.current.tenant_id)

  # Number of data-plane objects (keys/secrets/certs) seeded in this apply. These
  # are written over the vault DATA plane (<name>.vault.azure.net), which the Key
  # Vault firewall filters — the AzureServices bypass does not cover a Terraform
  # runner. nonsensitive() is safe here: it exposes only the *count* of secrets,
  # never any value.
  data_plane_object_count = length(var.keys) + nonsensitive(length(var.secrets)) + length(var.self_signed_certificates)

  # Whether the firewall, as configured, would let the deploying runner reach the
  # data plane: either it is not in default-deny, or at least one IP/subnet rule
  # is present to allow the runner in.
  data_plane_reachable = (
    var.network_acls.default_action != "Deny" ||
    length(var.network_acls.ip_rules) > 0 ||
    length(var.network_acls.virtual_network_subnet_ids) > 0
  )

  # Reaching the data plane is not the same as being ALLOWED on it. The vault is
  # RBAC-authorised, and creating a vault grants its creator no data-plane role,
  # so seeding needs an explicit assignment carrying key/secret/certificate
  # write permission. These are the built-in roles that do.
  data_plane_writer_roles = [
    "Key Vault Administrator",
    "Key Vault Certificates Officer",
    "Key Vault Crypto Officer",
    "Key Vault Secrets Officer",
  ]

  data_plane_authorised = length([
    for a in values(var.role_assignments) : a
    if contains(local.data_plane_writer_roles, a.role_definition_name)
  ]) > 0
}

resource "azurerm_key_vault" "this" {
  # checkov:skip=CKV_AZURE_110: secure default lives in variables.tf (purge_protection_enabled defaults to true); the example fixture sets false because purge protection is irreversible and would block live-test teardown — checkov evaluates the module through the example's values
  # checkov:skip=CKV_AZURE_42: secure defaults live in variables.tf (purge_protection_enabled true, soft_delete_retention_days 90); the example fixture uses the ephemeral test posture (false / 7 days) so live-test destroy works
  # checkov:skip=CKV_AZURE_109: secure default lives in variables.tf (network_acls.default_action is optional(string, "Deny")); the example fixture sets Allow because it seeds keys/secrets over the vault data plane, which the deploying runner must reach (the AzureServices bypass does not cover a Terraform runner — see the precondition below)
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = local.tenant_id
  sku_name            = var.sku_name

  rbac_authorization_enabled    = true
  purge_protection_enabled      = var.purge_protection_enabled
  soft_delete_retention_days    = var.soft_delete_retention_days
  public_network_access_enabled = var.public_network_access_enabled

  enabled_for_deployment          = var.enabled_for_deployment
  enabled_for_disk_encryption     = var.enabled_for_disk_encryption
  enabled_for_template_deployment = var.enabled_for_template_deployment

  network_acls {
    default_action             = var.network_acls.default_action
    bypass                     = var.network_acls.bypass
    ip_rules                   = var.network_acls.ip_rules
    virtual_network_subnet_ids = var.network_acls.virtual_network_subnet_ids
  }

  tags = var.tags

  # Seeding keys/secrets/certs writes over the vault DATA plane, which the firewall
  # filters. With default_action = "Deny" and no ip_rules / subnet allowed, the
  # runner is blocked (403) and the apply fails on the first data-plane object —
  # the AzureServices bypass does NOT cover a Terraform runner. Catch the trap at
  # plan time instead of after the vault is created.
  lifecycle {
    precondition {
      condition     = local.data_plane_object_count == 0 || local.data_plane_authorised
      error_message = "This apply seeds keys/secrets/certificates over the vault data plane, but no role_assignments entry grants the deployer a data-plane writer role (Key Vault Administrator, Crypto Officer, Secrets Officer or Certificates Officer). The vault is RBAC-authorised, and creating a vault grants its creator NO data-plane access — the writes would fail with 403 ForbiddenByRbac. Add an assignment for the identity running terraform (data.azurerm_client_config.current.object_id)."
    }

    precondition {
      condition     = local.data_plane_object_count == 0 || local.data_plane_reachable
      error_message = "network_acls.default_action is \"Deny\" but this apply also seeds keys/secrets/certificates over the vault data plane, and no ip_rules or virtual_network_subnet_ids allow the deploying runner in. The AzureServices bypass does not cover a Terraform runner, so the data-plane writes would be blocked (403). Add the runner's public IP to network_acls.ip_rules (or its subnet to virtual_network_subnet_ids), or set default_action = \"Allow\" for the bootstrap apply."
    }
  }
}

resource "azurerm_role_assignment" "this" {
  for_each = var.role_assignments

  scope                = azurerm_key_vault.this.id
  principal_id         = each.value.principal_id
  role_definition_name = each.value.role_definition_name
  principal_type       = each.value.principal_type
  description          = each.value.description
}

# Data-plane objects depend on the role assignments so a fresh deployment
# does not race Azure RBAC propagation.

resource "azurerm_key_vault_key" "this" {
  # checkov:skip=CKV_AZURE_112: key protection is a per-key buyer knob (keys[*].key_type accepts RSA-HSM / EC-HSM); HSM-backed keys require the premium vault SKU (sku_name), so software-protected RSA stays the default on the standard SKU
  for_each = var.keys

  name         = each.key
  key_vault_id = azurerm_key_vault.this.id
  key_type     = each.value.key_type
  key_size     = contains(["RSA", "RSA-HSM"], each.value.key_type) ? each.value.key_size : null
  curve        = contains(["EC", "EC-HSM"], each.value.key_type) ? coalesce(each.value.curve, "P-256") : null
  key_opts     = each.value.key_opts

  expiration_date = each.value.expiration_date
  not_before_date = each.value.not_before_date

  dynamic "rotation_policy" {
    for_each = each.value.rotation_policy == null ? [] : [each.value.rotation_policy]
    content {
      expire_after         = rotation_policy.value.expire_after
      notify_before_expiry = rotation_policy.value.notify_before_expiry

      automatic {
        time_before_expiry = rotation_policy.value.time_before_expiry
      }
    }
  }

  tags = var.tags

  depends_on = [azurerm_role_assignment.this]
}

resource "azurerm_key_vault_secret" "this" {
  for_each = nonsensitive(var.secrets)

  name            = each.key
  key_vault_id    = azurerm_key_vault.this.id
  value           = each.value.value
  content_type    = each.value.content_type
  expiration_date = each.value.expiration_date
  not_before_date = each.value.not_before_date

  tags = var.tags

  depends_on = [azurerm_role_assignment.this]
}

resource "azurerm_key_vault_certificate" "this" {
  for_each = var.self_signed_certificates

  name         = each.key
  key_vault_id = azurerm_key_vault.this.id

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      exportable = each.value.exportable
      key_type   = "RSA"
      key_size   = each.value.key_size
      reuse_key  = each.value.reuse_key
    }

    secret_properties {
      content_type = each.value.content_type
    }

    lifetime_action {
      action {
        action_type = "AutoRenew"
      }
      trigger {
        days_before_expiry = each.value.renew_days_before_expiry
      }
    }

    x509_certificate_properties {
      subject            = each.value.subject
      validity_in_months = each.value.validity_in_months
      key_usage          = ["digitalSignature", "keyEncipherment"]

      dynamic "subject_alternative_names" {
        for_each = length(each.value.dns_names) > 0 ? [1] : []
        content {
          dns_names = each.value.dns_names
        }
      }
    }
  }

  tags = var.tags

  depends_on = [azurerm_role_assignment.this]
}

resource "azurerm_monitor_diagnostic_setting" "this" {
  count = var.diagnostic_settings.enabled ? 1 : 0

  name                           = var.diagnostic_settings.name
  target_resource_id             = azurerm_key_vault.this.id
  log_analytics_workspace_id     = var.diagnostic_settings.log_analytics_workspace_id
  storage_account_id             = var.diagnostic_settings.storage_account_id
  eventhub_authorization_rule_id = var.diagnostic_settings.eventhub_authorization_rule_id

  dynamic "enabled_log" {
    for_each = toset(var.diagnostic_settings.log_categories)
    content {
      category = enabled_log.value
    }
  }
}

resource "azurerm_private_endpoint" "this" {
  count = var.private_endpoint == null ? 0 : 1

  name                = coalesce(var.private_endpoint.name, "pep-${var.name}-vault")
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint.subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-${var.name}-vault"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  dynamic "private_dns_zone_group" {
    for_each = length(var.private_endpoint.private_dns_zone_ids) > 0 ? [1] : []
    content {
      name                 = "default"
      private_dns_zone_ids = var.private_endpoint.private_dns_zone_ids
    }
  }
}
