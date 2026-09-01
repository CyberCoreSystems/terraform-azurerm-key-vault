variable "name" {
  description = "Globally-unique Key Vault name (3-24 chars, letters/digits/hyphens, starts with a letter, ends alphanumeric)."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$", var.name))
    error_message = "name must be 3-24 characters: letters, digits and hyphens, starting with a letter and ending alphanumeric."
  }
}

variable "resource_group_name" {
  description = "Name of an existing resource group."
  type        = string
}

variable "location" {
  description = "Azure region for the vault."
  type        = string
}

variable "tenant_id" {
  description = "Entra tenant ID for the vault. Null = the tenant of the deploying credentials."
  type        = string
  default     = null
}

variable "sku_name" {
  description = "Vault SKU: standard or premium (premium adds HSM-backed keys)."
  type        = string
  default     = "standard"

  validation {
    condition     = contains(["standard", "premium"], var.sku_name)
    error_message = "sku_name must be standard or premium."
  }
}

variable "purge_protection_enabled" {
  description = "Block permanent deletion until the retention window elapses. Required for CMK scenarios; cannot be disabled once on. Set false only for ephemeral/test vaults."
  type        = bool
  default     = true
}

variable "soft_delete_retention_days" {
  description = "Days a deleted vault/object is recoverable (7-90)."
  type        = number
  default     = 90

  validation {
    condition     = var.soft_delete_retention_days >= 7 && var.soft_delete_retention_days <= 90
    error_message = "soft_delete_retention_days must be between 7 and 90."
  }
}

variable "public_network_access_enabled" {
  description = "Allow traffic over the public endpoint (still filtered by network_acls). Set false for private-endpoint-only vaults."
  type        = bool
  default     = true
}

variable "enabled_for_deployment" {
  description = "Allow Azure VMs to retrieve certificates stored as secrets."
  type        = bool
  default     = false
}

variable "enabled_for_disk_encryption" {
  description = "Allow Azure Disk Encryption to retrieve secrets and unwrap keys."
  type        = bool
  default     = false
}

variable "enabled_for_template_deployment" {
  description = "Allow ARM template deployments to retrieve secrets."
  type        = bool
  default     = false
}

variable "network_acls" {
  description = "Vault network ACLs. Default denies everything except trusted Azure services; add your CIDRs/subnets so deployments can reach the data plane. Note: the AzureServices bypass does not cover a Terraform runner, so when default_action = \"Deny\" you must allow-list the runner's public IP (ip_rules) or subnet (virtual_network_subnet_ids) to seed keys/secrets/certificates — the module enforces this at plan time."
  type = object({
    default_action             = optional(string, "Deny")
    bypass                     = optional(string, "AzureServices")
    ip_rules                   = optional(list(string), [])
    virtual_network_subnet_ids = optional(list(string), [])
  })
  default = {}

  validation {
    condition     = contains(["Allow", "Deny"], var.network_acls.default_action) && contains(["AzureServices", "None"], var.network_acls.bypass)
    error_message = "network_acls.default_action must be Allow/Deny and bypass must be AzureServices/None."
  }
}

variable "role_assignments" {
  description = "Azure RBAC role assignments scoped to this vault, keyed by a stable label. Use built-in roles such as 'Key Vault Administrator', 'Key Vault Secrets User', 'Key Vault Crypto Service Encryption User'."
  type = map(object({
    principal_id         = string
    role_definition_name = string
    principal_type       = optional(string)
    description          = optional(string)
  }))
  default = {}

  validation {
    condition = alltrue([
      for assignment in values(var.role_assignments) :
      assignment.principal_type == null || contains(["User", "Group", "ServicePrincipal"], coalesce(assignment.principal_type, "User"))
    ])
    error_message = "role_assignments principal_type must be null, User, Group or ServicePrincipal."
  }
}

variable "keys" {
  description = "Managed keys keyed by key name. RSA keys use key_size; EC keys use curve. rotation_policy = {} enables the default 90-day auto-rotation."
  type = map(object({
    key_type        = optional(string, "RSA")
    key_size        = optional(number, 2048)
    curve           = optional(string)
    key_opts        = optional(list(string), ["sign", "verify", "wrapKey", "unwrapKey"])
    expiration_date = optional(string)
    not_before_date = optional(string)
    rotation_policy = optional(object({
      expire_after         = optional(string, "P90D")
      notify_before_expiry = optional(string, "P29D")
      time_before_expiry   = optional(string, "P30D")
    }))
  }))
  default = {}

  validation {
    condition     = alltrue([for key in values(var.keys) : contains(["RSA", "RSA-HSM", "EC", "EC-HSM"], key.key_type)])
    error_message = "keys key_type must be RSA, RSA-HSM, EC or EC-HSM."
  }

  validation {
    condition     = alltrue([for key in values(var.keys) : contains([2048, 3072, 4096], key.key_size)])
    error_message = "keys key_size must be 2048, 3072 or 4096."
  }
}

variable "secrets" {
  description = "Secrets keyed by secret name. Values are sensitive but still land in Terraform state — prefer seeding placeholders and rotating out-of-band."
  type = map(object({
    value           = string
    content_type    = optional(string)
    expiration_date = optional(string)
    not_before_date = optional(string)
  }))
  default   = {}
  sensitive = true
}

variable "self_signed_certificates" {
  description = "Self-signed certificate scaffolding keyed by certificate name (dev/test or bootstrap use; swap the issuer for a CA in production)."
  type = map(object({
    subject                  = string
    dns_names                = optional(list(string), [])
    validity_in_months       = optional(number, 12)
    key_size                 = optional(number, 2048)
    exportable               = optional(bool, true)
    reuse_key                = optional(bool, true)
    renew_days_before_expiry = optional(number, 30)
    content_type             = optional(string, "application/x-pkcs12")
  }))
  default = {}

  validation {
    condition = alltrue([
      for cert in values(var.self_signed_certificates) :
      cert.validity_in_months >= 1 && cert.validity_in_months <= 1200 && contains([2048, 3072, 4096], cert.key_size)
    ])
    error_message = "self_signed_certificates: validity_in_months must be 1-1200 and key_size 2048/3072/4096."
  }
}

variable "diagnostic_settings" {
  description = "Audit logging to Log Analytics, a storage account and/or Event Hub."
  type = object({
    enabled                        = optional(bool, false)
    name                           = optional(string, "diag-key-vault")
    log_analytics_workspace_id     = optional(string)
    storage_account_id             = optional(string)
    eventhub_authorization_rule_id = optional(string)
    log_categories                 = optional(list(string), ["AuditEvent"])
  })
  default = {}

  validation {
    condition     = !var.diagnostic_settings.enabled || var.diagnostic_settings.log_analytics_workspace_id != null || var.diagnostic_settings.storage_account_id != null || var.diagnostic_settings.eventhub_authorization_rule_id != null
    error_message = "diagnostic_settings.enabled requires at least one destination (Log Analytics, storage account or Event Hub)."
  }
}

variable "private_endpoint" {
  description = "Optional private endpoint for the vault data plane: { subnet_id, private_dns_zone_ids (privatelink.vaultcore.azure.net), name? }."
  type = object({
    subnet_id            = string
    private_dns_zone_ids = optional(list(string), [])
    name                 = optional(string)
  })
  default = null
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
