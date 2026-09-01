output "id" {
  description = "The Key Vault resource ID."
  value       = azurerm_key_vault.this.id
}

output "name" {
  description = "The Key Vault name."
  value       = azurerm_key_vault.this.name
}

output "vault_uri" {
  description = "The Key Vault data-plane URI (https://<name>.vault.azure.net/)."
  value       = azurerm_key_vault.this.vault_uri
}

output "tenant_id" {
  description = "The tenant ID the vault is bound to."
  value       = azurerm_key_vault.this.tenant_id
}

output "key_ids" {
  description = "Map of key name => current versioned key ID."
  value       = { for key, kv_key in azurerm_key_vault_key.this : key => kv_key.id }
}

output "key_versionless_ids" {
  description = "Map of key name => versionless key ID (use for CMK so rotation is picked up)."
  value       = { for key, kv_key in azurerm_key_vault_key.this : key => kv_key.versionless_id }
}

output "secret_ids" {
  description = "Map of secret name => versioned secret ID."
  value       = { for key, secret in azurerm_key_vault_secret.this : key => secret.id }
}

output "certificate_ids" {
  description = "Map of certificate name => certificate ID."
  value       = { for key, cert in azurerm_key_vault_certificate.this : key => cert.id }
}

output "certificate_secret_ids" {
  description = "Map of certificate name => secret ID backing the certificate (consumable by App Gateway / App Service)."
  value       = { for key, cert in azurerm_key_vault_certificate.this : key => cert.secret_id }
}

output "role_assignment_ids" {
  description = "Map of assignment label => role assignment ID."
  value       = { for key, ra in azurerm_role_assignment.this : key => ra.id }
}

output "private_endpoint_id" {
  description = "The private endpoint ID (null when not created)."
  value       = one(azurerm_private_endpoint.this[*].id)
}

output "private_endpoint_ip_address" {
  description = "The private endpoint IP address (null when not created)."
  value       = one(azurerm_private_endpoint.this[*].private_service_connection[0].private_ip_address)
}
