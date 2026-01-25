terraform {
  required_version = ">= 1.0"

  cloud {
    organization = "oxidize"
    workspaces {
      name = "oxidize-infrastructure"
    }
  }

  required_providers {
    latitudesh = {
      source  = "latitudesh/latitudesh"
      version = "~> 1.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "latitudesh" {
  auth_token = var.latitude_api_key
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

resource "latitudesh_server" "relay" {
  for_each = { for server in var.servers : server.name => server if server.enabled }

  project          = var.latitude_project_id
  plan             = each.value.plan
  site             = each.value.site
  operating_system = each.value.os
  hostname         = each.value.name
  ssh_keys         = [var.latitude_ssh_key_id]

  tags = [
    "environment:${var.environment}",
    "region:${each.value.region}",
    "managed_by:terraform"
  ]

  lifecycle {
    prevent_destroy = true
    ignore_changes  = all
  }
}

output "server_ips" {
  description = "Map of server names to IPs"
  value = {
    for name, server in latitudesh_server.relay : name => server.primary_ipv4
  }
}

output "ansible_inventory" {
  description = "Ansible inventory in INI format"
  value = templatefile("${path.module}/templates/inventory.tpl", {
    servers = latitudesh_server.relay
  })
}

# =============================================================================
# Cloudflare Load Balancer - Smart DNS routing with health checks
# =============================================================================

data "cloudflare_zone" "oxd" {
  name = var.cloudflare_zone
}

locals {
  # Get account ID from zone (no need to hardcode or add extra API permissions)
  cloudflare_account_id = data.cloudflare_zone.oxd.account_id
}

# Note: Cloudflare Load Balancer removed - UDP traffic cannot be proxied by CF
# Server discovery is handled by /api/servers endpoint which returns server IPs
# Tauri app connects directly to server IPs from the API response
