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
    ignore_changes  = [ssh_keys, tags, hostname, operating_system]
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
# Cloudflare DNS - Automatic DNS management
# =============================================================================

data "cloudflare_zone" "oxd" {
  name = var.cloudflare_zone
}

# Regional DNS records (e.g., chi.relay.oxd.sh)
# Multiple servers in same region = round-robin load balancing
resource "cloudflare_record" "relay_regional_a" {
  for_each = { for name, server in latitudesh_server.relay : name => server }

  zone_id = data.cloudflare_zone.oxd.id
  name    = "${var.servers[index(var.servers.*.name, each.key)].site}.relay"
  content = each.value.primary_ipv4
  type    = "A"
  ttl     = 300
  proxied = false  # Must be false for QUIC/UDP
}

# Note: IPv6 AAAA records created via workflow after server provisioning
# (latitudesh provider doesn't expose IPv6, and external data can't be used with for_each)

# Main relay.oxd.sh points to all servers (global round-robin)
resource "cloudflare_record" "relay_main_a" {
  for_each = { for name, server in latitudesh_server.relay : name => server }

  zone_id = data.cloudflare_zone.oxd.id
  name    = "relay"
  content = each.value.primary_ipv4
  type    = "A"
  ttl     = 300
  proxied = false
}

output "dns_records" {
  description = "Created DNS records"
  value = {
    regional = [for r in cloudflare_record.relay_regional_a : "${r.name}.${var.cloudflare_zone} -> ${r.content}"]
    main     = [for r in cloudflare_record.relay_main_a : "${r.name}.${var.cloudflare_zone} -> ${r.content}"]
  }
}
