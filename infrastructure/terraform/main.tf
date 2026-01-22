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

# Fetch IPv6 from Latitude API (provider doesn't expose it)
data "external" "server_ipv6" {
  for_each = latitudesh_server.relay

  program = ["bash", "-c", <<-EOF
    IPV6=$(curl -sf "https://api.latitude.sh/servers/${each.value.id}" \
      -H "Authorization: Bearer ${var.latitude_api_key}" | \
      jq -r '.data.ip_addresses[] | select(.family == "IPv6" and .primary == true) | .address // empty')
    echo "{\"ipv6\": \"$IPV6\"}"
  EOF
  ]

  depends_on = [latitudesh_server.relay]
}

# Regional IPv6 AAAA records
resource "cloudflare_record" "relay_regional_aaaa" {
  for_each = { for name, data in data.external.server_ipv6 : name => data if data.result.ipv6 != "" }

  zone_id = data.cloudflare_zone.oxd.id
  name    = "${var.servers[index(var.servers.*.name, each.key)].site}.relay"
  content = each.value.result.ipv6
  type    = "AAAA"
  ttl     = 300
  proxied = false
}

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

# Main IPv6 AAAA records
resource "cloudflare_record" "relay_main_aaaa" {
  for_each = { for name, data in data.external.server_ipv6 : name => data if data.result.ipv6 != "" }

  zone_id = data.cloudflare_zone.oxd.id
  name    = "relay"
  content = each.value.result.ipv6
  type    = "AAAA"
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
