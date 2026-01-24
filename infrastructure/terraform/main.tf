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

# Build a map of unique regions from servers
locals {
  # Group servers by site (region code)
  servers_by_site = {
    for site in distinct([for s in var.servers : s.site if s.enabled]) :
    site => [for name, server in latitudesh_server.relay : server if var.servers[index(var.servers.*.name, name)].site == site]
  }
}

# Health check monitor - checks /health endpoint on port 9090
resource "cloudflare_load_balancer_monitor" "relay_health" {
  account_id     = local.cloudflare_account_id
  type           = "http"
  port           = 9090
  path           = "/health"
  expected_body  = "healthy"
  expected_codes = "200"
  description    = "Oxidize relay health check"
  # Note: interval, retries, timeout use Cloudflare defaults (plan-dependent)
}

# Create a pool for each region
resource "cloudflare_load_balancer_pool" "relay_region" {
  for_each = local.servers_by_site

  account_id = local.cloudflare_account_id
  name       = "relay-${each.key}"
  monitor    = cloudflare_load_balancer_monitor.relay_health.id

  dynamic "origins" {
    for_each = each.value
    content {
      name    = origins.value.hostname
      address = origins.value.primary_ipv4
      enabled = true
      weight  = 1
    }
  }
}

# Main load balancer at relay.oxd.sh
resource "cloudflare_load_balancer" "relay" {
  zone_id          = data.cloudflare_zone.oxd.id
  name             = "relay.${var.cloudflare_zone}"
  fallback_pool_id = cloudflare_load_balancer_pool.relay_region[keys(local.servers_by_site)[0]].id
  default_pool_ids = [for pool in cloudflare_load_balancer_pool.relay_region : pool.id]
  steering_policy  = "geo"  # Route to closest region

  # Map Cloudflare regions to our pools (cf_region from server config)
  dynamic "region_pools" {
    for_each = local.servers_by_site
    content {
      region   = var.servers[index(var.servers.*.site, region_pools.key)].cf_region
      pool_ids = [cloudflare_load_balancer_pool.relay_region[region_pools.key].id]
    }
  }
}

output "load_balancer" {
  description = "Load balancer configuration"
  value = {
    hostname = cloudflare_load_balancer.relay.name
    pools    = [for name, pool in cloudflare_load_balancer_pool.relay_region : "${name}: ${pool.name}"]
  }
}
