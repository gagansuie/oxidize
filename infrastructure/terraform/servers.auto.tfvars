# Oxidize Relay Servers
# Add servers here - Terraform will provision them automatically

environment = "production"

servers = [
  {
    name      = "relay-chi-1"
    region    = "chicago"
    site      = "chi"
    plan      = "m4-metal-small"
    os        = "ubuntu_24_04_x64_lts"
    enabled   = true
    cf_region = "WNAM"  # Cloudflare: Western North America
  },

  # Add more servers:
  # {
  #   name      = "relay-chi-2"
  #   region    = "chicago"
  #   site      = "chi"
  #   plan      = "m4-metal-small"
  #   os        = "ubuntu_24_04_x64_lts"
  #   enabled   = true
  #   cf_region = "WNAM"
  # },
  #
  # {
  #   name      = "relay-fra-1"
  #   region    = "frankfurt"
  #   site      = "fra"
  #   plan      = "m4-metal-small"
  #   os        = "ubuntu_24_04_x64_lts"
  #   enabled   = true
  #   cf_region = "WEUR"  # Western Europe
  # },
  #
  # {
  #   name      = "relay-tok-1"
  #   region    = "tokyo"
  #   site      = "tok"
  #   plan      = "m4-metal-small"
  #   os        = "ubuntu_24_04_x64_lts"
  #   enabled   = true
  #   cf_region = "APAC"  # Asia Pacific
  # },
]
