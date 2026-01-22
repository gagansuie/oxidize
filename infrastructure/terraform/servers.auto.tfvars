# Oxidize Relay Servers
# Add servers here - Terraform will provision them automatically

environment = "production"

servers = [
  {
    name    = "chicago-1"
    region  = "chicago"
    site    = "chi"
    plan    = "m4-metal-small"
    os      = "ubuntu_22_04_x64_lts"
    enabled = true
  },

  # Add more servers:
  # {
  #   name    = "chicago-2"
  #   region  = "chicago"
  #   site    = "chi"
  #   plan    = "m4-metal-small"
  #   os      = "ubuntu_22_04_x64_lts"
  #   enabled = true
  # },
  #
  # {
  #   name    = "frankfurt-1"
  #   region  = "frankfurt"
  #   site    = "fra"
  #   plan    = "m4-metal-small"
  #   os      = "ubuntu_22_04_x64_lts"
  #   enabled = true
  # },
]
