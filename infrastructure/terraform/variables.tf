variable "latitude_api_key" {
  description = "Latitude.sh API key"
  type        = string
  sensitive   = true
}

variable "environment" {
  description = "Environment name (production, staging)"
  type        = string
  default     = "production"
}

variable "servers" {
  description = "List of servers to provision"
  type = list(object({
    name    = string
    region  = string
    site    = string
    plan    = string
    os      = string
    enabled = bool
  }))
  default = []
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token with DNS edit permissions"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone" {
  description = "Cloudflare zone name (domain)"
  type        = string
  default     = "oxd.sh"
}
