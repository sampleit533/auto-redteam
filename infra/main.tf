terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

variable "run_id" {
  description = "Unique run identifier — used to namespace all resources"
  type        = string
}

# Isolated sandbox network — no internet access
resource "docker_network" "sandbox" {
  name     = "rt-sandbox-${var.run_id}"
  internal = true

  labels {
    label = "auto-redteam"
    value = var.run_id
  }
}

output "sandbox_network_name" {
  value = docker_network.sandbox.name
}

output "sandbox_network_id" {
  value = docker_network.sandbox.id
}
