# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# The static IP and related DNS entry.
module "address" {
  source = "./address"

  dns-zone  = var.dns-zone
  subdomain = var.subdomain
}

# Instantiates the GKE Kubernetes cluster.
module "cluster" {
  source = "./cluster"

  name    = "pinniped-concourse"
  project = var.project
  region  = var.region
  zone    = var.zone

  node-pools = {

    "generic-1" = {
      auto-upgrade = true
      disk-size    = "50"
      disk-type    = "pd-ssd"
      image        = "COS_CONTAINERD"
      local-ssds   = 0
      machine-type = "e2-highcpu-8" # 8 vCPU and 4 GB memory
      max          = 2
      min          = 1
      preemptible  = false
      version      = "1.30.4-gke.1348000"
    },

    "workers-2" = {
      auto-upgrade = true
      disk-size    = "100"
      disk-type    = "pd-ssd"
      image        = "UBUNTU_CONTAINERD"
      local-ssds   = 0
      machine-type = "c3-standard-8" # 8 vCPU and 32 GB memory
      max          = 5
      min          = 1
      preemptible  = false
      version      = "1.30.4-gke.1348000"
    },
  }
}

# Creates the CloudSQL Postgres database to be used by the Concourse deployment.
module "database" {
  source = "./database"

  name            = "pinniped-concourse"
  cpus            = "4"
  memory_mb       = "7680"
  region          = var.region
  zone            = var.zone
  max_connections = "300"
}
