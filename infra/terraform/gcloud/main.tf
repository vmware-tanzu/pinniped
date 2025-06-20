# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Create the static IP.
module "address" {
  source = "./address"

  sharedVPCProject    = var.sharedVPCProject
  concourseSubnetName = var.concourseSubnetName
}

# Create the GKE Kubernetes cluster.
module "cluster" {
  source = "./cluster"

  name    = "pinniped-concourse"
  project = var.project
  zone    = var.zone

  sharedVPCProject = var.sharedVPCProject
  networkName      = var.networkName
  subnetName       = var.concourseSubnetName

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
      version      = "1.32.2-gke.1297002"
    },

    "workers-1" = {
      auto-upgrade = true
      disk-size    = "100"
      disk-type    = "pd-ssd"
      image        = "UBUNTU_CONTAINERD"
      local-ssds   = 0
      machine-type = "c3-standard-8" # 8 vCPU and 32 GB memory
      max          = 5
      min          = 1
      preemptible  = false
      version      = "1.32.2-gke.1297002"
    },
  }
}

# Creates the CloudSQL Postgres database to be used by the Concourse deployment.
module "database" {
  source = "./database"

  name   = "pinniped-concourse"
  region = var.region
  zone   = var.zone

  sharedVPCProject = var.sharedVPCProject
  networkName      = var.networkName

  cpus            = "4"
  memory_mb       = "7680"
  max_connections = "300"
}
