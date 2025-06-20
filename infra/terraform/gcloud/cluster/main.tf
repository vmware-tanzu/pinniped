# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# "data" reads a pre-existing resource without trying to manage its state.
data "google_compute_network" "existing_network" {
  project = var.sharedVPCProject
  name    = var.networkName
}

# This subnet is shared with us from another GCP project.
data "google_compute_subnetwork" "existing_subnet" {
  project = var.sharedVPCProject
  name    = var.subnetName
}

data "google_service_account" "default" {
  account_id = "terraform"
}

# See https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster
resource "google_container_cluster" "main" {
  # Allow "terraform destroy" for this cluster.
  # deletion_protection = false

  name     = var.name
  location = var.zone

  network    = data.google_compute_network.existing_network.id
  subnetwork = data.google_compute_subnetwork.existing_subnet.id

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. This allows node pools to be added and removed without recreating the cluster.
  # So we create the smallest possible default node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1

  min_master_version = "1.32.2-gke.1297002"

  # Settings for a private cluster.
  # See internal doc https://bsg-confluence.broadcom.net/pages/viewpage.action?pageId=689720737
  networking_mode = "VPC_NATIVE"
  private_cluster_config {
    enable_private_endpoint = true
    enable_private_nodes    = true
  }
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "10.0.0.0/8"
      display_name = "corp internal networks"
    }
  }
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }

    horizontal_pod_autoscaling {
      disabled = false
    }

    network_policy_config {
      disabled = false
    }
  }

  maintenance_policy {
    daily_maintenance_window {
      start_time = "03:00"
    }
  }

  network_policy {
    provider = "CALICO"
    enabled  = true
  }

  workload_identity_config {
    workload_pool = "${var.project}.svc.id.goog"
  }

  cluster_autoscaling {
    autoscaling_profile = "OPTIMIZE_UTILIZATION"
  }
}

# See https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_node_pool
resource "google_container_node_pool" "main" {
  provider = google-beta
  for_each = var.node-pools

  location = var.zone
  cluster  = google_container_cluster.main.name
  name     = each.key

  max_pods_per_node = 64

  autoscaling {
    min_node_count = each.value.min
    max_node_count = each.value.max
  }

  management {
    auto_repair  = true
    auto_upgrade = each.value.auto-upgrade
  }

  node_config {
    preemptible     = each.value.preemptible
    machine_type    = each.value.machine-type
    local_ssd_count = each.value.local-ssds
    disk_size_gb    = each.value.disk-size
    disk_type       = each.value.disk-type
    image_type      = each.value.image

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }

    service_account = data.google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    # Tag to attach appropriate firewall rules.
    tags = ["gke-broadcom"]
  }

  timeouts {
    create = "30m"
    delete = "30m"
  }
}
