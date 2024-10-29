# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

module "vpc" {
  source = "./vpc"

  name   = var.name
  region = var.region

  vms-cidr      = "10.10.0.0/16"
  pods-cidr     = "10.11.0.0/16"
  services-cidr = "10.12.0.0/16"
}

resource "google_service_account" "default" {
  account_id   = "${var.name}-sa"
  display_name = "GKE Node SA for ${var.name}"
}

# See https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster
resource "google_container_cluster" "main" {
  # Allow "terraform destroy" for this cluster.
  deletion_protection = false

  name     = var.name
  location = var.zone

  network    = module.vpc.name
  subnetwork = module.vpc.subnet-name

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. This allows node pools to be added and removed without recreating the cluster.
  # So we create the smallest possible default node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1

  min_master_version = "1.30.4-gke.1348000"

  ip_allocation_policy {
    cluster_secondary_range_name  = module.vpc.pods-range-name
    services_secondary_range_name = module.vpc.services-range-name
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

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.default.email
    oauth_scopes    = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }

  timeouts {
    create = "30m"
    delete = "30m"
  }
}
