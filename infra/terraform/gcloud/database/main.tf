# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# A piece of randomization that gets consumed by the
# `google_sql_database_instance` resources.
#
# This is needed in order to facilitate creating and recreating instances
# without waiting for the whole period that GCP requires to reuse name.
resource "random_id" "instance-name" {
  byte_length = 4
}

# "data" reads a pre-existing resource without trying to manage its state.
data "google_compute_network" "private_network" {
  provider = google-beta

  project = var.sharedVPCProject
  name    = var.networkName
}

# This API needs to be enabled in our project before creating our Cloud SQL instance,
# or else we get error "googleapi: Error 400: Invalid request: Incorrect Service Networking config
# for instance: xxx:xxx:SERVICE_NETWORKING_NOT_ENABLED., invalid".
# See https://stackoverflow.com/a/66537918.
resource "google_project_service" "project" {
  service            = "servicenetworking.googleapis.com"
  disable_on_destroy = false
}

resource "google_sql_database_instance" "main" {
  provider = google-beta

  # Allow "terraform destroy" for this db.
  # deletion_protection = false

  name             = "${var.name}-${random_id.instance-name.hex}"
  region           = var.region
  database_version = "POSTGRES_15"

  settings {
    availability_type = "ZONAL"
    disk_autoresize   = true
    disk_type         = "PD_SSD"
    tier              = "db-custom-${var.cpus}-${var.memory_mb}"
    edition           = "ENTERPRISE" # cheaper than ENTERPRISE_PLUS

    database_flags {
      name  = "log_min_duration_statement"
      value = "-1"
    }

    database_flags {
      name  = "max_connections"
      value = var.max_connections
    }

    ip_configuration {
      # Disable assignment of a public IP address
      ipv4_enabled = false

      ssl_mode = "ENCRYPTED_ONLY"

      private_network = data.google_compute_network.private_network.self_link

      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled    = true
      start_time = "23:00"
    }

    location_preference {
      zone = var.zone
    }
  }
}

resource "google_sql_database" "atc" {
  name = "atc"

  instance  = google_sql_database_instance.main.name
  charset   = "UTF8"
  collation = "en_US.UTF8"
}

resource "random_string" "password" {
  length  = 32
  special = true
}

resource "google_sql_user" "user" {
  name = "atc"

  instance    = google_sql_database_instance.main.name
  password_wo = random_string.password.result
}

resource "google_sql_ssl_cert" "cert" {
  common_name = "atc"
  instance    = google_sql_database_instance.main.name
}
