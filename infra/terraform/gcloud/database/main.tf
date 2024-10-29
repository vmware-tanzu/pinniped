# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# A piece of randomization that gets consumed by the
# `google_sql_database_instance` resources.
#
# This is needed in order to facilitate creating and recreating instances
# without waiting for the whole period that GCP requires to reuse name.
resource "random_id" "instance-name" {
  byte_length = 4
}

resource "google_sql_database_instance" "main" {
  name             = "${var.name}-${random_id.instance-name.hex}"
  region           = var.region
  database_version = "POSTGRES_15"

  settings {
    availability_type = "ZONAL"
    disk_autoresize   = true
    disk_type         = "PD_SSD"
    tier              = "db-custom-${var.cpus}-${var.memory_mb}"

    database_flags {
      name  = "log_min_duration_statement"
      value = "-1"
    }

    database_flags {
      name  = "max_connections"
      value = var.max_connections
    }

    ip_configuration {
      ipv4_enabled = "true"
      require_ssl  = "true"

      authorized_networks {
        name  = "all"
        value = "0.0.0.0/0"
      }
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

  instance = google_sql_database_instance.main.name
  password = random_string.password.result
}

resource "google_sql_ssl_cert" "cert" {
  common_name = "atc"
  instance    = google_sql_database_instance.main.name
}
