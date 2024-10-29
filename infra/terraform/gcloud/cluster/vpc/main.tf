# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

resource "google_compute_network" "main" {
  name = var.name

  auto_create_subnetworks = "false"
}

resource "google_compute_subnetwork" "main" {
  name = "${var.name}-sn-1"

  ip_cidr_range = var.vms-cidr
  network       = google_compute_network.main.name
  region        = var.region

  secondary_ip_range = [
    {
      range_name    = var.pods-range-name
      ip_cidr_range = var.pods-cidr
    },
    {
      range_name    = var.services-range-name
      ip_cidr_range = var.services-cidr
    }
  ]
}

resource "google_compute_firewall" "internal-ingress" {
  name = "${var.name}-internal"

  network   = google_compute_network.main.name
  direction = "INGRESS"

  source_ranges = [
    var.vms-cidr,
    var.pods-cidr,
    var.services-cidr,
  ]

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }
}

resource "google_compute_firewall" "external-ingress" {
  name      = "${var.name}-external"
  network   = google_compute_network.main.name
  direction = "INGRESS"

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}
