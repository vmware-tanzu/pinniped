# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

output "name" {
  value = google_compute_network.main.name
}

output "subnet-name" {
  value = google_compute_subnetwork.main.name
}

output "pods-range-name" {
  value = var.pods-range-name
}

output "services-range-name" {
  value = var.services-range-name
}

output "uri" {
  value = google_compute_network.main.self_link
}
