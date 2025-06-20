# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# "data" reads a pre-existing resource without trying to manage its state.
# This subnet is shared with us from another GCP project.
data "google_compute_subnetwork" "existing_subnet_for_concourse" {
  project = var.sharedVPCProject
  name    = var.concourseSubnetName
}

# Reserved internal static IPv4 address for the `web` instances.
# This is needed so that we can have a static IP for `ci.pinniped.broadcom.net`.
resource "google_compute_address" "main" {
  name         = "ci-pinniped-dev"
  description  = "static IP address reserved for Concourse web interface"
  subnetwork   = data.google_compute_subnetwork.existing_subnet_for_concourse.id
  address_type = "INTERNAL"

  # Allow it to be shared by multiple load balancers (each with different ports).
  # We will have one for web and one for web-worker-gateway.
  purpose = "SHARED_LOADBALANCER_VIP"

  # Manually picked an IP from the range that did not cause an error when entered
  # into GCP's "VPC Network / IP address / Reserve internal static IP" UI for this subnet.
  address = "10.31.141.90"
}
