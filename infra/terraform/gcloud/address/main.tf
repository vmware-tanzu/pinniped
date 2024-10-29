# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Use our pre-existing DNS zone.
data "google_dns_managed_zone" "main" {
  name = var.dns-zone
}

# Reserved external static IPv4 address for the `web` instances.
# This is needed so that we can have a static IP for `ci.pinniped.dev`.
resource "google_compute_address" "main" {
  name = "${var.subdomain}-${var.dns-zone}"
}

# Make a DNS A record for our subdomain to point at our new static IP.
resource "google_dns_record_set" "main" {
  name = "${var.subdomain}.${data.google_dns_managed_zone.main.dns_name}"
  type = "A"
  ttl  = 300

  managed_zone = data.google_dns_managed_zone.main.name

  rrdatas = [
    google_compute_address.main.address,
  ]
}
