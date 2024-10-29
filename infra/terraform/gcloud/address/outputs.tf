# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

output "ip" {
  value = google_compute_address.main.address
}

output "hostname" {
  value = trimsuffix(google_dns_record_set.main.name, ".")
}
