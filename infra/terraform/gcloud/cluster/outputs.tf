# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

output "cluster-name" {
  value = google_container_cluster.main.name
}
