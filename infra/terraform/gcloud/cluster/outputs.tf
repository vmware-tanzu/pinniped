# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

output "vpc-uri" {
  value = module.vpc.uri
}

output "cluster-name" {
  value = google_container_cluster.main.name
}
