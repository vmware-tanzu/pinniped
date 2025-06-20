# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

output "project" {
  value = var.project
}

output "region" {
  value = var.region
}

output "zone" {
  value = var.zone
}

output "web-ip" {
  value = module.address.ip
}

output "database-ip" {
  value = module.database.ip
}

output "database-ca-cert" {
  sensitive = true
  value     = module.database.ca-cert
}

output "database-username" {
  value = module.database.username
}

output "database-password" {
  sensitive = true
  value     = module.database.password
}

output "database-cert" {
  sensitive = true
  value     = module.database.cert
}

output "database-private-key" {
  sensitive = true
  value     = module.database.private-key
}

output "cluster-name" {
  value = module.cluster.cluster-name
}
