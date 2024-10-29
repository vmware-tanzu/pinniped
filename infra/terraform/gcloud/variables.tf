# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

variable "project" {
  description = "The Google GCP project to host the resources"
  type        = string
  # Please provide the value of this variable by setting the env var TF_VAR_project for all terraform commands.
}

variable "region" {
  description = "The cloud provider region where the resources created"
  default     = "us-central1"
}

variable "zone" {
  description = "The cloud provider zone where the resources are created"
  default     = "us-central1-c"
}

variable "dns-zone" {
  description = "The default DNS zone to use when creating subdomains"
  default     = "pinniped-dev"
}

variable "subdomain" {
  description = "Subdomain under the DNS zone to register"
  default     = "ci"
}
