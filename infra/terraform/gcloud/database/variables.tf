# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

variable "name" {
  default     = ""
  description = "The name of the CloudSQL instance to create (ps.: a random ID is appended to this name)."
}

variable "memory_mb" {
  default     = ""
  description = "Number of MBs to assign to the CloudSQL instance."
}

variable "cpus" {
  default     = ""
  description = "Number of CPUs to assign to the CloudSQL instance."
}

variable "zone" {
  default     = ""
  description = "The zone where this instance is supposed to be created at (e.g., us-central1-a)."
}

variable "region" {
  default     = ""
  description = "The region where the instance is supposed to be created at (e.g., us-central1)."
}

variable "max_connections" {
  default     = ""
  description = "The max number of connections allowed by postgres."
}

variable "sharedVPCProject" {
  description = "Name of the GCP project which contains the shared VPC."
  type        = string
}

variable "networkName" {
  description = "Name of the shared VPC network to use for the db."
  type        = string
}
