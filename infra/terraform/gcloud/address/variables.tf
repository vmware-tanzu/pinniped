# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

variable "sharedVPCProject" {
  description = "Name of the GCP project which contains the shared VPC."
  type        = string
}

variable "concourseSubnetName" {
  description = "Name of the GCP subnet to use for concourse."
  type        = string
}
