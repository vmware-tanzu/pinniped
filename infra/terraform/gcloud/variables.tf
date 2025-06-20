# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

variable "project" {
  description = "The Google GCP project to host the resources."
  type        = string
  # Please provide the value of this variable by setting the env var TF_VAR_project for all terraform commands.
}

variable "region" {
  description = "The cloud provider region where the resources created."
  default     = "us-west1"
}

variable "zone" {
  description = "The cloud provider zone where the resources are created."
  default     = "us-west1-c"
}

variable "sharedVPCProject" {
  description = "Name of the GCP project which contains the shared VPC."
  type        = string
  # Please provide the value of this variable by setting the env var TF_VAR_sharedVPCProject for all terraform commands.
}

variable "networkName" {
  description = "Name of the shared VPC network."
  type        = string
  # Please provide the value of this variable by setting the env var TF_VAR_networkName for all terraform commands.
}

variable "concourseSubnetName" {
  description = "Name of the GCP subnet to use for concourse."
  type        = string
  # Please provide the value of this variable by setting the env var TF_VAR_concourseSubnetName for all terraform commands.
}
