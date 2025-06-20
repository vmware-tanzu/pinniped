# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

variable "name" {
  default     = ""
  description = "The name of the GKE cluster to be created."
}

variable "zone" {
  default     = ""
  description = "The zone where the cluster should live."
}

variable "project" {
  description = "The Google GCP project to host the resources."
}

variable "node-pools" {
  description = "A list of node pool configurations to create and assign to the cluster."
}

variable "sharedVPCProject" {
  description = "Name of the GCP project which contains the shared VPC."
  type        = string
}

variable "networkName" {
  description = "Name of the shared VPC network to use for the cluster."
  type        = string
}

variable "subnetName" {
  description = "Name of the GCP subnet to use for the cluster."
  type        = string
}
