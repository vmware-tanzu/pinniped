# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

variable "name" {
  description = "TODO"
}

variable "region" {
  description = "TODO"
}

variable "vms-cidr" {
  description = "TODO"
}

variable "pods-cidr" {
  description = "TODO"
}

variable "pods-range-name" {
  default     = "pods-range"
  description = "TODO"
}

variable "services-cidr" {
  description = "TODO"
}

variable "services-range-name" {
  default     = "services-range"
  description = "TODO"
}
