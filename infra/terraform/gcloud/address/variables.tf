# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

variable "dns-zone" {
  description = "Name of the DNS zone"
  type        = string
}

variable "subdomain" {
  description = "Subdomain under the DNS zone to register"
  type        = string
}
