# Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

terraform {
  required_providers {
    google      = "~> 6"
    google-beta = "~> 6"
  }

  backend "gcs" {
    # By not providing credentials, you will use your current identity from the gcloud CLI.
    # credentials = "gcp.json"
    bucket = "pinniped-ci-terraform-state"
    prefix = "pinniped-concourse"
  }
}

provider "google" {
  # By not providing credentials, you will use your current identity from the gcloud CLI.
  # credentials = "gcp.json"
  project = var.project
  region  = var.region
  zone    = var.zone
}

# `google-beta` provides us access to GCP's beta APIs.
provider "google-beta" {
  # By not providing credentials, you will use your current identity from the gcloud CLI.
  # credentials = "gcp.json"
  project = var.project
  region  = var.region
  zone    = var.zone
}
