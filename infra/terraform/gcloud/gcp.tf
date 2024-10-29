# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

terraform {
  required_providers {
    google      = "~> 5"
    google-beta = "~> 5"
  }

  backend "gcs" {
    # By not providing credentials, you will use your current identity from the gcloud CLI.
    # credentials = "gcp.json"
    bucket = "tanzu-user-authentication-terraform-state"
    prefix = "pinniped-concourse-jan2024"
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
