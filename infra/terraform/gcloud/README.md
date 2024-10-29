# Terraform for Google Cloud Concourse Infrastructure

We used Terraform to create the infra needed for running our own Concourse.
This includes things like a GKE cluster, a static IP, a DNS entry, and a Postgres database.

NOTE: Do not manually edit these resources using the Google Cloud UI, API, or CLI.
Instead, please update the `.tf` files and follow the below steps again.

To run Terraform to create or update the infrastructure:
1. Install the `gcloud` CLI and authenticate as yourself, if you haven't already.
2. Use `gcloud auth application-default login` if you haven't already. This is not optional.
3. Install terraform if you haven't already. Use brew or brew install tfenv and then use tfenv.
   At the time of writing this README, we were using Terraform v1.6.6.
4. cd into this directory: `cd infra/terraform/gcloud`
5. Run `terraform init`, if you haven't already for this directory.
6. Run `terraform fmt`.
7. Run `terraform validate`.
8. Run `TF_VAR_project=$PINNIPED_GCP_PROJECT terraform apply`.
   This assumes that you have already exported an env var called `PINNIPED_GCP_PROJECT`
   whose value is the name of the GCP project.

If you do not need to run `terraform apply` because someone else has already done that,
then you still need to follow the above directions up to and including running `terraform init`
to set up terraform on your computer.

To delete the entire Concourse deployment and all its related cloud infrastructure,
use `terraform destroy`. There is no way to undo this action. This will also delete the Cloud SQL
database which contains all CI job history.
