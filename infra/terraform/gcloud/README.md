# Terraform for Google Cloud Concourse Infrastructure

We used Terraform to create the infra needed for running our own Concourse.
This includes things like a GKE cluster, a static IP, a DNS entry, and a Postgres database.

NOTE: Do not manually edit these resources using the Google Cloud UI, API, or CLI.
Instead, please update the `.tf` files and follow the below steps again.

To run Terraform to create or update the infrastructure:

1. If running for the first time ever, log in to the GCP Console for the project and
   create the GCS storage bucket where terraform will save its state (see [gcp.tf](gcp.tf) for the bucket name).
   Creating the bucket in one region (see [variables.tf](variables.tf) for the region name)
   with otherwise default options should suffice.
2. Install the `gcloud` CLI and authenticate as yourself using `gcloud auth login`, if you haven't already.
3. Use `gcloud auth application-default login` if you haven't already. This is not optional. If you forget this step,
   terraform will complain that it cannot read the state from the GCP bucket file.
4. Install terraform if you haven't already. Use brew to install terraform,
   or use `brew install tfenv` and then use tfenv to install Terraform.
   At the time of last updating this README, we were using Terraform v1.12.2.
5. cd into this directory: `cd infra/terraform/gcloud`
6. Run `TF_VAR_project=$PINNIPED_GCP_PROJECT terraform init`, if you haven't already for this directory.
   This assumes that you have already exported an env var called `PINNIPED_GCP_PROJECT`
   whose value is the name of the GCP project.
7. Run `terraform fmt`.
8. Run `terraform validate`.
9. Run
   `TF_VAR_project=$PINNIPED_GCP_PROJECT TF_VAR_sharedVPCProject=$VPC_PROJECT TF_VAR_networkName=$VPC_NAME TF_VAR_concourseSubnetName=$SUBNET_NAME terraform plan`.
   This assumes that you have already exported an env var called `PINNIPED_GCP_PROJECT`
   whose value is the name of the GCP project, along with `VPC_PROJECT` which is the name
   of another GCP project which is sharing a VPC network to our project, `VPC_NAME` which is
   the name of that shared VPC, and `SUBNET_NAME` which is the name of a subnet from that
   shared VPC that we want to give to our Concourse GKE cluster.
   This command is a dry-run which will print what the `apply` command would perform.
10. If you are happy with the output of `terraform plan`, then run
    `TF_VAR_project=$PINNIPED_GCP_PROJECT TF_VAR_sharedVPCProject=$VPC_PROJECT TF_VAR_networkName=$VPC_NAME TF_VAR_concourseSubnetName=$SUBNET_NAME terraform apply`
    to really create/update/delete the resources.

If you do not need to run `terraform apply` because someone else has already done that,
then you still need to follow the above directions up to and including running `terraform init`
to set up terraform on your computer.

To delete the entire Concourse deployment and all its related cloud infrastructure, use `terraform destroy`.
You may need to use `terraform apply` to set `deletion_protection=false` on some resources first (see Terraform docs).
There is no way to undo `terraform destroy`. This will also delete the Cloud SQL database which contains all CI job
history.
