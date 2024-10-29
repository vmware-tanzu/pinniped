# Installing and operating Concourse

Concourse is made up of a web deployment a worker deployment.

## Terraform

We use Terraform to create and update the IaaS infrastructure on which we run all the Concourse components.
This infrastructure must be created before deploying the corresponding Concourse components.

### Infrastructure Providers

We use Google Cloud for the infrastructure.

### Running Terraform

See [infra/terraform/gcloud/README.md](./terraform/gcloud/README.md) for details of using Terraform
to create or update the Google Cloud infrastructure for Concourse. This infrastructure will be used
to run the web and internal workers.

## Bootstrapping Secrets (after Terraform)

Before deploying Concourse for the first time, the
[infra/concourse-install/bootstrap-secrets.sh](./concourse-install/bootstrap-secrets.sh)
script must be used to auto-generate some values and store them in a new secret in the Secrets Manager.
This script only needs to be run once.

1. Create a github oauth client as described in https://concourse-ci.org/github-auth.html.
   The callback URI should be set to `https://ci.pinniped.dev/sky/issuer/callback`.
   Take note of the client ID and client secret for use in the next step.
2. Run `GITHUB_CLIENT_ID=<your_client_id> GITHUB_CLIENT_SECRET=<your_client_secret> ./bootstrap-secrets.sh`.
   This will create a secret in the GCP Secrets Manager which includes the GitHub client info
   along with some auto-generated secrets.

## Web Deployment

The "brains" of Concourse is its web deployment. It can be created and updated by running the
[infra/concourse-install/deploy-concourse-web.sh](./concourse-install/deploy-concourse-web.sh)
script on your laptop.

## Worker Deployments

We run our workers on the same GKE cluster where we run the web component.

See [infra/concourse-install/*-internal-workers.sh](./concourse-install) for scripts to deploy/update the workers,
scale the workers, and view the workers.

These workers can also be scaled by the jobs in the `concourse-workers` pipeline.

## Upgrading Concourse

To upgrade each deployment to a new version of Concourse:

1. If any infrastructure updates are needed, follow the terraform instructions again.
2. Change the version of the Helm Chart in the source code of the script used to create each deployment,
   and then run each script to upgrade the deployment. Note that this will scale the internal workers deployment
   back to its default number of replicas.
   1. [infra/concourse-install/deploy-concourse-web.sh](./concourse-install/deploy-concourse-web.sh)
   2. [infra/concourse-install/deploy-concourse-web.sh](./concourse-install/deploy-concourse-internal-workers.sh)
3. Commit and push those script changes. 
4. Trigger the CI jobs to scale the internal workers back to the desired number as needed.
