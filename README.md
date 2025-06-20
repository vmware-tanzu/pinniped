# Pinniped's `ci` branch

This `ci` branch contains the CI/CD tooling for [Pinniped](https://github.com/vmware-tanzu/pinniped).

The documentation and code in this branch is mainly intended for the maintainers of Pinniped.

This branch is not intended to be merged to the `main` branch.

The code in the branch previously lived in a private repository. It was made public by moving
the code into the `ci` branch of the Pinniped repository in late 2024. The previous git history
for these files was not copied from the private repository at the time of this migration.

## Reporting an issue in this branch

Found a bug or would like to make an enhancement request?
Please report issues in [this repo](https://github.com/vmware-tanzu/pinniped).

## Reporting security vulnerabilities

Please follow the procedure described in [SECURITY.md](https://github.com/vmware-tanzu/pinniped/blob/main/SECURITY.md).

## Creating a release

When the team is preparing to ship a release, a maintainer will create a new
GitHub [Issue](https://github.com/vmware-tanzu/pinniped/issues/new/choose) in this repo to
collaboratively track progress on the release checklist. As tasks are completed,
the team will check them off. When all the tasks are completed, the issue is closed.

The release checklist is committed to this repo as an [issue template](https://github.com/vmware-tanzu/pinniped/tree/main/.github/ISSUE_TEMPLATE/release_checklist.md).

## Pipelines

Pinniped uses [Concourse](https://concourse-ci.org) for CI/CD.
We are currently running our Concourse on a network that can only be reached from inside the corporate network at [ci.pinniped.broadcom.net](https://ci.pinniped.broadcom.net).

The following pipelines are implemented in this branch. Not all pipelines are necessarily publicly visible, although our goal is to make them all visible.

- `main`

  This is the main pipeline that runs on merges to `main`. It builds, tests, and (when manually triggered) releases from main.

- `pull-requests`

  This is a pipeline that triggers for each open pull request. It runs a smaller subset of the integration tests and validations as `pinniped`.

- `dockerfile-builders`

  This pipeline builds a bunch of custom utility container images that are used in our CI and testing.

  - `build-gi-cli` (a container image that includes the GitHub CLI)
  - `build-github-pr-resource` (a [fork](https://github.com/pinniped-ci-bot/github-pr-resource) of the `github-pr-resource` with support for gating PRs for untrusted users)
  - `build-code-coverage-uploader` (uploading code coverage during unit tests)
  - `build-eks-deployer-dockerfile` (deploying our app to EKS clusters)
  - `build-k8s-app-deployer-dockerfile` (deploying our app to clusters)
  - `build-pool-trigger-resource-dockerfile` (an updated implementation of the [pool-trigger-resource](https://github.com/cfmobile/pool-trigger-resource) for use in our CI)
  - `build-integration-test-runner-dockerfile` (running our integration tests)
  - `build-integration-test-runner-beta-dockerfile` (running our integration tests with the latest Chrome beta version)
  - `build-deployment-yaml-formatter-dockerfile` (templating our deployment YAML during a release)
  - `build-crane` (copy and tag container images during release)
  - `build-k8s-code-generator-*` (running our Kubernetes code generation under different Kubernetes dependency versions)
  - `build-test-dex` (a Dex used during tests)
  - `build-test-cfssl` (a cfssl used during tests)
  - `build-test-kubectl` (a kubectl used during tests)
  - `build-test-forward-proxy` (a Squid forward proxy used during tests)
  - `build-test-bitnami-ldap` (an OpenLDAP used during tests)

- `cleanup-aws`

  This runs a script that runs [aws-nuke](https://github.com/rebuy-de/aws-nuke) against our test AWS account.
  This was occasionally needed because [eksctl](https://eksctl.io/) sometimes fails and leaks AWS resources. These resources cost money and use up our AWS quota.
  However, we seem to have worked around these issues and this pipeline has not been used for some time.

  These jobs are only triggered manually. This is dangerous and should be used with care.

- `concourse-workers`

  Deploys worker replicas on a long-lived GKE cluster that runs the Concourse workers, and can scale them up or down.

- `go-compatibility`

  This pipeline runs nightly jobs that validate the compatibility of our code as a Go module in various contexts. We have jobs that test that our code compiles under older Go versions and that our CLI can be installed using `go install`.

- `security-scan`

  This pipeline has nightly jobs that run security scans on our current main branch and most recently released artifacts.

  The tools we use are:
  - [sonatype-nexus-community/nancy](https://github.com/sonatype-nexus-community/nancy), which scans Go module versions.
  - [aquasecurity/trivy](https://github.com/aquasecurity/trivy), which scans container images and Go binaries.
  - [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), which scans Go code to find calls to known-vulnerable dependencies.

  This pipeline also has a job called `all-golang-deps-updated` which automatically submits PRs to update all
  direct dependencies in Pinniped's go.mod file, and update the Golang and distroless container images used in
  Pinniped's Dockerfiles.

- `kind-node-builder`

  A nightly build job which uses the latest version of kind to build the HEAD of master of Kubernetes as a container
  image that can be used to deploy kind clusters. Other pipelines use this container image to install Pinniped and run
  integration tests. This gives us insight in any compatibility problems with the upcoming next release of Kubernetes.

## Deploying pipeline changes

After any shared tasks (`./pipelines/shared-tasks`) or helpers (`./pipelines/shared-helpers`) are edited,
the commits must be pushed to the `ci` branch of this repository to take effect.

After editing any CI secrets or pipeline definitions, a maintainer must run the corresponding
`./pipelines/$PIPELINE_NAME/update-pipeline.sh` script to apply the changes to Concourse.
To deploy _all_ pipelines, a maintainer can run `./pipelines/update-all-pipelines.sh`.
Don't forget to commit and push your changes after applying them!

## Github webhooks for pipelines

Some pipelines use github [webhooks to trigger resource checks](https://concourse-ci.org/resources.html#schema.resource.webhook_token),
rather than the default of polling every minute, to make these pipelines more responsive and use fewer compute resources
for running checks. Refer to places where `webhook_token` is configured in various `pipeline.yml` files.

To make these webhooks work, they must be defined on the [GitHub repo's settings](https://github.com/vmware-tanzu/pinniped/settings/hooks).

## Installing and operating Concourse

See [infra/README.md](./infra/README.md) for details about how Concourse was installed and how it can be operated.

## Acceptance environments

In addition to the many ephemeral Kubernetes clusters we use for testing, we also deploy a long-running acceptance environment.

Google Kubernetes Engine (GKE) in the `gke-acceptance-cluster` cluster in our GCP project in the `us-central1-c` availability zone.

To access this cluster, download the kubeconfig to `gke-acceptance.yaml` by running:

```cmd
KUBECONFIG=gke-acceptance.yaml gcloud container clusters get-credentials gke-acceptance-cluster --project "$PINNIPED_GCP_PROJECT" --zone us-central1-c
```

The above command assumes that you have already set `PINNIPED_GCP_PROJECT` to be the name of the GCP project.

## CI secrets

We use [Google Secret Manager](https://cloud.google.com/secret-manager) on GCP to store build/test/release secrets.
These secrets are only available to the maintainers.

Using the `gcloud secrets list` command or the [web console](https://console.cloud.google.com/security/secret-manager),
you can list the available secrets. The content of each secret is a YAML file with secret key/value pairs.
You can also use the `./hack/edit-gcloud-secret.sh <secretName>` script to edit or inspect each secret.

## Configure Azure for CI to test on AKS

There are several CI jobs which test that Pinniped works when installed on Azure's AKS.
For these jobs to run, they need to be able to create and delete ephemeral AKS clusters.
This requires the following:

1. An active Azure Subscription. (A "subscription" in Azure is the equivalent of an "account" in AWS or a "project" in GCP.)
2. An Azure App Registration (basically, a service account) active in the same Directory (aka tenant) as the Subscription.
   Create the app in "My Organization Only". It does not need a redirect URI or any other optional settings.
   Create a client secret for this app. If you want the client secret to have a long lifetime, you can use the `az` CLI to create it.
   In the Subscription's IAM settings, assign this app the role "Azure Kubernetes Service Contributor Role" to allow
   the app to manage AKS clusters. Also assign this app the role "Reader" to allow it to read all resources
   (used by the `remove-orphaned-aks-clusters` CI task).
   Do not grant this app permissions in any other Subscription or use it for any other purpose.
3. Configure the pipelines with the app's Application (client) ID, Client Secret, and Directory (tenant) ID
   as the appropriate secret values.

The CI jobs will create and delete AKS clusters in a Resource Group called `pinniped-ci` within the provided Subscription.

## Configure AWS for CI to test on EKS

There are several CI jobs which test that Pinniped works when installed on Amazon's EKS.
For these jobs to run, they need to be able to create and delete ephemeral EKS clusters.
There are also some jobs to cleanup any orphaned resources (e.g. IP addresses) in the AWS account.
These jobs requires the following:

1. An active AWS account, which will only be used for this purpose.
2. Two IAM users in that account, each with a role that can be assumed.
   These IAM users which should only be used for Pinniped CI and no other purpose.
   They should only have permissions to perform AWS actions in the relevant AWS account, and no other account.
3. The first user and role should have permission to create and delete EKS clusters using `eksctl`.
   The permissions required can be found in the [eksctl docs](https://eksctl.io/usage/minimum-iam-policies).
   The user also needs permission to run `aws logs put-retention-policy`, `aws ec2 describe-nat-gateways`,
   and `aws ec2 delete-nat-gateway`.
4. The second user and role should have broad permissions to get and delete everything in the account.
   It will be used to run `aws-nuke` to list and/or clean resources from the AWS account.
   To use `aws-nuke`, the user also needs to have an AWS account alias
   (see the [cleanup-aws task](pipelines/shared-tasks/cleanup-aws/task.sh) for details).

## Setting Up Active Directory Test Environment

To test the `ActiveDirectoryIdentityProvider` functionality, we have a long-running Active Directory Domain Controller
server instance in our GCP account. See [AD-SETUP.md](AD-SETUP.md) for details.

## Running integration tests on your laptop using AD

The relevant environment variables can be pulled from the secret manager via the `hack/get-active-directory-env-vars.sh` script.
This can be used by maintainers with Pinniped's `/hack/prepare-for-integration-tests.sh` script in the following way:

 ```bash
 # Must authenticate to glcoud to access the secret manager.
 gcloud auth login
 # In the pinniped repo's main branch or in your PR branch:
 hack/prepare-for-integration-tests.sh --get-active-directory-vars "$HOME/path/to/pinniped-ci-branch/hack/get-active-directory-env-vars.sh"
 ```

## Running integration tests on your laptop using GitHub

The relevant environment variables can be pulled from the secret manager via the `hack/get-github-env-vars.sh` script.
This can be used by maintainers with Pinniped's `/hack/prepare-for-integration-tests.sh` script in the following way:

 ```bash
 # Must authenticate to glcoud to access the secret manager.
 gcloud auth login
# In the pinniped repo's main branch or in your PR branch:
 hack/prepare-for-integration-tests.sh --get-github-vars "$HOME/path/to/pinniped-ci-branch/hack/get-github-env-vars.sh"
 ```

## License

Pinniped is open source and licensed under Apache License Version 2.0. See [LICENSE](LICENSE).

Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
