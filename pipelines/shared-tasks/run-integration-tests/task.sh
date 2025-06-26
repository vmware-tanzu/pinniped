#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the integration tests against a remote target cluster.
#
# This script is designed to be run both in CI as a task (see task.yaml)
# and on a development workstation (see hack/prepare-remote-cluster-for-integration-tests.sh).
# When editing this file, please ensure that both methods of running will still work.
# All required file/directory paths can be controlled by env vars so they can default
# to the CI task values but be overridden by an invocation on your workstation.
#
# This script assumes that the app is already deployed into the remote target cluster
# and that the necessary env vars are provided.

set -euo pipefail

export GOCACHE="$PWD/cache/gocache"
export GOMODCACHE="$PWD/cache/gomodcache"

# When run as a CI task the initial working directory is the directory above all of the
# inout directories.
initial_working_directory=$(pwd)

# Set some default paths that would apply when run as a CI task.
# There is no equivalent needed for these when running on your development laptop.
pinniped_test_cli="$initial_working_directory/ci-test-image/rootfs/usr/local/bin/pinniped"
integration_test_binary="$initial_working_directory/ci-test-image/rootfs/usr/local/bin/pinniped-integration-test"

# Set up the KUBECONFIG for the integration tests to use.
# To make it possible to run this script on your workstation, first check to see if $KUBECONFIG is already set by the caller.
kubeconfig=${KUBECONFIG:-"$initial_working_directory/kubeconfig/kubeconfig"}
echo "Using kubeconfig file $kubeconfig"
export KUBECONFIG="$kubeconfig"

# Load the env vars that were output by the previous script which are needed during go test
# To make it possible to run this script on your workstation, first check to see if an alternate path is set.
test_env_path=${TEST_ENV_PATH:-"integration-test-env-vars/integration-test-env"}
echo "Using test env file $test_env_path"
source "$test_env_path"

# cd to the source code repo.
# To make it possible to run this script on your workstation, first check to see if an alternate path is set.
source_path=${SOURCE_PATH:-"pinniped"}
cd "$source_path"
echo "Using source code directory $(pwd)"

# Some supervisor deployment settings, with default values that are appropriate defaults for both the CI task
# and for running on development workstations. These can be overridden to allow testing of secondary deploys
# i.e. when there are two Pinnipeds running on the same cluster.
supervisor_namespace=${PINNIPED_SUPERVISOR_NAMESPACE:-"supervisor"}
supervisor_nodeport_service=${PINNIPED_SUPERVISOR_NODEPORT_SERVICE:-"supervisor-nodeport"}
supervisor_https_host_port=${PINNIPED_SUPERVISOR_HTTPS_HOST_PORT:-12344} # see gce-init.sh for the meaning of this port

# Prepare to clean up any background jobs that we might start below.
background_pids=()
function cleanup() {
  if [[ "${#background_pids[@]}" -gt "0" ]]; then
    echo "Cleaning up background processes..."
    # Kill all background jobs. Can't use the $background_pids here since some of the commands that we
    # put into the background are pipelines of multiple commands, and $background_pids only holds the pids
    # of the last command in each pipeline. `jobs -p` is the pids of the first command in each pipeline.
    jobs -p | xargs kill
  fi
}
trap cleanup EXIT

# See kind port mappings in gce-init.sh for what these port number values hook into on a remote kind cluster.
# See single-node.yaml for the same port numbers when running a kind cluster on your development laptop.
ssh_mappings=(
  # The Pinniped Supervisor's https port.
  "127.0.0.1:12344:127.0.0.1:${supervisor_https_host_port}"
  # The squid proxy port. We run squid inside the cluster to allow the tests
  # to use it as an http_proxy to access all Services inside the cluster.
  "127.0.0.1:12346:127.0.0.1:12346"
)

kubectl_mapping_command1=(
  # The Pinniped Supervisor's https port.
  kubectl port-forward -n "$supervisor_namespace" "svc/$supervisor_nodeport_service" 12344:443 -v 9
)
kubectl_mapping_command2=(
  # The squid proxy port. We run squid inside the cluster to allow the tests
  # to use it as an http_proxy to access all Services inside the cluster.
  kubectl port-forward -n tools svc/proxy 12346:3128 -v 9
)
# The above variables are not unused, as shellcheck warns. They are passed by name into this array.
kubectl_mapping_commands=(kubectl_mapping_command1 kubectl_mapping_command2)

# The health checks that we should run before running the tests to ensure that our port mappings are ready.
port_health_checks=(
  # The Pinniped Supervisor's https port.
  "curl -fsk https://127.0.0.1:12344/healthz"
  # The squid proxy port.
  "https_proxy=127.0.0.1:12346 curl -fsk https://dex.tools.svc.cluster.local/dex/.well-known/openid-configuration"
)

# Use "gcloud ssh" to forward ports of remote kind clusters because "kubectl port-forward"
# proved to be unreliable in that use case.
if [[ "${START_GCLOUD_PROXY:-no}" == "yes" ]]; then
  if [[ -z "${GCP_ZONE:-}" || -z "${GCP_PROJECT:-}" ]]; then
    echo "\$GCP_ZONE and \$GCP_PROJECT are required when START_GCLOUD_PROXY==yes"
    exit 1
  fi

  # If the GCP_USERNAME env var was set, then use it along with $GCP_JSON_KEY to log in as a service account.
  # When running on your laptop we will assume that you are already logged in to gcloud as yourself.
  if [[ -n "${GCP_USERNAME:-}" ]]; then
    echo "Signing in to gcloud as service account $GCP_USERNAME ..."
    gcloud auth activate-service-account \
      "$GCP_USERNAME" \
      --key-file <(echo "$GCP_JSON_KEY") \
      --project "$GCP_PROJECT"
  fi

  # For using "gcloud ssh" with a remote kind cluster below, we'll need to know the name of the cluster.
  if [[ -f "$initial_working_directory/kubeconfig/cluster-name" ]]; then
    # In CI we set the cluster name as another file in the kubeconfig input directory.
    cluster_name="$(cat "$initial_working_directory/kubeconfig/cluster-name")"
  else
    # When running on your development workstation, the name of the file is the name of the cluster.
    cluster_name="$(basename "$KUBECONFIG")"
  fi

  # Make a private key that can be used for all ssh commands below, if one does not already exist.
  # Check if it exists because there is no need to regenerate it when running on your development workstation.
  ssh_key_file="$HOME/.ssh/pinniped-integration-test-key"
  if [[ ! -f "$ssh_key_file" ]]; then
    # Generate a private key which has no password, output to $ssh_key_file.
    ssh-keygen -t rsa -b 4096 -q -N "" -f "$ssh_key_file"
  fi

  # Use a unique username for each test invocation so that each test invocation will upload a new public key to our GCP project.
  # This allows any number of port forwards across parallel test runs to be independent.
  # Note that this username must be 32 character or less.
  unique_username="int-test-$(openssl rand -hex 8)"

  # When run in CI, the service account should not have permission to create project-wide keys, so explicitly add the
  # key only to the specific VM instance (as VM metadata). We don't want to pollute the project-wide keys with these.
  # See https://cloud.google.com/compute/docs/connect/add-ssh-keys#after-vm-creation for explanation of these commands.
  # Note that this overwrites all ssh keys in the metadata. At the moment, these VMs have no ssh keys in the metadata
  # upon creation, so it should always be okay to overwrite the empty value. However, if someday they need to have some
  # initial ssh keys in the metadata for some reason, and if those keys need to be preserved for some reason, then
  # these commands could be enhanced to instead read the keys, add to them, and write back the new list.
  future_time="$(date --utc --date '+3 hours' '+%FT%T%z')"
  echo \
    "${unique_username}:$(cat "${ssh_key_file}.pub") google-ssh {\"userName\":\"${unique_username}\",\"expireOn\":\"${future_time}\"}" \
    > /tmp/ssh-key-values
  gcloud compute instances add-metadata "$cluster_name" \
    --metadata-from-file ssh-keys=/tmp/ssh-key-values \
    --zone "$GCP_ZONE" --project "$GCP_PROJECT"

  # Get the IP so we can stop using gcloud ssh and start using regular ssh, now that it has been set up.
  # gcloud ssh seems to complain that the "remote host identification has changed" sometimes and there
  # seems to be no way to avoid it. :( So we'll use regular ssh.
  gcloud_instance_ip=$(gcloud compute instances describe \
    --zone "$GCP_ZONE" --project "$GCP_PROJECT" "${cluster_name}" \
    --format='get(networkInterfaces[0].networkIP)')

  # Now start some simultaneous background jobs.
  for mapping in "${ssh_mappings[@]}"; do
    echo "Starting ssh for temporary user ${unique_username} to map port ${mapping} ..."
    ssh "${unique_username}@${gcloud_instance_ip}" -i "${ssh_key_file}" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ExitOnForwardFailure=yes -NT -L "${mapping}" &
    background_pids+=($!)
  done

# For other kinds of remote clusters, "kubectl port-forward" works fine.
elif [[ "${START_KUBECTL_PROXY:-no}" == "yes" ]]; then
  for cmd_and_args_array_name in "${kubectl_mapping_commands[@]}"; do
    # All these array gymnastics are to avoid using eval to run the command because
    # eval makes it very hard to kill the background kubectl process during trap cleanup.
    cmd_and_args_array_name="$cmd_and_args_array_name""[@]"
    cmd_and_args_array=("${!cmd_and_args_array_name}")
    echo "Starting " "${cmd_and_args_array[@]}"
    "${cmd_and_args_array[@]}" | grep --line-buffered -v "Handling connection" &
    background_pids+=($!)
  done
fi

# Give a few moments for the background commands to run, only to avoid having their stdout
# interleave so much with the stdout of the commands that we're about to do below. This is
# not for correctness to avoid a race, because the while loop below is doing that.
sleep 10

# If we started either style of port forwarding above, then wait for all of the ports to
# start working before we start the integration tests to avoid a race between the port
# forwarding starting and the first integration test which tries to use one of these ports.
if [[ "${START_GCLOUD_PROXY:-no}" == "yes" || "${START_KUBECTL_PROXY:-no}" == "yes" ]]; then
  while true; do
    sleep 1
    for pid in "${background_pids[@]}"; do
      if ! ps -p "$pid" >/dev/null; then
        echo "Background port-forward process $pid seems to have died. Exiting. :("
        exit 1
      fi
    done
    succeeded=true
    # Try to curl an endpoint which should succeed through each port-forwarded port.
    for health_check in "${port_health_checks[@]}"; do
      echo "$health_check"
      if ! eval "$health_check" >/dev/null; then
        succeeded=false
        break
      fi
    done
    if [[ $succeeded == "true" ]]; then
      echo "All port-forwarded ports are ready."
      break
    fi
    echo "Waiting for port-forwarded ports to be ready..."
  done
fi

# Print version for logs.
go version
if [[ "$OSTYPE" != "darwin"* ]]; then
  google-chrome --version
fi

# If the cli has been pre-compiled then use it.
if [[ -f "$pinniped_test_cli" ]]; then
  export PINNIPED_TEST_CLI="$pinniped_test_cli"
fi

# Unset this before running the integration tests, to try to hide this GCP_JSON_KEY credential from the tests.
if [[ -n "${GCP_JSON_KEY:-}" ]]; then
  unset GCP_JSON_KEY GCP_ZONE GCP_PROJECT GCP_USERNAME
fi

if [ -d "../test-output" ]; then
  # this is probably running in CI, and test-output is the name of the concourse output directory
  # that we put the file in so that the next task can upload it to GCS.
  # we need to chmod it so our non-root user can write to it.
  chmod 777 ../test-output
  jsonfile_arg="../test-output/testoutput.log"
else
  # otherwise, we're probably running locally and don't actually want to output the logs to a file
  # to aggregate and analyze later.
  jsonfile_arg="/dev/null"
fi

test_run_regex=${TEST_RUN_REGEX:-'.*'}

if [[ -f "$integration_test_binary" ]]; then
  # If the integration test suite has been pre-compiled, then use it to run the tests.
  test_command="gotestsum --raw-command --format standard-verbose --jsonfile $jsonfile_arg -- go tool test2json -t -p pkgname \"$integration_test_binary\" -test.v -test.count=1 -test.timeout=70m -test.run='${test_run_regex}'"
else
  # Otherwise just run the tests with "go test".
  test_command="gotestsum --format standard-verbose --jsonfile $jsonfile_arg ./test/integration/ -- -race -v -count 1 -timeout 70m -run '${test_run_regex}'"
fi

# Run the integration tests. They can assume that the app is already deployed
# and that kubectl is configured to talk to the cluster. They also have the
# k14s tools available (ytt, kapp, etc) in case they want to do more deploys.
if [[ "$(id -u)" == "0" ]]; then
  # Downgrade to a non-root user to run the tests. We don't want them reading the
  # environment of any parent process, e.g. by reading from /proc. This user account
  # was created in the Dockerfile of the container image used to run this script in CI.
  # It is okay if $GCP_JSON_KEY is empty or unset, either way we've avoided sharing the
  # credential with the subprocess.
  if [[ -n $(su testrunner -c "echo $GCP_JSON_KEY") ]]; then
    echo "Tried to obscure the GCP_JSON_KEY secret from the testrunner user but it didn't work!"
    exit 1
  fi
  # This should not be necessary, but something strange started happening after upgrading to Concourse v7.7.0
  # where sometimes the owner and group IDs of these directories are wrong inside the container on Concourse.
  # Attempting the following chown as a workaround, which should change the owner/group of the files back to
  # what they were in the container image.
  chown -R testrunner:testrunner /home/testrunner
  echo "Downgrading to user testrunner and running: ${test_command}"
  # su without "-" keeps the parent environment variables, but we've already deleted the credential variables.
  su testrunner -c "$test_command"
else
  # Already non-root, so just run as yourself.
  echo "Running: ${test_command}"
  eval "$test_command"
fi
