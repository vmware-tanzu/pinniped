#!/usr/bin/env sh

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# This script will aggressively cleanup our AWS resources using the aws-nuke
# command below.
#
# Currently, we cleanup a hardcoded subset resource types to be
# risk-averse. This list can be extended by adding a resource type to
# .resource-types.targets in the config YAML below. The resources that are there
# were selected based on scanning our AWS account and finding the most egregious
# violators of infrastructure pollution.
#
# Some things to think about before you run/edit this script:
# - Are there CI jobs currently running on AWS infrastructure (think: EKS clusters)
#   that will start to fail if you run this script?
# - Are we deleting resources that VMware created when they set this account
#   up for us (think: bootstrapped IAMRole's)?
# - Should we start running this script on a scheduled (i.e., every Saturday
#   morning)?

# Set up our AWS service account for the aws-nuke command to use.
# This should be the equivalent of running these commands, but without needing the aws CLI:
#aws configure set credential_source Environment --profile service-account
#aws configure set role_arn "$AWS_ROLE_ARN" --profile service-account
mkdir "$HOME/.aws"
cat <<EOF > "$HOME/.aws/config"
[profile service-account]
credential_source = Environment
role_arn = $AWS_ROLE_ARN
EOF

targets="{}" # the empty map indicates that we want to target _all_ resource types
# target the whole account with no filters
if [[ "$ALL_RESOURCES" != "yes" ]]; then
  # let's try to keep these in case-insensitive alpha order for search-ability
  targets="
  targets:
  - CloudFormationStack
  - CloudWatchAlarm
  - EC2Address
  - EC2Instance
  - EC2InternetGateway
  - EC2InternetGatewayAttachment
  - EC2KeyPair
  - EC2NATGateway
  - EC2NetworkACL
  - EC2NetworkInterface
  - EC2RouteTable
  - EC2SecurityGroup
  - EC2Subnet
  - EC2Volume
  - EC2VPC
  - ELB
"
fi

# explicitly exclude us-east-2 from this list because we have long-running environments there.
config_file="$(mktemp)"
cat <<EOF >"$config_file"
regions:
- us-west-1
- us-west-2
- us-east-1
- global

account-blocklist:
# dummy entry -- we don't have any production accounts, but aws-nuke forces you to have at least 1
- "999999999999"

resource-types:
  # only nuke these resource types
  $targets

accounts:
  "${AWS_ACCOUNT_NUMBER}": {}
EOF

cmd="aws-nuke --config ${config_file} --profile service-account"
if [[ "$REALLY_CLEANUP" == "yes" ]]; then
  cmd="$cmd --no-dry-run"
fi

# turn off pipefail since the first command below (i.e., the subshell) will most
# likely get sent SIGPIPE after aws-nuke exits and that will cause our script to
# fail.
set +o pipefail

# continually send "tua-test1" to stdin to serve as a confirmation for aws-nuke.
# this is done in a loop since aws-nuke uses a new buffered reader to consume
# stdin each time it wants to accept input from the user.
(while true; do echo tua-test1; sleep 1; done) | ${cmd}
