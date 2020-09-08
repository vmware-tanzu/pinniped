#!/usr/bin/env bash
set -euo pipefail

#
# Helper functions
#
function log_note() {
  GREEN='\033[0;32m'
  NC='\033[0m'
  if [[ $COLORTERM =~ ^(truecolor|24bit)$ ]]; then
    echo -e "${GREEN}$*${NC}"
  else
    echo "$*"
  fi
}

function log_error() {
  RED='\033[0;31m'
  NC='\033[0m'
  if [[ $COLORTERM =~ ^(truecolor|24bit)$ ]]; then
    echo -e "🙁${RED} Error: $* ${NC}"
  else
    echo ":( Error: $*"
  fi
}

function check_dependency() {
  if ! command -v "$1" >/dev/null; then
    log_error "Missing dependency..."
    log_error "$2"
    exit 1
  fi
}


#
# Check for dependencies
#
check_dependency kubectl "Please install kubectl. e.g. 'brew install kubectl' for MacOS"
check_dependency htpasswd "Please install htpasswd. Should be pre-installed on MacOS. Usually found in 'apache2-utils' package for linux."

# Require kubectl >= 1.18.x
if [ "$(kubectl version --client=true --short | cut -d '.' -f 2)" -lt 18 ]; then
  echo "kubectl >= 1.18.x is required, you have $(kubectl version --client=true --short | cut -d ':' -f2)"
  exit 1
fi

pinniped_path="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$pinniped_path" || exit 1

app_name="pinniped"
namespace="integration"
webhook_url="https://local-user-authenticator.local-user-authenticator.svc/authenticate"
webhook_ca_bundle="$(kubectl get secret local-user-authenticator-tls-serving-certificate --namespace local-user-authenticator -o 'jsonpath={.data.caCertificate}')"

test_username="test-username"
test_groups="test-group-0,test-group-1"
set +o pipefail
test_password="$(openssl rand 16 -hex)"

log_note "Creating test user '$test_username'..."
kubectl create secret generic "$test_username" \
  --namespace local-user-authenticator \
  --from-literal=groups="$test_groups" \
  --from-literal=passwordHash="$(htpasswd -nbBC 10 x "$test_password" | sed -e "s/^x://")" \
  --dry-run=client \
  --output yaml |
  kubectl apply -f -

#
# Create the environment file
#
test_env_file="$pinniped_path/hack/lib/tilt/integration-test.env"

cat <<EOF > "$test_env_file"
# The following env vars should be set before running 'go test -v -count 1 ./test/...'
export PINNIPED_NAMESPACE=${namespace}
export PINNIPED_APP_NAME=${app_name}
export PINNIPED_TEST_USER_USERNAME=${test_username}
export PINNIPED_TEST_USER_GROUPS=${test_groups}
export PINNIPED_TEST_USER_TOKEN=${test_username}:${test_password}
export PINNIPED_TEST_WEBHOOK_ENDPOINT=${webhook_url}
export PINNIPED_TEST_WEBHOOK_CA_BUNDLE=${webhook_ca_bundle}

read -r -d '' PINNIPED_CLUSTER_CAPABILITY_YAML << PINNIPED_CLUSTER_CAPABILITY_YAML_EOF || true
$(cat "$pinniped_path/test/cluster_capabilities/kind.yaml")
PINNIPED_CLUSTER_CAPABILITY_YAML_EOF

export PINNIPED_CLUSTER_CAPABILITY_YAML
EOF

goland_vars=$(grep -v '^#' "$test_env_file" | grep -E '^export .+=' | sed 's/export //g' | tr '\n' ';')

log_note
log_note "🚀 Ready to run integration tests! For example..."
log_note "    cd $pinniped_path"
log_note "    source ./hack/lib/tilt/integration-test.env && go test -v -count 1 ./test/integration"
log_note
log_note 'Want to run integration tests in GoLand? Copy/paste this "Environment" value for GoLand run configurations:'
log_note "    ${goland_vars}PINNIPED_CLUSTER_CAPABILITY_FILE=$pinniped_path/test/cluster_capabilities/kind.yaml"
log_note
