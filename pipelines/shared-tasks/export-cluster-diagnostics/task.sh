#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export KUBECONFIG="$PWD/cluster-pool/metadata"

gcloud auth activate-service-account "$GCP_USERNAME" --key-file <(echo "$GCP_JSON_KEY") --project "$GCP_PROJECT"

# Make a temp directory for the pod log files.
output_dir="$(mktemp -d)"

# Get a list all the cluster pods with each line containing "<ns> <name>".
kubectl get pods -A -o custom-columns=ns:.metadata.namespace,name:.metadata.name \
  | tail +2 \
  | while read -r ns name ; do
  echo "collecting pod logs from $ns/$name..."
  mkdir -p "$output_dir/logs/$ns"
  kubectl logs --all-containers -n "$ns" "$name" > "$output_dir/logs/$ns/$name.log" || true
  kubectl logs --all-containers --previous -n "$ns" "$name" > "$output_dir/logs/$ns/$name.previous.log" 2>/dev/null  || true
done

# Delete any empty log files.
find "$output_dir/logs" -name "*.log" -size 0 -delete

# Dump all Kubernetes resources (except Secrets) into ./resources/TYPE.json while ignoring discovery errors
mkdir -p "$output_dir/resources"
resources="$(kubectl api-resources --verbs=list -o name || true)"
echo -n "${resources}" \
  | grep -v secrets \
  | xargs -P4 -n1 -I{} sh -c "kubectl get --ignore-not-found -A -o json {} > $output_dir/resources/{}.json"

# Dump secret metadata but not the actual contents
kubectl get --ignore-not-found -A -o wide secrets > $output_dir/resources/secrets.txt

# Compress the logs into a .tgz file in the output directory.
random_string="$(openssl rand -hex 4)"
output_tgz="cluster-diagnostics-$random_string.tgz"
tar -czf "$output_tgz" -C "$output_dir" .

# Upload the files into the GCS bucket under YYYY/MM/DD/cluster-diagnostics-XXXXXXXX.tgz
output_url_path="$(date +%Y)/$(date +%m)/$(date +%d)"
output_tgz_path="$output_url_path/$output_tgz"
gsutil cp "$output_tgz" "gs://$GCS_BUCKET/$output_tgz_path"

if [ -d test-output ] ; then
  # Take test output and make list of test successes and failures. This should include
  # test name and time elapsed.
  < test-output/testoutput.log jq -s 'map(select((.Action == "fail") or (.Action == "pass")))' > results.log
  output_json_path="$output_url_path/results-$random_string.json"
  gsutil cp results.log "gs://$GCS_BUCKET/$output_json_path"
  results_link="https://storage.googleapis.com/${GCS_BUCKET}/${output_json_path}"
else
  # Some "tests" don't actually run any Go tests, so there's nothing to upload here.
  results_link=""
fi

cat <<EOF


Collected cluster diagnostics:

  https://storage.googleapis.com/${GCS_BUCKET}/${output_tgz_path}
  ${results_link}

EOF
