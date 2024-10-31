#!/bin/bash

# Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

files=$(git diff --cached --name-only)
year=$(date +"%Y")

missing_copyright_files=()

for f in $files; do
    head -10 "$f" | grep -i 'Copyright.*the Pinniped contributors' 2>&1 1>/dev/null || continue

    if ! head -10 "$f" | grep -i -e "Copyright.*$year.*the Pinniped contributors" 2>&1 1>/dev/null; then
        missing_copyright_files+=("$f")
    fi
done

if [[ "${#missing_copyright_files[@]}" -gt "0" ]]; then
    echo "Copyright notice should include the year the file was created and the year the file was last modified."
    echo "$year is missing in the copyright notice of the following files:"
    for f in "${missing_copyright_files[@]}"; do
        echo "    $f"
    done
    echo "Try using hack/update-copyright-year.sh to update the copyright automatically in staged files."
    exit 1
fi
