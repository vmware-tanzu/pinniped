#!/bin/bash

# Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ "$OSTYPE" != "darwin"* ]]; then
  echo "This script was only written for MacOS (due to differences with Linux sed flags)"
  exit 1
fi

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
    echo "Fixing copyright notice in the following files:"
    for f in "${missing_copyright_files[@]}"; do
        echo "    $f"
        # The rule when updating copyrights is to always keep the starting year,
        # and to replace the ending year with the current year.
        # This uses MacOS sed flags to replace "XXXX-YYYY" with "XXXX-year" in the copyright notice.
        sed -E -e 's/Copyright ([0-9]{4})-([0-9]{4}) the Pinniped contributors/Copyright \1-'"$year"' the Pinniped contributors/' -i '' "$f"
        # This uses MacOS sed flags to replace "XXXX" with "XXXX-year" in the copyright notice.
        sed -E -e 's/Copyright ([0-9]{4}) the Pinniped contributors/Copyright \1-'"$year"' the Pinniped contributors/' -i '' "$f"
    done
    echo "Done!"
    exit 1
fi
