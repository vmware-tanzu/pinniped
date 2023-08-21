#!/bin/bash

# TODO: since I removed the deployments there is not much in the ./imgpkg/images.yaml output
#
# build images found in these directories.
# make use of build.yaml files to specify how builds should work,
# if we need it to be done.
# kbld --file ./concierge/config --imgpkg-lock-output ./concierge/.imgpkg/images.yml

# schema generation from values.yaml
# TODO: figure out why this isn't working.
ytt --file supervisor/config/values.yaml --data-values-schema-inspect --output openapi-v3 > supervisor/schema-openapi.yml
ytt --file concierge/config/values.yaml --data-values-schema-inspect --output openapi-v3 > concierge/schema-openapi.yml
