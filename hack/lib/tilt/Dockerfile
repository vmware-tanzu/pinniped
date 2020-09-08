# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

# Use a runtime image based on Debian slim
FROM debian:10.5-slim

# Copy the binary from the build-env stage
COPY build/pinniped-server /usr/local/bin/pinniped-server

# Document the port
EXPOSE 443

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/pinniped-server"]
