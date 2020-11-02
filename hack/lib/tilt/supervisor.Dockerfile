# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

# Use a runtime image based on Debian slim
FROM debian:10.5-slim

# Copy the binary which was built outside the container.
COPY build/pinniped-supervisor /usr/local/bin/pinniped-supervisor

# Document the port
EXPOSE 8080 8443

# Run as non-root for security posture
USER 1001:1001

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/pinniped-supervisor"]
