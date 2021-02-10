# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

# Use a runtime image based on Debian slim
FROM debian:10.8-slim

# Copy the binary which was built outside the container.
COPY build/local-user-authenticator /usr/local/bin/local-user-authenticator

# Document the port
EXPOSE 8443

# Run as non-root for security posture
# Commented out because it breaks the live-reload feature of Tilt. See https://github.com/tilt-dev/tilt/issues/2300
# Be aware that this creates a significant difference between running with Tilt and running otherwise.
#USER 1001:1001

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/local-user-authenticator"]
