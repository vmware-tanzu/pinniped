# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

# Use a runtime image based on Debian slim
FROM debian:10.5-slim

# Copy the binary which was built outside the container.
COPY build/local-user-authenticator /usr/local/bin/local-user-authenticator

# Document the port
EXPOSE 8443

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/local-user-authenticator"]
