# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Use a runtime image based on Debian slim
FROM debian:12.7-slim

# Install Squid and drop in a very basic, open proxy configuration.
RUN apt-get update && apt-get install -y squid
COPY squid.conf /etc/squid/squid.conf
EXPOSE 3128

# Launch Squid as a foreground process.
CMD squid -N -C -n proxy -d1 2>&1
