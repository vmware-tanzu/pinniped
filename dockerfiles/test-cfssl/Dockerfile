# Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# The cfssl/cfssl container image on dockerhub is built poorly.
# For every arch, the image contains /bin/* binaries for amd64.
# Therefore, we cannot use bash on arm64 inside this container image.
# This was observed in cfssl/cfssl:v1.6.4.
# However, they do compile their own binaries for both arm64 and amd64,
# so we can just copy their binaries into a vanilla linux base image.
FROM cfssl/cfssl:v1.6.5 as cfssl

# We just need any basic unix with bash, but we can pick the same
# base image that they use, just in case they did any dynamic linking.
FROM golang:1.24.3

# Thier Docerfile https://github.com/cloudflare/cfssl/blob/master/Dockerfile
# calls their Makefile https://github.com/cloudflare/cfssl/blob/master/Makefile
# which builds several binaries. Copy them all.
COPY --from=cfssl /usr/bin/cf* /usr/local/bin
COPY --from=cfssl /usr/bin/mkbundle /usr/local/bin
COPY --from=cfssl /usr/bin/multirootca /usr/local/bin
# Their Dockerfile also populates this directory, so copy that too.
COPY --from=cfssl /etc/cfssl /etc/cfssl

# These lines are copied from the cfssl Dockerfile.
EXPOSE 8888
ENTRYPOINT ["cfssl"]
CMD ["--help"]
