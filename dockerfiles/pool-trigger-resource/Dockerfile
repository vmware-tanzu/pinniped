# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# We would like to use https://github.com/cfmobile/pool-trigger-resource for our pool recycle jobs.
# Unfortuntely, the pool-trigger-resource repo seems like it is not maintained by anyone. The most recent
# commit was six years ago. On the other hand, its implementation is a shell script which basically
# just calls some git commands, so it shouldn't need much maintaince if it works.
# This is an updated version of https://github.com/cfmobile/pool-trigger-resource/blob/master/Dockerfile
# to use newer versions of linux, jq, and git. The "assets" directory's source code is copied from
# https://github.com/cfmobile/pool-trigger-resource/tree/master/assets as of commit efefe018c88e937.

FROM debian:12.7-slim

RUN apt-get update && apt-get install -y ca-certificates jq git && rm -rf /var/lib/apt/lists/*

ADD assets/ /opt/resource/
RUN chmod +rx /opt/resource/*
