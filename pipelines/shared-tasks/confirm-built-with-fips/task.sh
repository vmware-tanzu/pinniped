#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# check whether the pinniped-server binary has particular symbols that only exists when it's compiled with boringcrypto.
# https://go.googlesource.com/go/+/dev.boringcrypto/misc/boring#caveat

# Starting in 1.19, go-boringcrypto has been added to the main Go toolchain,
# hidden behind a `GOEXPERIMENT=boringcrypto` env var.
# See https://go.googlesource.com/go/+/dev.boringcrypto/README.boringcrypto.md
# and https://kupczynski.info/posts/fips-golang/ for details.

pinniped_server_has_boringcrypto="$(go tool nm './image/rootfs/usr/local/bin/pinniped-server' | grep '_Cfunc__goboringcrypto_')"
# check that we got any output from the previous command. If it wasn't built with boringcrypto, this variable
# should be empty because grep should filter it all out. Else it'll be a long list of symbols.
if [ -z "$pinniped_server_has_boringcrypto" ]
then
      echo "Pinniped server binary wasn't built with boringcrypto."
      exit 1
fi
# check whether the pinniped-server binary has particular symbols that only exist when it's compiled with non-boring crypto
pinniped_server_has_regular_crypto="$(go tool nm './image/rootfs/usr/local/bin/pinniped-server' | grep sha256 | grep di)"
# if any of these symbols exist, that means it was compiled wrong and it should fail.
if [ -n "$pinniped_server_has_regular_crypto" ]
then
  echo "Pinniped server binary was built with non-boring crypto."
  exit 1
fi
# check whether the kube-cert-agent binary has particular symbols that only exist when it's compiled with non-boring crypto
kube_cert_agent_has_regular_crypto="$(go tool nm './image/rootfs/usr/local/bin/pinniped-concierge-kube-cert-agent' | grep sha256 | grep di)"
# if any of these symbols exist, that means it was compiled wrong and it should fail.
if [ -n "$kube_cert_agent_has_regular_crypto" ]
then
  echo "kube-cert-agent binary was built with non-boring crypto."
  exit 1
fi
# check the ldd output to see whether we compiled a static executable or not.
pinniped_server_ldd="$(ldd './image/rootfs/usr/local/bin/pinniped-server' 2>&1)"
# if it doesn't contain this line, that means the executable was dynamic,
# which we don't want.
if [[ "$pinniped_server_ldd" != *"not a dynamic executable"* ]]
then
  echo "pinniped server binary is a dynamic executable."
  exit 1
fi
# check the ldd output to see whether we compiled a static executable or not.
kube_cert_agent_ldd="$(ldd './image/rootfs/usr/local/bin/pinniped-concierge-kube-cert-agent' 2>&1)"
# if it doesn't contain this line, that means the executable was dynamic,
# which we don't want.
if [[ "$kube_cert_agent_ldd" != *"not a dynamic executable"* ]]
then
  echo "kube cert agent binary is a dynamic executable."
  exit 1
fi