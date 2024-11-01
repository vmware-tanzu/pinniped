---
title: FIPS-compatible builds of Pinniped binaries
description: Reference for FIPS builds of Pinniped binaries
cascade:
  layout: docs
menu:
  docs:
    name: FIPS-compatible builds
    weight: 30
    parent: reference
---
By default, the Pinniped supervisor and concierge use ciphers that
are not supported by FIPS 140-2. If you are deploying Pinniped in an
environment with FIPS compliance requirements, you will have to build
the binaries yourself using the `fips_strict` build tag and Golang's
`GOEXPERIMENT=boringcrypto` compiler option.

The Pinniped team provides an [example Dockerfile](https://github.com/vmware-tanzu/pinniped/blob/main/hack/Dockerfile_fips)
demonstrating how you can build Pinniped images in a FIPS compatible way.
However, we do not provide official support for FIPS configuration.
We provide this for informational purposes only.

To build Pinniped use our example FIPS Dockerfile, you can run:
```bash
$ git clone git@github.com:vmware-tanzu/pinniped.git
$ cd pinniped
$ git checkout {{< latestversion >}}
$ docker build -f hack/Dockerfile_fips .
```

Now you can deploy [the concierge]({{< ref "install-concierge" >}}) and [the supervisor]({{< ref "install-supervisor" >}}) 
by specifying this image instead of the standard Pinniped image in your `values.yaml` or `deployment.yaml` file.
