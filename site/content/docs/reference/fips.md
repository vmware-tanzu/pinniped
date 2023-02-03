---
title: FIPS-compatible builds of Pinniped binaries
description: Reference for FIPS builds of Pinniped binaries
cascade:
  layout: docs
menu:
  docs:
    name: FIPS-compatible builds of Pinniped binaries
    weight: 30
    parent: reference
---
By default, the Pinniped supervisor and concierge use ciphers that are not supported by FIPS 140-2.
If you are deploying Pinniped in an environment with FIPS compliance requirements, you will have to build
the binaries yourself using `GOEXPERIMENT=boringcrypto`.

The Pinniped team provides an [example Dockerfile](https://github.com/vmware-tanzu/pinniped/blob/main/hack/Dockerfile_fips)
demonstrating how you can build Pinniped images in a FIPS compatible way.

However, we do not provide official support for FIPS configuration, and we may not
respond to GitHub issues opened related to FIPS support.
We provide this for informational purposes only.

To build Pinniped use our example fips Dockerfile, you can run:
```bash
$ git clone git@github.com:vmware-tanzu/pinniped.git
$ cd pinniped
$ git checkout {{< latestversion >}}
$ docker build -f hack/Dockerfile_fips .
```

Now you can deploy [the concierge]({{< ref "install-concierge" >}}) and [the supervisor]({{< ref "install-supervisor" >}}) 
by specifying this image instead of the standard Pinniped image in your `values.yaml` or `deployment.yaml` file.

