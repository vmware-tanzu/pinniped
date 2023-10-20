# local-user-authenticator

The local-user-authenticator is a component used for testing Pinniped and is not a production component.
See [Application main functions](https://pinniped.dev/docs/reference/code-walkthrough/#application-main-functions) for a brief description.

The Carvel Package deployment method can be exercised via the following invocation:

```bash
PINNIPED_USE_LOCAL_KIND_REGISTRY=1 ./hack/prepare-for-integration-tests.sh \
  --clean \
  --alternate-deploy ./hack/noop.sh \
  --post-install ./hack/build-carvel-packages.sh
```

## In this directory:

- `vendir` is used to copy the <root>/deploy/local-user-authenticator ytt files to <root>/deploy_carvel/local-user-authenticator/config.
