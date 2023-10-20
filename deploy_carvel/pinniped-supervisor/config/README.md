# Pinniped Supervisor Deployment

See [the how-to guide for details](https://pinniped.dev/docs/howto/install-supervisor/).

The Carvel Package deployment method can be exercised via the following invocation:

```bash
PINNIPED_USE_LOCAL_KIND_REGISTRY=1 ./hack/prepare-for-integration-tests.sh \
  --clean \
  --alternate-deploy ./hack/noop.sh \
  --post-install ./hack/build-carvel-packages.sh
```

## In this directory:

- `vendir` is used to copy the <root>/deploy/supervisor ytt files to <root>/deploy_carvel/supervisor/config.
