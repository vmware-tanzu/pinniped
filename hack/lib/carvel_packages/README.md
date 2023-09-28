# Deployment via Carvel Packages

The Carvel Package deployment method can be exercised via the following invocation:

```bash
PINNIPED_USE_LOCAL_KIND_REGISTRY=1 ./hack/prepare-for-integration-tests.sh \
  --clean \
  --alternate-deploy ./hack/noop.sh \
  --post-install ./hack/build-carvel-packages.sh
```
