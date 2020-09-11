# Contributing to Pinniped

Contributions to Pinniped are welcome. Here are some things to help you get started.

1. Please see the [Code of Conduct](code_of_conduct.md).
1. Learn about the [scope](scope.md) of the project.
1. Coming soon: details about how to legally contribute to the project, including CLA/DCO details.
1. See below for how to [file a bug report](#bugs).
1. See below for how to [suggest a feature](#features).
1. See below for how to [build the code](#building).
1. See below for how to [run the tests](#testing).

## Bugs

To file a bug report, please first open an
[issue](https://github.com/suzerain-io/pinniped/issues/new?template=bug_report.md). The project team
will work with you on your bug report.

Once the bug has been validated, a [pull request](https://github.com/suzerain-io/pinniped/compare)
can be opened to fix the bug.

For specifics on what to include in your bug report, please follow the
guidelines in the issue and pull request templates.

## Features

To suggest a feature, please first open an
[issue](https://github.com/suzerain-io/pinniped/issues/new?template=feature-proposal.md)
and tag it with `proposal`. The project team will work with you on your feature request.

Once the feature request has been validated, a [pull request](https://github.com/suzerain-io/pinniped/compare)
can be opened to implement the feature.

For specifics on what to include in your feature request, please follow the
guidelines in the issue and pull request templates.

## Building

The [Dockerfile](../Dockerfile) at the root of the repo can be used to build and
package the code. After making a change to the code, rebuild the docker image with the following command.

```bash
# From the root directory of the repo...
docker build .
```

## Testing

### Running Lint

```bash
./hack/module.sh lint
```

### Running Unit Tests

```bash
./hack/module.sh units
```

### Running Integration Tests

```bash
./hack/prepare-for-integration-tests.sh && source /tmp/integration-test-env && go test -v -count 1 ./test/...
```

The `./hack/prepare-for-integration-tests.sh` script will create a local
[`kind`](https://kind.sigs.k8s.io/) cluster on which the integration tests will run.

### Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com/) to agree on some conventions about whitespace/file encoding.

```bash
$ brew install pre-commit
[...]
$ pre-commit install
pre-commit installed at .git/hooks/pre-commit
```
