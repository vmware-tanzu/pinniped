# Contributing to Pinniped

We would love for you to contribute to Pinniped! Here is a basic list of things
you may want to know to get started.

1. Check out our [Code of Conduct](code-of-conduct.md).
1. Learn about the [scope](scope.md) of our project.
1. Coming soon: details about how to legally contribute to the project!
1. See below for how to [file a bug report](#bugs).
1. See below for how to [suggest a feature](#features).
1. See below for how to [build the code](#building).
1. See below for how to [run the tests](#testing).

## Bugs

To file a bug report, please first open an
[issue](https://github.com/suzerain-io/pinniped/issues/new?template=bug_report.md). The project team
will work with you on your bug report.

Once the bug has been validated, a [pull
request](https://github.com/suzerain-io/pinniped/compare) can be opened to fix
the bug.

For specifics on what to include in your bug report, please follow the
guidelines in the issue and pull request templates!

## Features

To suggest a feature, please first open an
[issue](https://github.com/suzerain-io/pinniped/issues/new) and tag it with
`proposal`. The project team will work with you on your feature request.

Once the feature request has been validated, a [pull
request](https://github.com/suzerain-io/pinniped/compare) can be opened to
implement the feature.

For specifics on what to include in your feature request, please follow the
guidelines in the issue and pull request templates!

## Building

The [Dockerfile](../Dockerfile) at the root of the repo is how we build and
package the `pinniped-server` code. After you make a change to the code, you can
rebuild that docker image with the following command.

```cmd
# From the root of the repo...
docker build .
```

## Testing

### Running Lint

```cmd
./hack/module.sh lint
```

### Running Unit Tests

```cmd
./hack/module.sh unittest
```

### Running Integration Tests

More details coming soon!

### Pre-commit hooks

This project uses the [pre-commit] to agree on some conventions about whitespace/file encoding.

```cmd
$ brew install pre-commit
[...]
$ pre-commit install
pre-commit installed at .git/hooks/pre-commit
```

[pre-commit]: https://pre-commit.com/
