# placeholder-name

Copyright 2020 VMware, Inc.

## Developing

### Running Lint

```cmd
./hack/module.sh lint
```

### Running Tests

```cmd
./hack/module.sh unittest
```

### Pre-commit hooks

This project uses the [pre-commit] to agree on some conventions about whitespace/file encoding.

```cmd
$ brew install pre-commit
[...]
$ pre-commit install
pre-commit installed at .git/hooks/pre-commit
```

[pre-commit]: https://pre-commit.com/
