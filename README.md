# Pinniped

<img src="https://cdn.pixabay.com/photo/2015/12/07/21/52/harbor-1081482_1280.png" alt="Image of pinniped" width="250px"/>

<!--
    Image source: https://pixabay.com/illustrations/harbor-seal-sitting-maine-marine-1081482/
    Free for commercial use without attribution. https://pixabay.com/service/license/
-->

## About Pinniped

Pinniped provides authentication for Kubernetes clusters.

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

## Licence

Pinniped is open source and licenced under Apache License Version 2.0. See [LICENSE](LICENSE) file.

Copyright 2020 VMware, Inc.
