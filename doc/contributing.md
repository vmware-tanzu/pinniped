# Contributing to Pinniped

Contributions to Pinniped are welcome. Here are some things to help you get started.

1. Please see the [Code of Conduct](code_of_conduct.md).
1. Learn about the [scope](scope.md) of the project.
1. Coming soon: details about how to legally contribute to the project, including CLA/DCO details.
1. See below for how to [file a bug report](#bugs).
1. See below for how to [suggest a feature](#features).
1. See below for how to [build the code](#building).
1. See below for how to [run the tests](#testing).

## Meeting with the Maintainers

The maintainers aspire to hold a video conference every other week with the Pinniped community.
Any community member may request to add topics to the agenda by contacting a [maintainer](../MAINTAINERS.md)
in advance, or by attending and raising the topic during time remaining after the agenda is covered.
Typical agenda items include topics regarding the roadmap, feature requests, bug reports, pull requests, etc.
A [public document](https://docs.google.com/document/d/1qYA35wZV-6bxcH5375vOnIGkNBo7e4OROgsV4Sj8WjQ)
tracks the agendas and notes for these meetings.

These meetings are currently scheduled for the first and third Thursday mornings of each month
at 8 AM Pacific Time, using this [Zoom meeting](https://VMware.zoom.us/j/94638309756?pwd=V3NvRXJIdDg5QVc0TUdFM2dYRzgrUT09).
If the meeting day falls on a US holiday, please consider that occurrence of the meeting to be canceled.

## Bugs

To file a bug report, please first open an
[issue](https://github.com/vmware-tanzu/pinniped/issues/new?template=bug_report.md). The project team
will work with you on your bug report.

Once the bug has been validated, a [pull request](https://github.com/vmware-tanzu/pinniped/compare)
can be opened to fix the bug.

For specifics on what to include in your bug report, please follow the
guidelines in the issue and pull request templates.

## Features

To suggest a feature, please first open an
[issue](https://github.com/vmware-tanzu/pinniped/issues/new?template=feature-proposal.md)
and tag it with `proposal`. The project team will work with you on your feature request.

Once the feature request has been validated, a [pull request](https://github.com/vmware-tanzu/pinniped/compare)
can be opened to implement the feature.

For specifics on what to include in your feature request, please follow the
guidelines in the issue and pull request templates.

## Issues

Github [issues](https://github.com/vmware-tanzu/pinniped/issues) can also be used for general
inquiries and discussion regarding the project.

Need an idea for a project to get started contributing? Take a look at the open
[issues](https://github.com/vmware-tanzu/pinniped/issues).
Also check to see if any open issues are labeled with
["good first issue"](https://github.com/vmware-tanzu/pinniped/labels/good%20first%20issue)
or ["help wanted"](https://github.com/vmware-tanzu/pinniped/labels/help%20wanted).

## CLA

We welcome contributions from everyone but we can only accept them if you sign
our Contributor License Agreement (CLA). If you would like to contribute and you
have not signed it, our CLA-bot will walk you through the process when you open
a Pull Request. For questions about the CLA process, see the
[FAQ](https://cla.vmware.com/faq) or submit a question through the GitHub issue
tracker.

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

1. Install dependencies:

   - [`kind`](https://kind.sigs.k8s.io/docs/user/quick-start)
   - [`tilt`](https://docs.tilt.dev/install.html)
   - [`ytt`](https://carvel.dev/#getting-started)
   - [`kubectl`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

   On macOS, these tools can be installed with [Homebrew](https://brew.sh/):

   ```bash
   brew install kind tilt-dev/tap/tilt k14s/tap/ytt kubectl
   ```

1. Create a local Kubernetes cluster using `kind`:

   ```bash
   kind create cluster --image kindest/node:v1.18.8
   ```

1. Install Pinniped and supporting dependencies using `tilt`:

   ```bash
   tilt up -f ./hack/lib/tilt/Tiltfile --stream
   ```

   Tilt will continue running and live-updating the Pinniped deployment whenever the code changes.

1. Run the Pinniped integration tests:

   ```bash
   source ./hack/lib/tilt/integration-test.env && go test -v -count 1 ./test/integration
   ```

To uninstall the test environment, run `tilt down -f ./hack/lib/tilt/Tiltfile`.
To destroy the local Kubernetes cluster, run `kind delete cluster`.

### Observing Tests on the Continuous Integration Environment

CI will not be triggered on a pull request until the pull request is reviewed and
approved for CI by a project [maintainer](../MAINTAINERS.md). Once CI is triggered,
the progress and results will appear on the Github page for that
[pull request](https://github.com/vmware-tanzu/pinniped/pulls) as checks. Links
will appear to view the details of each check.

## Documentation

Any pull request which adds a new feature or changes the behavior of any feature which was previously documented
should include updates to the documentation. All documentation lives in this repository. This project aspires to
follow the Kubernetes [documentation style guide](https://kubernetes.io/docs/contribute/style/style-guide).

## Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com/) to agree on some conventions about whitespace/file encoding.

```bash
$ brew install pre-commit
[...]
$ pre-commit install
pre-commit installed at .git/hooks/pre-commit
```

## Becoming a Pinniped Maintainer

Regular contributors who are active in the Pinniped community and who have contributed at least several
significant pull requests may be considered for promotion to become a maintainer upon request. Please
contact an existing [maintainer](../MAINTAINERS.md) if you would like to be considered.
