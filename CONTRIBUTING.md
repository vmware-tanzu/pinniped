# Contributing to Pinniped

Pinniped is better because of our contributors and [maintainers](MAINTAINERS.md). It is because of you that we can bring
great software to the community.

Contributions to Pinniped are welcome. Here are some things to help you get started.

## Code of Conduct

Please see the [Code of Conduct](./CODE_OF_CONDUCT.md).

## Project Scope

See [SCOPE.md](./SCOPE.md) for some guidelines about what we consider in and out of scope for Pinniped.

## Roadmap

The near-term and mid-term roadmap for the work planned for the project [maintainers](MAINTAINERS.md) is documented in [ROADMAP.md](ROADMAP.md).

## Discussion

Got a question, comment, or idea? Please don't hesitate to reach out
via GitHub [Discussions](https://github.com/vmware-tanzu/pinniped/discussions),
GitHub [Issues](https://github.com/vmware-tanzu/pinniped/issues),
or in the Kubernetes Slack Workspace within the [#pinniped channel](https://go.pinniped.dev/community/slack).
Join our [Google Group](https://go.pinniped.dev/community/group) to receive updates and meeting invitations.

## Issues

Need an idea for a project to get started contributing? Take a look at the open
[issues](https://github.com/vmware-tanzu/pinniped/issues).
Also check to see if any open issues are labeled with
["good first issue"](https://github.com/vmware-tanzu/pinniped/labels/good%20first%20issue)
or ["help wanted"](https://github.com/vmware-tanzu/pinniped/labels/help%20wanted).

### Bugs

To file a bug report, please first open an
[issue](https://github.com/vmware-tanzu/pinniped/issues/new?template=bug_report.md). The project team
will work with you on your bug report.

Once the bug has been validated, a [pull request](https://github.com/vmware-tanzu/pinniped/compare)
can be opened to fix the bug.

For specifics on what to include in your bug report, please follow the
guidelines in the issue and pull request templates.

### Features

To suggest a feature, please first open an
[issue](https://github.com/vmware-tanzu/pinniped/issues/new?template=feature-proposal.md)
and tag it with `proposal`, or create a new [Discussion](https://github.com/vmware-tanzu/pinniped/discussions).
The project [maintainers](MAINTAINERS.md) will work with you on your feature request.

Once the feature request has been validated, a [pull request](https://github.com/vmware-tanzu/pinniped/compare)
can be opened to implement the feature.

For specifics on what to include in your feature request, please follow the
guidelines in the issue and pull request templates.

### Reporting security vulnerabilities

Please follow the procedure described in [SECURITY.md](SECURITY.md).

## CLA

We welcome contributions from everyone, but we can only accept them if you sign
our Contributor License Agreement (CLA). If you would like to contribute and you
have not signed it, our CLA-bot will walk you through the process when you open
a Pull Request. For questions about the CLA process, see the
[FAQ](https://cla.vmware.com/faq) or submit a question through the GitHub issue
tracker.

## Learning about Pinniped

New to Pinniped?
- Start here to learn how to install and use Pinniped: [Learn to use Pinniped for federated authentication to Kubernetes clusters](https://pinniped.dev/docs/tutorials/concierge-and-supervisor-demo/)
- Start here to learn how to navigate the source code: [Code Walk-through](https://pinniped.dev/docs/reference/code-walkthrough/)
- Other more detailed documentation can be found at: [Pinniped Docs](https://pinniped.dev/docs/)

## Building

The [Dockerfile](Dockerfile) at the root of the repo can be used to build and
package the server-side code. After making a change to the code, rebuild the
docker image with the following command.

```bash
# From the root directory of the repo...
docker build .
```

The Pinniped CLI client can be built for local use with the following command.

```bash
# From the root directory of the repo...
go build -o pinniped ./cmd/pinniped
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

   - [`docker`](https://www.docker.com/)
   - `htpasswd` (installed by default on MacOS, usually found in `apache2-utils` package for linux)
   - [`kapp`](https://carvel.dev/#getting-started)
   - [`kind`](https://kind.sigs.k8s.io/docs/user/quick-start)
   - [`kubectl`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
   - [`ytt`](https://carvel.dev/#getting-started)
   - [`nmap`](https://nmap.org/download.html)
   - [`openssl`](https://www.openssl.org) (installed by default on MacOS)
   - [Chrome](https://www.google.com/chrome/)

   On macOS, these tools can be installed with [Homebrew](https://brew.sh/) (assuming you have Chrome installed already):

   ```bash
   brew install kind vmware-tanzu/carvel/ytt vmware-tanzu/carvel/kapp kubectl nmap && brew cask install docker
   ```

1. Create a kind cluster, compile, create container images, and install Pinniped and supporting test dependencies using:

   ```bash
   ./hack/prepare-for-integration-tests.sh
   ```

1. Run the Pinniped integration tests:

   ```bash
   ulimit -n 512 && source /tmp/integration-test-env && go test -v -count 1 -timeout 0 ./test/integration
   ```

   To run specific integration tests, add the `-run` flag to the above command to specify a regexp for the test names.
   Use a leading `/` on the regexp because the Pinniped integration tests are automatically nested under several parent tests
   (see [integration/main_test.go](https://github.com/vmware-tanzu/pinniped/blob/main/test/integration/main_test.go)).
   For example, to run an integration test called `TestE2E`, add `-run /TestE2E` to the command shown above.

1. After making production code changes, recompile, redeploy, and run tests again by repeating the same
   commands described above. If there are only test code changes, then simply run the tests again.

To destroy the local Kubernetes cluster, run `./hack/kind-down.sh`.

#### Using GoLand to Run an Integration Test

It can sometimes be convenient to use GoLand to run an integration test. For example, this allows using the
GoLand debugger to debug the test itself (not the server, since that it running in-cluster).

Note that the output of `hack/prepare-for-integration-tests.sh` says:

```bash
# Using GoLand? Paste the result of this command into GoLand's run configuration "Environment".
#    hack/integration-test-env-goland.sh | pbcopy
```

After using `hack/prepare-for-integration-tests.sh`, run `hack/integration-test-env-goland.sh | pbcopy` as instructed. Then:

1. Select and run an integration test within GoLand. It will fail complaining about missing env vars.
1. Pull down the menu that shows the name of the test which you just ran in the previous step, and choose "Edit Configurations...".
1. In the "Environment" text box for the run configuration of the integration test that you just ran,
   paste the results of `hack/integration-test-env-goland.sh | pbcopy`.
1. Apply, and then run the integration test again. This time the test will use the environment variables provided.

Note that if you run `hack/prepare-for-integration-tests.sh` again, then you may need to repeat these steps.
Each run of `hack/prepare-for-integration-tests.sh` can result in different values for some of the env vars.

### Observing Tests on the Continuous Integration Environment

[CI](https://ci.pinniped.dev/teams/main/pipelines/pull-requests)
will not be triggered on a pull request until the pull request is reviewed and
approved for CI by a project [maintainer](MAINTAINERS.md). Once CI is triggered,
the progress and results will appear on the Github page for that
[pull request](https://github.com/vmware-tanzu/pinniped/pulls) as checks. Links
will appear to view the details of each check.

## CI

Pinniped's CI configuration and code is in the [`ci`](https://github.com/vmware-tanzu/pinniped/tree/ci)
branch of this repo. The CI results are visible to the public at https://ci.pinniped.dev.

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
contact an existing [maintainer](MAINTAINERS.md) if you would like to be considered.
