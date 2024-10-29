---
name: Add new K8s version
about: 'Checklist for maintainers to add new K8s minor version'
title: 'Add new K8s version vX.X'
labels: ''
assignees: ''

---

<!-- Note: Please update the issue title to include the new Kubernetes version number. -->

# Adding a new Kubernetes Version

## `pinniped's ci branch`

- [ ] Update `dockerfile-builders` pipeline
- [ ] Update `pull-requests` pipeline
- [ ] Update `main` pipeline

## `pinniped`

- [ ] Bump all golang dependencies (especially the `k8s.io` dependencies to use the new minor version).
  - [ ] Be sure to verify that everything compiles and unit tests pass locally. This is probably a good starting point.
```shell
./hack/update-go-mod/update-go-mod.sh
./hack/module.sh unit
./hack/prepare-for-integration-tests.sh
```
- [ ] Log in to github as pinniped-ci-bot, then go to [this page](https://github.com/pinniped-ci-bot?tab=packages) and change the settings for the new `k8s-code-generator-1.*` image to be publicly visible
- [ ] Add the new K8s version to `hack/lib/kube-versions.txt` and run code generation.

## General Tasks

- [ ] Consider dropping support for any older versions of Kubernetes
- [ ] Create stories or chores to take advantage of features in the new Kubernetes version
- [ ] Close this issue
