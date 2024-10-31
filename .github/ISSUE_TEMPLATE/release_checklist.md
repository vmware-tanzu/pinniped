---
name: Release checklist
about: Checklist for maintainers to prepare for an upcoming release
title: 'Release checklist for vX.X.X'
labels: ''
assignees: ''

---

<!-- Note: Please update the issue title to include the planned release's version number. -->

# Release checklist

- [ ] Ensure that Pinniped's dependencies have been upgraded, to the extent desired by the team (refer to the diff output from the latest run of the [all-golang-deps-updated](https://ci.pinniped.dev/teams/main/pipelines/security-scan/jobs/all-golang-deps-updated/) CI job)
  - [ ] If you are updating golang in Pinniped, be sure to update golang in CI as well.  Do a search-and-replace to update the version number everywhere in the pinniped `ci` branch.
  - [ ] If the Fosite library is being updated and the format of the content of the Supervisor's storage Secrets are changed, or if any change to our own code changes the format of the content of the Supervisor's session storage Secrets, then be sure to update the `accessTokenStorageVersion`, `authorizeCodeStorageVersion`, `oidcStorageVersion`, `pkceStorageVersion`, `refreshTokenStorageVersion`, variables in files such as `internal/fositestorage/accesstoken/accesstoken.go`.  Failing tests should signal the need to update these values.
  - [ ] For go.mod direct dependencies that are v2 or above, such as `github.com/google/go-github/vXX`, check to see if there is a new major version available.
  - [ ] Evaluate all `replace` directives in the `go.mod` file. Are they up to date versions? Can any `replace` directives be removed?
- [ ] Ensure that Pinniped's codegen is up-to-date with the latest Kubernetes releases by making sure this [file](https://github.com/vmware-tanzu/pinniped/blob/main/hack/lib/kube-versions.txt) is updated compared to the latest releases listed [here for active branches](https://kubernetes.io/releases/) and [here for non-active branches](https://kubernetes.io/releases/patch-releases/#non-active-branch-history)
- [ ] Ensure that the `k8s-code-generator` CI job definitions are up-to-date with the latest Go, K8s, and `controller-gen` versions
- [ ] All relevant feature and docs PRs are merged
- [ ] The [main pipeline](https://ci.pinniped.dev/teams/main/pipelines/main) is green, up to and including the `ready-to-release` job. Check that the expected git commit has passed the `ready-to-release` job.
- [ ] Optional: a blog post for the release is written and submitted as a PR but not merged yet
- [ ] All merged user stories are accepted (manually tested)
- [ ] Only after all stories are accepted, manually trigger the `release` job to create a draft GitHub release
- [ ] Manually edit the draft release notes on the [GitHub release](https://github.com/vmware-tanzu/pinniped/releases) to describe the contents of the release, using the format which was automatically added to the draft release
- [ ] Publish (i.e. make public) the draft release
- [ ] After making the release public, the jobs in the [main pipeline](https://ci.pinniped.dev/teams/main/pipelines/main) beyond the release job should auto-trigger, so check to make sure that they passed
- [ ] Edit the blog post's date to make it match the actual release date, and merge the blog post PR to make it live on the website
- [ ] Publicize the release via tweets, etc.
- [ ] Close this issue
