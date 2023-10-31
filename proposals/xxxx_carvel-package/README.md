---
title: "Carvel Package Management for Pinniped"
authors: [ "@benjaminapetersen" ]
status: "in-review"
sponsor: [ "@cfryanr", "@joshuatcasey" ]
approval_date: ""
---

*Disclaimer*: Proposals are point-in-time designs and decisions.
Once approved and implemented, they become historical documents.
If you are reading an old proposal, please be aware that the
features described herein might have continued to evolve since.

# Carvel Package Management for Pinniped

## Problem Statement

There are a number of tools available to the Kubernetes ecosystem for deploying complex software 
to a Kubernetes cluster.  The Carvel toolchain provides a set of APIs, Custom Resources and CLI tools
that can aid a user in the configuration and lifecycle management of software deployed to a cluster.
We should enhance our deployment options by providing Carvel Packages for the Supervisor and Concierge
that may be installed on a cluster configured with Carvel's `kapp-controller` to manage the software 
on the cluster. 

## How Pinniped Works Today (as of version v0.25.0)

The `./deploy` directory in the root of the Pinniped repository contains a set of `ytt` templates
that:
- Are pre-rendered into installable templates listed with each Pinniped release:
  - [v0.25.0](https://github.com/vmware-tanzu/pinniped/releases/tag/v0.25.0)
- Can optionally be customized and rendered by a consumer of the Pinniped project by cloning down
  the github repository, making changes to the `values.yaml` file and then rendered via `ytt`.


## Terminology / Concepts

- `Carvel` is an open-source project that provides tools for managing software build, configuration
   and deployment on a Kubernetes cluster.  For more information [read the Carvel docs](https://carvel.dev/).
- `kapp` is a Carvel provided CLI tool for deploying software onto a Kubernetes cluster. See 
   [the docs](https://carvel.dev/kapp/) for more information.
- `imgpkg` is a Carvel provided CLI tool that provides a mechanism for collecting configuration and 
   OCI images into a bundle that can be deployed on a cluster.
- `kapp-controller` is a server side component managing software in the form of Carvel `App`s delivered
   via Carvel `Package`s. See [the docs](https://carvel.dev/kapp-controller/) for more information.
- `PackageRepository` is a custom resource that configures `kapp-controller` with a set of 
  `Package`s on a cluster.  See [the docs](https://carvel.dev/kapp-controller/docs/v0.47.x/packaging/#package-repository)
   for more information.
- `Package` is a custom resource that represents configuration in the form of metadata and OCI images
   that may be used to deliver software onto a Kubernetes cluster. See [the docs](https://carvel.dev/kapp-controller/docs/v0.47.x/packaging/#package)
   for more information. 
- `PackageMetadata` is a custom resource describing attributes for a `Package`.  See [the docs](https://carvel.dev/kapp-controller/docs/v0.47.x/packaging/#package-metadata)
   for more information.

## Proposal

Allow Pinniped to be deployed onto a Kubernetes cluster through the mechanism of two Carvel `Packages`,
a Supervisor and a Concierge package. These may be delivered via a `PackageRepository` resource and installed
via `PackageInstall` custom resources, and `Secret`s containing `Package` configuration.

Conceptually, cluster managers would make the Pinniped software available on the 
cluster by deploying the PackageRepository:

```bash
# Deploy the Pinniped PackageRepository to the globally available
# namespace watched by kapp-controller for new Packages 
kapp deploy --app pinniped-package-repository --file <pinniped-release-files>/pinniped-package-repository.yaml
```

Then developers responsible for deploying Supervisor and Concierge would create the 
appropriate resources to successfully deploy the PackageInstall and Packages for both 
Supervisor and Concierge:

```bash 
# create a Service account and RBAC for the PackageInstall 
vim supervisor-service-and-rbac.yaml
kapp deploy --app supervisor-rbac --file supervisor-service-and-rbac.yaml
vim concierge-service-and-rbac.yaml
kapp deploy --app concierge-rbac --file concierge-service-and-rbac.yaml

# create a PackageInstall and a Secret for configuring the Concierge
vim supervisor-package-install-bundle.yaml
kapp deploy --app supervisor --file supervisor-package-install-bundle.yaml
vim concierge-package-install-bundle.yaml
kapp deploy --app supervisor --file concierge-package-install-bundle.yaml
```

The `PackageRepository` will contain a series of versions of each of the Packages for Supervisor 
and Concierge.

The `PackageInstall` files will contain `constraints` representing acceptable versions of both the 
Supervisor and Concierge. For example:

```yaml
spec:  
  packageRef:
    # there will be two separate PackageInstall files, one for each 
    # Supervisor and Concierge
    refName: "supervisor.pinniped.dev"
    versionSelection:
      # Constraints may be used to specify an exact version of the package    
      constraints: "0.25.0"  
      # Alternatively, a constraint can be based on a semver range and can 
      # specify multiple acceptable versions of the software.  In this case, 
      # the Package will automatically upgrade to new versions when they become
      # available, for example, when a new version of the PackageRepository is 
      # deployed containing new versions of the Packages.
      constraints: ">0.25.0"  
```

### Goals and Non-goals

Goals
- Provide an additional deployment option to deliver Pinniped software to a Kubernetes cluster
  in the form of the `Package` apis provided by the Carvel toolchain.
- Provide a `PackageRepository` and two separate `Package`s for Supervisor and Concierge.

Non-Goals
- Provide additional deployment alternatives, such as official Helm charts
- Provide a single package for both Supervisor and Concierge.
- Provide Packages for testing tools, such as `local-user-authenticator`.

#### API Changes

No changes or additions to Pinniped's own APIs, this proposal represents a second, alternative 
method for deployment utilising Carvel APIs and tools.  

#### Upgrades

Upgrading Pinniped via the Carvel Package mechanism will look something like this:

- We deliver a `PackageRepository` that lists:
  - Pinniped Supervisor package at a number of versions (ex: 0.23.0,0.24.0,0.25.0, etc)
  - Pinniped Concierge package at a number of versions (ex: 0.23.0,0.24.0,0.25.0, etc)
- The user installs the Pinniped `PackageRepository`.
- The user creates:
  - A Supervisor and Concierge `PackageInstall` Custom Resource (and `Secret`) with the following:
```yaml
spec:  
  packageRef:
    refName: "supervisor.pinniped.dev"
    versionSelection:
      # - Constraints control the version and upgrades of the package
      #   if the constraint is pinned to a specific version, then only 
      #   that version is installed on the cluster
      # - If the PackageResource no longer serves a version that matches
      #   the constraint, then the PackageInstall will enter an error state
      #   until the constraint is updated      
      constraints: "0.25.0"  
      # - Alternatively, a constraint can be based on a semver range and can 
      #   control automatic updates.  
      constraints: ">0.25.0"  
```

#### Tests

Our current integration test suite uses the `./deploy` directory to deploy Pinniped onto a 
variety of clusters.  We should continue to test this for the majority of users who do not 
integrate with Carvel.  In addition, we should update at least 1 of our tests to make use of 
the new `Package` mechanism to ensure it functions correctly.  

Optionally we can:

- Change a single test to deploy via the `Package` mechanism
- Change several tests to deploy via the `Package` mechanism
- Provide a flag to our `./prepare-for-integration-test.sh` and cycle all of our tests,
  perhaps randomly back and forth between the simple deploy and the Package deploy.

#### New Dependencies

The Carvel toolset is not strictly a dependency for Pinniped itself.  This proposal is an 
optional method for delivering the Pinniped software to a kubernetes cluster.  Therefore, `kapp`, 
`kapp-controller`, and the custom resources such as `PackageRepository`, `Package`, `PackageMetadata`,
`PackageInstall` as well as `imgpkg`, `vendir` and `ytt` are all optional dependencies for a 
consumer of Pinniped.

#### Performance Considerations

None.  It is up to the user to determine if the adoption of the Carvel toolset is the 
correct decision for their application lifecycle needs.

#### Observability Considerations

`Package`, `App` and `PackageInstall` custom resources contain a `status` field like many 
Kubernetes resources.  These are thoroughly detailed with relevant bits of information that may 
aid the user in understanding the state of their applications.  For example, a Carvel `App` Custom Resource
(disambiguation, a Carvel `app` (lowercase) from `kapp` vs an `App` (uppercase) from `kapp-controller` are
entirely different resources) contains a detailed status referencing all resources owned by the `App`. This
is very helpful when attempting to understand the state of a complex multi-component application.

#### Security Considerations

Carvel is a toolset separate from Pinniped.  This feature is optional, users who choose to use 
Carvel should assess Carvel for its risks and tradeoffs. 

#### Usability Considerations

As of today the `./deploy` directory of Pinniped is implemented via the use of a subset of the 
Carvel toolchain, namely, `ytt`.  However, it is implemented in such a way that consumers of Pinniped
have choice, they may opt in to the use of the Carvel toolchain, or simply `kubectl apply -f` our 
pre-rendered yaml files, there is no requirement to use the Carvel toolchain.

This feature serves the community users who have deeply adopted Carvel into their management, such that
`kapp-controller` is installed on their cluster and used to manage software lifecycle.

#### Documentation Considerations

This design doc serves as an announcement that the feature will be implemented.
It would be helpful to provide a blog post describing how the feature was validated.
Also include in release notes.

#### Other Approaches Considered

None.

## Open Questions

A list of questions that need to be answered.

## Answered Questions 

* TBD - [Consult the open issue](https://github.com/vmware-tanzu/pinniped/issues/1614) requesting
  the creation of this proposal

## Implementation Plan

* TBD

## Implementation PRs

* TBD
* Consult the [Proof of concept WIP PR](https://github.com/vmware-tanzu/pinniped/pull/1635) 
