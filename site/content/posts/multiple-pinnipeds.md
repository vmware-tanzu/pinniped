---
title: "Pinniped v0.5.0: Now With Even More Pinnipeds"
slug: multiple-pinnipeds
date: 2021-02-04
author: Matt Moyer
image: https://images.unsplash.com/photo-1558060370-d644479cb6f7?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=2000&q=80
excerpt: "We encountered a problem that’s familiar to many Kubernetes controller developers: we need to support multiple instances of our controller on one cluster."
tags: ['Matt Moyer', 'api', 'release']
---

![toy robots](https://images.unsplash.com/photo-1558060370-d644479cb6f7?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=2000&q=80)
*Photo by [TRINH HUY HUNG](https://unsplash.com/@hungthdsn) on [Unsplash](https://unsplash.com/)*

## Motivation

Pinniped is a "batteries included" authentication system for Kubernetes clusters that tightly integrates with Kubernetes using native API patterns.
Pinniped is built using [custom resource definitions (CRDs)][crd] and [API aggregation][api-aggregation], both of which are core to the configuration and runtime operation of the app.

We encountered a problem that’s familiar to many Kubernetes controller developers: *we need to support multiple instances of our controller on one cluster*.

You may have a similar need for several reasons, such as:

1. **Soft Multi-Tenancy:** several teams share a cluster and they each want to manage their own instance of a controller.
3. **Scaling:** you have outgrown the vertical scaling limit for your controller and would like to shard it along some dimension that’s easy to operate and reason about.
4. **Backwards Compatibility:** you want to deploy two versions of your controller and provide a window of time for consumers to smoothly upgrade to the new version.
5. **Controller Development:** you want to run, for example, the *stable* and *alpha* versions of your controller on the same cluster. Most cluster users will only rely on the stable version, but some test workloads will use the alpha version.

With [Pinniped v0.5.0](https://github.com/vmware-tanzu/pinniped/releases/v0.5.0), we wanted to be able to bundle an opinionated configuration of Pinniped into our downstream commercial products while also allowing our customers to install their own Pinniped instance and configure it however they like.

This post describes how we approached the need for multiple Pinnipeds in v0.5.0.
   
## Existing Approaches

For many Kubernetes controllers, there are existing best practices that will work well:

1. **Add a "controller class" field:** the most well-known example of this pattern is the `spec.ingressClassName` field in the [`networking.k8s.io/v1` Ingress resource][ingress-spec] (formerly the `kubernetes.io/ingress.class` annotation).

   This field tags a particular object so that only the designated controller instance will watch it.
   This means that you must configure all the participating controllers to do the proper filtering and ignore any resources that they're not intended to manage.

1. **Use API versioning machinery:** the other key technique is to strictly adhere to Kubernetes API contracts and take advantage of Kubernetes versioning machinery.
   Your CRD can have multiple versions and you can write a webhook to handle gracefully converting between versions so that several versions of your controller can co-exist peacefully.

These two techniques are sufficient for many situations but have some limitations.
If your app uses [Kubernetes API aggregation][api-aggregation] then a controller class annotation may not be sufficient, since each version of your API group must be registered with a single [APIService][apiservice] resource.

Even in a purely CRD-based app, the CRD definition and associated [webhook conversion service][webhook-conversion] can only be defined once for each API type.
At a minimum, this requires that you carefully manage the deployment of these resources.
For example, in the soft multi-tenancy use case several teams must coordinate to deploy these singleton resources.

Building and maintaining webhook conversion functionality also carries a cost, especially if you need to handle many versions worth of version skew.

## Our Solution

Our solution is to have a single controller codebase where the names of all the API groups can be adjusted via configuration.
This is controlled via a new `--api-group-suffix` flag on the Pinniped server commands.
When unset, Pinniped defaults to the `pinniped.dev` API group, which is the "true" name we use in our API definitions and generated code.

When a user deploys Pinniped with a custom API group suffix such as `--api-group-suffix=pinniped1.example.com`, several new behaviors are triggered:

- **Templated Resources:** at install time, the Pinniped [ytt] templates will render renamed versions of CRD and APIService resources (via [`z0_crd_overlay.yaml`][ytt-crd-overlay] and [`deployment.yaml`][ytt-deployment]).
- **Outgoing Controller Requests:** throughout our controller code, we use a consistent set of Kubernetes clients via the [`go.pinniped.dev/internal/kubeclient`][kubeclient-client] package. These clients use [`k8s.io/client-go/rest#Config.Wrap`][rest-config-wrap] to inject a custom [`http.RoundTripper`][roundtripper] that can act as a client middleware layer.

  For each outbound request from our controller API clients, the RoundTripper applies a set of transformations:
  1. It decodes the request from JSON/Protobuf.
  2. It rewrites the request's `apiVersion` to match the configured API group suffix.
  3. It renames other API group references in well-known object fields such as [`metadata.ownerReferences`][ownerreferences].
  4. It re-encodes the request for wire transport and passes it along to the server.
  5. It decodes the response from JSON/Protobuf.
  6. It apply the inverse renaming operation to reverse step three and restore the default API group suffix (`pinniped.dev`).
  7. Finally, it re-encodes the response and passes it back to the client.
  
  Steps 5-7 must also handle the case of streaming response to a `watch` request.
  
  The business logic of these renaming operations is performed by the [`go.pinniped.dev/internal/groupsuffix`][groupsuffix] package, which returns a [`kubeclient.Middleware`][kubeclient-middleware] implementation.
- **Incoming Aggregated API Requests**: our aggregated API server is built using the [`k8s.io/apiserver/pkg/server`][apiserver-pkg] package. We have only a single aggregated API called TokenCredentialRequest, and we were able to get the functionality we needed by creating a custom [`k8s.io/apimachinery/pkg/runtime#Scheme`][runtime-scheme] that registers our API kinds under the custom group (in [`.../server.go`][custom-scheme]).
  
  With this configuration, all the builtin functionality of the generic API server works correctly.
  
  Requests and responses are unmarshaled and marshalled correctly, and the OpenAPI discovery API even serves the custom API group names.

- **App-Specific Code:** the Pinniped concierge server dynamically updates the TokenCredentialRequest APIService to rotate its TLS certificate authority bundle. This code had to become aware of the dynamic API group, but it was as easy as wiring through a new parameter from the CLI flag (see [`.../prepare_controllers.go`][prepare-controllers]).

With this system in place, we've achieved our goal. A user can deploy several instances of Pinniped, each interacting only with its own distinct set of API objects.

The default behavior of Pinniped remains unchanged, and we made sure to implement the changes such that they cause little to no overhead when no custom API group has been configured.

### Advantages and Disadvantages

With v0.5.0, each instance of Pinniped can be upgraded and operated 100% independently, with no coordination or shared state needed.
One remaining constraint is that each instance should be deployed into its own namespace.
This ensures that any other standard Kubernetes objects such as Secrets and ConfigMaps referenced by the configuration do not overlap.

Our middleware solution carries some ongoing costs:

- It took a non-trivial amount of code to implement all the required transformations.
  We now have the maintenance burden of ensuring this code continues to work in future versions of the Kubernetes API machinery.
- Other API consumers (including `kubectl` users) need to know which API group to use.
  This might be as simple as knowing to run `kubectl get jwtauthenticators.authentication.concierge.team1.example.com`
  instead of simply `kubectl get jwtauthenticators`.
  There is no builtin upgrade path between these versions, as there would be with a versioned CRD.
- The extra encoding/decoding steps cause some performance impact when this feature is in use.
  None of the Pinniped APIs are used in high throughput use cases, so this was not much a problem for us.


## Future Work

We're happy to have shipped this for Pinniped v0.5.0, but we have more ideas about how to extend the concept.
One idea is to extract the renaming middleware we've written for Pinniped into a standalone Go library that other Kubernetes apps can adopt.

We could also take this a step further and extract the behavior of our middleware into an out-of-process API proxy that can apply these transformations to an unmodified Kubernetes app.
This would require major changes and it would be challenging to support some features seamlessly, such as Protobuf encoding.

As a team, we have no immediate plans for either of these ideas, but if you are interested please [reach out in GitHub][discussion].

## Join the Pinniped Community!
Pinniped is better because of our contributors and maintainers.
It is because of you that we can bring great software to the community.

Please join us during our online community meetings, occurring every first and third Thursday of the month at 9AM PT / 12PM PT.
Use [this Zoom link][zoom] to attend and add any agenda items you wish to discuss to [the notes document][meeting-notes].

Join our [Google Group][google-group] to receive invites to this meeting.

[api-aggregation]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/
[apiserver-pkg]: https://pkg.go.dev/k8s.io/apiserver/pkg/server
[apiservice]: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#apiservice-v1-apiregistration-k8s-io
[crd]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
[custom-scheme]: https://github.com/vmware-tanzu/pinniped/blob/main/internal/concierge/server/server.go#L182
[discussion]: https://github.com/vmware-tanzu/pinniped/discussions/386
[google-group]:  https://go.pinniped.dev/community/group
[groupsuffix]: https://github.com/vmware-tanzu/pinniped/blob/main/internal/groupsuffix/groupsuffix.go
[ingress-spec]: https://kubernetes.io/docs/reference/kubernetes-api/services-resources/ingress-v1/#IngressSpec
[kubeclient-client]: https://github.com/vmware-tanzu/pinniped/blob/v0.5.0/internal/kubeclient/kubeclient.go#L22
[kubeclient-middleware]: https://github.com/vmware-tanzu/pinniped/blob/v0.5.0/internal/kubeclient/middleware.go#L17-L19
[meeting-notes]: https://go.pinniped.dev/community/agenda
[ownerreferences]: https://kubernetes.io/docs/concepts/workloads/controllers/garbage-collection/#owners-and-dependents
[prepare-controllers]: https://github.com/vmware-tanzu/pinniped/blob/v0.5.0/internal/controllermanager/prepare_controllers.go#L116-L120
[rest-config-wrap]: https://pkg.go.dev/k8s.io/client-go/rest#Config.Wrap
[roundtripper]: https://golang.org/pkg/net/http/#RoundTripper
[runtime-scheme]: https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#Scheme
[webhook-conversion]: https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#webhook-conversion
[ytt-crd-overlay]: https://github.com/vmware-tanzu/pinniped/blob/v0.5.0/deploy/concierge/z0_crd_overlay.yaml
[ytt-deployment]: https://github.com/vmware-tanzu/pinniped/blob/v0.5.0/deploy/concierge/deployment.yaml#L195
[ytt]: https://carvel.dev/ytt/
[zoom]: https://go.pinniped.dev/community/zoom
