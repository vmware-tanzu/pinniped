---
title: "Audit Logging"
authors: [ "@cfryanr" ]
status: "in-review"
sponsor: [ ]
approval_date: ""
---

*Disclaimer*: Proposals are point-in-time designs and decisions. Once approved and implemented, they become historical
documents. If you are reading an old proposal, please be aware that the features described herein might have continued
to evolve since.

# Audit Logging

## Problem Statement

Audit logging is a requirement from most compliance standards (e.g. FedRAMP, PCI-DSS). The Pinniped Supervisor and
Concierge components should provide audit logs to help users meet these compliance requirements.

The Kubernetes API server already supports
rich [audit logging features](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/) which are implemented
by vendors of Kubernetes distributions. The Pinniped audit logs are meant to augment, not replace, the Kubernetes audit
logs.

### How Pinniped Works Today (as of version v0.16.0)

The Pinniped Supervisor and Concierge components are Kubernetes Deployments. Today, each Pod has a single container,
which is the Supervisor or Concierge app. Kubernetes captures the stdout of the app into the Pod logs.

Today, the Pinniped Supervisor and Concierge log many interesting events to their Pod logs. These logs are meant
primarily to help an admin user debug problems with their Pinniped configuration or with their cluster. The Supervisor
and Concierge each offer an install-time configuration option to turn up the verbosity of these Pod logs.

However, these logs are not meant to be audit logs. They generally focus on logging problems, not on logging successes.
They try to avoid logging anything that might be confidential or PII (personally identifiable information). Since email
addresses might be considered PII, these logs generally avoid including usernames at the default log level, since
usernames could be email addresses in some configurations. Logging the identity of actors (usernames) are a key aspect
of audit logs.

## Terminology / Concepts

None.

## Proposal

The goal of an audit log is to log events that could be helpful in a forensic investigation of past usage, including the
actor (the username) and the actions that were taken on the system.

### Goals and Non-goals

Goals

- Auditing events relating to upstream identity provider (IDP) authentication, refresh, and sessions.
- Auditing events relating to minting and validating cluster credentials.
- Enabling auditors to easily stitch together authentication events into an audit trail.
- Provide consistent data across auditable events.
- Provide the ability to enable and disable auditing.
- Provide the ability to route audit logs to a separate destination from the rest of Pinniped’s logs.

Non-goals

- Enabling auditing in the impersonation proxy. If needed, this will be handled in a separate feature.
- Providing the ability to filter or choose which audit events to capture.
- Auditing the management of CRs (e.g. OIDCIdentityProvider). These events are captured by the API server audit logs.

### Specification / How it Solves the Use Cases

This proposal recommends following the recommendation of the Kubernetes docs to create a separate Pod container log.
This new container log will contain the audit logs (and only the audit logs).

#### API Changes

##### Configuration Options

There will be very few user-facing configuration options for audit logging in the first version of the feature. If later
found to be needed, more configuration could be added in future versions.

This proposal recommends adding a single on/off install-time configuration option for disabling audit logs. By default,
audit logs will be enabled. An admin user who is concerned about logging identities, for example because usernames may
be considered PII, may disable audit logging.

Like other install-time configuration options, this option would appear in the values.yaml file of the Supervisor and
Concierge deployment directories. The selected value would be rendered into the "static" ConfigMap, and read by the
Supervisor or Concierge app's Golang code at Pod startup time.

##### Event Data

Deciding every specific audit event is an implementation detail beyond the scope of this proposal.

Generally, the following data should be included with every audit event, whenever possible:

- What type of event occurred (e.g. login)
- Outcomes of event (succeed or fail)
- When the event occurred
- Where the event occurred (Kubernetes Pod logs automatically include the ID of the Pod, which should be sufficient)
- Source of the event (e.g. requester IP address)
- The identity of individuals or subjects associated with the event (who initiated, who participated. etc.)
- Details involving any objects accessed

The Supervisor's audit logs would include events such as:

- Upstream logins for all IdP types (started, succeeded, failed)
- Upstream refresh for all IdP types (succeeded, failed)
- Upstream group refresh for all IdP types (succeeded, failed)
- Downstream login (started, succeeded, failed)
- Downstream token exchange (succeeded, failed)
- Session expired
- Maybe: The equivalent of access log events for all Supervisor endpoints, since there is no other component providing
  access logs. This would include logging things like calls to the Supervisor's OIDC well-known discovery endpoint.
  These logs could help an investigator determine more about the usage pattern of a suspicious client.
- Maybe: Newly authenticated user is associated with “admin” RBAC. Note that the Supervisor is not directly aware of
  RBAC, so determining this would require otherwise unnecessary calls to the Kubernetes API server, which would degrade
  the performance of the Supervisor. It's also not clear what would constitute "admin" level access, since RBAC is
  configurable at a very fine-grained level. On the other hand, the Supervisor is directly aware of the user's group
  memberships, which could be logged.

The Concierge's audit logs would include events such as:

- Token credential request (succeeded, failed, maybe maps to admin RBAC). While already captured by the API server audit
  logs, those should likely be set to metadata. Duplicating the event allows for more controlled capture & management of
  data.
- WhoAmI Request. While already captured by the API server audit logs, duplicating the event allows for more controlled
  capture & management of data.

Other events may be useful to auditors and may be included in the audit logs, such as:

- Application startup with version information
- Graceful application shutdown

##### Audit Logs as Separate Log Files

The Concierge and Supervisor apps could each send audit logs to separate files on disk in JSON format. The performance
impact of logging to a file should be acceptable thanks to file buffering, but this assumption should be tested. Note
that this approach would not guarantee that the log statement is flushed to the file before the action is performed,
because then we would lose the benefit of buffering. It would be "best effort" to the file, e.g. the process crashing
might lose a few lines of logs. A normal pod shutdown should be able to flush the file without any loss.

[A new streaming sidecar container](https://kubernetes.io/docs/concepts/cluster-administration/logging/#sidecar-container-with-logging-agent)
will be added to both the Concierge and Supervisor apps Deployments' Pods. These containers will tail those audit logs
to stdout, thus effectively moving those log lines from files on the Pod to Kubernetes container logs. Those sidecar
container images can be minimal with just enough in the image to support the unix `tail` command (or similar Go binary,
such as [hpcloud/tail](https://github.com/hpcloud/tail)).

Kubernetes will take care of concerns such as log rotation for the container logs. For the files on the Pod's disk
output by the Supervisor and Concierge apps, we should research whether Pinniped should have code to avoid allowing
those files from growing too large. Old lines can be discarded since the sidecar container should have already streamed
them.

Container logs in JSON format are easy for node-level logging agents, e.g. fluentbit, to ingest/annotate/parse/filter
and send to numerous sink destinations. These containers could still run when audit logs are disabled by the admin, but
would produce no log lines in that case.

##### Parsing, Filtering, and Sending Audit Logs to an External Destination

Many users will use the popular [fluentbit](https://fluentbit.io) project to filter and extract Pod logs from their
cluster. This project implements
a [node-level log agent](https://kubernetes.io/docs/concepts/cluster-administration/logging/#using-a-node-logging-agent)
which understands the Kubernetes directory and file layout for Pod logs. It also has a feature to further enrich the
logs
by [automatically adding more information about the source Pod](https://docs.fluentbit.io/manual/pipeline/filters/kubernetes)
to each event (line) in the log. It supports many configurable options
for [parsing](https://docs.fluentbit.io/manual/pipeline/parsers),
[filtering](https://docs.fluentbit.io/manual/pipeline/filters), and sending logs
to [many destinations](https://docs.fluentbit.io/manual/pipeline/outputs).

By putting the Supervisor and Concierge audit logs into their own Pod logs, Pinniped will be compatible with any
existing node-level agent software which can extract logs from a Kubernetes cluster. This allows the Pinniped code to
focus on generating the logs as JSON, without worrying about providing any configuration options for filtering or
sending to various destinations.

##### Audit Log JSON Format

Each line of audit log will represent an event. Each line will be a complete JSON object,
i.e. `{"key1":"value1","key2":"value2"}`.

Some, but not all, events will be the result of a user making an API request to an endpoint. One API request from a user
may cause more than one event to be logged. If possible, unique ID will be determined for each incoming request, and
will be included in all events caused by that request.

Where possible, the top-level keys of the JSON object will use standardized names. Other top-level keys specific to that
action type may be added. All keys should be included in documentation for the audit log feature.

Every event should include these keys:

- `time`: the timestamp of the event
- `event`: the event type, which is a brief description of what happened, with no string interpolation, so it will
  always be the same for a given event type (e.g. `upstream refresh succeeded`)
- `v`: a number specifying the format version of the event type, starting with `1`, to give us flexibility to make
  breaking changes to the format of an event type in future releases (e.g. change the name of the JSON keys, or change
  the data type of the value of an existing key)

Depending on the event type, an event might include other keys, such as:

- `msg`: a freeform warning or error message meant to be read by a human (e.g. the error message that was returned by an
  upstream IDP during a failed login attempt)
- `requestID`: a unique ID for the request, if the event is related to an API request
- `requestPath`: the path of the endpoint, if the event is related to an API request
- `requestorIP`: the client's IP, if the event is related to an API request
- `user`: the username of the user performing the action, if there is one
- `groups`: the group memberships of the user performing the action, if the action is related determining or changing
  their group memberships

The details of these additional keys will be worked out as the details of the specific events are being worked out,
during implementation of this proposal.

##### Audit Log Timestamps

The date format used in the audit logs should be something which can be easily parsed by fluentbit, to make it easy for
users to configure fluentbit. We could easily document this to provide instructions on how to configure a custom
fluentbit parser for Pinniped audit logs. We should probably
avoid [fluentbit's default json parser's](https://github.com/fluent/fluent-bit/blob/845b6ae8576077fd512dbe64fb8e16ff4b15abdb/conf/parsers.conf#L35-L39)
date format, which assumes dates will be in an ugly format and also lacks sub-second precision
(e.g. `08/Apr/2022:19:24:01 +0000`).

fluentbit uses [strptime](https://linux.die.net/man/3/strptime)
with [an extension for fractional seconds](https://docs.fluentbit.io/manual/pipeline/parsers/configuring-parser#time-resolution-and-fractional-seconds)
to parse timestamps.

It would be desirable for a timestamp to:

1. Be human-readable (e.g. not seconds since an epoch)
2. Be easily parsable by log parsers, especially fluentbit
3. Be expressed in UTC time
4. Use at least millisecond precision
5. Use the consistent JSON key name `time`

[Syslog's RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.3) defines a timestamp format which meets
the above goals. An example timestamp in this format is `2003-10-11T22:14:15.003` which is represents UTC time on
October 11, 2003 at 10:14:15 pm, 3 milliseconds into the next second.

Given this timestamp format, the following fluentbit configuration could be used to parse Pinniped's audit logs.

```
    [PARSER]
      Name   json
      Format json
      Time_Key time
      Time_Format %Y-%m-%dT%H:%M:%S.%L
```

#### Upgrades

Since audit logs will be output to a new location, there are not any backward compatibility concerns for them in the
first release.

Adding a second container to the Pods in generally not noticeable by a user, but may have some impact on existing
installations in some rare cases, so it should be explained in the release notes. For example, a GKE Ingress will, by
default, read the Pod's container definition to try to guess the health check endpoint for the backend Service of the
Ingress. When there is only one container, it will try to guess, but where there is more than one container it will give
up on guessing and instead expect the user to configure the health checks. So upgrading could break the health checks of
a GKE Ingress, if no health checks were configured.

#### Tests

Audit logging will be a user-facing feature, and the format of the logs should be considered a kind of documented API.
Unnecessary changes to the format should be avoided after the first release. Therefore, all audit log events should be
covered by unit tests.

This implies that it may be desirable for the implementation to involve passing around a pointer to some interface to
all code which needs to add events to the audit log. Such an implementation would make the audit logs more testable. A
production code implementation of the interface should take care of common concerns, such as adding the timestamp,
deciding required key names, and formatting the output as JSON. A test implementation of the interface could handle
those common concerns differently to make testing easier.

#### New Dependencies

- We might want to consider using a library like [zap](https://github.com/uber-go/zap) to aid in implementation, but
  that is already an indirect dependency of Pinniped.
- The new streaming sidecar container will need a container image. Using the existing pinniped-server container image
  seems desirable. It is a distroless image, which is good for security. And it is the only image that we currently ship
  in Pinniped releases. One option to make this happen would be to implement the tail command in Go, but any binary that
  can work in a distroless image should be okay. We should avoid adding linux standard libraries to the container image,
  so the binary should be statically linked with no external dependencies. The binary should support the same OS and
  architecture that our existing Go binary supports.

#### Performance Considerations

By using buffered output to write to the audit log files, there should not be any meaningful performance impact. This
assumption should be tested.

#### Observability Considerations

Auditing will improve operator observability, as described in the other sections of this document.

#### Security Considerations

The audit logs will be Pod container logs, so the contents of the logs will be protected by Kubernetes like any Pod
container logs.

#### Usability Considerations

By using Pod container logs, the user will have many options to manage these logs.

#### Documentation Considerations

The supported audit event types, and they JSON keys output for each event type, should be documented. Users should be
able to build their own parsers for these events based on the documentation.

If the production code implementation of the audit interface used Golang constants for all allowed JSON key names and
event type names, and otherwise enforced certain standards, then it may be possible to auto-generate (or nearly
auto-generate) the documentation for the audit event types.

### Other Approaches Considered

None yet.

## Open Questions

- Should we output events that can function similar to access logs for the Supervisor endoints?
- Should we try to somehow detect that a user is "root-like"?

## Answered Questions

None yet.

## Implementation Plan

The maintainers will implement these features. It might fit into one PR.

## Implementation PRs

*This section is a placeholder to list the PRs that implement this proposal. This section should be left empty until
after the proposal is approved. After implementation, the proposal can be updated to list related implementation PRs.*
