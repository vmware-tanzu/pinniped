---
title: "Pinniped v0.18.0: With User-Friendly features such as JSON formatted logs, LDAP/ActiveDirectory UI Support"
slug: formatted-logs-ui-based-ldap-logins
date: 2022-06-08
author: Anjali Telang
image: https://images.unsplash.com/photo-1587738972117-c12f8389f1d4?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1752&q=80
excerpt: "With v0.18.0 you get cool new features like nicely formatted JSON logs, UI to login to your LDAP or ActiveDirectory Identity Provider, and more"
tags: ['Margo Crawford','Ryan Richard', 'Mo Khan', 'Anjali Telang', 'release']
---

![Friendly seal](https://images.unsplash.com/photo-1587738972117-c12f8389f1d4?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1752&q=80)
*Photo by [Steve Adams](https://unsplash.com/@sradams57) on [Unsplash](https://unsplash.com/s/photos/seal)*

We've listened to your requests and are excited to bring some cool user-friendly features that will enhance your Kubernetes Authentication experience. From this release onwards, we will have Pinniped logs in JSON format. We also bring you the ability to use a User Interface (UI) to login with your LDAP or ActiveDirectory credentials.

## JSON Formatted logs

[Kubernetes 1.19](https://kubernetes.io/blog/2020/09/04/kubernetes-1-19-introducing-structured-logs/) introduced the ability to have logs emitted in JSON log format. There are many benefits to using JSON as listed in this [KEP for structured logging](https://github.com/kubernetes/enhancements/tree/master/keps/sig-instrumentation/1602-structured-logging#json-output-format) :

* Broadly adopted by logging libraries with very efficient implementations (zap, zerolog).
* Out of the box support by many logging backends (Elasticsearch, Stackdriver, BigQuery, Splunk)
* Easily parsable and transformable
* Existing tools for ad-hoc analysis (jq)

Considering these benefits, from this release onwards we will *default to JSON formatted logs* for the Pinniped Supervisor and Concierge components.  

**Users please note: We are deprecating the text based log format with this release and we will remove the configuration in a future release.**  

We realize that it may take time for some users to adapt to this new format especially if they have existing tooling around *text* based logs. With that in mind, we will allow users to deploy Pinniped Supervisor or Concierge by setting *deprecated_log_format:text* in the values.yaml deployment file for these components. However, Please consider moving to json formatted logs for compatibility with latest releases. We will announce 2 releases prior to removing the field, as is our policy for removing configurations.

With this release, the Pinniped CLI logs have also been enhanced to emit useful information such as timestamps and line numbers of files, as shown in the example below:

```
$ pinniped get kubeconfig
Tue, 24 May 2022 11:18:50 EDT  cmd/kubeconfig.go:584  discovered CredentialIssuer  {"name": "concierge-config"}
Tue, 24 May 2022 11:18:50 EDT  cmd/kubeconfig.go:419  discovered Concierge operating in impersonation proxy mode
Tue, 24 May 2022 11:18:50 EDT  cmd/kubeconfig.go:432  discovered Concierge endpoint  {"endpoint": "https://abcd"}
Tue, 24 May 2022 11:18:50 EDT  cmd/kubeconfig.go:447  discovered Concierge certificate authority bundle  {"roots": 1}
Tue, 24 May 2022 11:18:50 EDT  cmd/kubeconfig.go:469  discovered WebhookAuthenticator  {"name": "wa"}
```


## LDAP User Interface

With [v0.18.0](https://github.com/vmware-tanzu/pinniped/releases/tag/v0.18.0) we are also adding support for a User Interface that users can access to input their credentials and login to their LDAP or Active Directory Identity Provider(IDP). This feature is a first step in our effort to provide a UI-driven workflow for our users. We will have more features that support UI workflows coming up in our next release, so stay tuned for that!

When using the Pinniped CLI, a successful login takes the user to the regular form_post success page, just like the previously supported *browser authcode flow* for an OIDC IDP.
This feature changes how the `pinniped get kubeconfig` cli deals with ambiguous flows. Previously, if there was more than one flow advertised for an IDP, the cli would require users to use the `--upstream-identity-provider-flow` flag.  Now, it chooses the first flow type in the Supervisor's discovery response by default.

Here's a snapshot of the UI hosted by the Pinniped Supervisor:
![LDAP / ActiveDirectory UI for login ](/docs/img/ldap-ad-ui.png)

### Features included in the UI  
The UI will provide the following features for now:

* A username and password fields along with the submit button
* Generalized error messaging for failed logins that do not expose sensitive information  
* Provides information easily allowing a user to identify the screen as belonging to Pinniped with the name of their Identity Provider displayed on the page
* Addresses basic security concerns for web forms such as use of HTTPS, a password field, CSRF protection and redirect protection
* Prevents LDAP injection attacks
* Screens that are accessible and friendly to screen readers
* Screens that are friendly to password managers

### Future enhancements for the UI
This is our effort to provide a basic UI for logins. We will enhance the UI further in future releases based on the feedback we receive from our users.
This can include (but is not limited to) the following features:

* Advanced UI features such as remember me and reveal password
* Branding & customization, besides what we provide today with the basic Pinniped information.
* Support for SSO integrations
* Internationalization or localization. Note that the CLI doesn't currently support this either.

*Note* that Pinniped relies on the user's IDP to address advanced security concerns such as brute force protection, username enumeration, etc.

## What else is in this release?
Refer to the [release notes for v0.18.0](https://github.com/vmware-tanzu/pinniped/releases/tag/v0.18.0) for a complete list of fixes and features included in the release.

## Community contributors

The Pinniped community continues to grow, and is a vital part of the project's success.

[Are you using Pinniped?](https://github.com/vmware-tanzu/pinniped/discussions/152)  
Have you tried any of our new features? Let us know what you think of our logging and UI features and if you are looking for any of the enhancements mentioned above.   

We thrive on community feedback and would like to hear more!  

Reach out to us in [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA) on Kubernetes Slack,
[create an issue](https://github.com/vmware-tanzu/pinniped/issues/new/choose) on our Github repository,
or start a [discussion](https://github.com/vmware-tanzu/pinniped/discussions).

{{< community >}}
