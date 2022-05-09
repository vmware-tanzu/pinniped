---
title: "Web UI for LDAP/AD login"
authors: [ "@margocrawf" ]
status: "draft"
approval_date: ""
---

*Disclaimer*: Proposals are point-in-time designs and decisions.
Once approved and implemented, they become historical documents.
If you are reading an old proposal, please be aware that the
features described herein might have continued to evolve since.

# Web UI for LDAP/AD login

## Problem Statement
Today the supervisor only supports a single, hard coded public OAuth client called
"pinniped-cli" which supports the pinniped CLI’s interactions with the Pinniped Supervisor.
When clients log in to their IDPs using LDAP or Active Directory, they are prompted to enter their
credentials the Pinniped CLI without a browser opening.
The pinniped cli sends the client credentials to the Supervisor, which sends them to the identity provider.
The "pinniped-cli" client is privileged and as such is trusted to handle a user's credentials
when authenticating with systems that do not provide an authentication UI (i.e. LDAP).

However, Pinniped is planning to introduce support for dynamic OAuth clients.
These clients should _not_ be trusted to handle a user's IDP credentials.
Therefore, we need a mechanism for untrusted clients to acquire Pinniped's downstream tokens while
leaving the IDP credential handling to the Pinniped supervisor.

## Proposal
Pinniped must provide a simple login screen in order to support UIs that wish
to authenticate with the Pinniped Supervisor to gain access to a cluster without
requiring each app to handle IDP credentials.

### Goals and Non-goals

#### Goals
* Prevent OAuth clients, other than the Pinniped CLI, from providing credentials via the authorization request
* Provide a minimal feature set (ie user id, password & submit button only)
* Provide generalized error messaging for failed logins that do not expose sensitive information (i.e. we should say "invalid username or password"
  but do not expose whether it's the username or password that's incorrect)
* Provide information easily allowing a user to identify the screen as belonging to Pinniped and which upstream IdP is being represented (e.g. IdP name)
* Address basic security concerns for web forms (HTTPS, passwords use a password field, CSRF protection, redirect protection)
* Prevent LDAP injection attacks
* Rely on the upstream IdP to address advanced security concerns (brute force protection, username enumeration, etc)
* Screens are accessible and friendly to screen readers
* Screens are friendly to password managers

#### Non-goals
* A rich client (ie the use of javascript)
* Advanced UI features (e.g. remember me, reveal password).
* Branding & customization beyond the information listed in the goals used to identify the login screen belongs to Pinniped.
* Supporting SSO integrations
* Internationalization or localization. The CLI doesn't currently support this either.

### Specification / How it Solves the Use Cases

#### API Changes

The supervisor must accept requests from other clients, as detailed
in the (todo) proposal for dynamic client registration.
When a client other than pinniped-cli makes an authorization endpoint request with `response_type=code` and their
IDP is an LDAP or Active Directory IDP, the user will be redirected to the new login page.
The login page should display the IDP name and indicate that it belongs to Pinniped.
When a client other than the Pinniped CLI makes an authorization endpoint request with
custom Username/Password headers, they should be rejected.

The discovery metadata for LDAP/AD IDPS should indicate that they support a flow of `browser_authcode`.

The state param should be augmented to include the IDP type as well as the IDP name. The type
should be included in `UpstreamStateParamData` so that later when we get it back in the callback
request we can tell which IDP it is referring to. This will require an update to
`UpstreamStataParamData.FormatVersion`, which would mean that logins in progress at the time of
upgrade would fail.

The pinniped cli should default to using the cli-based password flow, but when the `--upstream-identity-provider-flow`,
flag specifies `browser_authcode`, it will open a browser to log in
instead of prompting for username and password. Some users (for example, IDE plugins for kubernetes)
may wish to authenticate using the pinniped cli but without access to a terminal.

Here is how the login flow might work:
1. The supervisor receives an authorization request.
   1. If the client_id param is not "pinniped-cli", and it includes username and password via the custom headers, reject the request.
   2. If the request does not include the custom username/password headers, assume we want to use the webpage login.
   3. Today, the CLI specifies the IDP name and type as request parameters, but the server currently ignores these
      since the Supervisor does not allow multiple idps today. This could be enhanced in the future to use the requested
      IDP when the params are present, and to show another UI page to allow the end user to choose which IDP when the params
      are not present. This leaves room for future multiple IDP support in this flow,
      however, the details are outside the scope of this proposal.
   4. Encode the request parameters into a state param like is done today for the `OIDCIdentityProvider`.
      In addition to the values encoded today (auth params, upstream IDP name, nonce, csrf token and pkce),
      encode the upstream IDP type.
   5. Set a CSRF cookie on the response like what we do for OIDC today.
   6. Return a redirect to the LDAP web url. This should take the form `<issuer-url>/login`
2. The client receives the redirect and follows it to `<issuer-url>/login`
3. The supervisor receives the GET request to `<issuer-url>/login` and renders a simple login form with the Pinniped
logo and the IDP name.
   1. The submission should be POST `<issuer-url>/login`.
   2. The state param’s value is written into a hidden form input, properly escaped.
   3. Username and password form inputs are shown.
4. The supervisor receives the POST request.
   1. Decode your state form param to reconstitute the original authorization request params
   (the client’s nonce and PKCE, requested scopes, etc) and also compare the incoming CSRF cookie to the value
   from the state param. This code would be identical to what we do in the upstream OIDC callback endpoint today.
   If the decoded state param’s timestamp is too old, it might be prudent to reject the request.
   2. Using the idp name/type from the state param, look up the IDP, bind to it, verify the username/password and
   get the users downstream username and groups.
   3. If the login succeeds, mint an authcode and store the session as a secret the same way as we do on the
   callback endpoint today, and return the new authcode. If `response_mode=form_post` was requested, return a 200
   with Pinniped's form post html page, to be displayed on the login page. If it is `query`, return a redirect
   with the authcode as a query param. Default behavior when `response_mode` is unspecified should be handled
   by other parts of the code, but it should default to `query` on the supervisor.
   4. If the login fails, respond with a redirect to `<issuer-url>/login` with an error type as the query param,
   so the login page can render an error message. Allow the user to retry login the same way we do with the CLI today
   (we leave brute force protection to the IDP). Display two types of errors-- "login error" (incorrect username or password)
   or "internal error" for something that can't be easily fixed by the user (for example, requests to the LDAP server timing
   out, LDAP queries malformed). The error that is displayed to the user should be generic but should suggest to the user
   whether they should try again, or contact their administrator. (thanks @vrabbi for the suggestion!)

#### Upgrades

This change is backwards compatible. Users would see no changes unless they decided to register
a new client or change the pinniped cli flags.

However if they do choose to register a new client they may need to update the following:
- FederationDomains today may be using private certificate authorities. These are trusted
  for our use case but a browser will flag them as unsafe. Admins will have to transition to letsencrypt
  or another public Certificate Authority to prevent making end users click past messages about the certificate
  being untrusted.
- The name of the idp custom resource is currently not published to users logging in with Pinniped.
  We plan on exposing this to indicate to users which idp they are logging in to.
  Admins may need to update this to something more user-friendly.
  Note: While branding is an important part of the user experience, and we may consider adding
  the option to customize the page or add new fields (such as an IDP "display name" field), we
  are choosing to defer this work until later. We want to get the MVP work done and into users'
  hands and hope to hear more from the community once the MVP is completed.
  For the MVP, we should not add new config but should remind admins that the IDP field field
  is now displayed.

To enable users to upgrade smoothly, the behavior of the Pinniped CLI when it encounters multiple possible flow options will change.
Previously, the team had decided that the CLI should fail when there were multiple options (e.g. when it's could
use either the `browser_authcode` flow or the `cli_password` flow). However, that behavior would break existing
kubeconfigs once the `browser_authcode` flow was introduced to the IDP discovery doc.
Instead we are opting to prioritize based on the order listed in the IDP discovery doc.
Users will still have the option to override this priority with the `--upstream-identity-provider-flow` flag,
but that flag will not be required.

#### Tests

Chromedriver browser based integration tests will be needed to ensure that a user can log in from a web-based app
by entering their ldap credentials into the web page, as well as unit tests.

With the pinniped cli:
- succeeds with correct username and password
- fails with incorrect username, shows useful but nonspecific error message
- fails with incorrect password, shows useful but nonspecific error message
Once dynamic clients are implemented:
- fails when attempting to pass username/password as headers on requests to the authorize endpoint
- tests of the rest of the dynamic client functionality that should be detailed as part of that proposal

#### New Dependencies
This should be kept to a very simple HTML page with minimal, clean CSS styling.
Javascript should be avoided.
The styling should match the [form post html page](https://github.com/vmware-tanzu/pinniped/tree/main/internal/oidc/provider/formposthtml)
as much as possible, we should reuse some of the existing css and add to it to keep the style consistent.

#### Observability Considerations
* The existing logging in `upstreamldap.go` should be sufficient for logging the attempted logins.
  Further logging should be proposed as a separate proposal.

#### Security Considerations
* Preventing LDAP injection attacks: this should be done server-side using our existing
  string escaping.
* CSRF protection via a CSRF cookie: this should be similar to the way it is done for the
  OIDCIdentityProvider today
* The new UI page must be HTTPS.

#### Documentation Considerations
This new feature will require documentation to explain how to configure it and to publicise that it is available.
This should include:
* A blog post describing the feature
* Website documentation in the form of a how-to guide

### Other Approaches Considered
Today, users can configure Dex if they want a web-based LDAP login.
This introduces complexity because they have to install, configure and
maintain both Pinniped and Dex in order to use this feature. It also means
that users do not benefit from the opinionated `ActiveDirectoryIdentityProvider`
config because Dex does not have an equivalent.

## Answered Questions
* Q: What is the format for the URL? (`issuer/some/path`? Something else?)
  A: `<issuer>/login`
* Q: Can we make it so we can reuse the existing cert, or will we need a new wildcard cert?
  A: Since the page is hosted on the issuer, we can reuse the existing `FederationDomain` cert.

## Open Questions
* Q: Currently we have little validation on branding requirements. Is specifying the IDP name enough for users to understand
  how to log in? How many users will be blocked on using this feature until they can have a company name and logo on the login page?
  A: For our initial release, we will only specify the IDP name. We are open to adding further customization in response to feedback
  from users once the feature is released.

## Implementation Plan
While this work is intended to supplement the dynamic client work, parts of it
can be implemented independently.
The pinniped cli can support a web based ui flow via a command line flag, or environment variable.
Then once dynamic clients exist, we can add functionality to accept requests
from those clients as well.

## Implementation PRs
This section is a placeholder to list the PRs that implement this proposal.
This section should be left empty until after the proposal is approved.
After implementation, the proposal can be updated to list related
implementation PRs.
