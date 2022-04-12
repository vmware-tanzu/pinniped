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
* Address basic security concerns for web firms (HTTPS, passwords use a password field, CSRF protection, redirect protection)
* Prevent LDAP injection attacks
* Rely on the upstream IdP to address advanced security concerns (brute force protection, username enumeration, etc)
* Screens are accessible and friendly to screen readers
* Screens are friendly to password managers

#### Non-goals
* A rich client (ie the use of javascript)
* Advanced UI features (e.g. remember me, reveal password). These features are better left to identity providers to implement.
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

The pinniped cli should default to using the cli-based password flow, but when a tty is unavailable,
it will open a browser to log in
instead of prompting for username and password. Some users (for example, IDE plugins for kubernetes)
may wish to authenticate using the pinniped cli but without access to a terminal.

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

#### Tests

Chromedriver browser based integration tests will be needed to ensure that a user can log in from a web-based app
by entering their ldap credentials into the web page, as well as unit tests.

With the pinniped cli:
- succeeds with correct username and password
- fails with incorrect username, shows useful but nonspecific error message
- fails with incorrect password, shows useful but nonspecific error message
- with tty access, prompts for username and password on the cli
- without tty access, opens a browser
- without tty access, if the form post fails, don't ask user to copy and paste the authcode (we already know you have no tty to paste it into...)
Once dynamic clients are implemented:
- fails when attempting to pass username/password as headers on requests to the authorize endpoint
- tests of the rest of the dynamic client functionality that should be detailed as part of that proposal

#### New Dependencies
This should be kept to a very simple HTML page with minimal, clean CSS styling.
Javascript should be avoided.

#### Observability Considerations
* Logging login attempts at higher log levels.

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

## Open Questions
* What is the format for the URL? (`issuer/some/path`? Something else?) Can we make it so we can reuse the existing cert,
  or will we need a new wildcard cert?
* Currently we have little validation on branding requirements. Is specifying the idp name enough for users to understand
  how to log in?
* How many users will be blocked on using this feature until they can have a company name and logo on the login page?
* Should we allow admins or users to decide to use the web ui with the pinniped cli, or is it sufficient for us to
  determine it based on presence/absence of tty?

## Implementation Plan
While this work is intended to supplement the dynamic client work, parts of it
can be implemented independently.
The pinniped cli can support a web based ui flow via a command line flag, environment variable or checking whether a tty is available.
Then once dynamic clients exist, we can add functionality to accept requests
from those clients as well.

## Implementation PRs
This section is a placeholder to list the PRs that implement this proposal.
This section should be left empty until after the proposal is approved.
After implementation, the proposal can be updated to list related
implementation PRs.
