
## **Pinniped Project Roadmap**


### 
**About this document**

This document provides a link to the[ Pinniped Project issues](https://github.com/vmware-tanzu/pinniped/issues) list that serves as the up to date description of items that are in the Pinniped release pipeline. Most items are gathered from the community or include a feedback loop with the community. This should serve as a reference point for Pinniped users and contributors to understand where the project is heading, and help determine if a contribution could be conflicting with a longer term plan.


### 
**How to help?**

Discussion on the roadmap can take place in threads under [Issues](https://github.com/vmware-tanzu/pinniped/issues) or in [community meetings](https://github.com/vmware-tanzu/pinniped/blob/main/CONTRIBUTING.md#meeting-with-the-maintainers). Please open and comment on an issue if you want to provide suggestions and feedback to an item in the roadmap. Please review the roadmap to avoid potential duplicated effort.


### 
**Need an idea for a contribution?**

We’ve created an [Opportunity Areas](https://github.com/vmware-tanzu/pinniped/discussions/483) discussion thread that outlines some areas we believe are excellent starting points for the community to get involved. In that discussion we’ve included specific work items that one might consider that also support the high-level items presented in our roadmap. 


### 
**How to add an item to the roadmap?**

Please open an issue to track any initiative on the roadmap of Pinniped (usually driven by new feature requests). We will work with and rely on our community to focus our efforts to improve Pinniped.


### 
**Current Roadmap**

The following table includes the current roadmap for Pinniped. If you have any questions or would like to contribute to Pinniped, please attend a [community meeting](https://github.com/vmware-tanzu/pinniped/blob/main/CONTRIBUTING.md#meeting-with-the-maintainers) to discuss with our team. If you don't know where to start, we are always looking for contributors that will help us reduce technical, automation, and documentation debt. Please take the timelines & dates as proposals and goals. Priorities and requirements change based on community feedback, roadblocks encountered, community contributions, etc. If you depend on a specific item, we encourage you to attend community meetings to get updated status information, or help us deliver that feature by contributing to Pinniped.



Last Updated: March 2022
|Theme|Description|Timeline|
|--|--|--|
|Improving Security Posture|Support Audit logging of security events related to Authentication |May/June 2022|
|Improving Usability|Support for integrating with UI/Dashboards  |May/June 2022|
|Improving Security Posture|TLS hardening contd|June/July 2022|
|Multiple IDP support|Support multiple IDPs configured on a single Supervisor|Exploring/Ongoing|
|Improving Security Posture|mTLS for Supervisor sessions |Exploring/Ongoing|
|Improving Security Posture|Key management/rotation for Pinniped components with minimal downtime |Exploring/Ongoing|
|Improving Security Posture|Support for Session Logout |Exploring/Ongoing|
|Improving Security Posture|Support for Idle Session/ Inactivity timeout|Exploring/Ongoing|
|Improving Security Posture|Support for Max Concurrent Sessions|Exploring/Ongoing|
|Improving Security Posture|Support for configurable Session Length |Exploring/Ongoing|
|Improving Security Posture|Reject use of username and groups with system: prefix  |Exploring/Ongoing|
|Improving Security Posture|Support for using external KMS for Supervisor signing keys |Exploring/Ongoing|
|Improving Security Posture|Client side use of Secure Enclaves for Session data |Exploring/Ongoing|
|Improving Security Posture|Enforce the use of HTTP Strict Transport (HSTS) |Exploring/Ongoing|
|Improving Security Posture|Assert that Pinniped runs under the restricted PSP version2 levels  |Exploring/Ongoing|
|Wider Concierge cluster support|Support for OpenShift cluster types in the Concierge|Exploring/Ongoing|
|Identity transforms|Support prefixing, filtering, or performing coarse-grained checks on upstream users and groups|Exploring/Ongoing|
|CLI SSO|Support Kerberos based authentication on CLI |Exploring/Ongoing|
|Extended IDP support|Support more types of identity providers on the Supervisor|Exploring/Ongoing|
|Improved Documentation|Reorganizing and improving Pinniped docs; new how-to guides and tutorials|Exploring/Ongoing|
|Improve our CI/CD systems|Upgrade tests; make Kind more efficient and reliable for CI ; Windows tests; performance tests; scale tests; soak tests|Exploring/Ongoing|
|CLI Improvements|Improving CLI UX for setting up Supervisor IDPs|Exploring/Ongoing|
|Telemetry|Adding some useful phone home metrics as well as some vanity metrics|Exploring/Ongoing|
|Observability|Expose Pinniped metrics through Prometheus Integration|Exploring/Ongoing|
|Device Code Flow|Add support for OAuth 2.0 Device Authorization Grant in the Pinniped CLI and Supervisor|Exploring/Ongoing|
|Supervisor with New Clients|Enable registering new clients with Supervisor|Exploring/Ongoing|

   
