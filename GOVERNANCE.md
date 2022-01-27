# Pinniped Governance
This document defines the project governance for Pinniped.

# Overview
**Pinniped** is committed to building an open, inclusive, productive and self-governing open source community focused on building authentication services for Kubernetes clusters. The
community is governed by this document which defines how all members should work together to achieve this goal.

# Code of Conduct
The Pinniped community abides by this [code of conduct](https://github.com/vmware-tanzu/pinniped/blob/main/CODE_OF_CONDUCT.md).

# Community Roles
* **Users:** Members that engage with the Pinniped community via any medium (Slack, GitHub, mailing lists, etc.).
* **Contributors:** Do regular contributions to the Pinniped project (documentation, code reviews, responding to issues, participating in proposal discussions, contributing code, etc.).
* **Maintainers:** Responsible for the overall health and direction of the project. They are the final reviewers of PRs and responsible for Pinniped releases.

# Maintainers
New maintainers must be nominated by an existing maintainer and must be elected by a supermajority of existing maintainers. Likewise, maintainers can be removed by a supermajority of the existing maintainers or can resign by notifying one of the maintainers.

**Note:** If a maintainer leaves their employer they are still considered a maintainer of Pinniped, unless they voluntarily resign. Employment is not taken into consideration when determining maintainer eligibility unless the company itself violates our [Code of Conduct](https://github.com/vmware-tanzu/pinniped/blob/main/CODE_OF_CONDUCT.md).

# Decision Making
Ideally, all project decisions are resolved by consensus. If impossible, any maintainer may call a vote. Unless otherwise specified in this document, any vote will be decided by a supermajority of maintainers.

## Supermajority
A supermajority is defined as two-thirds of members in the group. A supermajority of maintainers is required for certain decisions as outlined in this document. A supermajority vote is equivalent to the number of votes in favor being at least twice the number of votes against. A vote to abstain equals not voting at all. For example, if you have 5 maintainers who all cast non-abstaining votes, then a supermajority vote is at least 4 votes in favor. Voting on decisions can happen on the mailing list, GitHub, Slack, email, or via a voting service, when appropriate. Maintainers can either vote "agree, yes, +1", "disagree, no, -1", or "abstain". A vote passes when supermajority is met.

## Lazy Consensus
To maintain velocity in Pinniped, the concept of [Lazy Consensus](http://en.osswiki.info/concepts/lazy_consensus) is practiced.

Other maintainers may chime in and request additional time for review, but should remain cognizant of blocking progress and abstain from delaying progress unless absolutely needed. The expectation is that blocking progress is accompanied by a guarantee to review and respond to the relevant action in short order.

Lazy consensus does not apply to the process of:
* Removal of maintainers from Pinniped

## Updating Governance
All substantive changes in Governance, including substantive changes to the proposal process, require a supermajority agreement by all maintainers.

# Proposal Process
The purpose of a proposal is to build consensus on a problem statement and solution design before starting work on the implementation.
A proposal is a design document that describes a significant change to Pinniped.
A proposal must be sponsored (or co-authored) by at least one maintainer.
Proposals can be submitted and reviewed by anyone in the community.

## When to Submit a Proposal
If there is significant risk with a potential feature or track of work (such as complexity, cost to implement,
product viability, etc.), then we recommend creating a proposal for feedback and approval. If a potential
feature is well understood and doesn't impose risk, then we recommend a standard GitHub issue to clarify the details.

If you are considering creating a PR to change Pinniped's source code, and you are not sure if the change is
significant enough to require using the proposal process, then please ask the maintainers.

If you would like to simply share a problem that you are having, or share an idea for a potential feature,
and you are not planning on designing a technical solution or submitting an implementation PR, then please feel free
to create a standard GitHub issue instead of using the proposal process.

## How to Submit a Proposal
To create a proposal, submit a PR to this repo introducing a new subdirectory under the `proposals` directory
with a terse name (for example, `0001_my-feature-name/`) prefixed by a monotonically incrementing proposal number.
In that new subdirectory, create a `README.md` containing the core proposal.
Include other files as necessary to help support understanding of the feature.

To make your new proposal known to all other contributors, please send a link to your new proposal PR
on the Kubernetes Slack in [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA)
or via the [Pinniped mailing list](mailto:project-pinniped@googlegroups.com).

Author(s) of proposals for major changes will give a time period of no less than five (5) working days
for comment and remain cognizant of popular observed world holidays.

If you don't already have a maintainer to sponsor your proposal, then reach out via Slack or the mailing list
with a description of the problem statement. If one or more of the maintainers agrees that the problem
statement is within the scope of the project (see [SCOPE.md](SCOPE.md)) and is appropriate to be addressed by a proposal,
then a maintainer will be assigned as your proposal's sponsor. The sponsor can provide you with support during
the drafting of the proposal, including sharing additional project and roadmap context as it relates to your
problem statement, answering questions, giving feedback, etc.

### Proposal Template
The below template is an example `README.md` for a new proposal.
Other than the high-level details at the top of the template (title, authors, status, sponsor, and approval_date)
and the disclaimer at the top, please use whichever sections make the most sense for your proposal.

```md
---
title: "The Name of My Proposal"
authors: [ "@margocrawf", "@enj" ]
status: "draft"
sponsor: [ "@cfryanr" ]
approval_date: ""
---

*Disclaimer*: Proposals are point-in-time designs and decisions.
Once approved and implemented, they become historical documents.
If you are reading an old proposal, please be aware that the
features described herein might have continued to evolve since.

# <Proposal Title>

## Problem Statement
This is a short summary of the problem that exists, why it needs to be
solved: what specific needs are being met. Compelling problem statements
include concrete examples and use cases (even if only by reference).
How exactly the proposal would meet those needs should be located in the
"Proposal" section, not this one. The goal of this section is to help
readers quickly empathize with the target users' current experience to
motivate the proposed change.

### How Pinniped Works Today (as of version vX.X.X)
How Pinniped works today in the context of the problem statement.
This will typically detail how Pinniped falls short of supporting
the desired use case(s).

## Terminology / Concepts
Define any terms or concepts that are used throughout this proposal.

## Proposal
The primary content of the proposal. Subsections will explain how the
problem(s) will be addressed.

### Goals and Non-goals
A short list of what the goals of this proposal are and are not.

### Specification / How it Solves the Use Cases
Detailed explanation of the proposal's design. This will typically
also detail how the specification supports the desired use cases.
If some use cases or parts of some use cases are being deferred
to a future proposal, that might be mentioned here as well.

#### API Changes
Describe how Pinniped's API will change. APIs include CLI commands,
HTTP endpoints, aggregated API endpoints, CRDs, etc.
Detail changes to their inputs, outputs, and behavior.
What will the default values be for any new fields or parameters?

#### Upgrades
Describe how upgrading to a new version of Pinniped which includes
these features would work. Are the new changes backwards compatible?
Can new and old versions of the CLI and servers be mixed?
Will it be possible to downgrade after upgrading?

#### Tests
What kind of integration tests could be used to test the new features?

#### New Dependencies
Would any significant new project dependencies be needed to support
the implementation? Consider Golang libraries, CI infrastructure, etc.

#### Performance Considerations
Any concerns with scalability, performance, or reliability for the
implementation?

#### Observability Considerations
Any new log statements or other considerations to make this feature
observable and debuggable for admin users?

#### Security Considerations
How does the proposal consider security? What makes the new features
secure?

#### Usability Considerations
How does the proposal consider usability for the end user (kubectl user)
and for the admin user who installs and configures Pinniped?

#### Documentation Considerations
How will users discover the new features? Will docs changes be required
during implementation?

### Other Approaches Considered
Mention of other reasonable ways that the problem(s)
could be addressed with rationale for why they were less
desirable than the proposed approach.

## Open Questions
A list of questions that need to be answered.

## Answered Questions
A list of questions that have been answered.

## Implementation Plan
Who will implement this proposal once it is finished and approved?
Do you already have ideas for how you might approach the implementation
in an iterative fashion? For a large proposal with an iterative plan,
where might you draw the line to define a minimum viable version?

## Implementation PRs
This section is a placeholder to list the PRs that implement this proposal.
This section should be left empty until after the proposal is approved.
After implementation, the proposal can be updated to list related
implementation PRs.
```

## Proposal States
| Status | Definition |
| --- | --- |
| `draft` | The proposal is actively being written by the proposer. Not yet ready for review. |
| `in-review` | The proposal is being reviewed by the community and the project maintainers. |
| `accepted` | The proposal has been accepted by the project maintainers. |
| `rejected` | The proposal has been rejected by the project maintainers. |
| `implemented` | The proposal was accepted and has since been implemented. |

## Lifecycle of a Proposal
1. Author adds a proposal by creating a PR in draft mode. (Authors can save their work until ready.)
2. When the author elaborates the proposal sufficiently to withstand critique they:
   1. change the status to `in-review` and
   2. mark the PR as "Ready for Review".
3. The community critiques the proposal by adding PR reviews in order to mature/converge on the proposal.
4. When the maintainers reach consensus or supermajority to accept a proposal, they:
   1. change the status to `accepted`,
   2. adjust the proposal number in the subdirectory's name if needed,
   3. record both majority and dissenting opinions,
   4. merge the PR, thus adding the new proposal to the `main` branch,
   5. code implementation PRs are submitted separately to implement the solution.
5. During implementation of an accepted proposal:
   1. if it is discovered that significant unanticipated changes are needed to the proposal, then the implementation work should
      be paused and the proposal should be updated with the new details to be reviewed by the maintainers again before resuming implementation, and
   2. when all implementation PRs are merged, the proposal doc should be updated to have status `implemented` and to list the related PRs.
6. When the maintainers do not reach consensus or supermajority, then the proposal is rejected, and they:
   1. may mark the status `rejected`, and
   2. close the PR with a note explaining the rejection.
7. Rejected proposal PRs may be reopened and moved back to `in-review` if there are material changes to the proposal which address the reasons for rejection.

## Proposal Review
Once a proposal PR marked as "Ready for Review", the community and all project maintainers will review the proposal.
The goal of the review is to gain an understanding of the problem being solved and the design of the proposed solution.

Maintainers will consider all aspects of the proposed problem and solution, including but not limited to:
- Is the problem within scope for the project?
- Would the additional future cost of maintenance imposed by an implementation of the solution justify solving the problem?
- Is the solution reasonably consistent with the rest of the project?
- How does the solution impact the usability, security, scalability, performance, observability, and reliability of Pinniped?
- How might an implementation of the solution be architected and tested via automation?
- What risks might be introduced by an implementation of the solution?
- The opportunity cost of the time it would take to implement the solution, if the implementation is to be done by the maintainers.

## Maintenance of Accepted Proposal Documents
Proposal documents reflect a point-in-time design and decision.
Once approved, they become historical documents, not living documents.
There is no expectation that they will be maintained in the future. Instead, significant changes to a feature
which came from a previous proposal should be proposed as a fresh proposal. New proposals should link
to previous proposals for historical context when appropriate.

## Getting Help with the Proposal Process
Please reach out to the maintainers in the Kubernetes Slack Workspace within
the [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA) channel
or on the [Pinniped mailing list](mailto:project-pinniped@googlegroups.com) with any questions.
