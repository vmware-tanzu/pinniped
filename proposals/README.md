# Proposals

This directory contains proposal documents for significant enhancements and changes to Pinniped.

Note that prior to early 2022, proposal documents were written as public Google Docs or Hackmd docs, so they were not
stored here.

# Proposal Process

The purpose of a proposal is to build consensus on a problem statement and solution design before starting work on the
implementation. A proposal is a design document that describes a significant change to Pinniped. A proposal must be
sponsored (or co-authored) by at least one maintainer. Proposals can be submitted and reviewed by anyone in the
community.

## When to Submit a Proposal

If there is significant risk with a potential feature or track of work (such as complexity, cost to implement, product
viability, etc.), then we recommend creating a proposal for feedback and approval. If a potential feature is well
understood and doesn't impose risk, then we recommend a standard GitHub issue to clarify the details.

If you are considering creating a PR to change Pinniped's source code, and you are not sure if the change is significant
enough to require using the proposal process, then please ask the maintainers.

If you would like to simply share a problem that you are having, or share an idea for a potential feature, and you are
not planning on designing a technical solution or submitting an implementation PR, then please feel free to create a
standard GitHub issue instead of using the proposal process.

## How to Submit a Proposal

Before submitting a proposal, please create a tracking issue. Open a new GitHub issue in this repo and choose the
"Proposal tracking" issue template. After creating the issue, note the issue's number. This tracking PR can be used
as a place for conversations beyond/between the proposal PR and implementation PRs.

To create a proposal, submit a PR to this repo introducing a new subdirectory under the `proposals` directory with a
terse name (for example, `0001_my-feature-name/`) prefixed by the tracking issue's number. In that new
subdirectory, create a `README.md` containing the core proposal. Include other files as necessary to help support
understanding of the feature.

To make your new proposal known to all other contributors, please send a link to your new proposal PR on the Kubernetes
Slack in [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA)
or via the [Pinniped mailing list](mailto:project-pinniped@googlegroups.com).

Author(s) of proposals for major changes will give a time period of no less than five (5) working days for comment and
remain cognizant of popular observed world holidays.

If you don't already have a maintainer to sponsor your proposal, then reach out via Slack or the mailing list with a
description of the problem statement. If one or more of the maintainers agrees that the problem statement is within the
scope of the project (see [SCOPE.md](SCOPE.md)) and is appropriate to be addressed by a proposal, then a maintainer will
be assigned as your proposal's sponsor. The sponsor can provide you with support during the drafting of the proposal,
including sharing additional project and roadmap context as it relates to your problem statement, answering questions,
giving feedback, etc.

### Proposal Template

The below template is an example `README.md` for a new proposal. Other than the high-level details at the top of the
template (title, authors, status, sponsor, and approval_date)
and the disclaimer at the top, please use whichever sections make the most sense for your proposal.

```markdown
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

1. Author creates a tracking issue.
2. Author adds a proposal by creating a PR in draft mode. (Authors can save their work until ready.)
3. Author updates the tracking issue to have a link to the PR.
4. When the author elaborates the proposal sufficiently to withstand critique they:
   1. change the status to `in-review` and
   2. mark the PR as "Ready for Review".
5. The community critiques the proposal by adding PR reviews in order to mature/converge on the proposal.
6. When the maintainers reach consensus or supermajority to accept a proposal, they:
   1. change the status to `accepted`,
   2. record both majority and dissenting opinions,
   3. merge the PR, thus adding the new proposal to the `main` branch,
   4. code implementation PRs are submitted separately to implement the solution.
7. During implementation of an accepted proposal:
   1. if it is discovered that significant unanticipated changes are needed to the proposal, then the implementation
      work should be paused and the proposal should be updated with the new details to be reviewed by the maintainers
      again before resuming implementation,
   2. as each implementation PR is created, the tracking issue should be updated to link to the new implementation PR, and
   3. when all implementation PRs are merged, the proposal doc should be updated to have status `implemented` and to
      list the related PRs, and the tracking issue should be closed.
8. When the maintainers do not reach consensus or supermajority, then the proposal is rejected, and they:
   1. may mark the status `rejected`, and
   2. close the PR with a note explaining the rejection, and
   3. close the related tracking issue.
9. Rejected proposal PRs (and the corresponding tracking issue) may be reopened and moved back to `in-review` if
   there are material changes to the proposal which address the reasons for rejection.

## Proposal Review

Once a proposal PR marked as "Ready for Review", the community and all project maintainers will review the proposal. The
goal of the review is to gain an understanding of the problem being solved and the design of the proposed solution.

Maintainers will consider all aspects of the proposed problem and solution, including but not limited to:

- Is the problem within scope for the project?
- Would the additional future cost of maintenance imposed by an implementation of the solution justify solving the
  problem?
- Is the solution reasonably consistent with the rest of the project?
- How does the solution impact the usability, security, scalability, performance, observability, and reliability of
  Pinniped?
- How might an implementation of the solution be architected and tested via automation?
- What risks might be introduced by an implementation of the solution?
- The opportunity cost of the time it would take to implement the solution, if the implementation is to be done by the
  maintainers.

## Maintenance of Accepted Proposal Documents

Proposal documents reflect a point-in-time design and decision. Once approved, they become historical documents, not
living documents. There is no expectation that they will be maintained in the future. Instead, significant changes to a
feature which came from a previous proposal should be proposed as a fresh proposal. New proposals should link to
previous proposals for historical context when appropriate.

## Getting Help with the Proposal Process

Please reach out to the maintainers in the Kubernetes Slack Workspace within
the [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA) channel or on
the [Pinniped mailing list](mailto:project-pinniped@googlegroups.com) with any questions.
