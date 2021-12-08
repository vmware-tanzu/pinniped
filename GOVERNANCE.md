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

---
# Supermajority
A supermajority is defined as two-thirds of members in the group. A supermajority of Maintainers is required for certain decisions as outlined above. A supermajority vote is equivalent to the number of votes in favor of being at least twice the number of votes against. For example, if you have 5 maintainers, a supermajority vote is 4 votes. Voting on decisions can happen on the mailing list, GitHub, Slack, email, or via a voting service, when appropriate. Maintainers can either vote "agree, yes, +1", "disagree, no, -1", or "abstain". A vote passes when supermajority is met. An abstain vote equals not voting at all.

---
# Decision Making
Ideally, all project decisions are resolved by consensus. If impossible, any maintainer may call a vote. Unless otherwise specified in this document, any vote will be decided by a supermajority of maintainers.

---
# Proposal Process 
The proposal process is currently being worked on. No formal process is available at this time. You may reach out to the maintainers in the Kubernetes Slack Workspace within the [#pinniped](https://kubernetes.slack.com/archives/C01BW364RJA) channel or on the [Pinniped mailing list](project-pinniped@googlegroups.com) with any questions you may have or to send us your proposals.

---
# Lazy Consensus
To maintain velocity in Pinniped, the concept of [Lazy Consensus](http://en.osswiki.info/concepts/lazy_consensus) is practiced. Ideas and / or proposals should be shared by maintainers via GitHub. Out of respect for other contributors, major changes should also be accompanied by a ping on the Kubernetes Slack in [#Pinniped](https://kubernetes.slack.com/archives/C01BW364RJA) or a note on the [Pinniped mailing list](project-pinniped@googlegroups.com) as appropriate. Author(s) of proposals for major changes will give a time period of no less than five (5) working days for comment and remain cognizant of popular observed world holidays.

**What constitutes the need for a proposal?**
If there is significant risk with a potential feature or track of work (such as complexity, cost to implement, product viability, etc.), then we recommend creating a proposal for feedback and approval. If a potential feature is well understood and doesn't impose risk, then we recommend a **standard GitHub issue** to clarify the details.

Other maintainers may chime in and request additional time for review, but should remain cognizant of blocking progress and abstain from delaying progress unless absolutely needed. The expectation is that blocking progress is accompanied by a guarantee to review and respond to the relevant action in short order.

Lazy consensus does not apply to the process of:
* Removal of maintainers from Pinniped

---
# Updating Governance
All substantive changes in Governance require a supermajority agreement by all maintainers.