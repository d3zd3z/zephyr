.. _secure code:

Secure Coding Guidelines
########################

Traditionally, microcontroller-based systems have not placed much
emphasis on security.
They have usually been thought of as isolated, disconnected
from the world, and not very vulnerabile, just because of the
difficulty in accessing them.  The Internet of Things has changed
this.  Now, code running on small microcontrollers often has access to
the internet, or at least to other devices (that may themselves have
vulnerabilities).  Given the volume they are often deployed at,
uncontrolled access can be devasating [#]_.

.. [#]  A recent attack_ resulting in a significant portion of DNS
   infrastructure being taken down.

.. _attack: http://www.theverge.com/2016/10/21/13362354/dyn-dns-ddos-attack-cause-outage-status-explained

This document describes the requirements and process for ensuring
security is addressed within the Zephyr project.  All code submitted
should comply with these guidelines.

Much of this document comes from the `CII best practices`_ document
(link?).

.. _CII best practices: https://github.com/linuxfoundation/cii-best-practices-badge

Introduction and Scope
======================

This document covers guidelines for the `Zephyr Project`_, from a
security perspective.  Much of the ideas contained herein are captured
from other open source efforts.

.. _Zephyr Project: https://www.zephyrproject.org/

It will begin with a section on `Secure development knowledge`, which
gives basic requirements that a developer working on the project will
need to have.  This section gives references to other security
documents, and full details of how to write secure software are beyond
the scope of this document.  This section also describes a
vulnerability knowledge that at least one of the primary developers
should have.  This knowlege will be necessary for the review process
described below this.

Following this will be a description of the review process used to
incorporate changes into the Zephyr codebase.  This is followed by
documentation about how security-sensitive issues are handled by the
project.

Finally, the document covers how changes are to be made to this
document.

Secure development knowledge
============================

Secure designer
---------------

The Zephyr project must have at least one primary developer who knows
how to design secure software.

This requires understanding the following design principles,
including the 8 principles from `Saltzer and Schroeder`_:

.. _Saltzer and Schroeder: http://web.mit.edu/Saltzer/www/publications/protection/

- economy of mechanism (keep the design as simple and small as
  practical, e.g., by adopting sweeping simplifications)

- fail-safe defaults (access decisions should deny by default, and
  projects' installation should be secure by default)

- complete mediation (every access that might be limited must be
  checked for authority and be non-bypassable)

- open design (security mechanisms should not depend on attacker
  ignorance of its design, but instead on more easily protected and
  changed information like keys and passwords)

- separation of privilege (ideally, access to important objects should
  depend on more than one condition, so that defeating one protection
  system won't enable complete access. E.G., multi-factor
  authentication, such as requiring both a password and a hardware
  token, is stronger than single-factor authentication)

- least privilege (processes should operate with the least privilege
  necessary)

- least common mechanism (the design should minimize the mechanisms
  common to more than one user and depended on by all users, e.g.,
  directories for temporary files)

- psychological acceptability (the human interface must be designed
  for ease of use - designing for "least astonishment" can help)

- limited attack surface (the attack surface - the set of the
  different points where an attacker can try to enter or extract data
  - should be limited)

- input validation with whitelists (inputs should typically be checked
  to determine if they are valid before they are accepted; this
  validation should use whitelists (which only accept known-good
  values), not blacklists (which attempt to list known-bad values)).

Vulnerability Knowledge
-----------------------

A "primary developer" in a project is anyone who is familiar with the
project's code base, is comfortable making changes to it, and is
acknowledged as such by most other participants in the project. A
primary developer would typically make a number of contributions over
the past year (via code, documentation, or answering questions).
Developers would typically be considered primary developers if they
initiated the project (and have not left the project more than three
years ago), have the option of receiving information on a private
vulnerability reporting channel (if there is one), can accept commits
on behalf of the project, or perform final releases of the project
software. If there is only one developer, that individual is the
primary developer.

At least one of the primary developers MUST know of common kinds of
errors that lead to vulnerabilities in this kind of software, as well
as at least one method to counter or mitigate each of them.

Examples (depending on the type of software) include SQL
injection, OS injection, classic buffer overflow, cross-site
scripting, missing authentication, and missing authorization. See the
`CWE/SANS top 25`_ or `OWASP Top 10`_ for commonly used lists.

.. _CWE/SANS top 25: http://cwe.mitre.org/top25/

.. _OWASP Top 10: https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project

Core Security Team
------------------

There shall be a “Core Security Team”, that is responsible for
enforcing this guideline, monitoring review, and improving the process
described herein.

This team will be made up of "project defined".

Code Review
===========

The Zephyr project shall use a code review system that all changes are
required to go through.  Each change shall be reviewed by at least one
primary developer that is not the author of the change.  This
developer shall determine if this change affects the security of the
system (based on their general understanding of security), and if so,
shall request the developer with vulnerability knowledge, or the
secure designer to also review the code.  Any of these individuals
shall have the ability to block the change from being merged into the
mainline code until the security issues have been addressed.

Issues and Bug Tracking
=======================

The Zephyr project shall have an issue tracking system (such as JIRA_)
that can be used to record and track defects that are found in the
system.

.. _JIRA: https://www.atlassian.com/software/jira

Because security issues are often sensitive, this issue tracking
system shall have a field to indicate a security system.  Setting this
field shall result in the issue only being visible to a
project-maintained list of a core security team.  In addition, these
members shall be able to add users to a list field to add other users
that may have access to the issue.

This embargo, or limited visibility, shall only be for a fixed
duration, with a default being a project-decided value.  However,
because security considerations are often external to the Zephyr
project itself, it may be necessary to increase this embargo time.
The time necessary shall be clearly annotated in the issue itself.

The list of issues shall be reviewed at least once a month by the core
security team on the Zephyr Project.  This review should focus on
tracking the fixes, determining if any external parties need to be
notified or involved, and determining when to lift the embargo on the
issue.  The embargo should not be lifted via an automated means, but
the review team should avoid unnecessary delay in lifting issues that
have been resolved.

Modifications to This Document
==============================

Changes to this document shall be reviewed by the core security team,
and approved by consensus.
