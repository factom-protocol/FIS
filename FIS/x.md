| FIS | Title                                                                          | Status | Category | Author                             | Created    |
| ----- | ---------------------------------------------------------------------------- | ------ | -------- | ---------------------------------- | ---------- |
| X     | Standard, Process and Guidelines for the Factom&reg; Improvement Specifications | Draft  | Meta     | Niels Klomp \<<nklomp@sphereon.com>\> | 20190506   |



# FIS-X

[FIS-X](/) is the initial specification that describes the core framework,
conventions, contribution guidelines, and ecosystem of FIS.


# What Is A FIS?

A FIS defines an informal specification and/or best practices for 2nd layer solutions on
top of the Factom&reg; Protocol. It is not mandatory that parties building on Factom adopt 
these specifications, but for maximum interoperability with other products and solutions we 
advise you to take any FIS related to your product into account. 

A FIS is never about the development of sofware itself. Developers may choose to make their 
software compatible with one or more Factom Interoperability Specifications.


# Why Are They Important?

FIS provides an open forum for the community to collaborate on and accept new
2nd layer specifications for the Factom&reg; Protocol. The Factom&reg; Protocol 
is completely open source, and we rely on our community and standing parties to keep us pointed
in the right direction. Everybody can create any software running on top of the protocol. 
As the protocol is public we encourage developers to develop their applications with 
interoperability in mind, so that people can interact with users of your software, without 
requiring use of your software and vice versa.


# Contributing

Create your submission in a markdown file following the guidelines defined in
[FIS-X](x.md) and the [FIS-Template](template.md)

To submit your specification, fork this repo and then submit a pull request to have
it reviewed and included for evaluation by the community.


# Specification Categories


## Identities & key management

Specifications that are related to identities on Factom, like native Factom identities, 
DIDs, and cryptographic key management/replacement.

## Wallets

Specification that govern hardware and software wallets.


## Explorers

Specification for explorers.


## APIs

Specifications for 2nd layer API tools, like Factom OpenAPI. This section is restricted to 
dedicated APIs, and should not include specifications for other tools such as wallets 
that only happen to have an API.

## Voting &amp; polls

Specifications for voting and poll solutions.


## Meta

Standards about FIS itself, processes, etc.


# Specification Statuses


## Work In Progress (WIP)

The specification's information is sufficient to be reviewed by the community. This
is essentially an "Intent to submit" a FIS. The community member(s)
submit a formatted pull request containing the preliminary version of the
proposed specification.

- If reviewed and denied, the specification may be revised and improved unless it is
  explicitly rejected
- If reviewed and approved it is assigned a FIS number and other metadata.
  The specification moves on to drafting.


## Draft

The specification is in the process of being revised. Follow-up pull requests will
be accepted to revise the specification until it is ready to go through the last
call process (explained below).


## Last Call

The specification is open to final evaluation by the community and general
public.

- If the specification requires further changes, it reverts to drafting again.
- If the specification is approved then it will
  move onto final.

As FIS is a new standard, there is currently no maximum timeline set for this status.
  

## Final

The specification has been finalized and accepted by the community. The specification is
adorned with the final official prefix **Factom-Protocol**, replacing the former **FIS**
prefix. Errata may be formally submitted following this stage if required.


# Specification Workflow


# FIS Editors

For each new FIS, an editor will:

- Read the FIS to check if it is ready, sound and complete. The ideas must
  make technical sense, even if they don't seem likely to get to final status.
- The title should accurately describe the content.
- Check the FIS for language (spelling, grammar, sentence structure, etc.),
  markup (Github flavored Markdown), code style.

If the FIS isn't ready, the editor will send it back to the author for
revision, with specific instructions.

Once the FIS is ready for the repository, the FIS editor will:

- Assign a FIS number (generally the PR number or, if preferred by the
  author, the Issue # if there was discussion in the Issues section of this
repository about this FIS).
- Merge the corresponding pull request.
- Send a message back to the FIS author with the next step.

Many FISs are written and maintained by developers with write access to the codebases
of the Factom&reg; Protocol or 3rd party applications. The FIS editors monitor FIS changes, and correct any
structure, grammar, spelling, or markup mistakes they see.




# Specification Structure

A [FIS Template](template) is supplied to begin writing your standard.


## Header

An informational header containing metadata about the FIS being submitted,
like so:

| FIS | Title         | Status | Category | Author                               | Created   |
| ----- | ------------- | ------ | -------- | ------------------------------------ | --------- |
| N     | Standard Name | Status | Category | Author Name \<<author@example.com>\> | 2019-05-03 |

Once accepted as a draft an editor will assign an official FIS number.


## Summary

"If you can't explain it simply, you don't understand it well enough." Provide
a simplified and layman-accessible explanation of the FIS.


## Motivation

Clearly explain what the existing problem is and how your FIS would
address the problem. FIS submissions without sufficient
motivation may be rejected outright. What motivated the design and why were
particular design decisions made?


## Specification

The technical specification should describe the syntax and semantics of any new
feature. The specification should be detailed enough to allow competing,
interoperable implementations for any of the current Factom&reg; Protocol.


## Implementation

As FIS is about specification, a software product is not necessarily the outcome of a FIS.
However, a reference implementation is always welcome.


## Copyright

The standard must have a copyright section that waives rights according to CC0. Please note that
this is only applicablefor the proposal itself:

```
Copyright and related rights waived via
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).
```


# Inheritance & Dependencies

Factom&reg; Improvement Specification can extend and inherit functionality and rules from others. The
`extends` \<FIS #> Keyword and Tag denotes feature inheritance on a feature
by feature basis. The author of the FIS must explain how and what is being
inherited, and if there are any changes being made. It is also possible to depend on another FIS. The
`depends-on` \<FIS #> Keyword and Tag denotes dependency on a feature
by feature basis.


# Copyright

Copyright and related rights waived via
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).
