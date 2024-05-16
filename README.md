# `in-toto` Policy

There are major gaps and issues with in-toto layouts (in-toto's policy system) that are hindering
in-toto's ability to enforce supply chain policies, especially those that involve the "newer"
addition of attestations. This is a fun experiment that explores some alternatives that would
hopefully inspire the community to create new and better solutions in this problem space.

## Problems

Not long after KubeCon EU 2024,
[this document](https://docs.google.com/document/d/1-pP-ycaIMN1H6llK1BWdovmNsY8AZ-grVRZZZwuWw2o/edit?usp=sharing)
was created by @alanssitis after conversations with members of the community on the major
drawbacks of the current in-toto framework. The hypothesis is as follows, in-toto layouts have
been left behind given the advent of attestations. As attestatoins have matured and gained
widespread adoption, layouts have not managed keep up and newer ITE's are only attempting to
catch up and do not solve any existing pain points in the framework. In order for in-toto layouts
to succeed, they need to be able to scale and be able to be applied everywhere like attestations.

The list of problems could be split into two: existing issues and attestation related issues.

#### Existing Issues

The existing policy pain points that stand out based on my observations are the following:

1. **Layouts are very inflexible.** While the artifact rules syntax and layouts format may be
simple and are great at creating granular definitions of a supply chain, they begin to feel
tedious when constraints need to be relaxed or changed in order to accomodate changes in a
supply chains that may encounter things such as version updates.
2. **It is hard to build a layout.** Layouts often require a "full-picture" view of the whole
supply chain and a good understanding on how the artifact rules work. This limits the pool of
individuals suited to build and make a policy. Tools have been created to make their creation
easier, but they have not gained much traction.
3. **There are not many layouts out there.** A side-effect of issues 1 and 2 is that there are
few, if any, production and reference layouts people could use to reference and learn
best-practices. This raises the bar for adoption and implementation of in-toto layouts.

#### Attestation Related Issues

The gap left between newer attestations and older layouts:

1. **No good way of specifying policy on attestations other than links.**
2. **Materials and products are no longer the only artifact collections out there.**

## Goals

While this project hopefully doesn't become the in-toto layout replacement as it was built by
one guy with no experience running in-toto at scale, it could be a place to explore ideas and
inspire the future of layouts as what attestations was to links.

## Solution

TODO
