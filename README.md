# `in-toto` Policy

There are major gaps and issues with in-toto layouts (in-toto's policy system)
that are hindering in-toto's ability to enforce supply chain policies,
especially those that involve attestations. This is an experiment that explores
some ideas and could perhaps be a good place for discussion on the future of
supply chain policies.

## Problems

Not long after KubeCon EU 2024, [this document](https://docs.google.com/document/d/1-pP-ycaIMN1H6llK1BWdovmNsY8AZ-grVRZZZwuWw2o/edit?usp=sharing)
was created after conversations with members of the in-toto community on the
major drawbacks of the current in-toto framework. It currently feels as if
in-toto layouts have been left behind since the advent of attestations. As
attestations have matured and gained adoption, layouts have not managed keep up
and newer ITE's are only attempting to patch some new use cases and do not solve
any existing pain points in the framework. In order for the other half of
in-toto to succeed, policies would need to be able to scale and be applied
everywhere like attestations.

The list of problems could be split into two: existing pain points and issues
introduced by attestations.

### Existing Issues

The existing policy pain points that stand out based on my observations are the following:

1. **Layouts are very inflexible.** While the artifact rules syntax and layouts
format may be simple and are great at creating granular definitions of a supply
chain, they begin to feel tedious when constraints need to be relaxed or changed
in order to accomodate changes that a supply chains may encounter such as
version updates.
2. **It is hard to build a layout.** Layouts often require a "full-picture" view
of the whole supply chain and a good understanding on how the artifact rules
work. This limits the pool of individuals suited to build and make a policy.
Tools have been created to make their creation easier, but they have not gained
much traction. In the general sense, two modules that leverage the same supply
chain should be able to share the same policy.
3. **There are not many layouts out there.** A side-effect of issues 1 and 2 is
that there are very few production and reference layouts people could use to
learn and create layouts whilst following best-practices. This raises the bar
for adoption and implementation of in-toto layouts.

### Attestation Related Issues

There has been good work by the community to push the spec in this regard.
However, the gap left between attestations and layouts demand a total redesign.
Below are listed the specific pain points:

1. **No good way of specifying policy on attestation fields.** Different types
of attestations now have multiple fields within them. ITEs [10](https://github.com/in-toto/ITE/blob/master/ITE/10/README.adoc),
[11](https://github.com/in-toto/ITE/pull/50) and
[attestation-policy](https://github.com/in-toto/attestation-verifier/) introduce
a good way of defining policy over such fields but they are not as polished and
undertake "hacky" methods to achieve certain results.
2. **Materials and products are no longer the only artifact collections out
there.** The aforementioned ITE introduced ways of using the existing
`ExpectedMaterial` and `ExpectedProduct` fields in the layouts with
attestations. However, the way it is defined currently is rather limiting and
would require the policy resolver to understand all attestations it needs to
resolve in order to place each artifact collection under the correct umbrella.

## Goals and Non-Goals

The goal is not to replace in-toto policies, as this is an experiment designed
by an individual with limited experience of applying in-toto at scale. It is to
introduce a few novel ideas that could be helpful for the community and
hopefully inspire further development in this area. The ideal outcome is to use
this project as reference and a conversation starter that would lead to an ITE
that introduces something that is to layouts as what attestatoins was to links.

Anything related to embedding trust or distribution of the policy is deemed out
of scope as it heavily depends on the existing infrastructure of the consumer.
Although a proper successor should consider an ITE outlining integration with
TUF to offer an example on how this can be done.

> [!IMPORTANT]
> One additional point that should be touched upon on a proper successor is the
> scalability of these policies for larger organizations. This would require
> thinking about how boundaries can be introduced within layouts as products
> delivered to the end-user may touch different teams that move at a different
> pace. Perhaps something like a trusted set or versions of sublayouts that can
> be updated using TUF could be used.

## Solution

This repository contains all code used to implement the experiment. Here is the
[layout](https://github.com/alanssitis/new-attestation-policy-demo/blob/main/layout.yaml)
from the demo shown at Kubecon EU 2024 and [here](test/data/policy.yaml)
is its new look.

> [!NOTE]
> `inspect` is still a WIP. But its functionality can be achieved
> via another policy type.

The goal of this was to dramatically improve the expressability of the policy
when trying to apply it to attestations rather than links, which lead to a lot
more control over artifact rules and attribute rules at the cost of increased
verbosity and a slight increase in complexity. Nevertheless, this should be a
net win as this improves the consistency of the policy and would allow any user
to clearly understand their policy.

The predicate attribute grammar was also simplified and changed as a lot of the
older grammar assumed a strict `MATERIALS` & `PRODUCTS` system that does not
particularly work well with attestations that are not links.

It should be straightforward to add more functionary capabilities as this is
using the Secure System Lib's `Verifier` interface.

There are two new features that I would like to highlight:

- Having different types of policies defined by a URI (similar to how there
  are different types of attestations)
- Applying artifact rules on different fields rather than predetermined
  `materials` and `products`.

There are example attestations generated from the aforementioned demo with the
associated policy in `test/data`. The test can be exectued by running
`make run-test`.

## Contributing

Feel free to open issues or PRs for any discussion or changes that could be
made to improve and refine this prototype.
