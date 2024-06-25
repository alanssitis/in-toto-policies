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

> [!IMPORTANT]
> One additional point that should be touched upon on a proper successor is the
> scalability of these policies for larger organizations. This would require
> thinking about how boundaries can be introduced within layouts as products
> delivered to the end-user may touch different teams that move at a different
> pace. Perhaps something like a trusted set or versions of sublayouts that can
> be updated using TUF could be used.

## Solution

This repository contains all protobuffs and code used to implement the
experiment. Below is the payload of the demo layout under `in-toto-golang`'s
tests, and the resulting "modern" policy which uses link attestations and
showcases some new concepts which would be introduced later in the document.

Here is the payload of [`demo.layout`](https://github.com/in-toto/in-toto-golang/blob/master/test/data/demo.layout)
in its original JSON. Below is the layout in a simplified YAML format that has
the description of the intended policy with key and certificate definitions
ommitted for clarity.

```yaml
steps:
  - name: write-code
    expected_products:
      - ALLOW foo.py
    pubkeys:
      - write-code-key
    cert_constraints:
      - roots: test-root
  - name: package
    expected_command: tar zcvf foo.tar.gz foo.py
    expected_materials:
      - MATCH foo.py WITH PRODUCTS FROM write-code
      - DISALLOW *
    expected_products:
      - ALLOW foo.tar.gz
      - ALLOW foo.py
    pubkeys:
      - package-key
inspect:
  - name: untar
    run: tar xfz foo.tar.gz
    expected_materials:
      - MATCH foo.tar.gz WITH PRODUCTS FROM package
      - DISALLOW foo.tar.gz
    expected_products:
      - MATCH foo.py WITH PRODUCTS FROM write-code
      - DISALLOW foo.py
keys:
  - name: write-code-key
    etc: ...
  - name: package-key
    etc: ...
rootcas:
  - name: test-root
    etc: ...
intermediatecas:
  - name: test-intermediate
    etc: ...
```

Now, here is the same layout implemented in the new policy system.

> [!NOTE]
> `inspect` is still a WIP.

```yaml
attestations:
  - name: write-code
    predicate_type: https://in-toto.io/attestation/link/v0.3
    policies:
      - type: artifact_rules
        field: this.subject
        rules:
          - ALLOW foo.py
    pubkeys:
      - write-code-key
    cert_constraints:
      - roots: test-root
  - name: package
    predicate_type: https://in-toto.io/attestation/link/v0.3
    policies:
      - type: attribute_rules
        rules:
          - this.predicate.command.join(' ') == 'tar zcvf foo.tar.gz foo.py'
      - type: artifact_rules
        field: this.predicate.materials
        rules:
          - MATCH foo.py WITH write-code.subject
          - DISALLOW *
      - type: artifact_rules
        field: this.subject
        rules:
          - ALLOW foo.tar.gz
          - ALLOW foo.py
    pubkeys:
      - package-key
# inspect -- This is WIP
keys:
  - name: write-code-key
    etc: ...
  - name: package-key
    etc: ...
rootcas:
  - name: test-root
    etc: ...
intermediatecas:
  - name: test-intermediate
    etc: ...
```
