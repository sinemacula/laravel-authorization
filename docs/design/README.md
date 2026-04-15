# Design Notes

These notes document the package's authorization-specific contracts and invariants that are easy to miss if you only read
the quick-start material or skim the test suite.

Each note is intentionally short and follows the same structure:

- `Purpose`
- `Invariants`
- `Success Path`
- `Failure / Edge Cases`
- `Implementation Anchors`
- `Authoritative Tests`
- `Change Triggers`

The planned note set (populated during implementation — see `ISSUES.md` item #7) is:

- `evaluation-order-and-deny-precedence.md`: the AWS IAM 4-step decision order and why an explicit DENY always wins over
  an RBAC allow.
- `polymorphic-identity-pivots.md`: why role, permission, and policy pivots use plain `string`
  `authorizable_type`/`authorizable_id` columns so that integer, UUID, and ULID identities all work.
- `principal-resolver-contract.md`: the standalone vs. plug-and-play boundary with `sinemacula/laravel-authentication`;
  why the shipped default resolver returns `null` (anonymous-safe) and how the umbrella package wires a real resolver.
- `wildcard-and-condition-semantics.md`: fnmatch semantics, missing-key behaviour, and the condition operator catalogue
  (`eq`, `neq`, `in`, `not_in`, `cidr`, `starts_with`, `ends_with`, `before`, `after`, `between`).

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
