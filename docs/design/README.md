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

- `evaluation-order-and-deny-precedence.md`: the AWS IAM 4-step decision order, why an explicit DENY always wins over
  an RBAC allow, and why an undecidable deny applies and a malformed or unreadable policy denies (`invalid_policy`)
  instead of being skipped.
- `polymorphic-identity-pivots.md`: why role, permission, and policy pivots use plain `string`
  `authorizable_type`/`authorizable_id` columns so that integer, UUID, and ULID identities all work.
- `subject-resolver-contract.md`: the one seam with `sinemacula/laravel-authentication` for the subject, its tenant
  and its application; the shipped default (Laravel's signed-in user, no tenant), the Gate's translation of its user,
  and how the umbrella package wires its own resolver.
- `wildcard-and-condition-semantics.md`: fnmatch semantics and escaping, resource-less checks, the four match outcomes
  (matches, does not match, undecidable, invalid), `${…}` interpolation, the write-time refusals, and the condition
  operator catalogue (`eq`, `neq`, `in`, `not_in`, `null`, `not_null`, `cidr`, `starts_with`, `ends_with`,
  `string_like`, `before`, `after`, `between`, `gt`, `gte`, `lt`, `lte`, `bool`).
- `permission-catalogue-sync.md`: declaring permissions in enums and providers, why booting never touches the
  database, and what `authorization:sync` adds, updates, reports as stale or protected, and prunes.
- `management-services.md`: the services every role, permission, policy and grant write goes through, their
  transaction, idempotent grants, re-armed expiries, the locked hierarchy check, and the scope each grant holds in.
- `events.md`: the one marker every event implements, the snapshot payloads, the actor the caller passes, one
  operation id per call, dispatch after commit, the grantees a delete reports and the document digests.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
