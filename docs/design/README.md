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

- `evaluation-order-and-deny-precedence.md`: the staged decision order (subject, resource, tenant, then the denies, the
  caps, the allows and the implicit deny), why an explicit DENY always wins over an RBAC allow, and why an undecidable
  deny applies and a malformed, unreadable or over-limit policy denies (`invalid_policy`) instead of being skipped;
  `insufficient_authentication`, where it ranks, and how long a decision that read an authentication requirement may be
  reused; where a check's policies come from (the policy store, the identity's own and inline policies, its roles'
  policies down the hierarchy, and the policies attached to the resource and its type) and why their order never
  matters; resource policies' `principals`, their denies for everyone and why their allows come after the tenant stage
  and every deny; the cap stages (guardrails, permission boundaries and session caps) between the denies and the allows,
  and why every guardrail, boundary and session cap that applies must allow a check and none grants anything; which
  guardrails apply to a check and who may change them; the session caps (a credential's scopes through the scope map,
  and the caller's explicit caps), machine principals, which need their credential's scopes and never receive a
  person's grants, and the scope registry; where a permission held is weighed (the allow stage alone, after every deny
  and cap) and the resources it reaches by its grant's tenant, subtree, application and expiry.
- `polymorphic-identity-pivots.md`: why role, permission, and policy pivots use plain `string`
  `authorizable_type`/`authorizable_id` columns so that integer, UUID, and ULID identities all work.
- `subject-resolver-contract.md`: the one seam with `sinemacula/laravel-authentication` for the subject, its tenant
  and its application; the shipped default (Laravel's signed-in user, no tenant), the Gate's translation of its user,
  and how the umbrella package wires its own resolver.
- `wildcard-and-condition-semantics.md`: fnmatch semantics and escaping, the statement keys (`sid`, `not_actions`,
  `not_resources`), resource-less checks, the four match outcomes (matches, does not match, undecidable, invalid), the
  check's namespaced context (`authentication`, `request`, `environment`, `subject` and `resource` with their
  built-ins and attribute providers, `input` and application namespaces from a `ContextSource`), built lazily and once a
  check, with caller values confined to `input`, and the context key catalogue
  with its types and the operators each type allows, `${…}` interpolation, the write-time refusals, limits and action
  catalogue, and the operator-first condition catalogue (`eq`, `neq`, `in`, `not_in`, `starts_with`, `ends_with`,
  `like`, `gt`, `gte`, `lt`, `lte`, `before`, `after`, `between`, `bool`, `null`, `ip_in`, `ip_not_in`, `any_value_in`,
  `all_values_in`, and the `_if_exists` suffix), the `authentication_requirement` operator, and the assurance keys no
  condition may test.
- `gate-authority.md`: the one `Gate::before` hook through which the package answers the abilities it declares, what
  falls through to Laravel, the registration order that decides precedence, the guest, and the switch that turns it
  off.
- `permission-catalogue-sync.md`: declaring permissions in enums and providers, why booting never touches the
  database, and what `authorization:sync` adds, updates, reports as stale or protected, and prunes.
- `management-services.md`: the services every role, permission, policy and grant write goes through, their
  transaction, idempotent grants, re-armed expiries, the locked hierarchy check, the scope each grant holds in, a
  role's policies as its grants, inline policies attached to their grantee alone and deleted with it, and policies
  attached to resources and resource types, permission boundaries set on principals and identities, and guardrails
  set on tenants and the platform by an actor allowed to.
- `events.md`: the one marker every event implements, the snapshot payloads, the actor the caller passes, one
  operation id per call, dispatch after commit, the grantees a delete reports, the boundary and guardrail events and the
  document digests.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
