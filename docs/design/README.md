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
  falls through to Laravel, the registration order that decides precedence, the guest, the switch that turns it off,
  and the trait through which a Laravel policy class decides the abilities left to it.
- `permission-catalogue-sync.md`: declaring permissions in enums and providers, why booting never touches the
  database, and what `authorization:sync` adds, updates, reports as stale or protected, and prunes.
- `management-services.md`: the services every role, permission, policy and grant write goes through, their
  transaction, idempotent grants, re-armed expiries, the locked hierarchy check, the scope each grant holds in, a
  role's policies as its grants, inline policies attached to their grantee alone and deleted with it, and policies
  attached to resources and resource types, permission boundaries set on principals and identities, and guardrails
  set on tenants and the platform by an acting subject allowed to.
- `delegated-administration.md`: the administration actions, the acting context, trusted and delegated calls, the
  operation resource and its attributes, the administration stage of a decision, what each part of BL-65 enforces,
  the reasons and the audit.
- `events.md`: the one marker every event implements, the snapshot payloads, the call's operation and actor, one
  operation id per call, dispatch after commit, the grantees a delete reports, the boundary and guardrail events and the
  document digests.
- `query-scoping.md`: the `whereAuthorized()` and model-level `AuthorizedScope` contract over a query's candidate
  rows, compiling at the call and at every execution, the classes of rows cut at the tenants the sources sit at and
  decided through the decision pipeline itself, literal ids, record attachments, the collation and key-kind proofs,
  the guards, every refusal reason, and the limits.
- `bulk-checks.md`: `checkMany()`, `canEach()` and `filterAuthorized()` deciding every check through the one decision
  path, the keys and occurrences they keep, what a batch reads once in each scope and what it reads in bulk for each
  chunk, the bulk tenant and attribute contracts and their fallbacks, one decision event per check and the last
  decision, and the consistency boundary within which a batch sees a write.
- `effective-permissions.md`: `permissionsFor()` listing exactly the catalogue's actions `check()` would allow in an
  `AuthorizationScope`, through the one decision path over data read once, the scope applied and restored, the
  subject forms, and why a listing records no decision and dispatches no event.
- `preview.md`: `previewFor()` and its fixed parties, the sessionless target in the caller's request context, the
  `authorization:subject.preview` admission on a typed preview resource in every scope a decision is made in, once per
  scope per use, and its revalidation at every use, the events naming both parties and the listing exception,
  explanations, what is refused, the refused query writes, why a preview confers no authority
  (`administration.previewing`), the disclosure point and the limits of a manager clone.
- `grant-scope.md`: the identity directory contract and its default, the shared reader of grant roots, `forIdentity()`'s
  `within`, `outside` and `unknown` and `hasGrantIn()`'s `present`, `absent` and `unknown`, the grantees reaching a
  tenant or within it, what counts as a grant, why no answer is membership or authorisation, why it is a trusted service
  returning only the status or the grantees, and the grant hooks: which grants widen an identity's scope, the veto-only
  contract and its ordered composite, the run before the package's first lock with the coverage check and retry, the
  recursion guard and nested calls.
- `explanations.md`: explain mode, the switch on the one decision path that leaves every everyday check as it was, the
  evidence it records (each condition test with its typed outcome, the unresolved references, where each grant that
  allowed a check came from, and what the check asked), the `Explanation` projection, its causes and the stages it
  never reached, its escaped text and versioned schema, what it never holds, what a stored decision explains, and the
  `authorization:why` command: the console subject resolver, the named scope, the resource as `check()` takes it,
  `--context` as input alone, the formats and the exit codes.
- `separation-of-duties.md`: pairs of mutually exclusive roles stored by role key in a canonical order, owned as a
  definition is, declared and removed through the role exclusion service under its own actions with the owner, rank
  and administered-scope rules, idempotence and its events, and the conflict report: where two holdings overlap by
  tenant, subtree, platform and application, roles held through parents, a principal with its identity, what holds
  nothing, the bounded read, and the refusal that carries the report and removes nothing.
- `access-reviews.md`: what an access review means by holding (grant routes, never effective access), the structural
  predicates it shares with a check and never evaluates beyond, every edge live and every route kept, the hierarchy
  read in a fixed number of queries, the scope selections and the explicit application selector, `holders()`,
  `holdings()` in principal and identity mode, `expiring()` in a UTC half-open window and `grantedBy()` as the last
  writer, the reference-only versioned rows, the byte-for-byte total order on every database, the bounded list with
  its exact truncation, the `authorization:review.read` admission through `check()` with the reach rule, the refusal
  that discloses nothing, and the explicit trusted path; then the keyset pages and their signed cursors bound to their
  review, readmission on every page and the frozen instant of a live scan, lazy streams, the versioned JSON Lines
  export under `authorization:review.export`, `authorization:review`, and the review indexes; then opt-in grant usage
  tracking: what counts and what never counts, the bucketed in-memory notes flushed by queued jobs, the usage and
  coverage tables, the `GrantUsageStore` contract, the heartbeat and pruning, the coverage rule behind `used`, `unused`
  and `unknown`, regrants, `unused()` and the `usage` field.
- `break-glass.md`: opt-in emergency access, not yet available: the `break_glass` settings and the switch refused
  until its audit trail ships, one record per activation in its own table, an activation live until it ends or
  expires, read through the role grant path so every check sees its role in its scope, human principals alone (never
  a machine or an identity), its changes seen on the next check, its route named in an explanation without its note,
  and the plan for activation and revocation, then the lifecycle events, reviews and attribution.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
