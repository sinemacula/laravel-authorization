# `sinemacula/laravel-authorization` — Open Issues

**Source of truth for v1.0 scope.** Every item listed here is in scope for
the initial release. Historical references to `SPECS.md` / the PRD remain
inline where they add design context; the documents themselves have been
consumed into this file and removed from the repo.

---

## P0 — Test coverage gaps

### 3. Feature suite missing spec-mandated scenarios

- **Spec reference:** §9.1 — Feature suite must cover service provider
  boot, facade wiring, Gate auto-wiring, config merge, migrations
  publishing, and role/permission/policy CRUD.
- **Observed state:** `tests/Feature/` contains
  `AuthorizationManagerTest`, `PolicyModelTest`, `ServiceProviderTest`,
  `TraitsCoverageTest`, and stubs. The following are absent:
  - **Gate auto-wiring tests** — no coverage for the
      `log | overwrite | throw` conflict modes configured in
      `AuthorizationServiceProvider::registerEnumGate()`, and no coverage
      proving the closure forwards `$user` via `Authorization::for($user)`
      (the seed bug called out in §6.3).
  - **Migration publishing test** — no assertion that
      `authorization-config` and `authorization-migrations` publish tags
      resolve to the expected targets.
  - **Role CRUD coverage** — no Feature test exercising the Role
      permission-management API (blocked by issue #2 above).

### 4. Integration suite thin

- **Spec reference:** §9.1 — Integration suite must cover polymorphic
  identities, the Spatie migration scenario, principal-resolver binding,
  Gate parity, and the MySQL + PostgreSQL + SQLite DB matrix.
- **Observed state:** `tests/Integration/` contains only
  `PolymorphicIdentityTest.php`. Missing:
  - Spatie migration scenario (a consumer swapping from
      `spatie/laravel-permission` using the shipped aliases).
  - Principal-resolver binding (a custom resolver bound into the
      container and used end-to-end through the facade).
  - Gate parity (for every registered enum case,
      `Gate::forUser($u)->allows(...)` yields the same decision as
      `Authorization::for($u)->can(...)`).
  - Cross-database tests — no MySQL/PostgreSQL harness exists; §10.1
      mandates the DB matrix in CI.

### 5. Performance suite missing RBAC N+1 and parse budgets

- **Spec reference:** §9.1 — Performance suite must cover evaluator
  throughput, RBAC lookup N+1 safety, and policy JSON parse cost.
- **Observed state:** `tests/Performance/EvaluatorThroughputTest.php` is
  the only performance test. There is no N+1 budget for `can()` repeated
  within a request (§12.2 calls this out explicitly), and no parse-cost
  budget for `Policy::fromArray()`.

---

## P0 — Benchmarks and docs

### 6. Three of the four required benches are missing

- **Spec reference:** §9.5 — benchmarks required in v1.0.0 are
  `Runtime/PolicyEvaluatorBench`, `Runtime/AuthorizationManagerBench`,
  `Runtime/RoleLookupBench`, and `Runtime/PolicyParseBench`.
- **Observed state:** only `benchmarks/Runtime/PolicyEvaluatorBench.php`
  exists. `benchmarks/Support/` is empty (no harnesses or in-memory
  fixtures, despite §2 listing `benchmarks/Support/` as the fixtures
  location).
- **Impact:** the Phase-4 exit criterion ("`composer bench:ci` publishes
  artefact") currently only exercises the evaluator, so the Manager,
  RBAC lookup, and policy-parse hot paths have no tracked budget.

### 7. Four design notes are missing

- **Spec reference:** §11 — `docs/design/` must contain
  `evaluation-order-and-deny-precedence.md`,
  `polymorphic-identity-pivots.md`,
  `principal-resolver-contract.md`, and
  `wildcard-and-condition-semantics.md`.
- **Observed state:** `docs/design/README.md` lists all four as
  "planned"; none of the note files exist.
- **Impact:** the auditable-decision contract (§12.1) relies on these
  notes to document invariants that are not obvious from the test suite
  alone. Their absence also violates §2's "same layout, same tooling"
  requirement vs. `laravel-authentication`.
- **Invariants the `evaluation-order-and-deny-precedence.md` note must
  pin down (confirmed design decisions):**
    1. RBAC is **additive / allow-only**. Direct permission grants and
       role-inherited permissions are unioned on read
       (`HasPermissions::getPermissions()`); there is no RBAC-layer
       deny mechanism.
    2. All deny semantics live **exclusively in policies**. A consumer
       needing "everyone in role X except these three users" must
       express that exception as a deny policy, not as an RBAC
       construct.
    3. The four-step evaluation order is
       `explicit deny → explicit allow → RBAC → implicit deny`; a deny
       statement whose conditions do not match is skipped (remains
       non-applicable), not treated as an explicit deny.
    4. Direct-user-permission grants sit alongside role-inherited
       permissions as equal citizens — no precedence between them; the
       union wins.

---

## Drop-in / DX friction (not spec gaps)

These are not violations of `SPECS.md` — they surfaced during exploratory
review of whether the package behaves as a drop-in RBAC solution with
minimal configuration. Each entry is a usability friction point for the
"pure RBAC, no policies, standard Laravel Auth" consumer, which is the
most likely first-use path.

### 22. No row-level multi-tenant role / permission scoping

- **Files:** `database/migrations/2026_04_14_000001_create_roles_table.php`
  (no tenant column); `database/migrations/2026_04_14_000002_create_permissions_table.php`
  (no tenant column); `src/Models/Role.php`, `src/Models/Permission.php`
  (no global scope); `SPECS.md` §4.3 item 4.
- **Observation:** the package has no notion of row-level tenant
  ownership on `roles` or `permissions`. All role and permission rows
  live in a single shared namespace, disambiguated only by
  `(name, guard_name)`. SPECS.md §4.3 explicitly defers tenant
  handling to the policy `context` array
  (`conditions: { tenant_id: {eq: 'org-1'} }`), and states the
  package "does not ship tenant middleware or tenant-aware tables."
- **Pushback on the spec stance:** SPECS.md §4.3 conflates two
  different tenancy problems:
    1. **Data-plane tenancy** — "user X can only read tenant Y's
       resources." Policy context conditions solve this well.
    2. **Control-plane tenancy** — "Client A defines a role called
       'Content Manager' that Client B does not know exists, with
       their own custom permissions, managed through Client A's
       admin UI." Policy conditions cannot model this — the role
       name itself is tenant-owned.
       Enterprise SaaS RBAC almost always needs **both**. The current
       design supports (1) and leaves (2) to the consumer, which means
       every SaaS consumer has to build their own tenant scoping on top
       of shared tables, or fork the package.
- **Impact:** SaaS consumers that want self-serve RBAC per tenant
  (Client A's admins managing their own role catalogue) have no
  path today without polluting the shared `roles` / `permissions`
  tables with `tenant_id` prefixes in the `name` column — a pattern
  that defeats the unique constraint and makes listing a tenant's
  roles a string-prefix query. For a package aspiring to be
  enterprise-ready, this is the largest single gap surfaced so far.
- **Options:** (a) add a nullable polymorphic owner
  (`tenant_type` / `tenant_id`) to `roles` and `permissions`, with
  `null` meaning "global / platform role" — scope lookups by the
  current tenant context supplied via a new `TenantResolver`
  contract (mirrors the `PrincipalResolver` pattern and keeps the
  package auth-agnostic); (b) keep the core tables single-tenant
  and ship a sibling `laravel-authorization-tenancy` package that
  layers tenant-scoped models on top; (c) document policy
  `context` conditions as the supported tenancy idiom and accept
  that control-plane tenancy is out of scope.
- **Follow-on work required for option (a):** schema change
  (nullable polymorphic owner on `roles` and `permissions`),
  lookup scoping (global scope keyed off the `TenantResolver`),
  attachment validation (prevent cross-tenant role ↔ permission
  and identity ↔ role attachment, analogous to issue #21 for
  guards), API ergonomics ("fetch this tenant's roles",
  "clone the platform role catalogue to tenant X"), and
  `PrincipalResolver` interaction (principal's effective tenant
  becomes an evaluation input). Each is tractable but the surface
  is wide — SPECS.md and the PRD should be amended to call out
  every touch point before implementation begins.

---

## Enterprise readiness gaps

Surfaced during deep code review against an enterprise RBAC checklist.
These are not spec deviations — they are features or surfaces a serious
enterprise consumer expects on day 1–30 that this package does not
ship. All items are in-scope for v1.0.0.

### 28. No role hierarchy / inheritance

_(Not to be confused with role rank — see #45. Hierarchy governs
**permission flow** ("admin inherits editor's permissions"); rank
governs **management authority** ("admin can act on editor, editor
cannot act on admin"). They are independent features and most
enterprise systems ship both.)_

- **Files:** `database/migrations/2026_04_14_000001_create_roles_table.php`
  (no `parent_id` column); `src/Models/Role.php` (no parent/children
  relations); `src/Traits/HasPermissions.php:143–164`
  (`getPermissions()` walks only the identity's own roles, never
  into role ancestors).
- **Observation:** roles are flat. There is no parent-child
  relationship, so `admin ⊃ editor ⊃ viewer` cannot be expressed
  structurally. Consumers wanting inheritance today must duplicate
  permissions across roles manually and keep them in sync.
- **Impact:** one of the most common enterprise RBAC asks. Without
  it, role catalogues bloat quickly and drift (someone adds
  `posts:archive` to `editor` but forgets to add it to `admin`).
- **Options:** (a) add nullable `parent_id` on `roles` with
  self-referential FK; `Role::ancestors()` resolves the chain;
  `getPermissions()` walks up ancestors unioning permissions at
  each level — requires cycle-detection guard on write; (b) adopt
  a closure-table pattern (separate `role_hierarchy` table with
  `ancestor_id`, `descendant_id`, `depth`) for O(1) ancestry
  lookup at the cost of write-time maintenance; (c) document the
  flat-role model as intentional and steer inheritance needs into
  policies. Option (a) is the lowest-friction and the standard
  idiom; option (b) matters only at very large role catalogues.

### 31. No permission categorisation / grouping

- **Files:** `database/migrations/2026_04_14_000002_create_permissions_table.php`;
  `src/Models/Permission.php`.
- **Observation:** permissions carry `name`, `guard_name`,
  `description` — no `category`, `group`, `module`, or tag
  metadata. A permissions-management UI rendering 500+ permissions
  has nothing to group by.
- **Impact:** admin UIs for RBAC configuration get unusable above
  ~100 permissions without grouping. Consumers end up deriving a
  category from the `name` prefix (`posts:*` → "Posts") at view
  time, which is both fragile and not persistable.
- **Options:** (a) add a nullable `category` string column on
  `permissions`; (b) introduce a `permission_categories` table
  with a FK for normalised grouping; (c) ship a tags package via
  `spatie/laravel-tags` or similar polymorphic tag support;
  (d) defer to consumer — document the `name` prefix convention.
  Option (a) is cheap and covers 90% of cases.

### 32. No soft deletes on roles, permissions, or policies

- **Files:** `src/Models/Role.php`, `src/Models/Permission.php`,
  `src/Models/Policy.php` — none use `SoftDeletes`.
- **Observation:** deletion is permanent. Historical questions
  ("what roles did user X hold on 2026-01-01?") become unanswerable
  once a role row is deleted, even if the assignment pivot rows
  were audit-logged.
- **Impact:** compliance-heavy deployments (SOC 2, ISO 27001) need
  to reconstruct historical authorization state during incident
  response. Without soft deletes this is impossible from the
  package's own tables.
- **Options:** (a) add `SoftDeletes` to all three models and a
  `deleted_at` column to each; cascade rules need updating so a
  soft-deleted role's pivot rows are not also cascaded hard;
  (b) defer to the future `laravel-audit-log` package, which can
  snapshot row state on delete; (c) combine — keep hard delete as
  default, offer soft-delete as an opt-in trait mixin. Depends on
  how much of the historical-reconstruction responsibility is
  pushed to the audit package.

### 35. No Artisan commands (`authorization:*`)

- **Files:** no `src/Console/` directory exists.
- **Observation:** no CLI surface. There is no
  `authorization:list-roles`, `authorization:grant`,
  `authorization:revoke`, `authorization:policy:validate`,
  `authorization:sync-permissions`, `authorization:why-can`.
- **Impact:** enterprise ops teams live in CLI (CI pipelines,
  deploy hooks, break-glass recovery). Every consumer reimplements
  this.
- **Options:** (a) ship a minimum set:
  `authorization:list-roles`,
  `authorization:list-permissions`,
  `authorization:grant {identity} {role}`,
  `authorization:revoke {identity} {role}`,
  `authorization:policy:validate {file}`,
  `authorization:why-can {identity} {action} {resource?}` (prints
  the evaluation trace — covers issue #42 CLI-side).

### 36. No testing helpers / PHPUnit assertions

- **Files:** no `src/Testing/` directory exists.
- **Observation:** no `assertCan()`, `assertCannot()`,
  `actingAsWithRole()`, `actingAsWithPermissions()`,
  `withPolicies()` helpers.
- **Impact:** every consumer writes the same test setup boilerplate
  — creating a user, attaching roles, impersonating via
  `Authorization::for($user)`. Slows adoption and invites
  inconsistent test patterns.
- **Options:** (a) ship `SineMacula\Laravel\Authorization\Testing\AuthorizesRequests`
  trait with PHPUnit assertions and actor helpers, and a
  `AuthorizationFactory` that constructs in-memory principals with
  given permission sets for unit tests.

### 37. No context variable interpolation in policy statements

- **Files:** `src/Evaluation/Statement.php:272–280` (`matchesResource()`)
  and `:313–328` (condition operators) treat pattern strings as
  literals.
- **Observation:** AWS IAM supports `${aws:username}`, `${aws:userid}`,
  etc. style variable substitution in resource patterns and
  condition operands. This package has no substitution — a policy
  statement with `resources: ["post:${principal.id}"]` is matched
  literally against the asked resource string.
- **Impact:** multi-tenant SaaS cannot template policies. "User can
  edit posts in their own tenant" becomes expressible only if the
  caller hydrates the policy document per-request, which defeats
  the point of a persisted policy doc.
- **Options:** (a) introduce a `ContextInterpolator` that walks
  pattern strings and condition operands, replaces `${path.to.key}`
  tokens from a merged view of principal + context + resource
  metadata, with an escape syntax for literal `$` characters;
  run before `fnmatch` / operator evaluation.
- **Namespace pattern (locked):** three namespaces —
  `${principal.*}` for the resolved principal's attributes
  (`principal.id`, `principal.type`, any `AuthorizableIdentity` helper
  returning scalar metadata), `${context.*}` for the caller-
  supplied context array, and `${resource.*}` for attributes of the
  resource object when it implements the proposed
  `AuthorizableResource` contract (see #49). Unknown keys resolve
  to the empty string and emit a debug log line — never throw.

### 38. Condition operator set is narrower than enterprise IAM norms

- **Files:** `src/Evaluation/Statement.php:313–328`.
- **Observation:** ten operators shipped — `eq`, `neq`, `in`,
  `not_in`, `cidr`, `starts_with`, `ends_with`, `before`, `after`,
  `between`. Missing: `string_like` (glob matching on condition
  values — `fnmatch` is used for action/resource but not for
  condition operands), `null` / `not_null`, `forAllValues` /
  `forAnyValue` (AWS's set-theoretic quantifiers for multi-valued
  context keys), numeric comparison (`gt`, `gte`, `lt`, `lte`),
  boolean coercion.
- **Impact:** any policy that conditions on multi-valued context
  keys, numeric ranges, nullable fields, or wildcard-matched
  condition values cannot be expressed today. A prospect migrating
  AWS IAM policies hits the missing operators on day one.
- **Options:** (a) expand the match arm with the above operators;
  (b) lock the operator set to what is shipped and document it
  authoritatively; (c) introduce an operator-registration API so
  consumers can plug in their own. Option (a) is the honest
  minimum for "enterprise IAM-style policy engine."

### 45. No role rank / level / seniority model

- **Files:** `database/migrations/2026_04_14_000001_create_roles_table.php`
  (no `rank` / `level` column); `src/Models/Role.php` (no rank
  attribute); `src/Traits/HasRoles.php` (no assignment-time guard
  against privilege escalation).
- **Observation:** there is no concept of role **seniority** —
  the idea that a principal cannot perform administrative actions
  on another principal whose role is equal or senior to their own.
  Industry terms for this include role rank, role level, role
  seniority, administrative scope, and permission boundaries (AWS).
  Every enterprise IAM system ships some form of it to prevent
  privilege escalation through the authorization system itself
  (a junior admin promoting themselves, a peer demoting a senior
  admin, a tenant admin acting on a platform admin).
- **Relationship to #28 (role hierarchy):** orthogonal. Hierarchy
  governs permission flow (admin _inherits_ editor's permissions).
  Rank governs management authority (admin _can act on_ editor,
  editor _cannot act on_ admin). Most enterprise systems ship
  both; they cover different risks.
- **Impact:** without rank, a consumer cannot model common
  requirements such as "tenant admins cannot demote platform
  staff", "team leads can assign the `member` role but not the
  `owner` role", or "a user cannot grant themselves a role higher
  than their current highest." Every consumer either builds this
  outside the package or accepts a privilege-escalation footgun.
- **Options (recommended shape):**
    1. **Schema.** Add a nullable integer `rank` column to the
       `roles` table. Lower values = more senior (0 is the most
       senior, mirroring IAM conventions). `null` means "unranked"
       — not subject to rank-guard — so the feature is opt-in per
       role and does not impose complexity on simple consumers.
    2. **Assignment-time guard (automatic).** In
       `HasRoles::assignRole()` / `syncRoles()`, reject the
       assignment when the actor's highest-ranked role has a
       larger `rank` value than the target role being assigned.
       Emit `RankGuardException`. Null-rank targets bypass this
       check (unranked roles are freely assignable). The actor is
       sourced from the `PrincipalResolver` — explicit service
       calls (seeders, system operations) can skip the guard via
       an `assumeSystemActor()` / `withoutRankGuard()` escape
       hatch.
    3. **Advisory helper (explicit).**
       `$actor->canActOn($target): bool` returns true only when
       the actor's highest-ranked role has a `rank` ≤ the target's
       highest-ranked role. Consumers call this in controllers
       and policies when the action is something other than role
       assignment (deleting a user record, sending them a DM,
       changing their email). Do **not** auto-inject into every
       `can()` check — that is too coarse and would break
       self-serve operations (a rank-5 user editing their own
       profile).
    4. **Super-admin interaction (#26).** A principal holding
       `*:*` sits at whichever rank their role carries — typically
       `0`. This is the cleanest way to make the super-admin
       genuinely un-actable-on from below, because rank and
       permission breadth compose naturally.
    5. **Tie-breaking.** Equal rank = cannot act. Document as
       "strict senior" semantics. A configurable
       `rank.equal_rank_can_act: bool` flag (default false) can
       be added later if consumers want peer-acting.
- **Configuration:** introduce `authorization.rank.enabled` (bool,
  default true once the schema lands) and
  `authorization.rank.default` (int|null, default null). Simple
  consumers who set every role's rank to null get current
  behaviour; enterprise consumers who set ranks get the guardrail
  automatically.

### 49. No `AuthorizableResource` contract for model-to-resource-string conversion

- **Files:** no contract exists; `src/AuthorizationManager.php` and
  `src/Evaluation/Statement.php` accept resource as `?string`
  only; there is no standard way to turn an Eloquent model into
  the resource identifier a policy matches against.
- **Observation:** when `$user->can('posts:edit', $post)` lands
  (contingent on #23 fixing the Gate closure to forward
  arguments), something has to convert `$post` to a string the
  evaluator can match against. Without a shipped contract, every
  consumer invents their own convention — stringifying the ULID,
  using a `morphMap` lookup, or dropping to
  `{modelName}:{primaryKey}`. Inconsistent conventions mean
  policy documents are not portable across apps and tenant
  context (`${resource.*}` interpolation in #37) has no defined
  source for field access.
- **Impact:** resource-aware authorization is effectively
  undefined behaviour across consumers. Policies with
  `resources: ["post:*"]` or `resources: ["post:${principal.id}"]`
  cannot be written confidently because the matched-against
  string shape varies. Also blocks the `${resource.*}` namespace
  of #37.
- **Options:** (a) ship
  `SineMacula\Laravel\Authorization\Contracts\AuthorizableResource`
  with `toAuthorizationResource(): string` returning the
  canonical identifier, and a default trait
  `ProvidesAuthorizationResource` that reads a
  `authorizationResourceType` property (falls back to the morph
  alias, falls back to the class basename) and composes it with
  the model key (`"{type}:{id}"`). The Gate closure (#23) and the
  `${resource.*}` interpolator (#37) consume this contract when
  the passed resource is an object. Scalars continue to pass
  through as literal strings.

### 50. No Spatie migration Artisan command

- **Files:** no `src/Console/` directory; CLI surface covered
  separately by #35 but this is a distinct one-off migration
  command.
- **Observation:** §12.5 commits to supporting Spatie's
  `laravel-permission` migration idiom, and #48 tracks the method
  alias surface. But a consumer migrating their database from
  Spatie to this package still has to hand-write SQL or a one-off
  script to move rows across the differing schemas (Spatie's
  `model_has_roles` vs this package's `authorizable_roles`,
  Spatie's `model_type`/`model_id` vs `authorizable_type`/
  `authorizable_id`, etc.).
- **Impact:** the "switch packages without rewriting every
  controller" §12.5 claim ends at the method surface. At the
  persistence layer, consumers are on their own for the one
  migration they need most. This is the friction point that
  decides whether a real Spatie consumer actually adopts.
- **Options:** (a) ship
  `php artisan authorization:migrate-from-spatie {--dry-run}
  {--guard=web}` that introspects the source tables, maps rows
  into this package's schema (roles, permissions, pivots,
  guard_name defaults), preserves IDs where safe and regenerates
  where required, and reports unmapped rows. Should be
  idempotent and transaction-wrapped. Ships alongside the Spatie
  migration guide under `docs/migration/spatie.md`.

### 51. No "effective permissions" API with wildcard expansion or policy inclusion

- **File:** `src/Traits/HasPermissions.php:143–164`
  (`getPermissions()`).
- **Observation:** `getPermissions()` returns the literal
  permission names attached directly or via roles, including
  wildcard permissions as their raw pattern
  (`posts:*` stays as `posts:*`). It does not:
    1. Expand wildcards against a known universe (e.g. a
       registered `PermissionEnum` case list).
    2. Include actions a principal can perform via policy allows
       (a principal may have no direct/role grant of
       `billing:view` but a policy statement allows it).
    3. Merge in wildcard-matched actions from held `*:*` /
       `posts:*` permissions (see #27) against the enum universe.
- **Impact:** UI consumers rendering "here is everything you can
  do" (a permission-picker, a capability checklist on a user's
  settings screen, an admin review panel) cannot get that list
  from the package. They either do it wrong or build their own
  resolver.
- **Options:** (a) add
  `AuthorizableIdentity::effectivePermissions(?EnumScope $universe = null): array`
  that returns the concrete, deduplicated action list. When
  called with a universe (the registered `PermissionEnum` cases)
  it expands wildcards against that universe and merges in
  actions granted by allow policies. When called without one, it
  returns the raw pattern list for consumers that want to do
  their own expansion; (b) keep `getPermissions()` as the raw
  accessor and add `effectivePermissions()` strictly as the
  expanded variant. Document the semantic difference clearly —
  the raw list is for debugging, the effective list is for UI.

### 52. No documented impersonation seam

- **Files:** `src/AuthorizationManager.php:142–155`
  (`for()` exists); no `docs/design/impersonation.md`.
- **Observation:** support engineers, platform admins, and QA
  teams routinely need to act-as another principal for debugging
  and incident response. The package already has the primitive —
  `Authorization::for($principal)->can(...)` returns a scoped
  manager — but there is no documented pattern for how to
  impersonate safely (event trail emission, time-bounded session,
  marking the actor so the audit log shows "X acting as Y", not
  just Y). Consumers will invent unsafe patterns (e.g. swapping
  the auth guard user at runtime) because the authorization
  layer doesn't tell them how.
- **Impact:** SOC 2 / ISO 27001 audits will specifically ask for
  impersonation controls. Without documentation, consumers ship
  unreviewed impersonation code — which is one of the most
  common sources of privilege-escalation incidents in SaaS.
- **Options:** (a) add
  `docs/design/impersonation.md` documenting: use `for()` for the
  authorization scope, emit a paired `Impersonating` /
  `ImpersonationEnded` event (new event pair the audit-log
  package can subscribe to), never swap the auth guard user,
  always record the original actor on the audit trail; (b)
  additionally ship a thin `Impersonation` facade that wraps
  `for()` with event emission and a closure-scoped lifetime
  (`Impersonation::as($target)->during(fn () => ...)`). Option
  (b) is the opinionated enterprise-grade path.

### 53. No `PermissionProvider` contract for modular / package-contributed permissions

- **Files:** `src/AuthorizationServiceProvider.php:144–163`
  (walks `authorization.permission_enums` config only);
  no contract for runtime contribution.
- **Observation:** permissions are registered through a single
  config array (`authorization.permission_enums`). A modular
  Laravel app where each installable module ships its own
  permissions — a CMS plugin adding `media:manage`, a billing
  plugin adding `invoices:issue`, etc. — cannot contribute those
  permissions at boot time without asking the host app to edit
  its config file. This breaks the standard Laravel convention
  where a package's own service provider registers its own
  surface.
- **Impact:** modular / plugin-driven apps cannot adopt the
  package without an awkward "consumer must edit their config to
  install this module" step. Enterprise IAM deployments often
  ship module-owned permissions; this is a drop-in friction
  point for a non-trivial cohort.
- **Options:** (a) introduce a
  `SineMacula\Laravel\Authorization\Contracts\PermissionProvider`
  interface with a `permissions(): iterable<PermissionEnum>`
  method; packages register providers via the container
  (`$this->app->tag($myProvider, 'authorization.providers')`);
  the service provider collects tagged providers at boot and
  merges their output with the config-declared enums before
  running the existing `registerGates()`; (b) same idea but
  config-driven: add a `authorization.permission_providers`
  config key mirroring `permission_enums`. Option (a) matches
  Laravel package-registration conventions better; option (b) is
  consistent with existing config idiom. Either works.

### 84. System-wide enum audit — cover, consolidate, and single-responsibility

- **Scope:** package-wide audit of every place a constrained
  set of values is represented as a string, an int, a
  class-constant, or anything other than a backed enum.
  Three things to land, in this order:
    1. **Cover** — every finite, closed-set value becomes a
       typed enum.
    2. **Consolidate** — no two enums encode the same domain;
       duplicates get merged or one-way-aliased.
    3. **Single-responsibility** — each enum represents exactly
       one category; no enum mixes unrelated concerns under one
       list of cases.
- **Candidate surfaces to audit (non-exhaustive, surfaced
  during commit review):**
  - `authorization.gate.on_conflict` config value —
      string-typed `'log' | 'throw' | 'overwrite'`, matched on
      string literals in `src/AuthorizationServiceProvider.php`
      (already tracked as #58; folds into this audit as
      `GateConflictMode`).
  - `EvaluationResult::REASON_*` class constants
      (`explicit_allow`, `explicit_deny`, `implicit_deny`,
      `rbac_allow`) — a closed set of decision-reason values
      passed as strings everywhere. Candidate enum
      `DecisionReason`. Consumer pattern today is
      `$result->reason === EvaluationResult::REASON_EXPLICIT_ALLOW`
      — typed enum would give exhaustive `match` and IDE
      completion.
  - Evaluation trace `decision` field
      (`'matched' | 'skipped'`) — string literal matched on raw
      strings. Candidate enum `TraceDecision`.
  - `SystemRoleProtectedException::$operation`
      (`'delete' | 'rename'`) — raised and compared as string.
      Candidate enum `ProtectedOperation`.
  - `ValidatesAuthorizationName::getAuthorizationNameKind()`
      return value — strings like `'role'`, `'permission'`.
      Candidate enum `AuthorizationEntityKind` (or reuse the
      `PolicyEffect`-style pattern per-model).
  - `authorization.permission_enums` entries — already enums
      implementing `PermissionEnum`; confirm the audit does not
      accidentally collapse this correct-by-construction seam.
  - `PolicyEffect` enum — already exists; audit for
      single-responsibility (allow / deny only, no drift).
  - `CacheKind` slots in `ResolutionCache`
      (`'policies' | 'permissions' | 'roles'`) — strings in the
      `rememberStringList` helper. Candidate enum.
- **Observation:** enums enforce exhaustiveness at the type
  system (a `match` over an enum missing a case is a
  phpstan-level-8 error), eliminate the class of "typo in the
  config fell through to default" bugs #58 / #59 flagged in
  their narrower scope, and make the public surface clearer in
  IDE autocomplete. The package already ships `PolicyEffect`,
  so the idiom is established — the audit's job is to apply it
  consistently.
- **Duplication watch:** any two enums whose cases sort to the
  same semantic list get merged or one becomes a thin type
  alias over the other. Cross-check every proposed new enum
  against the full `src/Enums/` directory as it grows. If two
  namespaces independently land `ResourceKind` and
  `EntityCategory` with overlapping cases, merge before
  shipping.
- **Single-responsibility rule:** each enum represents one
  orthogonal axis. Do **not** encode
  `ROLE_DELETE | ROLE_RENAME | PERMISSION_DELETE | PERMISSION_RENAME`
  as a single `ProtectedOperation` — that is two axes
  (entity + operation) crammed into one list. Two enums,
  composed: `AuthorizationEntityKind` and
  `ProtectedOperation`, paired via properties on the exception
  payload. Exhaustive matching stays tractable because each
  axis is short.
- **Options:** (a) one sweep-PR per category listed above,
  each landing a single enum plus every call site it touches;
  small, reviewable, reversible; (b) one-shot migration that
  introduces every enum together and lets phpstan catch the
  transition; faster to land, heavier to review; (c) write a
  dedicated `docs/design/enums.md` that states the policy
  (what qualifies for an enum, naming convention, namespace
  placement, one-axis rule) and apply it opportunistically as
  each issue it closes is picked up. Option (a) paired with
  option (c) is the honest iterative path; option (b) is the
  big-bang alternative and pairs well with the pre-release
  no-BC stance. Either way, the design note under option (c)
  should land first so every subsequent enum PR has a clear
  acceptance bar.
- **Related issues:** #58 (`gate.on_conflict`), and any future
  flag that surfaces a stringly-typed closed set will cite
  this audit as its landing home.

### 97. `instance()` accessor duplicated across `ResolutionCache` and `AuthorizationManager`

- **Files:** `src/Cache/ResolutionCache.php:92–106`;
  `src/AuthorizationManager.php:95–109`.
- **Observation:** the commit introduces the same 15-line
  static accessor on two unrelated classes, byte-for-byte
  identical:
  ```php
  public static function instance(): ?self
  {
      if (!\function_exists('app')) {
          return null;
      }
      $container = app();
      if (!$container->bound(self::class)) {
          return null;
      }
      /** @var self */
      return $container->make(self::class);
  }
  ```
  Two sanctioned service-locator sites is an improvement over
  the scattered `app()->bound(...) ? app(...) : null` idiom
  that preceded it, but the shape that repeats across two
  classes is itself duplicated logic. Also the
  `function_exists('app')` guard is defensive to the point of
  unreachable code (the Laravel global helper is always
  loaded when the package loads) — and is now the
  duplicated guard on both classes.
- **Impact:** drift risk if one site ever diverges (e.g. one
  class adds logging / metrics on the accessor and the other
  forgets). Also the pattern is likely to be needed on future
  container-bound classes (`LastDecisionStore`,
  `PolicyResolver`, etc.) and each new class will copy the
  15 lines.
- **Options:** (a) extract a `BindsInstanceFromContainer`
  trait with the static method and a single abstract hook
  (`containerKey(): string` defaulting to `self::class`);
  each class `use`s it, one source of truth; (b) extract a
  free-standing helper `ContainerInstance::ofOrNull(string
  $class): ?object` and have both classes' static methods
  delegate to it in one line; (c) accept the duplication and
  document — two-site drift is still cheaper than three.
  Option (a) composes cleanly with #92's proposed
  `ProtectsSystemFlaggedRows` trait pattern — one trait file
  per cross-cutting concern.

### 98. Cache-remember methods grew to four positional parameters with unrelated concerns

- **File:** `src/Cache/ResolutionCache.php:118–197`
  (`rememberPolicies`, `rememberPermissions`,
  `rememberRoles` signatures).
- **Observation:** the remember-methods now take
  `(object $principal, Closure $resolver, ?int $maxTtl = null,
  array $roleIds = [])` — four positional parameters mixing
  the core cache-slot identity (`$principal`, `$resolver`)
  with two TTL/tag-metadata fields (`$maxTtl`, `$roleIds`).
  Every call site in the traits now passes the TTL hint and
  the role-tag list positionally; a consumer reading
  `$cache->rememberRoles($user, fn() => ..., 3600, ['admin',
  'editor'])` has to infer what the trailing array is without
  looking up the signature. PHP 8 named arguments help but
  the positional shape is the canonical one consumers copy
  from.
- **Impact:** parameter-order footgun as the signature grows.
  If a fifth knob lands (e.g. a `CacheDriver` override, a
  per-call tag-prefix, a cache-hit-only flag) the positional
  shape keeps getting wider. Also splits a conceptually
  single invariant ("cache context for this remember") across
  three separate parameters.
- **Options:** (a) introduce a
  `ResolutionCacheContext` value object that bundles
  `?int $maxTtl` and `array $roleIds` (plus future knobs) as
  named properties; the remember-methods narrow to
  `(object $principal, Closure $resolver, ?ResolutionCacheContext $context = null)`
  and call sites construct context via `new ResolutionCacheContext(maxTtl: ..., roleIds: ...)`;
  (b) keep the positional shape and lean on consumers to use
  PHP 8 named arguments in their own code; (c) split the
  remember-methods into a low-level positional path and a
  higher-level fluent `->with()->remember()` DSL — more
  surface, clearer call sites. Option (a) is the simplest
  that caps the API width and gives every future knob a
  named home.

---

## Cross-references

- `SPECS.md` §3.2 lists ten behavioural gaps between the seed and
  v1.0.0. Items 1–6, 8, and 10 are implemented; items **7** (resolver
  contract) and **9** (`InvalidPolicyDocumentException` on bad parse)
  are implemented. This file tracks the gaps that remain after that
  wave of work — primarily the Role API (issue #2), the contract
  surface (issue #1), and the non-code scaffolding (issues #3–#7).
- PRD acceptance criteria referenced from §9.2 (`≥ 90% line coverage`
  on manager, evaluator, and traits) cannot be verified until the
  missing Feature / Integration tests land.
