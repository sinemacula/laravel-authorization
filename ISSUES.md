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

### 47. Open question §15.4 unresolved — gate conflict default

- **Spec reference:** §15 open question 4 — _"Gate conflict
  default. `log` is the safe default, but `throw` would be the
  opinionated enterprise default. Lock in v1.0.0."_
- **Files:** `config/authorization.php:88–90` — default is
  currently `log`; `src/AuthorizationServiceProvider.php:174–199`
  implements all three modes.
- **Observation:** the implementation supports all three modes
  (`log`, `throw`, `overwrite`), but the spec explicitly flags the
  default as an unresolved decision to lock before v1.0.0. The
  current `log` default silently preserves a user-defined Gate
  that collides with an auto-wired permission — which could
  silently weaken authorization if a consumer accidentally
  redefines a Gate name.
- **Impact:** defers a decision the spec itself calls out as
  pre-v1.0.0 mandatory. The enterprise-correct answer is almost
  certainly `throw` — a boot-time crash is strictly safer than a
  silently weakened Gate.
- **Options:** (a) change the default to `throw`, making
  collisions fail-loud; keep `log` and `overwrite` as opt-ins for
  consumers that have deliberate collision patterns; (b) keep
  `log` as default and document the rationale in
  `docs/design/`. Option (a) matches "opinionated enterprise
  default" in the spec text.

### 48. Open question §15.5 unresolved — final Spatie alias set

- **Spec reference:** §15 open question 5 — _"Spatie API aliases.
  Which Spatie method names do we alias on
  `HasRoles`/`HasPermissions`? Minimum is `assignRole`,
  `removeRole`, `givePermissionTo`, `hasPermissionTo`,
  `syncRoles`, `syncPermissions`. Full list to be finalised when
  the migration guide is drafted."_
- **Files:** `src/Traits/HasRoles.php` (has `assignRole`,
  `revokeRole`, `removeRole` alias at line 169, `syncRoles`,
  `hasRole`, `getRoles`); `src/Traits/HasPermissions.php` (has
  canonical methods plus `givePermissionTo`, `revokePermissionTo`,
  `hasPermissionTo`, `getPermissionNames` aliases).
- **Observation:** the minimum set is shipped, but the spec
  explicitly defers the full set until the Spatie migration guide
  is written — which has not yet happened (no migration guide
  lives in `docs/`). The full Spatie surface includes methods not
  yet aliased: `hasAnyRole`, `hasAllRoles`, `hasAnyPermission`,
  `hasAllPermissions`, `hasDirectPermission`,
  `getDirectPermissions`, `getAllPermissions`, `getRoleNames`,
  `permissionsViaRoles`. A Spatie consumer copy-pasting controller
  code will hit missing methods at runtime.
- **Impact:** the §12.5 compatibility claim ("Supports Spatie's
  `laravel-permission` migration idiom … so a Spatie consumer can
  switch packages without rewriting every controller") is only
  partially true under the current alias set. This is an
  unresolved spec commitment.
- **Options:** (a) ship the full Spatie read-side surface
  (`hasAnyRole`, `hasAllRoles`, `hasAnyPermission`,
  `hasAllPermissions`, `hasDirectPermission`,
  `getDirectPermissions`, `getAllPermissions`, `getRoleNames`,
  `permissionsViaRoles`) as thin wrappers over the existing
  canonical methods — mostly one-liners; (b) draft the Spatie
  migration guide first, enumerate every controller-layer idiom
  it recommends, and alias exactly that set; (c) narrow the
  §12.5 claim to "assignment-side idioms" and document the
  read-side methods consumers must rewrite. Option (a) delivers
  the spec commitment in full; option (b) is cleaner but
  sequence-dependent on the migration guide.

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

### 54. Events lack a SemVer stability guarantee

- **Files:** `src/Events/*.php` (eight event classes — public
  properties treated as payload contract).
- **Observation:** §12.6 locks SemVer on "public contracts in
  `Contracts/` and public trait method signatures" but does not
  name events. The §12.4 observability guarantee presupposes
  consumers subscribe to these events, which means the payloads
  are de facto public contract — but there is no documented
  commitment about when their shape can change. Adding a
  property, renaming one, changing a type, or changing the set of
  dispatched events could silently break every audit-log
  subscriber without a major-version bump.
- **Impact:** the `laravel-audit-log` sibling (and any consumer
  wiring its own event listeners) cannot pin a version confidently.
  Spec §12.4 is aspirational without a versioning commitment.
- **Options:** (a) amend §12.6 and the README to explicitly
  extend the SemVer commitment to dispatched events — payload
  property shape, property types, and the set of events emitted
  in each transition. Adding a new event or a new property on an
  existing event remains non-breaking; renaming, retyping, or
  removing is major-bumped; (b) additionally mark each event
  class `@api` in docblocks so static-analysis consumers can
  detect breakage. Do both.

### 67. `EvaluatorThroughputTest` budget flakes under parallel contention

- **Files:** `tests/Performance/EvaluatorThroughputTest.php`
  (0.5s wall-clock budget on a 100-statement evaluation).
- **Observation:** serial runs clear the budget with wide margin
  (~0.14s on the reference machine). Under ParaTest's default
  16-way parallel execution the same test regularly exceeds the
  budget — observed readings of 0.52s and 1.73s on consecutive
  `composer test` invocations while other processes saturate the
  CPU. The evaluator itself is unchanged; the variance is CPU
  contention between parallel processes competing for a single
  thread budget.
- **Impact:** `composer test` is unreliable for the performance
  tier — a green-on-serial / red-on-parallel outcome trains
  developers to ignore the tier's signals. CI reproducibility is
  at risk whenever the runner is shared or noisy.
- **Options:** (a) exclude the Performance suite from parallel
  execution in `phpunit.xml.dist` / `paratest` config, running
  it serially in CI (`composer test:performance` already runs
  serially via phpunit; the problem is
  `composer test` which uses ParaTest and pulls Performance in);
  (b) convert the wall-clock budget into a query-count /
  operation-count budget that is insensitive to CPU contention —
  asserts the evaluator performs at most N ops for N statements,
  not that the wall-clock is under X seconds; (c) widen the
  budget to absorb parallel contention (masks real regressions,
  weakens the signal). Option (b) is the most rigorous;
  option (a) is the fastest fix. Both acceptable.

### 68. Role-pivot mutations leave persistent cache entries stale until TTL

- **Files:** `src/Cache/ResolutionCache.php` (`flush()` documents
  the behaviour explicitly);
  `src/Listeners/InvalidateResolutionCache.php` (`handleRoleMutation`
  calls `flush()` on `RolePermissionGranted` / `Revoked`).
- **Observation:** when a role gains or loses a permission, every
  identity carrying the role has a stale cached
  `getPermissions()` list. The in-memory tier is cleared via
  `flush()`, but the persistent tier is **not** — flushing the
  configured cache store would wipe unrelated entries. With no
  reverse index from role to the identities carrying it, the
  listener cannot target only the affected principals, so the
  stale entries sit in the store until the configured TTL expires
  or until a principal-scoped event (assign / revoke / attach)
  fires for each affected identity.
- **Impact:** a production deployment with cross-request caching
  enabled and role-pivot mutations flowing through the admin UI
  will serve stale permission lists to affected users until TTL.
  For a token-lifetime TTL (e.g. 30 minutes) this is tolerable;
  for forever-caching (`ttl = 0`) the stale window is unbounded
  unless the consumer manually bumps each identity.
- **Options:** (a) use cache tags — Redis and Memcached support
  them, Laravel's `Cache::tags(['authorization', "role:{$id}"])`
  gives us a reverse index. Invalidate by role tag on pivot
  mutation. Only works for tag-capable stores; fall back to the
  current flush-in-memory-only behaviour otherwise; (b) walk
  the `authorizable_roles` pivot in the listener and forget each
  principal individually. Expensive for roles held by many
  identities; acceptable when pivot mutations are rare admin
  operations; (c) record a "generation number" for each role and
  bump it on pivot mutation; compose the cache key from
  `(principal, role-generation)` so stale entries are naturally
  superseded. Elegant but adds a second storage layer for the
  generation map. Option (a) plus option (b) fallback is the
  honest enterprise path.

### 69. Model traits reach `app()` service locator for cache access

- **Files:** `src/Traits/HasRoles.php:124–126,166–169`;
  `src/Traits/HasPermissions.php:126–127,168–172`;
  `src/Traits/HasPolicies.php:112–114` (and analogous
  `getPolicies` path where applicable).
- **Observation:** every cache touchpoint from the model traits
  follows the pattern:

  ```php
  if (app()->bound(ResolutionCache::class)) {
      app(ResolutionCache::class)->forget($this);
  }
  ```

  The `app()` global helper is a service-locator call inside a
  trait that mixes into Eloquent models. It couples the model
  layer to the container, makes the trait impossible to test in
  isolation without booting a Laravel app, and hides the cache as
  a concrete dependency of every `sync*` / `get*` method. The
  guard (`bound(...)`) papers over the coupling — the cache isn't
  declared as a dependency, it's opportunistically looked up.
- **Impact:** classic Service Locator anti-pattern at the trait
  layer. Unit-testing `syncRoles` now requires either a full
  container boot or a mock via `App::instance()`. Also
  architecturally inconsistent with the event-based listener
  (`InvalidateResolutionCache`) that _is_ cleanly
  dependency-injected — the same job is done twice, once via DI
  and once via service locator, only because the `sync*` methods
  bypass the single-event dispatch path.
- **Impact on #56 (sync-event gap):** this commit resolved the
  cache-invalidation side of the bypass by reaching for `app()`
  directly, but the audit-observability side remains open —
  consumers subscribing to `RoleAssigned` / `PermissionGranted`
  / `PolicyAttached` still get nothing from bulk `sync*` calls.
  Both gaps should be closed together.
- **Options:** (a) dispatch bulk-diff events from each `sync*`
  method (`RolesSynced`, `PermissionsSynced`, `PoliciesSynced`)
  carrying `attached` / `detached` ID arrays from Eloquent's
  `sync()` return; extend `InvalidateResolutionCache` to handle
  those events. Fixes #56 and removes the service-locator call
  in one move; (b) dispatch the existing single-item events
  (`RoleAssigned` / `RoleRevoked` etc.) from `sync*` for each
  attached / detached pivot row. Heavier but replays through
  every existing subscriber without new event classes.
  Option (b) is the least-new-surface fix and dovetails with
  #56's option (a).

### 77. Resolution cache returns stale role / permission / policy sets across temporal-grant expiry

- **Files:** `src/Cache/ResolutionCache.php` (memoises
  per-principal lookups); `src/Traits/HasRoles.php`,
  `src/Traits/HasPermissions.php`, `src/Traits/HasPolicies.php`
  (relations filter `expires_at` at read time).
- **Observation:** temporal grants (#30, now shipped) rely on a
  DB-level filter — `expires_at IS NULL OR expires_at > now()`
  evaluated on every relation read. The resolution cache sits
  above that filter and memoises the result per principal, so a
  list populated at 12:00 still reports an entry that expired at
  12:30 until an invalidation event fires on that principal
  (assign / revoke / attach / detach on the identity, or a role
  pivot change). The cache is correct on every write path, but
  wall-clock advance alone does not invalidate it.
- **Impact:** deployments that combine the persistent cache tier
  with temporal grants can report stale membership for up to the
  cache TTL past the expiry. For short-lived break-glass grants
  (e.g. "admin for one hour") a 30-minute TTL means up to 30
  minutes of drift between "actually expired" and "observably
  expired."
- **Options:** (a) compute an entry TTL bounded by the nearest
  `expires_at` across the stored rows — requires one extra read
  per populate path and a min() over the pivot. Cleanest, works
  across both tiers. (b) Ship a scheduled
  `authorization:prune-expired-grants` command that bumps the
  cache per affected principal when a row crosses its expiry —
  requires a generation / sweeper pattern. (c) Document the
  caveat (already done in `ResolutionCache`'s docblock), advise
  consumers using temporal grants to either disable the
  persistent tier or pair it with a short TTL, and close the
  gap in a follow-on release once option (a) is scoped.
  Option (a) is the honest enterprise path; option (c) is the
  current behaviour.

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

### 86. `BladeHelpers::currentPrincipal()` retains the `app()` service-locator path — middleware uses the facade

- **File:** `src/Support/BladeHelpers.php:38–45`.
- **Observation:** the consolidation commit updated
  `BladeHelpers` to route through
  `AuthorizationManager::currentPrincipal()` (correct), but the
  helper still resolves the manager via
  `app()->bound(AuthorizationManager::class)` with a
  `\function_exists('app')` guard in front. The middleware, by
  contrast, uses `Authorization::currentPrincipal()` — the
  facade that this commit explicitly exposed for exactly this
  purpose. Two sibling surfaces, two different entry points to
  the same method; only one of them honours the commit's
  "single accessor" promise.
- **Impact:** partial consolidation. The consolidation's value
  proposition — "every surface funnels through one accessor" —
  is weakened when one of the three surfaces (Blade)
  hand-rolls its own lookup. A future change to the facade
  (caching, logging, instrumentation) reaches the middleware
  but not the Blade layer. Also the `function_exists('app')`
  guard is defensive to the point of unreachable code: the
  package cannot load without Laravel, so the helper cannot
  exist.
- **Options:** (a) replace the body with a single
  `Authorization::currentPrincipal()` call, matching the
  middleware's path. Facades throw a clear
  `RuntimeException` when the root is unresolved — the
  Blade helper should let that surface naturally rather than
  silently returning null; (b) wrap in a `try / catch` for
  the facade-not-bootstrapped case but drop the
  `function_exists` guard — one layer of defence, not two;
  (c) keep the direct `app()` path and update the middleware
  to match — consistency via the ugly path. Option (a) is
  the enterprise answer; option (b) preserves test-harness
  friendliness at the cost of one line.

### 87. `AbstractAuthorizationMiddleware::matches()` type-erases the contract — concrete subclasses need a `@var` re-assertion

- **File:** `src/Http/Middleware/AbstractAuthorizationMiddleware.php:90`
  (abstract signature); `src/Http/Middleware/RequireRole.php:38–42`
  and `RequirePermission.php` (concrete `matches` methods).
- **Observation:** the abstract method signature is
  `matches(object $principal, string $needle): bool`. After
  `handle()`'s `instanceof $contract` guard, `$principal` is
  known to implement the contract returned by
  `requiredContract()`, but the type information is erased
  when the variable is handed to the subclass. Each concrete
  leaf then re-asserts the type with a PHPStan `@var`
  docblock:

  ```php
  protected function matches(object $principal, string $needle): bool
  {
      /** @var \SineMacula\Laravel\Authorization\Contracts\SupportsRoles $principal */
      return $principal->hasRole($needle);
  }
  ```

  Works, but the `@var` is load-bearing — remove it and
  PHPStan flags `hasRole` as "method not found on `object`".
  The safety of the `handle()`-level contract check is
  invisible to static analysis at the subclass call site.
- **Impact:** weak type propagation across the template-method
  boundary. Any future maintainer could delete the `@var`
  thinking it's a stale docblock and silently disable PHPStan
  coverage at the hot path. Also encourages copy-pasting the
  `@var` annotation for every new middleware that extends the
  abstract.
- **Options:** (a) add a PHPStan `@template T` annotation
  on the abstract class and parameterise `matches(T $principal)`
  — generics stay a PHPStan concern, runtime unchanged;
  concrete subclasses declare `@extends AbstractAuthorizationMiddleware<SupportsRoles>`
  and type propagation works without per-method `@var`; (b)
  accept the pattern and document in the abstract docblock
  that subclasses must re-assert the contract type on
  `$principal` — minimal churn, explicit; (c) narrow
  `matches` to accept the specific contract via late static
  binding on each subclass — requires PHP's
  contravariant-parameter rules to allow narrowing, which
  they don't, so this option does not work in practice. Option
  (a) is the right answer for a PHPStan-level-8 codebase.

### 90. `AuthorizableGrantPivot` is shared across three distinct pivot tables — can't express future per-table divergence

- **Files:** `src/Models/AuthorizableGrantPivot.php` (shared
  pivot class); `src/Traits/HasRoles.php`,
  `src/Traits/HasPermissions.php`, `src/Traits/HasPolicies.php`
  (three `->using(AuthorizableGrantPivot::class)` call sites).
- **Observation:** the three authorizable-grant pivots
  (`authorizable_roles`, `authorizable_permissions`,
  `authorizable_policies`) currently share an identical
  shape: morph keys + `expires_at`. One pivot class casts
  `expires_at` for all three — efficient today. But the
  in-flight work for #22 (polymorphic tenant scoping) and
  #30's sibling `granted_by` column noted as a future
  extension both land per-row metadata that may not apply
  uniformly across the three tables. A future
  `authorizable_policies.approved_by` column — for a policy
  attachment approval workflow — would not apply to roles or
  permissions, but the shared pivot class would either cast it
  for all three or have to split back out.
- **Impact:** design-time tension for future per-table
  features. Today the pivot is simple and correct. When the
  first per-table divergence lands, the refactor path is
  either "split `AuthorizableGrantPivot` into three subclasses"
  (back to where we were) or "let the shared class grow a
  field set that is partially ignored on two of the three
  tables" (muddy).
- **Options:** (a) keep the shared pivot as-is; treat the
  first per-table divergence as the trigger to split
  (`AuthorizableRolePivot`, `AuthorizablePermissionPivot`,
  `AuthorizablePolicyPivot` each extending
  `AuthorizableGrantPivot` for shared `expires_at` casting).
  YAGNI answer — no churn today; (b) split now along the three
  tables even though they currently share shape — each
  `Has*` trait already points at a distinct pivot slot, so
  the split is mechanical and future-proofs per-table fields;
  (c) accept the shared pivot and document that per-table
  metadata must go on `authorizable` or on the related model
  rather than the pivot — forces a design constraint but
  keeps the pivot surface tight. Option (a) is the honest
  iterative path and is already the committed state.

### 91. System-policy protection does not cover `document` mutations — the authorization-carrying field is unguarded

- **Files:** `src/Models/Policy.php:175–179`
  (`updating` hook calls `wasSystemPolicyRenamed` only);
  `src/Models/Policy.php:293–304`
  (`wasSystemPolicyRenamed` body + docblock).
- **Observation:** the `updating` hook on `Policy` blocks
  only rename mutations on `is_system = true` rows. The
  method's docblock states explicitly "description and
  document bumps pass unconditionally." The `document`
  column is the JSON payload that carries every statement,
  effect, action, resource, and condition the evaluator walks
  — it is the authorization-defining field on the Policy
  table. A caller with raw Eloquent access can freely
  overwrite a platform-shipped deny policy's `document` while
  the row stays delete-protected and rename-protected. The
  protection guards the wrapper and leaves the payload
  uncovered. Issue #76 option (a) flagged this exact case:
  "for `Policy`, document mutation as well — policy
  `document` changes are the authorization-impacting edit,
  analogous to role rename."
- **Impact:** the most security-relevant field on the Policy
  table is not covered by the system-protection invariant.
  A compliance-audited deployment that ships a platform deny
  policy still allows that policy's document body to be
  rewritten in place — same security hole as deleting the
  policy, only quieter because the row still exists.
- **Options:** (a) extend `wasSystemPolicyRenamed` into
  `wasSystemPolicyAuthorizationDirty` (or split into a
  second hook `wasSystemPolicyDocumentDirty`) that also
  returns true when `'document'` is dirty; the `updating`
  hook calls both and raises `SystemPolicyProtectedException`
  on either; (b) document the gap and treat document
  mutation as an explicit exception-to-the-rule — honest but
  leaves the security invariant half-enforced; (c) promote
  Policy to a three-operation protection matrix
  (`delete` / `rename` / `document-rewrite`) via an enum on
  the exception, giving callers structured reasons. Option
  (a) is the minimum change that closes #76's stated scope.

### 92. `is_system` protection pattern is triplicated across Role, Permission, Policy

- **Files:** `src/Models/Role.php:73–105,305–425`;
  `src/Models/Permission.php:71–107,185–286`;
  `src/Models/Policy.php:74–107,165–310` —
  plus three near-identical exception classes
  (`SystemRoleProtectedException`,
  `SystemPermissionProtectedException`,
  `SystemPolicyProtectedException`).
- **Observation:** the commit extends #76 by duplicating the
  full pattern across all three primitive models. Three
  instances of `private bool $systemProtectionBypassed`;
  three `forceSystem()` methods with identical bodies; three
  `assertSystemProtectionAllows()` methods whose only
  variation is the exception class thrown and the
  `getOriginal('name', ...)` label; three `wasSystem*Renamed`
  helpers that differ only in the entity name in the method
  identifier. Issue #76 explicitly called this out —
  "(b) lift the protection logic into a shared trait
  (`ProtectsSystemFlaggedRows`) … avoids the three-way
  duplication that would otherwise appear alongside the
  `ValidatesAuthorizationName` trait." The commit picked
  option (a) and shipped the foreseen duplication.
- **Impact:** ~150 lines of duplicated infrastructure across
  three models. Any future change to the protection
  semantics — adding a second protected operation (see #91
  on Policy's `document`), switching to an enum for
  `$operation` (see #84's audit), logging protected-mutation
  attempts, wiring a consumer-supplied audit listener —
  lands three times and diverges silently if one site is
  missed. Also complicates PHPStan coverage, test coverage,
  and onboarding.
- **Options:** (a) extract
  `SineMacula\Laravel\Authorization\Traits\ProtectsSystemFlaggedRows`
  with the `$systemProtectionBypassed` property,
  `forceSystem()`, `assertSystemProtectionAllows()`, and the
  `saved`-hook bypass reset. Each model composes the trait
  and overrides a single
  `protectedDirtyAttributes(): array<string>` hook that
  returns the list of attributes whose dirty-state triggers
  the check (`['name']` for Role / Permission, `['name',
  'document']` for Policy — closes #91 in the same move).
  The per-model exception class stays; the trait raises it
  via an abstract `protectedOperationException(string $operation): Throwable`
  hook. Three leaf classes become ~30 lines each; (b) accept
  the duplication and defer the trait until the third
  follow-on change makes it unavoidable — drift-by-design;
  (c) collapse the three exception classes into a single
  `SystemFlaggedRowProtectedException` carrying the entity
  kind alongside the operation (ties into #84's enum
  audit). Option (a) is the right enterprise answer and
  composes cleanly with the Policy-document extension in
  #91.

### 93. `OrphanedRolePermissionException::$side` is stringly-typed — candidate enum per #84

- **File:** `src/Exceptions/OrphanedRolePermissionException.php:29–56`
  (constructor + `getSide()` accessor).
- **Observation:** the legal values for `$side` are the
  string literals `'role'` and `'permission'`. The
  constructor takes `string`; `getSide()` returns `string`;
  consumers comparing the exception payload do so with
  `$e->getSide() === 'role'`. No compile-time enforcement
  that only those two values are supplied; a typo at the
  throw site (`side: 'Role'` capitalised) passes silently
  and every caller's equality check against `'role'` fails.
  Parallel case to
  `SystemRoleProtectedException::$operation` flagged in
  #84's candidate surfaces.
- **Impact:** minor on day-one usage, but every
  stringly-typed enum-candidate field adds to the surface
  #84 has to sweep. Catching them at introduction is
  cheaper than fixing during the audit pass.
- **Options:** (a) introduce
  `RolePermissionOrphanSide` enum (`Role = 'role'`,
  `Permission = 'permission'`) and retype the constructor
  and accessor. Matches the `GateConflictMode` shape
  already in `src/Enums/`; (b) fold into #84's audit pass
  and leave as-is for now — consistent with the "audit
  sweep" framing of that issue. Option (a) closes the new
  surface as it lands; option (b) is the consistent
  iterative path. Either is fine provided the field is not
  left stringly-typed through v1.0.0.

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
