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

### 16. `AuthorizableIdentity` contract forces policy methods on pure-RBAC consumers

- **File:** `src/Contracts/AuthorizableIdentity.php`.
- **Observation:** the contract mandates `attachPolicy`, `detachPolicy`,
  `syncPolicies`, and `getPolicies`. A consumer who only wants
  roles + permissions (RBAC-only) must either `use HasPolicies` — which
  is inert but pulls in the morph pivot and event wiring — or stub all
  four methods by hand. The architecture already supports policy-free
  operation at the evaluator level (empty policy set falls through to
  RBAC in `AuthorizationManager::evaluateFor()`), but the contract does
  not reflect that the policy surface is optional.
- **Options:** split the contract into narrower sibling interfaces
  (e.g. `SupportsRoles`, `SupportsPermissions`, `SupportsPolicies`) and
  have `AuthorizableIdentity` extend whichever are mandatory, or document
  `HasPolicies` as non-optional even for RBAC-only use and accept the
  unused pivot table. First option preserves drop-in purity; second is
  a one-line doc fix.

### 17. Gate auto-wiring requires a populated `permission_enums` config

- **File:** `src/AuthorizationServiceProvider.php:144–163`.
- **Observation:** `registerGates()` iterates `authorization.permission_enums`
  and registers one Gate per enum case. The config ships empty, so a
  consumer who calls `Gate::allows('posts:edit', $user)` out of the box
  gets no match — the check returns false regardless of RBAC state. The
  facade API (`Authorization::for($user)->can('posts:edit')`) works as
  expected; it is only the Laravel `Gate` integration that is silent
  until an enum is defined and registered.
- **Impact:** the "drop-in RBAC" narrative in README / CLAUDE.md implies
  Gate integration is automatic. It is, but only after the consumer
  writes a `PermissionEnum` class and lists it in config. For a
  string-only RBAC consumer this is unexpected friction.
- **Options:** (a) document the enum requirement explicitly in README's
  quickstart, (b) add an opt-in config flag that registers one Gate per
  `Permission` row at boot (introduces a DB query on boot — weigh
  carefully), or (c) ship a lightweight "StringPermissionEnum"
  convenience that consumers can register without defining their own.

### 18. No shipped `AuthGuardPrincipalResolver` for standard Laravel Auth

- **Files:** `src/Resolvers/` (only `NullPrincipalResolver.php`
  present); `src/AuthorizationServiceProvider.php:64–70`
  (resolver binding).
- **Observation:** the default `PrincipalResolver` binding is
  `NullPrincipalResolver`, which always returns `null` and therefore
  always yields implicit deny. Any consumer using Laravel's auth guard
  must write a custom resolver (e.g. `return auth()->user();`) and bind
  it themselves — a four-line boilerplate that covers the majority case
  for this package.
- **Options:** ship an opt-in `AuthGuardPrincipalResolver` that wraps
  `Auth::guard($config['defaults.guard'])->user()`. Keep
  `NullPrincipalResolver` as the default (anonymous-safe by design) and
  document the opt-in as the recommended wiring when the application
  uses Laravel Auth. Non-breaking.

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

### 24. Gate dispatch has no way to route by the caller's guard

- **Files:** `src/AuthorizationServiceProvider.php:190–199`;
  `src/Traits/HasRoles.php:204–211`; `src/Traits/HasPermissions.php:236–244`.
- **Observation:** Laravel's `Gate` is global and guard-agnostic —
  when `$user->can('posts:edit')` fires, the Gate closure receives
  `$user` with no indication of which guard the user authenticated
  under. This package's closure then calls
  `Authorization::for($user)->can($permission)`, whose string-based
  permission lookup is hard-coded to
  `config('authorization.defaults.guard', 'web')`. For a multi-guard
  application, a user authenticated under `api` will have their
  permission check resolved against the `web`-guard permission row
  (or fail to find one entirely). This is the core reason full
  Laravel `->can()` compatibility with multi-guard support is
  architecturally hard.
- **Impact:** multi-guard deployments cannot trust the standard
  Laravel authorization surface (`->can()`, `Gate::allows`, `@can`,
  `can:` middleware) to return the correct answer. They are forced
  to call `Authorization::for($user)->can($permission)` directly,
  which defeats the Laravel-compat narrative on exactly the workloads
  that need guard scoping most.
- **Guard model (landed).** The nullable-`guard_name` sentinel has
  shipped (commits `cf0772b` + `0aa8cd2`). This narrows the problem
  but does not solve it: the lookup in
  `HasRoles::resolveRole()` / `HasPermissions::resolvePermission()`
  now falls back to null-guard rows when the configured default
  guard has no match, but the Gate closure still hardcodes
  `config('authorization.defaults.guard')`. A user authenticated
  under a non-default guard (e.g. `api` when default is `web`)
  therefore still misses their own guard-specific rows and is
  served only the `web` row or the null-guard row. The routing
  hook is still required; cross-refs to #21 remain valid because
  attachment-layer enforcement and Gate-layer routing are the two
  separate integrity checks the guard model needs to reach parity
  with Spatie.
- **Options:** (a) require `AuthorizableIdentity` implementers to expose a
  `getAuthorizationGuard(): string` method (Spatie's shim idiom);
  closure calls `$user->getAuthorizationGuard()` to select the lookup
  scope — leaks auth semantics onto the identity model but is
  explicit; (b) introduce a `GuardResolver` contract (mirrors
  `PrincipalResolver`) that the closure consults; (c) bind a stack
  of Gates at boot — one per configured guard — and teach the
  closure to pick the active guard via the container's current
  `Auth::guard()->name`. Option (c) is the cleanest for Laravel
  idioms but requires the container to know which guard
  authenticated the request, which is only true inside an HTTP
  request scope.

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

### 29. No system / built-in role protection flag

- **Files:** `database/migrations/2026_04_14_000001_create_roles_table.php`;
  `src/Models/Role.php`.
- **Observation:** the `roles` table has `name`, `guard_name`,
  `description`, timestamps only. There is no `is_system`,
  `is_protected`, or `is_deletable` column. A platform-shipped role
  (e.g. `super-admin`, `auditor`) can be renamed or deleted by any
  caller with raw Eloquent access, with no model-level guard.
- **Impact:** accidental deletion or rename of a foundational role
  cascades into authorization failures across the application.
  Enterprise deployments want a "this role is part of the platform,
  hands off" signal.
- **Options:** (a) add a boolean `is_system` column, default false;
  a Role model observer rejects delete / name-change when the flag
  is true unless a `forceSystem()` escape hatch is invoked;
  (b) introduce a typed `RoleKind` enum column (`system`, `managed`,
  `custom`) for finer-grained protection; (c) document an
  observer-only convention and ship no schema change.

### 30. No expiring or temporal role assignments

- **Files:** `database/migrations/2026_04_14_000005_create_authorizable_roles_table.php`
  (pivot has `role_id`, `authorizable_type`, `authorizable_id`
  only); `src/Traits/HasRoles.php` (no temporal awareness);
  similarly for `authorizable_permissions` and
  `authorizable_policies`.
- **Observation:** role / permission / policy grants are forever.
  There is no `expires_at`, `granted_at`, or `granted_by` column on
  any pivot. Break-glass access ("give me admin for one hour"),
  just-in-time elevation, and on-call rotations all require custom
  scheduling outside the package today.
- **Impact:** every enterprise IAM deployment eventually wants
  time-bounded grants. Without schema support, consumers build their
  own side table or hack an expiry into a policy condition — both
  of which defeat the point of the assignment model.
- **Options:** (a) add nullable `expires_at` to all three
  `authorizable_*` pivots; assignment read paths filter out expired
  rows with `whereNull('expires_at')->orWhere('expires_at', '>', now())`
  and a scheduled sweeper garbage-collects them; (b) additionally
  add `granted_at`, `granted_by` (polymorphic) for audit trail
  (ties to issue #43 CRUD event hooks and the future audit
  package). Option (b) is the enterprise-grade path.

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

### 33. No `role:` / `permission:` route middleware shipped

- **Files:** no `src/Http/Middleware/` directory exists.
- **Observation:** Laravel's built-in `can:` middleware works
  because the package registers Gates. But `->middleware('role:admin')`
  or `->middleware('permission:posts:edit|posts:delete')` requires
  middleware this package does not ship.
- **Impact:** route-level RBAC is a standard Laravel idiom.
  Consumers either drop down to `can:` (which requires every role
  to also be a Gate — extra config burden) or write their own
  middleware.
- **Options:** (a) ship `RequireRole` and `RequirePermission`
  middleware with support for OR-piped arguments
  (`role:admin|editor`) and AND-comma arguments, register aliases
  in the service provider. Matches Spatie's shape for easy
  migration.

### 34. No Blade directives (`@role`, `@permission`, etc.)

- **Files:** `src/AuthorizationServiceProvider.php` — no
  `Blade::directive(...)` registrations.
- **Observation:** only `@can` (Laravel native) works. Spatie ships
  `@role`, `@hasrole`, `@hasanyrole`, `@hasallroles`, `@permission`,
  `@unlessrole`. None present here.
- **Impact:** every view that needs role-aware rendering falls back
  to `@if($user->hasRole(...))`, which is verbose and misses the
  Laravel idiom.
- **Options:** (a) register a parallel set of directives matching
  Spatie's shape; (b) register a smaller canonical set
  (`@role`, `@permission`, `@anyrole`, `@allroles`) and document
  the rest as `@if` patterns. Ship at least `@role` and
  `@permission`.

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

### 46. No CI check enforcing zero `sinemacula/laravel-*` runtime dependency

- **Spec reference:** §12.5 — _"Zero runtime dependency on any
  `sinemacula/laravel-*` package (enforced by CI check on
  `composer.json`)."_
- **Files:** `.github/workflows/tests.yml`,
  `.github/workflows/quality-gates.yml` — no job, step, or script
  inspects `composer.json`'s `require` block for sibling package
  entries.
- **Observation:** the package's standalone-first guarantee rests
  on this isolation, but nothing in CI fails the build if someone
  accidentally adds `sinemacula/laravel-authentication` (or any
  sibling) to runtime dependencies. Dev dependencies are fine;
  runtime dependencies are not.
- **Impact:** a silent future regression. One careless
  `composer require` and the "drop-in, standalone" narrative is
  broken without anyone noticing until a downstream consumer
  tries to install the package in isolation.
- **Options:** (a) add a small CI step that runs
  `jq '.require | keys[]' composer.json` (or equivalent
  `composer show --direct --format=json`), filters for entries
  matching `sinemacula/laravel-*`, and fails the build if any
  match; (b) write a dedicated PHP test under
  `tests/Unit/PackageIsolationTest.php` that reads `composer.json`
  and asserts the same invariant — runs on every test execution,
  not just CI. Option (b) catches it locally too.

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

### 55. Duplicate `resolvePermission()` logic on `Role` and `HasPermissions`

- **Files:** `src/Models/Role.php:252–…` (`resolvePermission`);
  `src/Traits/HasPermissions.php:228–…` (`resolvePermission`).
- **Observation:** `Role::resolvePermission()` is a verbatim copy
  of `HasPermissions::resolvePermission()`. Same config reads,
  same closure-scoped guard/null disjunction, same
  `orderByRaw('guard_name IS NULL')`, same
  `UnknownPermissionException` throw. The only tell today is the
  inline comment "Mirrors `HasPermissions::resolvePermission()`"
  on the Role copy.
- **Impact:** drift risk. When guard-model rules evolve —
  wildcard sentinels, case sensitivity, rank tie-breakers — both
  copies must change together. The duplication introduces a silent
  path where role-side and identity-side lookups disagree, and the
  resulting authorization decisions diverge between Role catalogue
  mutations and identity hasPermission checks.
- **Options:** (a) promote the lookup to a static factory on the
  `Permission` model
  (`Permission::resolveByName(string $name, ?string $guard = null): self`),
  and have both Role and HasPermissions delegate. The model owns
  its own lookup semantics; (b) introduce a `PermissionResolver`
  service bound in the container and inject where needed —
  cleaner for testability but heavier. Option (a) is the
  low-ceremony fix.

### 56. `sync*` methods dispatch no events — audit trail has a bulk-operation blind spot

- **Files:** `src/Traits/HasRoles.php` (`syncRoles`);
  `src/Traits/HasPermissions.php:108–…` (`syncPermissions`);
  `src/Traits/HasPolicies.php:94–…` (`syncPolicies`);
  `src/Models/Role.php:136–…` (`syncPermissions`).
- **Observation:** every `sync*` method across the authorizable
  traits and the Role API calls Eloquent's `sync()` and returns
  — no `Event::dispatch(...)` calls at all. Single-item
  counterparts (`assignRole` / `revokeRole`,
  `givePermission` / `revokePermission`,
  `attachPolicy` / `detachPolicy`,
  `Role::givePermission` / `revokePermission`) all emit dedicated
  events. A bulk `syncRoles([...])` that adds two roles and
  removes one emits nothing.
- **Impact:** the future `laravel-audit-log` sibling cannot
  reconstruct state transitions from the event stream alone —
  anything the caller flushes via `sync*` is invisible.
  Contradicts the observability guarantee that every assignment
  transition is emittable.
- **Options:** (a) inside each `sync*`, diff the
  before-vs-after pivot IDs using the return of Eloquent's
  `sync()` (`['attached' => [...], 'detached' => [...],
  'updated' => [...]]`), then dispatch the corresponding
  single-item events for each attached / detached row — replays
  cleanly through existing subscribers; (b) introduce bulk
  variant events (`RolesSynced`, `PermissionsSynced`,
  `PoliciesSynced`, `RolePermissionsSynced`) carrying the full
  delta — expands the event surface but is more economical for
  bulk-focused consumers. Option (a) leaves the event catalogue
  as-is and closes the audit gap.

### 57. Asymmetric event-class naming between identity-level and role-level mutations

- **Files:** `src/Events/PermissionGranted.php`,
  `src/Events/PermissionRevoked.php`, `src/Events/RoleAssigned.php`,
  `src/Events/RoleRevoked.php`, `src/Events/PolicyAttached.php`,
  `src/Events/PolicyDetached.php` (identity-level, unprefixed);
  `src/Events/RolePermissionGranted.php`,
  `src/Events/RolePermissionRevoked.php` (role-level,
  `Role`-prefixed).
- **Observation:** every identity-level event is unprefixed
  (`PermissionGranted`, `RoleAssigned`, `PolicyAttached`); the
  role-level events introduced in commit `e3699c0` carry an
  explicit `Role` prefix. An audit consumer subscribing to
  `PermissionGranted` expecting "all permission grants" silently
  misses role-to-permission mutations. The naming convention
  carries hidden context — "unprefixed = identity-scoped" — that
  the event class names do not communicate.
- **Impact:** SemVer-stable event contracts (tracked in #54) need
  names that discoverable-without-docs. The current asymmetry is
  a subscription footgun for enterprise audit.
- **Options:** (a) rename every identity-level event with an
  `Identity` prefix for symmetry:
  `IdentityPermissionGranted` / `IdentityPermissionRevoked`,
  `IdentityRoleAssigned` / `IdentityRoleRevoked`,
  `IdentityPolicyAttached` / `IdentityPolicyDetached`. Role-level
  events keep their current names. Both contexts become explicit
  with no default; (b) accept the asymmetry and document the
  "unprefixed = identity-scoped" convention in a design note.
  Option (a) is the enterprise-grade default and matches the
  `AuthorizableIdentity` contract's naming shift.

### 58. `gate.on_conflict` is stringly-typed; should be a backed enum

- **Files:** `config/authorization.php:88–90` (default `'log'`);
  `src/AuthorizationServiceProvider.php:174–188`
  (`registerEnumGate` `match` on the raw string).
- **Observation:** the legal values for
  `authorization.gate.on_conflict` are `'log'`, `'throw'`,
  `'overwrite'`. They are compared against string literals inside
  a `match` expression, with `default` silently routing to the
  log path. A typo — `AUTHORIZATION_GATE_ON_CONFLICT=Log`
  (capitalised) — falls into `default` and logs when the
  consumer asked for `throw` or `overwrite`. No type hint, no
  discoverability from the config comment, no way for an IDE to
  flag an invalid value.
- **Impact:** silent misconfiguration with security adjacency. A
  consumer setting `throw` to catch collisions at boot who
  typos the value gets every collision silently logged instead
  of a failing boot — the opposite of their intent. Ties into
  #47's outstanding decision on the default.
- **Options:** (a) introduce
  `SineMacula\Laravel\Authorization\Enums\GateConflictMode` as a
  string-backed enum (`Log = 'log'`, `Throw = 'throw'`,
  `Overwrite = 'overwrite'`); coerce the config value to the
  enum in `boot()` via `GateConflictMode::tryFrom($value)` and
  raise a typed config-validation exception (see #43) when
  `tryFrom` returns null; `registerEnumGate` then matches on
  the enum. Parallels the existing `PolicyEffect` enum idiom
  used for `allow` / `deny`.

### 59. Test fixture class names retain pre-rename terminology

- **Files:** `tests/Feature/Stubs/StubAuthorizable.php`;
  `tests/Feature/Stubs/StubSecondAuthorizable.php`; the stubs'
  backing table `stub_authorizables` in `tests/TestCase.php`.
- **Observation:** issue #25 renamed the contract to
  `AuthorizableIdentity` and the trait to `HasAuthorization`.
  Both fixtures were updated internally (their `implements` and
  `use` clauses cite the new names) but the class names
  themselves — `StubAuthorizable`, `StubSecondAuthorizable` —
  and the backing table `stub_authorizables` retain the
  pre-rename term. A grep for `AuthorizableIdentity` test
  coverage silently skips the fixture layer.
- **Impact:** minor readability and discoverability friction in
  the test suite. Not a correctness bug, but three different
  spellings of the same concept (`AuthorizableIdentity`,
  `HasAuthorization`, `StubAuthorizable`) coexist in a small
  surface area.
- **Options:** (a) rename to `StubIdentity` /
  `StubSecondIdentity` with backing table `stub_identities`
  (concise, symmetric with `AuthorizableIdentity`); (b) rename
  to `StubAuthorizableIdentity` / `StubSecondAuthorizableIdentity`
  (verbose but mirrors the contract exactly); (c) keep the
  current names and add a one-line class comment citing the
  rationale. Option (a) is the minimal-friction path and matches
  the shortened `*Identity` shape the contract uses.

### 60. `RolePermission` pivot re-queries both parents on every save — 2 extra DB round-trips per attach

- **Files:** `src/Models/RolePermission.php:54–94`
  (`ensureGuardParity`); called from the `saving` hook at line 38.
- **Observation:** on every pivot save the hook issues two fresh
  `find()` queries — one for the role, one for the permission —
  to read their `guard_name` columns. A typed
  `$role->givePermission($permission)` call already holds both
  Eloquent instances with `guard_name` loaded in memory, but the
  pivot discards that context and goes back to the database
  anyway. `$role->syncPermissions([... 50 permissions ...])` at
  typical scale therefore produces **~100 extra point-lookups**
  in addition to the sync itself.
- **Impact:** real performance cliff on bulk role
  configuration. Enterprise consumers seeding or re-syncing large
  role catalogues (platform-admin tooling, multi-tenant role
  templates) will feel it immediately. Also multiplies the
  cost of every Artisan seeder / test fixture creation path.
- **Options:** (a) short-circuit the check when the pivot is
  saved through a `BelongsToMany` relation path — Laravel passes
  the parent model to the pivot via `setPivotKeys()` /
  `$pivot->pivotParent`, so the role-side `guard_name` is
  reachable without a query; fetch only the permission side (one
  query) and only when its `guard_name` isn't already loaded in
  the current request via `Permission::find()` cache; (b) move
  the invariant to a DB-level trigger or a composite FK that
  includes `guard_name` on the pivot (heaviest, mirrors the
  option (c) of the now-resolved #21 discussion); (c) require
  the caller to have both models in hand and hydrate the pivot's
  `guard_name` attributes explicitly before save — the pivot
  validates against its own attributes only, zero extra queries.
  Option (a) is the minimum-change performance fix; (c) is the
  cleanest but is invasive.

### 61. `RolePermission` pivot silently passes when either parent row is missing

- **File:** `src/Models/RolePermission.php:75–77`.
- **Observation:** `ensureGuardParity()` bails out (`return;`)
  when either `$role` or `$permission` is null — i.e. when the
  `find()` call didn't resolve the FK'd row. The FK constraint
  on the pivot table catches the missing-parent case at DB layer,
  so the save ultimately fails, but the validator itself
  classifies a missing-parent row as "no guard mismatch" rather
  than "unknown parent." The two failure modes should not surface
  the same way to the caller.
- **Impact:** if a consumer ever disables FK enforcement
  (SQLite default, some CI matrices, testcontainers with
  `foreign_key_checks = OFF`), a pivot row pointing at a
  non-existent role or permission saves silently. Also masks the
  root cause in error output — the raw DB error will reference
  the FK column names, not the guard semantics, so the caller
  debugging a seeder sees a foreign-key error when the real issue
  might be a stale cache of IDs.
- **Options:** (a) raise a typed
  `UnknownRoleException` / `UnknownPermissionException` when the
  corresponding `find()` returns null, reusing the existing
  exception hierarchy; (b) accept the silent-pass behaviour and
  document in the class docblock that the pivot assumes FK
  integrity is enforced at the DB layer.

### 62. `RolePermission` hardcodes column names `role_id` and `permission_id`

- **File:** `src/Models/RolePermission.php:57,59`.
- **Observation:** the pivot reads its FK attributes via
  `$this->getAttribute('role_id')` and
  `$this->getAttribute('permission_id')` — literal strings.
  `Role::permissions()` at `src/Models/Role.php:75–82` passes
  `foreignPivotKey: 'role_id'` and
  `relatedPivotKey: 'permission_id'` explicitly. If a consumer
  (or a future refactor) overrides those pivot key names, the
  pivot's guard-parity check silently breaks — the `getAttribute`
  calls return null, the early-return at line 61 fires, and the
  invariant is no longer enforced.
- **Impact:** fragile coupling between the pivot model and the
  relation definition. Any future move toward configurable pivot
  column names — the rest of the package reads table names from
  `authorization.tables.*` but hardcodes pivot column names —
  silently disables this invariant without any test catching it.
- **Options:** (a) read the column names from the relation
  itself via `$this->pivotParent?->getRelation('permissions')`
  or have `Role::permissions()` register the names on the pivot
  model; (b) promote the two column names to
  `config('authorization.pivots.role_permissions.role_column', 'role_id')`
  (etc.) and read through config, mirroring the existing
  `authorization.tables.*` pattern; (c) accept the coupling and
  add a comment on the relation and the pivot documenting that
  the column names are load-bearing.

### 63. No direct unit test on the `RolePermission` pivot — coverage goes entirely through Role API

- **Files:** `tests/Feature/RoleGuardParityTest.php` (end-to-end
  scenarios); no corresponding unit test under `tests/Unit/Models/`.
- **Observation:** every test scenario exercises the pivot
  through `Role::givePermission()`, `permissions()->attach()`,
  or `permissions()->sync()`. The pivot's `ensureGuardParity()`
  logic is never unit-tested with the pivot attributes set
  directly — if the relation wiring changes and stops routing
  through the pivot, the feature tests still pass against the
  (silently disabled) invariant.
- **Impact:** coverage is tight at the integration layer but
  loose at the model layer. A future refactor to Role's
  `permissions()` relation could drop the `->using(...)` call
  and every guard-parity feature test would still pass because
  it bypasses the pivot entirely. The unit test on the pivot is
  the safety net.
- **Options:** (a) add `tests/Unit/Models/RolePermissionTest.php`
  that instantiates `RolePermission` with explicit `role_id` /
  `permission_id` attributes and calls `save()` directly,
  pinning each branch of `ensureGuardParity()` (same guards,
  null-on-role, null-on-permission, both-null, mismatched
  guards, missing parent row). Fast, no feature-test overhead.

### 64. `PolicyRepository` contract is misnamed — should mirror `PrincipalResolver`

- **Files:** `src/Contracts/PolicyRepository.php`;
  `src/Repositories/DefaultPolicyRepository.php`;
  `src/AuthorizationServiceProvider.php:100–105`;
  `src/AuthorizationManager.php:274–281`.
- **Observation:** the contract exposes a single read method
  `policiesFor(object $principal): array` — no create, update,
  delete, or persistence-layer query builder. In DDD and Laravel
  convention "Repository" implies a CRUD abstraction over a
  persistence backend (e.g. `UserRepository` with `find`, `save`,
  `delete`). This contract is a **resolution strategy** that
  answers "what policies apply right now for this principal?"
  and composes an optional external `PolicyStore` with the
  principal's own attached policies.
- **Asymmetry with `PrincipalResolver`:** the package already has
  `PrincipalResolver::resolve(): ?object` answering "what
  principal is in scope?". `PolicyRepository::policiesFor()`
  answers "what policies are in scope?". Same shape, same job,
  different suffix. A developer looking at the service-provider
  bindings sees `PrincipalResolver` and `PolicyRepository` and has
  to infer that they fill analogous roles — the names don't tell
  that story.
- **Impact:** cognitive tax on contract-surface discoverability.
  Consumers implementing a tenant-scoped policy seam expect to
  find a `PolicyResolver` alongside `PrincipalResolver`; today
  they find `PolicyRepository` and an old spec reference.
- **Options:** (a) rename the contract to `PolicyResolver` and
  its default implementation to `DefaultPolicyResolver`; move
  from `src/Repositories/` to `src/Resolvers/` to sit beside
  `NullPrincipalResolver`. Matches the existing idiom exactly;
  (b) keep `PolicyRepository` and document the non-standard
  semantic in a design note; (c) rename to `PolicyAggregator`
  / `PolicyGatherer` to describe the "union multiple sources"
  behaviour more precisely than either "Repository" or
  "Resolver". Option (a) is the symmetric answer and collapses
  the two mental models consumers need to carry.

### 65. `DecisionJournal` is a misnomer and its API leaks collection semantics onto single-slot storage

- **Files:** `src/DecisionJournal.php`;
  `src/AuthorizationManager.php:114,138,156–188` (call sites);
  `src/Facades/Authorization.php:22–23` (facade methods).
- **Observation:** "Journal" connotes a sequential, append-only
  record (transaction journal, audit journal, changelog). The
  class holds exactly **one** `EvaluationResult` at a time —
  every `record()` overwrites the previous value with no history
  retained. The method verbs compound the confusion:
    - `record()` — append-flavoured verb, suggests adding
    - `last()` — collection-flavoured, suggests "last of many"
    - `forget()` — single-value mutation verb
  Three different metaphors for a single-slot container. A
  reader's mental model on first encounter with
  `DecisionJournal::record(...)` is "this appends to a log" —
  which the implementation does not do.
- **Impact:** naming-driven incorrect mental models. A consumer
  expecting to read a history of decisions from the "journal"
  will discover the single-slot semantics only by reading the
  code. Also blocks a future actual journal — if we later want
  to record the last N decisions (for debugging, slow-query-style
  traces, or admin introspection), the name is already taken by
  the wrong thing.
- **Options:** (a) rename the class to `LastDecisionStore` (or
  `CurrentDecision` / `DecisionSlot`) and update the API to
  match the slot semantics: `set()` / `get()` / `clear()`.
  Facade becomes `Authorization::lastDecision()` (getter
  unchanged) and `Authorization::clearLastDecision()` (matches
  the getter's tense). Test `PolicyRepositoryAndJournalTest`
  renames too; (b) keep `DecisionJournal` but clarify the
  docblock that it is a single-slot holder and the verbs are
  Laravel-idiomatic (`forget` matches Cache / Session). Less
  churn, more reader-surprise; (c) upgrade the class to an
  actual journal — record the last N decisions with a ring
  buffer — and keep the name accurate. Useful for introspection
  / debugging if #42's expectations are met. Option (a) is the
  minimum-surprise fix.

### 66. `DecisionJournal` cross-request leakage in Octane / RoadRunner has no shipped auto-reset hook

- **Files:** `src/DecisionJournal.php:58–67` (docblock +
  `forget()`); `src/AuthorizationManager.php:185–188`
  (`forgetLastDecision()`); no shipped listener / middleware
  that calls either.
- **Observation:** the journal is bound as a container singleton
  at `src/AuthorizationServiceProvider.php:115`. Under Octane /
  RoadRunner / Swoole / FrankenPHP (all supported by modern
  Laravel) the container — and therefore the singleton — is
  **preserved across requests**. A decision recorded on request
  A stays readable via `Authorization::lastDecision()` on
  request B unless the consumer explicitly calls
  `forgetLastDecision()` between requests. The class docblock
  acknowledges this ("Long-running workers call this between
  requests") but no shipped code does it.
- **Impact:** a production Octane deployment using the journal
  will see cross-request decision leakage. The "why was this
  denied?" surface that the journal exists to provide will
  silently return the **previous request's** answer unless the
  consumer wires a reset hook. Not a correctness bug in the
  engine — a correctness bug in the observability surface.
- **Options:** (a) ship an Octane listener on
  `Laravel\Octane\Events\RequestReceived` (or the analogous
  RoadRunner / Swoole hooks) that calls
  `Authorization::forgetLastDecision()`. Bind only when the
  Octane package is installed (class_exists guard) to keep the
  package's zero-runtime-deps contract; (b) register a
  `TerminatingMiddleware` that calls the reset on HTTP response
  termination — works for Octane and standard FPM alike; (c)
  re-scope the journal to a per-request-scope binding rather
  than a singleton, so Octane's `flush()` clears it naturally.
  Option (c) is the cleanest architecturally but changes the
  clone-inheritance semantics the journal currently relies on.
  Option (b) is the most portable.

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
  (`InvalidateResolutionCache`) that *is* cleanly
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

### 70. Non-Model principals silently lose the persistent-cache tier

- **File:** `src/Cache/ResolutionCache.php:220–230` (`key()`).
- **Observation:** when the principal is not an Eloquent `Model`,
  the cache key falls back to `spl_object_hash($principal)`.
  That hash is stable only within a single request and — because
  PHP can recycle hashes when the originating object is garbage
  collected — not even reliably unique within a single request.
  The persistent-cache tier is therefore useless for non-Model
  principals: every request produces a new hash, every `get()`
  misses, every `put()` writes a fresh entry that no subsequent
  request will read. Worst case, a recycled hash collides with a
  different principal in the in-memory tier and serves the wrong
  cached payload.
- **Impact:** the cache narrative in the README / config block
  implies cross-request benefit for all principals. Consumers
  using custom principal shapes (value objects representing a
  service account, a non-Eloquent identity class) get only the
  in-memory tier and a silently-filling persistent cache that
  never hits. Silent under-performance with no log to flag it.
- **Options:** (a) skip the persistent tier entirely for
  non-Model principals — early-return from both `get()` and
  `put()` paths when the principal has no stable identifier —
  and document the limitation in the class / config block;
  (b) introduce a `CacheKey` contract
  (`cacheKeyForAuthorization(): string`) that any principal can
  implement to provide a stable, request-independent key
  (UUID-like); Model implements it via `getMorphClass()` +
  `getKey()`, custom principals implement it themselves; (c)
  require every principal to be an Eloquent Model — blunt, also
  contradicts the spec's "plain `object` to the engine"
  compatibility contract (§4.3 item 2). Option (b) matches the
  package's "contract for every decoupling" idiom.

### 71. Corrupt persistent-cache entry throws instead of falling through to the resolver

- **File:** `src/Cache/ResolutionCache.php:86–94`
  (`rememberPolicies` store path); also `Policy::fromArray`
  invariants.
- **Observation:** `rememberPolicies()` trusts the persistent
  cache to return a valid serialised policy list. When the store
  returns `array`, the code maps every element through
  `Policy::fromArray($document)` without a try/catch. A single
  corrupt document in the stored payload — version bump during
  deploy, a manual cache edit, a partial write, a corrupt
  serialiser — raises
  `InvalidPolicyDocumentException` from inside the map, which
  propagates all the way up through the manager and becomes a
  500-class error for every subsequent `can()` call against that
  principal until the cache entry is flushed. Compare to
  `rememberStringList` at `:198` which is defensively
  `array_filter($raw, 'is_string')` — silently drops garbage.
  The two tiers use opposite failure policies.
- **Impact:** violates the package-wide "fail closed"
  invariant pinned in the design notes and the body of #12.
  A corrupt cache state shouldn't become a live-site outage —
  it should deny and log, letting the request proceed with the
  resolver's freshly-gathered output. Also inconsistent with the
  sibling `rememberStringList`, which fails soft.
- **Options:** (a) wrap the `array_map(... Policy::fromArray ...)`
  call in a try/catch on `InvalidPolicyDocumentException`; on
  catch, `$this->store?->forget($key)`, log the corruption
  through the `authorization` channel (already used for Gate
  conflicts), and fall through to `$resolver()` so the caller
  gets a fresh, valid policy list. Matches fail-closed +
  self-healing intent; (b) tighten `rememberStringList` to
  fail-fast so the two paths are symmetric and corrupt caches
  always surface loudly. Option (a) is the honest
  production-grade answer; option (b) is the symmetric-but-louder
  alternative and works less well in long-running workers that
  cannot tolerate a 500 on transient cache corruption.

### 72. `permission_enums` validator accepts any `PermissionEnum` implementer, not specifically an enum

- **File:** `src/Config/ConfigValidator.php:63–94`.
- **Observation:** the validator checks that every entry in
  `permission_enums` exists (via `class_exists || interface_exists
  || enum_exists`) and implements `PermissionEnum` (via
  `is_subclass_of`). It does **not** check that the entry is
  specifically an enum. A consumer who registers a plain class
  that implements `PermissionEnum` (no `cases()` method,
  not a `UnitEnum`) sails past validation. At the use site —
  `AuthorizationServiceProvider::registerGates()` — the code calls
  `$className::cases()` which throws a `TypeError` on a non-enum,
  with no reference back to the `permission_enums` config key the
  validator was supposed to guard.
- **Impact:** the validator's purpose is "boot-time clarity over
  deep stack trace"; this gap leaves one class of misconfiguration
  (right contract, wrong shape) producing exactly the deep stack
  trace it was supposed to prevent. The config-docblock already
  says "Backed or unit enums implementing `PermissionEnum`" — the
  validator should enforce the enum half of that sentence.
- **Options:** (a) tighten the enum check: after the existence
  check, require `enum_exists($class)` (not just
  `class_exists`) before the contract assertion. A class
  implementing `PermissionEnum` that is not an enum fails
  validation with a specific message; (b) assert that the class
  is a subclass of `\UnitEnum` (the PHP core interface every enum
  implements) alongside the `PermissionEnum` check. Option (b)
  is the more precise invariant — it catches both backed and
  unit enums with no enum-family guessing.

### 73. Row-lifecycle `*Updated` events carry only post-save state — the stated before/after diff is unreconstructable

- **Files:** `src/Models/Role.php:77–79` (and identical shape in
  `src/Models/Permission.php`, `src/Models/Policy.php`);
  `src/Events/RoleUpdated.php:29–35` (and identical shape on
  `PermissionUpdated` / `PolicyUpdated`).
- **Observation:** the `*Updated` events are dispatched from
  `static::updated(...)` with `$role->getChanges()` passed as
  the `$changes` payload. `getChanges()` in Eloquent returns an
  `array<string, new_value>` — only the post-save values of the
  attributes that were modified. The class docblocks on
  `RoleUpdated`, `PermissionUpdated`, and `PolicyUpdated` all
  promise that "audit consumers can render a before/after diff
  without a second round-trip". They cannot — the **before**
  state is not in the payload, and by the time `updated` fires
  the model's `getOriginal()` returns the new values (the save
  has already refreshed them). A downstream audit subscriber
  wanting the pre-save state has to re-query the audit history
  or the journaled prior row from its own side.
- **Impact:** the SOC 2 / ISO 27001 narrative in the commit
  message ("reconstructing the 'who changed what' trail") fails
  on the 'what' half for update transitions — consumers have
  only the destination, not the delta. The event payload is
  shaped as if it contains a diff but contains a half-diff. A
  consumer reading the event class will expect the fuller
  contract the docblock promises.
- **Options:** (a) switch the hook from `static::updated` to
  `static::saving` (or `updating`) and capture both
  `$role->getDirty()` (for the incoming changes) and a loop over
  `$role->getOriginal($attribute)` for the baseline at the
  moment of the save; pass both as `before` / `after` arrays on
  the event. The event dispatches on the successful save path
  after the row persists; (b) change the event payload to a
  single `{attribute => [before, after]}` map captured via the
  `updating` hook and dispatched from the `updated` hook using
  a pre-save snapshot the model holds during the transition;
  (c) narrow the docblock claim to reflect the as-is payload —
  "updated row + new values" instead of "before/after diff" —
  and let consumers implement their own baseline capture via a
  `saving` listener. Option (a) keeps the SOC 2 promise and is
  the enterprise-grade answer.

### 74. `ConfigValidator::describe()` renders inconsistent value shapes in error messages

- **File:** `src/Config/ConfigValidator.php:249–260`.
- **Observation:** the debug-renderer returns three different
  shapes depending on input:
  - `string` →  `"'foo' (string)"`
  - other scalars → `var_export($value, true)` (e.g. `true`,
    `42`, `1.5`)
  - non-scalars → `get_debug_type($value)` (e.g. `array`,
    `object`, `null`)
  Error messages therefore read inconsistently: a bad
  `gate.on_conflict` value of `42` produces
  `"expected one of [...], got 42."` while a bad value of
  `"LOG"` produces `"expected one of [...], got 'LOG' (string)"`
  and a bad value of `null` produces
  `"expected one of [...], got null."` — three different
  punctuations of the type hint.
- **Impact:** minor, but for an enterprise-grade boot validator
  the error-message UX is part of the surface. Operators
  grepping production logs for a specific misconfiguration want
  predictable output. Also the `(string)` suffix on strings
  stands out because no other type gets the same treatment.
- **Options:** (a) render every value as
  `"{var_export($value, true)} ({get_debug_type($value)})"` —
  predictable `'foo' (string)` / `42 (int)` / `NULL (null)`
  across the board; (b) drop the `(string)` suffix from the
  string case so all three shapes are bare values. Option (a)
  keeps the type tag and makes it uniform.

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
