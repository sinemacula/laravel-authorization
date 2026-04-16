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

