# `sinemacula/laravel-authorization` — Open Issues

**Traces to:** `SPECS.md`
**Source of truth for gap analysis, not a roadmap.** Each entry cites the
SPECS.md section that defines the target state and names the file(s) where
the gap manifests today. Tests and benches are grouped separately so the
implementation work can be sequenced.

---

## P0 — Spec gaps blocking v1.0.0

### 1. `Contracts/PolicyRepository` interface is missing

- **Spec reference:** §3 (target `src/` layout) — lists
  `Contracts/PolicyRepository.php` as the internal abstraction over the
  Eloquent `Policy` model.
- **Observed state:** `src/Contracts/` contains `Authorizable`,
  `PermissionEnum`, `PolicyStore`, and `PrincipalResolver` only. There is
  no `PolicyRepository` contract, and the `AuthorizationManager` reaches
  the Eloquent layer via `Authorizable::getPolicies()` and an optional
  `PolicyStore` binding only.
- **Impact:** No seam for a DB-backed policy cache, policy preloader, or
  test fake that is distinct from `PolicyStore` (which is documented as
  an external source, not an internal one). The spec treats this as an
  internal abstraction contract — its absence locks consumers into the
  current gathering flow inside `AuthorizationManager::gatherPolicies()`.
- **Decision needed:** confirm the interface shape before adding it — the
  spec names the class but does not fix its method signatures.

### 2. `Role` model is missing the permission-management API

- **Spec reference:** §5.3 — requires `$role->givePermission(...)`,
  `$role->revokePermission(...)`, `$role->syncPermissions([...])`, and
  `$role->getPermissions(): array`.
- **Observed state:** `src/Models/Role.php` exposes the `permissions()`
  `BelongsToMany` relation and nothing else. None of the four
  spec-mandated helpers exist on the model, and there is no Spatie-style
  alias (`givePermissionTo`) either.
- **Impact:** Role → permission attachment in §3.2 item 4 is unsatisfied.
  Consumers are forced to drop into the relation manually
  (`$role->permissions()->sync(...)`) and lose the typed exception
  (`UnknownPermissionException`) behaviour that the authorizable traits
  provide. The Spatie migration story in §12.5 is also incomplete
  because `Role::givePermissionTo()` is part of the Spatie idiom.
- **Related:** no corresponding events are dispatched on role-level
  permission mutations. `PermissionGranted` / `PermissionRevoked`
  currently fire only from `HasPermissions` on the authorizable side.

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

---

## P1 — Minor deviations from the spec

### 8. `HasPolicies` mutators accept only the concrete `Policy` model

- **Spec reference:** §5.2 —
  `attachPolicy(Policy|Model $policy): self;` (and equivalent for
  `detachPolicy` / `syncPolicies`).
- **Observed state:** `src/Traits/HasPolicies.php` types every parameter
  as the concrete `Policy` model. A consumer that swaps the model via
  `authorization.models.policy` cannot pass their subclass instance
  without also satisfying Laravel's relation typing — which is fine in
  practice (subclasses pass the type check), but the spec explicitly
  widens to `Model` and the current narrower signature will break if a
  consumer ever wants to pass a duck-typed value object.
- **Low-risk fix:** broaden to
  `Policy|\Illuminate\Database\Eloquent\Model` or rely on the
  `config('authorization.models.policy')` resolution, matching the
  pattern used for `Role` / `Permission` in `HasRoles` / `HasPermissions`.

### 9. `Authorization::for()` documented as `self`, implemented as `static`

- **Spec reference:** §5.1 — `Authorization::for(object $principal): self`.
- **Observed state:** `AuthorizationManager::for()` returns `static`
  (src/AuthorizationManager.php:136).
- **Assessment:** functionally compatible — `static` is strictly more
  precise than `self` for subclasses — but the facade's PHPDoc
  `@method` line advertises the return as `AuthorizationManager`, so a
  subclassing consumer will see a type-narrowing warning from Psalm /
  PHPStan. Either tighten the facade's `@method` line to `static` or
  accept the status quo explicitly in the spec.

### 10. `AuthorizationFailed` fires only on the `authorize()` throw path

- **Spec reference:** §12.4 — "All decisions are emittable via Laravel
  events … consumers can subscribe and forward to
  `sinemacula/laravel-audit-log` without the authorization package
  depending on it."
- **Observed state:** `AuthorizationManager::authorize()` dispatches
  both `DecisionEvaluated` and `AuthorizationFailed`, but
  `AuthorizationManager::can()` / `::evaluate()` dispatch only
  `DecisionEvaluated` — a `can()` that returns `false` does not emit
  `AuthorizationFailed`.
- **Assessment:** arguably intentional (`AuthorizationFailed` tracks
  the "hard denial" path), but the spec does not clarify this. Either:
  - Document the split in §12.4, or
  - Emit `AuthorizationFailed` from `can()` / `evaluate()` whenever
    the result is not allowed.

---

## Observations (not spec gaps)

### 11. `Gate::has()` log-conflict path relies on string key ordering

- **File:** `src/AuthorizationServiceProvider.php:174–199`.
- **Observation:** the `match` in `registerEnumGate()` runs for all
  three conflict modes, but the subsequent
  `if ($onConflict === 'log') { return; }` guard is what prevents the
  `overwrite` arm from falling through. A future change that moves the
  `return` into the `match` arms (matching the pattern used elsewhere)
  would be clearer and remove the second branch.
- **Low-risk fix:** collapse the flow into a single `match` that either
  returns early (`'log'`, `'throw'`) or falls through (`'overwrite'`).

### 12. `HasPolicies::getPolicies()` is not fail-closed on a single bad row

- **File:** `src/Traits/HasPolicies.php:116–124`.
- **Observation:** `getPolicies()` maps every attached `Policy` through
  `toEvaluationPolicy()`, which throws `InvalidPolicyDocumentException`
  on a malformed document. A single bad row raises at the trait
  boundary, which aborts the entire evaluation for that principal. §12.3
  mandates "fail closed (denied)" — the current behaviour produces a
  500-class exception rather than a denied decision. Consider wrapping
  the per-row hydration in a try/catch that logs the failure and
  excludes the policy (still fail-closed because the excluded `ALLOW`
  cannot win) or converting the exception into a guaranteed implicit
  deny inside the manager.

### 13. `ConditionEvaluator::logUnknownOperator()` swallows logger errors silently

- **File:** `src/Evaluation/ConditionEvaluator.php:108–120`.
- **Observation:** the helper wraps the `logger()` call in a bare
  `catch (\Throwable)` with no rethrow and no fallback emit. The §12.4
  observability guarantee is therefore not enforced — in a container
  context where the facade root is missing, the warning vanishes. This
  is probably the right trade-off (the authorizer must not fail a
  request because the logger is unavailable), but the behaviour is
  undocumented.

### 14. Policy document versioning is present but unexercised

- **File:** `src/Evaluation/Policy.php:20–34`, §15 open question 3.
- **Observation:** `Policy::CURRENT_VERSION = 1` and `fromArray()`
  accepts a `version` key, but no migration path exists for bumping
  the version, and no test pins the current shape. §15 leaves this as
  an open question — it should be resolved and a compatibility test
  added before v1.0.0 so future schema changes are observable.

### 15. `Permission` model has no events for direct CRUD

- **Observation:** the event catalogue in §12.4 fires on assignment
  transitions (`RoleAssigned`, `PermissionGranted`, etc.) but not on
  permission/role/policy row CRUD itself. This is consistent with the
  spec — but audit consumers that want a full trail of "who created
  the `posts:create` permission row" will need model-observer wiring
  that the package does not ship. Flag for product decision.

---

## Drop-in / DX friction (not spec gaps)

These are not violations of `SPECS.md` — they surfaced during exploratory
review of whether the package behaves as a drop-in RBAC solution with
minimal configuration. Each entry is a usability friction point for the
"pure RBAC, no policies, standard Laravel Auth" consumer, which is the
most likely first-use path.

### 16. `Authorizable` contract forces policy methods on pure-RBAC consumers

- **File:** `src/Contracts/Authorizable.php:113–137`.
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
  have `Authorizable` extend whichever are mandatory, or document
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

### 19. No cross-guard ("global") role / permission support

- **Files:** `src/Traits/HasRoles.php:204–211`;
  `src/Traits/HasPermissions.php:236–244`;
  `database/migrations/2026_04_14_000001_create_roles_table.php:38–42`.
- **Observation:** resolution of a role or permission by string name
  performs a literal equality match on `guard_name`
  (`->where('guard_name', $guard)`). There is no wildcard convention
  (e.g. `'*'` or `null` meaning "any guard"), so an enterprise
  deployment with multiple guards — e.g. `web` for customers, `api`
  for partner integrations, `admin` for an internal console — cannot
  declare a single `super-admin` or `auditor` role that applies across
  every guard. The workaround today is to duplicate the row per guard
  and assign all copies to the identity, which invites drift between
  guard-scoped copies of the same logical role.
- **Impact:** multi-guard enterprise scenarios are second-class. A
  cross-guard role is a natural concept (a platform administrator acts
  the same regardless of how they authenticated), but the current
  schema and lookup logic force it to be modelled as N separate rows.
- **Options:** (a) treat a sentinel `guard_name` value (e.g. `'*'` or
  `null`) as "applies to every guard" and widen the `resolveRole` /
  `resolvePermission` lookups to match either the exact guard or the
  sentinel, (b) introduce a separate `guards` join table and allow a
  role/permission to be attached to many guards, or (c) document the
  "duplicate per guard" pattern as the supported idiom and provide a
  helper to keep the copies in sync. Option (a) is the lowest-friction
  and matches the spirit of Spatie's loose-typing conventions; option
  (b) is the most explicit but is a schema change.

### 20. Single-guard apps carry unused `guard_name` complexity

- **Files:** same as issue #19.
- **Observation:** the overwhelming majority of Laravel apps use a
  single guard (`web`). For those consumers, `guard_name` is always
  `'web'` on every row, the unique constraint on `(name, guard_name)`
  collapses to `(name)`, every `resolveRole` / `resolvePermission`
  lookup runs an extra `where` clause that narrows nothing, and the
  user must mentally account for a concept they have no use for. The
  package inherits this from Spatie's idiom, but Spatie's guard model
  exists because its permission engine is tightly bound to the
  authentication layer — this package is explicitly decoupled from
  auth via `PrincipalResolver`, so the same justification does not
  fully apply here.
- **Impact:** simple customer implementations pay an
  enterprise-shaped tax in schema, config, and lookup cost. It is not
  a large tax, but it is pure overhead for that cohort and
  contradicts the "minimal configuration" drop-in narrative.
- **Options:** (a) add a config flag
  (`authorization.guards.enabled = false`) that, when disabled, makes
  migrations omit `guard_name` and lookups drop the guard filter —
  enterprise consumers opt in, simple consumers get a slimmer schema;
  (b) keep the column but make it nullable and treat null as
  "guard-agnostic" (ties into issue #19's sentinel approach); (c)
  accept the overhead and document `guard_name` prominently in the
  README so new users understand why it is there. Option (a) is the
  cleanest for the simple case but introduces two schema variants —
  option (b) is a single schema that serves both cohorts.

### 21. Role ↔ permission guard mismatch is not prevented

- **Files:** `src/Models/Role.php:60–74` (`permissions()` relation, no
  hooks); `database/migrations/2026_04_14_000004_create_role_permissions_table.php`
  (pivot has `role_id` + `permission_id` only, no guard column or
  composite constraint).
- **Observation:** attaching a permission to a role performs no guard
  parity check. A role created under the `web` guard can have a
  permission created under the `api` guard attached to it via
  `$role->permissions()->attach(...)` or `sync(...)`. Spatie's
  `laravel-permission` throws `GuardDoesNotMatch` to prevent exactly
  this; this package accepts the attachment silently and the lookup
  layer then produces confusing results (the `api` permission is
  enumerable through the role but is effectively dead weight for a
  `web`-guard identity).
- **Impact:** data-integrity gap. Silent cross-guard attachment
  produces no runtime error but corrupts the mental model — the
  `web`-guard role's permission set no longer means "permissions a
  `web` user can inherit via this role." It also hides bugs at the
  caller: a fat-fingered guard selection in a role seeder will persist
  without complaint and only surface as a mysterious authorization
  failure in production.
- **Coupling to #19 / #20:** the enforcement rule depends on how cross
  guard support lands. If a `null` / `'*'` wildcard sentinel is
  introduced (#19), the invariant becomes "role.guard ==
  permission.guard OR either side is the wildcard." If guards are
  disabled altogether for single-guard apps (#20), there is nothing
  to enforce. This issue should be resolved **after** #19 / #20 so
  the rule is consistent with the final guard model.
- **Options:** (a) raise a typed exception
  (e.g. `GuardMismatchException`) from the role permission-management
  API when it lands (blocked on issue #2), (b) add a
  `Role::permissions()` `attaching` / `syncing` model event listener
  that throws on mismatch, or (c) enforce at the DB layer via a
  composite foreign key that includes `guard_name` (heaviest option;
  would require duplicating `guard_name` onto the pivot).

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
