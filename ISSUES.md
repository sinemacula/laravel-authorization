# `sinemacula/laravel-authorization` — Open Issues

**Source of truth for v1.0 scope.** Every item listed here is in scope for
the initial release. Historical references to `SPECS.md` / the PRD remain
inline where they add design context; the documents themselves have been
consumed into this file and removed from the repo.

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

### 23. Gate closure drops `$resource` and `$context` arguments

- **File:** `src/AuthorizationServiceProvider.php:190–199`.
- **Observation:** the registered Gate closure signature is
  `static function (?object $user = null) use ($permission): bool`.
  It receives only the user and forwards nothing else to the
  authorization manager. Laravel, however, dispatches additional
  arguments to Gate callbacks: `$user->can('posts:edit', $post)` or
  `Gate::allows('posts:edit', [$post, $context])` reaches the closure
  as `(?object $user, Post $post, ...)`. The closure drops every
  argument after `$user` on the floor and calls
  `Authorization::for($user)->can($permission)` with no resource or
  context — even though `AuthorizationManager::can()` accepts
  `string $action, ?string $resource = null, array $context = []`.
- **Impact:** resource-aware and context-aware authorization is
  unreachable via Laravel's standard `->can()` / `Gate::allows` /
  `@can` / `can:` middleware surfaces. A policy statement that
  conditions on `resources: ['post:{id}']` or
  `conditions: { owner_id: {eq: '${principal.id}'} }` cannot be
  exercised through Gates — only through the `Authorization` facade
  directly. This silently breaks the core promise of policy
  evaluation whenever a consumer reaches for the idiomatic Laravel
  API.
- **Options:** (a) change the closure signature to
  `static function (?object $user, ...$arguments) use ($permission)`
  and translate `$arguments` into the manager's `$resource` / `$context`
  parameters (convention: first positional argument is the resource
  identifier — stringify an Eloquent model via a `toAuthorizableResource()`
  method or its ULID, subsequent named arguments form context);
  (b) document the limitation and steer consumers away from `->can()`
  for resource-bound checks (weakens the Laravel-compat story); (c)
  introduce a companion Gate registration for each permission that
  accepts a resource and register both signatures. Option (a) is the
  right answer and aligns with Laravel's normal closure contract.

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
- **Coupling to #19 / #20 / #21:** whatever guard model lands
  determines the fix. If guards collapse to a single universe (#20 /
  option (a)), this issue dissolves. If a wildcard sentinel lands
  (#19), the closure's lookup still needs to prefer the caller's
  actual guard when known. If guards remain hard-partitioned, a
  guard-resolution hook must be introduced.
- **Options:** (a) require `Authorizable` implementers to expose a
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

### 25. Trait name `Authorizable` collides with Laravel's built-in trait

- **Files:** `src/Traits/Authorizable.php:16`;
  `src/Contracts/Authorizable.php:25`.
- **Observation:** Laravel ships `Illuminate\Foundation\Auth\Access\Authorizable`
  as a trait and `Illuminate\Contracts\Auth\Access\Authorizable` as
  a contract. Every `User` model that extends
  `Illuminate\Foundation\Auth\User` already has the Laravel trait
  imported and in use. A consumer wiring this package onto the
  standard `User` model must either:
    1. Alias one of the two imports —
       `use SineMacula\Laravel\Authorization\Traits\Authorizable as AuthorizesActions;`
    2. Use both names fully-qualified in the `use` block, which
       trips PHP's trait-resolution rules for same-short-name traits.
- **Impact:** the "drop-in" promise is slightly undercut on the
  single most common target — the built-in `User` model. IDE
  autocomplete on "Authorizable" now shows two options; a distracted
  consumer picks the wrong one and gets a silent no-op. For a
  package that aspires to be enterprise-ready with minimal
  configuration, shipping a name collision with a Laravel standard
  class is an avoidable footgun.
- **Options:** (a) rename the trait and contract to
  `HasAuthorization` / `AuthorizesActions` (trait) and
  `AuthorizableIdentity` (contract), eliminating the collision
  entirely; (b) keep `Authorizable` as the contract name (it matches
  the domain term) but rename only the trait to `HasAuthorization`;
  (c) document the alias idiom prominently in the README and accept
  the friction. Option (a) is the strongest — the contract name is
  also Laravel's contract name, and users who typehint on it will
  hit the same collision pain a reader-of-code will hit on the
  trait. Option (b) is the middle ground.

---

## Enterprise readiness gaps

Surfaced during deep code review against an enterprise RBAC checklist.
These are not spec deviations — they are features or surfaces a serious
enterprise consumer expects on day 1–30 that this package does not
ship. All items are in-scope for v1.0.0.

### 26. Super-admin bypass via explicit `*:*` wildcard permission (decision made)

- **Status:** design decision — implement.
- **Files to touch:** `src/Evaluation/Statement.php` (already wildcards
  via `fnmatch`), `src/Traits/HasPermissions.php:131–136` (needs
  wildcard support — see #27), docs.
- **Decision:** super-admin is not a `Gate::before()` hook or a
  hard-coded role; it is a principal that holds the literal
  `*:*` permission. The evaluator then resolves any check against
  that principal as allowed via the normal RBAC branch. This keeps
  the bypass visible, auditable, revocable like any other grant,
  and subject to explicit deny policies if needed.
- **Dependencies:** requires #27 (RBAC wildcard matching) to be
  implemented first; without wildcards in `hasPermission()`, the
  `*:*` string would only match a literal asked action of `*:*`.
- **Alternatives rejected:** `Gate::before()` hook (invisible
  escalation, not auditable); hard-coded role name (leaks a
  magic string into the evaluator).

### 27. RBAC `hasPermission()` must support wildcard matching (decision made)

- **Status:** design decision — implement.
- **File:** `src/Traits/HasPermissions.php:131–136` — `hasPermission()`
  currently does exact-match `in_array($name, $this->getPermissions(), true)`.
- **Decision:** change `hasPermission()` to walk the held-permission
  list with `fnmatch`, matching the semantics policies already use
  in `src/Evaluation/Statement.php:255–264`. A **held** permission of
  `posts:*` matches an **asked** action of `posts:create`. The
  reverse is not true: an asked `posts:*` does not match a held
  `posts:create`. Directional rule: "broader-held grants
  narrower-asked."
- **Guardrails (both required):**
    1. Permission-name validation (issue #39 below): forbid
       `fnmatch` metacharacters (`?`, `[`, `]`, `{`, `}`) in
       permission names. Allow only alphanumerics, `:`, `_`, `-`,
       `*`. Prevents accidental wildcards from malformed names.
    2. Document the directional semantics in
       `wildcard-and-condition-semantics.md` (tracked under #7).
- **Performance note:** `in_array` → `fnmatch` walk is still O(n)
  over held names with slightly more work per comparison.
  Acceptable for the hot path; per-request memoisation (blocked on
  #40 — cache config is currently dead) will amortise.
- **Consequence:** unlocks #26 (super-admin via `*:*`), reduces
  permission-row explosion for role definitions (a `content-admin`
  role can hold `posts:*`, `pages:*`, `media:*` instead of 30+
  explicit rows).

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
  (`principal.id`, `principal.type`, any `Authorizable` helper
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

### 39. No permission name validation

- **File:** `src/Traits/HasPermissions.php:62–75` (`givePermission()`);
  `src/Models/Permission.php` (no boot-time validator).
- **Observation:** nothing prevents creating a permission named
  `"weird permission"` (spaces), `""` (empty), `"posts:?"`
  (`fnmatch` metachar), or any other malformed string. The package
  happily writes the row and lookups silently fail later.
- **Impact:** silent misconfiguration. Permission names are
  effectively a small DSL (the `resource:action` convention,
  plus wildcards under #27), so consumers need a validator. Also a
  prerequisite for #27 — without it, wildcards could be ambiguous.
- **Options:** (a) on Permission model boot, validate `name`
  against `/^[A-Za-z0-9_\-:*]+$/` (alphanumerics, `:`, `_`, `-`,
  `*`) and raise `InvalidPermissionNameException` on save;
  (b) apply the same rule on Role `name`. Align with the
  naming-convention guardrail from #27.

### 40. Cache config block is advertised but never consumed

- **Files:** `config/authorization.php:119–133` (advertises
  `cache.store` and `cache.ttl`); `Grep` across `src/` for
  `authorization.cache` / `cache.store` / `cache.ttl` returns
  **zero** matches.
- **Observation:** the config block is documented and published as
  if the package supports a resolution cache, but nothing in the
  codebase reads either key. It is dead config. The README's
  performance narrative assumes caching; in practice every
  `->can()` call re-queries the identity's roles, permissions, and
  policies.
- **Impact:** false promise in the README. Consumers setting
  `AUTHORIZATION_CACHE_STORE=redis` in their env expecting a
  performance boost get nothing. For a hot-path authorization
  engine, per-request memoisation at minimum is non-negotiable.
- **Options:** (a) implement a `ResolutionCache` layer: per-request
  memoisation by default (in-memory, cleared on principal change),
  with optional persistent cache keyed on
  `auth:{principal_type}:{principal_id}` using the configured
  store and TTL; invalidated on `RoleAssigned` / `PermissionGranted`
  / `PolicyAttached` events. (b) remove the config block until
  implemented. Option (a) is required for production performance —
  option (b) is a holding action.

### 41. No composite index on `(name, guard_name)` lookups

- **Files:** `database/migrations/2026_04_14_000001_create_roles_table.php:42`;
  `database/migrations/2026_04_14_000002_create_permissions_table.php:37`.
- **Observation:** the migrations declare a unique constraint on
  `(name, guard_name)`. Most databases implicitly back unique
  constraints with an index, but this is not guaranteed for every
  MySQL storage engine / version the spec's CI matrix covers.
  Every string-based lookup (`resolveRole` / `resolvePermission`)
  uses both columns in the `where` clause, so the composite index
  is the hot path.
- **Impact:** at scale (10K+ permissions × multi-tenant), a missing
  composite index degrades every `->can()` string-lookup into a
  scan. Typically invisible in unit tests but bites in production.
- **Options:** (a) add an explicit `$table->index(['name', 'guard_name'])`
  in both migrations — redundant with the unique constraint on most
  engines but belt-and-braces; (b) verify the index is present on
  the MySQL / PostgreSQL / SQLite CI matrix and document the
  guarantee.

### 42. Gate-path decisions drop the evaluator trace

- **Files:** `src/AuthorizationServiceProvider.php:190–199` (Gate
  closure); `src/Evaluation/EvaluationResult.php:127–156`
  (`explain()` + trace exist).
- **Observation:** `EvaluationResult` carries a rich decision trace
  and an `explain()` method, but the Gate closure reduces the
  result to a bool and discards the trace. The `DecisionEvaluated`
  event is dispatched from the manager, but consumers who want to
  answer "why was this denied?" at the request layer (middleware,
  exception handlers) cannot get at the trace without bypassing
  the Gate.
- **Impact:** debugging authorization failures via Laravel idioms
  (`$user->can()`, `Gate::allows`, `@can`) is opaque. Consumers
  see "false" with no reason.
- **Options:** (a) stash the latest result on the
  `AuthorizationManager` instance (bound as singleton) and expose
  `Authorization::lastDecision(): ?EvaluationResult`; document its
  use in error handlers; (b) attach the trace to the dispatched
  `DecisionEvaluated` event (already done) and document that
  subscribers can use it — forces consumers to wire an
  event-listener to surface denial reasons; (c) a dedicated
  `AuthorizationDebugBar` / Telescope integration for request-scope
  inspection; (d) ship
  `Authorization::explain(action, resource?, context?): string` as
  a facade shortcut equivalent to
  `Authorization::evaluate(...)->explain()` — particularly useful
  for the `authorization:why-can` Artisan command under #35 and
  for error-handler output. Options (a) and (d) are complementary
  and both low-cost; ship both.

### 43. No configuration validation at boot

- **File:** `src/AuthorizationServiceProvider.php:38–46`,
  `:140–163`.
- **Observation:** boot-time config is taken on trust.
  Misspelled class names in `permission_enums`, non-enum classes,
  invalid `gate.on_conflict` values (anything other than `log` /
  `throw` / `overwrite`), missing `principal_resolver` class all
  either silently misbehave or throw deep in the boot cycle with
  unhelpful messages.
- **Impact:** consumers lose a day to typos or miswired config.
  For a package aiming at enterprise drop-in, boot-time config
  validation is a must.
- **Options:** (a) introduce a `ConfigValidator` run at service
  provider boot (after `mergeConfigFrom`) that verifies: each
  `permission_enums` entry is a string, resolves to an existing
  class, and implements `PermissionEnum`; `gate.on_conflict` is
  one of the three sentinels; `principal_resolver` resolves and
  implements `PrincipalResolver`; `policy_store` resolves and
  implements `PolicyStore` when non-null. Fail fast with a typed
  `InvalidAuthorizationConfigException` carrying the specific
  offending key.

### 44. No CRUD events for role / permission / policy rows (promotes #15)

- **Files:** `src/Models/Role.php`, `src/Models/Permission.php`,
  `src/Models/Policy.php` — no boot observers, no dispatched
  events on creation / update / deletion.
- **Observation:** promotes the existing observation #15 from
  "flag for product decision" to an in-scope gap. The
  `laravel-audit-log` package will need to reconstruct the full
  row-lifecycle trail (who created `posts:create` on which day,
  who renamed `admin` to `administrator`). Today it has no events
  to subscribe to — it would have to install its own model
  observers on package-internal classes, which is brittle.
- **Impact:** enterprise audit requirements (SOC 2 control
  CC7.2 — change management) expect a complete activity trail
  over authorization primitives. This is a must-have for any IAM
  system, and deferring it means the audit package duplicates work
  the authorization package should have surfaced as events.
- **Options:** (a) ship `RoleCreated`, `RoleUpdated`, `RoleDeleted`,
  `PermissionCreated`, `PermissionUpdated`, `PermissionDeleted`,
  `PolicyCreated`, `PolicyUpdated`, `PolicyDeleted` events, wired
  via model observers in each model's `booted()`; (b) ship a
  single generic `AuthorizationPrimitiveMutated` event carrying
  the model and change set. Option (a) matches the existing event
  naming (one class per transition) and is clearer for
  subscribers.

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
  governs permission flow (admin *inherits* editor's permissions).
  Rank governs management authority (admin *can act on* editor,
  editor *cannot act on* admin). Most enterprise systems ship
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

- **Spec reference:** §12.5 — *"Zero runtime dependency on any
  `sinemacula/laravel-*` package (enforced by CI check on
  `composer.json`)."*
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

- **Spec reference:** §15 open question 4 — *"Gate conflict
  default. `log` is the safe default, but `throw` would be the
  opinionated enterprise default. Lock in v1.0.0."*
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

- **Spec reference:** §15 open question 5 — *"Spatie API aliases.
  Which Spatie method names do we alias on
  `HasRoles`/`HasPermissions`? Minimum is `assignRole`,
  `removeRole`, `givePermissionTo`, `hasPermissionTo`,
  `syncRoles`, `syncPermissions`. Full list to be finalised when
  the migration guide is drafted."*
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
  `Authorizable::effectivePermissions(?EnumScope $universe = null): array`
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
