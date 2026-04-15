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
