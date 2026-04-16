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

### 100. `ancestors()` passes a UUID to `proposedParentName` — exception shows ID instead of name

- **File:** `src/Models/Role.php:213`.
- **Observation:** the cycle-detection throw inside `ancestors()`
  constructs `RoleHierarchyCycleException(roleName: $this->name,
  proposedParentName: $current->parent_id)`. The parameter
  `proposedParentName` receives a UUID string (`parent_id`), not
  the parent role's name. The saving hook at line 593–594
  correctly resolves the parent first
  (`$proposedParent?->name ?? $role->parent_id`); the
  `ancestors()` path skips the resolution. The exception message
  will read "Role 'admin' cannot set parent to
  '550e8400-e29b-…'" instead of "…to 'editor'".
- **Impact:** confusing error output. An enterprise consumer
  catching the exception in a controller gets an opaque UUID
  instead of the human-readable role name the saving-hook path
  would have given them.
- **Options:** (a) resolve the parent via `static::query()->find($current->parent_id)?->name`
  before throwing, matching the saving-hook pattern; (b) change
  the exception to accept both name and ID so the consumer
  can render whichever they prefer.

### 101. `descendants()` has no cycle guard — infinite loop if a cycle exists in the DB

- **File:** `src/Models/Role.php:237–253`.
- **Observation:** the breadth-first descendant walk uses
  `while ($queue !== [])` with no `$visited` set. If a cycle
  exists in the database — race condition between two concurrent
  `parent_id` saves, direct SQL bypassing the model's saving
  hook, FK enforcement off in SQLite/test — the BFS loops
  forever. The symmetry is broken:
  `ancestors()` at line 205–230 carries a `$visited` map and
  throws on re-encounter; `descendants()` does not.
- **Impact:** a corrupted hierarchy (however it got there) turns
  every `$role->descendants()` call — including the saving
  hook's own cycle check at line 588 — into a runaway loop that
  exhausts memory or hits max-execution-time. The saving hook
  itself becomes the vector: if someone inserts a cycle via raw
  SQL, the next legitimate `parent_id` update triggers
  `$role->descendants()` inside the hook and hangs.
- **Options:** (a) add a `$visited` set keyed by primary key
  inside the BFS, breaking the loop and throwing
  `RoleHierarchyCycleException` on re-encounter — mirrors the
  ancestors pattern; (b) cap the walk at a configurable
  `authorization.hierarchy.max_depth` (default 50) and throw
  on breach. Option (a) is the clean fix; option (b) adds a
  safety net for pathological trees regardless of cycles.

### 102. `isAncestorOf()` has no cycle guard — same infinite-loop risk as `descendants()`

- **File:** `src/Models/Role.php:261–281`.
- **Observation:** the parent-chain walk in `isAncestorOf()`
  uses `while ($current->parent_id !== null)` with no `$visited`
  set — the same missing guard as `descendants()`. A cycle in
  the DB turns this helper into a runaway loop. Unlike
  `ancestors()`, which has the guard, `isAncestorOf()` was
  implemented independently and missed it.
- **Impact:** same as #101 — a corrupted hierarchy hangs the
  caller. Consumer code like `$role->isAncestorOf($other)` in
  a Blade view or API controller produces a timeout instead of
  a catchable exception.
- **Options:** (a) add a `$visited` set and throw
  `RoleHierarchyCycleException` on re-encounter, consistent
  with `ancestors()`; (b) rewrite `isAncestorOf()` to delegate
  to `ancestors()` (which already has the guard) and check
  membership — eliminates the independent walk entirely. Option
  (b) is the single-owner answer.

