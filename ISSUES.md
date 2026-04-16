# `sinemacula/laravel-authorization` — Open Issues

**Source of truth for v1.0 scope.** Every item listed here is in scope for
the initial release. Historical references to `SPECS.md` / the PRD remain
inline where they add design context; the documents themselves have been
consumed into this file and removed from the repo.

---

## P0 — Test coverage gaps

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

### 103. `TenantScope::apply()` resolves the tenant on every Eloquent query — no memoization

- **File:** `src/Scopes/TenantScope.php:36–42`.
- **Observation:** the global scope calls
  `app(TenantResolver::class)->resolve()` inside `apply()`,
  which fires for **every** query Eloquent issues against the
  Role and Permission models. A request that loads a user's
  effective permissions can easily issue dozens of
  Role/Permission queries (the relation walks, the
  `effectivePermissions()` enum sweep, the cache-miss paths).
  Each one re-invokes the resolver. There is no per-request
  memoisation or container-singleton guarantee — the binding is
  bound as a regular singleton, but the `resolve()` call inside
  it could re-derive the tenant from request middleware,
  session, or a database lookup on every invocation depending
  on the consumer's implementation.
- **Impact:** consumers wiring a resolver that does any
  non-trivial work (database lookup, JWT decode, cache miss
  on first call) pay that cost N times per request. The
  `effectivePermissions()` enum walk in `2c9b5a2` is
  particularly exposed — it issues one Permission query per
  enum case.
- **Options:** (a) cache the resolved tenant on the scope
  instance for the request lifetime — flush via the same
  Octane `RequestTerminated` hook that resets the
  `LastDecisionStore`; (b) document an explicit
  expectation that consumer `TenantResolver` implementations
  must memoise internally, and provide a base
  `MemoisingTenantResolver` decorator they can compose;
  (c) accept the cost and document that hot paths bypass the
  scope via `withoutGlobalScope(TenantScope::class)`. Option
  (a) is the right enterprise default.

### 104. Non-Model tenants are silently broken — `spl_object_hash` fallback produces unstable IDs

- **Files:** `src/Scopes/TenantScope.php:48–50`;
  `src/Models/Role.php:223–225` (`scopeForTenant`);
  `src/Models/Permission.php` (parallel `scopeForTenant`).
- **Observation:** when the resolved tenant does not implement
  `getKey()`, both the global scope and the local
  `scopeForTenant` derive the morph_id via
  `spl_object_hash($tenant)`. That hash is PHP-internal,
  request-scoped, and reused after garbage collection. A
  consumer using a custom non-Eloquent `Tenant` class would
  have written rows with `tenant_id = '<their-canonical-id>'`
  (whatever value they passed to `Role::create`), but the
  scope queries with `WHERE tenant_id = '0000000000abc1234'`
  (the spl_object_hash). The two values never match, so
  every tenant-owned row is invisible to the consumer — but
  global rows still return, so the failure looks like
  "consumer's tenant has no roles" rather than "consumer's
  resolver is incompatible." Untested code path: every test
  fixture (`StubTenant`) extends `Model`, so the
  spl_object_hash branch is never exercised.
- **Impact:** silent data invisibility for a real consumer
  cohort. The contract docblock on `TenantResolver` says
  resolve returns `?object` — broad enough that consumers
  reasonably assume any object works. The implicit
  `getKey()` requirement is a hidden contract.
- **Options:** (a) require tenants to implement a contract
  (`AuthorizableTenant` with
  `getAuthorizationKey(): string`) and refuse to scope on
  anything else — throws a typed exception so the consumer
  knows what to fix; (b) keep the `spl_object_hash` branch
  but log a warning the first time it fires, so consumers
  see the silent failure surface in their logs; (c) document
  the `getKey()` requirement in the `TenantResolver` contract
  docblock and remove the `spl_object_hash` fallback —
  callers without `getKey()` get a clear runtime error
  instead of silent invisibility. Option (a) or (c) — both
  fail loudly. Option (b) is the half-measure.

### 105. No invariant enforces both-or-neither on `tenant_type` / `tenant_id` columns

- **Files:** `database/migrations/2026_04_14_000012_add_tenant_columns_to_roles_table.php`;
  `database/migrations/2026_04_14_000013_add_tenant_columns_to_permissions_table.php`;
  `src/Models/Role.php:185–207` (`tenant`, `isGlobal`,
  `isTenantOwned`).
- **Observation:** the migrations declare both
  `tenant_type` and `tenant_id` as nullable strings with no
  composite CHECK constraint. Nothing at the DB or model
  layer enforces the both-or-neither invariant — a row can
  be inserted with `tenant_type = 'App\Models\Tenant'` and
  `tenant_id = NULL`, or the inverse. The
  `TenantScope::apply` filter checks
  `tenant_type IS NULL` only, so a row with
  `tenant_type = X, tenant_id = NULL` would not match the
  global filter and would not match any tenant-id filter
  either — silently invisible. Likewise `isGlobal()` and
  `isTenantOwned()` only consult `tenant_type`, so an
  inconsistent row reads as "tenant-owned" but has no usable
  tenant ID.
- **Impact:** orphaned tenant rows are persistable. A bug in
  consumer code that writes one column without the other
  produces silently-invisible authorization data. The
  inverse case (tenant_id without tenant_type) is the
  worst — the row is unreachable through any scope.
- **Options:** (a) add a CHECK constraint at the DB layer
  in both migrations: `(tenant_type IS NULL AND tenant_id
  IS NULL) OR (tenant_type IS NOT NULL AND tenant_id IS NOT
  NULL)` — works on PostgreSQL and MySQL 8.0.16+ and
  SQLite. The package's CI matrix (per #4) covers all
  three; (b) enforce in the model `saving` hook with a
  typed exception (`InconsistentTenantOwnershipException`);
  (c) both — DB layer for data integrity, model layer for
  early surface. Option (c) is belt-and-braces and matches
  the COALESCE-index precedent on `(name, guard_name)`
  uniqueness.

