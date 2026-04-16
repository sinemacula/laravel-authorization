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

