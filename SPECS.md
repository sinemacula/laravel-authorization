# `sinemacula/laravel-authorization` — Engineering Specification

**Document type:** engineering spec (implementation contract)
**Traces to:** `docs/prd/04-laravel-authorization.md`
**Status:** draft — v1.0.0 target
**Author:** Ben Carey (`bdmc@sinemacula.co.uk`)
**Last reviewed:** 2026-04-14

This document is the authoritative specification for the `sinemacula/laravel-authorization` package. It exists because the repository was bootstrapped by cloning the `sinemacula/laravel-authentication` repo, so every scaffolding artefact (config, migrations, tests, benchmarks, CI, tooling) currently still references the authentication package and must be rewritten. The goal of this spec is twofold:

1. Define the target state for the package — structure, naming, public surface, behaviour, and enterprise-grade non-functional requirements — so the rewrite is deterministic rather than ad-hoc.
2. Record the "plug-and-play with `sinemacula/laravel-authentication`, standalone with anything else" compatibility contract that the umbrella `sinemacula/laravel-iam` package will later rely on.

The package is one of six repositories in the `laravel-iam` ecosystem:

| # | Repo                                 | Role                                                                 |
|---|--------------------------------------|----------------------------------------------------------------------|
| 1 | `sinemacula/laravel-authentication`  | Stateless contextual authentication (Identity, Principal, Device)    |
| 2 | `sinemacula/laravel-mfa`             | Multi-factor authentication step-up                                   |
| 3 | `sinemacula/laravel-sso`             | Single sign-on primitives                                             |
| 4 | `sinemacula/laravel-authorization`   | **This package** — RBAC + IAM-style policy evaluation                |
| 5 | `sinemacula/laravel-audit-log`       | Audit log primitives                                                  |
| 6 | `sinemacula/laravel-iam`             | Umbrella (installs all five, wires them together)                     |

Each sibling is standalone. This package has **zero required runtime dependencies** on any of them; the umbrella is the only package allowed to wire them together.

---

## 1. Package identity

| Field                   | Value                                                  |
|-------------------------|--------------------------------------------------------|
| Composer name           | `sinemacula/laravel-authorization`                     |
| PHP root namespace      | `SineMacula\Laravel\Authorization\`                    |
| PSR-4 autoload target   | `src/`                                                 |
| Test autoload target    | `tests/` → `Tests\`                                    |
| Benchmark autoload      | `benchmarks/` → `Benchmarks\`                          |
| Service provider class  | `SineMacula\Laravel\Authorization\AuthorizationServiceProvider` |
| Facade class            | `SineMacula\Laravel\Authorization\Facades\Authorization` |
| Container binding alias | `authorization`                                        |
| Published config file   | `config/authorization.php`                             |
| Published migrations    | `database/migrations/*.php`                            |
| Config-publish tag      | `authorization-config`                                 |
| Migrations-publish tag  | `authorization-migrations`                             |
| Supported PHP           | `^8.3`                                                 |
| Supported Laravel       | `^12.40 || ^13.3`                                      |
| License                 | Apache-2.0                                             |

> **Existing mismatch to fix:** `composer.json` currently declares the package as `sinemacula/laravel-authentication` while the `autoload` block already uses `SineMacula\Laravel\Authorization\`. The package metadata, Laravel service-provider entry, and runtime dependencies must be rewritten as part of the scrub. The current source code lives under `SineMacula\Laravel\Iam\Permissions\` — it must be relocated to `SineMacula\Laravel\Authorization\` to match the composer autoload and PRD #04.

---

## 2. Repository structure (must mirror `laravel-authentication`)

The authentication repo is the structural reference. Every top-level directory, configuration file, and CI workflow in authentication has a counterpart here — same layout, same tooling, same thresholds — so that contributors can move between the six packages without friction, and so the umbrella package can treat them uniformly.

```
laravel-authorization/
├── .claude/                           # Local Claude Code harness config (identical to sibling)
├── .editorconfig
├── .github/
│   └── workflows/
│       ├── quality-gates.yml          # Mutation + benchmarks (scheduled + manual)
│       └── tests.yml                  # Unit/Feature/Integration matrix + DB matrix
├── .gitignore
├── .qlty/
│   ├── qlty.toml                      # phpstan, php-codesniffer, php-cs-fixer, yamllint, trivy, etc.
│   └── configs/
│       ├── .php-cs-fixer.dist.php     # PhpCsFixerConfig::make(src, config, benchmarks, database, tests)
│       ├── phpcs.xml                  # Ruleset "SineMacula" applied to src/benchmarks/database/tests
│       └── phpstan.neon               # level 8, scanDirectories = src/benchmarks/database/tests
├── .sinemacula/
│   └── config.toml                    # Blueprint + Build plugin config (project_name etc.)
├── benchmarks/
│   ├── <domain>/                      # Authorization-specific benches (see §10)
│   └── Support/                       # Harnesses + in-memory fixtures
├── build/                             # CI-only artefacts (phpbench xml, infection logs)
├── config/
│   └── authorization.php              # Single publishable config
├── database/
│   └── migrations/                    # Seven migrations (see §7)
├── docs/
│   ├── design/                        # Short invariant notes (see §11)
│   │   ├── README.md
│   │   └── <note>.md
│   └── prd/
│       └── 04-laravel-authorization.md
├── infection.json5                    # Scoped mutation gate (the evaluator + manager)
├── infection.full.json5               # Full mutation suite (all of src/)
├── phpbench.json                      # phpbench bootstrap + path
├── phpunit.xml.dist                   # Four suites: Unit / Feature / Integration / Performance
├── src/                               # See §3
├── tests/
│   ├── Feature/                       # Testbench-powered (service provider, config, facade, migrations)
│   ├── Integration/                   # Multi-model + DB matrix scenarios
│   ├── Performance/                   # Query budgets (N+1 safety, evaluator throughput)
│   ├── Unit/                          # Pure engine: Statement, Policy, PolicyEvaluator, etc.
│   └── TestCase.php                   # Orchestra base case (see §8)
├── CHANGELOG.md
├── CLAUDE.md                          # Already rewritten for this repo
├── CONTRIBUTING.md
├── LICENSE
├── NOTICE
├── README.md                          # OUT OF SCOPE for the current task — do not touch
├── SECURITY.md
└── SPECS.md                           # This file
```

**Rule:** any structural change in `laravel-authentication` that is not package-specific (e.g. a new CI workflow, a new benchmark harness convention) must be mirrored here unless explicitly called out in §13.

---

## 3. `src/` target layout

The current `src/` is a seed of the authorization engine under the wrong namespace (`SineMacula\Laravel\Iam\Permissions\*`) and missing half of the P0 surface. The target layout below is what v1.0.0 ships.

```
src/
├── AuthorizationManager.php           # Successor to PermissionManager (renamed for clarity)
├── AuthorizationServiceProvider.php   # Successor to PermissionServiceProvider
├── Contracts/
│   ├── Authorizable.php               # Role/permission/policy interface for identity models
│   ├── PermissionEnum.php             # UnitEnum + toString() for Gate auto-wiring
│   ├── PolicyStore.php                # External policy source (optional)
│   ├── PrincipalResolver.php          # NEW — decouples engine from any specific auth package
│   └── PolicyRepository.php           # Internal abstraction over the Eloquent Policy model
├── Database/
│   └── MigrationCollisionGuard.php    # Same pattern as authentication — idempotent migrations
├── Enums/
│   └── PolicyEffect.php               # allow | deny (string-backed)
├── Evaluation/
│   ├── EvaluationResult.php           # Immutable — decision + reason + matched statement(s) + trace
│   ├── Policy.php                     # Immutable value object (name, statements[])
│   ├── PolicyEvaluator.php            # 4-step IAM evaluator
│   └── Statement.php                  # effect/actions/resources/conditions + matchers
├── Exceptions/
│   ├── AuthorizationException.php     # Thrown by authorize(); carries EvaluationResult
│   ├── InvalidPolicyDocumentException.php  # Structural policy errors (400-class)
│   └── UnknownRoleException.php       # Role assignment targeting a non-existent role
├── Facades/
│   └── Authorization.php              # Static proxy to AuthorizationManager
├── Models/
│   ├── Permission.php                 # Eloquent — UUID PK, name, guard_name, description
│   ├── Policy.php                     # Eloquent — UUID PK, name, document (JSON)
│   └── Role.php                       # Eloquent — UUID PK, name, guard_name, description
├── Resolvers/
│   └── NullPrincipalResolver.php      # Anonymous-safe default (returns null)
└── Traits/
    ├── HasRoles.php                   # Role assignment/revocation + hasRole
    ├── HasPermissions.php             # Direct permission assignment/revocation + hasPermission
    ├── HasPolicies.php                # Policy attachment/detachment + getPolicies
    └── Authorizable.php               # Convenience trait composing the three above
```

### 3.1 Renames from the current seed

| Current                                                                | Target                                                                  |
|------------------------------------------------------------------------|-------------------------------------------------------------------------|
| `SineMacula\Laravel\Iam\Permissions\PermissionManager`                 | `SineMacula\Laravel\Authorization\AuthorizationManager`                 |
| `SineMacula\Laravel\Iam\Permissions\PermissionServiceProvider`         | `SineMacula\Laravel\Authorization\AuthorizationServiceProvider`         |
| `SineMacula\Laravel\Iam\Permissions\Facades\Permission`                | `SineMacula\Laravel\Authorization\Facades\Authorization`                |
| `SineMacula\Laravel\Iam\Permissions\Contracts\*`                       | `SineMacula\Laravel\Authorization\Contracts\*`                          |
| `SineMacula\Laravel\Iam\Permissions\Enums\PolicyEffect`                | `SineMacula\Laravel\Authorization\Enums\PolicyEffect`                   |
| `SineMacula\Laravel\Iam\Permissions\Evaluation\*`                      | `SineMacula\Laravel\Authorization\Evaluation\*`                         |
| `SineMacula\Laravel\Iam\Permissions\Exceptions\AuthorizationException` | `SineMacula\Laravel\Authorization\Exceptions\AuthorizationException`    |
| `SineMacula\Laravel\Iam\Permissions\Traits\Authorizable`               | `SineMacula\Laravel\Authorization\Traits\Authorizable`                  |

Config key moves from `iam-permissions.*` to `authorization.*`; container alias moves from `iam.permissions` to `authorization`; publish tags follow.

### 3.2 Behavioural gaps in the current seed

The seed ships only the evaluator and a thin facade. The following P0 capabilities from PRD #04 are **not yet implemented** and are required for v1.0.0:

1. Eloquent `Role`, `Permission`, `Policy` models + published migrations with UUID primary keys and polymorphic pivots (`role_permissions`, `authorizable_roles`, `authorizable_permissions`, `authorizable_policies`).
2. Role assignment/revocation API on any `Authorizable` model (`$user->assignRole($role)`, `->revokeRole($role)`, `->syncRoles([...])`, `->hasRole($name)`).
3. Direct permission assignment/revocation API (`->givePermission($permission)`, `->revokePermission($permission)`, `->syncPermissions([...])`).
4. Role → permission attachment (`$role->givePermission(...)`, `$role->syncPermissions(...)`).
5. Policy attach/detach/sync on any `Authorizable` model.
6. Gate auto-wiring that resolves through `AuthorizationManager::can()` (currently the seed calls `Permission::can()` via a Gate closure, which does not take the identity into account — see §6.3).
7. `PrincipalResolver` contract + `NullPrincipalResolver` default + binding pattern (currently the evaluator calls `SineMacula\Laravel\Iam\Auth\Facades\Auth::principal()` directly — that is a hard dependency on the authentication package and must be removed).
8. Structured `AuthorizationException` with full evaluation trace (current exception carries the final result only; spec requires a reproducible trace — see §5.4).
9. `InvalidPolicyDocumentException` raised when a persisted policy fails structural validation on parse.
10. Configurable model overrides resolved through the config file rather than direct class-hinting.

---

## 4. Standalone + plug-and-play compatibility

The package must run in two modes without code changes:

### 4.1 Standalone mode (default)

- The consumer's app may use Laravel's built-in `auth`, another authentication package, or no authentication at all.
- The package resolves "the current principal" through a `PrincipalResolver` contract. The shipped default (`NullPrincipalResolver`) returns `null`, which makes `AuthorizationManager::can()` return `false` and `authorize()` throw. This is deliberate: the evaluator is anonymous-safe, never assumes a session, and never calls any `Auth::*` facade.
- Any Eloquent model can opt in by implementing `Authorizable` and applying the shipped traits. The consumer does not need to touch Laravel's `Authenticatable` contract.

### 4.2 Plug-and-play with `sinemacula/laravel-authentication`

- When the authentication package is also installed, the consumer (or the `sinemacula/laravel-iam` umbrella) binds a resolver that reads from authentication's `AuthManager::principal()`:

    ```php
    $this->app->singleton(
        \SineMacula\Laravel\Authorization\Contracts\PrincipalResolver::class,
        \SineMacula\Laravel\Iam\AuthenticationBridge\PrincipalResolver::class, // ships in the umbrella
    );
    ```

- The authorization package itself declares **no** `require` dependency on `sinemacula/laravel-authentication`. The bridge class lives in the umbrella package; the authorization package only depends on the contract it defines.
- The authorization facade and gate results must not change behaviour between modes: given the same principal, the decision is identical.

### 4.3 Compatibility contract

1. `PrincipalResolver::resolve(): ?object` — returns `null` when anonymous. The engine treats any non-null return as "the current principal" and uses it for RBAC and policy evaluation, provided it implements `Authorizable`.
2. The engine never type-hints `SineMacula\Laravel\Iam\Auth\Contracts\Principal` or any authentication-package type. Principals are plain `object` to the engine; capability is detected via the `Authorizable` contract.
3. `Authorizable` is the only coupling point. Identities in the 3D model (Identity → Principal → Tenant) of the authentication package can still implement `Authorizable` on whichever layer makes semantic sense; the authorization package does not care which.
4. Tenant scoping is expressed through the policy `context` array (e.g. `conditions: { tenant_id: {eq: 'org-1'} }`). This package does not ship tenant middleware or tenant-aware tables.

---

## 5. Public API surface (the v1.0.0 contract)

### 5.1 Facade / manager

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;

Authorization::can(string $action, ?string $resource = null, array $context = []): bool;
Authorization::authorize(string $action, ?string $resource = null, array $context = []): void; // throws
Authorization::evaluate(string $action, ?string $resource = null, array $context = []): EvaluationResult;
Authorization::for(object $principal): self;              // Override resolver per-call
Authorization::withPolicies(array $policies): self;       // Override gathered policies per-call (read-only)
```

Two-argument/one-argument calls are supported (a resource-less check is an action-only check; wildcard resources `*` match anything).

### 5.2 Authorizable model API

```php
$user->assignRole(string|Role $role): self;
$user->revokeRole(string|Role $role): self;
$user->syncRoles(array $roles): self;
$user->hasRole(string|Role $role): bool;
$user->getRoles(): array;                 // ["admin", "editor"]

$user->givePermission(string|Permission $p): self;
$user->revokePermission(string|Permission $p): self;
$user->syncPermissions(array $permissions): self;
$user->hasPermission(string|Permission $p): bool;  // inherits via roles + direct grants
$user->getPermissions(): array;

$user->attachPolicy(Policy|Model $policy): self;
$user->detachPolicy(Policy|Model $policy): self;
$user->syncPolicies(array $policies): self;
$user->getPolicies(): array;              // Returns array<int, Evaluation\Policy>
```

All mutation helpers return `$this` for chaining, never throw on duplicate assignments, and raise typed exceptions on unknown roles/permissions.

### 5.3 Role API

```php
$role = Role::create(['name' => 'admin']);
$role->givePermission('posts:create');
$role->revokePermission('posts:create');
$role->syncPermissions(['posts:create', 'posts:update']);
$role->getPermissions(): array;
```

### 5.4 Evaluation result

`EvaluationResult` must carry enough information to reconstruct the decision without re-running it:

- `allowed: bool`
- `reason: self::REASON_*` (explicit_allow | explicit_deny | implicit_deny | rbac_allow)
- `matchedStatement: ?Statement` — the statement that decided the outcome (if any)
- `trace: array<int, array{policy: string, statement_index: int, decision: 'matched'|'skipped', reason: string}>` — ordered, serialisable trace of every evaluated statement. Used by `AuthorizationException`.

The P2 "explain" helper is implemented as `EvaluationResult::explain(): string`.

### 5.5 Exceptions

| Exception                            | HTTP code | Raised when                                                                 |
|--------------------------------------|-----------|------------------------------------------------------------------------------|
| `AuthorizationException`             | 403       | `authorize()` denies                                                         |
| `InvalidPolicyDocumentException`     | 400       | A persisted policy document fails schema validation on parse                 |
| `UnknownRoleException`               | 404       | Role assignment/revocation targets a non-existent role                       |
| `UnknownPermissionException`         | 404       | Permission assignment/revocation targets a non-existent permission           |

All four extend `RuntimeException` (consistent with authentication's exception hierarchy) and expose immutable accessors for the inputs that triggered them.

---

## 6. Evaluation semantics (AWS IAM-style, 4-step)

### 6.1 Decision order

1. **Start at implicit deny.**
2. **Explicit deny (policy):** if any applicable policy statement matches and carries effect `DENY`, the result is `REASON_EXPLICIT_DENY`. Short-circuits the entire evaluation.
3. **Allow (policy or RBAC):** if any applicable policy statement matches with effect `ALLOW`, the result is `REASON_EXPLICIT_ALLOW`. Otherwise, if the principal has the action as a direct permission or inherits it via a role, the result is `REASON_RBAC_ALLOW`.
4. **Implicit deny:** otherwise, `REASON_IMPLICIT_DENY`.

Explicit deny in step 2 always wins, including over RBAC allows from step 3. The existing evaluator already implements 2 → 3 correctly; the manager must be rewritten so that RBAC is consulted **after** explicit deny has been ruled out but **before** implicit deny — not "only when no policies are configured" as the current seed does.

### 6.2 Wildcards

- Use `fnmatch` with default flags (the seed already does).
- `*` matches any characters including `:` — explicit in tests. The PRD acceptance criterion says wildcards should not match across segment separators "unless the wildcard is the entire segment". The v1.0.0 semantics are that `*` matches segment-separators by default but the `:*` suffix pattern is the idiomatic way to express "within this prefix only". Document and lock this in tests.
- Resources `['*']` is the default when omitted.

### 6.3 Laravel Gate auto-wiring

- Registered enums produce one Gate per case.
- Each Gate closure receives the `Authenticatable` user as its first argument (Laravel's standard) and must forward the check to `AuthorizationManager::for($user)->can($action)` — the current seed ignores the user and calls `can` against the globally-resolved principal, which silently breaks `$otherUser->can(...)` and `Gate::forUser($u)->allows(...)`.
- If a Gate with the same name already exists, the package logs a warning and does not overwrite. Configurable via `authorization.gate.on_conflict = log|overwrite|throw` (default `log`).

### 6.4 Condition operators

First-class operators shipped in v1.0.0:

| Operator        | Semantics                                                         |
|-----------------|-------------------------------------------------------------------|
| `eq`            | `===`                                                             |
| `neq`           | `!==`                                                             |
| `in`            | `in_array($actual, $operand, strict: true)`                       |
| `not_in`        | `!in_array($actual, $operand, strict: true)`                      |
| `cidr`          | IPv4 CIDR range containment (IPv6 added in a minor release)       |
| `starts_with`   | `str_starts_with`                                                 |
| `ends_with`     | `str_ends_with`                                                   |
| `before`        | ISO-8601 / Carbon-parseable comparison (`<`)                       |
| `after`         | ISO-8601 / Carbon-parseable comparison (`>`)                       |
| `between`       | Two-element range, inclusive                                      |

Missing context keys evaluate to false (no exception). Unknown operators short-circuit to false **and** emit a debug log line.

---

## 7. Database schema

Published migrations (UUID primary keys throughout; same `MigrationCollisionGuard` pattern as authentication):

| Table                       | Columns                                                                                                                                                      |
|-----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `roles`                     | `id` UUID PK, `name` unique-with-guard, `guard_name`, `description?`, timestamps                                                                             |
| `permissions`               | `id` UUID PK, `name` unique-with-guard, `guard_name`, `description?`, timestamps                                                                             |
| `policies`                  | `id` UUID PK, `name` unique, `document` JSON (statements), `description?`, timestamps                                                                        |
| `role_permissions`          | `role_id`, `permission_id` composite PK; FKs both sides, cascade delete                                                                                      |
| `authorizable_roles`        | `role_id`, polymorphic `authorizable_type` + `authorizable_id`; composite unique; indexed on `(authorizable_type, authorizable_id)`                           |
| `authorizable_permissions`  | `permission_id`, polymorphic `authorizable_type` + `authorizable_id`; composite unique; indexed                                                              |
| `authorizable_policies`     | `policy_id`, polymorphic `authorizable_type` + `authorizable_id`; composite unique; indexed                                                                  |

Design notes:

- Polymorphic columns are plain `string` (`authenticatable_type`, `authenticatable_id`), matching the authentication package's pattern, so ID types are portable across int / UUID / ULID identities.
- `guard_name` is retained for Spatie-compatibility; defaults to `'web'`.
- The `document` JSON column is validated on write via a model mutator that round-trips through `Policy::fromArray()`. A failing round-trip raises `InvalidPolicyDocumentException`.
- Table names are configurable via `authorization.tables.*` (same pattern as authentication's `device.table`).
- Configurable custom models via `authorization.models.*`.
- Every migration calls `MigrationCollisionGuard::ensureNotExists(...)` on `up()` to stay idempotent across matrix runs on persistent databases.

---

## 8. Configuration (`config/authorization.php`)

Single publishable config. Shape:

```php
return [
    'models' => [
        'role'       => Role::class,
        'permission' => Permission::class,
        'policy'     => Policy::class,
    ],

    'tables' => [
        'roles'                    => 'roles',
        'permissions'              => 'permissions',
        'policies'                 => 'policies',
        'role_permissions'         => 'role_permissions',
        'authorizable_roles'       => 'authorizable_roles',
        'authorizable_permissions' => 'authorizable_permissions',
        'authorizable_policies'    => 'authorizable_policies',
    ],

    'defaults' => [
        'guard' => env('AUTHORIZATION_DEFAULT_GUARD', 'web'),
    ],

    'permission_enums' => [
        // class-string<PermissionEnum>[]
    ],

    'gate' => [
        'on_conflict' => env('AUTHORIZATION_GATE_ON_CONFLICT', 'log'), // log | overwrite | throw
    ],

    'policy_store' => null, // optional class-string<PolicyStore>

    'principal_resolver' => NullPrincipalResolver::class,

    'cache' => [
        'store' => env('AUTHORIZATION_CACHE_STORE'),
        'ttl'   => (int) env('AUTHORIZATION_CACHE_TTL_SECONDS', 0),
    ],
];
```

> The current `config/authentication.php` file must be deleted and replaced with `config/authorization.php` shaped as above. The current migration `2026_04_06_000000_create_devices_table.php` must be deleted; it belongs to the authentication package.

---

## 9. Testing

### 9.1 Suite layout (`phpunit.xml.dist`)

Four suites, unchanged from the authentication structure:

- **Unit** — pure engine classes, no Testbench, no DB. `Statement`, `Policy`, `PolicyEvaluator`, `EvaluationResult`, `AuthorizationException`, `NullPrincipalResolver`, condition operators.
- **Feature** — Testbench-powered. Service provider boot, facade wiring, Gate auto-wiring, config merge, migrations publishing, role/permission/policy CRUD.
- **Integration** — cross-cutting scenarios. Polymorphic identities (distinct models sharing a role), Spatie migration scenario, principal resolver binding, Gate parity, DB matrix (MySQL + PostgreSQL + SQLite).
- **Performance** — query budgets. Evaluator throughput, RBAC lookup N+1 safety, policy JSON parse cost.

### 9.2 Coverage thresholds (PRD P0)

- ≥ 90% line coverage on `AuthorizationManager`, `PolicyEvaluator`, and the `Traits/*` classes.
- `composer test:coverage` produces `clover.xml` published to qlty via the `tests.yml` workflow on `master` pushes.

### 9.3 Stub/fixture policy

All stubs live under `tests/<Suite>/Stubs/` or `tests/<Suite>/Fixtures/` (same pattern as authentication). Integration fixtures that model different identity shapes (e.g. `StubUser`, `StubAdmin`, `StubServiceAccount`) are reused across the PRD's "polymorphic identity support" acceptance criterion.

### 9.4 Mutation testing

- **`infection.json5`:** scoped gate for the hot path — `PolicyEvaluator`, `AuthorizationManager`, `Statement`, `Traits/HasRoles`, `Traits/HasPermissions`, `Traits/HasPolicies`. Thresholds `--min-msi=85 --min-covered-msi=90`, identical to authentication's gate.
- **`infection.full.json5`:** full suite across `src/`, reported without thresholds on schedule and manual dispatch.

The current `infection.json5` exclusion list references authentication files (`AuthManager.php`, `Jwt/*`, etc.) and must be rewritten to target the authorization hot path.

### 9.5 Benchmarks (`phpbench`)

`benchmarks/` mirrors the `Runtime/` and `Support/` split from authentication. Required benches for v1.0.0:

| Bench                               | Measures                                                                |
|-------------------------------------|-------------------------------------------------------------------------|
| `Runtime/PolicyEvaluatorBench`      | Single-statement match, many-statement match, wildcard match, deny wins |
| `Runtime/AuthorizationManagerBench` | `can()` through Gate, `authorize()` through facade                      |
| `Runtime/RoleLookupBench`           | `$user->hasRole` / `$user->getPermissions` eager vs lazy                |
| `Runtime/PolicyParseBench`          | JSON → `Policy` round-trip                                              |

All authentication-specific benches (`JwtTokenServiceBench`, `BasicGuardBench`, `RefreshTokenExchangeBench`, `UpdateDeviceTimestampBench`, `JwtGuardBench`) and their harnesses must be deleted.

---

## 10. Continuous integration

Both workflows (`tests.yml`, `quality-gates.yml`) mirror authentication's structure. Authorization-specific changes:

### 10.1 `tests.yml`

- **Tests matrix:** PHP 8.3 × (Laravel 12.40, Laravel 13.3). Runs `composer test:coverage`. Publishes coverage to qlty on `master` pushes for Laravel 13.
- **Database matrix:** MySQL + PostgreSQL + SQLite (default in-memory). Database name renamed from `laravel_authentication_test` to `laravel_authorization_test`.

### 10.2 `quality-gates.yml`

- **`mutation` job:** runs on every PR/push — `composer test:mutation` against the scoped `infection.json5`.
- **`mutation-full` job:** scheduled Monday 07:00 UTC + manual dispatch — `composer test:mutation:full`.
- **`benchmarks` job:** scheduled + manual — `composer bench:ci`, uploads `build/phpbench.xml`.

The GitHub Actions step names and job labels change from "Laravel 13" branded as authentication to authorization-branded equivalents where they mention the package.

---

## 11. Design notes (`docs/design/`)

The authentication repo's design notes cover auth-specific invariants that do not apply here and must be deleted:

- `access-only-mode.md` — authentication-specific
- `fail-closed-pid-did.md` — authentication-specific
- `guard-lifecycle-and-events.md` — authentication-specific
- `refresh-rotation-and-replay.md` — authentication-specific

Replacement notes for authorization (same short-form structure — Purpose / Invariants / Success Path / Failure / Implementation Anchors / Authoritative Tests / Change Triggers):

- `evaluation-order-and-deny-precedence.md` — the 4-step IAM order; why explicit deny always wins.
- `polymorphic-identity-pivots.md` — why the pivots use string `authorizable_type`/`authorizable_id` columns.
- `principal-resolver-contract.md` — the standalone ↔ plug-and-play boundary with authentication.
- `wildcard-and-condition-semantics.md` — fnmatch flags, missing-key behaviour, CIDR / before / after.

The `docs/design/README.md` index is updated to list these four notes. Deletion of the authentication notes is part of the scrub.

---

## 12. Enterprise readiness

Non-functional requirements that apply to every release:

### 12.1 Determinism and auditability

- Every decision is reproducible from `(principal state, action, resource, context)` alone.
- `EvaluationResult::trace` is ordered, stable, and serialisable so audit logs can persist it verbatim.
- No hidden randomness; no time-based decision outside explicitly-configured `before`/`after`/`between` conditions (which read from `$context` or a fixed clock, never `time()` directly).

### 12.2 Performance

- Evaluator runs in O(statements) with no DB access — the manager loads policies once per request and evaluates in-memory.
- RBAC permission lookups use relation-caching on the model (`$user->permissions`, `$user->roles`) so repeat `can()` calls within one request avoid N+1.
- A `composer bench` run on a reference machine must complete within a published budget (codified in §10 benchmarks; thresholds locked in v1.0.0 release notes).

### 12.3 Security

- Policy documents are validated at write time and at read time. Invalid documents fail closed (denied) and raise `InvalidPolicyDocumentException` rather than partially evaluating.
- `PrincipalResolver::resolve()` returning `null` always results in implicit deny — never in "unauthenticated = unrestricted".
- The package never silently upgrades a permission check when a Gate is redefined.
- No global mutable state in the evaluator; `PolicyEvaluator` is a pure function across its inputs.

### 12.4 Observability

- All decisions are emittable via Laravel events (`DecisionEvaluated`, `AuthorizationFailed`, `RoleAssigned`, `RoleRevoked`, `PermissionGranted`, `PermissionRevoked`, `PolicyAttached`, `PolicyDetached`) — consumers can subscribe and forward to `sinemacula/laravel-audit-log` without the authorization package depending on it.
- Gate-conflict warnings are logged through Laravel's default logger on the `authorization` channel if configured, otherwise the default channel.

### 12.5 Compatibility

- Zero runtime dependency on any `sinemacula/laravel-*` package (enforced by CI check on `composer.json`).
- Works with any `Authenticatable` that implements `Authorizable` (or uses the shipped traits).
- Supports Spatie's `laravel-permission` migration idiom: `assignRole`, `givePermissionTo`, `hasPermissionTo` — implemented as aliases on the trait so a Spatie consumer can switch packages without rewriting every controller.
- Composer `replace` of `spatie/laravel-permission` is **not** declared — consumers opt into the migration explicitly.

### 12.6 Versioning and stability

- Public contracts in `Contracts/` and public trait method signatures are treated as SemVer stable. Breaking changes bump the major.
- The policy document schema (`Policy::fromArray`, `Statement::fromArray`) is versioned; breaking shape changes ship with a migration guide in `CHANGELOG.md` and, if needed, a document adapter.
- `PrincipalResolver` is locked before v1.0.0 so the umbrella package can wire it without reverification on every minor release.

---

## 13. Explicit deletions from the scrub

The following files were copied verbatim from `laravel-authentication` and are not relevant to this package. They must be deleted as part of the scrub:

**Source files** (already relocated under the `Example/` namespace in the authentication seed — not currently in this repo's `src/`, but referenced by the tests and benchmarks):

- Any file/directory under `src/` whose namespace prefix is not `SineMacula\Laravel\Authorization\` after the scrub.

**Config / database:**

- `config/authentication.php`
- `database/migrations/2026_04_06_000000_create_devices_table.php`

**Tests** (the entire authentication test suite — every file under `tests/Feature/`, `tests/Integration/`, `tests/Performance/`, and most of `tests/Unit/`):

- All files under `tests/Feature/*` (AuthManager, AuthServiceProvider, Cache, Facades, Guards, Jwt, Listeners, Models)
- All files under `tests/Integration/*` (Config, Events, Facade, Fixtures, Guards, Migration)
- All files under `tests/Performance/*` (Fixtures, JwtGuard budgets, UpdateDeviceTimestamp budget)
- All files under `tests/Unit/*` except brand-new authorization tests to be written

**Benchmarks:**

- `benchmarks/Crypto/JwtTokenServiceBench.php`
- `benchmarks/Runtime/BasicGuardBench.php`
- `benchmarks/Runtime/JwtGuardBench.php`
- `benchmarks/Runtime/RefreshTokenExchangeBench.php`
- `benchmarks/Runtime/UpdateDeviceTimestampBench.php`
- `benchmarks/Support/BasicGuardBenchHarness.php`
- `benchmarks/Support/BenchDatabase.php`
- `benchmarks/Support/ImmediateTimebox.php`
- `benchmarks/Support/JwtGuardBenchHarness.php`
- `benchmarks/Support/RefreshTokenExchangeBenchHarness.php`
- `benchmarks/Support/UpdateDeviceTimestampBenchHarness.php`

**Docs:**

- `docs/design/access-only-mode.md`
- `docs/design/fail-closed-pid-did.md`
- `docs/design/guard-lifecycle-and-events.md`
- `docs/design/refresh-rotation-and-replay.md`
- `docs/design/README.md` is kept and rewritten against the new note set (§11).

**Do NOT touch:**

- `README.md` — will be rewritten once the implementation lands.
- `.qlty/*` — tooling configuration is frozen per the project CLAUDE.md ("Do not change static analysis or formatting configuration without approval").
- `LICENSE`, `.editorconfig`, `.gitignore` — already correct for this repo.
- `NOTICE` — will be rewritten as part of this task; the content is boilerplate so it is in-scope.

---

## 14. Implementation phases (post-spec)

Derived from PRD #04's P0/P1/P2 and the compatibility contract. Not part of v1.0.0 scope decisions — recorded here only to make the scrub step's intent legible.

| Phase | Goal                                                                                              | Exit criterion                                                                                   |
|-------|---------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| 0     | Scrub and re-baseline — this SPECS.md, composer metadata, config/db/bench/test/ci scaffolding     | `composer install` runs; `composer check` is green on the minimal seed                            |
| 1     | Relocate the existing engine to the target namespace; add `PrincipalResolver` + null default      | Unit tests pass; evaluator has zero reference to `SineMacula\Laravel\Iam\Auth\*`                 |
| 2     | Ship Eloquent `Role` / `Permission` / `Policy` + migrations + Authorizable traits + integration   | PRD P0 acceptance criteria green on SQLite; DB matrix green on MySQL + PostgreSQL                |
| 3     | Gate auto-wiring fixed to forward the `Authenticatable` user; permission-enum binding path        | Gate parity integration test passes for every registered enum case                               |
| 4     | Performance + mutation gates                                                                      | `composer bench:ci` publishes artefact; scoped Infection meets `--min-msi=85 --min-covered-msi=90` |
| 5     | Docs (README, design notes, Spatie migration guide)                                               | PRD release-criteria checklist passes                                                            |

---

## 15. Open questions (to resolve before Phase 2 starts)

1. **Guard parameter on role/permission rows.** Spatie keyed every row by `guard_name`. Do we keep that for migration compatibility, or collapse it now and ship a migration guide?
2. **Soft deletes on roles/permissions/policies.** Authentication ships hard deletes on devices. Consistency says the same here — confirm before migration freeze.
3. **Policy versioning on the `policies.document` column.** Do we store a `version` attribute inside the JSON from v1.0.0 so a future schema change can be detected without a migration? (Low cost, high optionality — likely yes.)
4. **Gate conflict default.** `log` is the safe default, but `throw` would be the opinionated enterprise default. Lock in v1.0.0.
5. **Spatie API aliases.** Which Spatie method names do we alias on `HasRoles`/`HasPermissions`? Minimum is `assignRole`, `removeRole`, `givePermissionTo`, `hasPermissionTo`, `syncRoles`, `syncPermissions`. Full list to be finalised when the migration guide is drafted.

---

*End of spec.*
