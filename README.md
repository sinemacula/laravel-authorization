# Laravel Authorization

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-authorization.svg)](https://packagist.org/packages/sinemacula/laravel-authorization)
[![Build Status](https://github.com/sinemacula/laravel-authorization/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-authorization/actions/workflows/tests.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-authorization/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authorization)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-authorization/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authorization)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-authorization.svg)](https://packagist.org/packages/sinemacula/laravel-authorization)

Role-based access control plus AWS IAM-style policy evaluation for Laravel. Ships Eloquent `Role`, `Permission`, and
`Policy` models, an immutable four-step policy evaluator (explicit deny → explicit allow → RBAC allow → implicit deny),
and a Laravel Gate auto-wiring layer driven by a consumer-declared permission enum.

The permission catalogue is enum-first: the enum is the source of truth, the database is a read-only projection, and
`authorization:sync` reconciles the two on deploy. The package has zero runtime dependencies on sibling IAM packages —
the `PrincipalResolver` contract is the only coupling point with authentication, and a shipped `NullPrincipalResolver`
keeps the package anonymous-safe by default. Tenant scoping, policy stores, cache stores, and every first-class model
are pluggable through the published config.

## Core Concept

The package is built around six concepts:

| Concept                   | What it is                                                                                                                                                          |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Authorizable Identity** | A model (or pivot) that holds roles, permissions, and policies. Any Eloquent model opts in by implementing `AuthorizableIdentity` and using `HasAuthorization`.     |
| **Role**                  | A named bundle of permissions. Optional `parent_id` enables inheritance; optional `rank` drives seniority checks for `canActOn()`.                                  |
| **Permission**            | An atomic action string keyed by `(name, guard)`. Declared as a case on a `PermissionEnum`; projected into the `permissions` table by `authorization:sync`.         |
| **Policy**                | A JSON document attached to an identity: `effect` (allow / deny), `actions`, `resources`, and optional `conditions`. Evaluated in-memory.                           |
| **Tenant**                | An optional multi-tenant scope. A `TenantResolver` returns the current tenant; roles and permissions are scoped automatically. `null` tenant means platform-global. |
| **Principal**             | The acting subject a decision is rendered for. Resolved via `PrincipalResolver`; `NullPrincipalResolver` ships for anonymous-safe defaults.                         |

The evaluator is immutable and ordered: explicit **deny** always wins, followed by explicit **allow**, then RBAC
**allow** (including wildcards), then **implicit deny**. Policy-layer denials cannot be overridden by an RBAC wildcard.

## Features

- **Four-step policy evaluator** — explicit deny → explicit allow → RBAC allow → implicit deny, with the last decision
  available for introspection via `Authorization::lastDecision()` and `Authorization::explain()`
- **Enum-driven permission catalogue** — consumers declare a backed string enum implementing `PermissionEnum` and
  annotate cases with `#[Permission(description, category, guards)]`
- **Deploy-time sync** — `authorization:sync` projects the enum into the `permissions` table, with `add` / `update` /
  `reinstate` / `retire` / `protected` / `unchanged` buckets, JSON output for CI, and a `--dry-run` mode that exits
  non-zero on drift
- **Deprecated-not-deleted lifecycle** — retired rows are stamped `deprecated_at` so pivots stay intact and audit
  history survives; `authorization:prune-deprecated` is the explicit follow-up
- **System-row protection** — `is_system = true` rows are untouched by sync and prune, and refuse renames or deletes
  unless explicitly unlocked
- **Tenant-scope hook** — `AuthorizableTenant` plus `TenantResolver` auto-filters rows by the resolved tenant through
  shipped global and local scopes; `null` tenant is platform-global
- **Laravel Gate integration** — every configured permission case becomes a Gate, so `Gate::allows('posts:edit')`,
  `$user->can('posts:edit')`, `@can('posts:edit')`, and the `can:` route middleware all light up automatically
- **`Authorization` facade** — `Authorization::can(...)`, `Authorization::for($user)->can(...)`,
  `Authorization::authorize(...)`, `Authorization::evaluate(...)`, `Authorization::effectivePermissions(...)`,
  `Authorization::withPolicies(...)`, works with a null principal
- **Route middleware aliases** — `role:admin`, `permission:posts:edit`, registered automatically when the Laravel
  router is available
- **Blade directives** — `@role` / `@permission` quartet plus Spatie-compat aliases
- **Wildcard permissions** — `fnmatch` with `FNM_NOESCAPE`; held pattern matches asked literal (`posts:*` satisfies
  `posts:create`), `*:*` is the canonical super-admin grant
- **Rich condition catalogue** — `eq`, `neq`, `in`, `not_in`, `cidr`, `starts_with`, `ends_with`, `before`, `after`,
  `between`; missing context keys fail closed, unknown operators evaluate to `false`
- **Role inheritance and rank** — optional parent-child permission union, optional rank-based seniority enforced by
  `canActOn()`; both togglable in config
- **Resolution cache** — two-tier (always-on in-memory memoisation plus optional persistent cache store) with
  event-driven invalidation
- **Spatie migration path** — `authorization:migrate-spatie` brings rows across from the `laravel-permission` schema
- **Introspection commands** — `authorization:list-roles`, `authorization:list-permissions`,
  `authorization:grant-role`, `authorization:revoke-role`, `authorization:why-can`
- **SemVer-stable event surface** — lifecycle events for `Role`, `Permission`, `Policy`, and identity pivots, plus
  `DecisionEvaluated` and `AuthorizationFailed` for the evaluation pipeline
- **Pluggable everywhere** — models, principal resolver, tenant resolver, policy store, cache store, table names,
  pivot column names, default guard, gate conflict policy

## Installation

```bash
composer require sinemacula/laravel-authorization
php artisan vendor:publish --tag=authorization-config
php artisan vendor:publish --tag=authorization-migrations
php artisan migrate
```

## Declaring Permissions

Declare a backed string enum implementing `PermissionEnum` and annotate each case with the `#[Permission]` metadata
attribute. Alias the attribute import — `Attributes\Permission` and `Models\Permission` share the unqualified name.

```php
namespace App\Enums;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

enum Permission: string implements PermissionEnum
{
    #[PermissionMeta(description: 'View applications', category: 'Applications', guards: ['web', 'api'])]
    case VIEW_APPLICATIONS = 'applications:view';

    #[PermissionMeta(description: 'Edit applications', category: 'Applications')]
    case EDIT_APPLICATIONS = 'applications:edit';
}
```

Register the enum:

```php
// config/authorization.php
'permission_enums' => [
    App\Enums\Permission::class,
],
```

Project the catalogue into the `permissions` table on every deploy:

```bash
php artisan authorization:sync
```

Sync is idempotent — a run against an already-synced database is a no-op with every tuple reported as `unchanged`. A
case removed from the enum stamps `deprecated_at` on the corresponding row; the row stays queryable via
`Permission::withDeprecated()` but is filtered out of gate evaluation by `ExcludesDeprecatedScope`. Use
`authorization:prune-deprecated` as the explicit follow-up when you want to cut the cord.

## Authorizing a Request

Two surfaces, same evaluator. The native Laravel surface requires at least one configured enum (Laravel's Gate only
dispatches to actions it has been told about). The facade works out of the box against a null principal.

```php
// Native Laravel surface
Gate::allows('applications:view');
$user->can('applications:view');
```

```blade
@can('applications:view')
    {{-- ... --}}
@endcan
```

```php
// Route middleware
Route::get('/apps', ...)->middleware('can:applications:view');
Route::get('/admin', ...)->middleware('role:admin');
Route::post('/apps', ...)->middleware('permission:applications:edit');
```

```php
// Package facade - works with a null principal
use SineMacula\Laravel\Authorization\Facades\Authorization;

Authorization::can('applications:view');
Authorization::for($user)->can('applications:view');
Authorization::authorize('applications:edit', $resource);
Authorization::evaluate('applications:view', $resource, ['tenant' => 'org-42']);
Authorization::explain('applications:view'); // Human-readable trace
```

## Model Integration

Any Eloquent model opts in by implementing `AuthorizableIdentity` and using the `HasAuthorization` trait (which
composes `HasRoles`, `HasPermissions`, and `HasPolicies`):

```php
use Illuminate\Foundation\Auth\User as Authenticatable;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Traits\HasAuthorization;

class User extends Authenticatable implements AuthorizableIdentity
{
    use HasAuthorization;
}
```

Polymorphic identity pivots are supported — see `docs/design/polymorphic-identity-pivots.md` for the patterns the
package ships with.

## Policy Documents

Attach JSON policies to any authorizable identity. Each statement has an `effect`, an `actions` list, a `resources`
list, and optional `conditions`. Both `actions` and `resources` use `fnmatch` with `FNM_NOESCAPE`; the **held** pattern
is matched against the **asked** literal.

```json
{
  "effect": "allow",
  "actions": ["billing:*"],
  "resources": ["*"],
  "conditions": {
    "tenant": { "eq": "org-42" },
    "source_ip": { "cidr": "10.0.0.0/8" }
  }
}
```

Condition operators: `eq`, `neq`, `in`, `not_in`, `cidr`, `starts_with`, `ends_with`, `before`, `after`, `between`.
Missing context keys cause the condition to fail (not throw); unknown operators evaluate to `false`. See
`docs/design/wildcard-and-condition-semantics.md` for the full semantics.

## Tenant Scoping

Implement `AuthorizableTenant` on your tenant model and bind a `TenantResolver` that returns the current tenant. The
shipped global and local scopes auto-filter roles and permissions by the resolved tenant, and a `null` tenant means
platform-global visibility.

```php
// config/authorization.php
'tenant_resolver' => App\Auth\Resolvers\CurrentTenantResolver::class,
```

The default binding is `NullTenantResolver`, which disables tenant scoping — all roles and permissions are visible
regardless of ownership.

## Design Notes

The quick-start surface above is adoption-focused. The maintainer-oriented contracts and invariants live in
`docs/design/` and cite the concrete implementation paths and authoritative tests:

- `docs/design/enum-sync.md` — enum-as-source-of-truth model, sync command, deprecation lifecycle
- `docs/design/evaluation-order-and-deny-precedence.md` — four-step evaluator contract and deny precedence
- `docs/design/impersonation.md` — scope semantics for `Authorization::for(...)`
- `docs/design/model-extension.md` — swapping any of the three first-class models
- `docs/design/polymorphic-identity-pivots.md` — attaching roles, permissions, and policies to pivots
- `docs/design/principal-resolver-contract.md` — the authentication coupling point
- `docs/design/spatie-compatibility.md` — migration path from `spatie/laravel-permission`
- `docs/design/wildcard-and-condition-semantics.md` — `fnmatch` direction, `FNM_NOESCAPE`, condition operator catalogue

## Migrating from Spatie

A migration command is shipped for consumers coming from `spatie/laravel-permission`. Run
`php artisan authorization:migrate-spatie` to project Spatie's row shape into the authorization package's schema. The
parity surface (Blade directive aliases, default guard, column names) is covered in
`docs/design/spatie-compatibility.md`.

## Requirements

- PHP ^8.3
- Laravel ^12.0 || ^13.0

## Testing

```bash
composer test
composer test:coverage
composer check
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on branching, commits, code
quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for the
disclosure policy and contact details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
