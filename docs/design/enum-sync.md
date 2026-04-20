# Enum-Driven Permission Catalogue

The package treats the permission enum as the single source of truth for the catalogue. Consumers declare a backed
string enum implementing `PermissionEnum`; the enum is wired into Laravel's `Gate` surface on boot, and projected into
the `permissions` database table by a deploy-time `authorization:sync` command. The database is a read-only projection
of the enum — consumers query it for rich listing, filtering, and pagination through their own API layer, but never
mutate it at runtime.

## Invariants

1. **The enum is authoritative.** Every permission a gate, middleware, or resolver can check is declared as a case on
   a configured enum. A permission that exists in the database but not in any enum is either `is_system = true`
   (platform-protected) or deprecated.

2. **Enums are backed string enums.** The case value is the canonical permission name. `PermissionEnum` extends
   `\BackedEnum`, so PHP rejects unit-enum `implements` at parse time. `ConfigValidator::validatePermissionEnums`
   additionally rejects int-backed enums at boot.

3. **Sync runs at deploy, not boot.** The service provider registers gates on boot but never writes to the database.
   `authorization:sync` is the only path that mutates permission rows.

4. **Deprecation is a state, not a delete.** When a case is removed from an enum, sync stamps `deprecated_at` on the
   row. Role and identity pivots stay intact so audit history survives and operators can decide when to prune.
   `ExcludesDeprecatedScope` filters deprecated rows out of every gate evaluation, so a deprecated permission is never
   effective even while attached to a role.

5. **`is_system = true` rows are untouched.** Neither sync nor prune mutates a system row. Platform-shipped
   permissions that predate the current enum declaration are reported in the `protected` bucket.

## Consumer Workflow

### 1. Declare the enum

```php
namespace App\Enums;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

enum Permission: string implements PermissionEnum
{
    #[PermissionMeta(description: 'View applications', category: 'Applications', guards: ['web', 'api'])]
    case VIEW_APPLICATIONS = 'applications:view';

    #[PermissionMeta(description: 'Edit applications', category: 'Applications', guards: ['web'])]
    case EDIT_APPLICATIONS = 'applications:edit';

    case VIEW_DEMO = 'demo:view'; // No attribute — metadata defaults to null; guard-agnostic.
}
```

The attribute alias (`PermissionMeta`) is a convention — `Attributes\Permission` and `Models\Permission` share the
unqualified name, so every consumer that imports both aliases one of them.

### 2. Register the enum in config

```php
// config/authorization.php
'permission_enums' => [
    App\Enums\Permission::class,
],
```

`ConfigValidator` runs on boot and will raise a typed `InvalidAuthorizationConfigException` if the class is not a
backed string enum implementing `PermissionEnum`. A deploy fails before any request is served.

### 3. Project to the database

```bash
php artisan authorization:sync
```

Sync walks each configured enum, reads the `#[Permission]` attribute on every case, and projects the resulting
`(name, guard, description, category)` tuples into the `permissions` table. `guards: null` (or omitted) produces a
single guard-agnostic row; `guards: ['web', 'api']` produces one row per guard.

Run it on every deploy. It is idempotent — a run against an already-synced database is a no-op with every tuple
reported as `unchanged`.

### 4. Query from the API

The package ships no controllers. The typical pattern in the host application:

```php
// routes/api.php
Route::get('/permissions', function () {
    return Permission::query()
        ->when(request('category'), fn ($q, $v) => $q->where('category', $v))
        ->when(request('guard'), fn ($q, $v) => $q->where('guard', $v))
        ->orderBy('category')
        ->orderBy('name')
        ->paginate();
});
```

The `ExcludesDeprecatedScope` is applied automatically. Admin consoles that need the full catalogue call
`Permission::withDeprecated()->...` to bypass it.

## Sync Command

```text
authorization:sync
    [--dry-run]            Compute and report the diff without writing
    [--format=table|json]  Output format
    [--force-delete]       Hard-delete retired rows instead of stamping deprecated_at
```

### Algorithm

1. Load every class listed in `authorization.permission_enums`.
2. Walk each enum via `PermissionEnumWalker` → `list<PermissionTuple>`.
3. Load current global rows (`tenant_id IS NULL`) including deprecated.
4. Pre-compute the role-reference count for retire candidates.
5. Build the diff via `PermissionDiffBuilder`. Six buckets:
    - **Add** — tuple has no matching row.
    - **Update** — tuple matches a live row; metadata differs.
    - **Reinstate** — tuple matches a deprecated row; `deprecated_at` is cleared and metadata refreshed.
    - **Retire** — row has no matching tuple and `is_system = false`; `deprecated_at` is stamped (or the row is
      deleted under `--force-delete`).
    - **Protected** — row has no matching tuple and `is_system = true`; reported, never touched.
    - **Unchanged** — tuple matches a live row, metadata identical.
6. Apply the diff inside a single `DB::transaction`. Each action fires the relevant event (see below).
7. Flush `ResolutionCache::flush()` after a successful mutating run.

### Events

| Bucket                    | Event                                                           | Notes                                              |
|---------------------------|-----------------------------------------------------------------|----------------------------------------------------|
| Add                       | `Events\Permission\Created`                                     | Via `PermissionObserver`                           |
| Update                    | `Events\Permission\Updated`                                     | Via `PermissionObserver`                           |
| Reinstate                 | `Events\Permission\Updated` + `Events\Permission\Reinstated`    | The lifecycle event on top of the observer event   |
| Retire (soft)             | `Events\Permission\Deprecated`                                  | Manual dispatch; observer does not fire            |
| Retire (`--force-delete`) | `Events\Permission\Deleted`                                     | Via `PermissionObserver`                           |
| Protected                 | (none)                                                          |                                                    |
| Unchanged                 | (none)                                                          |                                                    |

All four events are `@api` and SemVer-stable.

### Exit codes

| Code | Meaning                                                                                       |
|------|-----------------------------------------------------------------------------------------------|
| 0    | Clean run, or `--dry-run` with no drift                                                       |
| 1    | `--dry-run` detected drift (any of `add` / `update` / `reinstate` / `retire` non-empty)       |
| 2    | Fatal error (bad config, invalid `--format`, invalid `#[Permission(guards: [])]` attribute)   |

CI pipelines can pipe `--dry-run --format=json` to a checker, parse the `summary`, and fail on non-zero exit.

### Tenant scope

Sync operates on **global rows only** (`tenant_id IS NULL`). Tenant-specific permissions, if a consumer creates any
outside the enum catalogue, are out of scope.

## Prune Command

```text
authorization:prune-deprecated
    [--before=<ISO-8601>]  Prune only rows deprecated at or before this instant
    [--dry-run]            Report without touching the DB
    [--format=table|json]  Output format
```

For each deprecated, non-system, global permission row: detach all role pivots, detach all identity pivots, delete
the row (which fires `Events\Permission\Deleted` through the observer), and flush the resolution cache.

`is_system = true` rows never appear in the candidate list, even for reporting. `--dry-run` always exits 0 — prune is
advisory. An unparseable `--before` value exits 2.

Keep prune manual. Sync leaves the pivots intact so the operator can see what still depends on a retired permission
before cutting the cord.

## Implementation Anchors

- Attribute: `src/Attributes/Permission.php`
- Reader: `src/Support/PermissionMetadataReader.php`
- Enum walker: `src/Console/Support/PermissionEnumWalker.php`
- Diff builder: `src/Console/Support/PermissionDiffBuilder.php`
- Sync command: `src/Console/SyncPermissionsCommand.php`
- Prune command: `src/Console/PrunePermissionsCommand.php`
- Deprecation scope: `src/Scopes/ExcludesDeprecatedScope.php` (wired via `#[ScopedBy]` on `Permission`)
- Events: `src/Events/Permission/Deprecated.php`, `src/Events/Permission/Reinstated.php`
- Config validator: `src/Config/ConfigValidator.php::validatePermissionEnums`
- Exception: `src/Exceptions/InvalidPermissionAttributeException.php`

## Authoritative Tests

- `tests/Unit/Console/Support/PermissionDiffBuilderTest.php` — every bucket, ordering, null-guard collapse.
- `tests/Unit/Console/Support/PermissionEnumWalkerTest.php` — attribute expansion, empty-guards error.
- `tests/Unit/Attributes/PermissionTest.php`, `tests/Unit/Support/PermissionMetadataReaderTest.php`.
- `tests/Feature/SyncPermissionsCommandTest.php` — fresh install, idempotence, drift, dry-run, JSON, force-delete,
  role-reference reporting, protected rows.
- `tests/Feature/PrunePermissionsCommandTest.php` — pivot detachment, system protection, `--before` filter.
- `tests/Feature/ExcludesDeprecatedScopeTest.php`, `tests/Integration/DeprecatedPermissionsTest.php` — gate parity
  under deprecation.

## Change Triggers

Update this note when any of the following changes:

- The `#[Permission]` attribute gains or loses a field.
- A new diff bucket is introduced or an existing one changes semantics.
- Sync or prune gains a new flag or changes exit-code behaviour.
- Events are renamed, added, or removed.
- The tenant-scope restriction is lifted.
- The deprecation-retain-versus-delete default changes.
