# `sinemacula/laravel-authorization` — Open Issues

**Source of truth for v1.0 scope.** Every item listed here is in scope for
the initial release. Historical references to `SPECS.md` / the PRD remain
inline where they add design context; the documents themselves have been
consumed into this file and removed from the repo.

---

## Naming flags (commit review)

### `src/` enforcement — accepted deviations (2026-04-17)

The `/build:enforce src/` scanner raised the following naming findings that were
reviewed and intentionally not applied. All are `detect-only` per the PHP pack.

- **`AuthorizationManager`** (`php-nam-034`, Low) — the `Manager` suffix is
  flagged as a generic filler. Rejected: the class is the package's primary
  entry point and mirrors Laravel's own `AuthManager` / `DatabaseManager`
  pattern; a domain-specific alternative (e.g. `AuthorizationCoordinator`) is
  less discoverable than the framework-idiomatic name.

- **`EvaluationResult`** (`php-nam-007`, `php-nam-039`, Low) — directory
  context `Evaluation/` is said to carry the prefix. Rejected: `Result` on its
  own is ambiguous at call sites (conflicts with assertion-library and
  standard-library idioms); the qualified name carries semantic weight even
  imported.

- **`ConfigValidator`** (`php-nam-007`, `php-nam-039`, Low) — directory context
  `Config/` is said to carry the prefix. Rejected for the same readability
  reason; a top-level `Validator` class would be misinterpreted as a generic
  input validator.

- **`bool $dryRun` parameter** in five private `MigrateSpatieCommand` helpers
  (`php-nam-035`, Low × 5) — the pack rule discourages boolean parameters.
  Rejected: the `--dry-run` flag is a long-standing Laravel/Symfony console
  convention carried through private migration helpers; replacing with an enum
  would add ceremony for a well-understood primitive without improving
  readability.

Rules `php-nam-007`, `php-nam-034`, `php-nam-035`, and `php-nam-039` have been
considered; remaining findings in the same categories were addressed by the
event-class renames in this commit.

---

## `MigrationCollisionGuard` should be an instance with an injected `Builder`

**Where:** `src/Database/MigrationCollisionGuard.php`.

**Current shape:** `final class` with a static `ensureNotExists(string $table)`
method that reaches for the `Schema` facade directly.

**Why change it:** the sibling `sinemacula/laravel-authentication` package's
`MigrationCollisionGuard` is a `final readonly class` with a constructor-
injected `Illuminate\Database\Schema\Builder`. That shape is trivially
mockable — tests can construct the guard with a fake schema without global
facade state. The authorization version can only be tested by swapping the
facade's bound instance at runtime.

**Fix:** mirror the authentication shape — promote to `final readonly class`,
inject `Builder $schema` via constructor property promotion, drop the facade
call, instantiate the guard where the migration currently calls
`MigrationCollisionGuard::ensureNotExists(...)` statically.

**Scope:** the migrations under `database/migrations/` call the static entry
point — they are the only production call sites. Tests under
`tests/Feature/MigrationCollisionGuardTest.php` (if it exists) need the same
adjustment.

---

## Column-name verbosity audit

**Where:** all tables under `database/migrations/`.

**Current shape:** `permissions.guard_name` (and any sibling `guard_name`
columns on related tables, e.g. `roles`). Spatie inherited `_name` suffix
where the column already describes a named thing.

**Why change it:** the suffix is redundant — `guard_name` holds a guard
identifier, `guard` says that more concisely and matches idiomatic Laravel
column naming (`type`, `name`, `role`, not `type_name`, `name_name`,
`role_name`). Shorter columns read better in queries, joins, and API
payloads.

**Fix:** audit every migration for similarly verbose column names.
Confirmed candidates: `guard_name` on `permissions` (and on any other table
that mirrors it). Rename to `guard`. Pre-release — no BC path required;
update migrations, models, queries, and the Spatie migrate command.
Non-candidates (keep as-is): `description`, `category`, `rank`, `parent_id`.

**Scope:** migrations, `Permission` / `Role` models, any raw queries or
scopes referencing `guard_name`, the `MigrateSpatieCommand` mapping, and
tests/docs that assert column names.

---

## Consolidate `add_*_to_*_table` migrations into their base creates

**Where:** `database/migrations/`.

**Current shape:** thirteen migrations, synthetic timestamps all dated `2026_04_14_*`,
of which seven are `add_X_to_Y_table` patches on tables whose `create_Y_table` file
sits immediately above them. Two migrations share the number `000010`
(`add_category_to_permissions_table` and `add_parent_id_to_roles_table`), which
confirms the splits were incremental development moves, not release-boundary
discipline.

**Why change it:** the package has not shipped. There is no production state to
preserve, so the ordinary rule — "never edit a run migration" — does not bind. A
fresh `composer require` consumer currently runs thirteen migrations to arrive at
a schema that can be described in seven. Reviewers reading the schema have to
stitch column sets together across multiple files instead of reading a single
`create_*_table` that captures the final v1.0 shape.

**Fix:** fold the `add_*_to_*_table` migrations into their parent `create_*_table`
migrations, deleting the patch files. Target layout:

- `create_roles_table` absorbs `is_system`, `parent_id`, `rank`, and the tenant
  columns.
- `create_permissions_table` absorbs `is_system`, `category`, the tenant columns,
  the upcoming `deprecated_at`, and the `guard_name` → `guard` rename.
- `create_policies_table` absorbs `is_system`.

Bundle this with the enum-sync work — that work already touches
`create_permissions_table`, so folding at the same time avoids a second pass.

**Scope:** every `add_*_to_*_table` file under `database/migrations/`, plus any
test that depends on a specific migration file name or invokes migrations
individually.

---

## Migration docblocks should sit above the anonymous class, not the file

**Where:** every file under `database/migrations/`.

**Current shape:** the descriptive docblock is placed at the top of the file,
before `declare(strict_types = 1)`. Example —
`2026_04_14_000001_create_roles_table.php`:

```php
<?php

/**
 * Create the `roles` table.
 * ...
 */

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
// ...

return new class extends Migration {
```

**Why change it:** a file-level docblock attaches to nothing in PHP's reflection
model — it documents "the file," which has no symbol. Moving it onto the
anonymous class makes the docblock a real class docblock, discoverable via
reflection, and matches the sibling `laravel-authentication` package's
convention.

**Fix:** move the docblock so it precedes `return new class extends Migration {`,
separated by a blank line (PHP-CS-Fixer does not recognise the anonymous class
as a class symbol and will reject a docblock sitting flush against the return):

```php
<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
// ...

/**
 * Create the MFA factors table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */

return new class extends Migration {
```

Scope every file uniformly. Retain the existing copy/attribution content; only
the position changes.

**Scope:** every file under `database/migrations/`. No code changes — docblock
relocation only.

---

## SPEC — Permission enum as single source of truth

**Where:** `src/Registrars/GateRegistrar.php`, `src/AuthorizationServiceProvider.php`,
`src/Contracts/PermissionEnum.php`, `src/Contracts/PermissionProvider.php`,
`src/Models/Permission.php`, `config/authorization.php`, `src/Console/`,
`database/migrations/`.

**Problem**

Two sources of truth for the permission catalogue today: `authorization.permission_enums`
drives Laravel Gates but never touches the DB; `authorization.permission_providers`
runs `firstOrCreate` at boot for every provider-declared string. Consumers who want
both Gate support and queryable DB rows must declare every permission in two places.
Boot-time `firstOrCreate` also issues redundant DB writes on every request in
non-cached configurations, and there is no mechanism to remove permissions that no
longer exist in code.

**Design**

Enum is the single source of truth. DB rows are a read-only projection produced by a
deploy-time sync command. Roles, identities, and grants remain runtime-mutable via
the normal Eloquent surface; permission rows themselves are only mutated by sync.

### 1. Enum contract

`PermissionEnum` stays a marker interface (no methods). New runtime constraint:
the enum MUST be a backed string enum. `ConfigValidator::validatePermissionEnums`
is extended to reject unit enums with a typed exception naming the class.

The case value is the canonical permission name. Developers own the shape
(`applications:view`, `edit_posts`, `tickets.assign`) — the library performs no
derivation.

### 2. Per-case metadata attribute

```php
namespace SineMacula\Laravel\Authorization\Attributes;

#[\Attribute(\Attribute::TARGET_CLASS_CONSTANT)]
final readonly class Permission
{
    /**
     * @param  list<string>|null  $guards
     */
    public function __construct(
        public ?string $description = null,
        public ?string $category    = null,
        public ?array  $guards      = null,
    ) {}
}
```

Applied per case:

```php
use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;

enum Permission: string implements PermissionEnum
{
    #[PermissionMeta(description: 'View applications', category: 'Applications', guards: ['web', 'api'])]
    case VIEW_APPLICATIONS = 'applications:view';
}
```

Resolution rules:

- Missing attribute → all fields null; one row per case with `guard_name = null`.
- `guards: null` or omitted → one row with `guard_name = null` (guard-agnostic).
- `guards: ['web', 'api']` → two rows, one per guard.
- Empty array (`guards: []`) is invalid; sync raises a typed exception.

Clash note: `Models\Permission` and `Attributes\Permission` share the unqualified
name. Consumers alias on import as shown above; docs carry the pattern.

### 3. Schema changes

Additive migration on the existing `permissions` table:

- `deprecated_at` nullable timestamp, indexed.

Separately tracked in this file: `guard_name` → `guard` rename.

No new columns for `description` or `category` — both already exist
(`2026_04_14_000002_create_permissions_table.php`,
`2026_04_14_000010_add_category_to_permissions_table.php`).

### 4. `authorization:sync` command

Signature:

```
authorization:sync
    [--dry-run]
    [--format=table|json]
    [--force-delete]
```

Algorithm:

1. Load every class listed in `authorization.permission_enums` (validator guarantees
   they are backed string enums implementing `PermissionEnum`).
2. Walk each case; read `#[Permission]` attribute via `ReflectionEnumUnitCase::getAttributes`.
3. Expand each case into `(name, guard)` tuples. `guards=null` yields one tuple
   with `guard=null`.
4. Load the current global (tenant-null) permission rows into memory.
5. Compute the diff:
    - **Add** — tuple in enum state, no matching row in DB.
    - **Update** — tuple matches a row but metadata (description, category) differs.
    - **Reinstate** — tuple matches a row whose `deprecated_at` is set; clear it and
      update metadata.
    - **Retire** — row present in DB with no matching tuple and `is_system = false`;
      stamp `deprecated_at = now()` unless `--force-delete`.
    - **Protected** — row with `is_system = true` has no matching tuple; report and
      leave untouched.
    - **Unchanged** — tuple matches a row, metadata identical, not deprecated.
6. Summary output: counts in the six buckets plus a `role_references` count (number of
   role-permission pivots attached to retired rows — reporting only).
7. Flush permission lookup caches at the end of a mutating run.

Flags:

- `--dry-run` — no DB writes. Non-zero exit (1) if any of `add`/`update`/`retire`/
  `reinstate` are non-zero. Used by CI.
- `--format=json` — emits the summary as structured JSON for pipeline consumption.
  Default `table`.
- `--force-delete` — retire bucket performs hard DELETE instead of `deprecated_at`
  stamp. Still leaves `is_system` rows alone. Role pivots are ORM-cascaded per the
  existing FK definition. Surface a confirmation prompt unless `--no-interaction`.

Exit codes: `0` no drift (or clean sync); `1` drift found in `--dry-run`; `2` fatal.

Tenant scope: sync operates on global permissions only (`tenant_id IS NULL`).
Tenant-specific permissions, if any consumer creates them, are out of scope.

### 5. Deprecation semantics

- `deprecated_at IS NOT NULL` rows are excluded from every gate evaluation. A global
  query scope on the `Permission` model (e.g. `ExcludesDeprecatedScope`) filters them
  on the hot path. The scope is applied by default; an opt-in method
  (`withDeprecated()`) reveals them for admin APIs.
- Role pivots are never detached by `sync`. Sync reports the attachment count; the
  operator decides when to prune.
- Emit a domain event (`PermissionDeprecated`, `PermissionReinstated`,
  `PermissionDeleted`) for each state transition. Existing event infrastructure in
  `src/Events/` is the pattern.

### 6. `authorization:prune-deprecated` command

Follow-up command, not tied to sync cadence:

```
authorization:prune-deprecated
    [--before=<ISO-8601>]   # only prune rows deprecated before this timestamp
    [--dry-run]
```

Walks deprecated permission rows, detaches role and identity pivots, then deletes
the row. Same `is_system` protection as sync.

### 7. Removals

- `authorization.permission_providers` config key.
- `SineMacula\Laravel\Authorization\Contracts\PermissionProvider` interface.
- `AuthorizationServiceProvider::registerPermissionProviders()` method.
- `ConfigValidator::validatePermissionProviders()` and its tests.
- Any docs or examples referencing the provider pattern.

Boot no longer writes to the DB. `registerPermissionProviders()` removed from the
boot chain entirely.

### 8. API guidance (docs only)

- `GET /permissions` — read-only, filterable by `category`, `guard`, `deprecated_at`.
- No write endpoints for permissions.
- Roles and identity grants remain runtime-mutable.

Example `index` action, Resource class, and query scope appear in the docs; the
package does not ship a controller.

### 9. Config shape (unchanged interface)

```php
'permission_enums' => [
    App\Enums\Permission::class,
],
```

Validator rules:

- Array of class-strings.
- Each class exists and implements `PermissionEnum`.
- Each class is a backed string enum (new rule).

### 10. Acceptance criteria

- A backed string enum with no attributes syncs to `(name=<case value>, guard=null)`
  rows. `description` and `category` are null.
- A case with `#[Permission(description, category, guards: [a, b])]` produces two
  rows, one per guard, populated metadata.
- A second `sync` against the same state issues zero writes and reports all tuples
  as `unchanged`.
- Removing a case and rerunning sync stamps `deprecated_at` on the row; role pivots
  remain; report names the pivot count.
- Re-adding the case clears `deprecated_at` and refreshes metadata.
- `sync --dry-run` exits 1 when drift exists.
- `sync --dry-run --format=json` produces parseable structured output suitable for
  CI assertions.
- Gate evaluation returns false for a deprecated permission even when a role grants
  it; verified in an integration test.
- `is_system` rows are never retired or hard-deleted by sync; they surface in the
  `protected` bucket when absent from enums.
- `permission_providers` config entry, removed between releases, causes no errors
  (key is dropped, not warned on).
- Config validator rejects unit enums with a message naming the class.

### 11. Work breakdown

1. `#[Permission]` attribute + reflection reader (`Support\PermissionMetadataReader`).
2. `deprecated_at` migration + `Permission` model scope + `withDeprecated()` escape hatch.
3. Diff engine (`Console\Support\PermissionDiffBuilder` or similar) — pure function,
   enum state in, diff out.
4. `authorization:sync` command wiring the diff engine to the DB, emitting events.
5. `authorization:prune-deprecated` command.
6. Extend `ConfigValidator` with the backed-enum rule.
7. Remove `PermissionProvider` contract, `registerPermissionProviders()`, and
   `permission_providers` config.
8. Gate evaluation path excludes deprecated rows; integration test covers parity.
9. Docs: attribute usage, sync lifecycle, API guidance, deprecation model.
10. Test matrix: unit (attribute reader, diff engine), feature (sync lifecycle,
    prune), integration (gate parity), performance (1000-case sync budget).

### 12. Out of scope

- Manifest file / committed catalogue snapshot. `--dry-run --format=json` covers
  CI drift detection; consumers who want a committed artefact redirect the output
  themselves.
- Tenant-specific sync — sync is global-only.
- API controllers/resources for `GET /permissions` — docs pattern only.
- Any secondary grouping axis beyond `category`. Consumers encode hierarchy into the
  `category` string (`billing.invoicing`) or add their own column.
- Per-case deprecation flags on the attribute. Deprecation is derived from enum
  state (case absent = deprecated); keeping both the attribute and the derived
  state creates two competing signals.
