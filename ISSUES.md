# `sinemacula/laravel-authorization` — Open Issues

**Source of truth for v1.0 scope.** Every item listed here is in scope for
the initial release. Historical references to `SPECS.md` / the PRD remain
inline where they add design context; the documents themselves have been
consumed into this file and removed from the repo.

---

## `README.md` is the wrong package's README

**Where:** `README.md` at repo root.

**Current shape:** the heading, badges, feature list, quick-start sections, and
design-note citations are all about `sinemacula/laravel-authentication` (the
sibling package) — not this package. Almost certainly a copy that was never
updated after the repo was split.

**Fix:** rewrite the README for `sinemacula/laravel-authorization`. The new
README should cover: the RBAC + AWS-IAM-style policy model, the four-step
evaluator (explicit deny → allow → RBAC → implicit deny), the enum-as-source-
of-truth catalogue (`permission_enums` config, `#[Permission]` attribute,
`authorization:sync`), the tenant-scope hook, the Gate / facade / middleware /
Blade surface, and a link into `docs/design/` for the authoritative notes.

Use the existing `README.md` as a layout template (badges, feature bullets,
installation, quick start) but replace every mention of JWT guards, devices,
refresh tokens, and principal contextualisation with authorization content.

**Scope:** `README.md` only. The `docs/design/` notes are correct.

**Where:** `src/Registrars/GateRegistrar.php`, `src/AuthorizationServiceProvider.php`,
`src/Contracts/PermissionEnum.php`, `src/Contracts/PermissionProvider.php`,
`src/Models/Permission.php`, `config/authorization.php`, `src/Console/`,
`database/migrations/`.

**Problem:** two sources of truth for the permission catalogue today: `authorization.permission_enums`
drives Laravel Gates but never touches the DB; `authorization.permission_providers`
runs `firstOrCreate` at boot for every provider-declared string. Consumers who want
both Gate support and queryable DB rows must declare every permission in two places.
Boot-time `firstOrCreate` also issues redundant DB writes on every request in
non-cached configurations, and there is no mechanism to remove permissions that no
longer exist in code.

**Design:** enum is the single source of truth. DB rows are a read-only projection produced by a
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

```text
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

```text
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
