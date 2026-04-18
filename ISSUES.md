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
