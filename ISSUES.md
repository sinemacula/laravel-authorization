# `sinemacula/laravel-authorization` — Open Issues

**Source of truth for v1.0 scope.** Every item listed here is in scope for
the initial release. Historical references to `SPECS.md` / the PRD remain
inline where they add design context; the documents themselves have been
consumed into this file and removed from the repo.

---

## Naming flags (commit review)

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
