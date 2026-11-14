# Model Extension via Config Swap

The package's `Role`, `Permission`, and `Policy` models are resolved through `authorization.models.*` config keys at
every call site. This design lets consumers replace any shipped model with their own subclass -- adding columns, traits,
scopes, or behavioural overrides -- without forking the package or patching migrations at the framework level. This note
explains the extension path and walks through a concrete example: adding soft deletes to the `Role` model.

## Invariants

1. **Every model reference is config-resolved.** Every query and every saved row goes through the class
   `Config\ModelClasses::get('role')` (and the equivalent for `permission` and `policy`) reads from
   `authorization.models`, so a consumer-registered subclass is used transparently. This covers the relations as well
   as the lookups: `parent()`, `children()`, `Role::permissions()`, `Permission::roles()` and the observer's hierarchy
   cycle check all use the configured class. The package builds a shipped `Role` or `Permission` directly only as an
   unsaved stand-in: a role or permission an `authorization:migrate-spatie` dry run reports, and the permission names
   delegated administration weighs. Both sides of the role-permission relation use the `RolePermission` pivot,
   so guard parity is enforced whichever side a permission is attached from.

2. **The configured class is validated at boot.** Each `authorization.models.*` entry must name an existing class that
   is the shipped model or a subclass of it. Anything else -- a class that does not exist, an unrelated model, an empty
   value -- raises `InvalidAuthorizationConfigException` naming the offending key when the application boots. After
   boot, `ModelClasses::get()` checks only that the value is a non-empty string.

3. **Subclasses inherit all package behaviour.** The shipped models attach their observers with `#[ObservedBy]`, and
   `Role` and `Permission` their tenant scope with `#[ScopedBy]`, which Laravel applies to a subclass too. The rest
   comes from traits: a `name` mutator validates the name, and `boot<Trait>()` methods, which Laravel calls by
   convention, add hooks such as system protection. A subclass therefore keeps lifecycle events, system protection,
   name validation and tenant scoping without doing anything; one that overrides a trait's boot method, such as
   `bootHasSystemProtection()`, calls the parent's.

4. **Schema changes are the consumer's responsibility.** The package ships migrations for its own columns. A subclass
   that adds columns (e.g. `deleted_at`, `archived_at`) must ship its own migration -- either in the application's
   migration directory or via a separate package that depends on this one.

## Extension Path

1. Create a subclass that extends the shipped model.
2. Add any traits, casts, scopes, or attribute overrides.
3. If the subclass requires additional columns, add a migration.
4. Register the subclass in `config/authorization.php`.

## Example: Adding Soft Deletes to Roles

### 1. Subclass

```php
namespace App\Models;

use Illuminate\Database\Eloquent\SoftDeletes;
use SineMacula\Laravel\Authorization\Models\Role as BaseRole;

class Role extends BaseRole
{
    use SoftDeletes;
}
```

### 2. Migration

The roles table may carry a prefix or another name, and may live on another connection, so the migration reads both
the way the package does:

```php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Config\TableNames;

return new class extends Migration {
    public function getConnection(): ?string
    {
        return config('authorization.connection') ?: null;
    }

    public function up(): void
    {
        $schema = Schema::connection($this->getConnection());

        $schema->table(TableNames::get('roles'), static function (Blueprint $table): void {
            $table->softDeletes();
        });
    }

    public function down(): void
    {
        $schema = Schema::connection($this->getConnection());

        $schema->table(TableNames::get('roles'), static function (Blueprint $table): void {
            $table->dropSoftDeletes();
        });
    }
};
```

### 3. Config Registration

```php
// config/authorization.php

'models' => [
    'role'       => \App\Models\Role::class,
    'permission' => \SineMacula\Laravel\Authorization\Models\Permission::class,
    'policy'     => \SineMacula\Laravel\Authorization\Models\Policy::class,
],
```

Once registered, every query the package makes through the model (`RoleService::find()`, the `HasRoles` relations,
the resolution cache's reads) instantiates the consumer's `App\Models\Role` and applies the `SoftDeletes` scope. The
package also reads its tables directly with the query builder in places, such as delegated administration's reads of
a role's policy attachments, where no model scope applies.

## Applying the Same Pattern to Permission and Policy

The steps are identical -- extend the shipped model, compose `SoftDeletes` (or any other trait), add the migration
column, and register the swap. The package treats all three entity models symmetrically through the config indirection.

## Trade-offs

- **No package-level soft deletes shipped.** The package uses hard deletes by default. Consumers who need historical
  reconstruction (SOC 2, ISO 27001 compliance) add soft deletes via the extension path above or rely on a dedicated
  audit-log package that snapshots row state on delete.
- **Cascade rules need consumer attention.** A soft-deleted role's pivot rows are not automatically soft-deleted --
  the `cascadeOnDelete` foreign keys fire on a hard delete only. Consumers should handle orphaned pivots via model
  events on the subclass or accept that pivot rows reference a trashed parent (which the `SoftDeletes` trait's
  `withTrashed()` scope can resolve at query time).
- **The table name comes from configuration.** Each shipped model's constructor sets its table from
  `Config\TableNames::get()`, so a `$table` property on a subclass has no effect. Rename a table through
  `authorization.tables`, before migrating.
- **The connection is the package's.** Every shipped model and pivot names `authorization.connection` when it is set,
  so a subclass's own `$connection` applies only while the setting is unset, and never to a pivot.

## Implementation Anchors

- `Config\ModelClasses::get()` -- the configured class, read at run time.
- `Config\ConfigValidator::model()` -- the boot check of each `authorization.models` entry.
- `Models\Role`, `Models\Permission`, `Models\Policy` -- the constructors that set the configured table and
  `getConnectionName()`.
- `Concerns\HasRoleHierarchy`, `Concerns\ManagesPermissions`, `Models\Permission::roles()` and `Observers\RoleObserver`
  -- the relations and the cycle check reading the configured class.

## Authoritative Tests

- `ConfigValidatorTest::testSubclassesOfShippedModelsPass` and `testInvalidModelEntryIsRejected` -- the boot check.
- `ModelClassesTest::testAConfiguredClassIsRead` -- the configured class read at run time.
- `HasRoleHierarchyTest::testParentReturnsConfiguredRoleClass`, `testChildrenReturnsConfiguredRoleClass` and
  `testAncestorsCycleLookupUsesConfiguredRoleClass` -- the relations and the cycle check.
- `HasSystemProtectionTest::testSubclassExtendingBootHookKeepsProtection` -- a subclass keeps system protection.
- `RoleObserverTest::testCycleCheckLooksUpProposedParentThroughConfiguredRoleClass` -- the observer's cycle check
  hydrating the configured class.
