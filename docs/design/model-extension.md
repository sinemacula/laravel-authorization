# Model Extension via Config Swap

The package's `Role`, `Permission`, and `Policy` models are resolved through `authorization.models.*` config keys at
every call site. This design lets consumers replace any shipped model with their own subclass -- adding columns, traits,
scopes, or behavioural overrides -- without forking the package or patching migrations at the framework level. This note
explains the extension path and walks through a concrete example: adding soft deletes to the `Role` model.

## Invariants

1. **Every model reference is config-resolved.** The package never hard-codes `new Role` or `Role::query()` in
   production code. All instantiation and query paths read `config('authorization.models.role')` (and the equivalent for
   `permission` and `policy`) so a consumer-registered subclass is used transparently.

2. **Subclasses inherit all package behaviour.** Extending the shipped model and calling `parent::booted()` (or letting
   Laravel's trait-boot convention handle it) preserves lifecycle events, system protection, name validation, and the
   guard-precedence query.

3. **Schema changes are the consumer's responsibility.** The package ships migrations for its own columns. A subclass
   that adds columns (e.g. `deleted_at`, `tenant_id`, `rank`) must ship its own migration -- either in the application's
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

```php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('roles', static function (Blueprint $table): void {
            $table->softDeletes();
        });
    }

    public function down(): void
    {
        Schema::table('roles', static function (Blueprint $table): void {
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

Once registered, every package-internal query (`resolveByName`, `HasRoles` trait methods, cache invalidation listeners)
instantiates the consumer's `App\Models\Role` and benefits from the `SoftDeletes` trait automatically.

## Applying the Same Pattern to Permission and Policy

The steps are identical -- extend the shipped model, compose `SoftDeletes` (or any other trait), add the migration
column, and register the swap. The package treats all three entity models symmetrically through the config indirection.

## Trade-offs

- **No package-level soft deletes shipped.** The package uses hard deletes by default. Consumers who need historical
  reconstruction (SOC 2, ISO 27001 compliance) add soft deletes via the extension path above or rely on a dedicated
  audit-log package that snapshots row state on delete.
- **Cascade rules need consumer attention.** A soft-deleted role's pivot rows are not automatically soft-deleted --
  Laravel's `cascadeOnDelete` foreign key fires on hard delete only. Consumers should handle orphaned pivots via model
  events on the subclass or accept that pivot rows reference a trashed parent (which the `SoftDeletes` trait's
  `withTrashed()` scope can resolve at query time).
- **The subclass must not change the table name.** The shipped migrations target the configured table name. A subclass
  that overrides `$table` must ensure its migrations target the same table or the schema will diverge.
