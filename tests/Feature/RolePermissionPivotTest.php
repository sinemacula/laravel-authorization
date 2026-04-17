<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\OrphanSide;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\OrphanedRolePermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Pivots\RolePermission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Direct unit-style coverage for the `RolePermission` pivot.
 *
 * The existing feature tests drive the pivot through the Role API;
 * this suite instantiates the pivot directly and pins each branch
 * of `ensureGuardParity()` — the in-memory parent fast-path, the
 * orphan-parent exception, and the configurable column-name
 * fallbacks. A future refactor of `Role::permissions()` that stops
 * routing through `using(RolePermission::class)` would leave the
 * feature tests green; this suite is the safety net for the
 * model-layer invariant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RolePermission::class)]
#[CoversClass(OrphanedRolePermissionException::class)]
#[CoversClass(OrphanSide::class)]
final class RolePermissionPivotTest extends TestCase
{
    /**
     * Matching concrete guards on a directly-instantiated pivot
     * save cleanly and land in the pivot table.
     *
     * @return void
     */
    public function testDirectPivotSavePersistsWithMatchingGuards(): void
    {
        $role       = $this->makeRole(guard: 'web');
        $permission = $this->makePermission(guard: 'web');

        $pivot = $this->newPivot([
            'role_id'       => $role->getKey(),
            'permission_id' => $permission->getKey(),
        ]);

        $pivot->save();

        self::assertSame(
            1,
            DB::table('role_permissions')
                ->where('role_id', $role->getKey())
                ->where('permission_id', $permission->getKey())
                ->count(),
        );
    }

    /**
     * A directly-instantiated pivot with two concrete, different
     * guards raises `GuardMismatchException` from the `saving`
     * hook — the invariant holds outside the relation path.
     *
     * @return void
     */
    public function testDirectPivotSaveWithGuardMismatchThrows(): void
    {
        $role       = $this->makeRole(guard: 'web');
        $permission = $this->makePermission(guard: 'api');

        $pivot = $this->newPivot([
            'role_id'       => $role->getKey(),
            'permission_id' => $permission->getKey(),
        ]);

        $this->expectException(GuardMismatchException::class);

        $pivot->save();
    }

    /**
     * Either side null on the pivot attributes short-circuits the
     * guard check — the FK constraint at the DB layer owns the
     * "required column" rule, not the guard-parity invariant.
     *
     * @return void
     */
    public function testNullIdentifierShortCircuitsGuardCheck(): void
    {
        $pivot = $this->newPivot([
            'role_id'       => null,
            'permission_id' => null,
        ]);

        // `saving` should pass without touching the DB. The save
        // itself still fails (missing PK columns) so we intercept
        // the hook directly by invoking an insert attempt.
        $raised = false;

        try {
            $pivot->save();
        } catch (GuardMismatchException|OrphanedRolePermissionException) {
            $raised = true;
        } catch (\Throwable) {
            // DB-layer failure is expected and acceptable — the
            // assertion is only that neither of our typed guards
            // fired on null identifiers.
        }

        self::assertFalse($raised, 'Null identifiers must not trigger a typed pivot guard.');
    }

    /**
     * When the role parent is attached via the pivot's `role`
     * relation, the guard-parity hook reads it from memory — no
     * `find()` query is issued for that side.
     *
     * @return void
     */
    public function testInMemoryRoleParentShortCircuitsRoleLookup(): void
    {
        $role       = $this->makeRole(guard: 'web');
        $permission = $this->makePermission(guard: 'web');

        $pivot = $this->newPivot([
            'role_id'       => $role->getKey(),
            'permission_id' => $permission->getKey(),
        ]);
        $pivot->setRelation('role', $role);
        $pivot->setRelation('permission', $permission);

        $queryLog = $this->captureQueryLog(static function () use ($pivot): void {
            $pivot->save();
        });

        foreach ($queryLog as $entry) {
            $sql = $entry['query'];

            self::assertStringNotContainsString(
                'from "roles"',
                $sql,
                'Pivot must not re-query the roles table when the parent is already loaded.',
            );
            self::assertStringNotContainsString(
                'from "permissions"',
                $sql,
                'Pivot must not re-query the permissions table when the parent is already loaded.',
            );
        }
    }

    /**
     * The `pivotParent` set by a `BelongsToMany` attach path is
     * treated as an authoritative role-side source — no lookup
     * for that side either.
     *
     * @return void
     */
    public function testPivotParentIsUsedAsRoleFastPath(): void
    {
        $role       = $this->makeRole(guard: 'web');
        $permission = $this->makePermission(guard: 'web');

        $pivot = $this->newPivot([
            'role_id'       => $role->getKey(),
            'permission_id' => $permission->getKey(),
        ]);
        $pivot->pivotParent = $role;
        $pivot->setRelation('permission', $permission);

        $queryLog = $this->captureQueryLog(static function () use ($pivot): void {
            $pivot->save();
        });

        foreach ($queryLog as $entry) {
            self::assertStringNotContainsString('from "roles"', $entry['query']);
        }
    }

    /**
     * A pivot attached to a role ID with no matching row raises
     * the typed `OrphanedRolePermissionException` — the DB-layer
     * FK constraint is not relied upon.
     *
     * @return void
     */
    public function testOrphanedRoleParentRaisesTypedException(): void
    {
        $permission = $this->makePermission(guard: 'web');

        $pivot = $this->newPivot([
            'role_id'       => (string) Str::uuid(),
            'permission_id' => $permission->getKey(),
        ]);

        try {
            $pivot->save();
            self::fail('Expected OrphanedRolePermissionException was not thrown.');
        } catch (OrphanedRolePermissionException $exception) {
            self::assertSame(OrphanSide::ROLE, $exception->getSide());
            self::assertSame($pivot->getAttribute('role_id'), $exception->getParentId());
        }
    }

    /**
     * A pivot attached to a permission ID with no matching row
     * raises the typed `OrphanedRolePermissionException`.
     *
     * @return void
     */
    public function testOrphanedPermissionParentRaisesTypedException(): void
    {
        $role = $this->makeRole(guard: 'web');

        $pivot = $this->newPivot([
            'role_id'       => $role->getKey(),
            'permission_id' => (string) Str::uuid(),
        ]);

        try {
            $pivot->save();
            self::fail('Expected OrphanedRolePermissionException was not thrown.');
        } catch (OrphanedRolePermissionException $exception) {
            self::assertSame(OrphanSide::PERMISSION, $exception->getSide());
            self::assertSame($pivot->getAttribute('permission_id'), $exception->getParentId());
        }
    }

    /**
     * The pivot reads its column names from config when no
     * relation supplies pivot keys — the default stays
     * `role_id` / `permission_id` and guard-parity still fires.
     *
     * @return void
     */
    public function testDefaultColumnConfigIsApplied(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        self::assertSame('role_id', $config->get('authorization.pivots.role_permissions.role_column'));
        self::assertSame('permission_id', $config->get('authorization.pivots.role_permissions.permission_column'));

        $role       = $this->makeRole(guard: 'web');
        $permission = $this->makePermission(guard: 'api');

        $pivot = $this->newPivot([
            'role_id'       => $role->getKey(),
            'permission_id' => $permission->getKey(),
        ]);

        $this->expectException(GuardMismatchException::class);

        $pivot->save();
    }

    /**
     * When the consumer overrides the pivot column names via
     * config and ships a matching schema, the pivot's guard-parity
     * check reads attributes from the new columns — a renamed
     * schema does not silently disable the invariant.
     *
     * @return void
     */
    public function testOverriddenColumnConfigIsHonoured(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.pivots.role_permissions.role_column', 'role_uuid');
        $config->set('authorization.pivots.role_permissions.permission_column', 'permission_uuid');

        Schema::dropIfExists('role_permissions');
        Schema::create('role_permissions', static function (Blueprint $table): void {
            $table->uuid('role_uuid');
            $table->uuid('permission_uuid');
            $table->primary(['role_uuid', 'permission_uuid']);
        });

        $role       = $this->makeRole(guard: 'web');
        $permission = $this->makePermission(guard: 'api');

        $pivot = $this->newPivot([
            'role_uuid'       => $role->getKey(),
            'permission_uuid' => $permission->getKey(),
        ]);

        $this->expectException(GuardMismatchException::class);

        $pivot->save();
    }

    /**
     * Capture every query issued while the callback runs.
     *
     * @param  (callable(): void)  $callback
     * @return array<int, array{query: string, bindings: array<int, mixed>, time: float|null}>
     */
    private function captureQueryLog(callable $callback): array
    {
        DB::enableQueryLog();
        DB::flushQueryLog();

        try {
            $callback();
        } finally {
            DB::disableQueryLog();
        }

        return DB::getQueryLog();
    }

    /**
     * Build a role row.
     *
     * @param  string|null  $guard
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private function makeRole(?string $guard, string $name = 'editor'): Role
    {
        return Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => $guard,
        ]);
    }

    /**
     * Build a permission row.
     *
     * @param  string|null  $guard
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private function makePermission(?string $guard, string $name = 'posts:create'): Permission
    {
        return Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => $guard,
        ]);
    }

    /**
     * Instantiate a fresh pivot with the given attributes set.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Authorization\Models\Pivots\RolePermission
     */
    private function newPivot(array $attributes): RolePermission
    {
        $pivot = new RolePermission;
        $pivot->setTable('role_permissions');
        $pivot->timestamps = false;
        $pivot->exists     = false;

        foreach ($attributes as $key => $value) {
            $pivot->setAttribute($key, $value);
        }

        return $pivot;
    }
}
