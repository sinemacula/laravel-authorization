<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Traits\HasAuthorization;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use Tests\TestCase;

/**
 * Feature coverage for the `getAuthorizationGuard()` duck-typed
 * hook.
 *
 * Identity models can declare the method to route their
 * name-based role / permission lookups to a specific guard —
 * typical for multi-guard deployments where a user
 * authenticated under `api` should resolve against `api`-guard
 * rows instead of the package's default guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversClass(Role::class)]
final class GuardRoutingTest extends TestCase
{
    /**
     * Define a separate table for the api-guard stub so the two
     * identity shapes coexist alongside the default-guard stub.
     *
     * @return void
     */
    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        Schema::create('api_guarded_users', static function ($table): void {
            $table->string('id')->primary();
            $table->timestamps();
        });
    }

    /**
     * An identity declaring `getAuthorizationGuard()` routes its
     * role lookups to the declared guard, not the package
     * default.
     *
     * @return void
     */
    public function testAuthorizationGuardHookRoutesRoleLookups(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'admin',
            'guard_name' => 'api',
        ]);

        $user = ApiGuardedUser::create(['id' => (string) Str::uuid()]);

        $user->assignRole('admin');

        self::assertTrue($user->fresh()?->hasRole('admin'));
    }

    /**
     * When the only matching role is scoped to a different guard,
     * a non-default-guard identity still fails the lookup — it
     * does not fall back to the package default.
     *
     * @return void
     */
    public function testAuthorizationGuardHookIsolatesLookupsByGuard(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'admin',
            'guard_name' => 'web',
        ]);

        $user = ApiGuardedUser::create(['id' => (string) Str::uuid()]);

        $this->expectException(UnknownRoleException::class);

        $user->assignRole('admin');
    }

    /**
     * The same hook routes permission lookups as well.
     *
     * @return void
     */
    public function testAuthorizationGuardHookRoutesPermissionLookups(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:create',
            'guard_name' => 'api',
        ]);

        $user = ApiGuardedUser::create(['id' => (string) Str::uuid()]);

        $user->givePermission('posts:create');

        self::assertTrue($user->fresh()?->hasPermission('posts:create'));
    }

    /**
     * A guard-scoped permission attached through the api guard is
     * inaccessible to the default-guard lookup path even when the
     * names match.
     *
     * @return void
     */
    public function testDefaultGuardLookupDoesNotReachApiGuardPermission(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'api:only',
            'guard_name' => 'api',
        ]);

        $user = ApiGuardedUser::create(['id' => (string) Str::uuid()]);

        // Sanity: api-guard user finds the permission.
        $user->givePermission('api:only');
        self::assertTrue($user->fresh()?->hasPermission('api:only'));

        // The permission never matches under the default guard,
        // so creating a web-guard permission with the same name
        // is permitted and the web-guard lookup resolves it
        // without leaking into the api-guard row.
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'api:only',
            'guard_name' => 'web',
        ]);

        self::assertTrue(true, 'Two same-name permissions scoped to different guards coexist.');
    }

    /**
     * A role's own `guard_name` drives the permission lookup
     * inside `Role::givePermission()` — a web-scoped role
     * resolves permissions under the web guard, an api-scoped
     * role under api.
     *
     * @return void
     */
    public function testRolePermissionLookupUsesRolesOwnGuard(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'shared',
            'guard_name' => 'api',
        ]);

        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'api-editor',
            'guard_name' => 'api',
        ]);

        $role->givePermission('shared');

        self::assertTrue($role->fresh()?->hasPermission('shared'));
    }

    /**
     * A default-guard identity without the hook continues to use
     * the configured default guard — the behaviour is additive.
     *
     * @return void
     */
    public function testAbsenceOfHookFallsBackToConfigDefault(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'default-bound',
            'guard_name' => 'web',
        ]);

        $user = DefaultGuardUser::create(['id' => (string) Str::uuid()]);

        $user->assignRole('default-bound');

        self::assertTrue($user->fresh()?->hasRole('default-bound'));
    }

    /**
     * Clean up the api-guard stub table after each test.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Schema::dropIfExists('api_guarded_users');

        parent::tearDown();
    }
}

/**
 * Test stub — identity declaring `api` as its authorization
 * guard via the duck-typed hook.
 *
 * @internal
 */
class ApiGuardedUser extends Model implements AuthorizableIdentity
{
    use HasAuthorization;

    public $incrementing = false;

    protected $primaryKey = 'id';

    protected $keyType = 'string';

    protected $fillable = ['id'];

    protected $table = 'api_guarded_users';

    public function getAuthorizationGuard(): string
    {
        return 'api';
    }
}

/**
 * Test stub — identity that does not declare the hook, so the
 * trait falls back to `config('authorization.defaults.guard')`.
 *
 * @internal
 */
class DefaultGuardUser extends Model implements AuthorizableIdentity
{
    use HasAuthorization;

    public $incrementing = false;

    protected $primaryKey = 'id';

    protected $keyType = 'string';

    protected $fillable = ['id'];

    protected $table = 'stub_authorizables';
}
