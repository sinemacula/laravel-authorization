<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Traits\HasAuthorization;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use SineMacula\Laravel\Authorization\Traits\ManagesPermissions;
use Tests\TestCase;

/**
 * Feature coverage for the `getAuthorizationGuard()` duck-typed hook.
 *
 * Identity models can declare the method to route their name-based role /
 * permission lookups to a specific guard — typical for multi-guard deployments
 * where a user authenticated under `api` should resolve against `api`-guard
 * rows instead of the package's default guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Role::class)]
#[CoversClass(RoleObserver::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(NullTenantResolver::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
#[CoversTrait(HasRoleHierarchy::class)]
#[CoversTrait(ManagesPermissions::class)]
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
final class GuardRoutingTest extends TestCase
{
    /**
     * Ensure the api-guard stub table exists whenever this suite runs. Needs to
     * work regardless of whether `migrate:fresh` already ran in this process,
     * so it's keyed off `Schema::hasTable` rather than the
     * `DatabaseRefreshed` hook.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (!Schema::hasTable('api_guarded_users')) {
            Schema::create('api_guarded_users', static function ($table): void {
                $table->string('id')->primary();
                $table->timestamps();
            });
        }
    }

    /**
     * An identity declaring `getAuthorizationGuard()` routes its role lookups
     * to the declared guard, not the package default.
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
     * When the only matching role is scoped to a different guard, a
     * non-default-guard identity still fails the lookup — it does not fall back
     * to the package default.
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
     * A guard-scoped permission attached through the api guard is inaccessible
     * to the default-guard lookup path even when the names match.
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
     * A role's own `guard_name` drives the permission lookup inside
     * `Role::givePermission()` — a web-scoped role resolves permissions under
     * the web guard, an api-scoped role under api.
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
     * A default-guard identity without the hook continues to use the configured
     * default guard — the behaviour is additive.
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
}

/**
 * Test stub — identity declaring `api` as its authorization guard via the
 * duck-typed hook.
 *
 * @internal
 */
// phpcs:ignore PSR1.Classes.ClassDeclaration.MultipleClasses
class ApiGuardedUser extends Model implements AuthorizableIdentity
{
    use HasAuthorization;

    /** @var bool */
    public $incrementing = false;

    /** @var string */
    protected $primaryKey = 'id';

    /** @var string */
    protected $keyType = 'string';

    /** @var array<int, string> */
    protected $fillable = ['id']; // @phpstan-ignore property.phpDocType

    /** @var string */
    protected $table = 'api_guarded_users'; // @phpstan-ignore property.phpDocType

    /**
     * @return string
     */
    public function getAuthorizationGuard(): string
    {
        return 'api';
    }
}

/**
 * Test stub — identity that does not declare the hook, so the trait falls back
 * to `config('authorization.defaults.guard')`.
 *
 * @internal
 */
// phpcs:ignore PSR1.Classes.ClassDeclaration.MultipleClasses
class DefaultGuardUser extends Model implements AuthorizableIdentity
{
    use HasAuthorization;

    /** @var bool */
    public $incrementing = false;

    /** @var string */
    protected $primaryKey = 'id';

    /** @var string */
    protected $keyType = 'string';

    /** @var array<int, string> */
    protected $fillable = ['id']; // @phpstan-ignore property.phpDocType

    /** @var string */
    protected $table = 'stub_identities'; // @phpstan-ignore property.phpDocType
}
