<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\QueryException;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the nullable `guard` semantics.
 *
 * A null `guard` marks a role or permission as guard-agnostic — the row applies
 * to every guard. String lookups (`assignRole`, `givePermission`, `hasRole`,
 * `hasPermission`) resolve against the configured default guard first and fall
 * back to the guard-agnostic row when no guard-specific match exists. The
 * uniqueness invariant for the null-guard slot is enforced by a functional
 * unique index on `(name, COALESCE(guard, ''))` at the data layer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
final class GuardAgnosticLookupTest extends TestCase
{
    /** Permission name used across the guard-agnostic permission scenarios. */
    private const string PERMISSION_NAME = 'platform:manage';

    /** Role name used across the guard-agnostic role scenarios. */
    private const string ROLE_NAME = 'platform-admin';

    /** Role name used when testing guard-specific precedence. */
    private const string PRECEDENCE_ROLE = 'admin';

    /** Permission name used when testing guard-specific precedence. */
    private const string PRECEDENCE_PERMISSION = 'posts:edit';

    /**
     * A role with a null `guard` resolves via string name on any guard.
     *
     * @return void
     */
    public function testGuardAgnosticRoleResolvesByStringName(): void
    {
        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::ROLE_NAME,
            'guard' => null,
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->assignRole(self::ROLE_NAME);

        self::assertTrue($user->fresh()?->hasRole(self::ROLE_NAME));
    }

    /**
     * A permission with a null `guard` resolves via string name on any guard.
     *
     * @return void
     */
    public function testGuardAgnosticPermissionResolvesByStringName(): void
    {
        Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PERMISSION_NAME,
            'guard' => null,
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->givePermission(self::PERMISSION_NAME);

        self::assertTrue($user->fresh()?->hasPermission(self::PERMISSION_NAME));
    }

    /**
     * A guard-specific role takes precedence over a guard-agnostic role with
     * the same name when both are present.
     *
     * @return void
     */
    public function testGuardSpecificRoleOutranksGuardAgnosticRole(): void
    {
        $agnostic = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PRECEDENCE_ROLE,
            'guard' => null,
        ]);
        $specific = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PRECEDENCE_ROLE,
            'guard' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->assignRole(self::PRECEDENCE_ROLE);

        $assigned = $user->fresh()?->roles->first();

        self::assertNotNull($assigned);
        self::assertSame($specific->getKey(), $assigned->getKey());
        self::assertNotSame($agnostic->getKey(), $assigned->getKey());
    }

    /**
     * A guard-specific permission takes precedence over a guard-agnostic
     * permission with the same name when both are present.
     *
     * @return void
     */
    public function testGuardSpecificPermissionOutranksGuardAgnosticPermission(): void
    {
        $agnostic = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PRECEDENCE_PERMISSION,
            'guard' => null,
        ]);
        $specific = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PRECEDENCE_PERMISSION,
            'guard' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->givePermission(self::PRECEDENCE_PERMISSION);

        $assigned = $user->fresh()?->permissions->first();

        self::assertNotNull($assigned);
        self::assertSame($specific->getKey(), $assigned->getKey());
        self::assertNotSame($agnostic->getKey(), $assigned->getKey());
    }

    /**
     * A second guard-agnostic role with the same name is rejected at save time.
     *
     * @return void
     */
    public function testDuplicateGuardAgnosticRoleIsRejected(): void
    {
        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::ROLE_NAME,
            'guard' => null,
        ]);

        $this->expectException(QueryException::class);

        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::ROLE_NAME,
            'guard' => null,
        ]);
    }

    /**
     * A second guard-agnostic permission with the same name is rejected at save
     * time.
     *
     * @return void
     */
    public function testDuplicateGuardAgnosticPermissionIsRejected(): void
    {
        Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PERMISSION_NAME,
            'guard' => null,
        ]);

        $this->expectException(QueryException::class);

        Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PERMISSION_NAME,
            'guard' => null,
        ]);
    }

    /**
     * Guard-specific and guard-agnostic rows with the same name may co-exist —
     * the unique-guard-agnostic invariant targets only the null-guard slot.
     *
     * @return void
     */
    public function testGuardSpecificAndGuardAgnosticMayCoexist(): void
    {
        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PRECEDENCE_ROLE,
            'guard' => 'web',
        ]);

        $agnostic = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PRECEDENCE_ROLE,
            'guard' => null,
        ]);

        self::assertSame(2, Role::query()->where('name', self::PRECEDENCE_ROLE)->count()); // @phpstan-ignore staticMethod.dynamicCall
        self::assertNotNull($agnostic->getKey());
    }

    /**
     * Updating a guard-specific row to guard-agnostic fails when a
     * guard-agnostic row with the same name already exists.
     *
     * @return void
     */
    public function testUpdatingToGuardAgnosticCollisionIsRejected(): void
    {
        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PRECEDENCE_ROLE,
            'guard' => null,
        ]);
        $specific = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PRECEDENCE_ROLE,
            'guard' => 'web',
        ]);

        $this->expectException(QueryException::class);

        $specific->guard = null;
        $specific->save();
    }

    /**
     * Re-saving an existing guard-agnostic row (no data change) is allowed —
     * the invariant ignores the row against itself.
     *
     * @return void
     */
    public function testResavingExistingGuardAgnosticRowIsAllowed(): void
    {
        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::ROLE_NAME,
            'guard' => null,
        ]);

        $role->description = 'platform admin role';
        $role->save();

        self::assertSame('platform admin role', $role->fresh()?->description);
    }
}
