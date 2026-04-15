<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use Tests\Feature\Stubs\StubAuthorizable;
use Tests\TestCase;

/**
 * Feature coverage for the nullable `guard_name` semantics.
 *
 * A null `guard_name` marks a role or permission as guard-agnostic
 * — the row applies to every guard. String lookups (`assignRole`,
 * `givePermission`, `hasRole`, `hasPermission`) resolve against the
 * configured default guard first and fall back to the guard-agnostic
 * row when no guard-specific match exists.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
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
     * A role with a null `guard_name` resolves via string name on any
     * guard.
     *
     * @return void
     */
    public function testGuardAgnosticRoleResolvesByStringName(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::ROLE_NAME,
            'guard_name' => null,
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);

        $user->assignRole(self::ROLE_NAME);

        self::assertTrue($user->fresh()?->hasRole(self::ROLE_NAME));
    }

    /**
     * A permission with a null `guard_name` resolves via string name
     * on any guard.
     *
     * @return void
     */
    public function testGuardAgnosticPermissionResolvesByStringName(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PERMISSION_NAME,
            'guard_name' => null,
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);

        $user->givePermission(self::PERMISSION_NAME);

        self::assertTrue($user->fresh()?->hasPermission(self::PERMISSION_NAME));
    }

    /**
     * A guard-specific role takes precedence over a guard-agnostic
     * role with the same name when both are present.
     *
     * @return void
     */
    public function testGuardSpecificRoleOutranksGuardAgnosticRole(): void
    {
        $agnostic = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PRECEDENCE_ROLE,
            'guard_name' => null,
        ]);
        $specific = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PRECEDENCE_ROLE,
            'guard_name' => 'web',
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);

        $user->assignRole(self::PRECEDENCE_ROLE);

        $assigned = $user->fresh()?->roles->first();

        self::assertNotNull($assigned);
        self::assertSame($specific->getKey(), $assigned->getKey());
        self::assertNotSame($agnostic->getKey(), $assigned->getKey());
    }

    /**
     * A guard-specific permission takes precedence over a
     * guard-agnostic permission with the same name when both are
     * present.
     *
     * @return void
     */
    public function testGuardSpecificPermissionOutranksGuardAgnosticPermission(): void
    {
        $agnostic = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PRECEDENCE_PERMISSION,
            'guard_name' => null,
        ]);
        $specific = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PRECEDENCE_PERMISSION,
            'guard_name' => 'web',
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);

        $user->givePermission(self::PRECEDENCE_PERMISSION);

        $assigned = $user->fresh()?->permissions->first();

        self::assertNotNull($assigned);
        self::assertSame($specific->getKey(), $assigned->getKey());
        self::assertNotSame($agnostic->getKey(), $assigned->getKey());
    }
}
