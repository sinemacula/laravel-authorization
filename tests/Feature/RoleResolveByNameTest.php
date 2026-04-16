<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature coverage for `Role::resolveByName()` (#96).
 *
 * Mirrors the guard-precedence query centralised in
 * `Permission::resolveByName()` — guard-specific rows outrank
 * guard-agnostic rows, and an unknown name raises
 * `UnknownRoleException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Role::class)]
#[CoversClass(UnknownRoleException::class)]
final class RoleResolveByNameTest extends TestCase
{
    /**
     * `resolveByName` returns the guard-specific row when both
     * guard-specific and guard-agnostic rows exist.
     *
     * @return void
     */
    public function testResolveByNameFavoursGuardSpecificRow(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'admin',
            'guard_name' => null,
        ]);

        $specific = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'admin',
            'guard_name' => 'web',
        ]);

        $resolved = Role::resolveByName('admin', 'web');

        self::assertSame($specific->getKey(), $resolved->getKey());
    }

    /**
     * `resolveByName` falls back to the guard-agnostic row when
     * no guard-specific match exists.
     *
     * @return void
     */
    public function testResolveByNameFallsBackToGuardAgnostic(): void
    {
        $agnostic = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'viewer',
            'guard_name' => null,
        ]);

        $resolved = Role::resolveByName('viewer', 'web');

        self::assertSame($agnostic->getKey(), $resolved->getKey());
    }

    /**
     * `resolveByName` with a null guard uses the configured
     * default guard.
     *
     * @return void
     */
    public function testResolveByNameWithNullGuardUsesDefault(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        $resolved = Role::resolveByName('editor');

        self::assertSame($role->getKey(), $resolved->getKey());
    }

    /**
     * `resolveByName` throws `UnknownRoleException` when no
     * matching row exists.
     *
     * @return void
     */
    public function testResolveByNameThrowsOnUnknownRole(): void
    {
        $this->expectException(UnknownRoleException::class);

        Role::resolveByName('non-existent-role', 'web');
    }
}
