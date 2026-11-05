<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Concerns\ManagesPermissions;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use Tests\TestCase;

/**
 * Feature coverage for `RoleService::find()`.
 *
 * Mirrors the guard-precedence query centralised in `PermissionService::find()`
 * — guard-specific rows outrank guard-agnostic rows, and an unknown name raises
 * `UnknownRoleException`.
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
#[CoversClass(UnknownRoleException::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
#[CoversTrait(HasRoleHierarchy::class)]
#[CoversTrait(ManagesPermissions::class)]
final class RoleResolveByNameTest extends TestCase
{
    /**
     * `RoleService::find()` returns the guard-specific row when both
     * guard-specific and guard-agnostic rows exist.
     *
     * @return void
     */
    public function testResolveByNameFavoursGuardSpecificRow(): void
    {
        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'admin',
            'guard' => null,
        ]);

        $specific = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'admin',
            'guard' => 'web',
        ]);

        $resolved = app(RoleService::class)->find('admin', 'web');

        self::assertSame($specific->getKey(), $resolved->getKey());
    }

    /**
     * `RoleService::find()` falls back to the guard-agnostic row when no
     * guard-specific match exists.
     *
     * @return void
     */
    public function testResolveByNameFallsBackToGuardAgnostic(): void
    {
        $agnostic = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'viewer',
            'guard' => null,
        ]);

        $resolved = app(RoleService::class)->find('viewer', 'web');

        self::assertSame($agnostic->getKey(), $resolved->getKey());
    }

    /**
     * `RoleService::find()` with a null guard uses the configured default
     * guard.
     *
     * @return void
     */
    public function testResolveByNameWithNullGuardUsesDefault(): void
    {
        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'editor',
            'guard' => 'web',
        ]);

        $resolved = app(RoleService::class)->find('editor');

        self::assertSame($role->getKey(), $resolved->getKey());
    }

    /**
     * `RoleService::find()` throws `UnknownRoleException` when no matching row
     * exists.
     *
     * @return void
     */
    public function testResolveByNameThrowsOnUnknownRole(): void
    {
        $this->expectException(UnknownRoleException::class);

        app(RoleService::class)->find('non-existent-role', 'web');
    }
}
