<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\ExcludesDeprecatedScope;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Integration coverage asserting that gate evaluation honours the
 * `ExcludesDeprecatedScope` global scope on `Permission`.
 *
 * A permission that has been retired by stamping its `deprecated_at` timestamp
 * must drop out of the evaluator's RBAC branch even when the underlying row and
 * pivot are still present — the scope filters it out of every model-layer query
 * the manager traverses. Admin flows that need the full catalogue reach in via
 * `Permission::withDeprecated()` without disturbing the default surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ExcludesDeprecatedScope::class)]
#[CoversClass(Permission::class)]
#[CoversClass(AuthorizationManager::class)]
final class DeprecatedPermissionsTest extends TestCase
{
    /**
     * A role-inherited permission resolves to allow while live, then denies the
     * moment it is deprecated — the scope filters the row out of the
     * model-layer query the RBAC branch traverses.
     *
     * @return void
     */
    public function testDeprecatingPermissionRemovesItFromGateEvaluation(): void
    {
        $permission = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'test:deprecated',
            'guard' => 'web',
        ]);

        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'deprecation-tester',
            'guard' => 'web',
        ]);
        $role->permissions()->attach($permission->getKey());

        $identity = StubIdentity::create(['id' => (string) Str::uuid()]);
        $identity->assignRole($role);

        self::assertTrue(
            Authorization::for($identity)->can('test:deprecated'),
            'Live permission attached via a role should allow.',
        );

        $permission->deprecated_at = CarbonImmutable::now();
        $permission->save();

        // Drop the Eloquent relation memo and the resolution-cache
        // memo so the next `can()` re-queries through the global
        // scope — the sync command that stamps `deprecated_at` in
        // production emits the cache-invalidation events that do
        // the same thing.
        $identity->unsetRelations();
        $this->app->make(ResolutionCache::class)->forget($identity); // @phpstan-ignore method.nonObject

        self::assertFalse(
            Authorization::for($identity)->can('test:deprecated'),
            'Deprecated permission must not be honoured by gate evaluation.',
        );

        // The row itself is still present — deprecation retires without
        // deleting so role pivots and audit history survive.
        $survivor = Permission::withDeprecated()
            ->where('name', 'test:deprecated')
            ->first();

        self::assertNotNull($survivor, 'Deprecated row should still be persisted.');
        self::assertNotNull($survivor->deprecated_at);
        self::assertSame($permission->getKey(), $survivor->getKey());
    }
}
