<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Performance budget for the Blade helpers.
 *
 * Every `@role` and `@can` block in a view compiles to a call on
 * `BladeHelpers::hasRole()` / `hasPermission()`. A single page
 * renders one call per permission-gated block; the budget bounds
 * the per-call overhead on a realistic page weight (50 role
 * directives).
 *
 * Observed reference-machine timings:
 *
 * - `hasRole()` positive match: ~15μs
 * - `hasPermission()` positive match: ~60μs
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(BladeHelpers::class)]
final class BladeHelpersBudgetTest extends TestCase
{
    /**
     * 50 `@role` directive calls must complete in under 100ms on
     * the reference machine (~15μs per call observed).
     *
     * @return void
     */
    public function testHasRoleOverheadStaysBoundedForFiftyDirectives(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'admin',
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('admin');

        $this->actAs($user);

        $start = \microtime(true);

        for ($i = 0; $i < 50; $i++) {
            BladeHelpers::hasRole('admin');
        }

        $elapsed = \microtime(true) - $start;

        self::assertLessThan(
            0.1,
            $elapsed,
            "BladeHelpers::hasRole() budget exceeded ({$elapsed}s for 50 directive calls).",
        );
    }

    /**
     * 50 `@can`-style directive calls against a role-inherited
     * permission must complete in under 200ms — permission checks
     * pay the heavier `hasPermission()` lookup.
     *
     * @return void
     */
    public function testHasPermissionOverheadStaysBoundedForFiftyDirectives(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:edit',
            'guard_name' => 'web',
        ]);
        $role->permissions()->attach($permission->getKey());

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('editor');

        $this->actAs($user);

        $start = \microtime(true);

        for ($i = 0; $i < 50; $i++) {
            BladeHelpers::hasPermission('posts:edit');
        }

        $elapsed = \microtime(true) - $start;

        self::assertLessThan(
            0.2,
            $elapsed,
            "BladeHelpers::hasPermission() budget exceeded ({$elapsed}s for 50 directive calls).",
        );
    }

    /**
     * Bind a principal resolver that returns the supplied
     * principal — mirrors the helper used by the feature suite.
     *
     * @param  object  $principal
     * @return void
     */
    private function actAs(object $principal): void
    {
        $resolver = new class ($principal) implements PrincipalResolver {
            public function __construct(private readonly object $principal) {}

            public function resolve(): ?object // @phpstan-ignore return.unusedType
            {
                return $this->principal;
            }
        };

        $app = $this->app;
        self::assertNotNull($app, 'Testbench application must be booted by setUp().');

        $app->instance(PrincipalResolver::class, $resolver);
        $app->forgetInstance('authorization');
        $app->forgetInstance(AuthorizationManager::class);
    }
}
