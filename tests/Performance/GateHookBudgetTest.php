<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Support\DeclaredAbilities;
use Tests\Concerns\MeasuresTime;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubPermissionProvider;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Performance budget for the package's `Gate::before` hook.
 *
 * The hook runs on every Gate check the application makes, its own abilities
 * included, so an ability the package does not declare must fall through at the
 * cost of a set lookup, and a declared one must cost no more than the decision
 * itself. The budgets bound 500 checks of each, well above the observed cost to
 * absorb CI variance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GateRegistrar::class)]
#[CoversClass(DeclaredAbilities::class)]
final class GateHookBudgetTest extends TestCase
{
    use MeasuresTime;

    /**
     * Declare the stub enum and provider, and act as a user holding one of the
     * enum's permissions, handed over by the Gate.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'authorization.permission_enums'     => [PermissionEnum::class],
            'authorization.permission_providers' => [StubPermissionProvider::class],
        ]);

        Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('posts:create');

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user));
        $this->app?->forgetInstance('authorization');

        Gate::swap(Gate::forUser($user));
    }

    /**
     * 500 checks of an ability the package does not declare, answered by an
     * application define, must complete in under 100ms: the hook adds a set
     * lookup to each and records no decision.
     *
     * @return void
     */
    public function testAnUndeclaredAbilityFallsThroughCheaply(): void
    {
        Gate::define('reports:view', static fn (?object $user = null): bool => true);

        $start = \microtime(true);

        for ($i = 0; $i < 500; $i++) {
            Gate::allows('reports:view');
        }

        $elapsed = \microtime(true) - $start;

        $this->assertWithinBudget(0.1, $elapsed, "Gate fall-through budget exceeded ({$elapsed}s for 500 checks).");
    }

    /**
     * 500 checks of a declared ability the user holds must complete in under
     * 500ms, the declared names being read once and the decision cached as the
     * package's own API's is.
     *
     * @return void
     */
    public function testADeclaredAbilityCostsNoMoreThanTheDecision(): void
    {
        self::assertTrue(Gate::allows('posts:create'));

        $start = \microtime(true);

        for ($i = 0; $i < 500; $i++) {
            Gate::allows('posts:create');
        }

        $elapsed = \microtime(true) - $start;

        $this->assertWithinBudget(0.5, $elapsed, "Gate hook budget exceeded ({$elapsed}s for 500 checks).");
    }
}
