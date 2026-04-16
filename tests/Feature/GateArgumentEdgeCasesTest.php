<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Models\Policy;
use Tests\Feature\Stubs\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Coverage for the two `translateGateArguments` / `stringifyGateResource`
 * branches the primary forwarding tests do not reach:
 *
 * - A list-shaped `$arguments` whose leading entry is itself an
 *   associative array. Gate consumers who build arguments
 *   programmatically — e.g. `Gate::allows('x', [$context])` — land
 *   here because the outer list is expanded into the variadic but
 *   the inner assoc array is retained at numeric index 0.
 * - A non-string, non-object leading entry (integer, list-array)
 *   that `stringifyGateResource` must coerce to a null resource so
 *   the Gate call still evaluates against the principal's RBAC.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(EventListenerRegistrar::class)]
#[CoversClass(AuthorizationManager::class)]
final class GateArgumentEdgeCasesTest extends TestCase
{
    /**
     * Boot the provider with the demo permission enum so the Gate
     * is wired for each test.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        (new AuthorizationServiceProvider($this->app))->boot();
    }

    /**
     * When the outer `arguments` list contains a single assoc array
     * at index 0, the closure treats it as the context map with no
     * resource — matching the documented `Gate::allows('x', [$ctx])`
     * idiom.
     *
     * @return void
     */
    public function testGateTreatsNestedAssociativeArrayAtIndexZeroAsContext(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'tenant-scoped-nested',
            'document' => [
                'statements' => [[
                    'effect'     => 'allow',
                    'actions'    => ['posts:create'],
                    'conditions' => ['tenant' => ['eq' => 'org-7']],
                ]],
            ],
        ]));

        // The outer list [$ctx] spreads to $arguments = [['tenant' => ...]],
        // hitting the index-0-assoc branch of translateGateArguments().
        self::assertTrue(Gate::allows('posts:create', [['tenant' => 'org-7']]));
        self::assertFalse(Gate::allows('posts:create', [['tenant' => 'org-9']]));
    }

    /**
     * A non-string, non-object leading entry (integer) coerces to a
     * null resource — the Gate still dispatches, evaluating against
     * the principal's RBAC alone.
     *
     * @return void
     */
    public function testGateCoercesNonStringNonObjectResourceToNull(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'resourceless-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create']],
                ],
            ],
        ]));

        // An integer at index 0 yields null resource via stringifyGateResource;
        // the policy still matches because it has no `resources` clause.
        self::assertTrue(Gate::allows('posts:create', [42]));
    }

    /**
     * Swap the principal resolver for one that returns the supplied
     * authorizable and refresh the manager so the next facade call
     * picks it up.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return void
     */
    private function actAs(StubIdentity $user): void
    {
        $resolver = new class ($user) implements PrincipalResolver {
            public function __construct(private readonly object $user) {}

            public function resolve(): ?object
            {
                return $this->user;
            }
        };

        $this->app->instance(PrincipalResolver::class, $resolver);
        $this->app->forgetInstance('authorization');
        $this->app->forgetInstance(AuthorizationManager::class);
    }
}
