<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Coverage for the two `translateGateArguments` / `stringifyGateResource`
 * branches the primary forwarding tests do not reach:
 *
 * - A list-shaped `$arguments` whose leading entry is itself an associative
 *   array. Gate consumers who build arguments programmatically — e.g.
 *   `Gate::allows('x', [$context])` — land here because the outer list is
 *   expanded into the variadic but the inner assoc array is retained at numeric
 *   index 0.
 * - A non-string, non-object leading entry (integer) that
 *   `stringifyGateResource` cannot identify as a resource, so the Gate records
 *   an implicit deny rather than treating it as a check about no resource.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(EventListenerRegistrar::class)]
#[CoversClass(AuthorizationManager::class)]
final class GateArgumentEdgeCasesTest extends TestCase
{
    /**
     * Boot the provider with the demo permission enum so the Gate is wired for
     * each test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        (new AuthorizationServiceProvider($this->app))->boot();
    }

    /**
     * When the outer `arguments` list contains a single assoc array at index 0,
     * the closure treats it as the context map with no resource — matching the
     * documented `Gate::allows('x', [$ctx])` idiom.
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

        // The outer list wrapper spreads so the gate receives one associative
        // array argument, hitting the translator's index-0-assoc branch.
        self::assertTrue(Gate::allows('posts:create', [['tenant' => 'org-7']]));
        self::assertFalse(Gate::allows('posts:create', [['tenant' => 'org-9']]));
    }

    /**
     * A non-string, non-object leading entry (integer) cannot be identified as
     * a resource, so the Gate records an implicit deny even though a
     * wildcard-resource allow and a held RBAC permission would both allow a
     * resource-less check.
     *
     * @return void
     */
    public function testGateDeniesNonStringNonObjectResourceArgument(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('posts:create');
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

        // An integer at index 0 is not a resource identifier; the Gate records
        // an implicit deny without consulting the policy or the RBAC grant.
        self::assertFalse(Gate::allows('posts:create', [42]));

        $refusal = Authorization::lastDecision();

        self::assertNotNull($refusal);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $refusal->reason);
        self::assertSame([], $refusal->trace);

        // The same principal is allowed when no resource is supplied, so the
        // denial above is down to the argument alone.
        self::assertTrue(Gate::allows('posts:create'));
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, Authorization::lastDecision()?->reason);
    }

    /**
     * Swap the subject resolver for one that returns the supplied authorizable
     * and refresh the manager so the next facade call picks it up.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return void
     */
    private function actAs(StubIdentity $user): void
    {
        $resolver = new StubSubjectResolver($user);

        $this->app->instance(SubjectResolver::class, $resolver); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance('authorization'); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance(AuthorizationManager::class); // @phpstan-ignore method.nonObject
    }
}
