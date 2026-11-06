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
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Coverage for the two `translateGateArguments` / `ResourceReferences::of()`
 * branches the primary forwarding tests do not reach:
 *
 * - A list-shaped `$arguments` whose leading entry is itself an associative
 *   array. Gate consumers who build arguments programmatically — e.g.
 *   `Gate::allows('x', [$context])` — land here because the outer list is
 *   expanded into the variadic but the inner assoc array is retained at numeric
 *   index 0.
 * - A non-string, non-object leading entry (integer) that
 *   `ResourceReferences::of()` cannot identify as a resource, so the decision
 *   denies it at the resource stage rather than treating it as a check about no
 *   resource.
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
                    'conditions' => ['eq' => ['input.tenant' => 'org-7']],
                ]],
            ],
        ]));

        // The outer list wrapper spreads so the gate receives one associative
        // array argument, hitting the translator's index-0-assoc branch.
        self::assertTrue(Gate::allows('posts:create', [['tenant' => 'org-7']]));
        self::assertFalse(Gate::allows('posts:create', [['tenant' => 'org-9']]));
    }

    /**
     * A resource identifier holding a NUL byte names nothing, so the Gate and
     * `Authorization::can()` deny it as `resource_unresolved` without a
     * ValueError, even under a statement allowing the action on every post.
     *
     * @return void
     */
    public function testGateDeniesAResourceHoldingANulByte(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'name'     => 'every-post',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['post:*']]]],
        ]));

        self::assertTrue(Gate::allows('posts:create', 'post:1'));

        foreach (["post:1\0", ['post', "1\0"]] as $resource) {
            self::assertFalse(Gate::allows('posts:create', [$resource]));
            self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, Authorization::lastDecision()?->reason);
            self::assertFalse(Gate::forUser($user)->check('posts:create', [$resource]));
            self::assertFalse(Authorization::can('posts:create', $resource));
            self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, Authorization::check('posts:create', $resource)->reason);
        }
    }

    /**
     * A non-string, non-object leading entry (integer) cannot be identified as
     * a resource, so the Gate records an unresolved-resource denial even though
     * a wildcard-resource allow and a held RBAC permission would both allow a
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

        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'resourceless-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create']],
                ],
            ],
        ]);

        $user->attachPolicy($policy);

        // An integer at index 0 is not a resource identifier; the Gate records
        // a denial at the resource stage without consulting the policy or the
        // RBAC grant.
        self::assertFalse(Gate::allows('posts:create', [42]));

        $refusal = Authorization::lastDecision();

        self::assertNotNull($refusal);
        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, $refusal->reason);
        self::assertSame(DecisionStage::RESOURCE, $refusal->stage);
        self::assertSame([], $refusal->trace);

        // The same principal is allowed when no resource is supplied, so the
        // denial above is down to the argument alone.
        self::assertTrue(Gate::allows('posts:create'));
        self::assertEquals([new StatementReference('resourceless-allow', 0, $policy->id)], Authorization::lastDecision()?->statements);
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
