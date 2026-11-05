<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the Gate callback the registrar defines per permission
 * enum case, focused on how the leading positional argument becomes the
 * resource the evaluator sees.
 *
 * An argument that cannot be identified as a resource (an unsaved model, a
 * model without a usable key, a number, a boolean, a list or a plain object) is
 * refused with a recorded implicit deny, without consulting any policy or RBAC
 * grant, so it can never be mistaken for a check about no resource at all. A
 * null argument means no resource; strings, saved models, resource-contract
 * objects and stringable objects are forwarded as their identifiers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GateRegistrar::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(AuthorizationManager::class)]
final class GateRegistrarTest extends TestCase
{
    /**
     * Boot the provider with the demo permission enum so the Gate is wired for
     * each test, and fake the decision event so every evaluation is observable.
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

        // Register a morph alias so model identifiers are short and exact.
        Relation::morphMap(['stub' => StubIdentity::class]);

        (new AuthorizationServiceProvider($this->app))->boot();

        Event::fake([DecisionEvaluated::class]);
    }

    /**
     * Reset morph map state after each test so cross-test leakage cannot mask a
     * regression.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * An unsaved model has no key, so it cannot be identified as a resource and
     * the Gate refuses it with an implicit deny.
     *
     * @return void
     */
    public function testUnsavedModelIsRefusedWithImplicitDeny(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(new StubIdentity, $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A model whose key is the empty string cannot be identified as a resource,
     * so the Gate refuses it with an implicit deny.
     *
     * @return void
     */
    public function testModelWithEmptyStringKeyIsRefusedWithImplicitDeny(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(new StubIdentity(['id' => '']), $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * An integer argument is not a resource identifier, so the Gate refuses it
     * with an implicit deny.
     *
     * @return void
     */
    public function testIntegerArgumentIsRefusedWithImplicitDeny(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(42, $user);
        $this->assertGateRefusesUnidentifiedArgument(0, $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A float argument is not a resource identifier, so the Gate refuses it
     * with an implicit deny.
     *
     * @return void
     */
    public function testFloatArgumentIsRefusedWithImplicitDeny(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(4.2, $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A boolean argument is not a resource identifier, so the Gate refuses it
     * with an implicit deny, whichever value it carries.
     *
     * @return void
     */
    public function testBooleanArgumentIsRefusedWithImplicitDeny(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(true, $user);
        $this->assertGateRefusesUnidentifiedArgument(false, $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A list array at index zero is neither a context map nor a resource
     * identifier, so the Gate refuses it with an implicit deny.
     *
     * @return void
     */
    public function testListArrayArgumentIsRefusedWithImplicitDeny(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(['arn:post:42', 'arn:post:43'], $user);
        $this->assertGateRefusesUnidentifiedArgument([], $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * A plain object without `__toString` cannot be identified as a resource,
     * so the Gate refuses it with an implicit deny.
     *
     * @return void
     */
    public function testPlainObjectArgumentIsRefusedWithImplicitDeny(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        $this->assertGateRefusesUnidentifiedArgument(new \stdClass, $user);
        $this->assertResourcelessCheckStillAllowed();
    }

    /**
     * The refusal also applies when the Gate is dispatched for an explicit user
     * rather than the resolved principal, and the recorded decision names the
     * Gate user rather than the resolved principal.
     *
     * @return void
     */
    public function testUnidentifiableArgumentIsRefusedForExplicitUser(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        // Resolve a different principal so the recorded decision can only name
        // the Gate user if the callback scoped the manager to it.
        $this->actAs(StubIdentity::create(['id' => (string) Str::uuid()]));

        self::assertFalse(Gate::forUser($user)->allows('posts:create', [42]));
        $this->assertRefusalRecorded(0, $user);

        self::assertTrue(Gate::forUser($user)->allows('posts:create', [null]));
        self::assertSame([null, null], $this->evaluatedResources());
        self::assertSame($user, $this->decisions()[1]->principal);
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, Authorization::lastDecision()?->reason);
    }

    /**
     * The context supplied alongside an unidentifiable argument is carried on
     * the recorded refusal, as it is for any other check.
     *
     * @return void
     */
    public function testUnidentifiableArgumentRefusalCarriesTheContext(): void
    {
        $user = $this->actAsFullyPermittedPrincipal();

        self::assertFalse(Gate::allows('posts:create', [42, ['tenant' => 'org-7']]));
        $this->assertRefusalRecorded(0, $user, ['tenant' => 'org-7']);
    }

    /**
     * A null argument means no resource: a wildcard-resource allow applies.
     *
     * @return void
     */
    public function testNullArgumentAppliesWildcardResourceAllow(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'wildcard-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create']],
                ],
            ],
        ]));

        self::assertTrue(Gate::allows('posts:create', [null]));
        self::assertSame([null], $this->evaluatedResources());
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, Authorization::lastDecision()?->reason);
    }

    /**
     * A null argument means no resource: an allow scoped to particular
     * resources does not apply to it.
     *
     * @return void
     */
    public function testNullArgumentDoesNotApplyResourceScopedAllow(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'scoped-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['arn:post:42']],
                ],
            ],
        ]));

        self::assertFalse(Gate::allows('posts:create', [null]));
        self::assertSame([null], $this->evaluatedResources());
        self::assertSame(DecisionReason::IMPLICIT_DENY, Authorization::lastDecision()?->reason);
    }

    /**
     * A string argument passes through unchanged as the resource identifier.
     *
     * @return void
     */
    public function testStringArgumentPassesThrough(): void
    {
        $this->actAsPrincipalAllowedOn('arn:post:42');

        self::assertTrue(Gate::allows('posts:create', ['arn:post:42']));
        self::assertFalse(Gate::allows('posts:create', ['arn:post:99']));
        self::assertSame(['arn:post:42', 'arn:post:99'], $this->evaluatedResources());
    }

    /**
     * A saved model is identified as `{morphClass}:{key}`.
     *
     * @return void
     */
    public function testSavedModelIsIdentifiedByMorphClassAndKey(): void
    {
        $target = StubIdentity::create(['id' => 'target-1']);

        $this->actAsPrincipalAllowedOn('stub:target-1');

        self::assertTrue(Gate::allows('posts:create', [$target]));
        self::assertSame(['stub:target-1'], $this->evaluatedResources());
    }

    /**
     * An Eloquent model implementing the resource contract is identified by
     * `toResourceIdentifier()`, both when it has a key of its own and when it
     * has none.
     *
     * @return void
     */
    public function testEloquentModelImplementingResourceContractUsesItsIdentifier(): void
    {
        $this->actAsPrincipalAllowedOn('document:contract-7');

        $resource = new class extends Model implements AuthorizableResource {
            /** @var string|null Backing table. */
            protected $table = 'stub_identities';

            /**
             * Return the canonical resource identifier.
             *
             * @return string
             */
            #[\Override]
            public function toResourceIdentifier(): string
            {
                return 'document:contract-7';
            }
        };

        self::assertTrue(Gate::allows('posts:create', [$resource]));

        $resource->forceFill(['id' => 'model-7']);

        self::assertTrue(Gate::allows('posts:create', [$resource]));
        self::assertSame(['document:contract-7', 'document:contract-7'], $this->evaluatedResources());
    }

    /**
     * A stringable object is identified by its string form.
     *
     * @return void
     */
    public function testStringableObjectIsIdentifiedByItsStringForm(): void
    {
        $this->actAsPrincipalAllowedOn('arn:post:stringable');

        $resource = new class implements \Stringable {
            /**
             * Return the string form of the resource.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'arn:post:stringable';
            }
        };

        self::assertTrue(Gate::allows('posts:create', [$resource]));
        self::assertSame(['arn:post:stringable'], $this->evaluatedResources());
    }

    /**
     * Assert the Gate refuses the supplied leading argument with exactly one
     * recorded implicit deny for the supplied principal.
     *
     * @param  mixed  $argument
     * @param  \Tests\Feature\Stubs\StubIdentity  $principal
     * @return void
     */
    private function assertGateRefusesUnidentifiedArgument(mixed $argument, StubIdentity $principal): void
    {
        $previousCount = \count($this->decisions());

        self::assertFalse(Gate::allows('posts:create', [$argument]));

        $this->assertRefusalRecorded($previousCount, $principal);
    }

    /**
     * Assert exactly one decision was dispatched after the supplied number of
     * earlier decisions, and that it is an implicit deny for a check about no
     * resource that consulted no policy or RBAC grant.
     *
     * A principal with a wildcard-resource allow and the RBAC permission would
     * be allowed by either, so the implicit deny reason and the empty trace
     * prove neither was evaluated.
     *
     * @param  int  $previousCount
     * @param  \Tests\Feature\Stubs\StubIdentity  $principal
     * @param  array<string, mixed>  $context
     * @return void
     */
    private function assertRefusalRecorded(int $previousCount, StubIdentity $principal, array $context = []): void
    {
        $decisions = $this->decisions();

        self::assertCount($previousCount + 1, $decisions);

        $decision = $decisions[$previousCount];

        self::assertSame($principal, $decision->principal);
        self::assertSame('posts:create', $decision->action);
        self::assertNull($decision->resource);
        self::assertSame($context, $decision->context);
        self::assertFalse($decision->result->allowed);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $decision->result->reason);
        self::assertNull($decision->result->matchedStatement);
        self::assertSame([], $decision->result->trace);
        self::assertSame($decision->result, Authorization::lastDecision());
    }

    /**
     * Assert the same principal is allowed a resource-less check, so a denial
     * recorded earlier in the test is down to the argument alone.
     *
     * @return void
     */
    private function assertResourcelessCheckStillAllowed(): void
    {
        $previousCount = \count($this->decisions());

        self::assertTrue(Gate::allows('posts:create', [null]));

        $decisions = $this->decisions();

        self::assertCount($previousCount + 1, $decisions);
        self::assertNull($decisions[$previousCount]->resource);
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, $decisions[$previousCount]->result->reason);
        self::assertSame($decisions[$previousCount]->result, Authorization::lastDecision());
    }

    /**
     * Return every decision event dispatched so far, in order.
     *
     * @return list<\SineMacula\Laravel\Authorization\Events\DecisionEvaluated>
     */
    private function decisions(): array
    {
        return \array_values(
            Event::dispatched(DecisionEvaluated::class)
                ->map(static fn (array $arguments): DecisionEvaluated => $arguments[0])
                ->all(),
        );
    }

    /**
     * Return the resource of every decision evaluated so far, in order.
     *
     * @return list<string|null>
     */
    private function evaluatedResources(): array
    {
        return \array_map(static fn (DecisionEvaluated $decision): ?string => $decision->resource, $this->decisions());
    }

    /**
     * Act as a principal that both holds the permission and carries a
     * wildcard-resource allow, so any check that is evaluated is allowed.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function actAsFullyPermittedPrincipal(): StubIdentity
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('posts:create');

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'wildcard-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create']],
                ],
            ],
        ]));

        $this->actAs($user);

        return $user;
    }

    /**
     * Act as a principal allowed the action on the supplied resource only.
     *
     * @param  string  $resource
     * @return void
     */
    private function actAsPrincipalAllowedOn(string $resource): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'scoped-allow',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => [$resource]],
                ],
            ],
        ]));

        $this->actAs($user);
    }

    /**
     * Swap the principal resolver for one that returns the supplied
     * authorizable and refresh the manager so the next facade call picks it up.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return void
     */
    private function actAs(StubIdentity $user): void
    {
        $resolver = new class ($user) implements PrincipalResolver {
            /**
             * Create a new resolver wrapping a fixed user.
             *
             * @param  object  $user
             * @return void
             */
            public function __construct(

                /** The user returned by every resolution call. */
                private readonly object $user,
            ) {}

            /**
             * Resolve the current principal.
             *
             * @return object|null
             *
             * @phpstan-ignore-next-line return.unusedType
             */
            #[\Override]
            public function resolve(): ?object
            {
                return $this->user;
            }
        };

        $this->app->instance(PrincipalResolver::class, $resolver); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance('authorization'); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance(AuthorizationManager::class); // @phpstan-ignore method.nonObject
    }
}
