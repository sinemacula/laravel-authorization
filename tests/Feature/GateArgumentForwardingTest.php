<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\Feature\Stubs\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the Gate closure's argument forwarding.
 *
 * Laravel dispatches the full argument tail to a Gate callback —
 * `Gate::allows('posts:create', $post)` reaches the closure as `(?$user,
 * $post)`. The service provider must translate that tail into the authorization
 * manager's `(resource, context)` pair so policies that condition on resources
 * or context are reachable via `$user->can()`, `@can`, `Gate::allows`, and the
 * `can:` middleware.
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
final class GateArgumentForwardingTest extends TestCase
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

        // Register a morph alias so `$stub->getMorphClass()` returns a
        // clean string; the default FQN contains backslashes that
        // trigger PHP's fnmatch escape handling in the evaluator.
        Relation::morphMap(['stub' => StubIdentity::class]);

        (new AuthorizationServiceProvider($this->app))->boot();
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
     * A string resource argument is forwarded to the evaluator's resource slot.
     *
     * @return void
     */
    public function testGateForwardsStringResource(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'only-post-42',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['arn:post:42']],
                ],
            ],
        ]));

        self::assertTrue(Gate::allows('posts:create', 'arn:post:42'));
        self::assertFalse(Gate::allows('posts:create', 'arn:post:99'));
    }

    /**
     * An Eloquent model argument is stringified as `{morphClass}:{key}` so it
     * matches the convention used by the package's polymorphic pivots.
     *
     * @return void
     */
    public function testGateForwardsEloquentModelAsMorphClassKey(): void
    {
        $user   = StubIdentity::create(['id' => (string) Str::uuid()]);
        $target = StubIdentity::create(['id' => 'target-1']);
        $this->actAs($user);

        $resourceIdentifier = $target->getMorphClass() . ':target-1';

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'target-bound',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => [$resourceIdentifier]],
                ],
            ],
        ]));

        self::assertTrue(Gate::allows('posts:create', $target));
    }

    /**
     * A stringable object argument is cast via `__toString`.
     *
     * @return void
     */
    public function testGateForwardsStringableObject(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'stringable-target',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['arn:post:stringable']],
                ],
            ],
        ]));

        $resource = new class {
            /**
             * @return string
             */
            public function __toString(): string
            {
                return 'arn:post:stringable';
            }
        };

        self::assertTrue(Gate::allows('posts:create', $resource));
    }

    /**
     * An associative array argument is forwarded as the context map with no
     * resource set.
     *
     * @return void
     */
    public function testGateForwardsAssociativeArrayAsContext(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'tenant-scoped',
            'document' => [
                'statements' => [[
                    'effect'     => 'allow',
                    'actions'    => ['posts:create'],
                    'conditions' => ['tenant' => ['eq' => 'org-1']],
                ]],
            ],
        ]));

        self::assertTrue(Gate::allows('posts:create', ['tenant' => 'org-1']));
        self::assertFalse(Gate::allows('posts:create', ['tenant' => 'org-2']));
    }

    /**
     * A resource followed by a context array combines both — the evaluator sees
     * the resource identifier and the context map simultaneously.
     *
     * @return void
     */
    public function testGateForwardsResourceAndContextCombination(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'resource-plus-context',
            'document' => [
                'statements' => [[
                    'effect'     => 'allow',
                    'actions'    => ['posts:create'],
                    'resources'  => ['arn:post:42'],
                    'conditions' => ['tenant' => ['eq' => 'org-1']],
                ]],
            ],
        ]));

        self::assertTrue(Gate::allows('posts:create', ['arn:post:42', ['tenant' => 'org-1']]));
        self::assertFalse(Gate::allows('posts:create', ['arn:post:42', ['tenant' => 'org-2']]));
        self::assertFalse(Gate::allows('posts:create', ['arn:post:99', ['tenant' => 'org-1']]));
    }

    /**
     * Calls with no extra arguments still evaluate against the principal's RBAC
     * grants — parity with the pre-fix behaviour.
     *
     * @return void
     */
    public function testGateWithoutExtraArgumentsMatchesPolicyOnAction(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'any-post',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create']],
                ],
            ],
        ]));

        self::assertTrue(Gate::allows('posts:create'));
    }

    /**
     * Unmappable non-object, non-array trailing arguments are silently
     * discarded rather than guessed at.
     *
     * @return void
     */
    public function testGateIgnoresUnmappableTrailingArguments(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'resource-only',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['arn:post:42']],
                ],
            ],
        ]));

        // The trailing integer is not a context array and is discarded.
        self::assertTrue(Gate::allows('posts:create', ['arn:post:42', 99]));
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
