<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\Feature\Stubs\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the `AuthorizableResource` contract integration with the
 * Gate translation layer.
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
final class AuthorizableResourceTest extends TestCase
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
     * An object implementing `AuthorizableResource` is converted via
     * `toResourceIdentifier()` when passed through the Gate.
     *
     * @return void
     */
    public function testAuthorizableResourceIsUsedByGate(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'custom-resource',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['custom:resource:42']],
                ],
            ],
        ]));

        $resource = new class implements AuthorizableResource {
            /**
             * @return string
             */
            public function toResourceIdentifier(): string
            {
                return 'custom:resource:42';
            }
        };

        self::assertTrue(Gate::allows('posts:create', $resource));
    }

    /**
     * `AuthorizableResource` takes precedence over `__toString` and Eloquent
     * model stringification.
     *
     * @return void
     */
    public function testAuthorizableResourceTakesPrecedenceOverToString(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'precedence-check',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['authorizable:id']],
                ],
            ],
        ]));

        // Object implements both AuthorizableResource and __toString —
        // the contract method should win.
        $resource = new class implements AuthorizableResource {
            /**
             * @return string
             */
            public function toResourceIdentifier(): string
            {
                return 'authorizable:id';
            }

            /**
             * @return string
             */
            public function __toString(): string
            {
                return 'tostring:id';
            }
        };

        self::assertTrue(Gate::allows('posts:create', $resource));
    }

    /**
     * A non-matching `AuthorizableResource` identifier correctly denies access.
     *
     * @return void
     */
    public function testNonMatchingAuthorizableResourceIsDenied(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'deny-mismatch',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:create'], 'resources' => ['custom:resource:99']],
                ],
            ],
        ]));

        $resource = new class implements AuthorizableResource {
            /**
             * @return string
             */
            public function toResourceIdentifier(): string
            {
                return 'custom:resource:1';
            }
        };

        self::assertFalse(Gate::allows('posts:create', $resource));
    }

    /**
     * Swap the principal resolver for the supplied identity.
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
