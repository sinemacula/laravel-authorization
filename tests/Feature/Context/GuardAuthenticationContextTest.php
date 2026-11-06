<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Context\GuardAuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\TestCase;

/**
 * Feature coverage for `GuardAuthenticationContext`, the default authentication
 * context, which supplies what Laravel knows: the guard and the signed-in user.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GuardAuthenticationContext::class)]
final class GuardAuthenticationContextTest extends TestCase
{
    /** @var string The key of the signed-in identity. */
    private const string USER_ID = 'a3c1f9c2-2b84-4d3e-9f3c-7f8d1c1e9a01';

    /**
     * Tear down Mockery instances and the morph map after every test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * The context supplies the `authentication` namespace alone.
     *
     * @return void
     */
    public function testSuppliesTheAuthenticationNamespaceAlone(): void
    {
        $context = $this->context();

        self::assertInstanceOf(AuthenticationContext::class, $context);
        self::assertSame(['authentication'], $context->namespaces());
    }

    /**
     * With nobody signed in, only the default guard's name is present.
     *
     * @return void
     */
    public function testWithNobodySignedInOnlyTheGuardIsPresent(): void
    {
        self::assertSame(['authentication' => ['guard' => 'web']], $this->context()->values());
    }

    /**
     * A signed-in Eloquent user supplies its key, as a string, and its class
     * name as its type when it has no morph alias.
     *
     * @return void
     */
    public function testASignedInUserSuppliesItsKeyAndType(): void
    {
        $this->actingAs(AuthenticatableIdentity::create(['id' => self::USER_ID]));

        self::assertSame(['authentication' => [
            'guard'     => 'web',
            'user_id'   => self::USER_ID,
            'user_type' => AuthenticatableIdentity::class,
        ]], $this->context()->values());
    }

    /**
     * An Eloquent user's type is its morph alias.
     *
     * @return void
     */
    public function testAnEloquentUsersTypeIsItsMorphAlias(): void
    {
        Relation::morphMap(['identity' => AuthenticatableIdentity::class]);

        $this->actingAs(AuthenticatableIdentity::create(['id' => self::USER_ID]));

        self::assertSame('identity', $this->context()->values()['authentication']['user_type'] ?? null);
    }

    /**
     * A user that is not an Eloquent model supplies its identifier, as a
     * string, and its class name.
     *
     * @return void
     */
    public function testAPlainUserSuppliesItsIdentifierAndClass(): void
    {
        $this->actingAs(new GenericUser(['id' => 7]));

        self::assertSame(['authentication' => [
            'guard'     => 'web',
            'user_id'   => '7',
            'user_type' => GenericUser::class,
        ]], $this->context()->values());
    }

    /**
     * A user whose identifier is not a scalar supplies its type alone.
     *
     * @return void
     */
    public function testAUserWithoutAScalarIdentifierSuppliesItsTypeAlone(): void
    {
        $user = \Mockery::mock(Authenticatable::class);
        $user->shouldReceive('getAuthIdentifier')->andReturn(null);

        $context = new GuardAuthenticationContext($this->factoryReturning('web', $user), $this->configWithDefaultGuard('web'));

        self::assertSame(['authentication' => ['guard' => 'web', 'user_type' => $user::class]], $context->values());
    }

    /**
     * The guard read is Laravel's default guard at the time of the check,
     * unless one is given at construction.
     *
     * @return void
     */
    public function testReadsTheDefaultGuardOrTheOneGiven(): void
    {
        $user = new GenericUser(['id' => 'u1']);

        $default = new GuardAuthenticationContext($this->factoryReturning('admin', $user), $this->configWithDefaultGuard('admin'));
        $given   = new GuardAuthenticationContext($this->factoryReturning('api', null), $this->configWithDefaultGuard('web'), 'api');

        self::assertSame(['authentication' => ['guard' => 'admin', 'user_id' => 'u1', 'user_type' => GenericUser::class]], $default->values());
        self::assertSame(['authentication' => ['guard' => 'api']], $given->values());
    }

    /**
     * A default guard that is empty or not a string names no guard, so no user
     * is read, even one the factory would return, and the namespace is absent.
     *
     * @return void
     */
    public function testAnUnnamedGuardIsLeftOut(): void
    {
        foreach (['', 42, null] as $default) {
            $factory = \Mockery::mock(AuthFactory::class);
            $factory->shouldReceive('guard')->never();

            self::assertSame([], (new GuardAuthenticationContext($factory, $this->configWithDefaultGuard($default)))->values());
        }
    }

    /**
     * With Laravel's own auth manager and no default guard named, the context
     * reads no guard, which Laravel would refuse as not defined, and the
     * namespace is absent.
     *
     * @return void
     */
    public function testNoDefaultGuardOnLaravelsAuthLeavesTheNamespaceAbsent(): void
    {
        $app = $this->app;

        self::assertNotNull($app);

        foreach ([null, ''] as $default) {
            $app->make(ConfigRepository::class)->set('auth.defaults.guard', $default);

            self::assertSame([], $this->context()->values());
        }
    }

    /**
     * It reads the request alone, so it is marked `ScopeInvariant` and a query
     * scope reads it once for a query.
     *
     * @return void
     */
    public function testItIsMarkedScopeInvariant(): void
    {
        self::assertContains(ScopeInvariant::class, \class_implements(GuardAuthenticationContext::class));
    }

    /**
     * Build the context on the application's auth and configuration.
     *
     * @return \SineMacula\Laravel\Authorization\Context\GuardAuthenticationContext
     */
    private function context(): GuardAuthenticationContext
    {
        $app = $this->app;

        self::assertNotNull($app);

        return new GuardAuthenticationContext($app->make(AuthFactory::class), $app->make(ConfigRepository::class));
    }

    /**
     * Build an auth factory whose given guard returns the given user.
     *
     * @param  string|null  $name
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null  $user
     * @return \Illuminate\Contracts\Auth\Factory
     */
    private function factoryReturning(?string $name, ?Authenticatable $user): AuthFactory
    {
        $guard = \Mockery::mock(Guard::class);
        $guard->shouldReceive('user')->once()->andReturn($user);

        $factory = \Mockery::mock(AuthFactory::class);
        $factory->shouldReceive('guard')->once()->with($name)->andReturn($guard);

        return $factory;
    }

    /**
     * Return a configuration whose Laravel default guard is the given value.
     *
     * @param  mixed  $guard
     * @return \Illuminate\Contracts\Config\Repository
     */
    private function configWithDefaultGuard(mixed $guard): ConfigRepository
    {
        $config = \Mockery::mock(ConfigRepository::class);
        $config->shouldReceive('get')->with('auth.defaults.guard')->andReturn($guard);

        return $config;
    }
}
