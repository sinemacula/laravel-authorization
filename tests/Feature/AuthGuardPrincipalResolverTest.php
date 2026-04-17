<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\Guard;
use Mockery;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardPrincipalResolver;
use Tests\TestCase;

/**
 * Feature coverage for `AuthGuardPrincipalResolver` — the shipped adapter that
 * reads the current principal out of Laravel's standard auth factory.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthGuardPrincipalResolver::class)]
final class AuthGuardPrincipalResolverTest extends TestCase
{
    /**
     * Tear down Mockery instances after every test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * When the configured guard has a user, the resolver hands it back
     * unchanged.
     *
     * @return void
     */
    public function testReturnsAuthenticatableFromConfiguredGuard(): void
    {
        $user  = \Mockery::mock(Authenticatable::class);
        $guard = \Mockery::mock(Guard::class);
        $guard->shouldReceive('user')->once()->andReturn($user);

        $factory = \Mockery::mock(AuthFactory::class);
        $factory->shouldReceive('guard')->once()->with('web')->andReturn($guard);

        $resolver = new AuthGuardPrincipalResolver($factory);

        self::assertSame($user, $resolver->resolve());
    }

    /**
     * When the guard reports no user, the resolver returns null so the
     * authorization engine falls through to implicit deny.
     *
     * @return void
     */
    public function testReturnsNullWhenGuardIsAnonymous(): void
    {
        $guard = \Mockery::mock(Guard::class);
        $guard->shouldReceive('user')->once()->andReturnNull();

        $factory = \Mockery::mock(AuthFactory::class);
        $factory->shouldReceive('guard')->once()->andReturn($guard);

        $resolver = new AuthGuardPrincipalResolver($factory);

        self::assertNull($resolver->resolve());
    }

    /**
     * An explicit guard override (for multi-guard deployments pinning
     * authorization to a specific guard) is honoured.
     *
     * @return void
     */
    public function testExplicitGuardOverrideIsHonoured(): void
    {
        $user  = \Mockery::mock(Authenticatable::class);
        $guard = \Mockery::mock(Guard::class);
        $guard->shouldReceive('user')->once()->andReturn($user);

        $factory = \Mockery::mock(AuthFactory::class);
        $factory->shouldReceive('guard')->once()->with('api')->andReturn($guard);

        $resolver = new AuthGuardPrincipalResolver($factory, guard: 'api');

        self::assertSame($user, $resolver->resolve());
    }

    /**
     * Wiring the resolver through the config binds it as the shipped
     * `PrincipalResolver` implementation.
     *
     * @return void
     */
    public function testContainerResolvesThroughConfig(): void
    {
        // Confirms the resolver is constructible through the
        // service container so
        // `authorization.principal_resolver => AuthGuardPrincipalResolver::class`
        // is a valid one-line wiring for consumers.
        $resolver = $this->app->make(AuthGuardPrincipalResolver::class); // @phpstan-ignore method.nonObject (test container is non-null)

        self::assertInstanceOf(AuthGuardPrincipalResolver::class, $resolver);
    }
}
