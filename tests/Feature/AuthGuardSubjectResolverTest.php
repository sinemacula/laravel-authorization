<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\EagerRolesIdentity;
use Tests\TestCase;

/**
 * Feature coverage for `AuthGuardSubjectResolver`, the shipped default that
 * decides about the user Laravel authenticated on its default guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthGuardSubjectResolver::class)]
final class AuthGuardSubjectResolverTest extends TestCase
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
     * A user on Laravel's default guard is the subject and its identity, with
     * no tenant and the guard's name as the application.
     *
     * @return void
     */
    public function testTheDefaultGuardsUserIsTheSubject(): void
    {
        $user     = \Mockery::mock(Authenticatable::class);
        $resolver = new AuthGuardSubjectResolver($this->factoryReturning('web', $user), $this->configWithDefaultGuard('web'));

        $this->assertSubject($resolver->resolve(), $user, 'web');
    }

    /**
     * No user on the guard means no subject.
     *
     * @return void
     */
    public function testNoUserMeansNoSubject(): void
    {
        $resolver = new AuthGuardSubjectResolver($this->factoryReturning('web', null), $this->configWithDefaultGuard('web'));

        self::assertNull($resolver->resolve());
    }

    /**
     * The guard read is Laravel's default guard at the time of the check, so
     * `Auth::shouldUse()` moves the resolver with it.
     *
     * @return void
     */
    public function testFollowsLaravelsDefaultGuard(): void
    {
        $user     = \Mockery::mock(Authenticatable::class);
        $resolver = new AuthGuardSubjectResolver($this->factoryReturning('admin', $user), $this->configWithDefaultGuard('admin'));

        $this->assertSubject($resolver->resolve(), $user, 'admin');
    }

    /**
     * A guard given at construction wins over Laravel's default guard.
     *
     * @return void
     */
    public function testAGuardGivenAtConstructionWins(): void
    {
        $user     = \Mockery::mock(Authenticatable::class);
        $resolver = new AuthGuardSubjectResolver($this->factoryReturning('api', $user), $this->configWithDefaultGuard('web'), 'api');

        $this->assertSubject($resolver->resolve(), $user, 'api');
    }

    /**
     * A default guard that is empty or not a string names no guard: Laravel's
     * auth factory then picks its own default, and the subject has no guard or
     * application.
     *
     * @return void
     */
    public function testAnUnnamedDefaultGuardLeavesTheGuardUnnamed(): void
    {
        foreach (['', 42, null] as $default) {
            $user     = \Mockery::mock(Authenticatable::class);
            $resolver = new AuthGuardSubjectResolver($this->factoryReturning(null, $user), $this->configWithDefaultGuard($default));

            $this->assertSubject($resolver->resolve(), $user, null);
        }
    }

    /**
     * `forUser()` wraps the user it is handed, in the request's guard and
     * application, without reading the guard's own user.
     *
     * @return void
     */
    public function testForUserWrapsTheGivenUser(): void
    {
        $factory = \Mockery::mock(AuthFactory::class);
        $factory->shouldNotReceive('guard');

        $other    = new \stdClass;
        $resolver = new AuthGuardSubjectResolver($factory, $this->configWithDefaultGuard('web'));

        $this->assertSubject($resolver->forUser($other), $other, 'web');
    }

    /**
     * The package binds the resolver by default, and it reads the user signed
     * in through Laravel's auth.
     *
     * @return void
     */
    public function testIsTheDefaultBindingAndReadsTheSignedInUser(): void
    {
        $resolver = $this->app?->make(SubjectResolver::class);

        self::assertInstanceOf(AuthGuardSubjectResolver::class, $resolver);
        self::assertNull($resolver->resolve());

        $user = AuthenticatableIdentity::create(['id' => 'a3c1f9c2-2b84-4d3e-9f3c-7f8d1c1e9a01']);
        $this->actingAs($user);

        $this->assertSubject($resolver->resolve(), $user, 'web');
    }

    /**
     * A user the session guard loads with its roles is resolved once: the roles
     * query run while loading it sees platform rows, instead of asking the
     * resolver again without end.
     *
     * @return void
     */
    public function testAUserLoadedWithItsRolesFromTheSessionResolves(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('auth.providers.users', ['driver' => 'eloquent', 'model' => EagerRolesIdentity::class]);

        Role::create(['name' => 'admin', 'guard' => 'web']);

        $user = EagerRolesIdentity::create(['id' => 'b8e2c4d6-1a3f-4e5b-8c7d-9f0a1b2c3d4e']);
        $user->assignRole('admin');

        /** @var \Illuminate\Auth\SessionGuard $guard */
        $guard = $this->app?->make('auth')->guard('web');
        $this->app?->make('session.store')->put($guard->getName(), $user->getKey());

        // A new request: nothing is resolved, and its first roles query
        // resolves the subject, which loads the user with its roles.
        $this->app?->forgetScopedInstances();

        self::assertSame(['admin'], Role::query()->pluck('name')->all());

        $subject = $this->app?->make(SubjectResolver::class)->resolve();

        self::assertInstanceOf(EagerRolesIdentity::class, $subject?->subject);
        self::assertSame($user->getKey(), $subject->subject->getKey());
        self::assertTrue($subject->subject->hasRole('admin'));
    }

    /**
     * Assert the subject is about the given user, as its own identity, with no
     * tenant and the given guard as both guard and application.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  object  $user
     * @param  string|null  $guard
     * @return void
     */
    private function assertSubject(?Subject $subject, object $user, ?string $guard): void
    {
        self::assertNotNull($subject);
        self::assertSame($user, $subject->subject);
        self::assertSame($user, $subject->identity);
        self::assertNull($subject->tenant);
        self::assertSame($guard, $subject->application);
        self::assertSame($guard, $subject->guard);
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
