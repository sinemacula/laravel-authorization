<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Exceptions\GateConflictException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;
use Tests\Feature\Stubs\PermissionEnum;
use Tests\TestCase;

/**
 * Feature tests exercising the service provider's container bindings,
 * config publishing, and Gate auto-wiring.
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
#[CoversClass(Authorization::class)]
final class ServiceProviderTest extends TestCase
{
    /**
     * Bindings are registered as singletons.
     *
     * @return void
     */
    public function testBindsManagerEvaluatorAndResolver(): void
    {
        self::assertInstanceOf(PolicyEvaluator::class, $this->app->make(PolicyEvaluator::class));
        self::assertInstanceOf(NullPrincipalResolver::class, $this->app->make(PrincipalResolver::class));
        self::assertInstanceOf(AuthorizationManager::class, $this->app->make('authorization'));
        self::assertSame($this->app->make('authorization'), $this->app->make(AuthorizationManager::class));
    }

    /**
     * Default config merge seeds the expected keys.
     *
     * @return void
     */
    public function testMergesDefaultConfig(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);

        self::assertSame('web', $config->get('authorization.defaults.guard'));
        self::assertSame('throw', $config->get('authorization.gate.on_conflict'));
        self::assertSame(NullPrincipalResolver::class, $config->get('authorization.principal_resolver'));
    }

    /**
     * Permission enum is wired into a Gate per case.
     *
     * @return void
     */
    public function testRegistersGateForEachEnumCase(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        // Re-boot the provider so the new config is picked up.
        $provider = new AuthorizationServiceProvider($this->app);
        $provider->boot();

        self::assertTrue(Gate::has('posts:create'));
        self::assertTrue(Gate::has('posts:delete'));
    }

    /**
     * Gate conflict policy = throw raises a dedicated exception.
     *
     * @return void
     */
    public function testGateConflictThrowMode(): void
    {
        Gate::define('posts:create', static fn (): bool => true);

        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.gate.on_conflict', 'throw');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        $provider = new AuthorizationServiceProvider($this->app);

        $this->expectException(GateConflictException::class);
        $provider->boot();
    }

    /**
     * Gate conflict policy = log preserves the existing Gate.
     *
     * @return void
     */
    public function testGateConflictLogMode(): void
    {
        Gate::define('posts:create', static fn (?object $user = null): bool => true);

        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.gate.on_conflict', 'log');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        $provider = new AuthorizationServiceProvider($this->app);
        $provider->boot();

        self::assertTrue(Gate::has('posts:create'));
        // Existing closure still in effect — returns true regardless of user.
        self::assertTrue(Gate::forUser((object) [])->allows('posts:create'));
    }

    /**
     * Gate conflict policy = overwrite replaces the existing Gate.
     *
     * @return void
     */
    public function testGateConflictOverwriteMode(): void
    {
        Gate::define('posts:create', static fn (): bool => true);

        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.gate.on_conflict', 'overwrite');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        $provider = new AuthorizationServiceProvider($this->app);
        $provider->boot();

        // The overwritten Gate now goes through the authorization manager,
        // which returns false for the anonymous null resolver.
        self::assertFalse(Gate::allows('posts:create'));
    }

    /**
     * Facade resolves to the bound manager singleton.
     *
     * @return void
     */
    public function testFacadeResolvesManager(): void
    {
        self::assertFalse(Authorization::can('posts:create'));
    }
}
