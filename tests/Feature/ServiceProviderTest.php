<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\TestCase;

/**
 * Feature tests exercising the service provider's container bindings, config
 * publishing, and the Gate hook.
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
#[CoversClass(Authorization::class)]
final class ServiceProviderTest extends TestCase
{
    /**
     * The bindings resolve to the expected classes, and the manager's class
     * alias shares the manager instance.
     *
     * @return void
     */
    public function testBindsManagerEvaluatorAndResolver(): void
    {
        self::assertInstanceOf(PolicyEvaluator::class, $this->container()->make(PolicyEvaluator::class));
        self::assertInstanceOf(AuthGuardSubjectResolver::class, $this->container()->make(SubjectResolver::class));
        self::assertInstanceOf(AuthorizationManager::class, $this->container()->make('authorization'));
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;
        self::assertSame($app->make('authorization'), $app->make(AuthorizationManager::class));
    }

    /**
     * Default config merge seeds the expected keys.
     *
     * @return void
     */
    public function testMergesDefaultConfig(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);

        self::assertSame('web', $config->get('authorization.defaults.guard'));
        self::assertTrue($config->get('authorization.gate.enabled'));
        self::assertSame(AuthGuardSubjectResolver::class, $config->get('authorization.subject_resolver'));
        self::assertFalse($config->has('authorization.principal_resolver'));
        self::assertFalse($config->has('authorization.tenant_resolver'));
    }

    /**
     * Booting registers the Gate hook, so a configured enum's cases are the
     * package's to answer, over a define registered for one of them, while
     * nothing is defined on the Gate.
     *
     * @return void
     */
    public function testBootRegistersTheGateHook(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        Gate::define('posts:create', static fn (?object $user = null): bool => true);

        self::assertFalse(Gate::has('posts:delete'));
        self::assertFalse(Gate::forUser((object) [])->allows('posts:create'));
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
