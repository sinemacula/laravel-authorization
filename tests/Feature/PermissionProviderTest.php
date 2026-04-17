<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\Feature\Stubs\StubNullGuardProvider;
use Tests\Feature\Stubs\StubPermissionProvider;
use Tests\TestCase;

/**
 * Feature tests for the `PermissionProvider` boot-time registration.
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
#[CoversClass(ConfigValidator::class)]
final class PermissionProviderTest extends TestCase
{
    /**
     * A stub provider creates permission rows in the database on boot.
     *
     * @return void
     */
    public function testProviderCreatesPermissionRowsOnBoot(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject (test container is non-null)
        $config->set('authorization.permission_providers', [StubPermissionProvider::class]);

        (new AuthorizationServiceProvider($this->app))->boot();

        self::assertNotNull(
            Permission::where('name', 'media:upload')->where('guard_name', 'web')->first(),
            'Expected media:upload permission to exist in the database.',
        );

        self::assertNotNull(
            Permission::where('name', 'media:delete')->where('guard_name', 'web')->first(),
            'Expected media:delete permission to exist in the database.',
        );
    }

    /**
     * Provider registration is idempotent — booting twice does not
     * create duplicate rows.
     *
     * @return void
     */
    public function testProviderRegistrationIsIdempotent(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject (test container is non-null)
        $config->set('authorization.permission_providers', [StubPermissionProvider::class]);

        (new AuthorizationServiceProvider($this->app))->boot();
        (new AuthorizationServiceProvider($this->app))->boot();

        self::assertSame(
            1,
            Permission::where('name', 'media:upload')->where('guard_name', 'web')->count(), // @phpstan-ignore staticMethod.dynamicCall (facade indirection)
        );
    }

    /**
     * A provider with a null guard creates guard-agnostic permission
     * rows.
     *
     * @return void
     */
    public function testNullGuardProviderCreatesAgnosticPermissions(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject (test container is non-null)
        $config->set('authorization.permission_providers', [StubNullGuardProvider::class]);

        (new AuthorizationServiceProvider($this->app))->boot();

        $permission = Permission::where('name', 'billing:view')->whereNull('guard_name')->first(); // @phpstan-ignore staticMethod.dynamicCall (facade indirection)

        self::assertNotNull($permission, 'Expected billing:view guard-agnostic permission to exist.');
    }

    /**
     * Config validation rejects a non-existent provider class.
     *
     * @return void
     */
    public function testConfigValidationRejectsNonExistentClass(): void
    {
        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessageMatches('/does not exist/');

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject (test container is non-null)
        $config->set('authorization.permission_providers', ['App\NonExistent\Provider']);

        (new AuthorizationServiceProvider($this->app))->boot();
    }

    /**
     * Config validation rejects a class that does not implement the
     * contract.
     *
     * @return void
     */
    public function testConfigValidationRejectsNonImplementingClass(): void
    {
        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessageMatches('/does not implement/');

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject (test container is non-null)
        $config->set('authorization.permission_providers', [\stdClass::class]);

        (new AuthorizationServiceProvider($this->app))->boot();
    }

    /**
     * An empty providers array is a no-op.
     *
     * @return void
     */
    public function testEmptyProvidersArrayIsNoop(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject (test container is non-null)
        $config->set('authorization.permission_providers', []);

        (new AuthorizationServiceProvider($this->app))->boot();

        self::assertSame(0, Permission::count());
    }
}
