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
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\Feature\Stubs\StubPermissionProvider;
use Tests\TestCase;

/**
 * Feature tests for the boot-time handling of permission providers.
 *
 * A configured provider is validated at boot and never read there: booting
 * writes no permission rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(ConfigValidator::class)]
final class PermissionProviderTest extends TestCase
{
    /**
     * Booting with a provider configured writes no permission rows.
     *
     * @return void
     */
    public function testBootWritesNoPermissionRows(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_providers', [StubPermissionProvider::class]);

        (new AuthorizationServiceProvider($this->app))->boot();

        self::assertSame(0, Permission::count());
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
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_providers', ['App\NonExistent\Provider']);

        (new AuthorizationServiceProvider($this->app))->boot();
    }

    /**
     * Config validation rejects a class that does not implement the contract.
     *
     * @return void
     */
    public function testConfigValidationRejectsNonImplementingClass(): void
    {
        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessageMatches('/does not implement/');

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_providers', [\stdClass::class]);

        (new AuthorizationServiceProvider($this->app))->boot();
    }
}
