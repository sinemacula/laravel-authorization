<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use Tests\Feature\Stubs\StubPolicyStore;
use Tests\TestCase;

/**
 * Coverage for the remaining `AuthorizationServiceProvider` branches:
 *
 * - A concrete `policy_store` class triggers the singleton binding in
 *   `registerPolicyStore`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
final class ServiceProviderExtraBranchesTest extends TestCase
{
    /**
     * Setting a concrete `policy_store` class triggers the optional singleton
     * bind so the manager's policy resolver can pick it up.
     *
     * @return void
     */
    public function testPolicyStoreIsBoundWhenConfigured(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.policy_store', StubPolicyStore::class);

        // Re-run the register phase so the binding is picked up; the parent
        // test boot skipped the binding because the default config sets
        // `policy_store` to null.
        (new AuthorizationServiceProvider($this->app))->register();

        self::assertTrue($this->app->bound(PolicyStore::class)); // @phpstan-ignore method.nonObject
        self::assertInstanceOf(StubPolicyStore::class, $this->app->make(PolicyStore::class)); // @phpstan-ignore method.nonObject
    }
}
