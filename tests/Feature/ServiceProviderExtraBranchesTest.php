<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Enums\GateConflictMode;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\Feature\Stubs\PermissionEnum;
use Tests\Feature\Stubs\StubPolicyStore;
use Tests\TestCase;

/**
 * Coverage for the remaining `AuthorizationServiceProvider` branches:
 *
 * - A concrete `policy_store` class triggers the singleton binding in
 *   `registerPolicyStore`.
 * - `authorization.gate.on_conflict` supplied as a native `GateConflictMode`
 *   enum instance (rather than the string sentinel) is passed through verbatim
 *   by `registerGates`.
 * - `registerGates` skips non-string and non-contract entries in
 *   `permission_enums` at runtime.
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
final class ServiceProviderExtraBranchesTest extends TestCase
{
    private const string POSTS_CREATE = 'posts:create';

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

        // Re-run the register phase so the binding is picked up; the
        // parent test boot skipped the binding because the default
        // config sets `policy_store` to null.
        (new AuthorizationServiceProvider($this->app))->register();

        self::assertTrue($this->app->bound(PolicyStore::class)); // @phpstan-ignore method.nonObject
        self::assertInstanceOf(StubPolicyStore::class, $this->app->make(PolicyStore::class)); // @phpstan-ignore method.nonObject
    }

    /**
     * A native `GateConflictMode` enum value for
     * `authorization.gate.on_conflict` is passed through verbatim — the service
     * provider does not try to cast it or fall back to the default.
     *
     * @return void
     */
    public function testGateConflictModeEnumInstanceIsAcceptedVerbatim(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.gate.on_conflict', GateConflictMode::OVERWRITE);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        // Pre-bind an existing gate so overwrite mode is the path we
        // observe behaviourally. If the provider coerced the enum to
        // the default (THROW), this call would raise.
        \Illuminate\Support\Facades\Gate::define(self::POSTS_CREATE, static fn (): bool => true);

        (new AuthorizationServiceProvider($this->app))->boot();

        // The overwrite path ran — the Gate now resolves via the
        // authorization manager rather than the preseeded closure.
        self::assertFalse(\Illuminate\Support\Facades\Gate::allows(self::POSTS_CREATE));
    }

    /**
     * A `permission_enums` entry that is not a string (or does not subclass the
     * `PermissionEnum` contract) is skipped by `registerGates` at runtime.
     * ConfigValidator is swapped out via `registerGates` directly — the
     * validator rejects the same shape earlier in boot, so this test calls the
     * register method via reflection to exercise the runtime guard in
     * isolation.
     *
     * @return void
     */
    public function testRegisterGatesSkipsNonStringEnumEntries(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [123, \stdClass::class, PermissionEnum::class]);
        $config->set('authorization.gate.on_conflict', 'overwrite');

        (new \SineMacula\Laravel\Authorization\Registrars\GateRegistrar($this->app))->register();

        // The valid PermissionEnum entries were wired; the garbage
        // entries were silently skipped without raising.
        self::assertTrue(\Illuminate\Support\Facades\Gate::has(self::POSTS_CREATE));
    }
}
