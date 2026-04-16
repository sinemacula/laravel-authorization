<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Enums\GateConflictMode;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Models\Permission;
use Tests\Feature\Stubs\PermissionEnum;
use Tests\TestCase;

/**
 * Stub `PolicyStore` implementation used to verify that a bound
 * store is resolved through the singleton container after the
 * service provider wires it up.
 *
 * @internal
 */
final class StubPolicyStore implements PolicyStore
{
    /**
     * @param  object  $principal
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function policiesFor(object $principal): array
    {
        return [];
    }
}

/**
 * Stub `PermissionProvider` that returns an empty string and a
 * non-string value — the service provider must skip both without
 * raising, and without creating database rows for them.
 *
 * @internal
 */
final class StubBadPermissionProvider implements PermissionProvider
{
    /**
     * @return array<int, mixed>
     */
    public function permissions(): array
    {
        return ['', 42, 'valid:perm'];
    }

    public function guard(): ?string
    {
        return 'web';
    }
}

/**
 * Coverage for the final trio of `AuthorizationServiceProvider`
 * branches:
 *
 * - A concrete `policy_store` class triggers the singleton binding
 *   in `registerPolicyStore`.
 * - `authorization.gate.on_conflict` supplied as a native
 *   `GateConflictMode` enum instance (rather than the string
 *   sentinel) is passed through verbatim by `registerGates`.
 * - `registerPermissionProviders` silently skips non-string or
 *   empty entries yielded by a provider, and non-string provider
 *   class-string entries themselves.
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
    /**
     * Setting a concrete `policy_store` class triggers the optional
     * singleton bind so the manager's policy resolver can pick it up.
     *
     * @return void
     */
    public function testPolicyStoreIsBoundWhenConfigured(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.policy_store', StubPolicyStore::class);

        // Re-run the register phase so the binding is picked up; the
        // parent test boot skipped the binding because the default
        // config sets `policy_store` to null.
        (new AuthorizationServiceProvider($this->app))->register();

        self::assertTrue($this->app->bound(PolicyStore::class));
        self::assertInstanceOf(StubPolicyStore::class, $this->app->make(PolicyStore::class));
    }

    /**
     * A native `GateConflictMode` enum value for
     * `authorization.gate.on_conflict` is passed through verbatim —
     * the service provider does not try to cast it or fall back to
     * the default.
     *
     * @return void
     */
    public function testGateConflictModeEnumInstanceIsAcceptedVerbatim(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.gate.on_conflict', GateConflictMode::OVERWRITE);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        // Pre-bind an existing gate so overwrite mode is the path we
        // observe behaviourally. If the provider coerced the enum to
        // the default (THROW), this call would raise.
        \Illuminate\Support\Facades\Gate::define('posts:create', static fn (): bool => true);

        (new AuthorizationServiceProvider($this->app))->boot();

        // The overwrite path ran — the Gate now resolves via the
        // authorization manager rather than the preseeded closure.
        self::assertFalse(\Illuminate\Support\Facades\Gate::allows('posts:create'));
    }

    /**
     * A provider that yields empty or non-string permission values
     * skips those entries without raising, and still persists the
     * well-formed ones.
     *
     * @return void
     */
    public function testPermissionProviderSkipsEmptyAndNonStringEntries(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', [StubBadPermissionProvider::class]);

        (new AuthorizationServiceProvider($this->app))->boot();

        self::assertNotNull(Permission::where('name', 'valid:perm')->first());
        self::assertNull(Permission::where('name', '')->first());
    }

    /**
     * A `permission_enums` entry that is not a string (or does not
     * subclass the `PermissionEnum` contract) is skipped by
     * `registerGates` at runtime. ConfigValidator is swapped out via
     * `registerGates` directly — the validator rejects the same
     * shape earlier in boot, so this test calls the register method
     * via reflection to exercise the runtime guard in isolation.
     *
     * @return void
     */
    public function testRegisterGatesSkipsNonStringEnumEntries(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [123, \stdClass::class, PermissionEnum::class]);
        $config->set('authorization.gate.on_conflict', 'overwrite');

        (new \SineMacula\Laravel\Authorization\Registrars\GateRegistrar($this->app))->register();

        // The valid PermissionEnum entries were wired; the garbage
        // entries were silently skipped without raising.
        self::assertTrue(\Illuminate\Support\Facades\Gate::has('posts:create'));
    }

    /**
     * `registerPermissionProviders` defensively skips entries that
     * are not class-strings or do not implement `PermissionProvider`
     * — the upstream `ConfigValidator` rejects the same shape, so
     * this exercises the runtime guard via reflection.
     *
     * @return void
     */
    public function testRegisterPermissionProvidersSkipsBadEntries(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', [
            123,                                    // non-string
            \stdClass::class,                       // string but not a provider
            StubBadPermissionProvider::class,       // well-formed
        ]);

        $provider = new AuthorizationServiceProvider($this->app);

        $reflection = new \ReflectionMethod($provider, 'registerPermissionProviders');
        $reflection->invoke($provider);

        self::assertNotNull(Permission::where('name', 'valid:perm')->first());
    }
}
