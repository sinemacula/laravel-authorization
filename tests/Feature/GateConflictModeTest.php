<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Exceptions\GateConflictException;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\Feature\Stubs\PermissionEnum;
use Tests\TestCase;

/**
 * Dedicated feature coverage for the three Gate auto-wiring conflict
 * modes driven by `authorization.gate.on_conflict`.
 *
 * Each scenario pre-registers a Gate under the same name as a
 * permission-enum case, reboots the provider, and asserts the
 * mode-specific behaviour: `log` preserves the existing Gate and
 * emits a warning, `throw` raises `GateConflictException`, and
 * `overwrite` replaces the existing closure with the package's
 * authorization-backed one.
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
#[CoversClass(EventListenerRegistrar::class)]
final class GateConflictModeTest extends TestCase
{
    /** Permission the three scenarios collide on. */
    private const string CONFLICTING_PERMISSION = 'posts:create';

    /**
     * `log` mode preserves the pre-existing Gate and emits a warning
     * via the global `Log` facade, which the spy captures.
     *
     * @return void
     */
    public function testLogModePreservesExistingGateAndLogsWarning(): void
    {
        // Swap the global log manager with a Mockery spy so every
        // `warning(...)` call the package routes through the `Log`
        // facade is recorded without stubbing channel resolution.
        $spy = \Mockery::spy(LoggerInterface::class);
        Log::swap($spy);

        // Pre-register a sentinel Gate that always allows so the
        // test can prove the package did NOT overwrite it.
        Gate::define(self::CONFLICTING_PERMISSION, static fn (?object $user = null): bool => true);

        $this->configureGate('log');

        (new AuthorizationServiceProvider($this->app))->boot();

        self::assertTrue(Gate::has(self::CONFLICTING_PERMISSION));
        // Existing sentinel closure still in effect.
        self::assertTrue(Gate::forUser((object) [])->allows(self::CONFLICTING_PERMISSION));

        $spy->shouldHaveReceived('warning')->withArgs(
            static fn (mixed $message): bool => \is_string($message)
                && \str_contains($message, self::CONFLICTING_PERMISSION)
                && \str_contains($message, 'already registered'),
        )->once();
    }

    /**
     * `throw` mode raises `GateConflictException` at boot when a
     * conflicting Gate is already defined.
     *
     * @return void
     */
    public function testThrowModeRaisesGateConflictException(): void
    {
        Gate::define(self::CONFLICTING_PERMISSION, static fn (): bool => true);

        $this->configureGate('throw');

        $provider = new AuthorizationServiceProvider($this->app);

        try {
            $provider->boot();
            self::fail('Expected GateConflictException to be raised.');
        } catch (GateConflictException $exception) {
            self::assertSame(self::CONFLICTING_PERMISSION, $exception->getPermission());
        }
    }

    /**
     * `overwrite` mode replaces the pre-existing Gate with the
     * package-owned closure that delegates to the authorization
     * manager.
     *
     * @return void
     */
    public function testOverwriteModeReplacesExistingGate(): void
    {
        // Sentinel closure that would return true if preserved. The
        // package's closure routes through the null principal
        // resolver, so the overwritten Gate must return false.
        Gate::define(self::CONFLICTING_PERMISSION, static fn (): bool => true);

        $this->configureGate('overwrite');

        (new AuthorizationServiceProvider($this->app))->boot();

        self::assertTrue(Gate::has(self::CONFLICTING_PERMISSION));
        self::assertFalse(
            Gate::allows(self::CONFLICTING_PERMISSION),
            'Expected the overwritten Gate to defer to the null principal resolver and deny.',
        );
    }

    /**
     * Seed the conflict mode and enum registration used by every
     * scenario.
     *
     * @param  string  $mode
     * @return void
     */
    private function configureGate(string $mode): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.gate.on_conflict', $mode);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);
    }
}
