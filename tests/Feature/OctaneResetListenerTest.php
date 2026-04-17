<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Octane\Events\RequestTerminated;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\TestCase;

/**
 * Feature coverage for the Octane request-boundary reset listener
 * the service provider wires when the Octane event class is present
 * in the host application. Closes ISSUES.md #66.
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
#[CoversClass(LastDecisionStore::class)]
final class OctaneResetListenerTest extends TestCase
{
    /**
     * Firing the Octane request-terminated event clears the
     * last-decision store so the next request inside the same
     * worker process does not see the previous request's result
     * via `Authorization::lastDecision()`.
     *
     * @return void
     */
    public function testOctaneRequestTerminatedEventResetsTheStore(): void
    {
        // Re-boot the provider now that the stubbed Octane event
        // class is guaranteed to exist in this process. Testbench
        // boots the package's service provider during its own
        // setUp(), which can race the test file's namespace
        // declaration on a parallel runner. Booting again here is
        // idempotent for every other surface and guarantees the
        // listener is wired against the in-process FQN.
        (new AuthorizationServiceProvider($this->app))->boot();

        /** @var \Illuminate\Events\Dispatcher $dispatcher */
        $dispatcher = $this->app->make(Dispatcher::class); // @phpstan-ignore method.nonObject (test container is non-null)

        self::assertTrue(
            $dispatcher->hasListeners(RequestTerminated::class),
            'The package should register a listener for the Octane RequestTerminated event when the class is present.',
        );

        /** @var \SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore $store */
        $store = $this->app->make(LastDecisionStore::class); // @phpstan-ignore method.nonObject (test container is non-null)
        $store->put(EvaluationResult::rbacAllowed());

        self::assertNotNull($store->get());

        $dispatcher->dispatch(new RequestTerminated);

        self::assertNull(
            $this->app->make(LastDecisionStore::class)->get(), // @phpstan-ignore method.nonObject (test container is non-null)
            'Dispatching Octane RequestTerminated should clear the LastDecisionStore.',
        );
    }

    /**
     * The store's `reset()` method is the seam the listener calls
     * and the documented manual reset surface for non-Octane
     * long-running workers. Verifies the rename slot semantics
     * stay coherent — `reset()` clears the slot the same way
     * `forget()` does.
     *
     * @return void
     */
    public function testResetClearsTheStore(): void
    {
        $store = new LastDecisionStore;
        $store->put(EvaluationResult::rbacAllowed());

        self::assertNotNull($store->get());

        $store->reset();

        self::assertNull($store->get());
    }
}
