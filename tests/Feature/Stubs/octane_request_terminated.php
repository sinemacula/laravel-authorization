<?php

declare(strict_types = 1);

/**
 * Stub `Laravel\Octane\Events\RequestTerminated` event class loaded
 * by `OctaneResetListenerTest` so the package's listener wiring can
 * detect Octane without a runtime dependency on the Octane package.
 *
 * The class lives in a real `Laravel\Octane\Events` namespace block
 * so `get_class()` returns the FQN the listener is registered
 * against — a `class_alias` on a Tests-namespace class would not
 * satisfy Laravel's dispatcher name match.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */

namespace Laravel\Octane\Events;

if (!\class_exists(RequestTerminated::class, false)) {
    /**
     * @internal
     */
    final class RequestTerminated {}
}
