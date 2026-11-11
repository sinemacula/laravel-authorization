<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Diagnostics\ContainerState;

/**
 * The registration steps the package leaves to the application's boot: those
 * that may load or run code the configuration names, which the package's
 * `register()` records rather than runs.
 *
 * Binding a class the configuration names autoloads it, loads a deferred
 * provider that provides its contract and calls the callbacks watching the
 * contract, and extending the grant hook applies at once to an instance held.
 * The package's `register()` binds each default and records each such step
 * here, with the name the configuration gives as a string (see `SeamBindings`).
 * They run as the application boots, after every provider registered and before
 * any boots, in the order recorded, once it is known that the configuration is
 * not refused (see `GuardedBoot`), or are dropped when it is.
 *
 * It is held as an instance of the container, never statically, so each
 * application keeps its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PendingRegistration
{
    /** @var list<\Closure(): void> Each step, in the order recorded. */
    private array $steps = [];

    /**
     * Return the steps the container holds, holding none first when it holds
     * none.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function of(Container $container): self
    {
        $pending = self::find($container);

        if ($pending !== null) {
            return $pending;
        }

        $pending = new self;

        $container->instance(self::class, $pending);

        return $pending;
    }

    /**
     * Return the steps the container holds, or null when it holds none.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self|null
     */
    public static function find(Container $container): ?self
    {
        $pending = ContainerState::instance($container, self::class);

        return $pending instanceof self ? $pending : null;
    }

    /**
     * Record a step to run as the application boots.
     *
     * @param  \Closure(): void  $step
     * @return void
     */
    public function later(\Closure $step): void
    {
        $this->steps[] = $step;
    }

    /**
     * Determine whether any step is still to run.
     *
     * @return bool
     */
    public function isPending(): bool
    {
        return $this->steps !== [];
    }

    /**
     * Run each step recorded, in order, each once, including one a step
     * records.
     *
     * @return void
     */
    public function run(): void
    {
        while ($this->steps !== []) {
            $step = \array_shift($this->steps);

            $step();
        }
    }

    /**
     * Drop each step recorded, running none.
     *
     * @return void
     */
    public function discard(): void
    {
        $this->steps = [];
    }
}
