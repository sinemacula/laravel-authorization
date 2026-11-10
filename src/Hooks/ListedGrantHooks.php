<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Hooks;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;

/**
 * The hooks `authorization.grant_hooks` lists, run before the hook bound on the
 * grant hook contract (N108).
 *
 * When the configuration lists hooks, the package extends the contract with
 * `around()`, so whatever Laravel builds for the contract is wrapped in this
 * decorator, and the grant service wraps the hook it calls with `wrap()`, so an
 * instance Laravel applies no extender to is wrapped too: the listed hooks run
 * first, in the order listed, then the hook it wraps, and any of them may
 * refuse. Hooks only refuse, so wrapping a hook never lets through what it
 * would refuse.
 *
 * The listed hooks run once for each call of a decorator, however many
 * decorators are nested in it, as when an extender registered after the
 * package's decorates the wrapped hook and the grant service wraps the
 * decoration again: a decorator called while another runs its hook for the same
 * widening calls its own hook alone. The decorators share which widenings they
 * are running their hook for, as nothing else reaches every one of them: a
 * widening is held only while a decorator runs its hook for it, weakly, and let
 * go once the hook returns or throws, so nothing is kept from one call to the
 * next, a call tried again with the same widening included.
 *
 * The listed hooks are built from the container that wrapped the hook, at the
 * decorator's first use, never when it is made, so wrapping an instance while
 * the package registers builds none of them. They are kept with the decorator,
 * which the container keeps as long as it would keep the hook it wraps: built
 * afresh for each request or job when the hook is the package's default, scoped
 * or bound with `bind()`, and kept with it when it is a singleton or an
 * instance.
 *
 * @managed-static
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ListedGrantHooks implements GrantHook
{
    /** @var \WeakMap<\SineMacula\Laravel\Authorization\Hooks\GrantWidening, true>|null The widenings a decorator is running its hook for, once the listed hooks have run. */
    private static ?\WeakMap $running = null;

    /** @var \SineMacula\Laravel\Authorization\Hooks\GrantHooks|null The listed hooks, once built. */
    private ?GrantHooks $listed = null;

    /**
     * Create a new decorator running the listed hooks before the hook.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantHook  $hook
     */
    public function __construct(

        /** The container the listed hooks are built from. */
        private readonly Container $container,

        /** The hook the listed hooks run before. */
        private readonly GrantHook $hook,
    ) {}

    /**
     * Wrap what the contract resolved to, the extender the package registers on
     * it, leaving anything that is no grant hook as it is, for the grant
     * service to refuse.
     *
     * @param  mixed  $hook
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return mixed
     */
    public static function around(mixed $hook, Container $container): mixed
    {
        return $hook instanceof GrantHook ? self::wrap($hook, $container) : $hook;
    }

    /**
     * Wrap the hook, unless it already is a decorator, as when the package
     * registered again in the same container or the grant service wraps the
     * hook the contract resolved to, so the listed hooks never run twice.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantHook  $hook
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return \SineMacula\Laravel\Authorization\Contracts\GrantHook
     */
    public static function wrap(GrantHook $hook, Container $container): GrantHook
    {
        return $hook instanceof self ? $hook : new self($container, $hook);
    }

    /**
     * Call each listed hook with the widening, in order, then the hook,
     * stopping at the first that throws; only the hook when a decorator this
     * one is nested in already ran the listed hooks for the widening.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    public function beforeWidening(GrantWidening $widening): void
    {
        $running = self::$running ??= new \WeakMap;

        if (isset($running[$widening])) {
            $this->hook->beforeWidening($widening);

            return;
        }

        $this->listed ??= GrantHooks::fromConfig($this->container);
        $this->listed->beforeWidening($widening);

        $running[$widening] = true;

        try {
            $this->hook->beforeWidening($widening);
        } finally {
            unset($running[$widening]);
        }
    }
}
