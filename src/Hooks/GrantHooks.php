<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Hooks;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;

/**
 * The ordered composite of grant hooks, and the package's default binding of
 * the grant hook contract (AUTHZ-11.3).
 *
 * It holds the hooks `authorization.grant_hooks` lists, each built from the
 * container, and calls them in the order listed: the first that throws stops
 * the rest, and its exception refuses the call. With none listed it does
 * nothing, and the grant service then classifies nothing, since there is no
 * hook to call. The list is validated at boot, and there is no way to add a
 * hook at run time: an application lists its hooks in the config, or binds its
 * own hook on the contract in place of this one.
 *
 * When the config lists hooks and a sibling package or the application bound a
 * hook on the contract before the package registered, the composite holds that
 * hook too, after the listed ones (N107): every hook runs, and any of them may
 * refuse, so nothing either would refuse is let through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GrantHooks implements GrantHook
{
    /**
     * Create a new composite of the hooks, in the order they run.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Contracts\GrantHook>  $hooks
     */
    public function __construct(

        /** The hooks, in the order they run. */
        private array $hooks = [],
    ) {}

    /**
     * Return the composite of the hooks `authorization.grant_hooks` lists, in
     * the order listed, each built from the container.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fromConfig(Container $container): self
    {
        /** @var list<class-string<\SineMacula\Laravel\Authorization\Contracts\GrantHook>> $classes */
        $classes = (array) config('authorization.grant_hooks', []);

        /** @var list<\SineMacula\Laravel\Authorization\Contracts\GrantHook> $hooks */
        $hooks = \array_map(static fn (string $class): object => $container->make($class), $classes);

        return new self($hooks);
    }

    /**
     * Return the composite of the hooks `authorization.grant_hooks` lists,
     * followed by the hook bound under the key, when one is (N107).
     *
     * The key holds what was bound on the contract before the package
     * registered, so that hook runs after every listed one.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $key
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function composed(Container $container, string $key): self
    {
        $listed = self::fromConfig($container);

        if (!$container->bound($key)) {
            return $listed;
        }

        $earlier = $container->make($key);

        if (!$earlier instanceof GrantHook) {
            $type = \get_debug_type($earlier);

            throw new \UnexpectedValueException('The grant hook bound on ' . GrantHook::class . " before the package registered resolves to {$type}, which does not implement it.");
        }

        return new self([...$listed->hooks, $earlier]);
    }

    /**
     * Call each hook with the widening, in order, stopping at the first that
     * throws.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    public function beforeWidening(GrantWidening $widening): void
    {
        foreach ($this->hooks as $hook) {
            $hook->beforeWidening($widening);
        }
    }

    /**
     * Determine whether the composite holds no hook, so calling it does
     * nothing.
     *
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->hooks === [];
    }

    /**
     * Return the hooks, in the order they run.
     *
     * @return list<\SineMacula\Laravel\Authorization\Contracts\GrantHook>
     */
    public function hooks(): array
    {
        return $this->hooks;
    }
}
