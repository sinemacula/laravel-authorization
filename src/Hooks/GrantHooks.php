<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Hooks;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;

/**
 * The ordered composite of grant hooks (AUTHZ-11.3), and, holding none, the
 * package's default binding of the grant hook contract.
 *
 * It calls its hooks in order: the first that throws stops the rest, and its
 * exception refuses the call. `fromConfig()` builds it from the hooks
 * `authorization.grant_hooks` lists, each built from the container. The list is
 * validated at boot, and there is no way to add a hook at run time: an
 * application lists its hooks in the config, or binds its own hook on the
 * contract. The listed hooks run before whatever the contract resolves to, this
 * default included, through `ListedGrantHooks` (N108). With none listed the
 * default does nothing, and the grant service then classifies nothing, since
 * there is no hook to call.
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
