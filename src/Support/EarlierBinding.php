<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Container\Container;

/**
 * Keeps what a sibling package or the application bound on a contract before
 * the package registered under a package-owned key, so the package can bind the
 * contract itself and still reach it (N107).
 *
 * The binding is copied as it was made, and nothing is resolved: a binding
 * keeps its concrete and is shared, scoped or neither as it was, so the queue
 * worker and Octane reset it as they would have; an instance, whether bound
 * with `instance()` or already resolved from a shared binding, is kept as that
 * instance; and an alias resolves the abstract it names. The container keeps
 * which abstracts are scoped and which instances it holds to itself, so they
 * are read in its own scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class EarlierBinding
{
    /**
     * Copy what is bound on the abstract under the key, as it was bound,
     * without resolving it. Nothing is bound under the key when nothing is
     * bound on the abstract.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $abstract
     * @param  string  $key
     * @return void
     */
    public static function copy(Container $container, string $abstract, string $key): void
    {
        /** @var array<string, array{concrete: \Closure, shared: bool}> $bindings */
        $bindings = $container->getBindings();
        $binding  = $bindings[$abstract] ?? null;

        [$instance, $scoped] = self::state($container, $abstract);

        if ($binding !== null) {
            $scoped
                ? $container->scoped($key, $binding['concrete'])
                : $container->bind($key, $binding['concrete'], $binding['shared']);
        }

        if ($instance !== null) {
            $container->instance($key, $instance);
        }

        if ($binding !== null || $instance !== null || !$container->isAlias($abstract)) {
            return;
        }

        $target = $container->getAlias($abstract);

        $container->bind($key, static fn (Container $container): mixed => $container->make($target));
    }

    /**
     * Return the instance the container holds for the abstract, if any, and
     * whether the abstract is scoped.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $abstract
     * @return array{object|null, bool}
     */
    private static function state(Container $container, string $abstract): array
    {
        $read = \Closure::bind(static fn (Container $container): array => [
            $container->instances[$abstract] ?? null,
            \in_array($abstract, $container->scopedInstances, true),
        ], null, Container::class);

        /** @var array{object|null, bool} */
        return $read($container);
    }
}
