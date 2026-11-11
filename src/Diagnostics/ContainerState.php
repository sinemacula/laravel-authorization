<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Container\Container as BaseContainer;
use Illuminate\Contracts\Container\Container;

/**
 * Read what a container holds for an abstract without building anything.
 *
 * The bindings and the alias are read through the container's public methods.
 * What Laravel offers no public way to read, the instances it holds, whether it
 * resolved the abstract (its public `resolved()` also counts an instance held),
 * the abstracts it scopes and the extenders still pending, is read in the
 * container's own scope, as `AuthorizationServiceProvider::isPackageDefault()`
 * reads the instances. Nothing here calls `make()`, `rebinding()`, `refresh()`,
 * `extend()` or `isShared()`, any of which may build or autoload what it is
 * asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContainerState
{
    /**
     * Return the concrete of the binding the container holds for the abstract,
     * or null when it holds none.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return (\Closure(mixed ...): mixed)|null
     */
    public static function concrete(Container $container, string $abstract): ?\Closure
    {
        $concrete = self::bindings($container)[$abstract]['concrete'] ?? null;

        return $concrete instanceof \Closure ? $concrete : null;
    }

    /**
     * Determine whether the binding the container holds for the abstract is
     * shared, a singleton or scoped.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return bool
     */
    public static function isShared(Container $container, string $abstract): bool
    {
        return (self::bindings($container)[$abstract]['shared'] ?? false) === true;
    }

    /**
     * Return the instance the container holds for the abstract, or null when it
     * holds none.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return object|null
     */
    public static function instance(Container $container, string $abstract): ?object
    {
        if (!$container instanceof BaseContainer) {
            return null;
        }

        $instance = \Closure::bind(static fn (BaseContainer $container): mixed => $container->instances[$abstract] ?? null, null, BaseContainer::class)($container);

        return \is_object($instance) ? $instance : null;
    }

    /**
     * Determine whether the container resolved the abstract before, after its
     * alias is followed. Unlike `resolved()`, an instance handed to the
     * container and never resolved does not count.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return bool
     */
    public static function wasResolved(Container $container, string $abstract): bool
    {
        if (!$container instanceof BaseContainer) {
            return false;
        }

        $alias = $container->getAlias($abstract);

        return \Closure::bind(static fn (BaseContainer $container): bool => isset($container->resolved[$alias]), null, BaseContainer::class)($container);
    }

    /**
     * Determine whether the container forgets the abstract's instance between
     * requests and jobs, as it does for one bound with `scoped()`.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return bool
     */
    public static function isScoped(Container $container, string $abstract): bool
    {
        if (!$container instanceof BaseContainer) {
            return false;
        }

        return \Closure::bind(static fn (BaseContainer $container): bool => \in_array($abstract, $container->scopedInstances, true), null, BaseContainer::class)($container);
    }

    /**
     * Return the abstracts the container forgets between requests and jobs,
     * those bound with `scoped()`, in the order they were bound, or none for a
     * container that is not Laravel's.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return list<string>
     */
    public static function scopedAbstracts(Container $container): array
    {
        if (!$container instanceof BaseContainer) {
            return [];
        }

        /** @var \Closure(\Illuminate\Container\Container): list<string> $scoped */
        $scoped = \Closure::bind(static fn (BaseContainer $container): array => $container->scopedInstances, null, BaseContainer::class);

        return $scoped($container);
    }

    /**
     * Return the extenders the container still holds for the abstract, after
     * its alias is followed, in the order they were registered. An extender
     * Laravel applied at once to an instance it already held is not kept, so it
     * is not among them.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return list<\Closure(mixed ...): mixed>
     */
    public static function extenders(Container $container, string $abstract): array
    {
        if (!$container instanceof BaseContainer) {
            return [];
        }

        $alias     = $container->getAlias($abstract);
        $extenders = \Closure::bind(static fn (BaseContainer $container): array => $container->extenders[$alias] ?? [], null, BaseContainer::class)($container);

        return \array_values(\array_filter($extenders, static fn (mixed $extender): bool => $extender instanceof \Closure));
    }

    /**
     * Return the abstract the abstract is an alias of, or null when it is no
     * alias.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return string|null
     */
    public static function alias(Container $container, string $abstract): ?string
    {
        if (!$container instanceof BaseContainer) {
            return null;
        }

        $alias = $container->getAlias($abstract);

        return $alias === $abstract ? null : $alias;
    }

    /**
     * Return the bindings the container holds, or none for a container that is
     * not Laravel's.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return array<string, array{concrete?: mixed, shared?: bool}>
     */
    private static function bindings(Container $container): array
    {
        return $container instanceof BaseContainer ? $container->getBindings() : [];
    }
}
