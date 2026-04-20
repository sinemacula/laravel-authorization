<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

/**
 * Container-bound static instance accessor.
 *
 * Provides a single, centralised `instance()` method that resolves the
 * consuming class from the Laravel container — or returns null when the
 * container is unavailable or the binding is not registered.
 *
 * Consumers that cannot take the class via constructor injection (notably
 * Eloquent model traits and static Blade-directive helpers) funnel through this
 * accessor instead of reaching for `app()` directly, keeping the
 * service-locator call in one auditable site.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait HasContainerInstance
{
    /**
     * Resolve the consuming class from the Laravel container, or return null
     * when the package is not booted / the binding is not registered.
     *
     * @return static|null
     */
    public static function instance(): ?static
    {
        if (!function_exists('app')) {
            return null; // @codeCoverageIgnore
        }

        $container = app();

        if (!$container->bound(static::class)) {
            return null;
        }

        /** @var static */
        return $container->make(static::class);
    }
}
