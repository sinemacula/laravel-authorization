<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authorization\Diagnostics\ContainerState;

/**
 * Forget the package's per-request state, and nothing else.
 *
 * Everything the package keeps for one request or job (the manager, the
 * resolved tenant, the resolution memo, the last decision, the remembered
 * decisions and the defaults behind its replaceable seams) is bound with
 * `scoped()`, so Laravel's queue worker and Octane forget it between units of
 * work with the rest of the scoped state. A long-running command that does
 * several units of work in one process, and must not forget what Laravel or
 * another package keeps scoped (the command's context, callbacks deferred with
 * `defer()`), calls `forget()` between them instead: it forgets exactly the
 * scoped instances held under the package's own names, its class names,
 * `authorization` and the `authorization.` keys, whatever the package binds now
 * or later, so a caller keeps no list of its own. What the package holds for
 * the application's lifetime (its state after boot, the declarations and the
 * binding registry) is not scoped, and is kept.
 *
 * Part of the stable API suite packages may use; breaking changes require a
 * major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RequestState
{
    /** @var string The namespace every class the package binds lives under. */
    private const string NAMESPACE = 'SineMacula\Laravel\Authorization\\';

    /** @var string The key the manager is bound under, and the prefix of the package's other keys. */
    private const string KEY = 'authorization';

    /**
     * Forget the scoped instances the container holds under the package's
     * names, so the next unit of work builds them afresh.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return void
     */
    public static function forget(Container $container): void
    {
        foreach (self::abstracts($container) as $abstract) {
            $container->forgetInstance($abstract);
        }
    }

    /**
     * Return the abstracts the container scopes under the package's names.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return list<string>
     */
    public static function abstracts(Container $container): array
    {
        return \array_values(\array_filter(ContainerState::scopedAbstracts($container), self::isPackages(...)));
    }

    /**
     * Determine whether the abstract is one of the package's names.
     *
     * @param  string  $abstract
     * @return bool
     */
    private static function isPackages(string $abstract): bool
    {
        return $abstract === self::KEY || \str_starts_with($abstract, self::KEY . '.') || \str_starts_with($abstract, self::NAMESPACE);
    }
}
