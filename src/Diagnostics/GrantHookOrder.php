<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingCatalogue;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\ValueRenderer;

/**
 * The order the grant hooks run in, without building any (N108): the hooks the
 * configuration lists in `authorization.grant_hooks` first, in the order
 * listed, then the hook bound to the contract. The chain stops at the first
 * hook that refuses.
 *
 * Each hook listed is shown by its class name, or by its type alone when the
 * entry is not one. The bound hook is shown as its seam is (see
 * `SeamClassifier`); the package's default holds no hook and runs none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GrantHookOrder
{
    /**
     * Return the hooks in the order they run.
     *
     * @param  mixed  $listed
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRow  $bound
     * @return list<array{position: int, source: string, class: string|null, type: string|null, origin: string|null, factory: string|null, runs: bool}>
     */
    public static function of(mixed $listed, SeamRow $bound): array
    {
        $hooks = [];

        foreach (\is_array($listed) ? \array_values($listed) : [] as $hook) {
            $shown = ValueRenderer::render(SettingCatalogue::CLASS_NAME, $hook);

            $hooks[] = [
                'position' => \count($hooks) + 1,
                'source'   => 'configured',
                'class'    => \is_string($shown[0] ?? null) ? $shown[0] : null,
                'type'     => ValueRenderer::typeOf($hook),
                'origin'   => null,
                'factory'  => null,
                'runs'     => true,
            ];
        }

        $hooks[] = [
            'position' => \count($hooks) + 1,
            'source'   => 'bound',
            'class'    => $bound->class(),
            'type'     => null,
            'origin'   => $bound->origin->value,
            'factory'  => $bound->factory,
            'runs'     => $bound->origin !== Origin::PACKAGE_DEFAULT && $bound->origin !== Origin::UNBOUND,
        ];

        return $hooks;
    }
}
