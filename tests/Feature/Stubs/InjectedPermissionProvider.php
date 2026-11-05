<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

/**
 * Stub provider with a constructor dependency, so it can only be built through
 * the container: it returns the definition the container injects.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InjectedPermissionProvider implements PermissionProvider
{
    /**
     * Create a new provider.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\PermissionDefinition  $definition
     */
    public function __construct(

        /** The definition the container injects. */
        private PermissionDefinition $definition,
    ) {}

    /**
     * Return the injected definition.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     */
    #[\Override]
    public function permissions(): array
    {
        return [$this->definition];
    }
}
