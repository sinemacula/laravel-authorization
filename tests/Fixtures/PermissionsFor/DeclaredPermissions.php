<?php

declare(strict_types = 1);

namespace Tests\Fixtures\PermissionsFor;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;

/**
 * A permission provider declaring the definitions a test gives it, or failing
 * with the exception it is given, bound in the container as an instance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeclaredPermissions implements PermissionProvider
{
    /**
     * Create a new provider.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>  $definitions
     * @param  \Throwable|null  $failure
     */
    public function __construct(

        /** The definitions `permissions()` returns. */
        private array $definitions = [],

        /** What `permissions()` throws, or null for nothing. */
        private ?\Throwable $failure = null,
    ) {}

    /**
     * Return the definitions given, or throw the failure given.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     *
     * @throws \Throwable
     */
    #[\Override]
    public function permissions(): array
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->definitions;
    }
}
