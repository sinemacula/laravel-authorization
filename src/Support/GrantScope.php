<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * Where a grant holds: in one tenant, or platform-wide when the tenant is null,
 * and in one application, or every application when the application is null.
 *
 * The grant service writes platform-wide grants for every application today, so
 * every grant event reports `GrantScope::platform()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GrantScope
{
    /**
     * Create a new grant scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     */
    public function __construct(

        /** The tenant the grant holds in; null for platform-wide. */
        public ?Reference $tenant = null,

        /** The application the grant holds in; null for every application. */
        public ?string $application = null,
    ) {}

    /**
     * Return the platform-wide scope, for every application.
     *
     * @return self
     */
    public static function platform(): self
    {
        return new self;
    }
}
