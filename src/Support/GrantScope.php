<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * Where a grant holds: in one tenant, or platform-wide when the tenant is null,
 * and in one application, or every application when the application is null.
 *
 * Every grant event reports the scope of its grant: the tenant its target's
 * owner fixes or the call names, else platform-wide, and whether a grant in a
 * tenant also reaches the tenants below it in the tenant tree (AUTHZ-5.3). A
 * platform-wide grant counts everywhere, so it always reaches below. Grants are
 * written for every application until applications are read.
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
     * @param  bool  $includeSubtree
     */
    public function __construct(

        /** The tenant the grant holds in; null for platform-wide. */
        public ?Reference $tenant = null,

        /** The application the grant holds in; null for every application. */
        public ?string $application = null,

        /** Whether the grant also holds in the tenants below its tenant. */
        public bool $includeSubtree = true,
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
