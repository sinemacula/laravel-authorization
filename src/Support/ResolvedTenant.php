<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;

/**
 * The tenant of the subject the bound `SubjectResolver` returned for the
 * current request or job, together with the resolver it came from.
 *
 * The service provider binds this holder with `scoped()`, so it is built once
 * per request or job from the resolver and discarded at its end: Laravel's
 * queue worker forgets scoped instances before each job, and Octane runs each
 * request on a fresh sandbox. `TenantScope` reads the tenant from here instead
 * of keeping its own memo, so no tenant outlives the request or job that
 * resolved it. When the resolver bound now is not the one the holder came from,
 * the scope builds a new holder, so the next query sees a rebound resolver.
 *
 * The tenant is null when there is no subject or the subject has no tenant, and
 * only platform-wide rows are visible then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResolvedTenant
{
    /**
     * Create a new resolved-tenant holder.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $resolver
     * @param  object|null  $tenant
     */
    public function __construct(

        /** The resolver the tenant was read from. */
        public SubjectResolver $resolver,

        /** The resolved tenant, or null when no tenant is active. */
        public ?object $tenant,
    ) {}

    /**
     * Resolve the subject's tenant through the given resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $resolver
     * @return self
     */
    public static function from(SubjectResolver $resolver): self
    {
        return new self($resolver, $resolver->resolve()?->tenant);
    }

    /**
     * Determine whether the tenant was read from the given resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $resolver
     * @return bool
     */
    public function isFrom(SubjectResolver $resolver): bool
    {
        return $this->resolver === $resolver;
    }
}
