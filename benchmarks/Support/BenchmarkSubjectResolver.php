<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Fixed subject resolver for benches.
 *
 * Returns the same subject, in the same tenant, on every call, so the benches
 * measure the middleware, Blade and tenant-scope paths rather than the
 * resolution itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final readonly class BenchmarkSubjectResolver implements SubjectResolver
{
    /**
     * Create a new resolver instance.
     *
     * @param  object|null  $subject
     * @param  object|null  $tenant
     */
    public function __construct(

        /** The subject returned by `resolve()`, or null for none. */
        private ?object $subject = null,

        /** The tenant of every subject returned, or null for none. */
        private ?object $tenant = null,
    ) {}

    /**
     * Return the fixed subject, or null when there is none.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    #[\Override]
    public function resolve(): ?Subject
    {
        return $this->subject === null ? null : $this->forUser($this->subject);
    }

    /**
     * Make the given user the subject, in the fixed tenant.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        return new Subject($user, $user, $this->tenant);
    }
}
