<?php

declare(strict_types = 1);

namespace Tests\Performance\Support;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Counting subject resolver used by the memo-contract assertions - exposes
 * `$calls` so the test can prove the subject's tenant is resolved once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingSubjectResolver implements SubjectResolver
{
    /** @var int Number of times `resolve` was invoked. */
    public int $calls = 0;

    /**
     * Create a new counting resolver wrapping a fixed tenant.
     *
     * @param  object|null  $tenant
     * @return void
     */
    public function __construct(

        /** The tenant of the subject returned by every resolution call. */
        private readonly ?object $tenant,
    ) {}

    /**
     * Resolve a placeholder subject in the tenant and increment the call
     * counter.
     *
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function resolve(): Subject
    {
        $this->calls++;

        return $this->forUser(new \stdClass);
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
