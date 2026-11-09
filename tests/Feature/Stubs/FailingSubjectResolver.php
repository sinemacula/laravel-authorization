<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A subject resolver that fails: it throws the failure it is given for the
 * request's subject and for every user it is handed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FailingSubjectResolver implements SubjectResolver
{
    /**
     * Create a new resolver instance.
     *
     * @param  \Throwable  $failure
     */
    public function __construct(

        /** The failure it throws. */
        private \Throwable $failure,
    ) {}

    /**
     * Throw the failure.
     *
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \Throwable
     */
    #[\Override]
    public function resolve(): Subject
    {
        throw $this->failure;
    }

    /**
     * Throw the failure, whichever user is given.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \Throwable
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        throw $this->failure;
    }
}
