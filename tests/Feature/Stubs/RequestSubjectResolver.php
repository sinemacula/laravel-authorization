<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A subject resolver for one request: it returns the request's subject, and
 * translates a user into the subject the same request decides about, through
 * `Subject::withSubject()`, so the user keeps the request's tenant, application
 * and platform marker.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequestSubjectResolver implements SubjectResolver
{
    /**
     * Create a new resolver for the request's subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     */
    public function __construct(

        /** The request's subject. */
        private Subject $subject,
    ) {}

    /**
     * Return the request's subject.
     *
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function resolve(): Subject
    {
        return $this->subject;
    }

    /**
     * Return the request's subject deciding about the user.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        return $this->subject->withSubject($user);
    }
}
