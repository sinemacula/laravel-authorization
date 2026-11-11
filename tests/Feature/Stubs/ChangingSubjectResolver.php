<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A subject resolver whose answer the test changes while it stays the resolver
 * bound, as a guard's does when a session signs in or out or the request's
 * tenant is switched, so only what the package holds for the request decides
 * whether the change is seen.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ChangingSubjectResolver implements SubjectResolver
{
    /**
     * Create a new changing subject resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     */
    public function __construct(

        /** The subject the request is about until the test changes it, or null for none. */
        public ?Subject $subject,
    ) {}

    /**
     * Return the current subject.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    #[\Override]
    public function resolve(): ?Subject
    {
        return $this->subject;
    }

    /**
     * Return a subject about the user, in the current subject's scope.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        return $this->subject?->withSubject($user) ?? new Subject($user, $user);
    }
}
