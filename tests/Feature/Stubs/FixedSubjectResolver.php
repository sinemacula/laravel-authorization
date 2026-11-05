<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A subject resolver that returns one subject, with its identity, as given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedSubjectResolver implements SubjectResolver
{
    /**
     * Create a new resolver instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     */
    public function __construct(

        /** The subject every request is about, or null for none. */
        private ?Subject $subject,
    ) {}

    /**
     * Return the fixed subject.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    #[\Override]
    public function resolve(): ?Subject
    {
        return $this->subject;
    }

    /**
     * Return a subject about the user, as its own identity.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        return new Subject($user, $user);
    }
}
