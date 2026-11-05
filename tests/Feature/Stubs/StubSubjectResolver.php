<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Subject resolver returning a fixed subject, or none, in a fixed tenant and
 * application, the way an application's own resolver reports its request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StubSubjectResolver implements SubjectResolver
{
    /**
     * Create a new resolver for a fixed request.
     *
     * @param  object|null  $subject
     * @param  object|null  $tenant
     * @param  string|null  $application
     * @param  string|null  $guard
     */
    public function __construct(

        /** The model the request is about, or null for none. */
        private ?object $subject = null,

        /** The request's tenant, or null for none. */
        private ?object $tenant = null,

        /** The request's application, or null for none. */
        private ?string $application = null,

        /** The request's guard, or null for none. */
        private ?string $guard = null,
    ) {}

    /**
     * Resolve the fixed subject, or null when there is none.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    #[\Override]
    public function resolve(): ?Subject
    {
        return $this->subject === null ? null : $this->forUser($this->subject);
    }

    /**
     * Make the given user the subject and its identity, in the fixed tenant,
     * application and guard.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        return new Subject($user, $user, $this->tenant, $this->application, $this->guard);
    }
}
