<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

/**
 * Who a decision is about, and where it is made.
 *
 * The subject resolver returns one of these for the current request or job. The
 * subject is the model decisions are about: a principal, or in an application
 * without principals, the model checked (its user). The identity is the person
 * or machine behind a principal, or the subject itself when there are no
 * principals. The tenant is the active tenant, null for none, so only
 * platform-wide rows count. The application and the guard say where the request
 * came in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Subject
{
    /**
     * Create a new subject.
     *
     * @param  object  $subject
     * @param  object|null  $identity
     * @param  object|null  $tenant
     * @param  string|null  $application
     * @param  string|null  $guard
     */
    public function __construct(

        /** The model decisions are about. */
        public object $subject,

        /** The identity behind the subject, or the subject itself. */
        public ?object $identity = null,

        /** The active tenant, or null when no tenant is active. */
        public ?object $tenant = null,

        /** The application the request came in on, or null for none. */
        public ?string $application = null,

        /** The authentication guard the subject was resolved from. */
        public ?string $guard = null,
    ) {}

    /**
     * Return this subject's request (its tenant, application and guard)
     * deciding about another model.
     *
     * The model named is its own identity, as in an application without
     * principals. Naming the model this subject is about keeps it unchanged,
     * identity included.
     *
     * @param  object  $subject
     * @return self
     */
    public function withSubject(object $subject): self
    {
        if ($subject === $this->subject) {
            return $this;
        }

        return new self($subject, $subject, $this->tenant, $this->application, $this->guard);
    }
}
