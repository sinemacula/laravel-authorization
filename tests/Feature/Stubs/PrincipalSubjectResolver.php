<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A subject resolver for an application with principals: every user it is
 * handed acts as one principal, with one identity behind it, in a tenant and
 * application of the request's, with a session, all of which a console subject
 * must lose but the principal and identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PrincipalSubjectResolver implements SubjectResolver
{
    /** @var string The session every subject it resolves signed in with. */
    public const string SESSION = 'session-sentinel-5d1c';

    /**
     * Create a new resolver instance.
     *
     * @param  object  $principal
     * @param  object|null  $identity
     * @param  object|null  $tenant
     */
    public function __construct(

        /** The principal every user acts as. */
        private object $principal,

        /** The identity behind the principal. */
        private ?object $identity,

        /** The tenant of the request, or null for none. */
        private ?object $tenant = null,
    ) {}

    /**
     * Return the subject about the identity.
     *
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function resolve(): Subject
    {
        return $this->forUser($this->identity ?? $this->principal);
    }

    /**
     * Return the principal, with its identity, in the request's tenant, on the
     * `web` application and guard, with a session, whichever user is given.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        return new Subject($this->principal, $this->identity, $this->tenant, 'web', 'web', self::SESSION);
    }
}
