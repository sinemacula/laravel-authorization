<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\SessionScopes;

/**
 * Makes the session caps of a check (AUTHZ-7.5): the scopes the session policy
 * source reports for the subject's credential, mapped to action patterns
 * through the scope map, and the explicit caps the caller passed to
 * `Authorization::capped()`.
 *
 * A subject that is a machine (see `AuthorizableMachine`) must have its
 * credential's scopes: when the source reports none, the check is capped by an
 * empty cap, which allows nothing, whatever explicit caps are passed. The
 * source is asked once per check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionCapResolver
{
    /**
     * Create a new session cap resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SessionPolicySource  $source
     * @param  \SineMacula\Laravel\Authorization\Support\SessionScopes  $scopes
     */
    public function __construct(

        /** Reports the scopes of the subject's credential, or null for no cap. */
        private SessionPolicySource $source = new NoSessionPolicy,

        /** Maps each scope to the action patterns it names. */
        private SessionScopes $scopes = new SessionScopes,
    ) {}

    /**
     * Return the session caps of a check about the subject, with the explicit
     * caps given, outermost first.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  list<list<string>>  $explicit
     * @return \SineMacula\Laravel\Authorization\Evaluation\SessionCaps
     */
    public function capsFor(Subject $subject, array $explicit = []): SessionCaps
    {
        $scopes = $this->source->scopesFor($subject);

        return SessionCaps::of($scopes === null ? null : $this->scopes->patternsFor($scopes), $explicit, $subject->subject instanceof AuthorizableMachine);
    }
}
