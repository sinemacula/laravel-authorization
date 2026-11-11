<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use SineMacula\Laravel\Authorization\Support\CredentialScopes;

/**
 * Who a decision is about, and where it is made.
 *
 * The subject resolver returns one of these for the current request or job. The
 * subject is the model decisions are about: a principal, or in an application
 * without principals, the model checked (its user). The identity is the person
 * or machine behind a principal, or the subject itself when there are no
 * principals, and null when the resolver gives none. The tenant is the active
 * tenant, null for none, so only platform-wide rows count. The application and
 * the guard say where the request came in. The session is the current request's
 * session id when the subject is the request's authenticated user, which an
 * authentication requirement checker judges the proofs of (N34); it is null for
 * a subject the caller names and outside a session, and every authentication
 * requirement is then unmet.
 *
 * The scopes say what the credential the subject acts with carries, as the
 * subject resolver read it, for the session policy source to cap its checks
 * with (N121, N126): `CredentialScopes::uncapped()` when the credential carries
 * no cap, and `CredentialScopes::of()` with the scopes it carries, where an
 * empty list carries none granted and allows nothing. Null says nothing about
 * them, which is not the same as no cap: the source then establishes the scopes
 * of the credential the subject names, its session or its guard's caller, and
 * fails closed when it cannot (see `SessionPolicySource`).
 *
 * The platform marker says the subject acts on the platform, as a job or a
 * console command acting for no tenant does (N120): `for()` of it decides on
 * the platform, with no tenant, on its application, or on none, whatever tenant
 * the request is in, and the request's scope is restored afterwards. A subject
 * on the platform names no tenant. A subject without the marker is decided in
 * its own tenant or application when `for()` names it with either, and in the
 * request's scope otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Subject
{
    /**
     * Create a new subject, refusing one on the platform that names a tenant.
     *
     * @param  object  $subject
     * @param  object|null  $identity
     * @param  object|null  $tenant
     * @param  string|null  $application
     * @param  string|null  $guard
     * @param  string|null  $session
     * @param  \SineMacula\Laravel\Authorization\Support\CredentialScopes|null  $scopes
     * @param  bool  $platform
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The model decisions are about. */
        public object $subject,

        /** The identity behind the subject (or itself), or null for none. */
        public ?object $identity = null,

        /** The active tenant, or null when no tenant is active. */
        public ?object $tenant = null,

        /** The application the request came in on, or null for none. */
        public ?string $application = null,

        /** The authentication guard the subject was resolved from. */
        public ?string $guard = null,

        /** The id of the session the subject signed in with, or null for none. */
        public ?string $session = null,

        /** What the subject's credential carries, uncapped or the scopes given, or null when the subject says nothing about it. */
        public ?CredentialScopes $scopes = null,

        /** Whether the subject acts on the platform, so `for()` of it decides there, whatever tenant the request is in. */
        public bool $platform = false,
    ) {
        if ($platform && $tenant !== null) {
            throw new \InvalidArgumentException('A subject on the platform names no tenant.');
        }
    }

    /**
     * Return this subject's request (its tenant, application, guard and
     * platform marker) deciding about another model.
     *
     * The model named is its own identity, as in an application without
     * principals. Naming the model this subject is about keeps its identity. A
     * subject the caller names has no session, whichever model it is, so no
     * authentication requirement is met for it, and is no request's credential,
     * so it says nothing of a credential's scopes either: they go whenever the
     * session goes, and stay only when this subject is returned as it is, and
     * the session policy source answers for the subject from its guard (see
     * `SessionPolicySource`). The platform marker stays, so the same request
     * deciding about another model stays on the platform.
     *
     * @param  object  $subject
     * @return self
     */
    public function withSubject(object $subject): self
    {
        if ($subject === $this->subject && $this->session === null) {
            return $this;
        }

        $identity = $subject === $this->subject ? $this->identity : $subject;

        return new self($subject, $identity, $this->tenant, $this->application, $this->guard, platform: $this->platform);
    }
}
