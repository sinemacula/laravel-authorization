<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Subject;

/**
 * Session policy source contract (AUTHZ-13.3).
 *
 * Answers the scopes the credential of a check's subject carries, which cap
 * every check about it (AUTHZ-7.5): an action passes the session stage only
 * when a pattern the scopes map to covers it, through
 * `authorization.session.scopes`, where a scope not mapped names an action or
 * an action pattern itself. A cap grants nothing.
 *
 * Null means the credential carries no cap, and differs from an empty list,
 * which allows nothing. A source answers in this order (N126):
 *
 * - The subject says what its credential carries, in its own `scopes`, which a
 *   subject resolver fills from the credential it read: the source answers from
 *   it, null for `CredentialScopes::uncapped()` and the list for
 *   `CredentialScopes::of()`.
 * - The subject says nothing (`scopes` is null) but names a credential: it
 *   names a session, or it names a guard whose caller is now the subject's own
 *   model, the same instance or one with the same key. The source establishes
 *   that credential's scopes itself, from what the subject names and never from
 *   the request around it, and answers an empty list, which allows nothing,
 *   when it cannot, such as for a session it cannot resolve. A guard whose
 *   caller is another model names no credential of the subject's.
 * - The subject names no credential: no session, and no guard whose caller is
 *   its model, as a job's or a console command's subject, or a model named
 *   through `Authorization::for()`. The source answers null, no cap, unless it
 *   knows the credential that subject acts with. A machine principal (see
 *   `AuthorizableMachine`) is still allowed nothing without scopes: null for
 *   one fails closed.
 *
 * A source never throws because it could not establish a credential's scopes:
 * it answers an empty list instead. A subject `withSubject()` makes for another
 * model says nothing of its scopes and names no session, as it is no request's
 * credential.
 *
 * The shipped default (`NoSessionPolicy`) knows no credential: it answers from
 * the subject's own `scopes`, and null when the subject says nothing. Under the
 * suite, `sinemacula/laravel-iam` binds one reading the scopes of the caller's
 * credential from `laravel-authentication` (AUTH-4.5).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SessionPolicySource
{
    /**
     * Return the scopes the subject's credential carries, or null when it
     * carries no cap, and an empty list when the credential the subject names
     * cannot be established.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     */
    public function scopesFor(Subject $subject): ?array;
}
