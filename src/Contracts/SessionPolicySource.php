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
 * which allows nothing. A machine principal (see `AuthorizableMachine`) is
 * allowed nothing without scopes: null for one fails closed. A subject the
 * caller names (`Authorization::for()`) is no request's credential, so a source
 * answers null for it unless it knows the credential that subject acts with.
 *
 * The shipped default (`NoSessionPolicy`) answers null for every subject. Under
 * the suite, `sinemacula/laravel-iam` binds one reading the scopes of the
 * caller's credential from `laravel-authentication` (AUTH-4.5).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SessionPolicySource
{
    /**
     * Return the scopes the subject's credential carries, or null when it
     * carries no cap.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     */
    public function scopesFor(Subject $subject): ?array;
}
