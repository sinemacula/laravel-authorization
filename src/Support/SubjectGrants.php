<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Resolvers\BoundaryResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * The grants a decision about a subject considers: the subject's own, and its
 * identity's when the identity is another model.
 *
 * An identity's grants hold in every principal of that identity, a principal's
 * only in that principal, and nothing reaches a principal through another
 * principal of the same identity. The permission boundaries of both cap every
 * check about the subject. A subject or identity that reports itself inactive
 * is denied everything, whatever either holds.
 *
 * The manager, the Blade role helpers and the `role:` middleware all ask here,
 * so they read the same grants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SubjectGrants
{
    /**
     * Determine whether the subject, or its identity, is inactive.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return bool
     */
    public static function isInactive(Subject $subject): bool
    {
        foreach (self::grantees($subject) as $grantee) {
            if ($grantee instanceof AuthorizableIdentity && !$grantee->isAuthorizationActive()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the subject or its identity holds the role, under the
     * guard when one is given; never while either is inactive.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $role
     * @param  string|null  $guard
     * @return bool
     */
    public static function holdsRole(Subject $subject, string $role, ?string $guard = null): bool
    {
        if (self::isInactive($subject)) {
            return false;
        }

        foreach (self::grantees($subject) as $grantee) {
            if ($grantee instanceof SupportsRoles && $grantee->hasRole($role, $guard)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the subject or its identity holds a permission that
     * matches the action, directly or through a role; never while either is
     * inactive.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @return bool
     */
    public static function holdsPermission(Subject $subject, string $action): bool
    {
        if (self::isInactive($subject)) {
            return false;
        }

        foreach (self::grantees($subject) as $grantee) {
            if ($grantee instanceof SupportsPermissions && $grantee->hasPermission($action)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the policies attached to the subject's identity when it is another
     * model; the subject's own come through the policy resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public static function identityPolicies(Subject $subject): array
    {
        $identity = self::separateIdentity($subject);

        return $identity instanceof SupportsPolicies ? $identity->getPolicies() : [];
    }

    /**
     * Return the permission boundaries that apply to a check about the subject
     * in the current tenant: its own, and its identity's when that is another
     * model, all of which cap the check together (see `BoundaryResolver`).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public static function boundaries(Subject $subject): array
    {
        return [...BoundaryResolver::boundariesFor($subject->subject), ...BoundaryResolver::boundariesFor(self::separateIdentity($subject))];
    }

    /**
     * Return the subject, and its identity when that is another model (null
     * otherwise, which holds nothing).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<object|null>
     */
    private static function grantees(Subject $subject): array
    {
        return [$subject->subject, self::separateIdentity($subject)];
    }

    /**
     * Return the subject's identity when it is another model than the subject,
     * or null.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return object|null
     */
    private static function separateIdentity(Subject $subject): ?object
    {
        return $subject->identity === $subject->subject ? null : $subject->identity;
    }
}
