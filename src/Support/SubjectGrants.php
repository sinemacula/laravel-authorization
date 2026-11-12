<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Resolvers\BoundaryResolver;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Usage\WeighedGrants;

/**
 * The grants a decision about a subject considers: the subject's own, and its
 * identity's when the identity is another model of the same kind.
 *
 * An identity's grants hold in every principal of that identity, a principal's
 * only in that principal, and nothing reaches a principal through another
 * principal of the same identity. A machine is never treated as a person
 * (AUTHZ-2.4): the identity's roles, permissions and the allow statements of
 * its policies reach the subject only when both are machines (see
 * `AuthorizableMachine`) or neither is, so a person's grants never reach a
 * machine principal and a machine's never reach a person. What only narrows a
 * check still holds across the two: the deny statements of the identity's
 * policies, its own and those its roles attach, deny the subject, the
 * permission boundaries of both cap every check about the subject, and a
 * subject or identity that reports itself inactive is denied everything,
 * whatever either holds. An identity policy that cannot be read therefore
 * denies the check whatever the identity's kind.
 *
 * A break-glass activation reaches only the principal it names: an identity
 * read here is marked as one (see `BreakGlassActivations::markIdentity()`), so
 * none of its activations reaches the subject.
 *
 * The manager, the Blade role helpers and the `role:` middleware all ask here,
 * so they read the same grants. The decision asks for the permission that
 * allows a check at its allow stage alone, after every deny and cap, and the
 * tenant stage asks only whether a platform-wide grant admits a resource from
 * outside the scope, which admits it but never allows it.
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
     * Determine whether the subject or its identity, when it grants to the
     * subject, holds the role, under the guard when one is given; never while
     * either is inactive.
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

        foreach ([$subject->subject, self::grantingIdentity($subject)] as $grantee) {
            if ($grantee instanceof SupportsRoles && $grantee->hasRole($role, $guard)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the subject or its identity, when it grants to the
     * subject, holds a permission that matches the action, directly or through
     * a role, in the current scope; never while either is inactive (see
     * `permissionFor()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @return bool
     */
    public static function holdsPermission(Subject $subject, string $action): bool
    {
        return self::permissionFor($subject, $action) !== null;
    }

    /**
     * Return the permission the subject, or its identity when it grants to the
     * subject, holds that matches the action, directly or through a role, as it
     * was granted (a pattern such as `posts:*` included); null when neither
     * holds one, or while either is inactive.
     *
     * The permissions are those the grantee resolves in the current scope (its
     * tenant chain and application, see `TenantChain::grants()`), so only a
     * grant that reaches the scope counts, and one that has expired never does.
     * The names are matched by the wildcard rules (see `HeldPermissions`), the
     * subject's first, so the identity's are read only when the subject's own
     * do not match. Given what a tracked check weighed, the grantee whose
     * permission matched is noted on it (see `Usage\WeighedGrants`).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Usage\WeighedGrants|null  $weighed
     * @return string|null
     */
    public static function permissionFor(Subject $subject, string $action, ?WeighedGrants $weighed = null): ?string
    {
        if (self::isInactive($subject)) {
            return null;
        }

        foreach ([$subject->subject, self::grantingIdentity($subject)] as $grantee) {
            $held = $grantee instanceof SupportsPermissions ? HeldPermissions::match($grantee->getPermissions(), $action) : null;

            if ($held !== null) {
                $weighed?->notePermission($held, $grantee);

                return $held;
            }
        }

        return null;
    }

    /**
     * Return the policies attached to the subject's identity when that is
     * another model; the subject's own come through the policy resolver. An
     * identity that grants to the subject gives its policies whole; one of the
     * other kind gives only those with a deny statement, each with its deny
     * statements alone, at their positions, since a deny only narrows a check.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public static function identityPolicies(Subject $subject): array
    {
        $identity = self::separateIdentity($subject);

        if (!$identity instanceof SupportsPolicies) {
            return [];
        }

        return self::grantingIdentity($subject) === null ? self::denialsOf($identity->getPolicies()) : $identity->getPolicies();
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
     * Return the subject's identity when it is another model than the subject
     * and of the same kind, both machines or neither, so its grants reach the
     * subject; null otherwise, which holds nothing.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return object|null
     */
    public static function grantingIdentity(Subject $subject): ?object
    {
        $identity = self::separateIdentity($subject);

        return $identity instanceof AuthorizableMachine === $subject->subject instanceof AuthorizableMachine ? $identity : null;
    }

    /**
     * Return each policy that has a deny statement with its deny statements
     * alone, each keeping its position, so the trace names it as the policy
     * does; a policy with none is left out. `whereAuthorized()` reads a
     * record's own tenant's attached denies through it too.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @internal
     */
    public static function denialsOf(array $policies): array
    {
        $denials = [];

        foreach ($policies as $policy) {
            $denies = \array_filter($policy->statements, static fn (Statement $statement): bool => $statement->effect === PolicyEffect::DENY);

            if ($denies === []) {
                continue;
            }

            $denials[] = new Policy($policy->name, $denies, $policy->version, $policy->id, $policy->resource);
        }

        return $denials;
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
     * marked as an identity, whose break-glass activations count for nothing,
     * or null.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return object|null
     */
    private static function separateIdentity(Subject $subject): ?object
    {
        $identity = $subject->identity === $subject->subject ? null : $subject->identity;

        if ($identity !== null) {
            BreakGlassActivations::markIdentity($identity);
        }

        return $identity;
    }
}
