<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\RoleGraph;

/**
 * Tells whether removing a grant, or shortening one, can only narrow authority,
 * so delegated administration need not prove it holds what it hands out (see
 * `OperationConstraints`).
 *
 * Removing something narrows only when it took nothing away: revoking a
 * permission always does; revoking a role does when no policy attached to the
 * role or, with the hierarchy enabled, to any of its ancestors denies anything,
 * since removing a deny can widen what the grantee may do; detaching a policy,
 * from a grantee or from a resource, does when the policy, as stored, has no
 * deny statement. Removing a permission boundary always widens. Everything is
 * read as stored, outside every tenant scope and on the write connection, so
 * the judgement is the same whatever tenant the check is decided in, and a
 * screen judges what the service judges. A document that cannot be read, and a
 * chain of roles that cannot be read whole, is taken to deny, so its removal is
 * never judged narrowing.
 *
 * Setting a permission boundary narrows when the grantee has no boundary in the
 * same scope, since it only adds a cap, or when it replaces one there with a
 * boundary that reaches no fewer tenants and caps no less: the same policy, or
 * one whose document can only narrow the old one's (see `DocumentComparison`).
 * Anything else, a wider document, a narrower reach or a document that cannot
 * be read, may widen.
 *
 * A grant to an identity or a principal of what it holds live in the same scope
 * (tenant and application) only shortens or narrows that grant when it lasts no
 * longer and reaches no further: it takes part of the grant away, so it narrows
 * exactly when revoking the whole grant would. Granting the same grant again,
 * with the same expiry and reach, changes nothing and narrows too. An
 * extension, a wider reach, a grant that has expired and is re-armed, and a
 * grant of anything not held live in the scope may widen.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Narrowing
{
    /**
     * Determine whether removing the target under the action can only narrow
     * what anyone may do.
     *
     * @param  string  $action
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @return bool
     */
    public static function isNarrowing(string $action, Model $target): bool
    {
        return match ($action) {
            PackagePermissions::PERMISSION_REVOKE                                         => true,
            PackagePermissions::ROLE_REVOKE                                               => $target instanceof Role   && !self::doesRoleDeny($target),
            PackagePermissions::POLICY_DETACH, PackagePermissions::RESOURCE_POLICY_DETACH => $target instanceof Policy && self::isAllowOnly($target),
            default                                                                       => false,
        };
    }

    /**
     * Determine whether the grant the change proposes can only shorten or
     * narrow a role, permission or policy the grantee, an identity or a
     * principal, holds live in the change's scope: it lasts no longer and
     * reaches no further than the grant held, and revoking that grant would
     * only narrow; or, for a boundary, whether it only adds or tightens the
     * grantee's cap in the scope. What is held is read on the write connection.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @return bool
     */
    public static function isShortening(string $action, OperationChange $change): bool
    {
        if ($action === PackagePermissions::BOUNDARY_SET) {
            return $change->target instanceof Policy && self::isTightening($change, $change->target);
        }

        $kind = self::kindGranting($action);

        if ($kind === null || $change->target === null || OperationGrantee::isRole($change->grantee)) {
            return false;
        }

        $held = GrantChanges::table($kind, $change->grantee, null, $change->scope)->liveRow(GrantChanges::key($change->target));

        return $held !== null && self::isWithin($change, ...$held) && self::isNarrowing($kind->revokeAction(), $change->target);
    }

    /**
     * Determine whether the policy, as stored, has no deny statement. A policy
     * that is gone, or whose document cannot be read, is taken to deny.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return bool
     */
    public static function isAllowOnly(Policy $policy): bool
    {
        return self::hasNoDeny(InlinePolicies::stored($policy->getKey()));
    }

    /**
     * Determine whether setting the policy as the grantee's boundary in the
     * change's scope only adds or tightens its cap there: it has none there, or
     * the one it has reaches no further below, and is the same policy or one
     * the new policy's document can only narrow.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return bool
     */
    private static function isTightening(OperationChange $change, Policy $policy): bool
    {
        $held = self::boundaryOf($change);

        if ($held === null) {
            return true;
        }

        [$key, $reachesBelow] = $held;

        $reaches = $change->scope->includeSubtree || !$reachesBelow;

        return $reaches && ($key === GrantChanges::key($policy) || self::isNarrowerDocument($key, $policy));
    }

    /**
     * Return the key of the policy the grantee's boundary in the change's scope
     * is and whether it reaches the tenants below, read on the write
     * connection, or null when it has none there.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @return array{string, bool}|null
     */
    private static function boundaryOf(OperationChange $change): ?array
    {
        /** @var string $table */
        $table  = config('authorization.tables.authorizable_boundaries', 'authorizable_boundaries');
        $tenant = $change->scope->tenant;
        $query  = AuthorizationConnection::connection()->table($table)->useWritePdo()
            ->where('authorizable_type', $change->grantee->type)
            ->where('authorizable_id', $change->grantee->id);

        $tenant === null ? $query->whereNull('tenant_type')->whereNull('tenant_id') : $query->where('tenant_type', $tenant->type)->where('tenant_id', $tenant->id);

        $row = $query->first(['policy_id', 'include_subtree']);

        /** @var array{policy_id: string, include_subtree: bool|int|string}|null $columns */
        $columns = $row === null ? null : (array) $row;

        return $columns === null ? null : [$columns['policy_id'], (bool) $columns['include_subtree']];
    }

    /**
     * Determine whether the policy's document can only narrow the document of
     * the stored policy with the key.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return bool
     */
    private static function isNarrowerDocument(string $key, Policy $policy): bool
    {
        return DocumentComparison::isNarrower(DocumentComparison::read(InlinePolicies::stored($key)?->document), DocumentComparison::read($policy->document));
    }

    /**
     * Return the kind of grant the action grants, or null for an action that
     * grants none of the grant service's kinds.
     *
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Enums\GrantTarget|null
     */
    private static function kindGranting(string $action): ?GrantTarget
    {
        foreach (GrantTarget::cases() as $kind) {
            if ($kind->grantAction() === $action) {
                return $kind;
            }
        }

        return null;
    }

    /**
     * Determine whether the change lasts no longer and reaches no further than
     * the grant held: a held grant that never expires outlasts any, and one
     * that reaches the tenants below covers one that does not.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @param  bool  $reachesBelow
     * @return bool
     */
    private static function isWithin(OperationChange $change, ?Carbon $expiresAt, bool $reachesBelow): bool
    {
        $lastsNoLonger = $expiresAt === null || ($change->expiresAt !== null && $change->expiresAt->lessThanOrEqualTo($expiresAt));

        return $lastsNoLonger && ($reachesBelow || !$change->scope->includeSubtree);
    }

    /**
     * Determine whether the stored policy has no deny statement: false for no
     * policy, or one whose document cannot be read.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy|null  $stored
     * @return bool
     */
    private static function hasNoDeny(?Policy $stored): bool
    {
        try {
            $statements = $stored === null ? null : PolicyDocument::hydrate($stored)->statements;
        } catch (InvalidPolicyDocumentException) {
            $statements = null;
        }

        return $statements !== null && \array_filter($statements, static fn (Statement $statement): bool => $statement->effect === PolicyEffect::DENY) === [];
    }

    /**
     * Determine whether a policy attached to the role, or to one of its
     * ancestors, in any scope, has a deny statement. The chain and the
     * attachments are read outside every tenant scope, on the write connection,
     * so an ancestor of any tenant counts, whichever tenant the check is
     * decided in, and a screen reads what the service reads. A chain that
     * cannot be read whole, a role or a parent missing from it, or one that
     * returns to a role it has passed, is taken to deny.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return bool
     */
    private static function doesRoleDeny(Role $role): bool
    {
        $chain = RoleAuthority::chainOf($role->id, RoleGraph::reach([$role->id]));

        if ($chain === null) {
            return true;
        }

        /** @var string $table */
        $table = config('authorization.tables.authorizable_policies', 'authorizable_policies');

        $keys = AuthorizationConnection::connection()->table($table)
            ->useWritePdo()
            ->where('authorizable_type', $role->getMorphClass())
            ->whereIn('authorizable_id', $chain)
            ->distinct()
            ->pluck('policy_id')
            ->all();

        foreach ($keys as $key) {
            if (!self::hasNoDeny(InlinePolicies::stored($key))) {
                return true;
            }
        }

        return false;
    }
}
