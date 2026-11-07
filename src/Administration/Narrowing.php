<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\RoleGraph;

/**
 * Tells whether removing a grant can only narrow authority, so delegated
 * administration may allow it on its action's decision alone, before the
 * constraints of the later parts of BL-65 are evaluated.
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
        $chain = self::chainOf($role->id, RoleGraph::reach([$role->id]));

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

    /**
     * Return the keys of the role and of each role above it, walking the links
     * from the role up to the root, or null when the walk reaches a role the
     * links do not hold, or one it has passed already.
     *
     * @param  string  $key
     * @param  array<string, string|null>  $links
     * @return list<string>|null
     */
    private static function chainOf(string $key, array $links): ?array
    {
        $chain   = [];
        $current = $key;

        while ($current !== null) {
            if (!\array_key_exists($current, $links) || \in_array($current, $chain, true)) {
                return null;
            }

            $chain[] = $current;
            $current = $links[$current];
        }

        return $chain;
    }
}
