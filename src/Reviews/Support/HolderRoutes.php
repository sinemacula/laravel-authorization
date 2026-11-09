<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Who holds a role, a permission or a policy in a review's scope (N93), one row
 * for each route, the grantee of the stored grant being the holder:
 *
 * - a direct grant of the target;
 * - for a role, a grant of a role below it, which inherits it;
 * - for a permission, a grant of a role that carries it, or of a role below
 *   one, through every such role, each its own route;
 * - for a policy, a grant of a role it is attached to, or of a role below one,
 *   through every such attachment that holds where the grant does.
 *
 * An identity's grant names the identity, whose principals the review does not
 * expand: the identity directory lists an identity's principals, not the other
 * way round. A permission means that definition, never a policy statement or a
 * wildcard grant that might authorise its action; a role, permission or policy
 * is matched by its key, so two definitions sharing a name under another guard
 * or owner are never confused.
 *
 * The grants are read a page at a time in the review's order, so the rows held
 * never exceed the limit and its one extra, and the queries never grow with the
 * holders: the roles involved are read first, in a fixed number of queries,
 * then the grants of all of them together.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HolderRoutes
{
    /**
     * Collect the rows of the holders of the query's target: none for a key no
     * definition could have, or for a definition the reviewed tenant does not
     * see.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function read(ReviewRun $run, ReviewQuery $query, RowCollector $rows): bool
    {
        $target = $query->target;
        $kind   = $query->targetKind();

        if ($target !== null && $kind !== null && Definitions::isKey($target->id) && $run->seesDefinition($kind, $target->id)) {
            match ($kind) {
                GrantTarget::ROLE       => self::ofRole($run, $target, $query->isDirectOnly, $rows),
                GrantTarget::PERMISSION => self::ofPermission($run, $target, $query->isDirectOnly, $rows),
                GrantTarget::POLICY     => self::ofPolicy($run, $target, $query->isDirectOnly, $rows),
            };
        }

        return true;
    }

    /**
     * Collect the holders of the role: its grants, then the grants of every
     * role below it, through the chain up to it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $role
     * @param  bool  $isDirectOnly
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function ofRole(ReviewRun $run, Reference $role, bool $isDirectOnly, RowCollector $rows): void
    {
        self::direct($run, GrantTarget::ROLE, $role, $rows);

        if ($isDirectOnly) {
            return;
        }

        $below = RoleChains::below($run, [$role->id]);

        unset($below[$role->id]);

        self::throughRoles($run, $below, $rows, static function (GrantRow $grant, array $chain) use ($rows, $role): void {
            $path = \array_slice($chain, 0, (int) \array_search($role->id, $chain, true) + 1);

            $rows->route(SourceKind::ROLE_INHERITED, $grant->grantee, $grant, $role, $path);
        });
    }

    /**
     * Collect the holders of the permission: its direct grants, then the grants
     * of every role carrying it or below one that does.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $permission
     * @param  bool  $isDirectOnly
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function ofPermission(ReviewRun $run, Reference $permission, bool $isDirectOnly, RowCollector $rows): void
    {
        self::direct($run, GrantTarget::PERMISSION, $permission, $rows);

        if ($isDirectOnly) {
            return;
        }

        $edges = RoleCarriers::edges($run, null, $permission->id);

        $chains = RoleChains::below($run, \array_map(strval(...), \array_keys($edges)));

        self::throughRoles($run, $chains, $rows, static function (GrantRow $grant, array $chain) use ($rows, $edges): void {
            RoleCarriers::throughEdges($rows, $grant->grantee, $grant, $chain, $edges);
        });
    }

    /**
     * Collect the holders of the policy: its direct attachments, then the
     * grants of every role it is attached to, or below one, through every
     * attachment that holds where the grant does.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $policy
     * @param  bool  $isDirectOnly
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function ofPolicy(ReviewRun $run, Reference $policy, bool $isDirectOnly, RowCollector $rows): void
    {
        self::direct($run, GrantTarget::POLICY, $policy, $rows);

        if ($isDirectOnly) {
            return;
        }

        $attachments = RoleCarriers::attachments($run, null, $policy->id);

        $chains = RoleChains::below($run, \array_map(strval(...), \array_keys($attachments)));

        self::throughRoles($run, $chains, $rows, static function (GrantRow $grant, array $chain) use ($run, $rows, $attachments): void {
            RoleCarriers::throughAttachments($run, $rows, $grant->grantee, $grant, $chain, $attachments);
        });
    }

    /**
     * Collect the target's direct grants in the scope, each one route, a
     * policy's attachments to roles left to the routes through roles.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $target
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @return void
     */
    private static function direct(ReviewRun $run, GrantTarget $kind, Reference $target, RowCollector $rows): void
    {
        $table = $kind->table();
        $query = self::scoped($run, $kind)->where($table . '.' . $kind->column(), $target->id);

        if ($kind === GrantTarget::POLICY) {
            InlinePolicies::attachedToTheirGrantee($query, $table)->where($table . '.authorizable_type', '!=', Definitions::morph(GrantTarget::ROLE));
        }

        $source = match ($kind) {
            GrantTarget::ROLE       => SourceKind::ROLE_GRANT,
            GrantTarget::PERMISSION => SourceKind::PERMISSION_GRANT,
            GrantTarget::POLICY     => SourceKind::POLICY_ATTACHMENT,
        };

        $chain = $kind === GrantTarget::ROLE ? [$target->id] : [];

        foreach (GrantRows::page(GrantRows::ordered($query, $table, $kind->column()), $kind->value, 0, $rows->room()) as $grant) {
            $rows->route($source, $grant->grantee, $grant, $target, $chain);
        }
    }

    /**
     * Collect the routes the callback expands each grant of one of the roles
     * into, given the role's chain, reading the grants a page at a time in the
     * review's order until the rows are full or none is left: a page is the
     * room left, and a grant may expand into no route at all, a role's policy
     * attachment holding nowhere the grant does, so another page is read only
     * then.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  array<string, list<string>>  $chains
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \Closure(\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow, list<string>): void  $expand
     * @return void
     */
    private static function throughRoles(ReviewRun $run, array $chains, RowCollector $rows, \Closure $expand): void
    {
        $table  = GrantTarget::ROLE->table();
        $query  = GrantRows::ordered(self::scoped($run, GrantTarget::ROLE)->whereIn($table . '.role_id', \array_map(strval(...), \array_keys($chains))), $table, 'role_id', false);
        $offset = 0;

        while ($chains !== [] && !$rows->isFull()) {
            $size = $rows->room();
            $page = GrantRows::page($query, GrantTarget::ROLE->value, $offset, $size);

            foreach ($page as $grant) {
                $expand($grant, $chains[$grant->targetId] ?? [$grant->targetId]);
            }

            $offset += $size;
            $chains = \count($page) < $size ? [] : $chains;
        }
    }

    /**
     * Return a query of the live grants of the kind in the review's scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @return \Illuminate\Database\Query\Builder
     */
    private static function scoped(ReviewRun $run, GrantTarget $kind): Builder
    {
        $table = $kind->table();

        return $run->live($run->constrain(GrantRows::of($kind), $table), $table);
    }
}
