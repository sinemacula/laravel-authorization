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
 * The grants are read a page at a time in the review's order, each page no
 * larger than the room left (the limit and its one extra, less the rows held),
 * so the grants read stay bounded by the limit. A later page of the review
 * reads no source whose rows all come before the page before ended, and the
 * source of its last row resumes, by keyset, at the grant that row starts from
 * (see `RowCollector`). A grant adds one row for each role of its chain that
 * carries the target, or each attachment that holds where it does, so the rows
 * held may exceed the limit and its one extra before they are cut to the limit.
 * The roles involved are read first, in a fixed number of queries, then the
 * grants of all of them together, never one query per holder: for a policy,
 * only the grants that reach one of its attachments are read (see
 * `RoleCarriers::reaching()`), so a grant that would add no row is never read,
 * and whether each page's grants meet the attachments is settled in a fixed
 * number of queries (see `ReviewRun::settle()`), never one for each tenant a
 * grant is held in.
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
     * see. A definition's key is a UUID, read in its canonical lowercase form
     * however the query spells it, as every database stores and returns it, so
     * a key in capitals finds the same holders, through the same routes, on
     * every database.
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
        $target = $query->target === null ? null : new Reference($query->target->type, \strtolower($query->target->id));
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

        self::throughRoles($run, $below, $rows, SourceKind::ROLE_INHERITED, static function (GrantRow $grant, array $chain) use ($rows, $role): void {
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

        self::throughRoles($run, $chains, $rows, SourceKind::ROLE_PERMISSION, static function (GrantRow $grant, array $chain) use ($rows, $edges): void {
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

        self::throughRoles(
            $run,
            $chains,
            $rows,
            SourceKind::ROLE_POLICY,
            static function (GrantRow $grant, array $chain) use ($run, $rows, $attachments): void {
                RoleCarriers::throughAttachments($run, $rows, $grant->grantee, $grant, $chain, $attachments);
            },
            static fn (Builder $query, string $table): Builder => RoleCarriers::reaching($run, $query, $table, $chains, $attachments),
            static function (array $page) use ($run, $attachments): void {
                $run->settle($page, $attachments);
            },
        );
    }

    /**
     * Collect the target's direct grants in the scope, each one route, a
     * policy's attachments to roles left to the routes through roles: none when
     * every one comes before the page before ended, and on a later page those
     * from its last row's on. Every grant read is of the one target, so they
     * are ordered, and resumed, by their grantee and scope alone, which the
     * index leading with the target and the grantee serves, and each row names
     * the target by the key its grant stores.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $target
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function direct(ReviewRun $run, GrantTarget $kind, Reference $target, RowCollector $rows): void
    {
        $source = match ($kind) {
            GrantTarget::ROLE       => SourceKind::ROLE_GRANT,
            GrantTarget::PERMISSION => SourceKind::PERMISSION_GRANT,
            GrantTarget::POLICY     => SourceKind::POLICY_ATTACHMENT,
        };

        if ($rows->isPast($source)) {
            return;
        }

        $table = $kind->table();
        $query = GrantRows::ordered(self::scoped($run, $kind)->where($table . '.' . $kind->column(), $target->id), $table, $kind->column(), null);

        if ($kind === GrantTarget::POLICY) {
            InlinePolicies::attachedToTheirGrantee($query, $table)->where($table . '.authorizable_type', '!=', Definitions::morph(GrantTarget::ROLE));
        }

        $resume = $rows->resumeAt($source);

        foreach (GrantRows::page(self::resumed($query, $table, $kind->column(), null, $resume), $kind->value, self::sizeOf($rows, $resume)) as $grant) {
            $rows->route($source, $grant->grantee, $grant, new Reference($target->type, $grant->targetId), $kind === GrantTarget::ROLE ? [$grant->targetId] : []);
        }
    }

    /**
     * Collect the routes of the source's kind the callback expands each grant
     * of one of the roles into, given the role's chain, reading the grants a
     * page at a time in the review's order until the rows are full or none is
     * left: none for no role; a page is the room left, the query narrowed first
     * when asked, and each page handed to the reader given before it is
     * expanded. The routes through roles are the last kind of a review of
     * holders, so no page before can have ended past them. Each page after the
     * first starts after the last grant read, never at an offset; on a later
     * page of the review, the first starts at the grant its last row starts
     * from, read again for its remaining routes, so it reads one grant more.
     * Every grant read expands into at least one route, so the first page fills
     * the rows or is the last.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  array<string, list<string>>  $chains
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $source
     * @param  \Closure(\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow, list<string>): void  $expand
     * @param  (\Closure(\Illuminate\Database\Query\Builder, string): \Illuminate\Database\Query\Builder)|null  $narrow
     * @param  (\Closure(list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>): void)|null  $read
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function throughRoles(
        ReviewRun $run,
        array $chains,
        RowCollector $rows,
        SourceKind $source,
        \Closure $expand,
        ?\Closure $narrow = null,
        ?\Closure $read = null,
    ): void {
        $table  = GrantTarget::ROLE->table();
        $query  = self::scoped($run, GrantTarget::ROLE)->whereIn($table . '.role_id', \array_map(strval(...), \array_keys($chains)));
        $query  = GrantRows::ordered($narrow === null ? $query : $narrow($query, $table), $table, 'role_id', false);
        $resume = $rows->resumeAt($source);
        $isLeft = $chains !== [];

        while ($isLeft && !$rows->isFull()) {
            $size = self::sizeOf($rows, $resume);
            $page = GrantRows::page(self::resumed(clone $query, $table, 'role_id', false, $resume), GrantTarget::ROLE->value, $size);

            self::expand($page, $chains, $expand, $read);

            $isLeft = \count($page) === $size;
            $resume = $page[$size - 1] ?? null;
        }
    }

    /**
     * Hand the page of grants to the reader given, then expand each grant into
     * its routes, given its role's chain, or its role alone when the role has
     * none.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>  $page
     * @param  array<string, list<string>>  $chains
     * @param  \Closure(\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow, list<string>): void  $expand
     * @param  (\Closure(list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>): void)|null  $read
     * @return void
     */
    private static function expand(array $page, array $chains, \Closure $expand, ?\Closure $read): void
    {
        if ($read !== null) {
            $read($page);
        }

        foreach ($page as $grant) {
            $expand($grant, $chains[$grant->targetId] ?? [$grant->targetId]);
        }
    }

    /**
     * Return the ordered grant query limited to start where the review left
     * off: at the stored row the last row of the page before starts from, read
     * again for its remaining routes, given that row's sort key; after a grant
     * already read, given the grant; from its start, given nothing.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  string  $target
     * @param  bool|null  $isTargetFirst
     * @param  list<bool|int|string|null>|\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow|null  $from
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \UnexpectedValueException
     */
    private static function resumed(Builder $query, string $table, string $target, ?bool $isTargetFirst, array|GrantRow|null $from): Builder
    {
        return match (true) {
            $from === null            => $query,
            $from instanceof GrantRow => GrantRows::after($query, $table, $target, $isTargetFirst, GrantRows::positionOf($from, $isTargetFirst)),
            default                   => GrantRows::after($query, $table, $target, $isTargetFirst, GrantRows::positionAt($from, $isTargetFirst), true),
        };
    }

    /**
     * Return how many grants to read next: the room left, and one more when the
     * read starts at the stored row a row of the page before starts from, which
     * may add no row.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  list<bool|int|string|null>|\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow|null  $from
     * @return int
     */
    private static function sizeOf(RowCollector $rows, array|GrantRow|null $from): int
    {
        return $rows->room() + (\is_array($from) ? 1 : 0);
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
