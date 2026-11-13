<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\GrantUsageKey;

/**
 * The stored rows a review of expiries or of an actor lists, one row for each,
 * never expanded into routes: the roles and permissions granted, the policies
 * attached to grantees and to roles, and, for expiries, the permission edges of
 * roles, a kind of their own. Each is listed whether or not it still counts at
 * the review's instant, its `grant_state` saying which.
 *
 * - Expiring: the rows whose expiry is at or after the start of the UTC window
 *   and before its end, so a row expiring exactly at the end falls in the next
 *   window, each bound kept to the microsecond against expiries stored to the
 *   whole second (see `window()`). An expiring row does not by itself mean
 *   access is lost: another route may keep the target held.
 * - Granted by: the rows whose `granted_by` pair is exactly the actor's: the
 *   last actor to grant or change each (N95), since a regrant, a changed expiry
 *   or a changed reach overwrites it. A trusted write names no actor, so no
 *   actor's review lists it; a revoked row is gone.
 *
 * The roles granted are read with the break-glass activations not ended or
 * expired at the review's instant, each a row of its own (see
 * `GrantRows::held()`): one expiring within the window, or one the actor
 * activated, is listed, and an unused review lists each as `unknown`, since its
 * use is never tracked.
 *
 * A role edge holds no scope of its own: in a review of what applies in a
 * tenant, it is listed when the tenant sees both its role and its permission;
 * in a review rooted within a tenant, when its role is owned there or below. A
 * role's policy attachment, in a review of what applies in a tenant, is listed
 * only when the tenant sees its role too, as a check reaches it only through
 * that role.
 *
 * - Unused: the live grants of each kind, roles and permissions granted and
 *   policies attached to grantees, that show no observed use from the review's
 *   `since`, or the grant's creation when later, to the review's instant (see
 *   `unused()`).
 *
 * Each kind is read in the review's order, one query of at most the room left,
 * a later page resuming after the last row of the page before by its keyset; an
 * unused review's kinds are read a fixed chunk at a time instead, since its
 * filter may pass over any number of grants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StoredRows
{
    /**
     * Collect the rows the query lists: for expiries, those of every kind,
     * edges included, whose expiry falls within its window; for an actor, those
     * of every kind of grant whose `granted_by` pair is the actor's. Every
     * grantee is known, so the review is complete.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @return bool
     *
     * @throws \UnexpectedValueException
     */
    public static function read(ReviewRun $run, ReviewQuery $query, RowCollector $rows): bool
    {
        $isExpiring = $query->kind === ReviewKind::EXPIRING;

        self::collectAll($run, $rows, $isExpiring ? self::window($query) : self::grantedBy($query), $isExpiring);

        return true;
    }

    /**
     * Collect the live grants of each kind, roles and permissions granted and
     * policies attached to grantees, whose route shows no observed use in its
     * window, unused or unknown, as the collector's filter keeps them (see
     * `ReviewUsage::isUnobserved()`). Each kind is read in the review's order a
     * fixed chunk at a time, what the store keeps of the chunk's routes read in
     * one lookup, until the rows are full or none is left. Every grantee is
     * known, so the review is complete.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewUsage  $usage
     * @return bool
     *
     * @throws \UnexpectedValueException
     */
    public static function unused(ReviewRun $run, RowCollector $rows, ReviewUsage $usage): bool
    {
        $role = Definitions::morph(GrantTarget::ROLE);
        $live = static function (Builder $stored, string $table) use ($run): void {
            $run->live($stored, $table);
        };

        $kinds = [
            [SourceKind::ROLE_GRANT, GrantTarget::ROLE, null],
            [SourceKind::PERMISSION_GRANT, GrantTarget::PERMISSION, null],
            [SourceKind::POLICY_ATTACHMENT, GrantTarget::POLICY, false],
        ];

        foreach ($kinds as [$source, $kind, $isToRole]) {
            self::collectUnobserved($rows, $source, $kind, self::grants($run, $kind, $isToRole, $role, $live), $usage);
        }

        return true;
    }

    /**
     * Return the condition a row expiring within the query's window meets: its
     * expiry at or after the window's start and before its end.
     *
     * An expiry is stored to the whole second, its fraction dropped, and an
     * instant is bound in the same whole-second format, so each bound is first
     * rounded up to the next whole second when it has a fraction: a stored
     * expiry is at or after a bound exactly when it is at or after the bound
     * rounded up, and before it exactly when it is before the bound rounded up,
     * so the window keeps its sub-second bounds on every database.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return \Closure(\Illuminate\Database\Query\Builder, string): void
     *
     * @throws \UnexpectedValueException
     */
    private static function window(ReviewQuery $query): \Closure
    {
        $from  = self::wholeSecondAtOrAfter($query->from ?? throw new \UnexpectedValueException('A review of expiries names its window.'));
        $until = self::wholeSecondAtOrAfter($query->until ?? throw new \UnexpectedValueException('A review of expiries names its window.'));

        return static function (Builder $stored, string $table) use ($from, $until): void {
            $stored->where($table . '.expires_at', '>=', $from)->where($table . '.expires_at', '<', $until);
        };
    }

    /**
     * Return the instant itself when it falls on a whole second, else the next
     * whole second.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return \Carbon\CarbonImmutable
     */
    private static function wholeSecondAtOrAfter(CarbonImmutable $at): CarbonImmutable
    {
        return $at->microsecond === 0 ? $at : $at->startOfSecond()->addSecond();
    }

    /**
     * Return the condition a row the query's actor last granted or changed
     * meets: its `granted_by` pair is exactly the actor's.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return \Closure(\Illuminate\Database\Query\Builder, string): void
     *
     * @throws \UnexpectedValueException
     */
    private static function grantedBy(ReviewQuery $query): \Closure
    {
        $actor = $query->actor ?? throw new \UnexpectedValueException('A review of an actor\'s grants names the actor.');

        return static function (Builder $stored, string $table) use ($actor): void {
            $stored->where($table . '.granted_by_type', $actor->type)->where($table . '.granted_by_id', $actor->id);
        };
    }

    /**
     * Collect the rows of each kind, in the order of the kinds, that meet the
     * condition, until the rows are full.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): void  $condition
     * @param  bool  $withEdges
     * @return void
     */
    private static function collectAll(ReviewRun $run, RowCollector $rows, \Closure $condition, bool $withEdges): void
    {
        $role = Definitions::morph(GrantTarget::ROLE);

        $kinds = [
            [SourceKind::ROLE_GRANT, GrantTarget::ROLE, null],
            [SourceKind::PERMISSION_GRANT, GrantTarget::PERMISSION, null],
            [SourceKind::POLICY_ATTACHMENT, GrantTarget::POLICY, false],
            [SourceKind::ROLE_PERMISSION_EDGE, GrantTarget::PERMISSION, null],
            [SourceKind::ROLE_POLICY_ATTACHMENT, GrantTarget::POLICY, true],
        ];

        foreach ($kinds as [$source, $kind, $isToRole]) {
            if ($source !== SourceKind::ROLE_PERMISSION_EDGE) {
                self::collect($rows, $source, $kind, self::grants($run, $kind, $isToRole, $role, $condition));
            } elseif ($withEdges) {
                self::collect($rows, $source, $kind, [Definitions::edges() => self::edges($run, $condition)], $role);
            }
        }
    }

    /**
     * Collect at most the room left of the queries' rows, in the review's
     * order, each the row of the source, its target of the kind: none when the
     * rows are full or every row of the source comes before the page before
     * ended, and on a later page those after its last row.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $source
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  non-empty-array<string, \Illuminate\Database\Query\Builder>  $queries
     * @param  string|null  $roleType
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function collect(RowCollector $rows, SourceKind $source, GrantTarget $kind, array $queries, ?string $roleType = null): void
    {
        if ($rows->isFull() || $rows->isPast($source)) {
            return;
        }

        $type   = Definitions::morph($kind);
        $stored = $roleType === null ? $kind->value : GrantRow::EDGE;
        $after  = $rows->resumeAt($source);
        $from   = static fn (Builder $query, string $table): Builder => self::resumed($query, $table, $kind, $roleType !== null, $after);

        foreach (GrantRows::pageOf($queries, $from, $stored, $rows->room(), true, $roleType) as $row) {
            $isRoleRow = $source === SourceKind::ROLE_POLICY_ATTACHMENT || $source === SourceKind::ROLE_PERMISSION_EDGE;
            $chain     = match (true) {
                $source === SourceKind::ROLE_GRANT => [$row->targetId],
                $isRoleRow                         => [$row->grantee->id],
                default                            => [],
            };

            $rows->route($source, $row->grantee, $row, new Reference($type, $row->targetId), $chain);
        }
    }

    /**
     * Collect the rows of the source the collector keeps, reading its grants a
     * fixed chunk at a time, the room the page leaves when it starts or
     * `GrantRows::CHUNK`, whichever is more, each chunk's routes looked up in
     * one go first, resuming after the last grant read, until the rows are full
     * or none is left; a chunk is never smaller for the rows already kept, so
     * the reads grow with the grants passed over, never one for each.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $source
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  non-empty-array<string, \Illuminate\Database\Query\Builder>  $queries
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewUsage  $usage
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function collectUnobserved(RowCollector $rows, SourceKind $source, GrantTarget $kind, array $queries, ReviewUsage $usage): void
    {
        $type  = Definitions::morph($kind);
        $after = $rows->resumeAt($source);
        $size  = \max($rows->room(), GrantRows::CHUNK);
        $chain = static fn (GrantRow $row): array => $source === SourceKind::ROLE_GRANT ? [$row->targetId] : [];

        while (!$rows->isFull() && !$rows->isPast($source)) {
            $from = static fn (Builder $query, string $table): Builder => self::resumed($query, $table, $kind, false, $after);
            $read = GrantRows::pageOf($queries, $from, $kind->value, $size, true);

            $usage->prime(\array_map(static fn (GrantRow $row): string => GrantUsageKey::ofStored($source, $row, new Reference($type, $row->targetId), $chain($row)), $read));

            foreach ($read as $row) {
                $rows->route($source, $row->grantee, $row, new Reference($type, $row->targetId), $chain($row));
            }

            if (\count($read) < $size) {
                return;
            }

            $last  = $read[\count($read) - 1];
            $after = [$source->position(), $type, $last->targetId, ...$last->orderKey(), ...RowCollector::routeKey($chain($last), [])];
        }
    }

    /**
     * Return the ordered query limited to the rows after the stored row the
     * last row of the page before is, given its sort key; from its start, given
     * none. Each stored row is one row of the review, so none is read again.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  bool  $isEdge
     * @param  list<bool|int|string|null>|null  $after
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \UnexpectedValueException
     */
    private static function resumed(Builder $query, string $table, GrantTarget $kind, bool $isEdge, ?array $after): Builder
    {
        return match (true) {
            $after === null => $query,
            $isEdge         => GrantRows::afterEdge($query, GrantRows::edgeAt($after)),
            default         => GrantRows::after($query, $table, $kind->column(), true, GrantRows::positionAt($after, true)),
        };
    }

    /**
     * Return the ordered queries, keyed by table, of the grants of the kind in
     * the review's scope that meet the condition, of definitions the reviewed
     * tenant sees; for a policy, only its attachments to roles, of roles the
     * tenant sees, or only those to grantees, as asked, an inline policy's to
     * another grantee left out.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  bool|null  $isToRole
     * @param  string  $role
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): void  $condition
     * @return non-empty-array<string, \Illuminate\Database\Query\Builder>
     */
    private static function grants(ReviewRun $run, GrantTarget $kind, ?bool $isToRole, string $role, \Closure $condition): array
    {
        return GrantRows::held($run, $kind, static function (Builder $query, string $table) use ($run, $kind, $isToRole, $role, $condition): Builder {
            $run->visible($run->constrain($query, $table), $kind, $table . '.' . $kind->column());

            $condition($query, $table);

            if ($isToRole !== null) {
                InlinePolicies::attachedToTheirGrantee($query, $table)->where($table . '.authorizable_type', $isToRole ? '=' : '!=', $role);
            }

            if ($isToRole === true) {
                $run->visibleRoles($query, $table);
            }

            return GrantRows::ordered($query, $table, $kind->column());
        });
    }

    /**
     * Return the ordered query of the role permission edges the review's scope
     * selects that meet the condition: those whose role the scope selects by
     * its owner, and, in a review of what applies in a tenant, whose permission
     * the tenant sees.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): void  $condition
     * @return \Illuminate\Database\Query\Builder
     */
    private static function edges(ReviewRun $run, \Closure $condition): Builder
    {
        $table         = Definitions::edges();
        [$roles, $key] = Definitions::tableOf(GrantTarget::ROLE);

        $owned = static function (Builder $owner) use ($run, $roles, $key, $table): void {
            $run->owned($owner->selectRaw('1')->from($roles)->whereColumn($roles . '.' . $key, $table . '.role_id'), $roles);
        };

        $query = $run->visible(GrantRows::edges(), GrantTarget::PERMISSION, $table . '.permission_id')->whereExists($owned);

        $condition($query, $table);

        ReviewOrder::by($query, $table . '.permission_id');

        return ReviewOrder::by($query, $table . '.role_id');
    }
}
