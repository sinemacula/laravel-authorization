<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Removes the grants that no longer count: those that have expired, and those
 * whose grantee no longer exists (AUTHZ-3.6, AUTHZ-2.5, AUTHZ-17.6).
 *
 * An expired grant already stopped counting at its expiry; removing it keeps
 * the grant tables small. Each is reported with a `RoleExpired`,
 * `PermissionExpired` or `PolicyExpired` event, and every chunk is one
 * operation with no actor, since the sweep is system work. A grant re-armed
 * between the read and the delete is kept. The grants of a grantee that no
 * longer exists, such as one deleted by a raw query rather than through the
 * model, are revoked through `GrantService::revokeAll()`, so each is reported
 * as revoked. A soft-deleted grantee still exists and keeps its grants. A
 * grantee type that names no model class is skipped and reported, so a missing
 * morph map entry never removes grants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GrantPruner
{
    /**
     * Create a new grant pruner instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Services\GrantService  $grants
     */
    public function __construct(

        /** The grant service the grants of a grantee that is gone are revoked through. */
        private GrantService $grants,
    ) {}

    /**
     * Remove the expired grants and the grants of grantees that no longer
     * exist, or, pretending, only count them.
     *
     * @param  int  $chunk
     * @param  bool  $pretend
     * @return \SineMacula\Laravel\Authorization\Services\PruneResult
     *
     * @throws \Throwable
     */
    public function prune(int $chunk = 1000, bool $pretend = false): PruneResult
    {
        $expired = 0;

        foreach (GrantTarget::cases() as $kind) {
            $expired += $pretend ? self::expired($kind)->count() : self::pruneExpired($kind, $chunk);
        }

        [$orphans, $unresolved] = self::orphans($chunk);
        $orphaned               = 0;

        foreach ($orphans as $grantee) {
            $orphaned += $pretend ? self::countGrants($grantee) : $this->grants->revokeAll($grantee);
        }

        return new PruneResult($expired, $orphaned, $unresolved);
    }

    /**
     * Remove the expired grants of one kind, a chunk at a time, each chunk one
     * operation, and return how many were removed.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  int  $chunk
     * @return int
     *
     * @throws \Throwable
     */
    private static function pruneExpired(GrantTarget $kind, int $chunk): int
    {
        $removed = 0;

        do {
            $rows   = self::expired($kind)->limit($chunk)->get()->map(static fn (object $row): array => (array) $row)->all();
            $pruned = OperationScope::run(Operation::begin(), static fn (Operation $operation): int => self::pruneChunk($kind, $rows, $operation));

            $removed += $pruned;
        } while ($pruned > 0 && \count($rows) === $chunk);

        return $removed;
    }

    /**
     * Remove one chunk of expired grants, reporting each removed, and return
     * how many were removed.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  list<array<string, scalar|null>>  $rows
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return int
     */
    private static function pruneChunk(GrantTarget $kind, array $rows, Operation $operation): int
    {
        $targets = self::targets($kind, $rows);
        $events  = [];

        foreach ($rows as $row) {
            $target = $targets[(string) $row[$kind->column()]] ?? null;

            if ($target === null || self::grant($kind, $row)->delete() === 0) {
                continue;
            }

            $events[] = self::expiredEvent($kind, $operation, $row, $target);
        }

        OperationScope::dispatch(...$events);

        return \count($events);
    }

    /**
     * Load the roles, permissions or policies the rows grant, keyed by key.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  list<array<string, scalar|null>>  $rows
     * @return array<string, \Illuminate\Database\Eloquent\Model>
     */
    private static function targets(GrantTarget $kind, array $rows): array
    {
        $ids     = \array_values(\array_unique(\array_map(static fn (array $row): string => (string) $row[$kind->column()], $rows)));
        $targets = [];

        foreach ($kind->find($ids) as $model) {
            $targets[(string) $model->getKey()] = $model; // @phpstan-ignore cast.string
        }

        return $targets;
    }

    /**
     * Build the event that reports the removal of one expired grant row.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  array<string, scalar|null>  $row
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @return \SineMacula\Laravel\Authorization\Contracts\IdentityEvent
     */
    private static function expiredEvent(GrantTarget $kind, Operation $operation, array $row, Model $target): IdentityEvent
    {
        $grantee = new Reference((string) $row['authorizable_type'], (string) $row['authorizable_id']);

        return $kind->expiredEvent($operation, $grantee, $target, self::scope($row), UtcDateTime::toUtc($row['expires_at']) ?? Carbon::now('UTC'));
    }

    /**
     * Query the expired grants of one kind.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @return \Illuminate\Database\Query\Builder
     */
    private static function expired(GrantTarget $kind): Builder
    {
        return AuthorizationConnection::connection()->table($kind->table())->where('expires_at', '<=', Carbon::now('UTC'));
    }

    /**
     * Query exactly one expired grant row: its target, grantee and scope, and
     * an expiry that has still passed, so a grant re-armed since it was read is
     * left.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  array<string, scalar|null>  $columns
     * @return \Illuminate\Database\Query\Builder
     */
    private static function grant(GrantTarget $kind, array $columns): Builder
    {
        $query = self::expired($kind)
            ->where($kind->column(), $columns[$kind->column()])
            ->where('authorizable_type', $columns['authorizable_type'])
            ->where('authorizable_id', $columns['authorizable_id']);

        foreach (['tenant_type', 'tenant_id', 'application'] as $column) {
            $columns[$column] === null ? $query->whereNull($column) : $query->where($column, $columns[$column]);
        }

        return $query;
    }

    /**
     * Return the scope a grant row holds in.
     *
     * @param  array<string, scalar|null>  $columns
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    private static function scope(array $columns): GrantScope
    {
        $tenant = $columns['tenant_type'] === null ? null : new Reference((string) $columns['tenant_type'], (string) $columns['tenant_id']);

        return new GrantScope($tenant, $columns['application'] === null ? null : (string) $columns['application']);
    }

    /**
     * Return the grantees, across every grant table, that no longer exist, and
     * the grantee types that name no model class.
     *
     * @param  int  $chunk
     * @return array{0: list<\SineMacula\Laravel\Authorization\Support\Reference>, 1: list<string>}
     */
    private static function orphans(int $chunk): array
    {
        $orphans    = [];
        $unresolved = [];

        foreach (GrantTarget::cases() as $kind) {
            /** @var list<string> $types */
            $types = AuthorizationConnection::connection()->table($kind->table())->distinct()->orderBy('authorizable_type')->pluck('authorizable_type')->all();

            foreach ($types as $type) {
                $class = Relation::getMorphedModel($type) ?? $type;

                if (!\is_a($class, Model::class, true)) {
                    $unresolved[$type] = $type;

                    continue;
                }

                foreach (self::missing($kind, $type, $class, $chunk) as $id) {
                    $orphans["{$type}:{$id}"] = new Reference($type, $id);
                }
            }
        }

        return [\array_values($orphans), \array_values($unresolved)];
    }

    /**
     * Return the keys of grantees of one type holding grants of one kind that
     * the type's model no longer has, soft-deleted rows counting as had.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  string  $type
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  int  $chunk
     * @return list<string>
     */
    private static function missing(GrantTarget $kind, string $type, string $class, int $chunk): array
    {
        $missing = [];

        AuthorizationConnection::connection()->table($kind->table())
            ->where('authorizable_type', $type)
            ->select('authorizable_id')
            ->distinct()
            ->orderBy('authorizable_id')
            ->chunk($chunk, static function ($rows) use ($class, &$missing): void {
                /** @var list<string> $ids */
                $ids      = $rows->pluck('authorizable_id')->map(static fn (mixed $id): string => (string) $id)->all(); // @phpstan-ignore cast.string
                $existing = $class::query()->withoutGlobalScopes()->whereKey($ids)->pluck((new $class)->getKeyName());
                $existing = $existing->map(static fn (mixed $key): string => (string) $key)->all(); // @phpstan-ignore cast.string

                $missing = [...$missing, ...\array_values(\array_diff($ids, $existing))];
            });

        return $missing;
    }

    /**
     * Count the grants of every kind the grantee holds, in every scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return int
     */
    private static function countGrants(Reference $grantee): int
    {
        $count = 0;

        foreach (GrantTarget::cases() as $kind) {
            $count += AuthorizationConnection::connection()->table($kind->table())
                ->where('authorizable_type', $grantee->type)
                ->where('authorizable_id', $grantee->id)
                ->count();
        }

        return $count;
    }
}
