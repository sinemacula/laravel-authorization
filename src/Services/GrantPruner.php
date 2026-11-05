<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
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
 * @phpstan-type ExpiredRow array{
 *     target_id: string,
 *     authorizable_type: string,
 *     authorizable_id: string,
 *     tenant_type: string|null,
 *     tenant_id: string|null,
 *     application: string|null,
 *     expires_at: string,
 * }
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
    public function prune(int $chunk, bool $pretend = false): PruneResult
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

        return new PruneResult($expired, $orphaned, \array_values($unresolved));
    }

    /**
     * Remove the expired grants of one kind, a chunk at a time, each chunk one
     * operation, and return how many were removed.
     *
     * Every row read is removed, or has been re-armed or removed since, so a
     * later read never returns it and the sweep ends.
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
            /** @var list<ExpiredRow> $rows */
            $rows = self::expired($kind)
                ->limit($chunk)
                ->get([$kind->column() . ' as target_id', 'authorizable_type', 'authorizable_id', 'tenant_type', 'tenant_id', 'application', 'expires_at'])
                ->map(static fn (object $row): array => (array) $row)
                ->all();

            $removed += OperationScope::run(Operation::begin(), static fn (Operation $operation): int => self::pruneChunk($kind, $rows, $operation));
        } while (\count($rows) === $chunk);

        return $removed;
    }

    /**
     * Remove one chunk of expired grants, reporting each removed, and return
     * how many were removed.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  list<ExpiredRow>  $rows
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return int
     */
    private static function pruneChunk(GrantTarget $kind, array $rows, Operation $operation): int
    {
        $targets = [];
        $events  = [];

        foreach ($kind->find(\array_column($rows, 'target_id')) as $model) {
            $targets[$model->getKey()] = $model; // @phpstan-ignore offsetAccess.invalidOffset
        }

        foreach ($rows as $row) {
            $target = $targets[$row['target_id']] ?? null;

            if ($target === null || self::grant($kind, $row)->delete() === 0) {
                continue;
            }

            $grantee  = new Reference($row['authorizable_type'], $row['authorizable_id']);
            $events[] = $kind->expiredEvent($operation, $grantee, $target, self::scope($row), Carbon::parse($row['expires_at'], 'UTC'));
        }

        OperationScope::dispatch(...$events);

        return \count($events);
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
     * @param  ExpiredRow  $row
     * @return \Illuminate\Database\Query\Builder
     */
    private static function grant(GrantTarget $kind, array $row): Builder
    {
        $query = self::expired($kind)
            ->where($kind->column(), $row['target_id'])
            ->where('authorizable_type', $row['authorizable_type'])
            ->where('authorizable_id', $row['authorizable_id']);

        foreach (['tenant_type', 'tenant_id', 'application'] as $column) {
            $row[$column] === null ? $query->whereNull($column) : $query->where($column, $row[$column]);
        }

        return $query;
    }

    /**
     * Return the scope a grant row holds in.
     *
     * @param  ExpiredRow  $row
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    private static function scope(array $row): GrantScope
    {
        $tenant = $row['tenant_type'] === null ? null : new Reference($row['tenant_type'], (string) $row['tenant_id']);

        return new GrantScope($tenant, $row['application']);
    }

    /**
     * Return the grantees, across every grant table, that no longer exist,
     * keyed so each is listed once, and the grantee types that name no model
     * class.
     *
     * @param  int  $chunk
     * @return array{0: array<string, \SineMacula\Laravel\Authorization\Support\Reference>, 1: array<string, string>}
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

        return [$orphans, $unresolved];
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
                $ids = $rows->pluck('authorizable_id')->all();

                // `array_diff()` compares as strings, so an integer key matches
                // the grant's string id.
                foreach (\array_diff($ids, $class::query()->withoutGlobalScopes()->whereKey($ids)->pluck((new $class)->getKeyName())->all()) as $id) {
                    $missing[] = $id;
                }
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
