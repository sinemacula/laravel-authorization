<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpired as RolePermissionExpired;
use SineMacula\Laravel\Authorization\Services\Support\ExpiredSweep;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Removes the grants that no longer count: those that have expired, those whose
 * grantee no longer exists, and the resource policy attachments whose record no
 * longer exists (AUTHZ-3.6, AUTHZ-2.5, AUTHZ-7.3, AUTHZ-17.6).
 *
 * An expired grant already stopped counting at its expiry; removing it keeps
 * the grant tables small. Each is reported with a `RoleExpired`,
 * `PermissionExpired` or `PolicyExpired` event, and every chunk is one
 * operation with no actor, since the sweep is system work. A grant re-armed
 * between the read and the delete is kept. The grants of a grantee that no
 * longer exists, such as one deleted by a raw query rather than through the
 * model, are revoked through `GrantService::revokeAll()`, so each is reported
 * as revoked. Its permission boundaries (AUTHZ-7.4) are removed first, through
 * `BoundaryService::removeAll()`, each reported as removed and counted apart
 * from the grants: a grantee whose only rows are boundaries is found too, so a
 * boundary it leaves behind never keeps its policy undeletable. A soft-deleted
 * grantee still exists and keeps its grants and its boundaries. A grantee type
 * that names no model class is skipped and reported, so a missing morph map
 * entry never removes grants or boundaries.
 *
 * The inline policies of a grantee that no longer exists are deleted too, each
 * through the model so it is reported as deleted and its attachments go with it
 * (AUTHZ-6.9): the owner columns are a morph with no foreign key, so a grantee
 * removed without its model's `deleted` event leaves them behind. They are
 * deleted last, once the orphaned grants are revoked, so a policy that cannot
 * be deleted never keeps the grants of a grantee that is gone.
 *
 * The resource policy attachments of a record that no longer exists are
 * detached too, through `ResourcePolicyService::detachAll()`, so each is
 * reported as detached: a resource names its record by morph type and key, with
 * no foreign key, so deleting the record leaves them behind, and a record
 * created again under the same key would otherwise inherit them. The morph type
 * is resolved to its model class as a grantee's is; a type that names no model
 * class is skipped and reported, and a whole type's attachments are never
 * removed.
 *
 * Pretending counts exactly what a real run would remove, in the same order: an
 * expired grant once, among the expired, the boundaries of a grantee that is
 * gone, and its grants that are still live, with the attachments of its own
 * inline policies among them, since a real run revokes those before it deletes
 * the policies, then the attachments of each record that is gone.
 *
 * @phpstan-type ExpiredRow array{
 *     target_id: string,
 *     authorizable_type: string,
 *     authorizable_id: string,
 *     tenant_type: string|null,
 *     tenant_id: string|null,
 *     include_subtree: bool|int|string,
 *     application: string|null,
 *     expires_at: string,
 * }
 * @phpstan-type RolePermissionRow array{role_id: string, permission_id: string, expires_at: string}
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
     * @param  \SineMacula\Laravel\Authorization\Services\ResourcePolicyService  $resourcePolicies
     * @param  \SineMacula\Laravel\Authorization\Services\BoundaryService  $boundaries
     */
    public function __construct(

        /** The grant service the grants of a grantee that is gone are revoked through. */
        private GrantService $grants,

        /** The resource policy service the attachments of a record that is gone are detached through. */
        private ResourcePolicyService $resourcePolicies,

        /** The boundary service the boundaries of a grantee that is gone are removed through. */
        private BoundaryService $boundaries,
    ) {}

    /**
     * Remove the expired grants, the boundaries, grants and inline policies of
     * grantees that no longer exist, and the resource policy attachments of
     * records that no longer exist, or, pretending, only count them.
     *
     * @param  int  $chunk
     * @param  bool  $pretend
     * @return \SineMacula\Laravel\Authorization\Services\PruneResult
     *
     * @throws \Throwable
     */
    public function prune(int $chunk, bool $pretend = false): PruneResult
    {
        $expired = self::removeExpired($chunk, $pretend);

        [$orphans, $unresolved]  = self::orphans($chunk);
        [$orphaned, $boundaries] = $this->removeOrphaned($orphans, $pretend);

        [$owners, $unowned] = self::missingOwners(self::table('policies'), 'owner', $chunk);
        $inline             = 0;

        foreach ($owners as $owner) {
            $inline += $pretend ? InlinePolicies::countOwnedBy($owner) : InlinePolicies::deleteOwnedBy($owner);
        }

        [$records, $unplaced] = self::missingOwners(self::table('resource_policies'), 'resource', $chunk);
        $attachments          = 0;

        foreach ($records as $record) {
            $attachments += $pretend ? self::countAttachments($record) : $this->resourcePolicies->detachAll(ResourceReference::record($record->type, $record->id));
        }

        return new PruneResult($expired, $orphaned, $inline, \array_values($unresolved + $unowned), $attachments, \array_values($unplaced), $boundaries);
    }

    /**
     * Remove the expired grants, a role's of permissions first, or, pretending,
     * only count them, and return how many there are.
     *
     * @param  int  $chunk
     * @param  bool  $pretend
     * @return int
     *
     * @throws \Throwable
     */
    private static function removeExpired(int $chunk, bool $pretend): int
    {
        $expired = $pretend ? self::expiredRolePermissions()->count() : (new ExpiredSweep(self::pruneRolePermissionChunk(...)))->run(
            self::expiredRolePermissions(),
            ['role_id', 'permission_id', 'expires_at'],
            $chunk,
        );

        foreach (GrantTarget::cases() as $kind) {
            $expired += $pretend ? self::expired($kind)->count() : (new ExpiredSweep(self::pruneChunk(...), $kind))->run(
                self::expired($kind),
                [$kind->column() . ' as target_id', 'authorizable_type', 'authorizable_id', 'tenant_type', 'tenant_id', 'include_subtree', 'application', 'expires_at'],
                $chunk,
            );
        }

        return $expired;
    }

    /**
     * Remove the boundaries and then the grants of each grantee that no longer
     * exists, or, pretending, only count them, and return how many grants and
     * how many boundaries there are.
     *
     * @param  array<string, \SineMacula\Laravel\Authorization\Support\Reference>  $orphans
     * @param  bool  $pretend
     * @return array{0: int, 1: int}
     *
     * @throws \Throwable
     */
    private function removeOrphaned(array $orphans, bool $pretend): array
    {
        $orphaned   = 0;
        $boundaries = 0;

        foreach ($orphans as $grantee) {
            $boundaries += $pretend ? self::countBoundaries($grantee) : $this->boundaries->removeAll($grantee);
            $orphaned   += $pretend ? self::countLiveGrants($grantee) : $this->grants->revokeAll($grantee);
        }

        return [$orphaned, $boundaries];
    }

    /**
     * Remove one chunk of a role's expired grants of permissions, reporting
     * each removed, and return how many were removed.
     *
     * @param  list<RolePermissionRow>  $rows
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return int
     */
    private static function pruneRolePermissionChunk(array $rows, Operation $operation): int
    {
        /** @var array<string, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = self::keyed(GrantTarget::ROLE, \array_column($rows, 'role_id'));

        /** @var array<string, \SineMacula\Laravel\Authorization\Models\Permission> $permissions */
        $permissions = self::keyed(GrantTarget::PERMISSION, \array_column($rows, 'permission_id'));
        $events      = [];

        foreach ($rows as $row) {
            $role       = $roles[$row['role_id']]             ?? null;
            $permission = $permissions[$row['permission_id']] ?? null;

            if ($role === null || $permission === null || self::rolePermission($row)->delete() === 0) {
                continue;
            }

            $events[] = new RolePermissionExpired(
                $operation,
                Reference::of($role),
                $role->name,
                Reference::of($permission),
                $permission->name,
                Reference::tenantOf($role),
                Carbon::parse($row['expires_at'], 'UTC')->toImmutable(),
            );
        }

        OperationScope::dispatch(...$events);

        return \count($events);
    }

    /**
     * Remove one chunk of expired grants, reporting each removed, and return
     * how many were removed.
     *
     * @param  list<ExpiredRow>  $rows
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @return int
     */
    private static function pruneChunk(array $rows, Operation $operation, GrantTarget $kind): int
    {
        $targets = self::keyed($kind, \array_column($rows, 'target_id'));
        $events  = [];

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
     * Load the roles, permissions or policies with the given keys, keyed by
     * key.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  list<string>  $ids
     * @return array<string, \Illuminate\Database\Eloquent\Model>
     */
    private static function keyed(GrantTarget $kind, array $ids): array
    {
        $models = [];

        foreach ($kind->find($ids) as $model) {
            $models[$model->getKey()] = $model; // @phpstan-ignore offsetAccess.invalidOffset
        }

        return $models;
    }

    /**
     * Query the expired grants of permissions to roles.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function expiredRolePermissions(): Builder
    {
        /** @var string $table */
        $table = config('authorization.tables.role_permissions', 'role_permissions');

        return AuthorizationConnection::connection()->table($table)->where('expires_at', '<=', Carbon::now('UTC'));
    }

    /**
     * Query exactly one expired grant of a permission to a role, so a grant
     * re-armed since it was read is left.
     *
     * @param  RolePermissionRow  $row
     * @return \Illuminate\Database\Query\Builder
     */
    private static function rolePermission(array $row): Builder
    {
        return self::expiredRolePermissions()->where('role_id', $row['role_id'])->where('permission_id', $row['permission_id']);
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

        return new GrantScope($tenant, $row['application'], (bool) $row['include_subtree']);
    }

    /**
     * Return the grantees, across every grant table and the boundaries table,
     * that no longer exist, keyed so each is listed once, and the grantee types
     * that name no model class.
     *
     * @param  int  $chunk
     * @return array{0: array<string, \SineMacula\Laravel\Authorization\Support\Reference>, 1: array<string, string>}
     */
    private static function orphans(int $chunk): array
    {
        $orphans    = [];
        $unresolved = [];

        foreach ([...\array_map(static fn (GrantTarget $kind): string => $kind->table(), GrantTarget::cases()), self::table('authorizable_boundaries')] as $table) {
            [$missing, $types] = self::missingOwners($table, 'authorizable', $chunk);

            $orphans    += $missing;
            $unresolved += $types;
        }

        return [$orphans, $unresolved];
    }

    /**
     * Return the records a table's morph names that no longer exist, keyed so
     * each is listed once, and the morph types that name no model class: the
     * grantees of a grant table, the grantees inline policies belong to, or the
     * records resource policies are attached to. A row whose key is null, such
     * as an attachment to a whole type, names no record and is passed over.
     *
     * @param  string  $table
     * @param  string  $morph
     * @param  int  $chunk
     * @return array{0: array<string, \SineMacula\Laravel\Authorization\Support\Reference>, 1: array<string, string>}
     */
    private static function missingOwners(string $table, string $morph, int $chunk): array
    {
        $missing    = [];
        $unresolved = [];

        /** @var list<string> $types */
        $types = AuthorizationConnection::connection()->table($table)
            ->whereNotNull($morph . '_type')
            ->whereNotNull($morph . '_id')
            ->distinct()
            ->orderBy($morph . '_type')
            ->pluck($morph . '_type')
            ->all();

        foreach ($types as $type) {
            $class = Relation::getMorphedModel($type) ?? $type;

            if (!\is_a($class, Model::class, true)) {
                $unresolved[$type] = $type;

                continue;
            }

            foreach (self::missing($table, $morph, $type, $class, $chunk) as $id) {
                $missing["{$type}:{$id}"] = new Reference($type, $id);
            }
        }

        return [$missing, $unresolved];
    }

    /**
     * Return the keys of the records of one type a table's morph names that the
     * type's model no longer has, soft-deleted rows counting as had.
     *
     * @param  string  $table
     * @param  string  $morph
     * @param  string  $type
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  int  $chunk
     * @return list<string>
     */
    private static function missing(string $table, string $morph, string $type, string $class, int $chunk): array
    {
        $missing = [];
        $column  = $morph . '_id';

        AuthorizationConnection::connection()->table($table)
            ->where($morph . '_type', $type)
            ->whereNotNull($column)
            ->select($column)
            ->distinct()
            ->orderBy($column)
            ->chunk($chunk, static function ($rows) use ($class, $column, &$missing): void {
                /** @var list<string> $ids */
                $ids = $rows->pluck($column)->all();

                $found = \array_filter($class::query()->withoutGlobalScopes()->whereKey($ids)->pluck((new $class)->getKeyName())->all(), \is_scalar(...));

                // `array_diff()` compares as strings, so an integer key matches
                // the grant's string id.
                foreach (\array_diff($ids, $found) as $id) {
                    $missing[] = $id;
                }
            });

        return $missing;
    }

    /**
     * Return the package table, as `authorization.tables` names it.
     *
     * @param  string  $name
     * @return string
     */
    private static function table(string $name): string
    {
        /** @var string */
        return config('authorization.tables.' . $name, $name);
    }

    /**
     * Count the resource policy attachments of the record, in every scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $record
     * @return int
     */
    private static function countAttachments(Reference $record): int
    {
        return AuthorizationConnection::connection()->table(self::table('resource_policies'))
            ->where('resource_type', $record->type)
            ->where('resource_id', $record->id)
            ->count();
    }

    /**
     * Count the grantee's permission boundaries, in every scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return int
     */
    private static function countBoundaries(Reference $grantee): int
    {
        return AuthorizationConnection::connection()->table(self::table('authorizable_boundaries'))
            ->where('authorizable_type', $grantee->type)
            ->where('authorizable_id', $grantee->id)
            ->count();
    }

    /**
     * Count the grants of every kind the grantee holds, in every scope, that
     * have not expired: a real run removes an expired one among the expired,
     * before it revokes the grantee's grants.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return int
     */
    private static function countLiveGrants(Reference $grantee): int
    {
        $count = 0;

        foreach (GrantTarget::cases() as $kind) {
            $count += LiveGrants::only(AuthorizationConnection::connection()->table($kind->table()), $kind->table())
                ->where('authorizable_type', $grantee->type)
                ->where('authorizable_id', $grantee->id)
                ->count();
        }

        return $count;
    }
}
