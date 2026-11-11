<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantColumns;

/**
 * Reads the grant tables for the grant service: the writer of a grantee's rows
 * of one kind, and the changes a sync or the revocation of everything makes, as
 * operation resources, so each can be decided before any is written; and
 * revokes everything a grantee holds, every row for trusted work, exactly the
 * rows decided for an acting context.
 *
 * @phpstan-type MalformedGrant array{target_id: string, tenant_type: string|null, tenant_id: string|null, application: string|null}
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GrantChanges
{
    /**
     * Return the grant table writer for the grantee's rows of the given kind in
     * the scope, recording the actor on every row it writes.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantTable
     */
    public static function table(GrantTarget $kind, Reference $grantee, ?Reference $actor, GrantScope $scope): GrantTable
    {
        return new GrantTable(
            AuthorizationConnection::connection(),
            $kind->table(),
            $kind->column(),
            $grantee->type,
            $grantee->id,
            $actor,
            $scope->tenant,
            $scope->includeSubtree,
            $scope->application,
        );
    }

    /**
     * Return the changes a sync makes, each to be decided before any is
     * written: a grant, in the written scope, of each kept row the grantee does
     * not hold live there (a new one, or one whose grant has expired and is
     * re-armed), the same row kept unchanged for each of the keys given as held
     * live, and a revocation of each row it drops, with the reach it had. The
     * sync judges the live keys at one instant and re-arms its rows as of the
     * same instant, so a row decided as kept unchanged is never re-armed; a
     * sync that changes nothing at all decides its revocation unchanged, so its
     * action is still decided.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  list<string>  $live
     * @param  array<array-key, \Illuminate\Database\Eloquent\Model>  $keep
     * @param  array<array-key, bool>  $revoked
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $written
     * @param  \DateTimeInterface|null  $expiresAt
     * @return non-empty-list<\SineMacula\Laravel\Authorization\Administration\OperationResource>
     */
    public static function ofSync(GrantTarget $kind, Reference $grantee, array $live, array $keep, array $revoked, GrantScope $written, ?\DateTimeInterface $expiresAt): array
    {
        $changes = [];

        foreach ($keep as $id => $model) {
            $changes[] = \in_array((string) $id, $live, true)
                ? OperationResource::unchanged($kind->grantAction(), $grantee, $model, $written)
                : OperationResource::grant($kind->grantAction(), $grantee, $model, $written, $expiresAt);
        }

        foreach ($kind->find(\array_map(\strval(...), \array_keys($revoked))) as $model) {
            $changes[] = OperationResource::revoke($kind->revokeAction(), $grantee, $model, new GrantScope($written->tenant, $written->application, $revoked[self::key($model)]));
        }

        return $changes === [] ? [OperationResource::unchanged($kind->revokeAction(), $grantee, null, $written)] : $changes;
    }

    /**
     * Return each row a revocation removes, of the candidates, in the scope
     * each one's owner fixes or the one named: its model, the writer of its
     * row, its key, its reach, null when the grantee does not hold it, and its
     * scope. Of the candidates of a name, those the grantee holds are kept, or,
     * when it holds none, the one the lookup ranks first, so the revocation the
     * call asks for is still decided; a candidate named by model is kept
     * whether or not it is held.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  non-empty-list<\Illuminate\Database\Eloquent\Model>  $candidates
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
     * @return non-empty-list<array{
     *     \Illuminate\Database\Eloquent\Model,
     *     \SineMacula\Laravel\Authorization\Services\Support\GrantTable,
     *     string,
     *     bool|null,
     *     \SineMacula\Laravel\Authorization\Support\GrantScope
     * }>
     */
    public static function revocations(GrantTarget $kind, Reference $grantee, ?Reference $actor, array $candidates, GrantScope $named): array
    {
        $rows = [];
        $held = [];

        foreach ($candidates as $model) {
            $scope = GrantScopes::of($kind, $model, $named->tenant);
            $table = self::table($kind, $grantee, $actor, new GrantScope($scope, $named->application));
            $key   = self::key($model);
            $reach = $table->reaches([$key])[$key] ?? null;
            $row   = [$model, $table, $key, $reach, new GrantScope($scope, $named->application, $reach ?? true)];

            $rows[] = $row;

            if ($reach === null) {
                continue;
            }

            $held[] = $row;
        }

        return $held === [] ? [$rows[0]] : $held;
    }

    /**
     * Return the revocation of every role, permission and policy the grantee
     * holds, and the removal of each of its permission boundaries, in every
     * scope, each to be decided before any is written; and, read by the same
     * queries, the rows naming half a tenant, which the package never writes:
     * each grant as its kind, what it grants and its row, and each boundary as
     * its row (see `malformed()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return array{
     *     list<\SineMacula\Laravel\Authorization\Administration\OperationResource>,
     *     list<array{\SineMacula\Laravel\Authorization\Enums\GrantTarget, \Illuminate\Database\Eloquent\Model, MalformedGrant}>,
     *     list<array{policy_id: string, tenant_type: string|null, tenant_id: string|null}>
     * }
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     */
    public static function everything(Reference $grantee): array
    {
        $changes   = [];
        $malformed = [];

        foreach (GrantTarget::cases() as $kind) {
            [$grants, $half] = self::table($kind, $grantee, null, GrantScope::platform())->grantsInEveryScope();
            $models          = self::keyed($kind, [...\array_column($grants, 0), ...\array_column($half, 'target_id')]);

            foreach ($grants as [$id, $scope]) {
                $changes[] = OperationResource::revoke($kind->revokeAction(), $grantee, $models[$id], $scope);
            }

            foreach ($half as $row) {
                $malformed[] = [$kind, $models[$row['target_id']], $row];
            }
        }

        [$boundaries, $halfBoundaries] = (new BoundaryTable(AuthorizationConnection::connection(), TableNames::get('authorizable_boundaries'), $grantee))->everywhere();

        return [[...$changes, ...BoundaryService::removals($grantee, $boundaries)], $malformed, $halfBoundaries];
    }

    /**
     * Return the revocation of each row naming half a tenant given, and the
     * removal of each boundary stored that way, each decided at platform scope,
     * a grant in the row's application: such a row is neither the platform's
     * nor any tenant's, and what restricts of it holds everywhere (see
     * `Support\TenantColumns`), so only platform authority covers it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  list<array{\SineMacula\Laravel\Authorization\Enums\GrantTarget, \Illuminate\Database\Eloquent\Model, MalformedGrant}>  $grants
     * @param  list<array{policy_id: string, tenant_type: string|null, tenant_id: string|null}>  $boundaries
     * @return list<\SineMacula\Laravel\Authorization\Administration\OperationResource>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     */
    public static function malformed(Reference $grantee, array $grants, array $boundaries): array
    {
        $changes = [];

        foreach ($grants as [$kind, $target, $row]) {
            $changes[] = OperationResource::revoke($kind->revokeAction(), $grantee, $target, new GrantScope(null, $row['application']));
        }

        return [...$changes, ...BoundaryService::malformedRemovals($grantee, $boundaries)];
    }

    /**
     * Revoke each row naming half a tenant given, as stored, and remove each
     * boundary stored that way, inside the caller's operation, writing each
     * removed to the log as malformed once the operation commits, since no
     * event can say where it held, and invalidating the cache as their events
     * would; and return how many were removed: a row no longer there is passed
     * over.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  list<array{\SineMacula\Laravel\Authorization\Enums\GrantTarget, \Illuminate\Database\Eloquent\Model, MalformedGrant}>  $grants
     * @param  list<array{policy_id: string, tenant_type: string|null, tenant_id: string|null}>  $boundaries
     * @return int
     */
    public static function revokeMalformed(Reference $grantee, Operation $operation, array $grants, array $boundaries): int
    {
        $events = [];

        foreach ($grants as [$kind, $target, $row]) {
            if (self::table($kind, $grantee, $operation->actor, GrantScope::platform())->revokeMalformed($row) !== 1) {
                continue;
            }

            $context = ['grantee' => "{$grantee->type}:{$grantee->id}", 'target_id' => $row['target_id']];

            TenantColumns::reportRemoved("a {$kind->value} grant", $row['tenant_type'], $row['tenant_id'], $context);

            $events[] = $kind->revokedEvent($operation, $grantee, $target, new GrantScope(null, $row['application']));
        }

        OperationScope::invalidate(...$events);

        return \count($events) + BoundaryService::removeMalformed($grantee, $operation, $boundaries);
    }

    /**
     * Revoke every row the grantee holds, of every kind and in every scope, and
     * remove its boundaries, inside the caller's trusted operation, and return
     * a revoked, detached or removed event for each, in its scope: what is done
     * for a deleted grantee, with nothing decided; with how many rows naming
     * half a tenant were removed, found by the same reads, each as
     * `revokeMalformed()` removes it, before the rest.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return array{list<\SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent>, int}
     */
    public static function revokeEverywhere(Reference $grantee, Operation $operation): array
    {
        $read      = [];
        $malformed = [];

        foreach (GrantTarget::cases() as $kind) {
            $table           = self::table($kind, $grantee, $operation->actor, GrantScope::platform());
            [$grants, $half] = $table->grantsInEveryScope();
            $models          = self::keyed($kind, [...\array_column($grants, 0), ...\array_column($half, 'target_id')]);
            $read[]          = [$kind, $table, $grants, $models];

            foreach ($half as $row) {
                $malformed[] = [$kind, $models[$row['target_id']], $row];
            }
        }

        $removed = self::revokeMalformed($grantee, $operation, $malformed, []);
        $events  = [];

        foreach ($read as [$kind, $table, $grants, $models]) {
            $table->revokeInEveryScope();

            foreach ($grants as [$id, $scope]) {
                $events[] = $kind->revokedEvent($operation, $grantee, $models[$id], $scope);
            }
        }

        [$boundaries, $halfBoundaries] = BoundaryService::removeEverywhere($grantee, $operation);

        return [[...$events, ...$boundaries], $removed + $halfBoundaries];
    }

    /**
     * Revoke exactly the rows the changes decided, inside the caller's
     * delegated operation, each by its key in its scope, and remove the
     * boundaries they decided, each in its scope, and return a revoked,
     * detached or removed event for each: what revoking everything a grantee
     * holds does for an acting context, so a row granted after the decision
     * read the grantee's rows is never revoked undecided. A row decided that is
     * no longer there to revoke throws `DependencyChangedException`, so the
     * operation is tried again.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  list<\SineMacula\Laravel\Authorization\Administration\OperationResource>  $changes
     * @return list<\SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    public static function revokeDecided(Reference $grantee, Operation $operation, array $changes): array
    {
        $kinds      = [];
        $events     = [];
        $boundaries = [];

        foreach (GrantTarget::cases() as $kind) {
            $kinds[$kind->revokeAction()] = $kind;
        }

        foreach ($changes as $change) {
            /** @var \SineMacula\Laravel\Authorization\Administration\OperationChange $made */
            $made = $change->change;

            /** @var \Illuminate\Database\Eloquent\Model $target */
            $target = $made->target;
            $kind   = $kinds[$change->action] ?? null;

            if ($kind === null) {
                $boundaries[] = [self::key($target), $made->scope];

                continue;
            }

            if (self::table($kind, $grantee, $operation->actor, $made->scope)->revoke([self::key($target)]) !== 1) {
                throw DependencyChangedException::rows($kind->table());
            }

            $events[] = $kind->revokedEvent($operation, $grantee, $target, $made->scope);
        }

        return [...$events, ...BoundaryService::removeDecided($grantee, $operation, $boundaries)];
    }

    /**
     * Return a model's primary key as a string.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    public static function key(Model $model): string
    {
        /** @var int|string $key */
        $key = $model->getKey();

        return (string) $key;
    }

    /**
     * Resolve the grantee's optional `getAuthorizationGuard()` hook. The hook
     * is duck-typed, so it is read through reflection.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return string|null
     */
    public static function guard(Model|Reference $grantee): ?string
    {
        $reflection = new \ReflectionObject($grantee);

        if (!$reflection->hasMethod('getAuthorizationGuard')) {
            return null;
        }

        $guard = $reflection->getMethod('getAuthorizationGuard')->invoke($grantee);

        return \is_string($guard) ? $guard : null;
    }

    /**
     * Return the roles, permissions or policies with the given keys, by key,
     * reading none for no keys.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  list<string>  $ids
     * @return array<string, \Illuminate\Database\Eloquent\Model>
     */
    private static function keyed(GrantTarget $kind, array $ids): array
    {
        $models = [];

        foreach ($ids === [] ? [] : $kind->find($ids) as $model) {
            $models[self::key($model)] = $model;
        }

        return $models;
    }
}
