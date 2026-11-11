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
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Reads the grant tables for the grant service: the writer of a grantee's rows
 * of one kind, and the changes a sync or the revocation of everything makes, as
 * operation resources, so each can be decided before any is written; and
 * revokes everything a grantee holds, every row for trusted work, exactly the
 * rows decided for an acting context.
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
     * written: a grant of each kept row the grantee does not hold live (a new
     * one, or one whose grant has expired and is re-armed), with the sync's
     * expiry; a grant, with the expiry it keeps, of each row held live with the
     * other reach than its entry names; the same row kept unchanged for each
     * other row held live; and a revocation of each row it drops, with the
     * reach it had. Each kept row is decided in the scope the plan writes it in
     * (`SyncPlan::scopeOf()`). The sync judges the live rows at one instant and
     * re-arms its rows as of the same instant, so a row decided as kept
     * unchanged is never re-armed; a sync that changes nothing at all decides
     * its revocation unchanged, so its action is still decided.
     *
     * @param  \SineMacula\Laravel\Authorization\Services\Support\SyncPlan  $plan
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<array-key, array{\Illuminate\Support\Carbon|null, bool}>  $live
     * @param  array<array-key, bool>  $revoked
     * @param  \DateTimeInterface|null  $expiresAt
     * @return non-empty-list<\SineMacula\Laravel\Authorization\Administration\OperationResource>
     */
    public static function ofSync(SyncPlan $plan, Reference $grantee, array $live, array $revoked, ?\DateTimeInterface $expiresAt): array
    {
        $kind    = $plan->kind;
        $changes = [];
        $kept    = self::keptAsHeld($live, $plan->reaches);

        foreach ($plan->keep as $model) {
            $id        = self::key($model);
            $scope     = $plan->scopeOf($id);
            $changes[] = \in_array($id, $kept, true)
                ? OperationResource::unchanged($kind->grantAction(), $grantee, $model, $scope)
                : OperationResource::grant($kind->grantAction(), $grantee, $model, $scope, self::expiryOf($live, $id, $expiresAt));
        }

        foreach ($kind->find(\array_map(\strval(...), \array_keys($revoked))) as $model) {
            $held      = new GrantScope($plan->written->tenant, $plan->written->application, $revoked[self::key($model)]);
            $changes[] = OperationResource::revoke($kind->revokeAction(), $grantee, $model, $held);
        }

        return $changes === [] ? [OperationResource::unchanged($kind->revokeAction(), $grantee, null, $plan->written)] : $changes;
    }

    /**
     * Return the keys of the rows held live, of those given, that a sync keeps
     * as they are: each but a row listed with a reach of its own (the scopes
     * given) that holds with the other reach.
     *
     * @param  array<array-key, array{\Illuminate\Support\Carbon|null, bool}>  $live
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\GrantScope>  $reaches
     * @return list<string>
     */
    public static function keptAsHeld(array $live, array $reaches): array
    {
        $kept = [];

        foreach ($live as $id => [, $isBelow]) {
            if (($reaches[$id] ?? null)?->includeSubtree === !$isBelow) {
                continue;
            }

            $kept[] = (string) $id;
        }

        return $kept;
    }

    /**
     * Return the expiry a sync grants the kept row of the key with: the one the
     * row held live keeps, when it is held live, else the sync's.
     *
     * @param  array<array-key, array{\Illuminate\Support\Carbon|null, bool}>  $live
     * @param  array-key  $id
     * @param  \DateTimeInterface|null  $expiresAt
     * @return \DateTimeInterface|null
     */
    public static function expiryOf(array $live, int|string $id, ?\DateTimeInterface $expiresAt): ?\DateTimeInterface
    {
        return \array_key_exists($id, $live) ? $live[$id][0] : $expiresAt;
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
     * scope, each to be decided before any is written.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return list<\SineMacula\Laravel\Authorization\Administration\OperationResource>
     */
    public static function everything(Reference $grantee): array
    {
        $changes = [];

        foreach (GrantTarget::cases() as $kind) {
            $grants = self::table($kind, $grantee, null, GrantScope::platform())->grantsInEveryScope();
            $models = [];

            foreach ($kind->find(\array_column($grants, 0)) as $model) {
                $models[self::key($model)] = $model;
            }

            foreach ($grants as [$id, $scope]) {
                $changes[] = OperationResource::revoke($kind->revokeAction(), $grantee, $models[$id], $scope);
            }
        }

        return [...$changes, ...self::boundaries($grantee)];
    }

    /**
     * Revoke every row the grantee holds, of every kind and in every scope, and
     * remove its boundaries, inside the caller's trusted operation, and return
     * a revoked, detached or removed event for each, in its scope: what is done
     * for a grantee that was deleted, with nothing decided.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return list<\SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent>
     */
    public static function revokeEverywhere(Reference $grantee, Operation $operation): array
    {
        $events = [];

        foreach (GrantTarget::cases() as $kind) {
            $table  = self::table($kind, $grantee, $operation->actor, GrantScope::platform());
            $grants = $table->grantsInEveryScope();
            $models = [];

            foreach ($kind->find(\array_column($grants, 0)) as $model) {
                $models[self::key($model)] = $model;
            }

            $table->revokeInEveryScope();

            foreach ($grants as [$id, $scope]) {
                $events[] = $kind->revokedEvent($operation, $grantee, $models[$id], $scope);
            }
        }

        return [...$events, ...BoundaryService::removeEverywhere($grantee, $operation)];
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
     * Return the removal of each of the grantee's permission boundaries, in
     * every scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return list<\SineMacula\Laravel\Authorization\Administration\OperationResource>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     */
    private static function boundaries(Reference $grantee): array
    {
        $table = TableNames::get('authorizable_boundaries');

        return BoundaryService::removals($grantee, (new BoundaryTable(AuthorizationConnection::connection(), $table, $grantee))->everywhere());
    }
}
