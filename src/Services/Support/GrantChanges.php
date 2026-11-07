<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Reads the grant tables for the grant service: the writer of a grantee's rows
 * of one kind, and the changes a sync or the revocation of everything makes, as
 * operation resources, so each can be decided before any is written.
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
     * re-armed), and a revocation of each row it drops, with the reach it had.
     * A kept row held live is left as it is, and decides nothing.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Services\Support\GrantTable  $table
     * @param  array<array-key, \Illuminate\Database\Eloquent\Model>  $keep
     * @param  array<array-key, bool>  $revoked
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $written
     * @param  \DateTimeInterface|null  $expiresAt
     * @return list<\SineMacula\Laravel\Authorization\Administration\OperationResource>
     */
    public static function ofSync(GrantTarget $kind, Reference $grantee, GrantTable $table, array $keep, array $revoked, GrantScope $written, ?\DateTimeInterface $expiresAt): array
    {
        $live    = $table->live(\array_map(\strval(...), \array_keys($keep)));
        $changes = [];

        foreach ($keep as $id => $model) {
            if (\in_array((string) $id, $live, true)) {
                continue;
            }

            $changes[] = OperationResource::grant($kind->grantAction(), $grantee, $model, $written, $expiresAt);
        }

        foreach ($kind->find(\array_map(\strval(...), \array_keys($revoked))) as $model) {
            $reach     = $revoked[self::key($model)] ?? true;
            $changes[] = OperationResource::revoke($kind->revokeAction(), $grantee, $model, new GrantScope($written->tenant, $written->application, $reach));
        }

        return $changes;
    }

    /**
     * Return each row a revocation removes, of the candidates, in the scope
     * each one's owner fixes or the one named: its model, the writer of its
     * row, its key, its reach, null when the grantee does not hold it, and its
     * scope. A candidate named by name the grantee does not hold is left out,
     * so nothing is decided for it; one named by model is kept, so it is
     * decided whether or not it is held.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  array<int, \Illuminate\Database\Eloquent\Model>  $candidates
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
     * @param  bool  $isNamed
     * @return list<array{
     *     \Illuminate\Database\Eloquent\Model,
     *     \SineMacula\Laravel\Authorization\Services\Support\GrantTable,
     *     string,
     *     bool|null,
     *     \SineMacula\Laravel\Authorization\Support\GrantScope
     * }>
     */
    public static function revocations(GrantTarget $kind, Reference $grantee, ?Reference $actor, array $candidates, GrantScope $named, bool $isNamed): array
    {
        $rows = [];

        foreach ($candidates as $model) {
            $scope = GrantScopes::of($kind, $model, $named->tenant);
            $table = self::table($kind, $grantee, $actor, new GrantScope($scope, $named->application));
            $key   = self::key($model);
            $reach = $table->reaches([$key])[$key] ?? null;

            if ($reach === null && $isNamed) {
                continue;
            }

            $rows[] = [$model, $table, $key, $reach, new GrantScope($scope, $named->application, $reach ?? true)];
        }

        return $rows;
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
     */
    private static function boundaries(Reference $grantee): array
    {
        /** @var string $table */
        $table   = config('authorization.tables.authorizable_boundaries', 'authorizable_boundaries');
        $changes = [];

        foreach ((new BoundaryTable(AuthorizationConnection::connection(), $table, $grantee))->everywhere() as [$key, $scope]) {
            $policy = InlinePolicies::stored($key);

            if ($policy === null) {
                continue;
            }

            $changes[] = OperationResource::revoke(PackagePermissions::BOUNDARY_REMOVE, $grantee, $policy, $scope);
        }

        return $changes;
    }
}
