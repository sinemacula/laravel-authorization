<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\Support\GrantChange;
use SineMacula\Laravel\Authorization\Services\Support\GrantTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Grants, revokes and syncs roles, permissions and policies to a grantee.
 *
 * Every call runs in one transaction on the package's connection, and reads the
 * role, permission and policy classes `authorization.models` configures. A role
 * or permission named by a string is looked up under the grantee's guard (its
 * `getAuthorizationGuard()`, when it declares one), else the package default.
 *
 * Every grant holds in a scope (AUTHZ-5.1): a role, permission or policy one
 * tenant owns is granted in that tenant, and naming another is refused with
 * `GrantScopeMismatchException`; one the platform owns is granted in the tenant
 * a call names as `$tenant`, else platform-wide. A name is looked up among the
 * rows visible in the tenant named, else in the current tenant. A revocation
 * follows the same rule, and a sync replaces the grants in one scope: the
 * tenant named, else the tenant that owns every target, else the platform.
 * Every grant is for every application.
 *
 * Grants are idempotent: granting what the grantee holds, with the same expiry,
 * changes nothing and is reported as unchanged, and a concurrent duplicate
 * never surfaces a unique-constraint violation. Re-granting a grant that has
 * expired re-arms it with the new expiry, and a different expiry on a live
 * grant is reported as a change.
 *
 * The identity events (`RoleAssigned`, `PermissionGranted`, `PolicyAttached`,
 * their revoked and detached counterparts, and the expiry-changed events) are
 * dispatched once the write commits, on the package's connection, and only for
 * a write that changed something; a write that rolls back, alone or with an
 * enclosing transaction, dispatches nothing. A changed expiry dispatches the
 * granted event as well as the expiry-changed one.
 *
 * Each method takes the actor making the call as `$actor`, a model or a
 * reference: null for console and system work. Every event the call dispatches
 * carries it, with one operation id the call's events share, and every grant
 * row it writes records it in `granted_by_type` and `granted_by_id`. It is
 * never read from the authenticated user. A grantee that is not a saved model
 * with a key, or a reference with a type and a key, throws
 * `InvalidGranteeException` before anything is read. A role or permission name
 * that answers no row throws `UnknownRoleException` or
 * `UnknownPermissionException`; a target that is not a saved model of the kind
 * granted, such as a policy sync handed another model, throws
 * `InvalidGrantTargetException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GrantService
{
    use HasContainerInstance;

    /**
     * Grant a role to the grantee, until the given expiry or forever.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantRole(
        Model|Reference $grantee,
        Role|string $role,
        ?\DateTimeInterface $expiresAt = null,
        Model|Reference|null $actor = null,
        Model|Reference|null $tenant = null,
    ): GrantOutcome {
        return $this->grant(GrantTarget::ROLE, $grantee, $role, $expiresAt, $actor, $tenant);
    }

    /**
     * Revoke a role from the grantee, and return how many roles were revoked:
     * none when the grantee held none.
     *
     * A name revokes every held role of that name under the grantee's guard, or
     * guard-agnostic, whichever tenant or the platform owns it.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return int
     *
     * @throws \Throwable
     */
    public function revokeRole(Model|Reference $grantee, Role|string $role, Model|Reference|null $actor = null, Model|Reference|null $tenant = null): int
    {
        return $this->revoke(GrantTarget::ROLE, $grantee, $role, $actor, $tenant);
    }

    /**
     * Replace the grantee's roles with the given ones.
     *
     * A name keeps every held role of that name, and only when the grantee
     * holds none is the role the lookup ranks first granted. A role the sync
     * grants, or re-arms because it had expired, carries the given expiry; a
     * live role is left as it is.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncRoles(
        Model|Reference $grantee,
        array $roles,
        ?\DateTimeInterface $expiresAt = null,
        Model|Reference|null $actor = null,
        Model|Reference|null $tenant = null,
    ): SyncResult {
        return $this->sync(GrantTarget::ROLE, $grantee, $roles, $expiresAt, $actor, $tenant);
    }

    /**
     * Grant a permission directly to the grantee, until the given expiry or
     * forever.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantPermission(
        Model|Reference $grantee,
        Permission|string $permission,
        ?\DateTimeInterface $expiresAt = null,
        Model|Reference|null $actor = null,
        Model|Reference|null $tenant = null,
    ): GrantOutcome {
        return $this->grant(GrantTarget::PERMISSION, $grantee, $permission, $expiresAt, $actor, $tenant);
    }

    /**
     * Revoke a direct permission from the grantee, and return how many
     * permissions were revoked: none when the grantee held none.
     *
     * A name revokes every held permission of that name under the grantee's
     * guard, or guard-agnostic, whichever tenant or the platform owns it.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return int
     *
     * @throws \Throwable
     */
    public function revokePermission(Model|Reference $grantee, Permission|string $permission, Model|Reference|null $actor = null, Model|Reference|null $tenant = null): int
    {
        return $this->revoke(GrantTarget::PERMISSION, $grantee, $permission, $actor, $tenant);
    }

    /**
     * Replace the grantee's direct permissions with the given ones, as
     * `syncRoles()` replaces its roles.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPermissions(
        Model|Reference $grantee,
        array $permissions,
        ?\DateTimeInterface $expiresAt = null,
        Model|Reference|null $actor = null,
        Model|Reference|null $tenant = null,
    ): SyncResult {
        return $this->sync(GrantTarget::PERMISSION, $grantee, $permissions, $expiresAt, $actor, $tenant);
    }

    /**
     * Attach a policy to the grantee, until the given expiry or forever.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function attachPolicy(
        Model|Reference $grantee,
        Policy $policy,
        ?\DateTimeInterface $expiresAt = null,
        Model|Reference|null $actor = null,
        Model|Reference|null $tenant = null,
    ): GrantOutcome {
        return $this->grant(GrantTarget::POLICY, $grantee, $policy, $expiresAt, $actor, $tenant);
    }

    /**
     * Detach a policy from the grantee, and return how many were detached: none
     * when it was not attached.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return int
     *
     * @throws \Throwable
     */
    public function detachPolicy(Model|Reference $grantee, Policy $policy, Model|Reference|null $actor = null, Model|Reference|null $tenant = null): int
    {
        return $this->revoke(GrantTarget::POLICY, $grantee, $policy, $actor, $tenant);
    }

    /**
     * Replace the grantee's attached policies with the given ones, as
     * `syncRoles()` replaces its roles. Each entry must be a saved policy.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPolicies(
        Model|Reference $grantee,
        array $policies,
        ?\DateTimeInterface $expiresAt = null,
        Model|Reference|null $actor = null,
        Model|Reference|null $tenant = null,
    ): SyncResult {
        return $this->sync(GrantTarget::POLICY, $grantee, $policies, $expiresAt, $actor, $tenant);
    }

    /**
     * Revoke every role, permission and policy the grantee holds, in one
     * transaction and as one operation, dispatching a revoked or detached event
     * for each. The `HasAuthorization` trait calls this once a grantee is
     * deleted.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function revokeAll(Model|Reference $grantee, Model|Reference|null $actor = null): int
    {
        $reference = self::grantee($grantee);
        $operation = Operation::begin($actor);

        $revoked = OperationScope::run($operation, static function (Operation $operation) use ($reference): int {
            $count  = 0;
            $events = [];

            foreach (GrantTarget::cases() as $kind) {
                $table  = self::table($kind, $reference, $operation, null);
                $grants = $table->grantsInEveryScope();
                $models = [];

                foreach ($kind->find(\array_column($grants, 0)) as $model) {
                    $models[self::key($model)] = $model;
                }

                $table->revokeInEveryScope();

                foreach ($grants as [$id, $tenant]) {
                    if (!isset($models[$id])) {
                        continue;
                    }

                    $events[] = $kind->revokedEvent($operation, $reference, $models[$id], new GrantScope($tenant));
                }

                $count += \count($grants);
            }

            OperationScope::dispatch(...$events);

            return $count;
        });

        foreach (GrantTarget::cases() as $kind) {
            self::forgetRelation($kind, $grantee);
        }

        return $revoked;
    }

    /**
     * Grant one row of the given kind in one transaction, in the scope its
     * owner fixes or the tenant named, else platform-wide.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  mixed  $target
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    private function grant(
        GrantTarget $kind,
        Model|Reference $grantee,
        mixed $target,
        ?\DateTimeInterface $expiresAt,
        Model|Reference|null $actor,
        Model|Reference|null $tenant,
    ): GrantOutcome {
        $reference = self::grantee($grantee);
        $named     = self::tenant($tenant);
        $operation = Operation::begin($actor);

        /** @var \SineMacula\Laravel\Authorization\Enums\GrantOutcome $outcome */
        $outcome = OperationScope::run($operation, static function (Operation $operation) use ($kind, $grantee, $reference, $named, $target, $expiresAt): GrantOutcome {
            $model  = $kind->resolve($target, self::guard($grantee), $named);
            $scope  = self::scopeOf($kind, $model, $named);
            $change = self::table($kind, $reference, $operation, $scope)->grant(self::key($model), $expiresAt);

            OperationScope::dispatch(...self::grantEvents($operation, $kind, $reference, $model, new GrantScope($scope), $change, $expiresAt));

            return $change->outcome;
        });

        self::forgetRelation($kind, $grantee);

        return $outcome;
    }

    /**
     * Revoke rows of the given kind in one transaction, each in the scope its
     * owner fixes or the tenant named, else platform-wide.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  mixed  $target
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return int
     *
     * @throws \Throwable
     */
    private function revoke(GrantTarget $kind, Model|Reference $grantee, mixed $target, Model|Reference|null $actor, Model|Reference|null $tenant): int
    {
        $reference = self::grantee($grantee);
        $named     = self::tenant($tenant);
        $operation = Operation::begin($actor);

        $revoked = OperationScope::run($operation, static function (Operation $operation) use ($kind, $grantee, $reference, $named, $target): int {
            $candidates = \is_string($target) ? $kind->named($target, self::guard($grantee), $named) : [$kind->assertTarget($target)];
            $events     = [];

            foreach ($candidates as $model) {
                $scope = self::scopeOf($kind, $model, $named);
                $table = self::table($kind, $reference, $operation, $scope);

                if ($table->held([self::key($model)]) === []) {
                    continue;
                }

                $table->revoke([self::key($model)]);

                $events[] = $kind->revokedEvent($operation, $reference, $model, new GrantScope($scope));
            }

            OperationScope::dispatch(...$events);

            return \count($events);
        });

        self::forgetRelation($kind, $grantee);

        return $revoked;
    }

    /**
     * Replace the grantee's rows of the given kind in one scope, in one
     * transaction: the tenant named, else the tenant that owns every target,
     * else the platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    private function sync(
        GrantTarget $kind,
        Model|Reference $grantee,
        array $targets,
        ?\DateTimeInterface $expiresAt,
        Model|Reference|null $actor,
        Model|Reference|null $tenant,
    ): SyncResult {
        $reference = self::grantee($grantee);
        $named     = self::tenant($tenant);
        $operation = Operation::begin($actor);

        /** @var \SineMacula\Laravel\Authorization\Services\SyncResult $result */
        $result = OperationScope::run($operation, static function (Operation $operation) use ($kind, $grantee, $reference, $named, $targets, $expiresAt): SyncResult {
            $scope   = $named ?? self::commonOwner($kind, $grantee, $targets);
            $table   = self::table($kind, $reference, $operation, $scope);
            $held    = $table->held();
            $keep    = self::toKeep($kind, $grantee, $targets, $held, $scope);
            $revoked = \array_values(\array_diff($held, \array_map(self::key(...), $keep)));
            $changed = [];
            $events  = [];

            $table->revoke($revoked);

            foreach ($keep as $model) {
                $id     = self::key($model);
                $change = $table->rearm($id, $expiresAt);
                $events = [...$events, ...self::grantEvents($operation, $kind, $reference, $model, new GrantScope($scope), $change, $expiresAt)];

                $changed[$change->outcome->value][] = $id;
            }

            foreach ($kind->find($revoked) as $model) {
                $events[] = $kind->revokedEvent($operation, $reference, $model, new GrantScope($scope));
            }

            OperationScope::dispatch(...$events);

            return new SyncResult($changed[GrantOutcome::GRANTED->value] ?? [], $changed[GrantOutcome::REARMED->value] ?? [], $revoked);
        });

        self::forgetRelation($kind, $grantee);

        return $result;
    }

    /**
     * Resolve the sync's targets, keyed by key: a named target keeps every held
     * row of the name, else the row the lookup ranks first. Each must be
     * grantable in the sync's scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  list<string>  $held
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $scope
     * @return array<string, \Illuminate\Database\Eloquent\Model>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     */
    private static function toKeep(GrantTarget $kind, Model|Reference $grantee, array $targets, array $held, ?Reference $scope): array
    {
        $keep = [];

        foreach ($targets as $target) {
            $models = \is_string($target) ? $kind->heldOrFirst($target, self::guard($grantee), $held, $scope) : [$kind->assertTarget($target)];

            foreach ($models as $model) {
                self::assertGrantableIn($kind, $model, $scope);

                $keep[self::key($model)] = $model;
            }
        }

        return $keep;
    }

    /**
     * Return the tenant that owns every target of a sync, or null for the
     * platform when any target is the platform's, their owners differ, or there
     * is none.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private static function commonOwner(GrantTarget $kind, Model|Reference $grantee, array $targets): ?Reference
    {
        $owners = \array_map(static fn (mixed $target): ?Reference => Reference::tenantOf($kind->resolve($target, self::guard($grantee))), $targets);
        $first  = $owners[0] ?? null;

        foreach ($owners as $owner) {
            if (!self::isSameTenant($owner, $first)) {
                return null;
            }
        }

        return $first;
    }

    /**
     * Return the scope a grant of the target holds in: the tenant that owns it,
     * else the tenant named, else null for platform-wide. A target one tenant
     * owns cannot be granted in another.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $named
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     */
    private static function scopeOf(GrantTarget $kind, Model $target, ?Reference $named): ?Reference
    {
        $scope = $named ?? Reference::tenantOf($target);

        self::assertGrantableIn($kind, $target, $scope);

        return $scope;
    }

    /**
     * Refuse a target one tenant owns in any scope but that tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $scope
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     */
    private static function assertGrantableIn(GrantTarget $kind, Model $target, ?Reference $scope): void
    {
        $owner = Reference::tenantOf($target);

        if ($owner === null || self::isSameTenant($owner, $scope)) {
            return;
        }

        /** @var string $name */
        $name = $target->getAttribute('name');

        throw new GrantScopeMismatchException($kind->value, $name, $owner, $scope);
    }

    /**
     * Determine whether two scopes are the same: the same tenant, or both the
     * platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $left
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $right
     * @return bool
     */
    private static function isSameTenant(?Reference $left, ?Reference $right): bool
    {
        return $left?->type === $right?->type && $left?->id === $right?->id;
    }

    /**
     * Build the events a grant's change dispatches: none when nothing changed,
     * the granted event for a new grant, and also the expiry-changed event for
     * a re-armed grant or a changed expiry.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \SineMacula\Laravel\Authorization\Services\Support\GrantChange  $change
     * @param  \DateTimeInterface|null  $expiresAt
     * @return list<\SineMacula\Laravel\Authorization\Contracts\IdentityEvent>
     */
    private static function grantEvents(
        Operation $operation,
        GrantTarget $kind,
        Reference $grantee,
        Model $model,
        GrantScope $scope,
        GrantChange $change,
        ?\DateTimeInterface $expiresAt,
    ): array {
        return match ($change->outcome) {
            GrantOutcome::UNCHANGED => [],
            GrantOutcome::GRANTED   => [$kind->grantedEvent($operation, $grantee, $model, $scope, $expiresAt)],
            default                 => [
                $kind->grantedEvent($operation, $grantee, $model, $scope, $expiresAt),
                $kind->expiryChangedEvent($operation, $grantee, $model, $scope, $change->previousExpiresAt, $expiresAt),
            ],
        };
    }

    /**
     * Clear the grantee's loaded relation onto the rows of the given kind, once
     * the call's transaction has returned.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return void
     */
    private static function forgetRelation(GrantTarget $kind, Model|Reference $grantee): void
    {
        if (!$grantee instanceof Model) {
            return;
        }

        $grantee->unsetRelation($kind->relation());
    }

    /**
     * Return the reference to the grantee, before the call's transaction opens,
     * once the grantee is known to be one a grant can be written for: a saved
     * model with a key, or a reference with a type and a key.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException
     */
    private static function grantee(Model|Reference $grantee): Reference
    {
        $reference = Reference::of($grantee);

        if ($reference->type === '' || $reference->id === '' || ($grantee instanceof Model && !$grantee->exists)) {
            throw new InvalidGranteeException($grantee);
        }

        return $reference;
    }

    /**
     * Return the grant table writer for the grantee's rows of the given kind,
     * recording the operation's actor on every row it writes.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantTable
     */
    private static function table(GrantTarget $kind, Reference $grantee, Operation $operation, ?Reference $tenant): GrantTable
    {
        return new GrantTable(AuthorizationConnection::connection(), $kind->table(), $kind->column(), $grantee->type, $grantee->id, $operation->actor, $tenant);
    }

    /**
     * Return the reference to the tenant a call names, or null for none.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    private static function tenant(Model|Reference|null $tenant): ?Reference
    {
        if (!$tenant instanceof Model) {
            return $tenant;
        }

        [$type, $id] = TenantScope::extractTenantPair($tenant);

        return new Reference($type, $id);
    }

    /**
     * Return a model's primary key as a string.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function key(Model $model): string
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
    private static function guard(Model|Reference $grantee): ?string
    {
        $reflection = new \ReflectionObject($grantee);

        if (!$reflection->hasMethod('getAuthorizationGuard')) {
            return null;
        }

        $guard = $reflection->getMethod('getAuthorizationGuard')->invoke($grantee);

        return \is_string($guard) ? $guard : null;
    }
}
