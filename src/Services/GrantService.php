<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\GrantScopes;
use SineMacula\Laravel\Authorization\Services\Support\GrantTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleParity;

/**
 * Grants, revokes and syncs roles, permissions and policies to a grantee.
 *
 * Every call runs in one transaction on the package's connection, and reads the
 * role, permission and policy classes `authorization.models` configures. A role
 * or permission named by a string is looked up under the grantee's guard (its
 * `getAuthorizationGuard()`, when it declares one), else the package default.
 *
 * Every grant holds in a scope (AUTHZ-5.1): a role, permission or policy one
 * tenant owns is granted in that tenant, or a tenant below it that a call
 * names, and naming any other is refused with `GrantScopeMismatchException`;
 * one the platform owns is granted in the tenant a call names as `$tenant`,
 * else platform-wide. A name is looked up among the rows visible in the tenant
 * named, else in the current tenant. A revocation follows the same rule, and a
 * sync replaces the grants in one scope: the tenant named, else the tenant that
 * owns every target, else the platform. A grant holds in the application the
 * call names as `$application`, else in every application (AUTHZ-5.6, D24); a
 * revocation and a sync stay in it the same way.
 *
 * A grant in a tenant also holds in the tenants below it in the tenant tree
 * (AUTHZ-5.3), unless the call passes `$includeSubtree` false to limit it to
 * that tenant; a platform-wide grant counts everywhere whatever it is given.
 * Granting what the grantee holds, with the same expiry and another reach,
 * changes the reach and is reported as `REACH_CHANGED` with the granted event
 * (D21); a sync writes its reach only to what it grants or re-arms.
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
 * A grantee is an identity or a role: a policy attached to a role applies to
 * whoever holds the role, within both grants' scopes, and to whoever holds a
 * role below it (AUTHZ-7.2). An inline policy is attached only to the grantee
 * it belongs to; attaching or syncing it to any other throws
 * `InlinePolicyAttachmentException` before anything is written (AUTHZ-6.9).
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
     * @param  bool  $includeSubtree
     * @param  string|null  $application
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
        bool $includeSubtree = true,
        ?string $application = null,
    ): GrantOutcome {
        return $this->grant(GrantTarget::ROLE, $grantee, $role, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
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
     * @param  string|null  $application
     * @return int
     *
     * @throws \Throwable
     */
    public function revokeRole(
        Model|Reference $grantee,
        Role|string $role,
        Model|Reference|null $actor = null,
        Model|Reference|null $tenant = null,
        ?string $application = null,
    ): int {
        return $this->revoke(GrantTarget::ROLE, $grantee, $role, $actor, $tenant, $application);
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
     * @param  bool  $includeSubtree
     * @param  string|null  $application
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
        bool $includeSubtree = true,
        ?string $application = null,
    ): SyncResult {
        return $this->sync(GrantTarget::ROLE, $grantee, $roles, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
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
     * @param  bool  $includeSubtree
     * @param  string|null  $application
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
        bool $includeSubtree = true,
        ?string $application = null,
    ): GrantOutcome {
        return $this->grant(GrantTarget::PERMISSION, $grantee, $permission, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
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
     * @param  string|null  $application
     * @return int
     *
     * @throws \Throwable
     */
    public function revokePermission(
        Model|Reference $grantee,
        Permission|string $permission,
        Model|Reference|null $actor = null,
        Model|Reference|null $tenant = null,
        ?string $application = null,
    ): int {
        return $this->revoke(GrantTarget::PERMISSION, $grantee, $permission, $actor, $tenant, $application);
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
     * @param  bool  $includeSubtree
     * @param  string|null  $application
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
        bool $includeSubtree = true,
        ?string $application = null,
    ): SyncResult {
        return $this->sync(GrantTarget::PERMISSION, $grantee, $permissions, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
    }

    /**
     * Attach a policy to the grantee, an identity or a role, until the given
     * expiry or forever. An inline policy is attached only to the grantee it
     * belongs to.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
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
        bool $includeSubtree = true,
        ?string $application = null,
    ): GrantOutcome {
        return $this->grant(GrantTarget::POLICY, $grantee, $policy, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
    }

    /**
     * Detach a policy from the grantee, and return how many were detached: none
     * when it was not attached.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @return int
     *
     * @throws \Throwable
     */
    public function detachPolicy(
        Model|Reference $grantee,
        Policy $policy,
        Model|Reference|null $actor = null,
        Model|Reference|null $tenant = null,
        ?string $application = null,
    ): int {
        return $this->revoke(GrantTarget::POLICY, $grantee, $policy, $actor, $tenant, $application);
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
     * @param  bool  $includeSubtree
     * @param  string|null  $application
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
        bool $includeSubtree = true,
        ?string $application = null,
    ): SyncResult {
        return $this->sync(GrantTarget::POLICY, $grantee, $policies, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
    }

    /**
     * Revoke every role, permission and policy the grantee holds, in one
     * transaction and as one operation, dispatching a revoked or detached event
     * for each. The `HasAuthorization` trait calls this once a grantee is
     * deleted, `RoleObserver` once a role is deleted, and the grant pruner for
     * a grantee that no longer exists.
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
            $events = [];

            foreach (GrantTarget::cases() as $kind) {
                $events = [...$events, ...self::revokeEverywhere($kind, $reference, $operation)];
            }

            OperationScope::dispatch(...$events);

            return \count($events);
        });

        foreach (GrantTarget::cases() as $kind) {
            self::forgetRelation($kind, $grantee);
        }

        return $revoked;
    }

    /**
     * Revoke every row of the given kind the grantee holds, in every scope, and
     * return a revoked or detached event for each, in its scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return list<\SineMacula\Laravel\Authorization\Contracts\IdentityEvent>
     */
    private static function revokeEverywhere(GrantTarget $kind, Reference $grantee, Operation $operation): array
    {
        $table  = self::table($kind, $grantee, $operation, GrantScope::platform());
        $grants = $table->grantsInEveryScope();
        $models = [];
        $events = [];

        foreach ($kind->find(\array_column($grants, 0)) as $model) {
            $models[self::key($model)] = $model;
        }

        $table->revokeInEveryScope();

        foreach ($grants as [$id, $scope]) {
            $events[] = $kind->revokedEvent($operation, $grantee, $models[$id], $scope);
        }

        return $events;
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
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
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
        GrantScope $named,
    ): GrantOutcome {
        $reference = self::grantee($grantee);
        $operation = Operation::begin($actor);

        /** @var \SineMacula\Laravel\Authorization\Enums\GrantOutcome $outcome */
        $outcome = OperationScope::run($operation, static function (Operation $operation) use ($kind, $grantee, $reference, $named, $target, $expiresAt): GrantOutcome {
            $model = $kind->resolve($target, self::guard($grantee), $named->tenant);
            $scope = self::scope(GrantScopes::of($kind, $model, $named->tenant), $named->includeSubtree, $named->application);

            RoleParity::assertGrantable($kind->value, $model, self::guard($grantee));
            InlinePolicies::assertAttachable($model, $reference);

            $change = self::table($kind, $reference, $operation, $scope)->grant(self::key($model), $expiresAt);

            OperationScope::dispatch(...$kind->changeEvents($operation, $reference, $model, $scope, $change, $expiresAt));

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
     * @param  string|null  $application
     * @return int
     *
     * @throws \Throwable
     */
    private function revoke(GrantTarget $kind, Model|Reference $grantee, mixed $target, Model|Reference|null $actor, Model|Reference|null $tenant, ?string $application): int
    {
        $reference = self::grantee($grantee);
        $named     = GrantScopes::named($tenant);
        $operation = Operation::begin($actor);

        $revoked = OperationScope::run($operation, static function (Operation $operation) use ($kind, $grantee, $reference, $named, $target, $application): int {
            $candidates = \is_string($target) ? $kind->named($target, self::guard($grantee), $named) : [$kind->assertTarget($target)];
            $events     = [];

            foreach ($candidates as $model) {
                $scope = GrantScopes::of($kind, $model, $named);
                $table = self::table($kind, $reference, $operation, new GrantScope($scope, $application));
                $key   = self::key($model);
                $reach = $table->reaches([$key]);

                if ($reach === []) {
                    continue;
                }

                $table->revoke([$key]);

                $events[] = $kind->revokedEvent($operation, $reference, $model, new GrantScope($scope, $application, $reach[$key]));
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
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
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
        GrantScope $named,
    ): SyncResult {
        $reference = self::grantee($grantee);
        $operation = Operation::begin($actor);

        /** @var \SineMacula\Laravel\Authorization\Services\SyncResult $result */
        $result = OperationScope::run($operation, static function (Operation $operation) use ($kind, $grantee, $reference, $named, $targets, $expiresAt): SyncResult {
            $scope   = $named->tenant ?? GrantScopes::commonOwner($kind, self::guard($grantee), $targets);
            $written = self::scope($scope, $named->includeSubtree, $named->application);
            $table   = self::table($kind, $reference, $operation, $written);
            $held    = $table->held();
            $keep    = self::toKeep($kind, $grantee, $targets, $held, $scope);
            $revoked = \array_values(\array_diff($held, \array_map(self::key(...), $keep)));
            $changed = [];
            $events  = [];

            $reaches = $table->reaches($revoked);

            $table->revoke($revoked);

            foreach ($keep as $model) {
                $id     = self::key($model);
                $change = $table->rearm($id, $expiresAt);
                $events = [...$events, ...$kind->changeEvents($operation, $reference, $model, $written, $change, $expiresAt)];

                $changed[$change->outcome->value][] = $id;
            }

            foreach ($kind->find($revoked) as $model) {
                $events[] = $kind->revokedEvent($operation, $reference, $model, new GrantScope($scope, $named->application, $reaches[self::key($model)]));
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
     * grantable in the sync's scope, and to the grantee.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  list<string>  $held
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $scope
     * @return array<string, \Illuminate\Database\Eloquent\Model>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     */
    private static function toKeep(GrantTarget $kind, Model|Reference $grantee, array $targets, array $held, ?Reference $scope): array
    {
        $keep = [];

        foreach ($targets as $target) {
            $models = \is_string($target) ? $kind->heldOrFirst($target, self::guard($grantee), $held, $scope) : [$kind->assertTarget($target)];

            foreach ($models as $model) {
                GrantScopes::assertGrantableIn($kind, $model, $scope);
                RoleParity::assertGrantable($kind->value, $model, self::guard($grantee));
                InlinePolicies::assertAttachable($model, Reference::of($grantee));

                $keep[self::key($model)] = $model;
            }
        }

        return $keep;
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
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantTable
     */
    private static function table(GrantTarget $kind, Reference $grantee, Operation $operation, GrantScope $scope): GrantTable
    {
        return new GrantTable(
            AuthorizationConnection::connection(),
            $kind->table(),
            $kind->column(),
            $grantee->type,
            $grantee->id,
            $operation->actor,
            $scope->tenant,
            $scope->includeSubtree,
            $scope->application,
        );
    }

    /**
     * Return the scope a call names: the tenant it names (a model taken as its
     * reference), whether a grant reaches the tenants below it, and the
     * application, each before the target's owner settles the tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    private static function named(Model|Reference|null $tenant, bool $includeSubtree, ?string $application): GrantScope
    {
        return new GrantScope(GrantScopes::named($tenant), $application, $includeSubtree);
    }

    /**
     * Return the scope a grant is written in: its tenant, whether it also holds
     * in the tenants below it, and its application. A platform-wide grant
     * counts in every tenant, so it always reaches below.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    private static function scope(?Reference $tenant, bool $includeSubtree, ?string $application): GrantScope
    {
        return new GrantScope($tenant, $application, $includeSubtree || $tenant === null);
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
