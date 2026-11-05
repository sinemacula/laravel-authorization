<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\GrantChange;
use SineMacula\Laravel\Authorization\Services\Support\GrantTable;
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
 * Grants are platform-wide, for every application. Nothing reads a grant's
 * tenant or application yet, so the service takes neither, and never writes a
 * scoped grant a check would read as platform-wide.
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
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantRole(Model|Reference $grantee, Role|string $role, ?\DateTimeInterface $expiresAt = null, Model|Reference|null $actor = null): GrantOutcome
    {
        return $this->grant(GrantTarget::ROLE, $grantee, $role, $expiresAt, $actor);
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
     * @return int
     *
     * @throws \Throwable
     */
    public function revokeRole(Model|Reference $grantee, Role|string $role, Model|Reference|null $actor = null): int
    {
        return $this->revoke(GrantTarget::ROLE, $grantee, $role, $actor);
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
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncRoles(Model|Reference $grantee, array $roles, ?\DateTimeInterface $expiresAt = null, Model|Reference|null $actor = null): SyncResult
    {
        return $this->sync(GrantTarget::ROLE, $grantee, $roles, $expiresAt, $actor);
    }

    /**
     * Grant a permission directly to the grantee, until the given expiry or
     * forever.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantPermission(
        Model|Reference $grantee,
        Permission|string $permission,
        ?\DateTimeInterface $expiresAt = null,
        Model|Reference|null $actor = null,
    ): GrantOutcome {
        return $this->grant(GrantTarget::PERMISSION, $grantee, $permission, $expiresAt, $actor);
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
     * @return int
     *
     * @throws \Throwable
     */
    public function revokePermission(Model|Reference $grantee, Permission|string $permission, Model|Reference|null $actor = null): int
    {
        return $this->revoke(GrantTarget::PERMISSION, $grantee, $permission, $actor);
    }

    /**
     * Replace the grantee's direct permissions with the given ones, as
     * `syncRoles()` replaces its roles.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPermissions(Model|Reference $grantee, array $permissions, ?\DateTimeInterface $expiresAt = null, Model|Reference|null $actor = null): SyncResult
    {
        return $this->sync(GrantTarget::PERMISSION, $grantee, $permissions, $expiresAt, $actor);
    }

    /**
     * Attach a policy to the grantee, until the given expiry or forever.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function attachPolicy(Model|Reference $grantee, Policy $policy, ?\DateTimeInterface $expiresAt = null, Model|Reference|null $actor = null): GrantOutcome
    {
        return $this->grant(GrantTarget::POLICY, $grantee, $policy, $expiresAt, $actor);
    }

    /**
     * Detach a policy from the grantee, and return how many were detached: none
     * when it was not attached.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function detachPolicy(Model|Reference $grantee, Policy $policy, Model|Reference|null $actor = null): int
    {
        return $this->revoke(GrantTarget::POLICY, $grantee, $policy, $actor);
    }

    /**
     * Replace the grantee's attached policies with the given ones, as
     * `syncRoles()` replaces its roles. Each entry must be a saved policy.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPolicies(Model|Reference $grantee, array $policies, ?\DateTimeInterface $expiresAt = null, Model|Reference|null $actor = null): SyncResult
    {
        return $this->sync(GrantTarget::POLICY, $grantee, $policies, $expiresAt, $actor);
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
                $table = self::table($kind, $reference, $operation);
                $held  = $table->held();

                $table->revoke($held);

                foreach ($kind->find($held) as $model) {
                    $events[] = $kind->revokedEvent($operation, $reference, $model);
                }

                $count += \count($held);
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
     * Grant one row of the given kind in one transaction.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  mixed  $target
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    private function grant(GrantTarget $kind, Model|Reference $grantee, mixed $target, ?\DateTimeInterface $expiresAt, Model|Reference|null $actor): GrantOutcome
    {
        $reference = self::grantee($grantee);
        $operation = Operation::begin($actor);
        $table     = self::table($kind, $reference, $operation);

        /** @var \SineMacula\Laravel\Authorization\Enums\GrantOutcome $outcome */
        $outcome = OperationScope::run($operation, static function (Operation $operation) use ($kind, $grantee, $reference, $table, $target, $expiresAt): GrantOutcome {
            $model  = $kind->resolve($target, self::guard($grantee));
            $change = $table->grant(self::key($model), $expiresAt);

            OperationScope::dispatch(...self::grantEvents($operation, $kind, $reference, $model, $change, $expiresAt));

            return $change->outcome;
        });

        self::forgetRelation($kind, $grantee);

        return $outcome;
    }

    /**
     * Revoke one row of the given kind, or every held row of a name, in one
     * transaction.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  mixed  $target
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    private function revoke(GrantTarget $kind, Model|Reference $grantee, mixed $target, Model|Reference|null $actor): int
    {
        $reference = self::grantee($grantee);
        $operation = Operation::begin($actor);
        $table     = self::table($kind, $reference, $operation);

        $revoked = OperationScope::run($operation, static function (Operation $operation) use ($kind, $grantee, $reference, $table, $target): int {
            $candidates = \is_string($target) ? $kind->named($target, self::guard($grantee)) : [$kind->assertTarget($target)];
            $held       = $table->held(\array_map(self::key(...), $candidates));
            $revoked    = \array_filter($candidates, static fn (Model $model): bool => \in_array(self::key($model), $held, true));

            $table->revoke($held);

            OperationScope::dispatch(...\array_map(static fn (Model $model): IdentityEvent => $kind->revokedEvent($operation, $reference, $model), $revoked));

            return \count($revoked);
        });

        self::forgetRelation($kind, $grantee);

        return $revoked;
    }

    /**
     * Replace the grantee's rows of the given kind in one transaction.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    private function sync(GrantTarget $kind, Model|Reference $grantee, array $targets, ?\DateTimeInterface $expiresAt, Model|Reference|null $actor): SyncResult
    {
        $reference = self::grantee($grantee);
        $operation = Operation::begin($actor);
        $table     = self::table($kind, $reference, $operation);

        /** @var \SineMacula\Laravel\Authorization\Services\SyncResult $result */
        $result = OperationScope::run($operation, static function (Operation $operation) use ($kind, $grantee, $reference, $table, $targets, $expiresAt): SyncResult {
            $held    = $table->held();
            $keep    = self::toKeep($kind, $grantee, $targets, $held);
            $revoked = \array_values(\array_diff($held, \array_map(self::key(...), $keep)));
            $changed = [];
            $events  = [];

            $table->revoke($revoked);

            foreach ($keep as $model) {
                $id     = self::key($model);
                $change = $table->rearm($id, $expiresAt);
                $events = [...$events, ...self::grantEvents($operation, $kind, $reference, $model, $change, $expiresAt)];

                $changed[$change->outcome->value][] = $id;
            }

            foreach ($kind->find($revoked) as $model) {
                $events[] = $kind->revokedEvent($operation, $reference, $model);
            }

            OperationScope::dispatch(...$events);

            return new SyncResult($changed[GrantOutcome::GRANTED->value] ?? [], $changed[GrantOutcome::REARMED->value] ?? [], $revoked);
        });

        self::forgetRelation($kind, $grantee);

        return $result;
    }

    /**
     * Return the rows a sync keeps, by key: a model as given; for a name, every
     * held row of that name, else the one the lookup ranks first.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  list<string>  $held
     * @return array<string, \Illuminate\Database\Eloquent\Model>
     */
    private static function toKeep(GrantTarget $kind, Model|Reference $grantee, array $targets, array $held): array
    {
        $keep = [];

        foreach ($targets as $target) {
            $models = \is_string($target) ? $kind->heldOrFirst($target, self::guard($grantee), $held) : [$kind->assertTarget($target)];

            foreach ($models as $model) {
                $keep[self::key($model)] = $model;
            }
        }

        return $keep;
    }

    /**
     * Return the events one grant row write dispatches: none when nothing
     * changed, the granted event for a new grant, and the granted and
     * expiry-changed events for a re-armed grant or a changed expiry.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \SineMacula\Laravel\Authorization\Services\Support\GrantChange  $change
     * @param  \DateTimeInterface|null  $expiresAt
     * @return list<\SineMacula\Laravel\Authorization\Contracts\IdentityEvent>
     */
    private static function grantEvents(Operation $operation, GrantTarget $kind, Reference $grantee, Model $model, GrantChange $change, ?\DateTimeInterface $expiresAt): array
    {
        return match ($change->outcome) {
            GrantOutcome::UNCHANGED => [],
            GrantOutcome::GRANTED   => [$kind->grantedEvent($operation, $grantee, $model, $expiresAt)],
            default                 => [
                $kind->grantedEvent($operation, $grantee, $model, $expiresAt),
                $kind->expiryChangedEvent($operation, $grantee, $model, $change->previousExpiresAt, $expiresAt),
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
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantTable
     */
    private static function table(GrantTarget $kind, Reference $grantee, Operation $operation): GrantTable
    {
        return new GrantTable(AuthorizationConnection::connection(), $kind->table(), $kind->column(), $grantee->type, $grantee->id, $operation->actor);
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
