<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\GrantChange;
use SineMacula\Laravel\Authorization\Services\Support\GrantTable;
use SineMacula\Laravel\Authorization\Support\GranteeReference;

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
 * dispatched once the transaction has returned, and only for a write that
 * changed something. A changed expiry dispatches the granted event as well as
 * the expiry-changed one, so the resolution cache listening for the former is
 * cleared.
 *
 * Each method takes the acting subject as `$actor`: null for console and system
 * work. A role or permission name that answers no row throws
 * `UnknownRoleException` or `UnknownPermissionException`; a target that is not
 * a saved model of the kind granted, such as a policy sync handed another
 * model, throws `InvalidGrantTargetException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @SuppressWarnings("php:S1172")
 */
final class GrantService
{
    use HasContainerInstance;

    /**
     * Grant a role to the grantee, until the given expiry or forever.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantRole(GranteeReference|Model $grantee, Role|string $role, ?\DateTimeInterface $expiresAt = null, ?object $actor = null): GrantOutcome
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
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  object|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function revokeRole(GranteeReference|Model $grantee, Role|string $role, ?object $actor = null): int
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
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncRoles(GranteeReference|Model $grantee, array $roles, ?\DateTimeInterface $expiresAt = null, ?object $actor = null): SyncResult
    {
        return $this->sync(GrantTarget::ROLE, $grantee, $roles, $expiresAt, $actor);
    }

    /**
     * Grant a permission directly to the grantee, until the given expiry or
     * forever.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantPermission(GranteeReference|Model $grantee, Permission|string $permission, ?\DateTimeInterface $expiresAt = null, ?object $actor = null): GrantOutcome
    {
        return $this->grant(GrantTarget::PERMISSION, $grantee, $permission, $expiresAt, $actor);
    }

    /**
     * Revoke a direct permission from the grantee, and return how many
     * permissions were revoked: none when the grantee held none.
     *
     * A name revokes every held permission of that name under the grantee's
     * guard, or guard-agnostic, whichever tenant or the platform owns it.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  object|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function revokePermission(GranteeReference|Model $grantee, Permission|string $permission, ?object $actor = null): int
    {
        return $this->revoke(GrantTarget::PERMISSION, $grantee, $permission, $actor);
    }

    /**
     * Replace the grantee's direct permissions with the given ones, as
     * `syncRoles()` replaces its roles.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPermissions(GranteeReference|Model $grantee, array $permissions, ?\DateTimeInterface $expiresAt = null, ?object $actor = null): SyncResult
    {
        return $this->sync(GrantTarget::PERMISSION, $grantee, $permissions, $expiresAt, $actor);
    }

    /**
     * Attach a policy to the grantee, until the given expiry or forever.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function attachPolicy(GranteeReference|Model $grantee, Policy $policy, ?\DateTimeInterface $expiresAt = null, ?object $actor = null): GrantOutcome
    {
        return $this->grant(GrantTarget::POLICY, $grantee, $policy, $expiresAt, $actor);
    }

    /**
     * Detach a policy from the grantee, and return how many were detached: none
     * when it was not attached.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  object|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function detachPolicy(GranteeReference|Model $grantee, Policy $policy, ?object $actor = null): int
    {
        return $this->revoke(GrantTarget::POLICY, $grantee, $policy, $actor);
    }

    /**
     * Replace the grantee's attached policies with the given ones, as
     * `syncRoles()` replaces its roles. Each entry must be a saved policy.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPolicies(GranteeReference|Model $grantee, array $policies, ?\DateTimeInterface $expiresAt = null, ?object $actor = null): SyncResult
    {
        return $this->sync(GrantTarget::POLICY, $grantee, $policies, $expiresAt, $actor);
    }

    /**
     * Grant one row of the given kind in one transaction.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  mixed  $target
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    private function grant(GrantTarget $kind, GranteeReference|Model $grantee, mixed $target, ?\DateTimeInterface $expiresAt, ?object $actor): GrantOutcome
    {
        $events = [];

        /** @var \SineMacula\Laravel\Authorization\Enums\GrantOutcome $outcome */
        $outcome = AuthorizationConnection::connection()->transaction(static function () use ($kind, $grantee, $target, $expiresAt, &$events): GrantOutcome {
            $model  = $kind->resolve($target, self::guard($grantee));
            $change = self::table($kind, $grantee)->grant(self::key($model), $expiresAt);
            $events = self::grantEvents($kind, $grantee, $model, $change, $expiresAt);

            return $change->outcome;
        });

        self::finish($kind, $grantee, $events, $actor);

        return $outcome;
    }

    /**
     * Revoke one row of the given kind, or every held row of a name, in one
     * transaction.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  mixed  $target
     * @param  object|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    private function revoke(GrantTarget $kind, GranteeReference|Model $grantee, mixed $target, ?object $actor): int
    {
        /** @var list<\Illuminate\Database\Eloquent\Model> $revoked */
        $revoked = AuthorizationConnection::connection()->transaction(static function () use ($kind, $grantee, $target): array {
            $candidates = \is_string($target) ? $kind->named($target, self::guard($grantee)) : [$kind->assertTarget($target)];
            $table      = self::table($kind, $grantee);
            $held       = $table->held(\array_map(self::key(...), $candidates));

            $table->revoke($held);

            return \array_values(\array_filter($candidates, static fn (Model $model): bool => \in_array(self::key($model), $held, true)));
        });

        self::finish($kind, $grantee, \array_map(static fn (Model $model): object => $kind->revokedEvent($grantee, $model), $revoked), $actor);

        return \count($revoked);
    }

    /**
     * Replace the grantee's rows of the given kind in one transaction.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    private function sync(GrantTarget $kind, GranteeReference|Model $grantee, array $targets, ?\DateTimeInterface $expiresAt, ?object $actor): SyncResult
    {
        $events = [];

        /** @var \SineMacula\Laravel\Authorization\Services\SyncResult $result */
        $result = AuthorizationConnection::connection()->transaction(static function () use ($kind, $grantee, $targets, $expiresAt, &$events): SyncResult {
            $table   = self::table($kind, $grantee);
            $held    = $table->held();
            $keep    = self::toKeep($kind, $grantee, $targets, $held);
            $revoked = \array_values(\array_diff($held, \array_map(self::key(...), $keep)));

            $table->revoke($revoked);

            $changed = [];

            foreach ($keep as $model) {
                $id     = self::key($model);
                $change = $table->rearm($id, $expiresAt);
                $events = [...$events, ...self::grantEvents($kind, $grantee, $model, $change, $expiresAt)];

                $changed[$change->outcome->value][] = $id;
            }

            foreach ($kind->find($revoked) as $model) {
                $events[] = $kind->revokedEvent($grantee, $model);
            }

            return new SyncResult($changed[GrantOutcome::GRANTED->value] ?? [], $changed[GrantOutcome::REARMED->value] ?? [], $revoked);
        });

        self::finish($kind, $grantee, $events, $actor);

        return $result;
    }

    /**
     * Return the rows a sync keeps, by key: a model as given; for a name, every
     * held row of that name, else the one the lookup ranks first.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  list<string>  $held
     * @return array<string, \Illuminate\Database\Eloquent\Model>
     */
    private static function toKeep(GrantTarget $kind, GranteeReference|Model $grantee, array $targets, array $held): array
    {
        $keep = [];

        foreach ($targets as $target) {
            $models = \is_string($target) ? self::heldOrFirst($kind->named($target, self::guard($grantee)), $held) : [$kind->assertTarget($target)];

            foreach ($models as $model) {
                $keep[self::key($model)] = $model;
            }
        }

        return $keep;
    }

    /**
     * Return the named rows the grantee holds, else the first.
     *
     * @param  non-empty-list<\Illuminate\Database\Eloquent\Model>  $named
     * @param  list<string>  $held
     * @return list<\Illuminate\Database\Eloquent\Model>
     */
    private static function heldOrFirst(array $named, array $held): array
    {
        $kept = \array_values(\array_filter($named, static fn (Model $model): bool => \in_array(self::key($model), $held, true)));

        return $kept !== [] ? $kept : [$named[0]];
    }

    /**
     * Return the events one grant row write dispatches: none when nothing
     * changed, the granted event for a new grant, and the granted and
     * expiry-changed events for a re-armed grant or a changed expiry.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \SineMacula\Laravel\Authorization\Services\Support\GrantChange  $change
     * @param  \DateTimeInterface|null  $expiresAt
     * @return list<object>
     */
    private static function grantEvents(GrantTarget $kind, GranteeReference|Model $grantee, Model $model, GrantChange $change, ?\DateTimeInterface $expiresAt): array
    {
        return match ($change->outcome) {
            GrantOutcome::UNCHANGED => [],
            GrantOutcome::GRANTED   => [$kind->grantedEvent($grantee, $model)],
            default                 => [
                $kind->grantedEvent($grantee, $model),
                $kind->expiryChangedEvent($grantee, $model, $change->previousExpiresAt, $expiresAt),
            ],
        };
    }

    /**
     * Clear the grantee's loaded relation and dispatch the call's events, once
     * its transaction has returned. The actor is the acting subject the call
     * was made for; the events do not carry it yet.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @param  list<object>  $events
     * @param  object|null  $actor
     * @return void
     */
    private static function finish(GrantTarget $kind, GranteeReference|Model $grantee, array $events, ?object $actor): void
    {
        if ($grantee instanceof Model) {
            $grantee->unsetRelation($kind->relation());
        }

        foreach ($events as $event) {
            Event::dispatch($event);
        }
    }

    /**
     * Return the grant table writer for the grantee's rows of the given kind.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantTable
     */
    private static function table(GrantTarget $kind, GranteeReference|Model $grantee): GrantTable
    {
        return new GrantTable(
            AuthorizationConnection::connection(),
            $kind->table(),
            $kind->column(),
            $grantee->getMorphClass(),
            $grantee instanceof Model ? self::key($grantee) : $grantee->getKey(),
        );
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
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference  $grantee
     * @return string|null
     */
    private static function guard(GranteeReference|Model $grantee): ?string
    {
        $reflection = new \ReflectionObject($grantee);

        if (!$reflection->hasMethod('getAuthorizationGuard')) {
            return null;
        }

        $guard = $reflection->getMethod('getAuthorizationGuard')->invoke($grantee);

        return \is_string($guard) ? $guard : null;
    }
}
