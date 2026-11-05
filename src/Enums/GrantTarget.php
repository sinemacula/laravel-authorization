<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The kinds of row a grantee can be granted, each with its configured model,
 * grant table and events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum GrantTarget: string
{
    /** A role granted to a grantee. */
    case ROLE = 'role';

    /** A permission granted directly to a grantee. */
    case PERMISSION = 'permission';

    /** A policy attached to a grantee. */
    case POLICY = 'policy';

    /**
     * Return the grant table, as `authorization.tables` names it.
     *
     * @return string
     */
    public function table(): string
    {
        $default = 'authorizable_' . $this->relation();

        /** @var string */
        return config('authorization.tables.' . $default, $default);
    }

    /**
     * Return the grant table's column that names the granted row.
     *
     * @return string
     */
    public function column(): string
    {
        return $this->value . '_id';
    }

    /**
     * Return the name of the grantee's relation onto the granted rows.
     *
     * @return string
     */
    public function relation(): string
    {
        return match ($this) {
            self::ROLE       => 'roles',
            self::PERMISSION => 'permissions',
            self::POLICY     => 'policies',
        };
    }

    /**
     * Resolve a grant's target: a name to the row the lookup ranks first under
     * the guard, a model to itself once it is known to be of this kind.
     *
     * @param  mixed  $target
     * @param  string|null  $guard
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function resolve(mixed $target, ?string $guard, ?Reference $tenant = null): Model
    {
        return \is_string($target) ? $this->named($target, $guard, $tenant)[0] : $this->assertTarget($target);
    }

    /**
     * Return every row of the configured model that answers the name under the
     * guard (the package default when none is given), in the order the lookup
     * ranks them. A policy is never named.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return non-empty-list<\Illuminate\Database\Eloquent\Model>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function named(string $name, ?string $guard, ?Reference $tenant = null): array
    {
        if ($this === self::POLICY) {
            throw new InvalidGrantTargetException($this->value, $name);
        }

        /** @var string $default */
        $default = config('authorization.defaults.guard', 'web');

        $models = GuardScopedLookup::allForGuard($this->modelClass(), $name, $guard ?? $default, $tenant);

        if ($models === [] && $this === self::PERMISSION) {
            throw new UnknownPermissionException($name);
        }

        if ($models === []) {
            throw new UnknownRoleException($name);
        }

        return $models;
    }

    /**
     * Return the rows that answer the name under the guard and are among the
     * held keys, else the one row the lookup ranks first, so a sync that names
     * a row keeps every held row of the name rather than swapping one for
     * another.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  list<string>  $held
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return non-empty-list<\Illuminate\Database\Eloquent\Model>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function heldOrFirst(string $name, ?string $guard, array $held, ?Reference $tenant = null): array
    {
        $named = $this->named($name, $guard, $tenant);
        $kept  = \array_values(\array_filter($named, static function (Model $model) use ($held): bool {
            /** @var int|string $key */
            $key = $model->getKey();

            return \in_array((string) $key, $held, true);
        }));

        return $kept !== [] ? $kept : [$named[0]];
    }

    /**
     * Return the target when it is a saved model of this kind, and refuse
     * anything else.
     *
     * @param  mixed  $target
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     */
    public function assertTarget(mixed $target): Model
    {
        if (!$target instanceof Model || !$target->exists || !\is_a($target, $this->baseClass())) {
            throw new InvalidGrantTargetException($this->value, $target);
        }

        return $target;
    }

    /**
     * Load the rows of the configured model with the given keys, outside the
     * tenant scope, so a grant of another tenant's row is still reported.
     *
     * @param  list<string>  $ids
     * @return list<\Illuminate\Database\Eloquent\Model>
     */
    public function find(array $ids): array
    {
        /** @var list<\Illuminate\Database\Eloquent\Model> */
        return $this->modelClass()::query()->withoutGlobalScope(TenantScope::class)->whereKey($ids)->get()->all();
    }

    /**
     * Return a reference to every grantee that holds the given row, in any
     * scope and whether or not the grant has expired, read on the package's
     * connection, for the event a delete of the row dispatches.
     *
     * @param  string  $id
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    public function holders(string $id): array
    {
        /** @var list<\stdClass> $rows */
        $rows = AuthorizationConnection::connection()->table($this->table())
            ->where($this->column(), $id)
            ->distinct()
            ->orderBy('authorizable_type')
            ->orderBy('authorizable_id')
            ->get(['authorizable_type', 'authorizable_id'])
            ->all();

        return \array_map(static fn (\stdClass $row): Reference => new Reference(self::text($row->authorizable_type), self::text($row->authorizable_id)), $rows);
    }

    /**
     * Build the event a new or re-armed grant dispatches.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \DateTimeInterface|null  $expiresAt
     * @return \SineMacula\Laravel\Authorization\Contracts\IdentityEvent
     */
    public function grantedEvent(Operation $operation, Reference $grantee, Model $target, GrantScope $scope, ?\DateTimeInterface $expiresAt): IdentityEvent
    {
        $event = match ($this) {
            self::ROLE       => RoleAssigned::class,
            self::PERMISSION => PermissionGranted::class,
            self::POLICY     => PolicyAttached::class,
        };

        return new $event($operation, $grantee, Reference::of($target), self::text($target->getAttribute('name')), $scope, self::immutable($expiresAt));
    }

    /**
     * Build the event a revocation dispatches.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return \SineMacula\Laravel\Authorization\Contracts\IdentityEvent
     */
    public function revokedEvent(Operation $operation, Reference $grantee, Model $target, GrantScope $scope): IdentityEvent
    {
        $event = match ($this) {
            self::ROLE       => RoleRevoked::class,
            self::PERMISSION => PermissionRevoked::class,
            self::POLICY     => PolicyDetached::class,
        };

        return new $event($operation, $grantee, Reference::of($target), self::text($target->getAttribute('name')), $scope);
    }

    /**
     * Build the event a change of a held grant's expiry dispatches.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \DateTimeInterface|null  $previous
     * @param  \DateTimeInterface|null  $next
     * @return \SineMacula\Laravel\Authorization\Contracts\IdentityEvent
     */
    public function expiryChangedEvent(
        Operation $operation,
        Reference $grantee,
        Model $target,
        GrantScope $scope,
        ?\DateTimeInterface $previous,
        ?\DateTimeInterface $next,
    ): IdentityEvent {
        $event = match ($this) {
            self::ROLE       => RoleExpiryChanged::class,
            self::PERMISSION => PermissionExpiryChanged::class,
            self::POLICY     => PolicyExpiryChanged::class,
        };

        return new $event(
            $operation,
            $grantee,
            Reference::of($target),
            self::text($target->getAttribute('name')),
            $scope,
            self::immutable($previous),
            self::immutable($next),
        );
    }

    /**
     * Return a value read from a row as a string: a scalar as itself, anything
     * else as empty.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function text(mixed $value): string
    {
        return \is_scalar($value) ? (string) $value : '';
    }

    /**
     * Return an expiry as an immutable instant in UTC.
     *
     * @param  \DateTimeInterface|null  $expiresAt
     * @return \DateTimeImmutable|null
     */
    private static function immutable(?\DateTimeInterface $expiresAt): ?\DateTimeImmutable
    {
        return UtcDateTime::toUtc($expiresAt)?->toImmutable();
    }

    /**
     * Return the model class `authorization.models` configures for this kind.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model>
     */
    private function modelClass(): string
    {
        /** @var class-string<\Illuminate\Database\Eloquent\Model> */
        return config('authorization.models.' . $this->value, $this->baseClass());
    }

    /**
     * Return the package's model for this kind, which every configured model
     * extends.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model>
     */
    private function baseClass(): string
    {
        return match ($this) {
            self::ROLE       => Role::class,
            self::PERMISSION => Permission::class,
            self::POLICY     => Policy::class,
        };
    }
}
