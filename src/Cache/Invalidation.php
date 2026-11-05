<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Events\Permission\Deleted as PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\Permission\Updated as PermissionUpdated;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted as PolicyDeleted;
use SineMacula\Laravel\Authorization\Events\Policy\Updated as PolicyUpdated;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpired as RolePermissionExpired;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpiryChanged as RolePermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Which version tokens a write bumps, read from the events it dispatches.
 *
 * - A grantee's grant, revocation or expiry change bumps the grantee.
 * - A change to a role (its permissions or their expiry, its parent, its name,
 *   its owner) or its deletion bumps the role. Entries record every role they
 *   were built from, ancestors included, so the bump reaches every identity
 *   that holds the role or a role below it.
 * - A change to a policy or its deletion bumps the policy.
 * - A deleted permission bumps the roles and grantees that held it, as the
 *   event carries them. A permission renamed or moved to another owner bumps
 *   its holders too, read when the change is made; any other change to a
 *   permission alters no resolution.
 * - A record created alters no resolution until it is granted, which is a write
 *   of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class Invalidation
{
    /** @var list<string> The permission fields whose change alters what its holders resolve to. */
    private const array PERMISSION_FIELDS = ['name', 'tenant_type', 'tenant_id'];

    /**
     * Return the version keys the events bump, each once.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\VersionedStore  $store
     * @param  list<\SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent>  $events
     * @return list<string>
     */
    public static function keys(VersionedStore $store, array $events): array
    {
        $keys = [];

        foreach ($events as $event) {
            $keys = [...$keys, ...self::keysFor($store, $event)];
        }

        return \array_values(\array_unique($keys));
    }

    /**
     * Return the version keys one event bumps.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\VersionedStore  $store
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent  $event
     * @return list<string>
     */
    private static function keysFor(VersionedStore $store, AuthorizationEvent $event): array
    {
        return match (true) {
            $event instanceof IdentityEvent => [$store->granteeKey($event->grantee)], // @phpstan-ignore property.notFound
            $event instanceof RolePermissionGranted,
            $event instanceof RolePermissionRevoked,
            $event instanceof RolePermissionExpiryChanged,
            $event instanceof RolePermissionExpired,
            $event instanceof RoleUpdated,
            $event instanceof RoleDeleted => [$store->roleKey($event->role->id)],
            $event instanceof PolicyUpdated,
            $event instanceof PolicyDeleted     => [$store->policyKey($event->policy->id)],
            $event instanceof PermissionDeleted => self::holderKeys($store, \array_map(static fn (Reference $role): string => $role->id, $event->roles), $event->grantees),
            $event instanceof PermissionUpdated => self::renamedPermissionKeys($store, $event),
            default                             => [],
        };
    }

    /**
     * Return the version keys of a permission's holders when the change renamed
     * it or moved it to another owner, or none otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\VersionedStore  $store
     * @param  \SineMacula\Laravel\Authorization\Events\Permission\Updated  $event
     * @return list<string>
     */
    private static function renamedPermissionKeys(VersionedStore $store, PermissionUpdated $event): array
    {
        if (\array_intersect(\array_keys($event->changes['after']), self::PERMISSION_FIELDS) === []) {
            return [];
        }

        $connection = AuthorizationConnection::connection();

        /** @var string $rolePermissions */
        $rolePermissions = config('authorization.tables.role_permissions', 'role_permissions');

        /** @var string $grants */
        $grants = config('authorization.tables.authorizable_permissions', 'authorizable_permissions');

        /** @var list<string> $roles */
        $roles = $connection->table($rolePermissions)->where('permission_id', $event->permission->id)->pluck('role_id')->all();

        $grantees = $connection->table($grants)
            ->where('permission_id', $event->permission->id)
            ->get(['authorizable_type', 'authorizable_id'])
            ->map(static fn (object $row): Reference => new Reference($row->authorizable_type, $row->authorizable_id)) // @phpstan-ignore argument.type, argument.type
            ->all();

        return self::holderKeys($store, $roles, \array_values($grantees));
    }

    /**
     * Return the version keys of the roles and grantees that hold a permission.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\VersionedStore  $store
     * @param  list<string>  $roles
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @return list<string>
     */
    private static function holderKeys(VersionedStore $store, array $roles, array $grantees): array
    {
        return [
            ...\array_map($store->roleKey(...), $roles),
            ...\array_map($store->granteeKey(...), $grantees),
        ];
    }
}
