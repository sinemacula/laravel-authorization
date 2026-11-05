<?php

declare(strict_types = 1);

use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;

return [

    /*
    |---------------------------------------------------------------------------
    | Models
    |---------------------------------------------------------------------------
    |
    | Eloquent classes that back the three first-class authorization entities.
    | Consumers may point any of these at their own subclass — the package
    | resolves models through config to avoid hard class references anywhere
    | in the engine. Each class must be the shipped model or a subclass of it;
    | any other value is refused when the application boots.
    |
    */

    'models' => [
        'role'       => Role::class,
        'permission' => Permission::class,
        'policy'     => Policy::class,
    ],

    /*
    |---------------------------------------------------------------------------
    | Database connection
    |---------------------------------------------------------------------------
    |
    | The connection the package's tables live on. Every package model and
    | pivot reads and writes on it, the shipped migrations create and drop
    | their tables on it, and the package's own transactions run on it. Point
    | it at the connection the application keeps its identity tables on, so
    | a transaction that creates a principal and its grants commits or rolls
    | back as one. Null uses the application's default connection.
    |
    */

    'connection' => env('AUTHORIZATION_DB_CONNECTION'),

    /*
    |---------------------------------------------------------------------------
    | Tables
    |---------------------------------------------------------------------------
    |
    | Physical table names used by the shipped migrations and Eloquent models.
    | Override here if you need to sidestep naming collisions with existing
    | application tables. The tables' column names are fixed.
    |
    */

    'tables' => [
        'roles'                    => env('AUTHORIZATION_TABLE_ROLES', 'roles'),
        'permissions'              => env('AUTHORIZATION_TABLE_PERMISSIONS', 'permissions'),
        'policies'                 => env('AUTHORIZATION_TABLE_POLICIES', 'policies'),
        'role_permissions'         => env('AUTHORIZATION_TABLE_ROLE_PERMISSIONS', 'role_permissions'),
        'authorizable_roles'       => env('AUTHORIZATION_TABLE_AUTHORIZABLE_ROLES', 'authorizable_roles'),
        'authorizable_permissions' => env('AUTHORIZATION_TABLE_AUTHORIZABLE_PERMISSIONS', 'authorizable_permissions'),
        'authorizable_policies'    => env('AUTHORIZATION_TABLE_AUTHORIZABLE_POLICIES', 'authorizable_policies'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Defaults
    |---------------------------------------------------------------------------
    |
    | The guard a role or permission lookup by name uses when the caller names
    | none, and the auth guard `AuthGuardPrincipalResolver` reads by default.
    | Rows record their own guard in the `guard` column; a null guard makes a
    | row apply to every guard.
    |
    */

    'defaults' => [
        'guard' => env('AUTHORIZATION_DEFAULT_GUARD', 'web'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Permission enums
    |---------------------------------------------------------------------------
    |
    | String-backed enums implementing `PermissionEnum`; each case's value is
    | the permission name, and an enum backed by integers is refused at boot.
    | Every case is wired into a Laravel Gate on boot, so a permission defined
    | here is immediately callable via `Gate::allows(...)`, `$user->can(...)`,
    | `@can(...)`, and the `can:` route middleware.
    |
    | **Required for Laravel's Gate surface.** The `Authorization` facade
    | (`Authorization::can(...)`, `Authorization::for($user)->can(...)`) works
    | out of the box, but Laravel's Gate never dispatches to an action it has
    | not been told about — `Gate::allows('posts:edit')` silently returns false
    | until a `PermissionEnum` case is listed here. Consumers who want the
    | standard Laravel authorization surface must register at least one enum;
    | consumers who only use the facade can leave this empty.
    |
    */

    'permission_enums' => [],

    /*
    |---------------------------------------------------------------------------
    | Permission providers
    |---------------------------------------------------------------------------
    |
    | Class-strings implementing `PermissionProvider`. Each provider contributes
    | a list of permission strings and a guard scope, so modular packages can
    | ship their own permission sets without the host application editing a
    | central enum. The classes are validated at boot, but a provider is never
    | read there: booting writes nothing to the database.
    |
    */

    'permission_providers' => [],

    /*
    |---------------------------------------------------------------------------
    | Gate conflict policy
    |---------------------------------------------------------------------------
    |
    | Decides what happens when auto-wiring a permission that already has a
    | Gate of the same name. The opinionated enterprise default is `throw` —
    | a duplicate Gate registration is almost always a bug, and failing boot
    | is catchable and loud. `log` preserves the existing Gate and emits a
    | warning (opt-in for consumers with deliberate collision patterns);
    | `overwrite` silently replaces it.
    |
    */

    'gate' => [
        'on_conflict' => env('AUTHORIZATION_GATE_ON_CONFLICT', 'throw'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Log channel
    |---------------------------------------------------------------------------
    |
    | The log channel the package writes its warnings and debug lines to: a
    | Gate conflict under `log`, a discarded corrupt cache entry, a policy
    | whose document cannot be read. Leave as null to use the application's
    | default channel. A name that is not a channel in `logging.channels` falls
    | back to the default channel.
    |
    */

    'log_channel' => env('AUTHORIZATION_LOG_CHANNEL'),

    /*
    |---------------------------------------------------------------------------
    | Policy store
    |---------------------------------------------------------------------------
    |
    | Optional class implementing `PolicyStore`. When set, the manager loads
    | additional policies for the current principal from this source on every
    | check. Leave as null to rely solely on policies attached to identities.
    |
    */

    'policy_store' => null,

    /*
    |---------------------------------------------------------------------------
    | Principal resolver
    |---------------------------------------------------------------------------
    |
    | Bridges the engine to whatever concept of "current principal" the
    | application uses. The shipped default returns null, making the package
    | anonymous-safe and zero-dependency. The `sinemacula/laravel-iam`
    | umbrella binds a resolver that delegates to `sinemacula/laravel-authentication`.
    |
    */

    'principal_resolver' => NullPrincipalResolver::class,

    /*
    |---------------------------------------------------------------------------
    | Tenant resolver
    |---------------------------------------------------------------------------
    |
    | Bridges the engine to whatever concept of "current tenant" the
    | application uses. The shipped default (and null) resolves no tenant,
    | under which only platform-wide roles and permissions are visible:
    | tenant-owned rows never show without their tenant. Applications wire
    | their own resolver through this key or by binding the contract
    | directly. The resolver and the tenant it returns are bound per
    | request or job, so queue workers and Octane resolve them afresh.
    |
    */

    'tenant_resolver' => NullTenantResolver::class,

    /*
    |---------------------------------------------------------------------------
    | Resolution cache
    |---------------------------------------------------------------------------
    |
    | Two-tier cache for principal roles, permissions, and policies. The
    | in-memory tier is always on and memoises results per request or job.
    | The optional persistent tier kicks in when `store` is set to one of
    | the configured cache connections — results are written there with
    | the supplied TTL (0 = forever) under a namespaced key prefix, and the
    | shipped `InvalidateResolutionCache` listener drops entries when the
    | package's events fire. Entries in both tiers live no longer than the
    | TTL and the nearest grant expiry.
    |
    */

    'cache' => [
        'store'  => env('AUTHORIZATION_CACHE_STORE'),
        'ttl'    => (int) env('AUTHORIZATION_CACHE_TTL_SECONDS', 0),
        'prefix' => env('AUTHORIZATION_CACHE_PREFIX', 'authorization'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Role hierarchy
    |---------------------------------------------------------------------------
    |
    | Controls whether the role parent-child hierarchy affects permission
    | resolution. When enabled (the default), a role's `getPermissions()`
    | returns the deduplicated union of its own direct permissions and all
    | permissions inherited from ancestor roles. When disabled, only directly
    | attached permissions are returned — `parent_id` can still be set for
    | organisational grouping but has no effect on authorization decisions.
    |
    */

    'hierarchy' => [
        'enabled' => (bool) env('AUTHORIZATION_HIERARCHY_ENABLED', true),
    ],

    /*
    |---------------------------------------------------------------------------
    | Role rank / seniority
    |---------------------------------------------------------------------------
    |
    | Controls whether rank-based seniority checks are active. When enabled
    | (the default), `canActOn()` on an authorizable identity compares the
    | actor's highest-ranked role (lowest numeric `rank` value) against the
    | target's. When disabled, `canActOn()` always returns true — consumers
    | who do not need rank-based authority can skip the feature entirely.
    |
    | Roles with a null `rank` are unranked and exempt from rank checks
    | regardless of this toggle.
    |
    */

    'rank' => [
        'enabled' => (bool) env('AUTHORIZATION_RANK_ENABLED', true),
    ],
];
