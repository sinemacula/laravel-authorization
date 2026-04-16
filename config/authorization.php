<?php

declare(strict_types = 1);

use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;

return [

    /*
    |---------------------------------------------------------------------------
    | Models
    |---------------------------------------------------------------------------
    |
    | Eloquent classes that back the three first-class authorization entities.
    | Consumers may point any of these at their own subclass — the package
    | resolves models through config to avoid hard class references anywhere
    | in the engine.
    |
    */

    'models' => [
        'role'       => \SineMacula\Laravel\Authorization\Models\Role::class,
        'permission' => \SineMacula\Laravel\Authorization\Models\Permission::class,
        'policy'     => \SineMacula\Laravel\Authorization\Models\Policy::class,
    ],

    /*
    |---------------------------------------------------------------------------
    | Tables
    |---------------------------------------------------------------------------
    |
    | Physical table names used by the shipped migrations and Eloquent models.
    | Override here if you need to sidestep naming collisions with existing
    | application tables.
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
    | Pivot columns
    |---------------------------------------------------------------------------
    |
    | Column names used on the shipped pivot tables. Consumers who swap the
    | pivot table schema (renamed FKs, legacy column names, bespoke naming
    | conventions) can override each side here. The `RolePermission` pivot
    | reads these when Laravel has not already supplied the relation's pivot
    | keys (e.g. direct instantiation paths); otherwise the pivot prefers the
    | relation-supplied keys so a consumer who overrides a relation definition
    | still gets the invariant enforced.
    |
    */

    'pivots' => [
        'role_permissions' => [
            'role_column'       => env('AUTHORIZATION_PIVOT_ROLE_PERMISSIONS_ROLE_COLUMN', 'role_id'),
            'permission_column' => env('AUTHORIZATION_PIVOT_ROLE_PERMISSIONS_PERMISSION_COLUMN', 'permission_id'),
        ],
        'authorizable_roles' => [
            'authorizable_type_column' => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_ROLES_TYPE_COLUMN', 'authorizable_type'),
            'authorizable_id_column'   => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_ROLES_ID_COLUMN', 'authorizable_id'),
            'role_column'              => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_ROLES_ROLE_COLUMN', 'role_id'),
            'expires_at_column'        => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_ROLES_EXPIRES_AT_COLUMN', 'expires_at'),
        ],
        'authorizable_permissions' => [
            'authorizable_type_column' => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_PERMISSIONS_TYPE_COLUMN', 'authorizable_type'),
            'authorizable_id_column'   => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_PERMISSIONS_ID_COLUMN', 'authorizable_id'),
            'permission_column'        => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_PERMISSIONS_PERMISSION_COLUMN', 'permission_id'),
            'expires_at_column'        => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_PERMISSIONS_EXPIRES_AT_COLUMN', 'expires_at'),
        ],
        'authorizable_policies' => [
            'authorizable_type_column' => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_POLICIES_TYPE_COLUMN', 'authorizable_type'),
            'authorizable_id_column'   => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_POLICIES_ID_COLUMN', 'authorizable_id'),
            'policy_column'            => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_POLICIES_POLICY_COLUMN', 'policy_id'),
            'expires_at_column'        => env('AUTHORIZATION_PIVOT_AUTHORIZABLE_POLICIES_EXPIRES_AT_COLUMN', 'expires_at'),
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Defaults
    |---------------------------------------------------------------------------
    |
    | The default guard recorded on role and permission rows. Retained for
    | migration compatibility with Spatie's `laravel-permission` package.
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
    | Backed or unit enums implementing `PermissionEnum`. Every case is wired
    | into a Laravel Gate on boot, so a permission defined here is immediately
    | callable via `Gate::allows(...)`, `$user->can(...)`, `@can(...)`, and the
    | `can:` route middleware.
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

    'permission_enums' => [
        // \App\Enums\Permission::class,
    ],

    /*
    |---------------------------------------------------------------------------
    | Permission providers
    |---------------------------------------------------------------------------
    |
    | Class-strings implementing `PermissionProvider`. Each provider contributes
    | a list of permission strings and a guard scope. At boot the service
    | provider walks every entry and creates `Permission` rows via
    | `firstOrCreate`, so modular packages can ship their own permission sets
    | without the host application editing a central enum.
    |
    */

    'permission_providers' => [
        // \App\Authorization\BlogPermissionProvider::class,
    ],

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
    | Resolution cache
    |---------------------------------------------------------------------------
    |
    | Two-tier cache for principal roles, permissions, and policies. The
    | in-memory tier is always on and memoises results per-request. The
    | optional persistent tier kicks in when `store` is set to one of the
    | configured cache connections — results are written there with the
    | supplied TTL (0 = forever) under a namespaced key prefix, and the
    | shipped `InvalidateResolutionCache` listener drops entries when the
    | package's events fire.
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
