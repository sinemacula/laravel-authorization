<?php

declare(strict_types = 1);

use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;

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
    | none. Rows record their own guard in the `guard` column; a null guard
    | makes a row apply to every guard. Who a check is about comes from the
    | subject resolver below, not from this setting.
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
    | The cases are also the permission catalogue: `authorization:sync` writes
    | each one to the database, with the description, category and guards of
    | the `#[Permission]` attribute on the case. Booting never writes them, so
    | run the sync after `migrate` when you deploy.
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
    | Class-strings implementing `PermissionProvider`. Each provider returns
    | `PermissionDefinition` objects, each a permission's name, description,
    | category and guard, so modular packages can ship their own permission
    | sets without the host application editing a central enum. The classes
    | are validated at boot, but a provider is read only by
    | `authorization:sync`, which writes its permissions alongside the enums'.
    | A provider's permissions can be checked through the `Authorization`
    | facade and `hasPermission()`, but they are not registered as Gate
    | abilities and do not appear in `effectivePermissions()`; declare a
    | permission as an enum case when it must work with `Gate`, `@can` or the
    | `can:` middleware.
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
    | additional policies for the current subject from this source on every
    | check. Leave as null to rely solely on policies attached to identities.
    |
    */

    'policy_store' => null,

    /*
    |---------------------------------------------------------------------------
    | Subject resolver
    |---------------------------------------------------------------------------
    |
    | A class implementing `SubjectResolver`, which answers who every check
    | without a named subject is about, in which tenant and on which
    | application. The shipped default decides about the user Laravel
    | authenticated on its default guard, with no tenant (so only platform-wide
    | roles and permissions are visible) and the guard's name as the
    | application; a request with no user is denied. Laravel's Gate hands its
    | user to the resolver's `forUser()`, so `@can` and `can:` decide about the
    | same subject.
    |
    | An application with principals or tenants binds its own resolver here or
    | binds the contract directly; the `sinemacula/laravel-iam` umbrella binds
    | one that delegates to `sinemacula/laravel-authentication`. Null or a class
    | that does not implement the contract is refused at boot. The package's
    | default and the tenant it returns are built per request or job, so queue
    | workers and Octane resolve them afresh, while a resolver the application
    | binds itself is kept.
    |
    */

    'subject_resolver' => AuthGuardSubjectResolver::class,

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
