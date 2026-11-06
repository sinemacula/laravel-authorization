<?php

declare(strict_types = 1);

use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;

return [

    /*
    |---------------------------------------------------------------------------
    | Models
    |---------------------------------------------------------------------------
    |
    | Eloquent classes that back the three first-class authorization entities.
    | Consumers may point any of these at their own subclass — the package
    | resolves models through config to avoid hard class references anywhere
    | in the engine, the management services included. Each class must be the
    | shipped model or a subclass of it; any other value is refused when the
    | application boots.
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
    | their tables on it, and the package's own transactions run on it: each
    | call to the role, permission, policy, grant and resource policy services
    | runs in one transaction here. Point it at the connection the application
    | keeps its identity tables on, so a transaction that creates a principal
    | and its grants commits or rolls back as one. Null uses the application's
    | default connection.
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
        'resource_policies'        => env('AUTHORIZATION_TABLE_RESOURCE_POLICIES', 'resource_policies'),
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
    | Policies are checked against the same catalogue: every `actions` and
    | `not_actions` pattern in a policy document must match at least one
    | permission declared here or by a provider, so a misspelt action is
    | refused rather than stored. With nothing declared, every policy write is
    | refused.
    |
    | **Required for Laravel's Gate surface.** The `Authorization` facade
    | (`Authorization::can(...)`, `Authorization::for($user)->can(...)`) works
    | out of the box, but Laravel's Gate never dispatches to an action it has
    | not been told about — `Gate::allows('posts:edit')` silently returns false
    | until a `PermissionEnum` case is listed here. Consumers who want the
    | standard Laravel authorization surface must register at least one enum;
    | consumers who only use the facade can leave this empty, as long as a
    | provider declares the permissions their policies name.
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
    | `authorization:sync`, which writes its permissions alongside the enums',
    | and by the policy validator, which accepts a policy pattern that matches
    | one of them. A provider's permissions can be checked through the
    | `Authorization` facade and `hasPermission()`, but they are not
    | registered as Gate abilities and do not appear in
    | `effectivePermissions()`; declare a permission as an enum case when it
    | must work with `Gate`, `@can` or the `can:` middleware.
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
    | check, such as policies shipped in code. Leave as null to rely solely on
    | the policies stored in the database: those attached to the identity,
    | inline ones included, those attached to the roles it holds, and those
    | attached to the check's resource and its type.
    |
    */

    'policy_store' => null,

    /*
    |---------------------------------------------------------------------------
    | Policy limits
    |---------------------------------------------------------------------------
    |
    | Caps on a policy document, so a policy cannot be made expensive to store
    | or evaluate: `document_bytes` on its JSON encoding, `statements` on how
    | many statements it holds, `conditions` on how many key tests one
    | statement's conditions hold, and `pattern_length` on the characters of
    | any action or resource pattern and any string operand. Each must be a
    | whole number of at least 1.
    |
    | A document over a limit is refused when it is written, and a stored one
    | over a limit denies every check for its holder as an invalid policy.
    | Cached policies are keyed by the limits they were checked under, so
    | lowering a limit makes the stored documents over it deny until they are
    | fixed; `php artisan authorization:policy:validate --database` lists them.
    |
    */

    'policies' => [
        'limits' => [
            'document_bytes' => (int) env('AUTHORIZATION_POLICY_DOCUMENT_BYTES', 65536),
            'statements'     => (int) env('AUTHORIZATION_POLICY_STATEMENTS', 100),
            'conditions'     => (int) env('AUTHORIZATION_POLICY_CONDITIONS', 50),
            'pattern_length' => (int) env('AUTHORIZATION_POLICY_PATTERN_LENGTH', 512),
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Context
    |---------------------------------------------------------------------------
    |
    | The context a policy's conditions and `${…}` references read is nested
    | namespaces, each key a dot path: `authentication` (`guard`, `user_id`,
    | `user_type`), `request` (`ip`, `method`, `route`, present only in a
    | routed request), `environment` (`time`, UTC), `subject` and `resource`
    | (see attributes below), `input` (what the caller passes to `check()`,
    | `can()`, a Gate and the like, held there alone, so `['post' =>
    | ['status' => 'draft']]` is `input.post.status`) and any namespace a
    | source below adds. Replace a trusted namespace by binding its
    | contract (`AuthenticationContext`, `RequestContext`,
    | `EnvironmentContext`).
    |
    | `keys` declares the keys a policy may read beyond the package's own, by
    | namespace, each a dot path mapped to its type: `string`, `number`,
    | `bool`, `time`, `ip` or `list`, for example
    | `['input' => ['post.status' => 'string'], 'tenant' => ['plan' =>
    | 'string']]`. A policy reading an undeclared key, or testing a key with an
    | operator that does not suit its type, is refused when it is written. A
    | service provider may also register keys on the `ContextKeyCatalogue`.
    | Keys under `subject` and `resource` are refused here; declare them on an
    | attribute provider (see attributes below).
    |
    | `sources` lists classes implementing `ContextSource`, resolved from the
    | container, each supplying one namespace of its own, built only when a
    | statement reads it. A class that does not implement the contract, a
    | reserved namespace (`authentication`, `request`, `environment`, `input`,
    | `subject`, `resource`) and a namespace two sources supply are refused at
    | boot.
    |
    */

    'context' => [
        'keys'    => [],
        'sources' => [],
    ],

    /*
    |---------------------------------------------------------------------------
    | Subject and resource attributes
    |---------------------------------------------------------------------------
    |
    | The `subject` and `resource` namespaces hold the check's subject and
    | resource. Their built-in keys are `id`, `type`, `tenant.type` and
    | `tenant.id`: the subject's key, morph type and tenant, and the
    | resource's id (a record only), type (a record or a type alone) and
    | tenant. An opaque resource identifier has neither id nor type.
    |
    | Further attributes come from providers registered by morph type:
    | `resources` maps a type to a class implementing
    | `ResourceAttributeProvider`, given the record and the model the check
    | was given, if any (a model implementing `AuthorizableResource` too,
    | when its reference carries no model), and `subjects` maps a type to a
    | class implementing `SubjectAttributeProvider`, given the subject. Each
    | is resolved from the container, and the attributes it declares
    | (`['status' => 'string']` becomes `resource.status`) are the only ones
    | it exposes; nothing under a declared key is, and a map, or a list under
    | a type other than `list`, stays present but undecidable. A class that
    | does not implement its contract, an unknown type, a built-in, a key
    | under another the provider declares and a key two providers declare
    | with different types are refused at boot. A provider that throws aborts
    | the check with `AttributeProviderFailed`.
    |
    */

    'attributes' => [
        'resources' => [],
        'subjects'  => [],
    ],

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
    | An application with principals or tenants names its own resolver here or
    | binds the contract directly; the `sinemacula/laravel-iam` umbrella binds
    | one that delegates to `sinemacula/laravel-authentication`. Null or a class
    | that does not implement the contract is refused at boot. A class named
    | here, like the default, is built per request or job, so queue workers and
    | Octane resolve it afresh, while a resolver bound directly on the contract
    | (`instance()`, `singleton()` or `bind()`) is kept. The resolved tenant is
    | held per request or job whichever resolver is bound.
    |
    */

    'subject_resolver' => AuthGuardSubjectResolver::class,

    /*
    |---------------------------------------------------------------------------
    | Tenant tree
    |---------------------------------------------------------------------------
    |
    | A class implementing `TenantTree`, which answers a tenant's ancestors,
    | whether one tenant is within another, and a tenant's subtree as a query.
    | The package never stores the tree. A grant in a tenant applies there and,
    | unless it is limited to its own tenant, in every tenant below it; a tenant
    | sees the roles, permissions and policies its ancestors own. The shipped
    | default is a flat set of tenants, so a grant applies only in its own
    | tenant. Report a change to the tree (a tenant moved or deleted) with
    | `Authorization::treeChanged($tenant)`. Null or a class that does not
    | implement the contract is refused at boot; like the subject resolver, a
    | class named here is built per request or job.
    |
    */

    'tenant_tree' => FlatTenantTree::class,

    /*
    |---------------------------------------------------------------------------
    | Application access
    |---------------------------------------------------------------------------
    |
    | The permission each application requires before a principal may use it,
    | keyed by the application's name (its guard's name, as
    | `laravel-authentication` names it), for example
    | `['admin' => 'admin:access']`. `ApplicationAccess::mayUse()` asks the
    | full decision whether the principal holds it on that application, so a
    | grant made for that application counts; grant it through the roles that
    | should get in. An application not named here is open to every principal.
    |
    */

    'application_access' => [],

    /*
    |---------------------------------------------------------------------------
    | Resource tenant resolver
    |---------------------------------------------------------------------------
    |
    | A class implementing `ResourceTenantResolver`, which answers which tenant
    | owns the record a check is about, named by its model or by a `(type,
    | id)` pair. A resource of the active tenant, or of a tenant below it, is
    | then decided in its own tenant, and one of any other tenant is denied as
    | `tenant_scope` unless a platform-wide grant covers it. The shipped
    | default knows no record's tenant, so nothing is refused for its tenant
    | until you bind your own (reading a tenant column, say). A resource
    | implementing `AuthorizableResource` names its own tenant.
    |
    */

    'resource_tenant_resolver' => NoResourceTenant::class,

    /*
    |---------------------------------------------------------------------------
    | Authentication requirement checker
    |---------------------------------------------------------------------------
    |
    | A class implementing `AuthenticationRequirementChecker`, which judges an
    | `authentication_requirement` condition (additional verification,
    | multifactor, phishing resistance, a minimum assurance level, each with
    | an optional `max_age`) for the subject's session, fetching the proofs
    | itself. It answers met, with the instant until which the requirement
    | stays met, or unmet, with the parts that are not. A subject without a
    | session, such as one named with `for()`, meets no requirement, and the
    | checker is not asked; a checker that throws makes the test undecidable.
    |
    | The shipped default refuses: every part of every requirement is unmet,
    | so an allow that states one never applies, and when nothing else allows
    | the check is denied as `insufficient_authentication`. Under the suite
    | `sinemacula/laravel-iam` binds `laravel-mfa`'s requirement check. A class
    | that does not implement the contract is refused at boot. A class named
    | here is built per request or job, while a checker bound directly on the
    | contract is kept.
    |
    */

    'requirement_checker' => RefusingRequirementChecker::class,

    /*
    |---------------------------------------------------------------------------
    | Resolution cache
    |---------------------------------------------------------------------------
    |
    | Two-tier cache for what an identity's roles, permissions and policies
    | come to, and for the policies attached to a resource and its type. The
    | in-memory tier is always on and memoises results per request or job. The
    | optional persistent tier is used when `store` names one of the configured
    | cache stores; any store works, with or without tags. Entries are keyed by
    | identity (or resource) and tenant, and record a version of the identity
    | and of every role and policy they were built from; every write bumps the
    | versions it affects, so a change takes effect on the next check in every
    | worker. A store that fails is skipped for the rest of the request or job,
    | and checks read the database.
    |
    | `ttl` is the longest, in seconds, any entry lives in either tier; an
    | entry also lapses a second before the nearest grant it counts expires.
    | It must be a whole number of at least 1.
    |
    */

    'cache' => [
        'store'  => env('AUTHORIZATION_CACHE_STORE'),
        'ttl'    => (int) env('AUTHORIZATION_CACHE_TTL_SECONDS', 300),
        'prefix' => env('AUTHORIZATION_CACHE_PREFIX', 'authorization'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Role hierarchy
    |---------------------------------------------------------------------------
    |
    | Controls whether the role parent-child hierarchy affects permission and
    | policy resolution. When enabled (the default), a role's `getPermissions()`
    | returns the deduplicated union of its own direct permissions and all
    | permissions inherited from ancestor roles, and a role's holders get the
    | policies attached to its ancestors as well as its own, and are named by
    | a resource policy's `role:` selector for any of them. When disabled,
    | only directly attached permissions and policies count — `parent_id` can
    | still be set for organisational grouping but has no effect on
    | authorization decisions.
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
