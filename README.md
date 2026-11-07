<h1 align="center">Laravel Authorization</h1>

<div align="center">

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-authorization.svg)](https://packagist.org/packages/sinemacula/laravel-authorization)
[![PHP Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-authorization/php.svg)](https://packagist.org/packages/sinemacula/laravel-authorization)
[![Laravel Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-authorization/laravel/framework.svg?label=laravel)](https://packagist.org/packages/sinemacula/laravel-authorization)
[![Build Status](https://github.com/sinemacula/laravel-authorization/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-authorization/actions/workflows/tests.yml)
[![Quality Gates](https://github.com/sinemacula/laravel-authorization/actions/workflows/quality-gates.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-authorization/actions/workflows/quality-gates.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-authorization/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authorization)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-authorization/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authorization)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-authorization.svg)](https://packagist.org/packages/sinemacula/laravel-authorization)
[![License](https://img.shields.io/github/license/sinemacula/laravel-authorization.svg)](LICENSE)

</div>

Role-based access control and IAM-style policy evaluation for Laravel. Decides what a principal may do: roles and
permissions granted to any Eloquent model, policy documents that allow or deny actions on resources under conditions,
and one evaluator that combines them.

Drops into Laravel's existing authorisation machinery: the package is the authority of Laravel's Gate for every
permission it declares, so `Gate::allows()`, `@can`, `can:` middleware and `$user->can()` work unchanged and decide
through it. Adds `role`, `permission` and `authorize` route middleware,
Blade directives, console commands and test assertions.

## Core Concept

| Concept         | What it is                                                                                                   |
|-----------------|--------------------------------------------------------------------------------------------------------------|
| **Principal**   | Who a decision is about: any Eloquent model that implements `AuthorizableIdentity`, usually your user model. |
| **Role**        | A named set of permissions, granted as one. Roles can inherit from a parent role.                            |
| **Permission**  | A named action, such as `posts:update` or `posts.update`, or a wildcard pattern of them, such as `posts:*`.  |
| **Policy**      | A JSON document of statements, each allowing or denying actions on resources, optionally under conditions.   |
| **Boundary**    | A policy set on a principal or an identity that caps what it may do, whatever its grants allow.              |
| **Guardrail**   | A policy set on a tenant or the platform that caps what anyone may do there, whatever their grants allow.    |
| **Session cap** | A set of actions, a credential's scopes or the caller's, that bounds what one check may allow.               |
| **Machine**     | A principal that acts for no person, such as a service account, capped by its credential's scopes.           |
| **Decision**    | The answer to one check: allowed or not, with the reason and a trace of the statements that decided it.      |

Every check runs the same stages (see [How a check is decided](#how-a-check-is-decided)): the subject, the resource and
its tenant are checked first, then an explicit deny in any policy that applies (the principal's, its roles', the
resource's, the guardrails' and its boundaries') wins, then the caps (the guardrails on the tenant, its ancestors and
the platform, then its permission boundaries, then the session caps: its credential's scopes and any the caller passes)
must each allow the check, then an explicit allow or a permission held allows it, and anything left is denied.

## Features

- **Roles and permissions** as Eloquent models with UUID keys, granted to any model through polymorphic pivots (integer,
  UUID and ULID keys all work), each grant with an optional expiry, stored in UTC whatever zone it is given in. A
  role's grant of a permission can expire too.
- **Owned records**: a role, permission or policy belongs to the platform or to one tenant, and its name is unique
  within its tenant (and, for roles and permissions, its guard; an inline policy's name is unique among its grantee's
  instead), so two tenants can each have their own `manager`. A tenant cannot take the name of a platform system role,
  revoking a name removes every held grant of it (the platform's and the tenant's), and `hasRole()` given a role model
  matches only that row.
- **Role and permission names** of letters, digits and `_ - : . *`, so `posts:edit`, `posts.edit` and
  `sso.connection.trust` are all valid; anything else is refused when the name is saved.
- **Wildcard permissions** (`posts:*`, `posts.*`, `*:create`, and `*` for everything; `*:*` matches only names with a
  `:`) and **role hierarchy**: a role inherits its parent's permissions, with cycle checks on write.
- **Policy documents** of statements with an optional `sid`, an `effect`, `actions` or `not_actions`, `resources` or
  `not_resources`, and operator-first `conditions`: twenty operators (equality, set membership, prefix, suffix and glob,
  numeric and time comparisons, booleans, null tests, IPv4 and IPv6 ranges, and multi-valued keys), every one but
  `null` with an `_if_exists` form, the `authentication_requirement` operator, and `${…}` interpolation from the
  check's context. A document is refused when it is saved if it is malformed, over the configured limits, reads a
  context key nobody declared, tests a key with an operator that does not suit its type, tests or references an
  assurance key, or names an action no declared permission matches, and `authorization:policy:validate` checks files or
  stored policies against the same rules.
- **Role and inline policies**: a policy attaches to an identity or to a role, whose holders get it where both grants
  hold (tenant, application and expiry) and inherit it down the role hierarchy. An inline policy belongs to one
  grantee, is attached to it alone and is deleted with it; its name is unique among that grantee's.
- **Resource-based policies**: a managed policy attaches to one record or to a whole resource type. Each of its allows
  names the subjects it applies to in `principals`, by reference or by a role's key, and allows them without any
  permission held; its denies apply to everyone checking the resource. The tenant stage still comes first, so a
  resource policy never reaches across tenants.
- **Permission boundaries**: a managed policy set on a principal or an identity, platform-wide or in a tenant, caps
  everything the check could otherwise allow: a policy's allow, a resource policy's and a permission held alike. Every
  boundary that applies must allow the check, a boundary grants nothing, and its denies count with every other deny.
- **Guardrails**: a managed policy set on a tenant, reaching its subtree, or on the platform caps every check in its
  scope, whoever the subject is, as a boundary caps one grantee's. Every guardrail that applies must allow the check,
  a guardrail grants nothing, and only an actor holding `authorization:guardrails:manage` from above the scope, a
  permission the package declares itself and no guardrail caps, may set or remove one.
- **Session caps and machines**: a check is capped by the scopes of the subject's credential, from a session policy
  source you bind and mapped to actions through a scope map checked at boot, and by any actions the caller passes to
  `Authorization::capped()`. Every cap must cover the action, a cap grants nothing, and an empty cap allows nothing. A
  machine principal is allowed nothing without its credential's scopes, a person's grants never reach a machine, and a
  machine's grants never reach a person, though an identity's denies apply whatever its kind. A scope registry backed
  by the permission catalogue tells which scopes a credential may carry.
- **Authentication requirements**: an allow can require additional verification, multifactor authentication,
  phishing resistance or a minimum assurance level, each with an optional maximum age, judged for the subject's session
  by a requirement checker you bind. When only that requirement keeps an allow from applying, the check is denied as
  `insufficient_authentication` with the parts that are unmet, so the application can ask for a step-up rather than
  refuse.
- **A namespaced context**: conditions read dot paths such as `request.ip`, `authentication.user_id`,
  `environment.time`, `subject.id`, `resource.owner.id` and `input.post.status`. The trusted namespaces come from their
  own sources, never from the caller, whose values land under `input` alone; the subject's and the resource's attributes
  come from providers registered by morph type; an application adds a namespace of its own with a `ContextSource`, and
  declares every key a policy may read, with its type, in a key catalogue. A namespace is built only when a statement
  reads it, and at most once a check.
- **The Gate's authority**: one `Gate::before` hook answers every ability the enums, the providers or the package
  declare, and its allow and its deny both stand over any `Gate::define` callback or Laravel policy class; every other
  ability falls through to Laravel unchanged. Configuration can turn it off, and `authorization:check` reports it.
- **Query scoping**: `whereAuthorized()` restricts an Eloquent query to exactly the rows `check()` would allow, by
  adding one condition the database evaluates, compiled again every time the query runs, so pagination, counts and
  chunks stay correct; a query it cannot scope exactly is refused with a dedicated exception, never filtered after
  loading. It compiles literal ids and key prefixes, tenant subtrees under any tenant tree, platform-wide grants and
  policies attached to records, and a model-level `AuthorizedScope` applies it to every query of a model.
- **A programmatic API**: `can`, `cannot`, `authorize`, `check`, `any`, `all` and `explain`, through the
  `Authorization` facade or an injected `AuthorizationManager`, about the current subject or one named with `for()` or
  `forUser()`, and a trait through which a Laravel policy class decides the abilities the Gate hook leaves to it.
- **Bulk checks**: `checkMany()`, `canEach()` and `filterAuthorized()` decide many resources at once, each exactly as
  `check()` would decide it and reported with its own decision event, reading the subject's grants and policies once in
  each scope and the resources' tenants, attached policies and attributes in bulk, so with the package's resolvers and
  bulk-reading attribute providers a check over many resources does not cost a query per resource, outside the few cases
  the [bulk checks](#bulk-checks) section names.
- **Effective permissions**: `permissionsFor()` lists the actions of the permission catalogue a subject may take in a
  scope (a tenant or the platform, an application and a resource, named with `AuthorizationScope`), exactly those
  `check()` would allow there, for a UI to show or hide its controls. The actions share one read of the subject's
  grants and policies, and listing them records no decision and dispatches no event.
- **A permission catalogue in code**: enums and providers declare each permission with a description, a category and
  its guards, and `authorization:sync` writes them to the database on deploy, reporting stale rows rather than
  deleting them. Booting never touches the database.
- **Route middleware and Blade directives**: `permission:`, `authorize:` and the permission directives decide on the
  same full decision as the Gate; `role:` and the role directives check role membership. `|` separates the names of a
  list: any one of them admits for the middleware and the any-of directives, every one is needed for the all-of ones.
- **Localisable messages**: every denial and unauthenticated response a client can see is a translation key, with one
  generic line for every denial and the reason code beside it for an application that words its own.
- **System records**: roles, permissions and policies flagged `is_system` cannot be edited, deleted or have the flag
  cleared unless `forceSystem()` unlocks the next change.
- **Explanations**: `Authorization::explain()`, the last decision of the request, and `authorization:why-can` on the
  command line.
- **Management services** that own every write of a role, permission, policy, grant, resource attachment, permission
  boundary or guardrail: each call runs in one transaction on the package's connection, through the configured models,
  and grants are idempotent under concurrency. The traits, the grant and revoke commands and the Spatie import write
  through them; only `authorization:sync` still writes the permission catalogue through the permission model, in its own
  transaction.
- **Events** for every grant, revocation, expiry change, resource attachment, boundary or guardrail change and model
  change that changes something, for each use of the system override, for each decision, and when `authorize()` refuses.
  All implement one marker interface; the change events are snapshots of plain values that carry the actor the caller
  named, and are dispatched only once the write commits.
- **Resolution cache** for roles, permissions, policies, boundaries and guardrails, in memory and optionally in any
  cache store, versioned so every write takes effect on the next check in every worker, and falling back to the database
  when the store fails.
- **Swappable everything**: models, table names, the database connection, the subject resolver and the policy store.
- **Spatie import**: `authorization:migrate-spatie` copies roles, permissions and grants from
  `spatie/laravel-permission` through the management services (its `guard_name` becomes `guard`), reporting and
  skipping any role or permission whose name the package refuses, and any permission whose name contains `*`, along
  with its grants.

## Installation

```bash
composer require sinemacula/laravel-authorization
```

## Configuration

Publish the config and the migrations, then migrate:

```bash
php artisan vendor:publish --tag=authorization-config
php artisan vendor:publish --tag=authorization-migrations
php artisan migrate
```

The tables live on the application's default connection. To keep them on another, such as the one your identity
tables use, set `AUTHORIZATION_DB_CONNECTION` (or `connection` in `config/authorization.php`) before migrating: the
migrations create the tables there, and the models read and write there.

Every check that does not name its subject is about the subject the subject resolver returns. The shipped resolver,
`AuthGuardSubjectResolver`, returns the user Laravel authenticated on its default guard, with no tenant and the guard's
name as the application, so `Authorization::can()`, the package's middleware and the Blade directives decide about the
signed-in user with no setup. A request with no user has no subject, and its checks are denied. Laravel's Gate hands its
user to the same resolver, so `@can`, `can:` and `Gate::forUser($user)` decide about the subject the resolver translates
that user into, and a guest is denied (see [Laravel's Gate](#laravels-gate)).

An application with principals or tenants binds its own resolver, a class implementing
`SineMacula\Laravel\Authorization\Contracts\SubjectResolver`, in `config/authorization.php`. The active tenant comes
only from it: without a tenant, only platform-wide roles and permissions are visible.

```php
'subject_resolver' => App\Authorization\CurrentSubject::class,
```

List the enums whose cases are the application's permissions, and any permission providers; the Gate asks the package
about every permission either declares:

```php
'permission_enums' => [
    App\Authorization\PostPermission::class,
],

'permission_providers' => [
    App\Authorization\MediaPermissions::class,
],
```

The same declarations are the actions a policy may name: a policy is refused when it is saved if one of its `actions` or
`not_actions` patterns matches no declared permission. Until you declare yours, a policy is refused with the reason
that no permissions are declared, unless it names only the package's own permission, `authorization:guardrails:manage`
(see [Guardrails](#guardrails)), which a policy may always name.

Booting the package never queries or writes the database, so `config:cache`, `route:cache` and `migrate` run before
the tables exist. The permissions the enums and providers declare reach the database when you sync them, which belongs
in your deployment after the migrations:

```bash
php artisan migrate --force
php artisan authorization:sync
```

The package writes its warnings (a discarded cache entry, a policy whose document cannot be read) to your default log
channel. To send them elsewhere, name a channel from `config/logging.php`:

```dotenv
AUTHORIZATION_LOG_CHANNEL=stderr
```

`config/authorization.php` documents every other option: models, tables, the default guard, permission providers, the
Gate switch, the policy store, the policy limits, the context keys and sources, the attribute providers, the subject
resolver, the authentication requirement checker, the session policy source and the scope map, the cache, the bulk
checks' chunk size, and the role hierarchy and rank.

## Usage

Give your user model the contract and the trait:

```php
namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

class User extends Authenticatable implements AuthorizableIdentity
{
    use HasAuthorization;
}
```

Keys may be integers, UUIDs or ULIDs. Deleting the model removes its grants and its permission boundaries; a model that
soft-deletes keeps them until it is force-deleted, so restoring it restores its access. To deny a suspended user
everything, override `isAuthorizationActive()`:

```php
public function isAuthorizationActive(): bool
{
    return $this->suspended_at === null;
}
```

A check about an inactive subject is denied with the `subject_inactive` reason before anything else is read. When the
subject resolver returns a subject with a separate identity (an account belonging to a person, say), a check counts the
grants and policies of both, and is denied if either is inactive. When one of the two is a machine and the other is
not, only the identity's denies, boundaries and inactivity count: see
[Session caps and machines](#session-caps-and-machines).

Define permissions as a string-backed enum. Each case's value is the permission name:

```php
namespace App\Authorization;

use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

enum PostPermission: string implements PermissionEnum
{
    case UPDATE = 'posts:update';
    case DELETE = 'posts:delete';
}
```

A `#[Permission]` attribute on a case gives the permission a description and a category, and limits it to guards. A
case without `guards` declares one guard-agnostic permission; a list declares one permission per guard. The attribute
shares its short name with the permission model, so alias it:

```php
use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

enum PostPermission: string implements PermissionEnum
{
    #[PermissionMeta(description: 'Edit any post', category: 'Posts')]
    case UPDATE = 'posts:update';

    #[PermissionMeta(description: 'Delete any post', category: 'Posts', guards: ['web', 'api'])]
    case DELETE = 'posts:delete';
}
```

A module that ships its own permissions can declare them with a provider. A provider's permissions are written to the
catalogue, answered through the Gate, `@can` and the `can:` middleware like an enum's, and checked through the
`Authorization` facade and `hasPermission()`, and listed by `permissionsFor()`:

```php
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

final class MediaPermissions implements PermissionProvider
{
    public function permissions(): array
    {
        return [
            new PermissionDefinition(name: 'media:upload', description: 'Upload media', category: 'Media', guard: 'web'),
        ];
    }
}
```

`authorization:sync` adds the declared permissions that have no row and updates the description and category of those
that differ, in one transaction, through the configured permission model. A platform permission that no enum or
provider declares is reported as `stale` and left alone; `--prune` deletes stale permissions, except system ones, which
are reported as `protected` and never changed. Permissions owned by a tenant are never read or changed. Every row is
listed with its action, as a table or, with `--format=json`, as JSON. A name outside the package's name rules, an empty
guard list or a guard that is not a non-empty string fails the sync with exit code `2` before anything is written. In
CI, `--dry-run` exits with `1` when anything would be added, updated or pruned:

```bash
php artisan authorization:sync --dry-run --format=json
```

Once the permissions are synced, grant roles and permissions, then check them as with any Laravel ability:

```php
use Illuminate\Support\Facades\Gate;
use SineMacula\Laravel\Authorization\Models\Role;

Role::create(['name' => 'editor'])->givePermission('posts:update');

$user->assignRole('editor');
$user->givePermission('posts:delete', now()->addDay());

$user->hasRole('editor');              // true
$user->hasPermission('posts:update');  // true, through the role
Gate::forUser($user)->allows('posts:update');
```

### Managing roles, permissions and grants

Every write goes through seven services, which you inject or resolve from the container: `RoleService`,
`PermissionService` and `PolicyService` for the records, `GrantService` for what a grantee holds,
`ResourcePolicyService` for the policies attached to resources (see [Resource-based
policies](#resource-based-policies)), `BoundaryService` for the permission boundaries of principals and identities (see
[Permission boundaries](#permission-boundaries)), and `GuardrailService` for the guardrails of tenants and the platform,
whose actor is required (see [Guardrails](#guardrails)). Each call runs in one transaction on the package's connection
(`authorization.connection`), through the models `authorization.models` configures, and takes the actor making the call
as an optional `actor`, a model or a reference (null for console and system work). Every event the call dispatches
carries it, and every grant row it writes records it in `granted_by_type` and `granted_by_id`; it is never read from the
signed-in user:

```php
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;

$roles  = app(RoleService::class);
$grants = app(GrantService::class);

$editor = $roles->create('editor', 'web', 'Edits posts', actor: $admin);
$roles->grantPermission($editor, 'posts:update', actor: $admin);
$roles->setParent($editor, 'author', actor: $admin);

$grants->grantRole($user, $editor, now()->addMonth(), actor: $admin); // GrantOutcome::GRANTED
$grants->syncPermissions($user, ['posts:delete'], actor: $admin);     // SyncResult
$grants->revokeRole($user, 'editor', actor: $admin);                  // 1, the roles revoked
```

Grants are idempotent: granting what the grantee holds, with the same expiry, changes nothing, dispatches no event and
returns `GrantOutcome::UNCHANGED`, and a concurrent duplicate never raises a unique-constraint violation. Re-granting a
grant that has expired re-arms it with the new expiry (`REARMED`), and a new expiry on a live grant is reported as
`EXPIRY_CHANGED`. A sync re-arms a listed grant that has expired with the sync's expiry, or with none when it is given
none, and leaves a live one as it is. A role's permissions work the same way: `RoleService::grantPermission()` and
`syncPermissions()`, and the role's `givePermission()` and `syncPermissions()`, each take an optional expiry. The
identity traits' sync methods take no expiry, so a lapsed temporary grant they list comes back permanent; to re-arm it
for a limited time, call `GrantService::syncRoles()` (or `syncPermissions()`, `syncPolicies()`) with an expiry. Setting
a role's parent locks the roles involved and refuses a cycle. A role with children cannot be deleted
(`RoleHasChildrenException`), so no one holding a child loses what it inherited by surprise: move the children to
another parent or delete them first. A target of the wrong kind, such as a role in a policy sync, is refused with
`InvalidGrantTargetException`; a grantee that is not a saved model with a key with `InvalidGranteeException`; and an
unsaved role, permission or policy handed to its service, which would otherwise be created or clear a parent, with
`UnsavedRecordException`.

`authorization:sync` is the one writer that does not go through the services yet: it writes the permission catalogue
through the permission model, in one transaction on the package's connection and as one operation, and will move onto
`PermissionService` later.

Every grant holds in a scope: one tenant, or the whole platform. A role, permission or policy a tenant owns is granted
in that tenant; one the platform owns is granted platform-wide unless you name a tenant, so one person can be admin in
one organisation and viewer in another:

```php
$user->assignRole('admin', tenant: $organisationA);
$user->assignRole('viewer', tenant: $organisationB);
```

A check counts the grants made platform-wide, those made in the current tenant and those made in its ancestors that
reach the tenants below them; without a tenant, only platform-wide grants. A check on a resource of the current tenant,
or of a tenant below it, counts the grants that reach that tenant instead; a check on a resource of any other tenant (or
of any tenant when none is active) is denied as `tenant_scope` unless a platform-wide grant admits it, and then counts
only platform-wide grants (see [Permissions held and the resources they
reach](#permissions-held-and-the-resources-they-reach)). Granting a tenant's own role outside that tenant and the
tenants below it, or platform-wide, is refused with `GrantScopeMismatchException`. A revocation removes the grant in the
same scope, and a sync replaces the grants of one scope: the tenant named, else the tenant that owns every target, else
the platform. A grant is for every application unless the call names one.

Tenants, grantees, resources and applications are matched by their exact bytes, on every database: `org`, `ORG` and
`org` followed by a space are three different tenants. On MySQL the package's migrations give every reference column
(the tenant, grantee, resource, owner and granted-by types and keys, and the application) the `utf8mb4_0900_bin`
collation, which neither folds case nor pads trailing spaces, so a check matches rows in SQL as the package compares
references in PHP. Role, permission and policy names keep the table's collation.

A grant can also be limited to one application (a guard's name, as `laravel-authentication` names it): it counts only
when the subject resolver reports that application, and a grant for every application counts on all of them. Each
application is a grant of its own, revoked, synced and reported on its own:

```php
$user->assignRole('staff', application: 'admin');  // only in the admin app
$user->assignRole('member');                       // in every app
$user->revokeRole('staff', application: 'admin');
```

Whether a principal may use an application at all (sign in to it, switch to it, refresh a session of it) is answered by
`ApplicationAccess::mayUse($application, $principal, $tenant)`, in the principal's own tenant (null for a platform
principal), the answer `laravel-authentication`'s application access contract asks for. That contract admits every
principal until it is bound to an adapter calling this service, as `laravel-iam` binds it. Name the permission each
application requires in `config/authorization.php`, and grant it through the roles that should get in; an application
not named there is open to every principal:

```php
'application_access' => ['admin' => 'admin:access'],
```

The check is the full decision, made on the application asked about and in the tenant given, so a grant made for that
application counts and policies can add conditions or denies.

A role takes only the platform's permissions and parent roles, its own tenant's and its tenant's ancestors', so a
platform role takes only the platform's; anything else is refused with `OwnerMismatchException`. Guards follow the same
rule as a role and its permissions: two concrete guards must match, and a guard-agnostic side suits any. A parent of
another guard is refused with `ParentGuardMismatchException`, and a role or permission granted to a grantee of another
guard with `GranteeGuardMismatchException`. The tenant that owns a role, permission or policy is fixed once it is
created (`OwnerChangedException`): to move one, create it in the new tenant and grant it again.

Tenants can form a tree (an organisation above its accounts, say). The package never stores it: bind a class
implementing `SineMacula\Laravel\Authorization\Contracts\TenantTree` as `tenant_tree` in `config/authorization.php`,
answering a tenant's ancestors, whether one tenant is within another, and a tenant's subtree as a query. The subtree
query selects exactly the `tenant_type` and `tenant_id` of every tenant within, whatever the tenant scope, and
[query scoping](#query-scoping) nests it whole, so it runs on the connection of the models it scopes. The default is
a flat set of tenants. With a tree, a grant in a tenant also applies in every tenant below it, unless it is limited to
that tenant, and a tenant sees the roles, permissions and policies its ancestors own as well as its own and the
platform's; the nearest owner's wins a lookup by name. Granting again with the other reach changes it, reported as
`GrantOutcome::REACH_CHANGED`. When the tree changes (a tenant moved under another parent, or deleted), report it so
cached answers below it are dropped and the move takes effect at once:

```php
$user->assignRole('admin', tenant: $organisation);                          // the organisation and its accounts
$user->assignRole('billing', tenant: $organisation, includeSubtree: false); // the organisation alone

Authorization::treeChanged($account);
```

The trait methods (`assignRole()`, `givePermission()`, `attachPolicy()`, `$role->givePermission()` and the others)
still work and go through the same services, with no actor. A raw relation write such as
`$role->permissions()->attach()` bypasses them: it dispatches no event and leaves the resolution cache stale, so it is
unsupported for any change that must be audited.

Attach a policy to refine what the grants allow. An explicit deny wins over any role:

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;

$user->attachPolicy(Policy::create([
    'name'     => 'no-deletes-off-network',
    'document' => [
        'statements' => [
            [
                'sid'        => 'deny-off-network',
                'effect'     => 'deny',
                'actions'    => ['posts:delete'],
                'conditions' => ['ip_not_in' => ['request.ip' => ['10.0.0.0/8', '192.168.0.0/16']]],
            ],
        ],
    ],
]));

Authorization::for($user)->can('posts:delete', 'posts/42');
Authorization::for($user)->explain('posts:delete', 'posts/42');
```

`request.ip` is the address Laravel resolved for the current request, through its trusted proxies; the caller never
supplies it (see [The check's context](#the-checks-context)).

`Authorization::check()` returns the full `Decision`: `isAllowed()`, the denial's reason code (`reason`), the stage that
decided it (`stage`), the statements that did (`statements`) and a trace of every step. `can()`, `cannot()`, `any()`,
`all()` and `authorize()` are shortcuts over it (see [The programmatic API](#the-programmatic-api)).
A check runs in stages, stopping at the first that decides: the subject (`subject_unresolved`,
`subject_inactive`), the resource (`resource_unresolved`), its tenant (`tenant_scope`), then the denies in every
applicable policy, a guardrail's and a permission boundary's included (`explicit_deny`, or `invalid_policy` for a
statement that cannot be evaluated), then the caps: the [guardrails](#guardrails) and the [permission
boundaries](#permission-boundaries), each of which must allow the check (`guardrail` or `boundary`, or `invalid_policy`
for a cap's statement that cannot be evaluated), and the [session caps](#session-caps-and-machines), every one of which
must cover the action (`session_policy`), then the allows (an allow statement, then a permission held), then the
implicit deny (`insufficient_authentication` when an allow statement names the check and only its [authentication
requirement](#authentication-requirements) is unmet, `condition_failed` when an allow statement names the check but its
conditions do not hold, else `no_match`). [How a check is decided](#how-a-check-is-decided) sets the stages out in full.
Each stage assesses its statements in a fixed order, so the decision is the same whatever order the policies are read
in, and the trace records condition key names and whether each held, never their values:

```php
$decision = Authorization::for($user)->check('posts:delete', 'posts/42');

$decision->isAllowed();        // false
$decision->reason;             // DecisionReason::EXPLICIT_DENY
$decision->statements;         // [StatementReference('no-deletes-off-network', 0, <its key>, 'deny-off-network')]
```

A check's resource can be a model (`type:id`), a `[type, id]` pair, a model class for a check on the type alone
(`type:*`, so `post:*` covers "create a post" and `post:42` does not), an object implementing
`SineMacula\Laravel\Authorization\Contracts\AuthorizableResource` (which returns its own `ResourceReference`), or any
other string, used as given. A value that cannot be identified, such as an unsaved model or an identifier holding a NUL
byte, denies as `resource_unresolved`. Through the Gate, `Gate::allows('posts:update', ['post', 42])` names the pair
too, since Laravel spreads the array into two arguments. To have tenant-owned resources decided in their own tenant,
bind a `ResourceTenantResolver` as `resource_tenant_resolver` in `config/authorization.php`. It answers a model's tenant
(`tenantOf()`) and a pair's (`tenantOfRecord()`, which returns `false` when it cannot tell, denying the check as
`resource_unresolved`), so a record is decided the same way however it is named. A resource of the active tenant, or of
a tenant below it, is then decided there, and one of any other tenant is denied as `tenant_scope` before any policy is
read, unless a platform-wide grant of the permission covers it. The default knows no record's tenant; a model
implementing `QueryableResource` takes its tenant from its declaration instead (see [Query scoping](#query-scoping)).
Any other string is never given a tenant, so a tenant-owned resource that is not a model should implement
`AuthorizableResource` and carry its tenant.

Policies fail closed. A deny whose condition cannot be decided, such as one on `request.ip` in a check made outside a
routed request (a queued job, a console command), where the key is missing, still applies, while an allow in the same
position does not. A check without a resource
matches only statements with neither `resources` nor `not_resources`, or whose `resources` include `*`. A stored policy
that cannot be read, or that is over a configured limit, denies every check for its holder, with the reason
`invalid_policy`, until it is fixed.

`Authorization::authorize()` throws `SineMacula\Laravel\Authorization\Exceptions\AuthorizationException` when the check
is denied. It extends Laravel's `Illuminate\Auth\Access\AuthorizationException`, so Laravel's handler answers `403`. It
carries the decision's reason code (`getReason()`) and nothing else: its message is the translated
`authorization::authorization.denied` line, whatever the reason, and the action, the resource and the policies stay out
of it. A denial as `insufficient_authentication` throws `InsufficientAuthenticationException` instead (see
[Authentication requirements](#authentication-requirements)). The full decision is on the `AuthorizationFailed` event
and `Authorization::lastDecision()`. To reword the message, add a locale or word a message per reason, see
[Localisation](#localisation).

### Role and inline policies

A role takes policies as an identity does, through the same trait methods and `GrantService` calls, and they apply to
whoever holds the role:

```php
$editor->attachPolicy($noDeletesOffNetwork);                  // for every holder of editor
$editor->attachPolicy($businessHours, tenant: $organisation); // only in the organisation
$grants->detachPolicy($editor, $noDeletesOffNetwork, actor: $admin);
```

A role's policy applies only where both grants hold: the holder's grant of the role and the role's attachment of the
policy must each hold in the current tenant (or in a tenant above it, when that grant reaches its subtree) and on the
current application, and neither may have expired. A policy attached to a role in one tenant therefore applies to the
role's holders there and nowhere else, and a role granted in one tenant brings none of its policies to another. With
the hierarchy enabled (`hierarchy.enabled`, the default), a role's policies are inherited down the hierarchy exactly as
its permissions are: whoever holds `editor`, whose parent is `author`, gets the policies of both. A deny in a role's
policy is an explicit deny like any other, and wins over every allow and every permission held.

Attaching or detaching a role's policy, or changing its expiry, dispatches the same `Identity\PolicyAttached`,
`Identity\PolicyDetached` and `Identity\PolicyExpiryChanged` events, with the role as the grantee, and takes effect on
the next check for every holder: a change to any role's policy attachments refreshes every identity's cached policies,
and moving a role in the hierarchy refreshes those of the identities that reach it. Deleting a role detaches its
policies, each reported as detached.

An inline policy belongs to one grantee, an identity or a role. It is attached to that grantee alone and is deleted
with it. Create one through the grantee or `PolicyService::createInline()`, which check its document as any policy's
is checked, then attach it in the scope it should hold in:

```php
use SineMacula\Laravel\Authorization\Services\PolicyService;

$document = [
    'statements' => [
        [
            'effect'     => 'deny',
            'actions'    => ['posts:update'],
            'conditions' => ['neq' => ['resource.owner.id' => '${subject.id}']],
        ],
    ],
];

$policy = $user->createInlinePolicy('own-posts-only', $document);

$user->attachPolicy($policy);

// Or through the service, with an actor, here for a role:
$editors = app(PolicyService::class)->createInline($editor, 'own-posts-only', $document, actor: $admin);

$editor->attachPolicy($editors);
```

Creating an inline policy does not attach it. Attaching it to any grantee but the one it belongs to is refused with
`InlinePolicyAttachmentException`, through the trait methods, `GrantService` (a grant or a sync) and a write through a
grantee's `policies()` relation alike. Each reads that grantee from the stored row, so a policy loaded without its
`owner_type` and `owner_id`, or with them changed and not saved, is judged as it is stored, and a policy whose row is
gone is refused with `InvalidGrantTargetException`. Its name is unique among that grantee's inline policies, so two
users can each have an `own-posts-only`, and it never clashes with a managed policy's name. The grantee is held in
`owner_type` and `owner_id`, apart from the policy's tenant: both are set or neither (`InvalidPolicyOwnerException`),
the grantee is fixed once the policy is created (`OwnerChangedException`), and an inline policy is never a system
policy (`SystemInlinePolicyException`). Deleting the grantee deletes its inline policies, each reported as
`Policy\Deleted`, and their attachments with them; a soft-deleted grantee keeps them until it is force-deleted. A
grantee deleted without its model events, such as by a raw query, leaves them behind until `authorization:prune`
deletes them, once it has revoked the grantee's grants. `authorization:policy:validate --database` checks inline
policies with the rest.

A check gathers its policies from four places: the bound policy store (`policy_store`, for policies shipped in code or
kept elsewhere), the identity's own attachments, managed and inline, its roles' policies, and the policies attached to
the check's resource and to its type (see [Resource-based policies](#resource-based-policies)), plus those of a separate
identity, own and role-attached alike (see `docs/design/evaluation-order-and-deny-precedence.md`). A policy attached
both to the identity and to one of its roles counts once. The order they are gathered in never changes the decision:
each stage assesses them by name, then stored key, then the resource a resource policy is attached to, then document.
The grantee's permission boundaries are read apart from them, so a custom resolver never drops them (see [Permission
boundaries](#permission-boundaries)).

### Resource-based policies

A policy attached to a resource decides who may do what to that resource, whoever holds which permission. It attaches
to one record, or to a whole resource type, through `ResourcePolicyService`, and its statements say whom they apply to:

```php
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;

$sharing = Policy::create([
    'name'     => 'post-42-sharing',
    'document' => [
        'statements' => [
            [
                'sid'        => 'reviewers-read',
                'effect'     => 'allow',
                'actions'    => ['posts:read', 'posts:comment'],
                'principals' => ['user:17', 'role:' . $reviewers->id],
            ],
            [
                'sid'     => 'never-delete',
                'effect'  => 'deny',
                'actions' => ['posts:delete'],
            ],
        ],
    ],
]);

$resources = app(ResourcePolicyService::class);

$resources->attach($sharing, $post, actor: $admin);                // GrantOutcome::GRANTED, on post:42
$resources->attach($archiving, Post::class, tenant: $organisation); // every post, in the organisation
$resources->detach($sharing, $post, actor: $admin);                // 1, the attachments removed

Authorization::for($user)->can('posts:read', $post);    // true for user 17, with no posts:read permission
Authorization::for($admin)->can('posts:delete', $post); // false: the deny applies to everyone
```

The resource is a saved model (that record), a `[type, id]` pair, a `ResourceReference` with a type, a model class (the
whole type) or a morph type as a string (the whole type). A pair names its record without asking the bound resource
tenant resolver, since the call says where the attachment holds, so a pair the resolver cannot place is still attached.
An unsaved model, anything that names no type, a type or key longer than 191 bytes, and a record whose key is `*` (which
a check on the whole type stands for) are refused with `InvalidResourceException`. An attachment holds in a scope
exactly as a grant does: a policy a tenant owns is attached in that tenant, or a tenant below it that the call names,
and naming any other is refused with `GrantScopeMismatchException`; a platform policy is attached in the tenant named,
else platform-wide. It reaches the tenants below its tenant unless `includeSubtree` is false, and holds in the
application named, else in every application. Attaching what is already attached changes nothing and returns
`GrantOutcome::UNCHANGED`, attaching it again with the other reach returns `REACH_CHANGED`, and `detach()` finds the
attachment in the same scope and returns how many it removed. Each call is one transaction and one operation, and
dispatches `Resource\PolicyAttached` or `Resource\PolicyDetached` once it commits, only when it changed something,
carrying the resource's type, its key (null for the whole type), the policy, its name, the scope and the actor. Deleting
the policy removes its attachments with its row. An attachment names its resource by type and key, so deleting the
record leaves it in place: detach it when the record goes, with `detachAll($record)`, which detaches every policy
attached to the record in every scope (never a whole type's), or let `authorization:prune` remove the attachments of
records that no longer exist (see [Console commands](#console-commands)).

A check on a record (a model, a pair, or an `AuthorizableResource` whose reference names one) reads the policies
attached to that record and those attached to its type; a check on the type alone (a model class) reads those attached
to the type; a check on any other string, or on no resource, reads none. A record whose key no attachment can name (one
longer than 191 bytes, say) still reads its type's policies, its denies included. Only the attachments that hold in the
tenant and application the check is decided in count, and a policy attached to the record and to its type counts once.
They are read in one query and cached with the rest of the resolution: attaching or detaching refreshes the cached
entries of the resource's type, and editing or deleting any policy refreshes every cached resource-policy entry.

**Principals.** Every allow statement of a resource policy carries `principals`, a non-empty list of selectors naming
whom it applies to:

- `<morph type>:<id>` names a subject by reference: the subject's principal or its identity, by morph class (under
  your morph map) and key, such as `user:17`.
- `role:<role id>` names whoever holds that role in the tenant and application the check is decided in. It follows the
  role hierarchy: with `hierarchy.enabled`, it also names whoever holds a role below that role, as the role's
  permissions and policies reach them; with the hierarchy disabled, only whoever holds that role itself. The role is
  named by its key, never its name, so a role of the same name that another tenant owns, or the role held for another
  application, names no one. The roles a subject holds are read through the resolution cache, as its roles are, so
  once warm a check that matches a role selector reads no role.

A selector is an exact name, never a pattern: a space, `*` or `${` in one is refused, and each part is 1 to 191 bytes. A
deny statement takes no `principals` (refused when the policy is saved) and applies to everyone checking the resource,
wherever the check is decided. A statement that names principals applies only as part of a resource policy, so the rule
is held at every write:

- Attaching an inline policy to a resource, or a policy with an allow statement that names no principals, is refused
  with `ResourcePolicyException`.
- Attaching a policy whose statements name principals to an identity or a role (the trait methods, `GrantService`, a
  sync and a write through a grantee's `policies()` relation alike) is refused with `ResourcePolicyException`.
- Rewriting an attached policy's document so that it breaks the rule for where it is attached is refused with
  `ResourcePolicyException`. `getPolicyName()` and `getStatements()` (the positions, from zero) say what broke it.

**How a check decides with them.** A resource policy's denies count at the deny stage with every other deny, so one that
matches denies everyone, a subject that holds the permission or an allow in its own policies included. An allow whose
principals name the subject is an allow source like any other, and allows the check without the subject holding any
permission; one whose principals do not name the subject is recorded as `principal_mismatch` and counts for nothing, an
unmet authentication requirement on it included. A statement that names principals in a policy attached any other way
(one from the policy store, or supplied through `withPolicies()`) is recorded the same way and never allows. The tenant
stage runs first, so a resource of a tenant outside the subject's scope is still denied as `tenant_scope` before any
policy is read: a resource policy never allows across tenants, and the guardrails and the subject's permission
boundaries are weighed before any allow, so they cap a resource policy's allow as they cap every other. When a subject
is admitted to such a resource through a platform-wide permission, and the check runs at platform scope, a deny attached
to the resource in its own tenant still applies: the resource's owner can lock it against everyone, a support user with
a platform-wide grant included. That tenant's resource-policy allows do not reach the subject there. `withPolicies()`
bypasses the resource's policies with the rest; give a supplied policy a resource with `Policy::withResource('post:42')`
to have it evaluated as one.

The decision, the trace and `explain()` name a resource policy's statements as they name any other, with the resource
the policy is attached to: `post-42-sharing[<its key>]#0 sid="reviewers-read" on "post:42"`. `authorization:why-can`
names its resource as an opaque identifier, so it reads no resource policies; explain a check on the model or the pair
to see them.

### Permission boundaries

A permission boundary caps what a principal or an identity may do, whatever its grants allow. It is a managed policy
set on the grantee through `BoundaryService`: a check about the grantee passes only what the boundary's allow
statements allow, conditions included, and the boundary's deny statements deny as any other deny does. A boundary
grants nothing: a check it lets through still needs an allow statement or a permission held.

```php
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\BoundaryService;

$supportCap = Policy::create([
    'name'     => 'support-read-only',
    'document' => [
        'statements' => [
            ['sid' => 'read', 'effect' => 'allow', 'actions' => ['posts:read', 'comments:read']],
            ['sid' => 'no-exports', 'effect' => 'deny', 'actions' => ['posts:export']],
        ],
    ],
]);

$boundaries = app(BoundaryService::class);

$boundaries->set($user, $supportCap, actor: $admin);                // GrantOutcome::GRANTED, platform-wide
$boundaries->set($user, $tenantCap, tenant: $organisation);         // GRANTED, in the organisation and below it
$boundaries->set($user, $stricterCap, tenant: $organisation);       // REPLACED: one boundary per scope
$boundaries->set($user, $stricterCap, $organisation, false);        // REACH_CHANGED: the organisation alone
$boundaries->remove($user, tenant: $organisation, actor: $admin);   // true: it had one there

$user->givePermission('posts:update');

Authorization::for($user)->can('posts:update', $post); // false: the boundary does not allow it
Authorization::for($user)->can('posts:read', $post);   // false: the boundary allows it, but nothing grants it
```

**Setting one.** `set($grantee, $policy, $tenant, $includeSubtree, $actor)` takes a saved model or a reference with a
type and a key as the grantee, and a stored managed policy. A grantee has at most one boundary per scope, so setting
another where it has one replaces it (`GrantOutcome::REPLACED`), setting the same one again changes nothing and returns
`UNCHANGED`, and setting it with the other reach returns `REACH_CHANGED`. The scope works as a grant's does: a policy a
tenant owns is set in that tenant, or a tenant below it that the call names, and naming any other is refused with
`GrantScopeMismatchException`; a platform policy is set in the tenant named, else platform-wide. A boundary in a tenant
reaches the tenants below it unless `includeSubtree` is false. Boundaries have no application: one holds in every
application. `remove($grantee, $tenant, $actor)` removes the grantee's boundary in the tenant named, else its
platform-wide one, and returns whether it had one there. A boundary caps a principal or an identity, so a grantee that
is never one, a role, a permission or a policy, is refused with `BoundaryException`: a role's holders never read its
boundary. An inline policy is refused with `BoundaryException` too, since it belongs to one grantee and is deleted with
it; a policy whose allows name `principals` is refused with `ResourcePolicyException`, a policy whose row is gone with
`InvalidGrantTargetException`, and a grantee that is unsaved or has no key with `InvalidGranteeException`, each before
anything is written. A boundary is only reported set once its row is read back: a policy deleted while the boundary is
written is refused with `InvalidGrantTargetException`, and a boundary a concurrent change kept from being written with
`UnwrittenGrantException`, which is safe to retry, so no `BoundarySet` is ever dispatched for a boundary that is not
there.

**Which apply.** A check reads the boundaries of the subject's principal and, when it is a separate model, of its
identity, whichever contracts each implements, so a boundary set on a saved model always caps the checks about it. It
reads those that hold in the tenant the check is decided in: the platform-wide one, the tenant's own, and the one of
each tenant above it that reaches down, exactly as grants reach. A tenant-owned resource the tenant stage admits is
decided in its own tenant, so that tenant's boundaries apply; a check that falls back to platform scope reads the
platform-wide ones. With no tenant, only the platform-wide boundaries apply, and with none at all nothing is capped.

**Intersection.** Every boundary that applies must allow the check: a tenant's boundary never replaces the platform-wide
one, and the principal's never replaces its identity's. A check passes only what each of them allows, so setting a
boundary in a tenant can only narrow what the grantee may do there. A boundary with no allow statement that covers the
check denies it as `boundary`, and so does one with no allow statement at all. Each boundary that refuses the check adds
a step naming it to the trace, so `explain()` says which cap refused it.

**What they cap.** Boundaries are weighed after every deny and before any allow, so they cap every allow source alike: a
permission held directly or through a role, an allow in the grantee's own or its roles' policies, a resource policy's
allow naming the subject, and a platform-wide permission that admitted a resource of another tenant. A boundary that
does not allow the check denies it as `boundary` at the `boundary` stage; a boundary statement that cannot be evaluated
denies it as `invalid_policy` there, and one whose document cannot be read denies, as `invalid_policy`, every check
about the grantee in a scope that boundary covers (every check, for a platform-wide boundary), so a broken boundary
never lifts the cap. An allow in a boundary whose authentication requirement is unmet does not allow the check, and the
denial is `boundary`, never `insufficient_authentication`: a step-up never gets past a boundary. `withPolicies()`
replaces the check's policies alone, so the subject's boundaries and permissions still apply: an override never lifts a
cap. `hasPermission()` and `hasRole()` report what is granted, not what a boundary lets through; decide with `can()`,
`check()` or the Gate.

**Lifecycle.** Setting or removing a boundary dispatches `Identity\BoundarySet` (carrying the policy it replaced as
`previous`, when it replaced one) or `Identity\BoundaryRemoved` once the call commits, only when it changed something,
with the grantee, the policy, its name, the scope and the actor. Both implement `IdentityEvent`, and the change takes
effect on the next check in every worker, as a grant's does. Deleting the grantee removes its boundaries, each reported
as removed, and `authorization:prune` removes those of a grantee deleted without its model events, counting them apart
from its grants. A policy in use as a boundary cannot be deleted: the delete is refused with `BoundaryException`, whose
`getGrantees()` lists every grantee it bounds, until each boundary is removed, and the table's foreign key refuses a
delete made past the model. Rewriting a boundary's document so that an allow names `principals` is refused with
`ResourcePolicyException`. A boundary's statements are named in the decision, the trace and `explain()` as any policy's
are, at the `deny` stage for its denies and the `boundary` stage for its allows. A policy reached more than once, such
as one attached to the grantee and set as its boundary too, or the boundary of both the principal and its identity,
plays each part but is named once.

The boundaries are read in one query, apart from the policies, so a custom `PolicyResolver` never drops them, and are
cached with the rest of the resolution: once warm, a check reads none.

### Guardrails

A guardrail caps what anyone may do in a tenant, or across the platform, whatever their grants allow. It is a managed
policy set on a tenant, or on the platform, through `GuardrailService`: a check in its scope passes only what the
guardrail's allow statements allow, conditions included, and the guardrail's deny statements deny as any other deny
does. Where a boundary caps one grantee, a guardrail caps every subject checked in its scope. Like a boundary, a
guardrail grants nothing: a check it lets through still needs an allow statement or a permission held.

```php
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\GuardrailService;

$organisationCap = Policy::create([
    'name'     => 'organisation-cap',
    'document' => [
        'statements' => [
            ['sid' => 'work', 'effect' => 'allow', 'actions' => ['posts:*', 'comments:*']],
            ['sid' => 'no-exports', 'effect' => 'deny', 'actions' => ['posts:export']],
        ],
    ],
]);

$platformCap = Policy::create([
    'name'     => 'platform-cap',
    'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:*', 'comments:*', 'billing:*']]]],
]);

$guardrails = app(GuardrailService::class);

$guardrails->set($organisationCap, $organisation, $platformAdmin); // GrantOutcome::GRANTED, here and below
$guardrails->set($organisationCap, $organisation, $platformAdmin); // UNCHANGED: it is already there
$guardrails->set($platformCap, null, $platformAdmin);              // GRANTED, on the platform

// $post belongs to $organisation, and $editor is checked in it, so both guardrails apply.
$editor->givePermission('billing:view');

Authorization::for($editor)->can('posts:export', $post); // false: organisation-cap denies it, whatever the editor holds
Authorization::for($editor)->can('billing:view');        // false: platform-cap allows it, but organisation-cap does not

$guardrails->remove($organisationCap, $organisation, $platformAdmin); // true: the organisation had it

Authorization::for($editor)->can('billing:view'); // true: platform-cap, the one guardrail left, allows it
```

**Setting one.** `set($policy, $tenant, $actor)` sets a stored managed policy as a guardrail on the tenant named, a
saved model or a reference with a type and a key, or on the platform when the tenant is null. A scope may have any
number of guardrails, and each policy once: setting a policy where it is already a guardrail changes nothing and
returns `GrantOutcome::UNCHANGED`. A policy a tenant owns is set on that tenant or a tenant below it, and naming any
other scope, the platform included, is refused with `GrantScopeMismatchException`; a platform policy can be set on any
scope. Guardrails have no application: one holds in every application. `remove($policy, $tenant, $actor)` removes the
policy's guardrail from the scope named and returns whether the scope had it. An inline policy is refused with
`GuardrailException`, since it belongs to one grantee, a policy whose allows name `principals` with
`ResourcePolicyException`, and a policy whose row is gone with `InvalidGrantTargetException`, each before anything is
written. A guardrail is only reported set once its row is there: a policy deleted while the guardrail is written is
refused with `InvalidGrantTargetException`, and a guardrail a concurrent change kept from being written with
`UnwrittenGrantException`, which is safe to retry, so no `GuardrailSet` is ever dispatched for a guardrail that is not
there.

**Reach.** A guardrail on a tenant holds in that tenant and in every tenant below it in the tenant tree, as a grant
that reaches down does, and a guardrail on the platform holds everywhere. The guardrails of a check are the platform's
and those of the check's tenant and each of its ancestors. The check's tenant is the resource's when the resource has
one, also when a platform-wide permission admitted a resource of a tenant outside the subject's scope and the check is
decided at platform scope, so a tenant's guardrails always cap a check on its resources; otherwise it is the active
tenant. With no tenant, only the platform's guardrails apply, and with none at all nothing is capped.

**Intersection.** Every guardrail that applies must allow the check: a tenant's guardrail never replaces its parent's
or the platform's, so setting one on a tenant can only narrow what anyone may do there. A guardrail with no allow
statement that covers the check denies it as `guardrail` at the `guardrail` stage, and so does one with no allow
statement at all; each guardrail that refuses the check adds a step naming it to the trace (`[guardrail]
organisation-cap[<key>]: refused`). Guardrails are weighed after every deny and before the permission boundaries and
every allow, so they cap every allow source alike: a permission held directly or through a role, an allow in the
subject's own or its roles' policies, and a resource policy's allow naming the subject. `withPolicies()` replaces the
check's policies alone, so the guardrails still apply: an override never lifts a cap. An allow in a guardrail whose
authentication requirement is unmet does not allow the check, and the denial is `guardrail`, never
`insufficient_authentication`. A guardrail statement that cannot be evaluated denies as `invalid_policy` at the
`guardrail` stage, and a guardrail whose document cannot be read denies, as `invalid_policy`, every check in its scope,
so a broken guardrail never lifts the cap. The one check no guardrail caps is that of `authorization:guardrails:manage`
(see **Who may change them** below).

**Who may change them.** Only an actor that holds `authorization:guardrails:manage` from above the scope. The right is
decided through `check()`, so it must be held effectively: every deny and boundary that applies to the actor counts, and
an inactive actor holds nothing. The guardrails never count: a check of exactly `authorization:guardrails:manage`,
whoever makes it, is exempt from the guardrail stage, so no guardrail is read for it, neither its denies nor its allows
apply, and the trace records the stage as `[guardrail] guardrails: exempt`. For a tenant's guardrails it is decided just
below the tenant's parent, so a grant held at an ancestor of the tenant counts when it reaches the tenants below it, a
platform-wide grant counts, and a grant held within the tenant itself never does: a tenant's own administrators never
lift the guardrails their tenant is set under. A tenant with no parent, and the platform, are changed only through a
platform-wide grant. The check keeps the request's application and is recorded and reported like any other decision. An
actor without the right is refused with `GuardrailException`, whose `getReason()` is `not_permitted` and `getActor()`
the actor, before anything is read or written.

```php
// Every scope, the platform included.
$platformAdmin->givePermission('authorization:guardrails:manage');

// The tenants below the organisation, never the organisation itself.
$organisationAdmin->givePermission('authorization:guardrails:manage', tenant: $organisation);
```

So no guardrail can lock the guardrails: one that does not allow `authorization:guardrails:manage`, one that denies it,
and one whose document cannot be read, a platform guardrail included, keep no actor from changing the guardrails of
any scope, and each can still be removed through the service. Nothing else is exempt: every other source's denies, the
actor's permission boundaries and the session caps still apply to the check, and the grant must still reach the scope
from above.

**The permission.** The package declares `authorization:guardrails:manage` in its own permission catalogue, whatever
the application configures: guard-agnostic and under the `authorization` category. `authorization:sync` writes it with
the application's permissions, so it can be granted as any permission can, and a policy naming it validates, even
before the application declares any permission of its own. It is decided through `check()`, exempt from the
guardrails, and the Gate asks the package about it as about any declared permission.

**Lifecycle.** Setting or removing a guardrail dispatches `Guardrail\GuardrailSet` or `Guardrail\GuardrailRemoved` once
the call commits, only when it changed something, with the policy, its name, the scope and the actor. Both implement
`AuthorizationEvent`, and the change takes effect on the next check in every worker. A policy in use as a guardrail can
be neither edited nor deleted: either is refused with `GuardrailException`, whose `getReason()` is `in_use` and whose
`getTenants()` lists every scope it caps, the platform first as null, until each guardrail is removed through the
service, and the table's foreign key refuses a delete made past the model. A guardrail's statements are named in the
decision, the trace and `explain()` as any policy's are, at the `deny` stage for its denies and the `guardrail` stage
for its allows.

The guardrails that apply are read in one query, apart from the policies, so a custom `PolicyResolver` never drops
them, and are cached with the rest of the resolution: once warm, a check reads none.

### Session caps and machines

A session cap bounds what a check may allow, whatever the subject's grants allow. It is a set of actions and action
patterns, not a policy: every cap present must cover the action, so the caps intersect, and an action a cap does not
cover is denied as `session_policy` at the `session` stage. A cap grants nothing: an action it covers is still decided
by every other stage, and needs an allow statement or a permission held. A check can be capped in two ways:

- **The credential's scopes.** The bound `SessionPolicySource` answers the scopes the credential of the check's subject
  carries, such as an API token's or a service account's, or null when it carries no cap.
- **An explicit cap.** `Authorization::capped([...])` returns a scoped manager, as `for()` does, whose checks are capped
  by the actions given, for a delegated or a restricted call.

```php
$user->givePermission('posts:read');
$user->givePermission('posts:edit');

// The credential the user signed in with carries the scopes ['posts:read'].
Authorization::for($user)->can('posts:read'); // true: the scope covers it, and the permission allows it
Authorization::for($user)->can('posts:edit'); // false: session_policy, whatever the user holds

$readOnly = Authorization::for($user)->capped(['posts:read', 'comments:*']);

$readOnly->can('posts:read');                         // true: both caps cover it
$readOnly->can('comments:read');                      // false: the credential's scopes do not cover it
$readOnly->capped(['comments:*'])->can('posts:read'); // false: nested caps intersect
```

**No cap and an empty cap.** No cap at all caps nothing: a source answering null, and a manager never capped, leave
the check to the other stages, and the trace records `[session] session caps: uncapped`. An empty cap allows nothing: a
credential carrying no scopes (`[]`), and `capped([])`, deny every check as `session_policy`.

**Intersection.** The credential's cap and each explicit cap must all cover the action; one never replaces another, so
`capped()` can only narrow what a credential allows, and capping a capped manager narrows it further. A cap covers an
action when one of its patterns is the action, or matches it as a statement's `actions` pattern does (`posts:*`,
`*:read`, `*`). Each cap adds a step to the trace naming it, `covered` or `refused`: `credential` for the credential's
scopes and `capped[1]`, `capped[2]` and so on for the explicit caps, outermost first:

```php
echo Authorization::for($user)->capped(['posts:edit'])->explain('posts:read');
```

```text
DENY (session_policy: a session cap does not allow it) at the session stage.
  [guardrail] guardrails: uncapped
  [boundary] boundaries: uncapped
  [session] credential: covered
  [session] capped[1]: refused
```

**What they cap.** The session stage runs after every deny, the guardrails and the permission boundaries, and before
any allow, so a session cap caps every allow source alike: a permission held directly or through a role, an allow in
the subject's own or its roles' policies, and a resource policy's allow naming the subject. `withPolicies()` replaces
the check's policies alone, so the caps still apply. An action a cap refuses is never a step-up: the denial is
`session_policy`, never `insufficient_authentication`. A cap has no deny statements, so it adds nothing to the deny
stage, and a deny decides before any cap is weighed. The credential's scopes cap every check about the subject: the
Gate, the `permission:` and `authorize:` middleware, the permission directives and `permissionsFor()` included.
An explicit cap caps only the checks made through the manager `capped()` returned, so the Gate and the middleware never
see it. `hasPermission()`, `hasRole()`, the `role:` middleware and `@role` report what is granted, not what a cap lets
through, so a cap never stops a role check.

**The source.** A class implementing `SineMacula\Laravel\Authorization\Contracts\SessionPolicySource` answers
`scopesFor(Subject $subject): ?array`, the scopes as a list of strings or null. It is asked once for each check that
gets past the subject, resource and tenant stages and whose policies, guardrails and boundaries could then be read; a
check denied as `invalid_policy` before then asks no source. It is given the check's `Subject`, also one named with
`for()`, so answer null for a subject the credential does not belong to. A source that throws aborts the check, so no
decision is made.

```php
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;

final class CredentialScopes implements SessionPolicySource
{
    public function __construct(private CurrentCredential $credential) {}

    public function scopesFor(Subject $subject): ?array
    {
        return $this->credential->isHeldBy($subject->subject) ? $this->credential->scopes() : null;
    }
}
```

Name it in `config/authorization.php`, where it is checked at boot and built per request or job, or bind the contract
yourself. The default, `NoSessionPolicy`, answers null for every subject, so no credential caps a person's checks. Under
the suite, `sinemacula/laravel-iam` binds a source that reads the scopes of the caller's credential from
`laravel-authentication`.

```php
'session' => [
    'source' => App\Authorization\CredentialScopes::class,
    'scopes' => [],
],
```

**The scope map.** By default a scope names an action or an action pattern itself, so a credential carrying
`posts:read` and `comments:*` is capped to those. `authorization.session.scopes` maps a scope to the action patterns it
stands for instead; a scope listed on its own names itself, as one the map does not name does:

```php
'scopes' => [
    'posts:read',                                // names itself
    'editor'  => ['posts:*', 'comments:read'],   // stands for both patterns
    'billing' => ['invoices:*'],
],
```

The map is checked when the application boots: each scope must be a string that is not empty, named once and mapped to
a list of one pattern or more, and every pattern, a scope listed on its own included, must cover at least one
permission the package or the application declares, as a policy's `actions` must. A bad map is refused with
`InvalidAuthorizationConfigException`. To check it, the permission enums and providers are read at boot, but only when
the map names a scope, and the package's tables never are. A scope that is a whole number, such as `42`, can only be
listed on its own, since PHP turns such a key into an integer.

**Machines.** A model implementing `SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine` is a machine
principal: a service account, an integration, a client acting for no person. Its grants work as a person's, capped by
its credential's scopes, which it must have: when the source answers null for a machine, the check is denied as
`session_policy` (`[session] credential:missing: refused`), whatever it holds, and `capped()` never stands in for the
missing scopes, it only narrows them further. With the default source, a machine is therefore allowed nothing.

```php
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;

class ServiceAccount extends Model implements AuthorizableIdentity, AuthorizableMachine
{
    use HasAuthorization;
}
```

A machine is never treated as a person. A subject's identity contributes its roles, its permissions and the allow
statements of its policies only when the subject and its identity are both machines or neither is, so a person's grants
never reach a machine principal acting for them, and a machine's grants never reach a person; a resource policy naming
the identity by reference does not name such a principal either. What only narrows a check still holds across the two:
the deny statements of the identity's policies, its own and its roles', still deny the principal, the identity's
permission boundaries cap it, and an inactive identity denies it everything. An identity policy that cannot be read
therefore denies the check as `invalid_policy` whatever the identity's kind.

**The scope registry.** `SineMacula\Laravel\Authorization\Contracts\ScopeRegistry` answers which scopes a credential may
carry, so that one is issued only scopes naming real permissions: `isValid($scope)` and `scopes()`. The package ships
`CatalogueScopeRegistry`, backed by the permission catalogue and the scope map, and binds none. It accepts every scope
the map names and every other scope that names a declared permission, the package's own included, or a pattern
covering at least one; `scopes()` lists the mapped scopes, then the declared permissions. Bind it where your
credentials' scopes are issued; under the suite, `sinemacula/laravel-iam` binds it as `laravel-authentication`'s scope
registry:

```php
use SineMacula\Laravel\Authorization\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authorization\Support\CatalogueScopeRegistry;

$this->app->bind(ScopeRegistry::class, CatalogueScopeRegistry::class);

app(ScopeRegistry::class)->isValid('editor');     // true: the map names it
app(ScopeRegistry::class)->isValid('posts:*');    // true: it covers a declared permission
app(ScopeRegistry::class)->isValid('payroll:*');  // false: it covers none
```

The registry reads the catalogue the first time it is asked, and keeps it for its lifetime. The caps read nothing from
the database: a check a cap covers runs the same queries as one with no cap, and one a cap refuses never reads the
permissions.

### How a check is decided

`Authorization::check()` is the one decision behind `can()`, `cannot()`, `any()`, `all()`, `authorize()`, `explain()`,
the Gate, a Laravel policy class deciding through the package's trait, the `permission:` and `authorize:` middleware and
the permission directives (`role:` and `@role` check membership only, so no stage applies to them, guardrails and
boundaries included). It runs these stages in order, and the first that decides ends it; no allow
is weighed before every deny and every cap has run:

| Stage       | What it weighs                                                                                                    | Denies as                                                     |
|-------------|-------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| `subject`   | Whether there is a subject, and whether it and its identity are active                                            | `subject_unresolved`, `subject_inactive`                      |
| `resource`  | Whether the resource argument can be identified                                                                   | `resource_unresolved`                                         |
| `tenant`    | Whether the resource's tenant is within the check's, or a platform-wide grant of the permission admits it         | `tenant_scope`                                                |
| `deny`      | Every deny: the subject's, its identity's of either kind, their roles', the resource's, guardrails', boundaries'  | `explicit_deny`, `invalid_policy`                             |
| `guardrail` | Every guardrail on the check's tenant, its ancestors and the platform must allow the check, unless it is exempt   | `guardrail`, `invalid_policy`                                 |
| `boundary`  | Every permission boundary of the principal and of its identity that applies must allow the check                  | `boundary`, `invalid_policy`                                  |
| `session`   | Every session cap, the credential's scopes and each set of actions `capped()` was given, must cover the action    | `session_policy`                                              |
| `allow`     | Every allow statement that applies to the subject, a resource policy's naming it included, then a permission held | `invalid_policy`                                              |
| `implicit`  | Nothing allowed                                                                                                   | `insufficient_authentication`, `condition_failed`, `no_match` |

Within each stage, the policies are assessed in a fixed order (name, stored key, resource, then document) and each
statement by its position, so the decision and its trace never depend on the order the policies were read in. The
decision records the stage that decided it and every step it took: each statement assessed, each guardrail and boundary
that refused the check as `refused`, naming it, each session cap as `covered` or `refused`, naming it, a cap stage that
capped nothing as `uncapped`, the guardrail stage as `exempt` for a check of `authorization:guardrails:manage`, whose
deny stage weighs no guardrail's denies either, and the permission step, which is asked only when no allow statement
matched and none was invalid:

```text
DENY (boundary: a permission boundary does not allow it) at the boundary stage.
  [deny] support-read-only[<key>]#1 sid="no-exports": not_applicable
  [guardrail] guardrails: uncapped
  [boundary] support-read-only[<key>]#0 sid="read": not_applicable
  [boundary] support-read-only[<key>]: refused
```

The full contract, and why a deny and a cap always win, is in [Evaluation order and deny
precedence](docs/design/evaluation-order-and-deny-precedence.md).

#### Permissions held and the resources they reach

A permission held, directly or through a role, is one allow source among the others, weighed at the `allow` stage
alone: never before every deny, guardrail, boundary and session cap has let the check through, and only once no allow
statement matched. Nothing answers a check from the permissions before then, so a deny or a cap always beats a
permission held, a `*` included. The permission step names the held permission that allowed, as it was granted, so a
wildcard says which pattern let the action through:

```text
ALLOW at the allow stage.
  [guardrail] guardrails: uncapped
  [boundary] boundaries: uncapped
  [session] session caps: uncapped
  [allow] permission "posts:*": held
```

The subject's own permissions are read first and its granting identity's only when none of the subject's covers the
action; within that grantee, the action itself is named when held, else the first covering pattern in byte order, so
the trace is the same whatever order the grants were read in.

A permission allows a check on a resource only when the grant it came from reaches the resource:

- A resource of a tenant: a grant made in that tenant, a grant made in one of its ancestors that reaches the tenants
  below it (`includeSubtree`, the default), or a platform-wide grant. The resource must still be within the active
  tenant, or below it, to be decided at all; one of any other tenant is denied as `tenant_scope` unless a platform-wide
  grant of the permission admits it, and then only platform-wide grants count, while that tenant's guardrails and the
  denies attached to the resource there still apply.
- A resource with no tenant, a type alone, an opaque identifier or no resource: the grants that hold in the active
  tenant, its own, its ancestors' that reach below and platform-wide ones; with no active tenant, platform-wide grants
  alone.

A grant limited to an application counts only in checks on that application, and an expired grant counts nowhere, for
every kind of resource. A permission held in tenant A therefore allows actions on resources in A and, when the grant
reaches its subtree, in the tenants below A, and never in a sibling of A or in another tree.

The grants are resolved for each scope a check is decided in and kept per scope (tenant and application) in the
resolution cache, so the reach costs no query of its own: once each scope is warm, checks on its resources read none.

The Gate, the `permission:` and `authorize:` middleware and the permission directives all decide through `check()`,
and the bulk checks and `permissionsFor()` decide as it does, so they answer what the decision allows, with every
stage above. `hasPermission()` (and its alias `hasPermissionTo()`), `getPermissions()` and `assertHasPermission()` keep
their meaning: they report what is granted in the current scope and decide nothing, so a permission held that a deny or
a cap refuses is still reported as held.

### Writing policies

A policy document is a `version` (1, the default) and a list of `statements`. Each statement takes:

| Key             | Holds                                                                                     |
|-----------------|-------------------------------------------------------------------------------------------|
| `sid`           | Optional: 1 to 64 letters, digits, `_`, `-`, `:` or `.`, unique within the policy         |
| `effect`        | `allow` or `deny`                                                                         |
| `actions`       | The action patterns the statement names                                                   |
| `not_actions`   | Instead of `actions`: the statement names every action none of these patterns matches     |
| `resources`     | Optional: the resource patterns the statement names                                       |
| `not_resources` | Instead of `resources`: the statement names every resource none of these patterns matches |
| `principals`    | An allow in a resource policy only: whom it applies to, by reference or `role:<role id>`  |
| `conditions`    | Optional: a map of operator to context key path to operand, every test of which must hold |

A statement takes exactly one of `actions` and `not_actions`, and at most one of `resources` and `not_resources`; each
is a non-empty list of non-empty strings. Without either resource list a statement names every resource and a check that
names none. `not_resources` still scopes the statement to resources, so it never covers a check without one. The `sid`
names the statement in the decision and the trace, and never changes how it is evaluated. `principals` belongs to the
allow statements of a policy attached to a resource, and to nothing else (see [Resource-based
policies](#resource-based-policies)).

Conditions name the operator first, then each context key it tests, as a dot path into the check's context:

```php
'conditions' => [
    'ip_in'        => ['request.ip' => ['10.0.0.0/8', '2001:db8::/32']],
    'eq'           => ['resource.owner.id' => '${subject.id}'],
    'any_value_in' => ['input.groups' => ['editors', 'admins']],
    'null'         => ['input.post.archived_at' => true],
    'before'       => ['environment.time' => '2026-12-31T23:59:59Z'],
],
```

| Operator                        | Operand                               | Holds when the context value                                   |
|---------------------------------|---------------------------------------|----------------------------------------------------------------|
| `eq`, `neq`                     | one scalar                            | is a scalar or null that is, or is not, strictly equal to it   |
| `in`, `not_in`                  | a non-empty list of scalars           | is a scalar or null that is, or is not, in the list (strictly) |
| `starts_with`, `ends_with`      | a non-empty string                    | is a string that starts, or ends, with it                      |
| `like`                          | a non-empty glob                      | is a string that matches it                                    |
| `gt`, `gte`, `lt`, `lte`        | a number or numeric string            | is a number above, at least, below or at most it               |
| `before`, `after`               | a time                                | is a time before, or after, it                                 |
| `between`                       | a pair of times                       | is a time within them, inclusive                               |
| `bool`                          | `true`, `false`, `1`, `0`, `'true'` … | has the same boolean meaning                                   |
| `null`                          | `true` or `false`                     | `true`: is missing or null; `false`: is present and not null   |
| `ip_in`, `ip_not_in`            | an address or range, or a list        | is an IPv4 or IPv6 address within any, or within none, of them |
| `any_value_in`, `all_values_in` | a non-empty list of scalars           | is a list with some element, or only elements, in it           |

- A condition key is a dot path read one segment at a time, never a literal key: `input.post.status` reads the
  `status` of the `post` of `input`, and a caller passing `['post.status' => 'draft']` supplies a key named
  `post.status`, which the path never reaches.
- A key the context lacks makes a test undecidable: an allow does not apply and a deny does. `null` decides a missing
  key instead, and any other operator but `authentication_requirement` takes the `_if_exists` suffix (`ip_in_if_exists`,
  `eq_if_exists`), under which a missing key passes; everything else is decided as without it.
- A context value that is not an IP address is undecidable for `ip_in` and `ip_not_in`, so `ip_not_in` never treats
  an unreadable address as outside every range. PHP's `FILTER_VALIDATE_IP` decides what an address is, on every
  platform, so a zone id (`fe80::1%en0`) or an IPv4 part with a leading zero (`010.0.0.1`) is not one.
- A NUL byte is refused in a `starts_with`, `ends_with`, `like` or time operand and in a resource pattern, and a
  context value holding one is undecidable for them and for `ip_in` and `ip_not_in`. A `${…}` value holding one leaves
  a resource pattern unresolved.
- `any_value_in` and `all_values_in` need the context value to be a list, such as a token's scopes. An empty list never
  passes `all_values_in`.
- `eq` and `neq` never take a list: use `in` or `not_in`. String operands may use `${…}` interpolation; list operands
  are literal. A reference reads the same dot paths a condition key does, through the same resolver (`${request.ip}`,
  `${input.post.id}`, `${subject.id}`, `${resource.owner.id}`); a missing, null or non-scalar value leaves it
  unresolved, which makes the test undecidable.
- `authentication_requirement` tests only the reserved key `authentication`, and its operand is a requirement rather
  than a value: see [Authentication requirements](#authentication-requirements).

A policy is checked whenever it is saved, through the model or `PolicyService`, and refused with every limit,
context-key and catalogue reason at once, or, for a malformed document, the first structural fault found and any limit
it breaks. The reasons are a malformed document; a condition key or `${…}` reference that the context key catalogue
does not declare; a condition on a key that may not be tested; a condition on, or a `${…}` reference to, an assurance
key; an operator that does not suit the key's type; an
`actions` or `not_actions` pattern that matches no declared permission; or a document over the limits in
`policies.limits` (`AUTHORIZATION_POLICY_DOCUMENT_BYTES`, `_STATEMENTS`, `_CONDITIONS` and `_PATTERN_LENGTH`: 64 KiB of
JSON, 100 statements, 50 key tests a statement and 512 characters a pattern or string operand). The limits are checked
again when a stored policy is read, and the resolution cache keys cached policies by the limits they were checked
under, so lowering one makes the stored policies over it deny as `invalid_policy` until they are fixed. To find them, or
to check policy files before you deploy them:

```bash
php artisan authorization:policy:validate --database
php artisan authorization:policy:validate policies/
```

The [condition semantics note](docs/design/wildcard-and-condition-semantics.md) has every operand and edge case.

### The check's context

A policy's conditions and `${…}` references read the check's context: nested namespaces, each key a dot path within
one. A namespace is built only when a statement under evaluation reads it, through a condition key or a reference, and
at most once a check, so a check whose policies read nothing of the request never looks at it.

| Namespace        | Keys                            | Comes from                                                  |
|------------------|---------------------------------|-------------------------------------------------------------|
| `authentication` | `guard`, `user_id`, `user_type` | The bound `AuthenticationContext`                           |
| `request`        | `ip`, `method`, `route`         | The bound `RequestContext`, only in a routed request        |
| `environment`    | `time`                          | The bound `EnvironmentContext`                              |
| `subject`        | `id`, `type`, `tenant.*`, more  | The check's subject and its attribute provider              |
| `resource`       | `id`, `type`, `tenant.*`, more  | The check's resource and its attribute provider             |
| `input`          | The keys you declare            | What the caller passes                                      |
| Any other        | The keys its owner declares     | A `ContextSource` listed in `authorization.context.sources` |

The shipped defaults supply what Laravel knows. `authentication` holds the default guard's name and, when someone is
signed in on it, the user's key as a string and morph type (the morph alias, or the class name); with nobody signed in
only `guard` is present. `request` holds Laravel's `ip()`, resolved through your trusted proxies, the method and the
route's name, and only once the request has been routed: in a queued job or a console command the namespace is absent,
so every `request` key is missing. `environment.time` is `now()` in UTC as `Y-m-d\TH:i:s\Z`, fixed the first time the
check reads `environment`, then kept for the rest of the check, so `Carbon::setTestNow()` freezes it in tests.
`subject` and `resource` describe who the check is about and what it is on; see [Subject and resource
attributes](#subject-and-resource-attributes).

What the caller passes lands under `input`, and only there: the `$context` of `check()`, `can()`, `cannot()`, `any()`,
`all()`, `authorize()`, `explain()`, `canEach()`, `filterAuthorized()`, each `CheckInput` of `checkMany()`,
`permissionsFor()` and a policy class's `decide()`, the string-keyed and associative arguments of a Gate check,
and the context of `assertCan()` and `assertCannot()`. A caller can never supply a trusted value:

```php
Authorization::can('posts:publish', $post, ['post' => ['status' => 'draft']]); // input.post.status
Gate::allows('posts:publish', [$post, ['post' => ['status' => 'draft']]]);     // input.post.status
Authorization::can('posts:delete', $post, ['request' => ['ip' => '10.0.0.1']]); // input.request.ip, never request.ip
```

Every key a policy reads must be declared in the context key catalogue, with a type, or the policy is refused when it
is saved. The package declares its own keys, those in the table above, and your attribute providers declare theirs;
declare the rest, `input`'s included, in `config/authorization.php`, each path within its namespace:

```php
'context' => [
    'keys' => [
        'input'  => [
            'post.status'      => 'string',
            'post.tenant'      => 'string',
            'post.archived_at' => 'time',
            'groups'           => 'list',
        ],
        'tenant' => ['plan' => 'string', 'seats' => 'number'],
    ],
    'sources' => [App\Authorization\TenantContext::class],
],
```

or register them from a service provider, which is how a package adds its namespace:

```php
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;

public function boot(): void
{
    $keys = $this->app->make(ContextKeyCatalogue::class);

    $keys->register('device', ['trusted' => 'bool', 'platform' => 'string']);
    $keys->declare('device.enrolled_at', ContextKeyType::TIME);
}
```

A key's type decides the operators a condition may test it with; `null` suits every type, and an `_if_exists` form
follows its operator. A key may also be declared untestable (`declare($path, $type, isTestable: false)`), so that a
reference may read it but no condition may test it. The assurance keys of the authentication context are always
untestable, and not even a reference may read them (see [Assurance keys](#assurance-keys)). Declaring a key again
with another type is refused, and so is a key under `subject` or `resource`, whose keys come only from the package and
the attribute providers. The type is checked when the policy is written; a value of the wrong type at evaluation is
still undecidable.

| Type     | Operators                                                       |
|----------|-----------------------------------------------------------------|
| `string` | `eq`, `neq`, `in`, `not_in`, `starts_with`, `ends_with`, `like` |
| `number` | `eq`, `neq`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`           |
| `bool`   | `eq`, `neq`, `bool`                                             |
| `time`   | `before`, `after`, `between`                                    |
| `ip`     | `eq`, `neq`, `in`, `not_in`, `ip_in`, `ip_not_in`               |
| `list`   | `any_value_in`, `all_values_in`                                 |

An application adds a namespace with a class implementing `SineMacula\Laravel\Authorization\Contracts\ContextSource`,
listed in `authorization.context.sources` and resolved from the container. It names its namespace and returns its
values, nested by key; an empty array leaves the namespace absent:

```php
use SineMacula\Laravel\Authorization\Contracts\ContextSource;

final class TenantContext implements ContextSource
{
    public function __construct(private CurrentTenant $tenant) {}

    public function namespace(): string
    {
        return 'tenant';
    }

    public function values(): array
    {
        $tenant = $this->tenant->get();

        return $tenant === null ? [] : ['plan' => $tenant->plan, 'seats' => $tenant->seats];
    }
}
```

A source that does not implement the contract, one that claims a reserved namespace (`authentication`, `request`,
`environment`, `input`, `subject` or `resource`), two sources claiming one namespace, and a source claiming a namespace
your `AuthenticationContext` adds are refused at boot. The trusted namespaces are replaced only by rebinding
their own contracts. To supply `authentication` from your authentication layer, along with any namespace it adds
beside it such as `mfa` or `sso`, bind your own `AuthenticationContext`. Its `namespaces()` lists every namespace it
supplies and `values()` returns their values keyed by namespace; declare the keys of any namespace it adds in the
catalogue. It is resolved at boot, which refuses a namespace it adds that is not a name, is reserved or is listed twice.
Bind it in a service provider's `register()`:

```php
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;

$this->app->scoped(AuthenticationContext::class, App\Authorization\SessionAuthenticationContext::class);
```

`RequestContext` and `EnvironmentContext` are rebound the same way. The defaults are built per request or job, so queue
workers and Octane read the request and the user they are serving; a binding of your own is kept as you bound it.

### Subject and resource attributes

The `subject` namespace describes who the check is about and `resource` what it is on. The package declares and
supplies their built-in keys, every one a string:

| Key                                          | Holds                                                                         |
|----------------------------------------------|-------------------------------------------------------------------------------|
| `subject.id`                                 | The subject's key (`getKey()` for a model)                                    |
| `subject.type`                               | The subject's morph type (the morph alias, or the class name)                 |
| `subject.tenant.type`, `subject.tenant.id`   | The morph type and key of the tenant the subject resolver gave the subject    |
| `resource.id`                                | The record's key, for a check on one record                                   |
| `resource.type`                              | The resource's type, for a record or a type alone                             |
| `resource.tenant.type`, `resource.tenant.id` | The resource's tenant, from the resource tenant resolver or its reference     |

A check with no subject has no `subject` namespace, and one without a resource has no `resource` namespace; the tenant
keys are missing when there is no tenant. A model, or a `(type, id)` pair, names a record and has both `resource.id`
and `resource.type`. A model class (`Post::class`) names a type alone, so only `resource.type` is present. Any other
string is an opaque identifier with neither: `'reports:42'` is never split at its `:`.

Every other attribute comes from a provider, registered for one morph type. A resource attribute provider implements
`SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider`: `attributes()` declares each attribute, a dot
path within `resource`, with its type, and `values()` returns a record's values, nested by key. It is given the
record's reference and the model the check was given, so it can read the model rather than query for it. A model that
implements `AuthorizableResource` is handed on too, when the reference it returns names one record and carries no
model. The model is null when the check named the record some other way, such as a `(type, id)` pair or an
`AuthorizableResource` that is not a model:

```php
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

final class PostAttributes implements ResourceAttributeProvider
{
    public function attributes(): array
    {
        return ['status' => 'string', 'owner.id' => 'string'];
    }

    public function values(ResourceReference $resource, ?Model $model): array
    {
        $post = $model ?? Post::query()->find($resource->id);

        return $post === null ? [] : ['status' => $post->status, 'owner' => ['id' => (string) $post->user_id]];
    }
}
```

A subject attribute provider implements `SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider` the same
way, its `values()` given the subject:

```php
use SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider;

final class UserAttributes implements SubjectAttributeProvider
{
    public function attributes(): array
    {
        return ['department' => 'string', 'clearance' => 'number'];
    }

    public function values(object $subject): array
    {
        return ['department' => $subject->department, 'clearance' => $subject->clearance_level];
    }
}
```

Register each under the morph type it serves (the morph alias, or the class name) in `config/authorization.php`. They
are resolved from the container:

```php
'attributes' => [
    'resources' => ['post' => App\Authorization\PostAttributes::class],
    'subjects'  => ['user' => App\Authorization\UserAttributes::class],
],
```

A policy then reads them like any other key, through a condition or a `${…}` reference:

```php
'conditions' => [
    'eq' => ['resource.owner.id' => '${subject.id}'],
    'in' => ['resource.status' => ['draft', 'review']],
],
```

What a provider declares enters the key catalogue at boot. A class that does not implement its contract or cannot be
resolved, a provider declaring a built-in (`id`, `type` or anything under `tenant`), a provider declaring a key under
another key it declares (`owner` and `owner.id`), and two providers declaring one key with different types are refused
at boot; two providers may declare one key alike. Only the keys a provider declares are exposed: a value it returns
for any other key is dropped, and so is everything under a declared key. A declared key holds a scalar or `null`, or,
for a `list`, a list of them; a map, or a list under any other type, stays present but cannot be read into, so a test
of the key is undecidable, `${…}` does not resolve it and none of the keys under it can be read. A value of the wrong
type is undecidable when the policy is evaluated, as for any context value.

A namespace is built the first time a statement under evaluation reads any of its keys, built-in or not, and at most
once a check, so a provider is asked at most once a check, and not at all by a check whose policies read nothing of
its namespace. Nothing is kept for the next check. The resource provider is asked only about a record: a type alone,
an opaque identifier, no resource and a type with no provider leave only the built-ins that apply, so an attribute key
is missing. A missing key makes its test undecidable, so an allow on it does not apply and a deny does, unless it is
tested with `null` or an `_if_exists` operator.

A provider that throws aborts the check rather than letting it be decided with the attribute missing: `check()`,
`can()`, `authorize()`, the Gate and every other entry point throw
`SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed`, with the provider's exception as its previous
one. No decision is made, so no decision event is dispatched and the check records no last decision. The message names
the provider's class and the namespace, never an attribute value, and nothing the provider returned or threw reaches a
decision, an event or the trace.

### Authentication requirements

An allow can require that the subject's session was authenticated strongly enough, and recently enough, for the
action. State it with the `authentication_requirement` operator on the reserved key `authentication`:

```php
[
    'sid'        => 'refund-after-step-up',
    'effect'     => 'allow',
    'actions'    => ['invoices:refund'],
    'conditions' => [
        'authentication_requirement' => [
            'authentication' => [
                'multifactor'        => ['max_age' => 900],
                'phishing_resistant' => [],
            ],
        ],
        'eq' => ['resource.tenant.id' => '${subject.tenant.id}'],
    ],
],
```

The operand maps one or more parts to their options, `{}` (an empty array) for none:

| Part                      | Requires                                                    | Options                         |
|---------------------------|-------------------------------------------------------------|---------------------------------|
| `additional_verification` | A verification beyond the sign-in, such as a password again | `max_age`                       |
| `multifactor`             | Multifactor authentication                                  | `max_age`                       |
| `phishing_resistant`      | A phishing-resistant proof, such as a passkey               | `max_age`                       |
| `assurance_level`         | An assurance level of at least `min`                        | `min` (required), and `max_age` |

`max_age` is a whole number of seconds, at least 1: the proof that meets the part must be no older. `min` is a string
that is not empty or blank, an assurance level your checker knows, and no longer than the `pattern_length` limit. Every
part named must be met, and the requirement is one test judged whole, so it counts as one key test against the
`conditions` limit. The policy is refused when it is saved if the requirement is on any key but `authentication`, names
no part, an unknown part or an unknown option, gives a `max_age` that is not a whole number of at least 1, or gives
`assurance_level` no `min`. There is no `authentication_requirement_if_exists`. `authentication` is not read from the
context here, so the requirement needs no key declared in the catalogue.

#### The requirement checker

A requirement is judged by the bound
`SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker`, given the requirement and the check's
`Subject`. The checker fetches the proofs of the subject's `session` itself, so the newest proof that meets each part
is judged, never separate scalar tests that a fresh weak proof and a stale strong one could meet together; the package
never passes proofs or `amr` in. It answers with a `RequirementResult`: met, with the instant until which the
requirement stays met when it knows one, or unmet, with the parts that are not met:

```php
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;

final class SessionProofChecker implements AuthenticationRequirementChecker
{
    public function __construct(private SessionProofs $proofs) {}

    public function check(AuthenticationRequirement $requirement, Subject $subject): RequirementResult
    {
        $proofs = $this->proofs->of($subject->session);
        $unmet  = array_values(array_filter(
            $requirement->names(),
            fn (string $part): bool => !$proofs->meets($part, $requirement->maxAge($part), $requirement->minimumLevel),
        ));

        return $unmet === []
            ? RequirementResult::met($proofs->metUntil($requirement))
            : RequirementResult::unmet($unmet);
    }
}
```

Name it in `config/authorization.php`, where it is checked at boot and built per request or job, or bind the contract
yourself:

```php
'requirement_checker' => App\Authorization\SessionProofChecker::class,
```

The default, `RefusingRequirementChecker`, finds every part of every requirement unmet, so until you bind a checker an
allow that states a requirement never applies. The checker is asked afresh for every requirement of every check, and
nothing it answers is remembered. A met result whose instant has already passed counts as unmet, every part with it. An
unmet result keeps only the parts the requirement names, and one that names none of them leaves every part unmet. A
checker that throws makes the test undecidable, so an allow it guards does not apply and a deny it guards does; the
failure is logged at debug level by the checker's class and the exception's class alone, never with the exception's
message or anything the checker held.

#### Sessions

`Subject::$session` is the session the checker judges. The shipped resolver sets it to the current request's session
id only when that session signed in that very user: the guard is a `SessionGuard` using the request's session, and the
session's login key names the user, compared strictly as strings. That holds for the user signed in on its guard,
including when the Gate hands it that same user. It is null for a user set on the guard without the session
(`Auth::once()`, `onceUsingId()`, `onceBasic()`, the `auth.basic.once` middleware or `setUser()`), whatever login the
session holds; for a user a token or request guard returns; for a subject you name (`Authorization::for($user)`, or
`Gate::forUser()` with another user); and outside a session (a console command, a queued job, a request without a
started session). A subject without a session meets no requirement: every part is unmet and the checker is not asked.
A resolver of your own sets `session` to whatever its checker knows the proofs by, and only for the user that session
authenticated. Your checker should still confirm the proofs it finds belong to `$subject->subject`.

#### The decision and the exception

A check is denied as `insufficient_authentication` when no deny applies, no invalid policy blocks it, every permission
boundary allows it, nothing else allows it (no other allow statement and no permission held), and at least one allow
statement names the action and the resource with every other condition holding and only its requirement unmet. It ranks
above `condition_failed`, and deny precedence always wins. A requirement that cannot be checked is undecidable, not
unmet, so its statement is no candidate and, alone, leaves the check `condition_failed`. The decision's `requirements`
lists each such statement's requirement with its unmet parts, as an `UnmetRequirement`: they are alternatives, any one
of which met would allow the check. On a deny statement an unmet requirement is a test that does not hold, so the deny
does not apply, while one that cannot be checked applies it, as any undecidable test does. The trace records the
requirement as the key `authentication`, with whether it held, and never a proof.

`authorize()`, and the `permission:` and `authorize:` middleware, throw
`SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException` for it. It extends Laravel's
`Illuminate\Auth\Access\AuthorizationException`, not the package's, so a handler that maps the package's denials does
not catch it, and an application that maps it to nothing still answers `403`. It carries the reason code
(`getReason()`) and the candidate requirements, once each (`requirements()`); never a policy, a statement, the trace or
a proof. Its message is the generic `authorization::authorization.denied` line, as every denial's is, so a step-up
prompt is the application's own to word (see [Localisation](#localisation)). Like any denial, it is recorded as the
last decision and fires `AuthorizationFailed` first. Map it to your step-up response, such as RFC 9470's
`insufficient_user_authentication` challenge:

```php
// bootstrap/app.php
use Illuminate\Foundation\Configuration\Exceptions;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;

->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->render(fn (InsufficientAuthenticationException $exception) => response()->json(
        [
            'message'      => __('Confirm your identity to continue.'),
            'requirements' => array_map(
                fn (UnmetRequirement $candidate): array => $candidate->toArray(),
                $exception->requirements(),
            ),
        ],
        401,
        ['WWW-Authenticate' => 'Bearer error="insufficient_user_authentication"'],
    ));
})
```

A decision that read a requirement is reused only while it still holds. `Authorization::lastDecision()` returns it only
in the session of the request that recorded it, whichever subject it was about (one named with `for()` included), and
until the earliest instant a met requirement it read stops being met. The decision's own `$decision->freshness` keeps a
fingerprint of the session it was made in (its SHA-256 hash, never the session id, so the decision stays safe to log)
and that instant, and `isFreshFor($session)` says whether it may be reused in a session. Nothing else keeps a decision:
`can()`, `cannot()`, `any()`, `all()`, `checkMany()`, `canEach()`, `filterAuthorized()`, the Gate, a policy class's
`decide()`, the Blade directives and `permissionsFor()` decide afresh every time, and the resolution cache holds
grants and policies, never decisions.

#### Under the suite

With `sinemacula/laravel-iam`, the checker is bound to `laravel-mfa`'s requirement check, and the `mfa` namespace comes
through the authentication context. `laravel-iam` maps `InsufficientAuthenticationException` to MFA's step-up
exception, which owns the RFC 9470 response and the mapping from assurance levels to `acr` values, so only one package
produces step-up responses and the application maps nothing itself. This package never reads MFA's tables or a
session's proofs, never treats `mfa` in `amr` as multifactor authentication, and never decides who must use MFA.

#### Assurance keys

An assurance level, the time of authentication or the seconds since a step-up can sit in the context for your own code
to show or log, but a policy may not decide on them: separate scalar tests could be met by a fresh weak proof and a
stale strong one together, which the requirement checker never allows. A key of `authentication`, or of a namespace
your `AuthenticationContext` adds beside it (such as `mfa`), is an assurance key when any segment of its path after the
namespace is `assurance_level`, `auth_time`, `seconds_since_step_up`, `last_verified_at`, `verification_age`,
`multifactor` or `amr`, so `authentication.amr` and `mfa.multifactor.enabled` both are. The package declares none of
them, and whatever the declaring context or configuration says, the catalogue declares each one untestable. A policy
with a condition on one, or a `${…}` reference to one in an operand or a resource pattern, is refused when it is
saved, with a reason that points at `authentication_requirement`.

### Listening to events

Every event the package dispatches implements `SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent`, so one
listener, or one audit mapper registration, covers them all. The grant and boundary events also implement
`IdentityEvent` and name their `grantee`; the guardrail events name no grantee, so they implement the marker alone:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;

Event::listen(static function (AuthorizationEvent $event): void {
    // Every role, permission, policy, grant and guardrail change, every override and every decision.
});

Event::listen(static function (RoleDeleted $event): void {
    $event->role;               // Reference: the role's morph type and key
    $event->grantees;           // a Reference to every grantee that held it
    $event->operation->actor;   // the actor the caller passed, or null
    $event->operation->id;      // the same for every event of the call
});
```

The change events (roles, permissions and policies created, updated and deleted; permissions granted to and revoked from
a role; roles, permissions and policies granted to, revoked from and re-dated on a grantee; policies attached to and
detached from a resource, `Resource\PolicyAttached` and `Resource\PolicyDetached`; permission boundaries set and
removed, `Identity\BoundarySet` and `Identity\BoundaryRemoved`; guardrails set and removed, `Guardrail\GuardrailSet` and
`Guardrail\GuardrailRemoved`; and `SystemOverrideUsed`) are `final readonly` snapshots of plain values: a record is a
`Reference`, its morph class under your morph map and its key as a string, never a model, alongside names, the scope,
expiries and times. An update carries the fields it changed, before and after. A policy event carries its document's
version and SHA-256 digest, never the document. A delete lists every grantee that held the role, permission or policy,
so the evidence says who lost access.

Each is dispatched only once its write commits on the package's connection: inside your own transaction it waits for
the outermost commit, and a transaction that rolls back dispatches nothing. Every event of one service call carries
the same operation id and the call's actor; a write made through a model outside the services is an operation of its
own with no actor. A change `forceSystem()` unlocked dispatches `SystemOverrideUsed`, naming the record, the change and
the actor.

`DecisionEvaluated` and `AuthorizationFailed` implement the marker too, but are dispatched when the decision is made,
not after a commit, and still carry the principal, the context and the decision as they were evaluated.

### The programmatic API

Every check goes through `SineMacula\Laravel\Authorization\AuthorizationManager`, which the `Authorization` facade
proxies and the container injects. Each method decides about the current subject, as the subject resolver gives it,
or about the subject of the scoped manager it is called on:

| Method                                            | What it does                                                                                                    |
|---------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `can($action, $resource, $context)`               | Decides the action and returns whether it is allowed                                                            |
| `cannot($action, $resource, $context)`            | Returns the opposite of `can()`                                                                                 |
| `authorize($action, $resource, $context)`         | Decides the action and throws when it is not allowed                                                            |
| `check($action, $resource, $context)`             | Decides the action and returns the full `Decision`                                                              |
| `any($actions, $resource, $context)`              | Returns whether at least one of the actions is allowed                                                          |
| `all($actions, $resource, $context)`              | Returns whether every one of the actions is allowed                                                             |
| `checkMany($checks)`                              | Decides each `CheckInput` and returns its `Decision`, keyed as the checks are (see [Bulk checks](#bulk-checks)) |
| `canEach($action, $resources, $context)`          | Decides the action on each resource and returns whether each is allowed, keyed as the resources are             |
| `filterAuthorized($action, $resources, $context)` | Returns the resources the action is allowed on, with their keys and order, a `Collection` as its own class      |
| `explain($action, $resource, $context)`           | Decides the action and returns its explanation as text                                                          |
| `lastDecision()`                                  | Returns the latest decision of the request or job, whichever manager made it                                    |
| `permissionsFor($subject, $scope, $context)`      | Lists the actions of the permission catalogue the subject may take in the scope                                 |
| `for($subject)`                                   | Returns a scoped manager deciding about the model named, in the request's tenant and application                |
| `forUser($user)`                                  | Returns a scoped manager deciding about the subject the resolver translates the user into                       |
| `capped($actions)`                                | Returns a scoped manager whose checks are capped by the actions given                                           |
| `withPolicies($policies)`                         | Returns a scoped manager that evaluates only the policies given                                                 |
| `queryScope($model, $action, $context)`           | Returns the scope `whereAuthorized()` puts on a query (see [Query scoping](#query-scoping))                     |

`check()` is the one decision, and `checkMany()` the same decision over many checks, `check()` deciding as `checkMany()`
decides a batch of one: every other method but `queryScope()` and `permissionsFor()` adapts one of them, and each
decision they make is recorded as the last decision and reported with `DecisionEvaluated`; `queryScope()` compiles a
scope from the same pipeline without deciding a check, and `permissionsFor()` decides each action through the path
`checkMany()` takes but as introspection, so both record and report nothing. `permissionsFor()` takes its subject as an
argument, null for the one the manager's checks are about (see [Effective permissions](#effective-permissions)). The
resource and the context take the same forms everywhere: a model, a `[type, id]` pair, a `ResourceReference`, an
`AuthorizableResource`, a model class or a string names the resource (see
[Managing roles, permissions and grants](#managing-roles-permissions-and-grants)), and the context is the caller's
values, read under `input` (see [The check's context](#the-checks-context)).

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;

Authorization::can('posts:update', $post);                       // true or false
Authorization::cannot('posts:delete', ['post', 42]);             // the opposite of can()
Authorization::any(['posts:update', 'posts:publish'], $post);    // true at the first action allowed
Authorization::all(['posts:update', 'posts:publish'], $post);    // false at the first action refused
Authorization::for($user)->authorize('posts:publish', $post);  // throws when the check is denied
```

`any()` and `all()` decide their actions one at a time, in the order given, and stop as soon as the answer is known:
`any()` at the first action allowed, `all()` at the first refused, so no action after it is decided. Each action
decided is recorded and reported as `check()` records it, so the last decision is that of the last action decided. An
`insufficient_authentication` decision is a refusal there, as it is for `can()`; to ask for a step-up, decide the
action with `authorize()` or read the decision's requirements from `check()`. A list that names no action is refused
with an `InvalidCheckArgumentException` (an `InvalidArgumentException`) before anything is decided. There is no
throwing form over several actions: call `authorize()` for each action that must be allowed.

The facade resolves the manager scoped to the current request or job, so every call in that lifecycle reaches the same
manager, and the next request or job gets a new one. `for()`, `forUser()`, `capped()` and `withPolicies()` never change
it: each returns a new scoped manager, which every method above works on, and which shares the lifecycle's last
decision, so `Authorization::lastDecision()` returns the latest decision whichever of them made it. They chain: a
scoped manager made from another keeps its subject, its caps and its policies, and a further cap narrows its caps:

```php
$preview = Authorization::for($user)->capped(['posts:*'])->withPolicies([$hypothetical]);

$preview->all(['posts:read', 'posts:update'], $post);
Authorization::lastDecision();  // the decision of the last action $preview decided
```

Injected, the manager is the same one the facade resolves. Inject it into a class built for the request or job, such
as a controller, an action or a queued job's `handle()`; a singleton would keep the manager of the request it was
first built in:

```php
use SineMacula\Laravel\Authorization\AuthorizationManager;

final class PublishPost
{
    public function __construct(private readonly AuthorizationManager $authorization) {}

    public function __invoke(Post $post): void
    {
        $this->authorization->authorize('posts:publish', $post);

        $post->publish();
    }
}
```

### Bulk checks

`checkMany()`, `canEach()` and `filterAuthorized()` decide many checks at once, a page of results or a list of rows,
each exactly as `check()` would decide it on its own, but reading what the checks share once rather than once a check:

```php
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Facades\Authorization;

$decisions = Authorization::checkMany([
    'edit'    => new CheckInput('posts:update', $post),
    'publish' => new CheckInput('posts:publish', $post, ['channel' => 'web']),
    'report'  => new CheckInput('reports:view', ['report', 42]),
]);

$decisions['publish']->isAllowed();

Authorization::canEach('posts:update', $posts);         // [key => bool], one entry for each post
Authorization::filterAuthorized('posts:view', $posts);  // the posts allowed, with their keys, in their order

$user->canEach('posts:update', $posts);                 // Authorization::for($user)->canEach(...)
$user->filterAuthorized('posts:view', $posts);          // Authorization::for($user)->filterAuthorized(...)
```

`checkMany()` takes an array of `CheckInput`s, each an action, a resource in any form `check()` takes and the caller's
context, and returns one `Decision` for each, under the same key and in the same order, a check repeated decided and
returned under each of its keys. A list holding anything other than a `CheckInput` is refused with an
`InvalidCheckArgumentException` before any check is decided. `canEach()` decides one action, with one context, on each
of the resources of an array, a collection or any other iterable, and returns whether each is allowed, keyed as the
resources are; an `insufficient_authentication` decision is `false`, as it is for `can()`. `filterAuthorized()` returns
the resources the action is allowed on, the very objects given, with their keys, in their order: an
`Illuminate\Support\Collection`, or a subclass of it such as an Eloquent collection, comes back as a collection of its
own class, and anything else, a `LazyCollection` or a generator included, as an array, its keys kept, so call
`values()` or `array_values()` for a list. Neither stops at a denial: every resource is
decided. No checks or no resources return an empty result. A generator that yields a key twice keeps the last resource
under it, as `iterator_to_array()` does. Models using `HasPermissions` get `canEach()` and `filterAuthorized()` too,
deciding about the model through `Authorization::for($model)`.

Each check goes through the same stages as `check()`, its own tenant, scope, policies, caps and attributes included, so
its decision, reason, stage, trace and requirements are those `check()` would give. Each is recorded as the last
decision and reported with its own `DecisionEvaluated` as soon as it is decided, before the next one, in the order of
the checks; there is no event for the batch as a whole. `Authorization::lastDecision()` is then the last check
decided, and an empty batch leaves it as it was. A check that throws where `check()` would throw (an attribute
provider that fails, say) stops the batch there: the checks before it are recorded and reported, nothing is returned,
and the tenant scope is restored however the batch ends.

What the checks share is read once. The subject is resolved once for the batch, and its grants, roles, policies,
permission boundaries, session caps and the guardrails are resolved once in each scope (tenant and application) the
checks are decided in, through the resolution cache, which keeps each scope's apart. The resources' tenants, the
policies attached to the records and the records' attributes are read in bulk, so deciding 100 records of one type and
tenant costs the queries deciding one does: at most one for their tenants (none for a model that declares its tenant),
one for the policies attached to them and one for their attributes. A tenant tree of your own is asked about each
tenant's place in it once for the batch, however many of its resources are decided, and a persistent cache store is
read and written for the records' attachments together, in the same number of round trips for one record as for 100.
A single check, `check()` or a batch of one, reads nothing ahead and holds nothing for later: it reads its resource's
tenant, attached policies and attributes on its own, as it always has.

Reading in bulk needs the resource tenant resolver and the attribute providers to read in bulk. The package's own
resolvers do. A resolver of your own implements `Contracts\BulkResourceTenantResolver`: `tenantsOf($models)` and
`tenantsOfRecords($type, $ids)` return each tenant, keyed as given, `null` for none and, for a record, `false` when it
cannot tell. A resource attribute provider implements `Contracts\BulkResourceAttributeProvider`, whose
`valuesMany($items)` is given each record's reference and model under a token and returns what `values()` would for
each, keyed by token:

```php
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\BulkResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

final class PostAttributes implements BulkResourceAttributeProvider
{
    public function attributes(): array
    {
        return ['status' => 'string'];
    }

    public function values(ResourceReference $resource, ?Model $model): array
    {
        return $this->valuesOf($model ?? Post::query()->find($resource->id));
    }

    public function valuesMany(array $items): array
    {
        $ids   = array_map(fn (array $item): ?string => $item['resource']->id, $items);
        $posts = Post::query()->findMany(array_values($ids))->getDictionary();

        $model = fn (array $item): ?Model => $item['model'] ?? $posts[$item['resource']->id] ?? null;

        return array_map(fn (array $item): array => $this->valuesOf($model($item)), $items);
    }

    private function valuesOf(?Model $post): array
    {
        return $post === null ? [] : ['status' => $post->status];
    }
}
```

An item's answer can be the exception `values()` would throw for it: it fails that item's check alone, and only if the
check reads `resource`. An item left out of the answer, or every item when `valuesMany()` itself throws, is asked about
through `values()`, and so is every item of a resolver or provider without the bulk contract. That keeps every decision
correct, but costs one read for each resource that reads the database, so the one-query guarantee holds only with the
bulk contracts. Even with them, two cases read one record at a time, each decision still exact:

- record attachments are read one record at a time when the attachments table does not compare keys byte for byte (a
  case-folding collation, or a driver the package does not know); the package's own tables compare byte for byte;
- a string-keyed declared record the bulk query does not find under its exact spelling, a missing UUID say, is asked
  about on its own, one query each.

The first check on a type that reads `resource` asks its provider about every record of that type still to be decided
in the chunk in the same scope as that check (where the request is, the record's own tenant below the request's, or
platform scope for a record admitted from outside it), and asks it in that scope, so a provider reading through the
tenant scope finds for each record what it would find on its own; the records of another scope are read when the first
of them reads `resource`. A provider can be asked about a record whose own check never reads `resource`; that answer is
used by no check. Two models with the same key are two items, since each may hold other attributes in memory, while one
`ResourceReference` given to several checks is one item, read once for all of them, in every chunk. A provider that does
not read in bulk is asked about each item once, however many of its checks read `resource`.

The checks are decided in chunks of `authorization.bulk.chunk_size` (`AUTHORIZATION_BULK_CHUNK_SIZE`, 500 by default,
a whole number of at least 1, checked at boot), and what a chunk read is released once it is decided. The decisions
themselves, traces included, are all returned at once, so decide a very large set in pages of your own, with
`chunkById()` say.

A batch sees a write as a sequence of `check()` calls in the same request would. A grant, revocation, policy,
attachment, boundary or guardrail written while the batch runs, by a listener reacting to one of its decisions
included, empties the resolution cache, so every later check reads it; so does a change to the tenant tree reported
through `Authorization::treeChanged()`, after which the tree is asked again. The resources' tenants and attributes are
read for each chunk, the tenants as it starts and the attributes when its first check on a type reads them, so a change
to a resource's tenant or attributes made after it was read is seen from the next chunk, except by the later checks on
a `ResourceReference` they share, which keep what was read for it.

### Effective permissions

`permissionsFor()` lists the actions a subject may take in a scope, for a UI to show or hide its controls. It returns
the action names, a list:

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;

// In the request's tenant and application.
$actions = Authorization::permissionsFor($user, AuthorizationScope::current()); // ['posts:create', 'posts:update']

// In another tenant, on the admin application, or at platform scope.
$actions = Authorization::permissionsFor($user, AuthorizationScope::tenant($account, 'admin'));
$actions = Authorization::permissionsFor($user, AuthorizationScope::platform());

// On one post, for its row's controls, with the caller's context.
$actions = Authorization::permissionsFor($user, AuthorizationScope::current()->withResource($post), ['plan' => 'pro']);

// The same from the model, through `HasPermissions`.
$actions = $user->permissionsFor(AuthorizationScope::current());

// A null subject is the one the manager's checks are about: the request's, or the one named.
$actions = Authorization::permissionsFor(null, AuthorizationScope::current());
$actions = Authorization::for($user)->permissionsFor(null, AuthorizationScope::current());

// A guest's actions, which are none.
$actions = Authorization::forUser(null)->permissionsFor(null, AuthorizationScope::current()); // []
```

**The scope.** An `AuthorizationScope` names the tenant, or none for the platform, the application, or none, and the
resource, or none:

- `AuthorizationScope::current()` captures the request's tenant and application, as the subject resolver reports them;
- `AuthorizationScope::platform($application = null)` names no tenant;
- `AuthorizationScope::tenant($tenant, $application = null)` names a tenant, as a model, an `AuthorizableTenant` or a
  `Reference`; a tenant without a key is refused with `InvalidTenantException`;
- `->withResource($resource)` returns the scope with a resource, in any form `check()` takes.

A null tenant always means the platform, never "the request's tenant": capture that with `current()`. A null
application means no application, so only grants for every application count. The scope's tenant and application are
put in place of the request's while the actions are decided, both as the subject's and as the scope of the grants that
count, and the request's are restored afterwards, even when deciding one throws. The resource's own tenant still goes
through admission, as for `check()`: a resource of a tenant outside the scope's tenant and its subtree is refused as
`tenant_scope` unless a platform-wide grant covers it, and naming a resource never moves the scope to its tenant.

**The subject.** A resolved `Subject` is taken as it is, keeping its identity, guard and session, so a session that
meets an authentication requirement still meets it. Any other object is named as `for()` names it, in the request's
guard, with no session. `null` is the subject the manager's checks are about, exactly as `check()` takes it: the
request's subject on the facade, the subject named on a manager from `for()` or `forUser()`, and a guest, who is allowed
nothing, on `forUser(null)` or when the request has no subject.

**What a listed action means.** The listing is exact: it holds the actions the permission catalogue declares (the
package's own permissions, the cases of the configured enums and the definitions of the configured providers), each
name once, a name declared for two guards included, in the catalogue's order, for which
`check($action, $scope->resource, $context)` would allow, in that scope, about that subject, as things stand. An action
the catalogue does not declare is never listed, whatever a wildcard grant or a stored permission name covers. Each
action is decided as `check()` decides it, never as the allows less the denies, so its denies, conditions, guardrails,
boundaries, session caps (a `capped()` manager's included) and authentication requirements are weighed exactly as
`check()` weighs them. An action whose check would be `insufficient_authentication` is not listed. An action whose check
would throw, through a failing attribute provider say, makes the listing throw what it throws, so nothing is listed
that the check would not allow. A catalogue that cannot be read, one declaring a name twice for a guard with different
metadata say, throws `InvalidPermissionCatalogueException`; an entry of `authorization.permission_enums` the boot
validation would refuse is skipped.

**Generic and resource-specific listings differ.** A listing with no resource answers the check with no resource, so an
allow limited to some records, or conditioned on a resource's attributes, does not list its action there; a listing
for one resource answers for that resource. Use the resource-specific listing for a row's controls, and the generic one
for the controls of a page.

**The server still authorizes.** A listing tells the UI what to show. What is granted can change between rendering and
the request, so authorize the action again when it is taken, with `authorize()`, the `authorize:` middleware or the
Gate.

**It records nothing.** Listing is introspection, not a check: it records no last decision and dispatches no
`DecisionEvaluated` and no `AuthorizationFailed`. Break-glass grants, when they arrive, will define how a listing that
relies on one is reported.

**What it costs.** The actions are decided together, through the path `checkMany()` takes, so the subject is resolved
once and its grants, roles, policies, boundaries and caps, the guardrails and the resource's tenant, attached policies
and attributes are read once for the listing: listing fifty actions costs the queries listing five costs. The catalogue
is read from code on each call and touches no database. A scope already in place, such as `current()`, is not applied
again, so a listing in it reads what the request's checks have already resolved, and a check after it still does. A
listing in another scope keeps what the request has resolved and puts it back once it returns, unless a write emptied
the cache meanwhile. See [Effective permissions](docs/design/effective-permissions.md) for the design.

### Query scoping

`whereAuthorized()` restricts an Eloquent query to the rows the subject may take an action on, alongside the
application's own filters, ordering, selects and pagination:

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;

Post::query()->where('status', 'live')->whereAuthorized('posts:view')->paginate();

Post::query()->whereAuthorized('posts:view', ['channel' => 'web'], Authorization::forUser($user))->get();
```

The rows it keeps are exactly the rows of the query's candidate set, before any limit or offset, that `check()` would
allow the subject on for the record loaded with every column, whatever columns the query selects, with the same
context, under the state at the instant the query runs; a row on which `check()` would throw for that record is not
kept. When the scope cannot prove that, it throws a `QueryScopeRefusedException` instead: it never filters rows after
loading them, and never keeps a row it has not proved `check()` allows. A model loaded without its key or its tenant
columns cannot itself be passed to `check()` (it throws, or denies as `resource_unresolved`), so select those columns
if you mean to check the results.

The subject is the one `check()` decides about: the current manager's, or that of the manager passed as the third
argument, so a scoped manager from `for()`, `forUser()`, `withPolicies()` or `capped()` scopes the query with its
subject, its policy override and its caps. A guest keeps no row. The context is the caller's values, read under
`input`, as `check()` reads them.

The scope is compiled when `whereAuthorized()` is called, so a refusal throws there and the builder is left exactly as
it was, and again every time the query is compiled to run, from the state then: a page and its count, each chunk, an
update or a deletion are each decided afresh, so a grant revoked after the call is seen by the next execution, and no
decision is reused. Compiling, at the call or at execution, records no last decision and dispatches no
`DecisionEvaluated`, so an audit of row access needs its own hook. The scope never runs a query on the model's table of
its own.

When the query runs, every constraint of the application's, those added before the call, after it and by other global
scopes alike, is put in one group, and the scope's condition, with no bindings, is joined to it with `and`: an
`orWhere()`, or a raw condition or expression holding `OR`, never reaches past it, and a comment at the end of a raw
condition leaves the group unclosed, so the database refuses the query rather than drop the condition. To compare the
tenant columns exactly, byte for byte, the condition also compares the bare columns with the active tenant, which an
index on them can serve; whether the planner uses it beside the rows of no tenant is the database's choice.

A query is refused when it runs if it would escape the condition: one with a union, one that selects from anything but
the model's table (an alias or a subquery included), one joined with `or` at the top after the condition (a
`beforeQuery()` callback adding one included), one whose scopes were removed after the call (remove scopes before
calling `whereAuthorized()`), and one changed at the top after the scope's own last check. `whereAuthorized()` is
called on the query that runs: called inside a `where()`, `orWhere()` or `whereNot()` group, or in a relation's
definition that `whereHas()`, `has()`, `withCount()` or `withExists()` then uses, its scope is never applied, and the
query refuses rather than keep every row. A relation scoped in its definition works when it is loaded, lazily or
eagerly; to filter by a relation, pass the scope in its constraint:
`Owner::whereHas('posts', fn ($query) => $query->whereAuthorized('posts:view'))`.

A scoped builder another query takes whole, as `whereHas()`, `whereExists()` and `where($column, $builder)` take it,
is decided each time that query runs, and so is a base query taken with `toBase()`, which refuses once it is widened
with `or` or given a condition outside the group. One taken in as SQL text, by `whereIn()`, `fromSub()`, `joinSub()`,
`selectSub()`, `insertUsing()`, a `withCount()` or `withExists()` constraint, or `has()` with a count, is decided when
it is taken in, and the other query reuses that decision every time it runs: Laravel gives no sign of a compile that is
for such a text, so this one shape is not refused. Build the other query again to decide again, or call
`whereAuthorized()` on it. A `beforeQuery()` callback registered by a global scope applied after `whereAuthorized()`'s
own runs after the scope's last check, and is the application's to keep honest.

#### Declaring a model

A model whose queries are scoped implements `QueryableResource` and declares where its records keep their tenant:

```php
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

final class Post extends Model implements QueryableResource
{
    public static function resourceTenancy(): ResourceTenancy
    {
        return ResourceTenancy::columns('tenant_type', 'tenant_id');
    }
}
```

| Declaration                                 | The records' tenant                                                           |
|---------------------------------------------|-------------------------------------------------------------------------------|
| `ResourceTenancy::tenantless()`             | None                                                                          |
| `ResourceTenancy::columns($type, $id)`      | The morph type and key in the two columns                                     |
| `ResourceTenancy::ofType($tenantType, $id)` | Always of the type given (a morph type or a model class), keyed by the column |

The resource tenant resolver the package binds answers a declared model's tenant from its declaration, so `check()`
reads the same columns the scope compares, raw; every other model is still answered by the resolver
`authorization.resource_tenant_resolver` configures. A record whose type or id is null has no tenant.

By declaring its tenancy a model promises that its key and its tenant columns are read raw, as the database holds
them: no accessor, cast or override changes them on load, and no hook, such as a `retrieved` listener or observer,
changes them once a record is loaded. The scope refuses every breach it can detect.

#### What compiles

The scope compiles every statement it can compare with each row's key in SQL exactly as `check()` matches it:

- the actions and `not_actions` of every statement;
- resources absent, or `resources` and `not_resources` whose patterns, resolved as `check()` resolves them, are `*`,
  a literal, or a literal and then `*`: a literal naming a record of the type (`T:5`, `T:abc`, `T` being the model's
  morph type) compares the key, a literal and then `*` longer than `T:` (`T:ab*`) compares the start of the key's
  text byte for byte, and any other names every record of the type or none. A key that is `*` or ends in `:*` is
  matched on the whole identifier, as `check()` matches it, so `T:${input.k}` with a `*` substituted names no record;
- an integer key equals only an integer's canonical decimal text within 64 bits (`-0`, `+1`, `01` and `1.0` name no
  record), a uuid key on PostgreSQL only a uuid's canonical lower-case text, and a string key a value byte for byte;
- conditions on `input`, on the subject's namespace, built-in keys included, when the subject's type has no attribute
  provider or one marked `ScopeInvariant`, and on the namespaces of sources marked `ScopeInvariant`, the package's
  defaults included, and authentication requirements a checker so marked judges;
- the permissions held, the subject's and its identity's policies, its roles' policies, permission boundaries,
  guardrails (except for `authorization:guardrails:manage`), session caps and the policies attached to the model's
  type or to its records, whose allows apply to the subjects their `principals` name, by reference or by role, and
  whose denies apply to everyone; a policy attached to a record weighs on that record alone, compared in SQL under
  the attachment column's own collation, and a `withPolicies()` override reads no attachment;
- tenantless models, and tenant-bearing models under any tenant tree: the rows of no tenant are decided in the
  request's scope; the rows within the active tenant's subtree in their own tenant's scope, every grant there, above
  them reaching below, or platform-wide counting; and, when the subject holds the action through a platform-wide
  grant for the request's application, every other tenant's rows at platform scope, each still capped by its own
  tenant chain's guardrails and denied by the denies attached in its tenant chain. Without that grant `check()` denies
  those rows as `tenant_scope`, and they are left out;
- rows whose key cannot identify a record (null, empty or holding a NUL byte), rows whose tenant columns hold something
  other than a string, an integer or null (a real number SQLite keeps in an integer column) or a part over 191 bytes,
  and, when a statement matches a pattern against the identifier, rows whose identifier is too long for `fnmatch()`,
  are left out, as `check()` denies or throws on them.

A tree other than the flat one is read through `TenantTree::subtree()`, nested in the condition whole, so it must run
on the model's connection; its contract is that `subtree(T)` selects exactly the string forms (`tenant_type`,
`tenant_id`) of every tenant within `T`, whatever the tenant scope. The rows are split into classes at the tenants the
decision's sources sit at: the subject's grants, policies and boundaries, its roles', the guardrails and the type's
attached policies. Each class is decided once, every time the query runs, so the number of tenants and classes is
bounded:

```php
// config/authorization.php
'query_scoping' => [
    'max_anchors'     => 64, // the active tenant and those the sources may sit at, over which `too_many_scopes`
    'max_scopes'      => 16, // classes one query is decided in, over which `too_many_scopes`
    'max_attachments' => 64, // record attachments naming the action in a scope, over which `too_many_attachments`
],
```

`max_anchors` counts the active tenant and every other tenant the decision's sources may sit at: those of the grants,
policies and boundaries of the subject and its identity, of the policies of the roles they hold and every role above
those, of the tenants owning those roles and the granted permissions, of the guardrails, and of the policies attached to
the type or its records. Under the flat tree, where only a platform-wide grant cuts the rows, only the guardrail and
attached-policy tenants count. Both limits are checked before any class is cut, so the work of cutting is bounded by
them. `max_attachments` bounds the policies attached to records of the type, in one scope, that name the action; the
read also stops, and refuses as `too_many_attachments`, once four times as many are attached there whatever their
actions, so it is bounded by the rows it scans as well as by those it keeps. Each scope's attachments are read once per
compile. Each limit is a whole number of at least 1.

The comparisons are exact only where the database compares bytes as PHP does. When the rows are cut below a tenant
or admitted from outside the active tenant's subtree, the tenant columns of every authorization table must compare
bytes: no collation or `BINARY` on SQLite, a deterministic collation on PostgreSQL, and `utf8mb4_0900_bin` or `binary`
on MySQL, as the package's migrations create them. A string key compared with a value must compare bytes the same
way. An integer key compared with a value must hold only integers PHP reads as they are: on SQLite it must be the
table's rowid (`INTEGER PRIMARY KEY`, never `INTEGER PRIMARY KEY DESC`, which SQLite does not make the rowid), and on
MySQL it must be neither an unsigned `BIGINT` nor `ZEROFILL`, whose digits PHP reads padded. The column of an attached
record's key must compare bytes on SQLite and PostgreSQL; on MySQL its own utf8mb4 collation is followed. On PostgreSQL
a table is looked up as Laravel finds it, the connection's prefix before the table's own name and after any schema, and
a column not found there is treated as not exact.

A record attachment, and a subtree of a tree other than the flat one, are read in the condition itself, with every value
they are bound to (a tenant, an application, a policy) inlined as the database reads it bound, its characters written
as hex or escaped code points, so a quote, a backslash, a question mark or a NUL byte is never read as SQL; a value that
cannot be written so, and a subtree query whose text holds a question mark that is not a placeholder, refuse as
`inline_value`.

`check()` reads the authorization tables on the write connection, and a condition that reads them must too. On a model
connection with a separate read connection, outside a transaction (where Laravel already reads on the write
connection), the query carrying such a condition is put on the write connection when it is the query being run: a
scoped query's own `get()`, `first()`, `pluck()`, `count()` and other aggregates, `exists()`, `paginate()` (its count
and its page), `cursor()`, `chunk()`, `chunkById()`, `lazy()`, `lazyById()`, `update()` or `delete()`, with
`whereAuthorized()` or the model-level scope alike. Laravel passes the query's choice of connection only after
compiling it, so this holds for that execution alone. A query that carries the condition but is not itself run cannot
be moved, and refuses as `read_replica`: one nested whole in another (`whereHas()`, `whereExists()`, a relation's
existence query, the model-level scope on a related model), one compiled to text (`toSql()`, `toRawSql()`, and every
shape that takes it in as text, such as `whereIn()`, `fromSub()`, `withCount()`, `withExists()` and `has()` with a
count), and `paginate()` on a grouped query, whose count Laravel runs as another query around it. A condition that
reads no authorization table (no record attachment and no nested subtree) leaves the query on the read connection.

A statement gathered for the type is refused only when a check would weigh it: it names the action, its target can
name a row and, for an allow, it applies to the subject. A document that cannot be read always refuses. Everything
else that could change a decision refuses, with no pruning:

| Reason                                                   | Refused                                                                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `model_undeclared`                                       | A model that does not implement `QueryableResource`                                                                                                  |
| `model_contract`                                         | A model implementing `AuthorizableResource`, or a morph type too long to identify a record                                                           |
| `model_override`                                         | An override of `getMorphClass`, `newFromBuilder`, `getKey`, `getKeyName`, `getAttribute`, `getAttributes`, `getAttributeValue` or `setRawAttributes` |
| `model_listener`                                         | A `retrieved` listener or observer, or a model dispatching its own event when retrieved                                                              |
| `column_accessor`, `column_cast`                         | An accessor, or a cast other than the key's own kind, on the key or a tenant column                                                                  |
| `column_type`                                            | A key or tenant column missing, or of a type that cannot be compared exactly; an integer key PHP may read otherwise, once it is compared             |
| `column_collation`                                       | A string key compared under a collation that is not exact, or an authorization table's tenant column so, once rows are cut below or admitted         |
| `connection_charset`, `driver`                           | A connection that is not UTF-8, or not SQLite, PostgreSQL or MySQL                                                                                   |
| `tenant_resolver`                                        | A resource tenant resolver bound in place of the package's                                                                                           |
| `subtree_connection`                                     | A tenant tree whose subtree query runs on another connection than the model's                                                                        |
| `attachment_connection`, `attachment_collation`          | Policies attached to records kept on another connection, or whose key column cannot be compared with the key, once one is attached                   |
| `too_many_scopes`, `too_many_attachments`                | More tenants, classes or record attachments than `authorization.query_scoping` allows                                                                |
| `inline_value`                                           | A tenant, application or policy value, or a subtree query, that cannot be inlined exactly as the database reads it bound                             |
| `read_replica`                                           | A record attachment or subtree read by a query that is not itself run, on a separate read connection outside a transaction                           |
| `resource_pattern`                                       | A pattern with `?` or `[`, a `*` not at its end or more than one, a trailing `\`, one too long for `fnmatch()`, or an integer id beyond 64 bits      |
| `resource_namespace`, `scope_variant_source`             | A statement reading the resource, or a source not marked `ScopeInvariant`                                                                            |
| `invalid_statement`, `invalid_policy`                    | A statement that cannot be evaluated, or a document that cannot be read                                                                              |
| `query_union`, `query_from`, `query_or`, `query_changed` | A query that would escape the condition                                                                                                              |
| `scope_removed`                                          | A scope removed after the call, or never applied: called inside a `where` group or a relation's definition, or run past its scopes                   |
| `reentrant`                                              | The model-level scope on the subject's model, or on a model the decision reads                                                                       |

#### The model-level scope

`AuthorizedScope` keeps every query of a model to the rows the current subject may take an action on, added in the
model's `booted()`:

```php
use SineMacula\Laravel\Authorization\Scopes\AuthorizedScope;

protected static function booted(): void
{
    static::addGlobalScope(new AuthorizedScope('posts:view'));
}
```

It shares `whereAuthorized()`'s compiler and behaves as it does: it is compiled every time a query of the model runs,
for the subject `check()` would decide about then, with no decision cached; a refusal throws from the call that runs
the query; and its condition is grouped and guarded the same way. `withoutGlobalScope(AuthorizedScope::class)` opts a
query out, and it then runs unscoped with no refusal, since that is the application's explicit choice; removing a
`whereAuthorized()` scope, by contrast, refuses as `scope_removed`. It must never be on the subject's own model, nor on
a model the decision reads while deciding (the grants, roles, policies and tenants): such a query refuses as
`reentrant` rather than recurse.

#### The exception

`QueryScopeRefusedException` is a `RuntimeException`, not an `AuthorizationException`, thrown alike by
`whereAuthorized()` and `AuthorizedScope`: a refusal is a developer or configuration fault, which Laravel renders as a
500. It carries the `action`, the model's `resourceType` (its morph
type, through the morph map when it has one) and every `refusal`, each with its `reason`, the `policy` and `statement`
it names, the condition key, namespace, column or seam class (`key`) and a fixed `detail`, and `reasons()` lists their
reasons. Neither it nor its message ever carries an operand, a pattern, a context value, a row's value or a tenant id,
and a refusal for record attachments names no policy, however many there are.

### Laravel's Gate

The package is the authority of Laravel's Gate for the abilities it declares. Booting registers one `Gate::before`
hook, and defines no ability. The hook answers every ability whose exact name a permission enum, a permission provider
or the package itself (`authorization:guardrails:manage`) declares, with the package's decision: true for an allow,
false for a deny. Laravel stops at the first before-callback that answers, so both stand: no `Gate::define` callback,
Laravel policy class or `Gate::after` callback can override either. `Gate::allows()`, `Gate::forUser($user)`,
`$user->can()`, `@can`, the `can:` middleware, `Gate::authorize()` and a controller's `authorize()` all go through it,
whatever Laravel policy class the resource's model has:

```php
Gate::define('posts:update', fn (User $user) => true);  // never consulted: posts:update is declared

Gate::allows('posts:update', $post);                     // the package's decision about $post
Gate::forUser($other)->allows('posts:update', $post);    // the same, about $other
```

The Gate's arguments reach the check as the package's own API takes them: a model, a reference, a string or a
`(type, id)` pair names the resource, and string keys and associative arrays are the caller's values, read under
`input` (see [The check's context](#the-checks-context)).

Every other ability falls through to Laravel unchanged: the hook answers nothing, so the application's defines and
policy classes decide it as they always have. A name is matched exactly, never as a pattern, so `posts:*` is the
package's only when a permission of that name is declared. A permission row that exists only in the database, declared
by no enum or provider, is not the package's either: the Gate leaves it to Laravel, while `Authorization::can()` still
decides it.

The Gate's user is translated into the subject through the subject resolver's `forUser()`, so the check is about the
principal the user acts as. A guest (no user) is decided as no subject, which denies as `subject_unresolved`; it is
never decided as the current request's subject.

**Precedence.** Laravel runs before-callbacks in the order they were registered, and the first that answers wins. The
package registers its hook first thing in its boot, so a `Gate::before` the application registers afterwards, in its
own service provider for example, runs after it and can only answer the abilities the package leaves alone. A
`Gate::before` registered before the package boots (in a provider listed before it, or in a `register()` method) runs
first and can pre-empt the package.

**The switch.** To leave the Gate to Laravel entirely, turn the hook off:

```dotenv
AUTHORIZATION_GATE_ENABLED=false
```

Then nothing is registered and the Gate knows none of the package's permissions; the package's own API, middleware and
directives still decide them. Only true or false is accepted: any other value of `authorization.gate.enabled` is
refused at boot. `authorization:check` reports whether the hook is enabled. The contract behind the hook is in
[Gate authority](docs/design/gate-authority.md).

### Laravel policy classes

A Laravel policy class can decide through the package with the
`SineMacula\Laravel\Authorization\Concerns\DecidesThroughAuthorization` trait. Each policy method names its action and
hands `decide()` the user Laravel gives it, the model or any other resource, and any context:

```php
namespace App\Policies;

use App\Models\Post;
use App\Models\User;
use Illuminate\Auth\Access\Response;
use SineMacula\Laravel\Authorization\Concerns\DecidesThroughAuthorization;

final class PostPolicy
{
    use DecidesThroughAuthorization;

    public function archive(User $user, Post $post): Response
    {
        return $this->decide($user, 'posts:archive', $post);
    }

    public function preview(?User $user, Post $post): Response
    {
        return $this->decide($user, 'posts:read', $post, ['preview' => true]); // input.preview
    }
}
```

`decide()` makes one check, through `Authorization::forUser($user)->check()`, about the subject the subject resolver
translates the user into, so it is recorded as the last decision and reported with `DecisionEvaluated` as any check
is, and it takes the resource and the context in the same forms as the [programmatic API](#the-programmatic-api). No
method name is mapped to an action: each method names its own. A guest (a null user, which Laravel hands only to a
method whose user is nullable) is no subject, so it is denied as `subject_unresolved`.

An allow is `Response::allow()`. A denial is `Response::deny()` with the decision's reason code as its code, such as
`explicit_deny`, and as its message the generic `authorization::authorization.denied` line, whatever the reason, in the
current locale; read the code to word a message per reason (see [Localisation](#localisation)). A denial is never a
not-found response, so Laravel answers it with a `403`:

```php
Gate::inspect('archive', $post)->code();     // 'explicit_deny'
Gate::inspect('archive', $post)->message();  // 'This action is unauthorized.'
```

An `insufficient_authentication` denial keeps its own code, but the trait raises no
`InsufficientAuthenticationException` and the response carries no requirements, so it is answered as any other `403`.
A caller that needs to ask for a step-up decides the action with `authorize()`, which raises that exception, or with
`check()`, whose decision names the requirements (see [Authentication requirements](#authentication-requirements)).

For an ability whose exact name the package declares, the [Gate hook](#laravels-gate) answers before any policy class
runs, so a policy method is never called for it. The trait is for the abilities outside the catalogue's exact names,
such as `archive` above, which the hook leaves to Laravel and its policy classes, and for applications that turn the
hook off, where Laravel's policy classes answer the Gate for every ability.

### Middleware and Blade

The package registers three route middleware aliases, each only when the application has not already taken it:

```php
Route::get('/reports', ListReports::class)->middleware('permission:reports:view|reports:manage');
Route::put('/posts/{post}', UpdatePost::class)->middleware('authorize:posts:update,post');
Route::get('/admin', AdminDashboard::class)->middleware('role:admin|editor');
Route::get('/api/admin', ApiAdmin::class)->middleware('role:admin,api');
```

- `permission:` decides each listed action on the same full decision as `Authorization::can()`, `@can` and the Gate:
  policies, explicit denies, the permissions held, the subject's tenant, the guardrails and its permission boundaries.
  An explicit deny wins over a held permission, a policy allow admits without one, and either is capped by every
  guardrail and boundary that applies.
  The check has no resource, so only statements with neither `resources` nor `not_resources`, or whose `resources`
  include `*`, apply to it.
- `authorize:{action},{route parameter}` decides the action on the parameter's bound model, referenced as every check
  references it, or on the parameter's value when nothing binds it. A value that cannot be identified, such as an
  unsaved model or a value holding a NUL byte, or a parameter the route does not carry, denies as `resource_unresolved`.
  Without a parameter, the check has no resource. Like Laravel's `can:`, it is placed right after `SubstituteBindings`
  in the middleware priority, so it decides on the bound model wherever the route lists it.
- `role:` checks role membership. A role is not an action, so policies never apply to it: it sees the roles the
  subject's `hasRole()` sees, the platform's and its tenant's. A second argument limits it to the roles of that
  authentication guard and the guard-agnostic ones. A name that is not in `auth.guards` is refused, and so is a bare
  name that is also the name of a role, since `role:editor,admin` may mean "editor or admin"; write such a guard as
  `role:editor,guard=admin`. Checking a bare guard against the roles costs one query.

In each of them `|` separates alternatives, and any one admits the request; chain the middleware to require several. A
comma does not list alternatives: the second argument is the guard of `role:` or the route parameter of `authorize:`,
`permission:` refuses one (no guard changes a decision), and a third argument, or a list that names nothing, is refused
with an `InvalidCheckArgumentException`. A request without a subject throws Laravel's `AuthenticationException`
(`401`) with the translated `authorization::authorization.unauthenticated` line. A denial throws the package's
`AuthorizationException` (`403`) with the reason code and the translated `authorization::authorization.denied` line,
whatever the reason.
A denial of `permission:` or `authorize:` is a decision: it is recorded as the last decision and fires
`AuthorizationFailed` once, for the list's last action, before its denial is thrown, or, when that action is denied as
`insufficient_authentication`, an `InsufficientAuthenticationException` (see
[Authentication requirements](#authentication-requirements)). A denial of `role:` is not a decision: it carries
`no_match`, or `subject_inactive` for an inactive subject, and records nothing and fires no event.

Run the package's middleware after authentication and after any step-up middleware, so a request that is not signed
in, or not signed in strongly enough, is answered by those (a `401` or a step-up response) before it can be denied:

```php
Route::middleware(['auth:sanctum', /* step-up middleware */ 'authorize:invoices:refund,invoice'])
    ->post('/invoices/{invoice}/refund', RefundInvoice::class);
```

The Blade directives make the same checks on the same subject:

```blade
@permission('posts:update|posts:delete')
    <button>Edit</button>
@endpermission

@allpermissions(['posts:update', 'posts:publish'])
    <button>Publish</button>
@endallpermissions

@role('admin|editor')
    <a href="/admin">Admin</a>
@endrole

@role('admin', 'api')
    <a href="/api-admin">API admin</a>
@endrole
```

The permission directives (`@permission`, `@anypermission`, `@allpermissions` and their Spatie-shaped `@has…` aliases)
decide each action on the full decision, as `@can` does: the any forms need one allowed, the all forms every one. The
role directives check membership as `role:` does and take a guard; a permission directive refuses one. Every directive
takes a string or a list, with `|` between names in either, and refuses a third argument. With no subject, every
directive is false.

### Localisation

Every message the package can put in front of a client is a translation key of its `authorization` language file
(AUTHZ-9.7). There are two:

| Key                                            | English                        | Carried by                                                                                                                                                             |
|------------------------------------------------|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `authorization::authorization.denied`          | `This action is unauthorized.` | Every denial: `AuthorizationException` and `InsufficientAuthenticationException`, from `authorize()` and the route middleware, and a policy class's `Response::deny()` |
| `authorization::authorization.unauthenticated` | `Unauthenticated.`             | The `AuthenticationException` the route middleware throw for a request without a subject                                                                               |

Every denial carries the one generic `denied` line, whatever its reason: an explicit deny, a missing role,
`insufficient_authentication` and every other. Laravel's handler renders the message and not the reason code, so by
default a client learns that it was refused and not why; what more to tell it is the application's choice. Each line
is translated in the current locale when the exception or response is built. Without a translator, or when the locale
has no line for the key, the message is Laravel's own English (`This action is unauthorized.`, `Unauthenticated.`).
Laravel's exception handler is left as it is, and renders the message as it renders any `403` or `401`.

To reword a line, or to add a locale, publish the package's language files into `lang/vendor/authorization`:

```bash
php artisan vendor:publish --tag=authorization-lang
```

Then edit `lang/vendor/authorization/en/authorization.php`, or add a file for another locale beside it, such as
`lang/vendor/authorization/fr/authorization.php`. Laravel reads a published line in place of the package's, so a file
needs only the keys it changes:

```php
// lang/vendor/authorization/fr/authorization.php
return [
    'denied'          => 'Cette action n’est pas autorisée.',
    'unauthenticated' => 'Non authentifié.',
];
```

To word a message per reason, read the reason code the denial carries, `getReason()` on the exceptions and `code()` on
a policy response, and render a line of your own for it. A step-up prompt is worded the same way, in the
`InsufficientAuthenticationException` mapping shown under [Authentication requirements](#authentication-requirements):

```php
// bootstrap/app.php
use Illuminate\Foundation\Configuration\Exceptions;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;

->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->render(fn (AuthorizationException $exception) => response()->json(
        ['message' => __("denials.{$exception->getReason()->value}"), 'code' => $exception->getReason()->value],
        403,
    ));
})
```

```php
$response = Gate::inspect('archive', $post);
$message  = $response->allowed() ? null : __("denials.{$response->code()}");
```

The reason codes are those of `DecisionReason`, listed under [How a check is decided](#how-a-check-is-decided).

AUTHZ-9.7 covers the denials and the unauthenticated response, the messages a client sees. The package's other
messages are diagnostics for developers and administrators, and stay untranslated: the validators' refusals of a
policy document, a name or a mistaken route or directive argument (`InvalidCheckArgumentException`), a management
service's refusal (a protected system record, an unknown role or permission, a mismatched guard or tenant), the
configuration validator's errors, and the console commands' output.

### Console commands

From the command line, naming an identity as `{morph type}:{key}`, where the type is a morph map alias or a class:

```bash
php artisan authorization:grant user:1 editor
php artisan authorization:grant user:1 editor --actor=user:7
php artisan authorization:revoke user:1 editor
php artisan authorization:list-roles
php artisan authorization:list-permissions
php artisan authorization:why-can user:1 posts:delete posts/42
php artisan authorization:policy:validate --database
php artisan authorization:prune --pretend
php artisan authorization:check
```

`authorization:check` reports the configuration the application runs with, one `name: state` line per check, and exits
with `0`. It reports whether the Gate hook is enabled:

```text
Gate hook: enabled (the package answers every ability it declares through Gate::before)
```

It is the start of the configuration report: each setting and seam it comes to report adds a line.

The listing commands are administrative views: they list every role or permission, platform-wide and tenant-owned
alike, and show each one's owner. `grant` and `revoke` write through the grant service and look the role up within the
tenant scope, so without a resolved tenant they find platform-wide roles only. A role the identity already holds with
no expiry, or does not hold, is reported as such and nothing is written. `grant` gives no expiry, so a role the
identity holds on a temporary or expired grant is made permanent and reported as granted. `grant`, `revoke` and
`authorization:sync` take `--actor={morph type}:{key}` to name who made the change, which their events carry and the
grant rows record; it must name a row that exists, and without it they record no actor.

`authorization:prune` removes the grants that no longer count: expired grants, reported as `RoleExpired`,
`PermissionExpired` or `PolicyExpired` with no actor, a role's expired grants of permissions, reported as
`Role\PermissionExpired`, the permission boundaries of a grantee deleted without its model events, such as by a raw
query, reported as `Identity\BoundaryRemoved` and counted apart from its grants, a grantee whose only rows are
boundaries included, then its grants, reported as revoked, then the inline policies of such a grantee, reported as
deleted, and last the resource policy attachments of a record that no longer exists, reported as
`Resource\PolicyDetached`. The record's morph type is resolved to its model class as a grantee's is; a type that names
no model class is reported and its records' attachments are left, and a whole type's attachments are never removed. A
soft-deleted grantee keeps its grants, its boundaries and its inline policies, and a soft-deleted record its
attachments. Expired grants stop counting at their expiry with or without it, so pruning keeps the tables small rather
than making checks correct. Like `model:prune`, it takes `--pretend`, which counts exactly what a run would remove, the
boundaries apart from the grants as a run does, and `--chunk`, and is scheduled like any command:

```php
Schedule::command('authorization:prune')->daily();
```

### Testing assertions

In your tests, `SineMacula\Laravel\Authorization\Testing\Concerns\AuthorizationAssertions` adds `assertCan()`,
`assertCannot()`, `assertHasRole()` and `assertHasPermission()`, and `actingAsIdentity($user, $tenant)` and
`actingAsSubject($subject)`, which make every check without a named subject about that subject, in its tenant. They also
make the subject's identity, or its principal when it has none, the Gate's user, so `Gate::allows()`, `@can` and `can:`
decide about the same subject as the facade without a user signed in; `Gate::forUser()` with the subject's principal or
identity does too. The Gate they bind keeps every ability, policy and callback registered before, and lives in the
test's container, so nothing carries over to the next test. A subject built without a `session` meets no authentication
requirement, so to test one give it a session and bind a checker of your own:

```php
$this->app->instance(AuthenticationRequirementChecker::class, new MetRequirementChecker);
$this->actingAsSubject(new Subject($user, $user, session: 'session-1'));
```

### Design notes

The contracts behind the evaluator, for maintainers and reviewers, are in [docs/design](docs/design/README.md):

| Note                                                                                        | Covers                                                        |
|---------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| [Evaluation order and deny precedence](docs/design/evaluation-order-and-deny-precedence.md) | The stages, policy sources and caps, and why a deny wins      |
| [Wildcard and condition semantics](docs/design/wildcard-and-condition-semantics.md)         | Pattern matching, undecidable tests and condition operators   |
| [Polymorphic identity pivots](docs/design/polymorphic-identity-pivots.md)                   | Why grants work for integer, UUID and ULID keys               |
| [Subject resolver contract](docs/design/subject-resolver-contract.md)                       | The default resolver and how an application binds its own     |
| [Model extension](docs/design/model-extension.md)                                           | Swapping the shipped models for your own subclasses           |
| [Impersonation](docs/design/impersonation.md)                                               | Checking as another principal                                 |
| [Spatie compatibility](docs/design/spatie-compatibility.md)                                 | The import from `spatie/laravel-permission` and its aliases   |
| [Permission catalogue sync](docs/design/permission-catalogue-sync.md)                       | Declaring permissions in code and `authorization:sync`        |
| [Management services](docs/design/management-services.md)                                   | The services every role, permission and grant write uses      |
| [Events](docs/design/events.md)                                                             | The marker, the snapshots, the actor and after-commit         |
| [Gate authority](docs/design/gate-authority.md)                                             | The `Gate::before` hook, the switch and policy classes        |
| [Query scoping](docs/design/query-scoping.md)                                               | `whereAuthorized()`, what it compiles and what it refuses     |
| [Bulk checks](docs/design/bulk-checks.md)                                                   | `checkMany()`, what it reads once and in bulk, and its events |
| [Effective permissions](docs/design/effective-permissions.md)                               | `permissionsFor()`, its scope, exactness and introspection    |

## Requirements

- PHP ^8.3 (extension: mbstring)
- Laravel ^12.40 || ^13.3

## Testing

```bash
composer test               # all suites in parallel (Paratest)
composer test:coverage      # all suites with clover coverage
composer test:unit          # unit suite only
composer test:feature       # feature suite only
composer test:integration   # integration suite only
composer test:performance   # performance budget suite (serial)
composer test:mutation      # scoped mutation gate
composer test:mutation:full # full mutation suite (no thresholds)
composer bench              # PHPBench hot-path benchmarks
composer check              # static analysis + style
composer format             # format the codebase
composer smells             # advisory code smells (duplication, complexity)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on branching, commits, code
quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for the
disclosure policy and contact details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
