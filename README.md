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

Drops into Laravel's existing authorisation machinery: permission enums become Gate abilities, so `Gate::allows()`,
`@can`, `can:` middleware and `$user->can()` work unchanged. Adds `role`, `permission` and `authorize` route middleware,
Blade directives, console commands and test assertions.

## Core Concept

| Concept        | What it is                                                                                                    |
|----------------|---------------------------------------------------------------------------------------------------------------|
| **Principal**  | Who a decision is about: any Eloquent model that implements `AuthorizableIdentity`, usually your user model.  |
| **Role**       | A named set of permissions, granted as one. Roles can inherit from a parent role.                             |
| **Permission** | A named action, such as `posts:update` or `posts.update`, or a wildcard pattern of them, such as `posts:*`.   |
| **Policy**     | A JSON document of statements, each allowing or denying actions on resources, optionally under conditions.    |
| **Decision**   | The answer to one check: allowed or not, with the reason and a trace of the statements that decided it.       |

Every check runs the same stages: the subject, the resource and its tenant are checked first, then an explicit deny in
any attached policy wins, then an explicit allow, then the principal's role and permission grants, and anything left is
denied.

## Features

- **Roles and permissions** as Eloquent models with UUID keys, granted to any model through polymorphic pivots (integer,
  UUID and ULID keys all work), each grant with an optional expiry, stored in UTC whatever zone it is given in. A
  role's grant of a permission can expire too.
- **Owned records**: a role, permission or policy belongs to the platform or to one tenant, and its name is unique
  within its owner (and, for roles and permissions, its guard), so two tenants can each have their own `manager`. A
  tenant cannot take the name of a platform system role, revoking a name removes every held grant of it (the
  platform's and the tenant's), and `hasRole()` given a role model matches only that row.
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
- **Gate auto-wiring**: every case of a configured permission enum is registered as a Gate ability, with a choice of
  what happens when an ability of the same name already exists.
- **A permission catalogue in code**: enums and providers declare each permission with a description, a category and
  its guards, and `authorization:sync` writes them to the database on deploy, reporting stale rows rather than
  deleting them. Booting never touches the database.
- **Route middleware and Blade directives**: `permission:`, `authorize:` and the permission directives decide on the
  same full decision as the Gate; `role:` and the role directives check role membership. `|` separates the names of a
  list: any one of them admits for the middleware and the any-of directives, every one is needed for the all-of ones.
- **System records**: roles, permissions and policies flagged `is_system` cannot be edited, deleted or have the flag
  cleared unless `forceSystem()` unlocks the next change.
- **Explanations**: `Authorization::explain()`, the last decision of the request, and `authorization:why-can` on the
  command line.
- **Management services** that own every write of a role, permission, policy or grant: each call runs in one
  transaction on the package's connection, through the configured models, and grants are idempotent under
  concurrency. The traits, the grant and revoke commands and the Spatie import write through them; only
  `authorization:sync` still writes the permission catalogue through the permission model, in its own transaction.
- **Events** for every grant, revocation, expiry change and model change that changes something, for each use of the
  system override, for each decision, and when `authorize()` refuses. All implement one marker interface; the change
  events are snapshots of plain values that carry the actor the caller named, and are dispatched only once the write
  commits.
- **Resolution cache** for roles, permissions and policies, in memory and optionally in any cache store, versioned so
  every write takes effect on the next check in every worker, and falling back to the database when the store fails.
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
that user into.

An application with principals or tenants binds its own resolver, a class implementing
`SineMacula\Laravel\Authorization\Contracts\SubjectResolver`, in `config/authorization.php`. The active tenant comes
only from it: without a tenant, only platform-wide roles and permissions are visible.

```php
'subject_resolver' => App\Authorization\CurrentSubject::class,
```

List the enums whose cases should become Gate abilities and permissions, and any permission providers:

```php
'permission_enums' => [
    App\Authorization\PostPermission::class,
],

'permission_providers' => [
    App\Authorization\MediaPermissions::class,
],
```

The same declarations are the actions a policy may name: a policy is refused when it is saved if one of its `actions` or
`not_actions` patterns matches no declared permission, and with nothing declared no policy can be saved.

Booting the package never queries or writes the database, so `config:cache`, `route:cache` and `migrate` run before
the tables exist. The permissions the enums and providers declare reach the database when you sync them, which belongs
in your deployment after the migrations:

```bash
php artisan migrate --force
php artisan authorization:sync
```

The package writes its warnings (a Gate conflict under the `log` mode, a discarded cache entry, a policy whose document
cannot be read) to your default log channel. To send them elsewhere, name a channel from `config/logging.php`:

```dotenv
AUTHORIZATION_LOG_CHANNEL=stderr
```

`config/authorization.php` documents every other option: models, tables, the default guard, permission providers, the
Gate conflict mode, the policy store, the policy limits, the context keys and sources, the attribute providers, the
subject resolver, the authentication requirement checker, the cache, and the role hierarchy and rank.

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

Keys may be integers, UUIDs or ULIDs. Deleting the model removes its grants; a model that soft-deletes keeps them until
it is force-deleted, so restoring it restores its access. To deny a suspended user everything, override
`isAuthorizationActive()`:

```php
public function isAuthorizationActive(): bool
{
    return $this->suspended_at === null;
}
```

A check about an inactive subject is denied with the `subject_inactive` reason before anything else is read. When the
subject resolver returns a subject with a separate identity (an account belonging to a person, say), a check counts the
grants and policies of both, and is denied if either is inactive.

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
catalogue and can be checked through the `Authorization` facade and `hasPermission()`, but they are not registered as
Gate abilities and do not appear in `effectivePermissions()`. Declare a permission as an enum case when it must work
with `Gate`, `@can` or the `can:` middleware:

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

Every write goes through four services, which you inject or resolve from the container: `RoleService`,
`PermissionService` and `PolicyService` for the records, and `GrantService` for what a grantee holds. Each call runs in
one transaction on the package's connection (`authorization.connection`), through the models `authorization.models`
configures, and takes the actor making the call as an optional `actor`, a model or a reference (null for console and
system work). Every event the call dispatches carries it, and every grant row it writes records it in
`granted_by_type` and `granted_by_id`; it is never read from the signed-in user:

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

A check counts the grants made platform-wide and those made in the current tenant; without a tenant, only platform-wide
grants. Granting a tenant's own role outside that tenant and the tenants below it, or platform-wide, is refused with
`GrantScopeMismatchException`. A revocation removes the grant in the same scope, and a sync replaces the grants of one
scope: the tenant named, else the tenant that owns every target, else the platform. A grant is for every
application unless the call names one.

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
guard with `GranteeGuardMismatchException`. A role's, permission's or policy's owner is fixed once it is created
(`OwnerChangedException`): to move one, create it in the new owner and grant it again.

Tenants can form a tree (an organisation above its accounts, say). The package never stores it: bind a class
implementing `SineMacula\Laravel\Authorization\Contracts\TenantTree` as `tenant_tree` in `config/authorization.php`,
answering a tenant's ancestors, whether one tenant is within another, and a tenant's subtree as a query. The default is
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
decided it (`stage`), the statements that did (`statements`) and a trace of every step. `can()` and `authorize()` are
shortcuts over it. A check runs in stages, stopping at the first that decides: the subject (`subject_unresolved`,
`subject_inactive`), the resource (`resource_unresolved`), its tenant (`tenant_scope`), then the denies in every
applicable policy (`explicit_deny`, or `invalid_policy` for a statement that cannot be evaluated), then the allows (an
allow statement, then a permission held), then the implicit deny (`insufficient_authentication` when an allow statement
names the check and only its [authentication requirement](#authentication-requirements) is unmet, `condition_failed`
when an allow statement names the check but its conditions do not hold, else `no_match`). Each stage assesses its
statements in a fixed order, so the decision is the same whatever order the policies are read in, and the trace records
condition key names and whether each held, never their values:

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
read, unless a platform-wide grant of the permission covers it. The default knows no record's tenant. Any other string
is never given a tenant, so a tenant-owned resource that is not a model should implement `AuthorizableResource` and
carry its tenant.

Policies fail closed. A deny whose condition cannot be decided, such as one on `request.ip` in a check made outside a
routed request (a queued job, a console command), where the key is missing, still applies, while an allow in the same
position does not. A check without a resource
matches only statements with neither `resources` nor `not_resources`, or whose `resources` include `*`. A stored policy
that cannot be read, or that is over a configured limit, denies every check for its holder, with the reason
`invalid_policy`, until it is fixed.

`Authorization::authorize()` throws `SineMacula\Laravel\Authorization\Exceptions\AuthorizationException` when the check
is denied. It extends Laravel's `Illuminate\Auth\Access\AuthorizationException`, so Laravel's handler answers `403`. It
carries the decision's reason code (`getReason()`) and nothing else: its message is the translated
`authorization::authorization.denied` line, and the action, the resource and the policies stay out of it. A denial as
`insufficient_authentication` throws `InsufficientAuthenticationException` instead (see [Authentication
requirements](#authentication-requirements)). The full decision is on the `AuthorizationFailed` event and
`Authorization::lastDecision()`. To reword the message or add a locale, publish the language files:

```bash
php artisan vendor:publish --tag=authorization-lang
```

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
| `conditions`    | Optional: a map of operator to context key path to operand, every test of which must hold |

A statement takes exactly one of `actions` and `not_actions`, and at most one of `resources` and `not_resources`; each
is a non-empty list of non-empty strings. Without either resource list a statement names every resource and a check that
names none. `not_resources` still scopes the statement to resources, so it never covers a check without one. The `sid`
names the statement in the decision and the trace, and never changes how it is evaluated.

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
  key instead, and any other operator takes the `_if_exists` suffix (`ip_in_if_exists`, `eq_if_exists`), under which a
  missing key passes; everything else is decided as without it.
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

What the caller passes lands under `input`, and only there: the `$context` of `check()`, `can()`, `authorize()`,
`explain()` and `effectivePermissions()`, the string-keyed and associative arguments of a Gate check, and the context
of `assertCan()` and `assertCannot()`. A caller can never supply a trusted value:

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

`max_age` is a whole number of seconds, at least 1: the proof that meets the part must be no older. `min` is a
non-empty string, an assurance level your checker knows. Every part named must be met, and the requirement is one test
judged whole, so it counts as one key test against the `conditions` limit. The policy is refused when it is saved if
the requirement is on any key but `authentication`, names no part, an unknown part or an unknown option, gives a
`max_age` that is not a whole number of at least 1, or gives `assurance_level` no `min`. There is no
`authentication_requirement_if_exists`. `authentication` is not read from the context here, so the requirement needs no
key declared in the catalogue.

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
nothing it answers is remembered. A met result whose instant has already passed counts as unmet, every part with it.
An unmet result keeps only the parts the requirement names, and one that names none of them leaves every part unmet. A
checker that throws makes the test undecidable, so an allow it guards does not apply and a deny it guards does; the
failure is logged at debug level by the checker's class alone, never with anything it held.

#### Sessions

`Subject::$session` is the session the checker judges. The shipped resolver sets it to the current request's session
id when the subject is the user signed in on its guard, including when the Gate hands it that same user. It is null for
a subject you name (`Authorization::for($user)`, or `Gate::forUser()` with another user) and outside a session (a
console command, a queued job, a request without a started session), and a subject without a session meets no
requirement: every part is unmet and the checker is not asked. A resolver of your own sets `session` to whatever its
checker knows the proofs by.

#### The decision and the exception

A check is denied as `insufficient_authentication` when no deny applies, no invalid policy blocks it, nothing else
allows it (no other allow statement and no permission held), and at least one allow statement names the action and the
resource with every other condition holding and only its requirement unmet. It ranks above `condition_failed`, and
deny precedence always wins. A requirement that cannot be checked is undecidable, not unmet, so its statement is no
candidate and, alone, leaves the check `condition_failed`. The decision's
`requirements` lists each such statement's requirement with its unmet parts, as an `UnmetRequirement`: they are
alternatives, any one of which met would allow the check. On a deny statement an unmet requirement is a test that does
not hold, so the deny does not apply, while one that cannot be checked applies it, as any undecidable test does. The
trace records the requirement as the key `authentication`, with whether it held, and never a proof.

`authorize()`, and the `permission:` and `authorize:` middleware, throw
`SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException` for it. It extends Laravel's
`Illuminate\Auth\Access\AuthorizationException`, not the package's, so a handler that maps the package's denials does
not catch it, and an application that maps it to nothing still answers `403`. It carries the reason code
(`getReason()`) and the candidate requirements, once each (`requirements()`); never a policy, a statement, the trace or
a proof. Its message is the translated `authorization::authorization.insufficient_authentication` line. Like any
denial, it is recorded as the last decision and fires `AuthorizationFailed` first. Map it to your step-up response,
such as RFC 9470's `insufficient_user_authentication` challenge:

```php
// bootstrap/app.php
use Illuminate\Foundation\Configuration\Exceptions;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;

->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->render(fn (InsufficientAuthenticationException $exception) => response()->json(
        [
            'message'      => $exception->getMessage(),
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

A decision that read a requirement is reused only while it still holds. `Authorization::lastDecision()` returns it
only in the session it was made in and until the earliest instant a met requirement it read stops being met
(`$decision->freshness`, and `isFreshFor($session)`). Nothing else keeps a decision: `can()`, the Gate, the Blade
directives and `effectivePermissions()` decide afresh every time, and the resolution cache holds grants and policies,
never decisions.

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
listener, or one audit mapper registration, covers them all. The grant events also implement `IdentityEvent` and name
their `grantee`:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;

Event::listen(static function (AuthorizationEvent $event): void {
    // Every role, permission, policy and grant change, every override and every decision.
});

Event::listen(static function (RoleDeleted $event): void {
    $event->role;               // Reference: the role's morph type and key
    $event->grantees;           // a Reference to every grantee that held it
    $event->operation->actor;   // the actor the caller passed, or null
    $event->operation->id;      // the same for every event of the call
});
```

The change events (roles, permissions and policies created, updated and deleted; permissions granted to and revoked
from a role; roles, permissions and policies granted to, revoked from and re-dated on a grantee; and
`SystemOverrideUsed`) are `final readonly` snapshots of plain values: a record is a `Reference`, its morph class under
your morph map and its key as a string, never a model, alongside names, the scope, expiries and times. An update
carries the fields it changed, before and after. A policy event carries its document's version and SHA-256 digest,
never the document. A delete lists every grantee that held the role, permission or policy, so the evidence says who
lost access.

Each is dispatched only once its write commits on the package's connection: inside your own transaction it waits for
the outermost commit, and a transaction that rolls back dispatches nothing. Every event of one service call carries
the same operation id and the call's actor; a write made through a model outside the services is an operation of its
own with no actor. A change `forceSystem()` unlocked dispatches `SystemOverrideUsed`, naming the record, the change and
the actor.

`DecisionEvaluated` and `AuthorizationFailed` implement the marker too, but are dispatched when the decision is made,
not after a commit, and still carry the principal, the context and the decision as they were evaluated.

### Middleware and Blade

The package registers three route middleware aliases, each only when the application has not already taken it:

```php
Route::get('/reports', ListReports::class)->middleware('permission:reports:view|reports:manage');
Route::put('/posts/{post}', UpdatePost::class)->middleware('authorize:posts:update,post');
Route::get('/admin', AdminDashboard::class)->middleware('role:admin|editor');
Route::get('/api/admin', ApiAdmin::class)->middleware('role:admin,api');
```

- `permission:` decides each listed action on the same full decision as `Authorization::can()`, `@can` and the Gate:
  policies, explicit denies, the permissions held and the subject's tenant. An explicit deny wins over a held
  permission, and a policy allow admits without one. The check has no resource, so only statements with neither
  `resources` nor `not_resources`, or whose `resources` include `*`, apply to it.
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
(`401`). A denial throws the package's `AuthorizationException` (`403`) with the reason code and a translated message.
A denial of `permission:` or `authorize:` is a decision: it is recorded as the last decision and fires
`AuthorizationFailed` once, for the list's last action, before the `authorization::authorization.denied` line is
thrown, or, when that action is denied as `insufficient_authentication`, an `InsufficientAuthenticationException` (see
[Authentication requirements](#authentication-requirements)). A denial of `role:` is not a decision: it carries
`no_match` and the `authorization::authorization.role_required` line, and records nothing and fires no event.

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
```

The listing commands are administrative views: they list every role or permission, platform-wide and tenant-owned
alike, and show each one's owner. `grant` and `revoke` write through the grant service and look the role up within the
tenant scope, so without a resolved tenant they find platform-wide roles only. A role the identity already holds with
no expiry, or does not hold, is reported as such and nothing is written. `grant` gives no expiry, so a role the
identity holds on a temporary or expired grant is made permanent and reported as granted. `grant`, `revoke` and
`authorization:sync` take `--actor={morph type}:{key}` to name who made the change, which their events carry and the
grant rows record; it must name a row that exists, and without it they record no actor.

`authorization:prune` removes the grants that no longer count: expired grants, reported as `RoleExpired`,
`PermissionExpired` or `PolicyExpired` with no actor, a role's expired grants of permissions, reported as
`Role\PermissionExpired`, and the grants of a grantee deleted without its model events, such
as by a raw query, reported as revoked. A soft-deleted grantee keeps its grants. Expired grants stop counting at their
expiry with or without it, so pruning keeps the tables small rather than making checks correct. Like `model:prune`, it
takes `--pretend` and `--chunk`, and is scheduled like any command:

```php
Schedule::command('authorization:prune')->daily();
```

### Testing assertions

In your tests, `SineMacula\Laravel\Authorization\Testing\Concerns\AuthorizationAssertions` adds `assertCan()`,
`assertCannot()`, `assertHasRole()` and `assertHasPermission()`, and `actingAsIdentity($user, $tenant)` and
`actingAsSubject($subject)`, which make every check without a named subject about that subject, in its tenant. When
the Gate hands over the subject's principal or identity (for example after `actingAs($identity)`), `@can`, `can:` and
`Gate::allows()` decide about the same subject. A subject built without a `session` meets no authentication
requirement, so to test one give it a session and bind a checker of your own:

```php
$this->app->instance(AuthenticationRequirementChecker::class, new MetRequirementChecker);
$this->actingAsSubject(new Subject($user, $user, session: 'session-1'));
```

### Design notes

The contracts behind the evaluator, for maintainers and reviewers, are in [docs/design](docs/design/README.md):

| Note                                                                                        | Covers                                                      |
|---------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| [Evaluation order and deny precedence](docs/design/evaluation-order-and-deny-precedence.md) | The staged decision order and why an explicit deny wins     |
| [Wildcard and condition semantics](docs/design/wildcard-and-condition-semantics.md)         | Pattern matching, undecidable tests and condition operators |
| [Polymorphic identity pivots](docs/design/polymorphic-identity-pivots.md)                   | Why grants work for integer, UUID and ULID keys             |
| [Subject resolver contract](docs/design/subject-resolver-contract.md)                       | The default resolver and how an application binds its own   |
| [Model extension](docs/design/model-extension.md)                                           | Swapping the shipped models for your own subclasses         |
| [Impersonation](docs/design/impersonation.md)                                               | Checking as another principal                               |
| [Spatie compatibility](docs/design/spatie-compatibility.md)                                 | The import from `spatie/laravel-permission` and its aliases |
| [Permission catalogue sync](docs/design/permission-catalogue-sync.md)                       | Declaring permissions in code and `authorization:sync`      |
| [Management services](docs/design/management-services.md)                                   | The services every role, permission and grant write uses    |
| [Events](docs/design/events.md)                                                             | The marker, the snapshots, the actor and after-commit       |

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
