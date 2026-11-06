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

Every check runs the same four steps: an explicit deny in any attached policy wins, then an explicit allow, then the
principal's role and permission grants, and anything left is denied.

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
- **Policy documents** with `effect`, `actions`, `resources` and `conditions`, eighteen condition operators (equality,
  set membership, prefix, suffix and glob, IPv4 and IPv6 CIDR, numeric and time comparisons, booleans and nulls) and
  `${…}` interpolation from the check's context. Malformed documents are refused when they are saved.
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
Gate conflict mode, the policy store, the subject resolver, the cache, and the role hierarchy and rank.

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

A check counts the grants made platform-wide and those made in the current tenant; without a tenant, only
platform-wide grants. Granting a tenant's own role in another tenant, or platform-wide, is refused with
`GrantScopeMismatchException`. A revocation removes the grant in the same scope, and a sync replaces the grants of one
scope: the tenant named, else the tenant that owns every target, else the platform. Every grant is for every
application.

A role takes only the platform's permissions and parent roles and its own tenant's, so a platform role takes only the
platform's; anything else is refused with `OwnerMismatchException`. Guards follow the same rule as a role and its
permissions: two concrete guards must match, and a guard-agnostic side suits any. A parent of another guard is refused
with `ParentGuardMismatchException`, and a role or permission granted to a grantee of another guard with
`GranteeGuardMismatchException`. A role's, permission's or policy's owner is fixed once it is created
(`OwnerChangedException`): to move one, create it in the new owner and grant it again.

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
                'effect'     => 'deny',
                'actions'    => ['posts:delete'],
                'resources'  => ['*'],
                'conditions' => ['ip' => ['not_in' => ['10.0.0.1', '10.0.0.2']]],
            ],
        ],
    ],
]));

Authorization::for($user)->can('posts:delete', 'posts/42', ['ip' => request()->ip()]);
Authorization::for($user)->explain('posts:delete', 'posts/42', ['ip' => request()->ip()]);
```

Policies fail closed. A deny whose condition cannot be decided, such as a check made without `ip` in its context,
still applies, while an allow in the same position does not. A check without a resource matches only statements whose
resources include `*`. A stored policy that cannot be read denies every check for its holder, with the reason
`invalid_policy`, until it is fixed.

`Authorization::authorize()` throws `SineMacula\Laravel\Authorization\Exceptions\AuthorizationException` when the check
is denied. It extends Laravel's `Illuminate\Auth\Access\AuthorizationException`, so Laravel's handler answers `403`. It
carries the decision's reason code (`getReason()`) and nothing else: its message is the translated
`authorization::authorization.denied` line, and the action, the resource and the policies stay out of it. The full
decision is on the `AuthorizationFailed` event and `Authorization::lastDecision()`. To reword the message or add a
locale, publish the language files:

```bash
php artisan vendor:publish --tag=authorization-lang
```

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
not after a commit, and still carry the principal, the context and the result as they were evaluated.

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
  permission, and a policy allow admits without one. The check has no resource, so only statements whose resources
  include `*` apply to it.
- `authorize:{action},{route parameter}` decides the action on the parameter's bound model, converted as the Gate
  converts its argument (`morphClass:key`, or the identifier of an `AuthorizableResource`), or on the parameter's value
  when nothing binds it. A value that cannot be identified, such as an unsaved model, or a parameter the route does not
  carry, denies. Without a parameter, the check has no resource. Like Laravel's `can:`, it is placed right after
  `SubstituteBindings` in the middleware priority, so it decides on the bound model wherever the route lists it.
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
thrown. A denial of `role:` is not a decision: it carries `implicit_deny` and the
`authorization::authorization.role_required` line, and records nothing and fires no event.

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
`Gate::allows()` decide about the same subject.

### Design notes

The contracts behind the evaluator, for maintainers and reviewers, are in [docs/design](docs/design/README.md):

| Note                                                                                        | Covers                                                      |
|---------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| [Evaluation order and deny precedence](docs/design/evaluation-order-and-deny-precedence.md) | The four-step decision order and why an explicit deny wins  |
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
