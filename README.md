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
`@can`, `can:` middleware and `$user->can()` work unchanged. Adds `role` and `permission` route middleware, Blade
directives, console commands and test assertions.

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
  UUID and ULID keys all work), each grant with an optional expiry, stored in UTC whatever zone it is given in.
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
- **Route middleware and Blade directives** for roles and permissions, with `|` or `,` between alternatives.
- **System records**: roles, permissions and policies flagged `is_system` cannot be edited, deleted or have the flag
  cleared unless `forceSystem()` unlocks the next change.
- **Explanations**: `Authorization::explain()`, the last decision of the request, and `authorization:why-can` on the
  command line.
- **Events** for every grant, revocation, expiry change and model change, for each decision, and when `authorize()`
  refuses.
- **Resolution cache** for role and permission lookups, in memory and optionally in a cache store.
- **Swappable everything**: models, table names, the database connection, the principal resolver, the tenant resolver
  and the policy store.
- **Spatie import**: `authorization:migrate-spatie` copies roles, permissions and grants from
  `spatie/laravel-permission` (its `guard_name` becomes `guard`), reporting and skipping any role or permission whose
  name the package refuses, and any permission whose name contains `*`, along with its grants.

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

The package decides nothing about the current user until you tell it where to find one. The shipped principal
resolver returns `null`, so checks made without a principal are denied. To check the user your auth guard
authenticated, bind the shipped guard resolver in `config/authorization.php`:

```php
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardPrincipalResolver;

'principal_resolver' => AuthGuardPrincipalResolver::class,
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
Gate conflict mode, the policy store, the tenant resolver, the cache, and the role hierarchy and rank.

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

A module that ships its own permissions can declare them with a provider instead of an enum case:

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
listed with its action, as a table or, with `--format=json`, as JSON. A name outside the package's name rules, or an
empty guard list, fails the sync with exit code `2` before anything is written. In CI, `--dry-run` exits with `1` when
anything would be added, updated or pruned:

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

```php
Route::put('/posts/{post}', UpdatePost::class)->middleware('permission:posts:update');
Route::get('/admin', AdminDashboard::class)->middleware('role:admin|editor');
```

```blade
@can('posts:update')
    <button>Edit</button>
@endcan

@role('admin')
    <a href="/admin">Admin</a>
@endrole
```

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

From the command line, naming an identity as `{morph type}:{key}`, where the type is a morph map alias or a class:

```bash
php artisan authorization:grant user:1 editor
php artisan authorization:revoke user:1 editor
php artisan authorization:list-roles
php artisan authorization:list-permissions
php artisan authorization:why-can user:1 posts:delete posts/42
```

The listing commands are administrative views: they list every role or permission, platform-wide and tenant-owned
alike, and show each one's owner. `grant` and `revoke` look the role up within the tenant scope, so without a resolved
tenant they find platform-wide roles only.

In your tests, `SineMacula\Laravel\Authorization\Testing\Concerns\AuthorizationAssertions` adds `assertCan()`,
`assertCannot()`, `assertHasRole()` and `assertHasPermission()`.

### Design notes

The contracts behind the evaluator, for maintainers and reviewers, are in [docs/design](docs/design/README.md):

| Note                                                                                        | Covers                                                      |
|---------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| [Evaluation order and deny precedence](docs/design/evaluation-order-and-deny-precedence.md) | The four-step decision order and why an explicit deny wins  |
| [Wildcard and condition semantics](docs/design/wildcard-and-condition-semantics.md)         | Pattern matching, undecidable tests and condition operators |
| [Polymorphic identity pivots](docs/design/polymorphic-identity-pivots.md)                   | Why grants work for integer, UUID and ULID keys             |
| [Principal resolver contract](docs/design/principal-resolver-contract.md)                   | The default resolver and how an application binds its own   |
| [Model extension](docs/design/model-extension.md)                                           | Swapping the shipped models for your own subclasses         |
| [Impersonation](docs/design/impersonation.md)                                               | Checking as another principal                               |
| [Spatie compatibility](docs/design/spatie-compatibility.md)                                 | The import from `spatie/laravel-permission` and its aliases |
| [Permission catalogue sync](docs/design/permission-catalogue-sync.md)                       | Declaring permissions in code and `authorization:sync`      |

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
