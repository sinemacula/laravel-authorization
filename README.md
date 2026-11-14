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
through it. Adds `role`, `permission` and `authorize` route middleware, Blade directives, console commands and test
assertions.

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

A check weighs the subject, the resource and its tenant first, then any explicit deny, then the caps (guardrails,
permission boundaries and session caps), each of which must allow it, then an allow statement or a permission held.
Anything left is denied. [How a check is decided](docs/guides/policies.md#how-a-check-is-decided) sets out the stages.

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

A check that names no subject is about the user Laravel authenticated on its default guard. An application with
principals or tenants binds its own resolver, a class implementing
`SineMacula\Laravel\Authorization\Contracts\SubjectResolver`, in `config/authorization.php`:

```php
'subject_resolver' => App\Authorization\CurrentSubject::class,
```

Booting never touches the database. Sync the permissions you declare in your deployment, after the migrations:

```bash
php artisan migrate --force
php artisan authorization:sync
```

See [Configuration](docs/guides/configuration.md) for every option.

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

Define permissions as a string-backed enum, and list it under `permission_enums` in `config/authorization.php`. Each
case's value is the permission name:

```php
namespace App\Authorization;

use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

enum PostPermission: string implements PermissionEnum
{
    case UPDATE = 'posts:update';
    case DELETE = 'posts:delete';
}
```

Write them to the database with `php artisan authorization:sync`, then grant roles and permissions, and check them as
with any Laravel ability:

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
                'conditions' => ['ip_not_in' => ['request.ip' => ['10.0.0.0/8', '192.168.0.0/16']]],
            ],
        ],
    ],
]));

Authorization::for($user)->can('posts:delete', 'posts/42'); // false off the network
```

### Guides

| Guide                                                                         | Covers                                                                                   |
|-------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| [Configuration](docs/guides/configuration.md)                                 | Publishing, the connection and table prefix, binding seams, every setting and its checks |
| [Roles, permissions and grants](docs/guides/grants.md)                        | The user model, declaring and syncing permissions, the management services, tenants      |
| [Checking access](docs/guides/checking-access.md)                             | The facade, Laravel's Gate and policy classes, middleware and Blade, bulk checks         |
| [Policies](docs/guides/policies.md)                                           | How a check is decided, policy documents, role, inline and resource-based policies       |
| [Context, attributes and authentication requirements](docs/guides/context.md) | The check's context, subject and resource attributes, authentication requirements        |
| [Boundaries, guardrails and session caps](docs/guides/caps.md)                | Permission boundaries, guardrails, session caps and machines                             |
| [Separation of duties](docs/guides/separation-of-duties.md)                   | Mutually exclusive roles, the conflict report and enforcement                            |
| [Break-glass](docs/guides/break-glass.md)                                     | Emergency access: settings, activation, surrender, revocation and reporting              |
| [Delegated administration and grant hooks](docs/guides/administration.md)     | Administration actions, acting contexts, grant hooks, the grant scope query              |
| [Query scoping](docs/guides/query-scoping.md)                                 | `whereAuthorized()`, declaring a model, what compiles, the model-level scope             |
| [Access reviews](docs/guides/access-reviews.md)                               | Holders and holdings, expiring grants, paging, exports and usage tracking                |
| [Preview and explanations](docs/guides/preview-and-explanations.md)           | What another subject may do, and why a check was decided as it was                       |
| [Events](docs/guides/events.md)                                               | Every event, reading a change for an audit log, which decisions are reported             |
| [Localisation](docs/guides/localisation.md)                                   | The denial and unauthenticated messages and their translation                            |
| [Console commands](docs/guides/console.md)                                    | Every command, the configuration check, the diagnostic boot, `authorization:why`         |
| [Testing](docs/guides/testing.md)                                             | Assertions, acting as a subject and the tenant tree test kit                             |

The contracts behind them, for maintainers and reviewers, are in [docs/design](docs/design/README.md).

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

The performance suite holds query, row and memory budgets in every run. Its wall-clock budgets are compared only when
code coverage is not being collected, since a coverage driver slows the code it measures: `composer test:performance`
enforces them, and a run with coverage still runs those tests but skips their timing comparisons.

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
