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
must each allow the check, then an explicit allow or a permission held allows it, and anything left is denied. A check
of an administration action on its own operation resource then passes the operation's constraints, which can only
refuse what the allow permitted (see [Delegated administration](#delegated-administration)).

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
  a guardrail grants nothing, and only an actor holding `authorization:guardrail.manage` from above the scope, a
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
  grants and policies, and listing them records no decision and dispatches no event, except on a preview, whose
  listing dispatches one event per action (see Preview).
- **Preview**: `previewFor($subject)` answers what another subject may do, for "what can this person do?" screens, while
  the caller stays who is asking. The caller must hold `authorization:subject.preview` for the subject in every scope a
  decision is made in, admitted as a check about the caller at every use; the subject is evaluated with no session,
  every decision is reported with both the previewer and the previewed subject, and nothing a preview evaluates may
  change anything. The package never impersonates.
- **Access reviews**: `AccessReview` lists who holds a role, permission or policy in a scope, what a subject holds and
  where, what expires within a window and what an actor last granted, one row for each grant route, by reference alone,
  in one order on every database and bounded by a limit. A review is admitted through `check()` as the reviewer under
  `authorization:review.read`, across the whole of a broad reach, or run as trusted work. It is read a page at a time
  by keyset with signed cursors, streamed a chunk at a time, or exported as versioned JSON Lines under
  `authorization:review.export` as well, and `authorization:review` exports one from the console. With opt-in usage
  tracking it also lists which grants show no observed use (`unused()`), every row carrying a `usage` status of
  `used`, `unused` or `unknown`.
- **Grant scope query**: `GrantScopeQuery` tells a trusted integration whether every grant of an identity and of the
  principals an application-bound identity directory lists lies within a tenant (`within`), any lies outside it
  (`outside`), or that cannot be told (`unknown`), and whether a principal holds a grant that applies in a tenant. It
  returns only the answer, in one query whatever the number of grants or the depth of the tree, and is neither
  membership nor authorisation.
- **Grant hooks**: before a grant that widens an identity's scope is written (to the identity itself, platform-wide,
  or in a tenant its principals held nothing in), the grant service calls the bound hook, before the package takes any
  lock, for trusted and delegated calls alike. A hook may only refuse, by throwing, and every management service refuses
  while it runs.
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
- **Explanations**: `Authorization::explain()` decides a check in explain mode and returns an `Explanation`: the
  statements, caps or permission that decided it, every condition test with its outcome, the keys found missing, the
  stages it never reached and where each grant that allowed it came from, as text or versioned JSON, never a value; the
  last decision of the request explains with what it recorded, and `authorization:why` prints the explanation of a
  saved subject's check from the command line, under the scope and console context its options name.
- **Delegated administration**: every change a management service makes is an administration action the package
  declares (`authorization:role.grant`, `authorization:policy.update` and the rest), decided through `check()` as the
  acting subject on an operation resource naming the change, inside the change's transaction and before anything is
  written, when the call names an acting context; a call that names none is trusted system work. A screen checking the
  same operation gets the same decision. This release weighs the administered scope, rank and self of every change to
  a subject, possession or explicit grantability of every permission and policy handed out, a granted role's whole
  authority included, the owner rule and the impact on every existing holder of a change to a definition, and
  boundaries and resource-policy attachments, and refuses, as `administration.unprovable`, every change it cannot prove.
  A delegated call locks what its decisions read and checks it again before it writes, so it never commits on
  authority that changed under it: a conflict is tried again, then refused as `administration.conflict` (see
  [Delegated administration](#delegated-administration)).
- **Management services** that own every write of a role, permission, policy, grant, resource attachment, permission
  boundary or guardrail: each call runs in one transaction on the package's connection, through the configured models,
  and grants are idempotent under concurrency. The traits, the grant and revoke commands and the Spatie import write
  through them; only `authorization:sync` still writes the permission catalogue through the permission model, in its own
  transaction.
- **Events** for every grant, revocation, expiry change, resource attachment, boundary or guardrail change and model
  change that changes something, for each use of the system override, for each decision, and when `authorize()` refuses.
  All implement one marker interface; the change events are snapshots of plain values that carry the call's operation
  (its id, its actor and identity, whether it was trusted or delegated, and its actions), and are dispatched only once
  the write commits.
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

Every seam the package gives a default for can also be bound directly on its contract, from any service provider: the
subject resolver, the tenant tree, the identity directory, the grant hook, the console subject resolver, the resource
tenant resolver, the policy store, the policy resolver, the action catalogue, the context key catalogue, the
authentication requirement checker, the session policy source and the authentication, request and environment contexts.
The package binds its default only when nothing is bound to the contract yet, so a binding made before it registers, by
a sibling package or by your application, `instance()` included, stands, and a binding made afterwards with `bind()`,
`singleton()`, `scoped()` or `instance()` replaces the default. A class you name in `config/authorization.php` is
different: when `subject_resolver`, `tenant_tree`, `identity_directory`, `resource_tenant_resolver`,
`requirement_checker` or `session.source` names a class other than the package's default, or when `policy_store` names
any class, the package binds the contract to it even over a binding a sibling package made before it registered, since
your configuration is the explicit choice. The same holds for a sibling package's deferred provider, which would
otherwise bind the contract at its first resolution and so replace your class: the package loads that provider before
binding your class, as it registers when the application already knows of the provider, and otherwise as the application
boots, since Laravel learns of the deferred providers of your configuration and of package discovery only once every
eager provider, this package among them, has registered. A value equal to the package's default, or no value, binds
nothing over an earlier binding, and nor does a value that names no class implementing the contract (null, a number or
an empty string among them): the package binds its default as though nothing were configured, so registering never fails
on it, and the boot refuses the setting. `policy_store` differs on both counts: the package has no store of its own, so
such a value binds nothing at all, and null is not refused, since it means no store. From the highest precedence down, a
contract resolves to a binding made after the package registers, then the class your configuration names, then a binding
made before the package registers, then the package's default. Binding your configured class over a contract follows
Laravel's rules for any binding: an extender a sibling package registered on the contract is applied to your class, so
one typed to the sibling's own class fails, and when the contract was already resolved, a callback watching it with
`rebinding()` or `refresh()` is called, which may resolve your class while the package registers. The grant hook is the
one exception: hooks only refuse, so when `grant_hooks` lists any, the package extends the contract and the listed hooks
run before whatever hook it resolves to, rather than replacing it (see [Grant hooks](#grant-hooks)). The order your
providers register in therefore never lets the package's default replace a binding of yours. It still decides between
other bindings of the same contract: of two bindings made outside the package, by a sibling package and your application
for example, the later one wins as usual, and a `bindIf()`, `singletonIf()` or `scopedIf()` only fills a contract
nothing has bound yet, so one made after the package registers is skipped and the package's default, or your configured
class, stands. To replace a seam whatever order providers register in, bind it unconditionally. A binding of your own is
kept as you bound it across the reset between queue jobs and Octane requests, while the package's defaults and
configured classes, the context key catalogue aside, are built afresh for each.

A sibling package that registers after this one and wants to replace only the package's default, never a binding the
application made, asks `AuthorizationServiceProvider::isPackageDefault($app, $contract)`. It is true only while the
contract holds the package's own default: a class your configuration names, an instance, any other binding and an
unbound contract all answer false.

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
that no permissions are declared, unless it names only the package's own actions, the administration actions of
[Delegated administration](#delegated-administration), `authorization:guardrail.manage` among them (see
[Guardrails](#guardrails)), which a policy may always name.

Booting the package never queries or writes the database, so `config:cache`, `route:cache` and `migrate` run before
the tables exist. The permissions the enums and providers declare reach the database when you sync them, which belongs
in your deployment after the migrations:

```bash
php artisan migrate --force
php artisan authorization:sync
```

The package writes its warnings (a discarded cache entry, a policy whose document cannot be read) to your default log
channel. To send them elsewhere, name a channel from `config/logging.php`; a name that is not one is refused at boot:

```dotenv
AUTHORIZATION_LOG_CHANNEL=stderr
```

`config/authorization.php` documents every other option: models, tables, the default guard, permission providers, the
Gate switch, the policy store, the policy limits, the context keys and sources, the attribute providers, the subject
resolver, the identity directory, the authentication requirement checker, the session policy source and the scope map,
the cache, the bulk checks' chunk size, the role hierarchy and rank, the access reviews' limit, and grant usage
tracking (see [Usage tracking](#usage-tracking)).

### Configuration checks

Every setting is checked when the application boots, and a malformed one stops the boot with an
`InvalidAuthorizationConfigException` naming the setting, rather than being read as something else:

- A key the package does not define is refused, at the top level and in every block whose keys the package defines
  (`models`, `tables`, `defaults`, `gate`, `policies` and `policies.limits`, `context`, `attributes`, `session`,
  `cache`, `hierarchy`, `rank`, `query_scoping`, `bulk`, `administration`, `reviews` and `usage`), naming its full
  path, such as `authorization.models.rol`, so a misspelt key never leaves its default in place. The maps you fill in
  (`context.keys`, `context.sources`, the attribute providers, `session.scopes` and `application_access`) take any
  key; each entry is checked against its own shape instead.
- A setting left out takes its default, also when the configuration was cached without the package's defaults merged
  into it. A setting set to null is refused, a block set to null among them, except where null means the default or
  none: `connection`, `policy_store`, `cache.store`, `usage.connection`, `usage.queue` and `log_channel`. The whole
  `authorization` configuration must be an array.
- A value read from the environment is checked as it is written, since the config file casts none of them. A whole
  number is an int, or a string written as one in base 10 (`300`, not `300s`, `3e2`, `300.0`, `-0`, one with a space
  around it or an empty value) and no larger than PHP holds. A switch (`gate.enabled`, `hierarchy.enabled`,
  `rank.enabled` and `usage.enabled`) is true or false, which the environment gives for `true`, `false`, `(true)` and
  `(false)`; `0`, `1`, `off` and `no` are refused.
- Each table name is a plain identifier (a letter or an underscore, then letters, digits and underscores) with no
  schema before it, short enough that every index and key name the migrations build from it fits in 63 characters,
  PostgreSQL's limit (from 33 to 51 characters, depending on the table), and the twelve names are distinct.
- `defaults.guard` names a guard in `auth.guards`, `log_channel` a channel in `logging.channels`, and
  `usage.connection`, when set, a connection in `queue.connections`. `connection` names a connection in
  `database.connections`, or, when it is null or empty, `database.default` must. Each is read from the configuration as
  it stands when the application boots, and nothing is connected to.
- `cache.prefix` is a string that is not empty, and `cache.ttl` a whole number of seconds of at least 1.
- `hierarchy.enabled` and `rank.enabled` are switches, checked as `gate.enabled` is.

A setting the package reads after boot is read through the same checks, so one changed at run time (by `config()->set()`
in a test, a queue worker or an Octane request) is refused with the same exception when it is read, never read as its
default, cast or skipped. That covers the policy limits, the query scoping limits, the bulk chunk size, the
administration limits, the access reviews' limit, usage tracking, `cache.ttl` and `cache.prefix`, the three switches,
the permission enums and providers, `application_access` (an entry for an application that is not a permission name,
null among it, is refused rather than opening the application), `session.scopes`, `context.keys` and `context.sources`,
the attribute providers and `grant_hooks`. A block on the way to a setting that is not an array is refused too, rather
than read as one that leaves the setting out. A setting read on every check is read with a few array lookups and plain
comparisons, so the checks add next to nothing to a request.

The names are checked after boot for their type only. A table name, a model class or `defaults.guard` that is not a
string, or is empty, is refused with the same exception, and so is a `connection` or `cache.store` that is neither null
nor a string, or a `cache.store` that is empty (null, and for `connection` an empty string, mean the default). Whether
the name exists is checked only at boot, so one changed after boot to a name that does not exist is used as it is, never
swapped for the default: a table fails with the database's own error and a model class with PHP's when they are used, a
connection or a cache store with Laravel's own `InvalidArgumentException` from the database or cache manager, and a
lookup by name under a guard that does not exist finds only the roles and permissions that name no guard. The log
channel is checked at boot only, by design: a warning is written from inside error handling, and writing one never stops
a check, so a channel changed after boot to one that does not exist is written to as the default channel.

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
whose acting context is required (see [Guardrails](#guardrails)). Each call runs in one transaction on the package's
connection (`authorization.connection`), through the models `authorization.models` configures, and takes an optional
`actor`, the `ActingContext` making the call. A call without one is trusted system work, as seeders, migrations and
console commands are, and is not decided; a call with one is delegated administration, each change decided as that
actor (see [Delegated administration](#delegated-administration)). Every event the call dispatches carries its
operation, and every grant row it writes records the actor in `granted_by_type` and `granted_by_id`; it is never read
from the signed-in user:

```php
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;

$roles  = app(RoleService::class);
$grants = app(GrantService::class);

// Trusted work, such as a seeder: nothing is decided.
$editor = $roles->create('editor', 'web', 'Edits posts');
$author = $roles->create('author', tenant: $team); // owned by the team, not the platform
$roles->grantPermission($editor, 'posts:update');
$roles->setParent($editor, 'author');

$grants->grantRole($user, $editor, now()->addMonth()); // GrantOutcome::GRANTED
$grants->syncPermissions($user, ['posts:delete']);     // SyncResult

// Delegated administration: decided as the request's subject.
$grants->revokeRole($user, 'editor', actor: ActingContext::current()); // 1, the roles revoked
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
application counts and policies can add conditions or denies. It is made without session caps, for people and machines
alike: a principal being admitted holds no session yet, so the scopes of the request's credential, which belong to
whoever made the request, never cap it, and a machine is not refused for lacking scopes it has yet to be given. Its
denies, guardrails and permission boundaries still refuse it. Once the session exists, its caps apply to every check
(see [Session caps and machines](#session-caps-and-machines)).

A role takes only the platform's permissions and parent roles, its own tenant's and its tenant's ancestors', so a
platform role takes only the platform's; anything else is refused with `OwnerMismatchException`. Guards follow the same
rule as a role and its permissions: two concrete guards must match, and a guard-agnostic side suits any. A parent of
another guard is refused with `ParentGuardMismatchException`, and a role or permission granted to a grantee of another
guard with `GranteeGuardMismatchException`. The tenant that owns a role, permission or policy is fixed once it is
created (`OwnerChangedException`): to move one, create it in the new tenant and grant it again.

**How a tenant is named.** A tenant is an Eloquent model, or any object implementing
`SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant`, and the package names it by its morph type and its
`getKey()` everywhere: in the `tenant_type` and `tenant_id` of every grant and owned row, in the tenant tree's questions
and answers, in the resolution cache's keys, in events and in a `Support\Reference`. `getKey()` is the contract's
identifier, and for a model it is the primary key, so a tenant that also carries a public identifier of its own (a slug,
an external id) is still named by its key. A sibling package, or the application, naming a tenant to this one passes
the tenant, a `Reference` made from it, or its morph type and key, never the other identifier. A non-Eloquent tenant
returns from `getKey()` the value its rows are to be keyed by, and keeps it for the tenant's life.

Tenants can form a tree (an organisation above its accounts, say). The package never stores it: bind a class
implementing `SineMacula\Laravel\Authorization\Contracts\TenantTree` as `tenant_tree` in `config/authorization.php`,
answering a tenant's ancestors, whether one tenant is within another, and a tenant's subtree as a query. The subtree
query selects exactly the `tenant_type` and `tenant_id` of every tenant within, whatever the tenant scope. Two readers
nest it whole in a query of their own, so each needs it on that query's connection: [query scoping](#query-scoping)
needs it on the connection of the models it scopes, and the [grant scope query](#grant-scope-query) needs it on the
package's connection (`authorization.connection`). A tree kept on the connection of both the scoped models and the
package's tables serves both. The default is a flat set of tenants. With a tree, a grant in a tenant also applies in
every tenant below it, unless it is limited to that tenant, and a tenant sees the roles, permissions and policies its
ancestors own as well as its own and the platform's; the nearest owner's wins a lookup by name. Granting again with the
other reach changes it, reported as `GrantOutcome::REACH_CHANGED`. When the tree changes (a tenant moved under another
parent, or deleted), report it so cached answers below it are dropped and the move takes effect at once:

```php
$user->assignRole('admin', tenant: $organisation);                          // the organisation and its accounts
$user->assignRole('billing', tenant: $organisation, includeSubtree: false); // the organisation alone

Authorization::treeChanged($account);
```

The trait methods (`assignRole()`, `givePermission()`, `attachPolicy()`, `$role->givePermission()` and the others) go
through the same services. Without `actor:` they are trusted; given `actor:`, they pass it on, so the change is decided
as that administrator (see [Trusted surfaces](#delegated-administration)). A raw relation write such as
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
must cover the action (`session_policy`), then the allows (an allow statement, then a permission held), then, for an
administration action on its own operation resource, the operation's constraints, which can only refuse an allow (the
`administration.*` reasons, see [Delegated administration](#delegated-administration)), then the implicit deny
(`insufficient_authentication` when an allow statement names the check and only its [authentication
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
carries the decision's reason code (`getReason()`) and, for audit, the denying decision (`getDecision()`), but neither
reaches the client: its message is the translated `authorization::authorization.denied` line, whatever the reason, and
the action, the resource and the policies stay out of it. A denial as `insufficient_authentication` throws
`InsufficientAuthenticationException` instead (see [Authentication requirements](#authentication-requirements)).
`Authorization::lastDecision()` returns the decision too; the `AuthorizationFailed` event carries its reason, statements
and keys (see [Listening to events](#listening-to-events)). To reword the message, add a locale or word a message per
reason, see [Localisation](#localisation).

### Role and inline policies

A role takes policies as an identity does, through the same trait methods and `GrantService` calls, and they apply to
whoever holds the role:

```php
$editor->attachPolicy($noDeletesOffNetwork);                  // for every holder of editor
$editor->attachPolicy($businessHours, tenant: $organisation); // only in the organisation
$grants->detachPolicy($editor, $noDeletesOffNetwork);
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

// Or through the service, here for a role:
$editors = app(PolicyService::class)->createInline($editor, 'own-posts-only', $document);

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

$resources->attach($sharing, $post);                                // GrantOutcome::GRANTED, on post:42
$resources->attach($archiving, Post::class, tenant: $organisation); // every post, in the organisation
$resources->detach($sharing, $post);                                // 1, the attachments removed

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
the policy is attached to: `post-42-sharing[<its key>]#0 sid="reviewers-read" on "post:42"`. `authorization:why`
passes a `post:42` resource to the check as the `['post', '42']` pair, so it reads that record's resource policies and
those of its type, and `post:*` as the type alone; with `--opaque`, the resource is an opaque identifier and reads none.

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

$boundaries->set($user, $supportCap);                               // GrantOutcome::GRANTED, platform-wide
$boundaries->set($user, $tenantCap, tenant: $organisation);         // GRANTED, in the organisation and below it
$boundaries->set($user, $stricterCap, tenant: $organisation);       // REPLACED: one boundary per scope
$boundaries->set($user, $stricterCap, $organisation, false);        // REACH_CHANGED: the organisation alone
$boundaries->remove($user, tenant: $organisation);                  // true: it had one there

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

$actor = ActingContext::for($platformAdmin);

$guardrails->set($organisationCap, $organisation, $actor); // GrantOutcome::GRANTED, here and below
$guardrails->set($organisationCap, $organisation, $actor); // UNCHANGED: it is already there
$guardrails->set($platformCap, null, $actor);              // GRANTED, on the platform

// $post belongs to $organisation, and $editor is checked in it, so both guardrails apply.
$editor->givePermission('billing:view');

Authorization::for($editor)->can('posts:export', $post); // false: organisation-cap denies it, whatever the editor holds
Authorization::for($editor)->can('billing:view');        // false: platform-cap allows it, but organisation-cap does not

$guardrails->remove($organisationCap, $organisation, $actor); // true: the organisation had it

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
so a broken guardrail never lifts the cap. The one check no guardrail caps is that of `authorization:guardrail.manage`
(see **Who may change them** below).

**Who may change them.** Only an acting subject that holds `authorization:guardrail.manage` from above the scope: the
acting context is required, so there is no trusted guardrail change. The right is decided through `check()`, as the
acting context's subject with its session and caps, inside the change's transaction, so it must be held effectively:
every deny and boundary that applies to the actor counts, and an inactive actor holds nothing. The guardrails never
count: a check of exactly `authorization:guardrail.manage`, whoever makes it, is exempt from the guardrail stage, so no
guardrail is read for it, neither its denies nor its allows apply, and the trace records the stage as `[guardrail]
guardrails: exempt`. For a tenant's guardrails it is decided just below the tenant's parent, so a grant held at an
ancestor of the tenant counts when it reaches the tenants below it, a platform-wide grant counts, and a grant held
within the tenant itself never does: a tenant's own administrators never lift the guardrails their tenant is set under.
A tenant with no parent, and the platform, are changed only through a platform-wide grant. A removal lifts a cap across
the scope's whole subtree, so it is also weighed across that subtree, or across every tenant for a platform guardrail,
by the administered-scope rule of delegated administration: the right, and `authorization:administration.impersonated`
for an impersonated actor, are refused when anything that denies or caps the actor anywhere there could limit them, read
as stored and as conservatively as for the action (any overlapping deny counts, whatever its application or conditions),
the guardrails still never counting against the right itself. So an organisation's administrator denied the right by a
role it holds in one team cannot remove the guardrails of the account above it. Setting a guardrail only adds a cap, so
it is decided from above alone. The check keeps the request's application and is recorded and reported like any other
decision. An actor without the right is refused with `GuardrailException`, whose `getReason()` is `not_permitted` and
`getActor()` the actor's principal, before anything is read or written. An impersonated actor is refused with
`AuthorizationException` as `administration.impersonating` unless `authorization:administration.impersonated` is allowed
it from above the scope too. Every change runs under the [concurrency protocol](#delegated-administration) of delegated
administration: the actor's authority, the policy's row and the guardrails of the scope and the scopes above it are
locked before the right is decided and read again before anything is written, so a right revoked or a policy rewritten
meanwhile has the change tried again, and refused as `administration.conflict` once every try has conflicted.

```php
// Every scope, the platform included.
$platformAdmin->givePermission('authorization:guardrail.manage');

// The tenants below the organisation, never the organisation itself.
$organisationAdmin->givePermission('authorization:guardrail.manage', tenant: $organisation);
```

So no guardrail can lock the guardrails: one that does not allow `authorization:guardrail.manage`, one that denies it,
and one whose document cannot be read, a platform guardrail included, keep no actor from changing the guardrails of
any scope, and each can still be removed through the service. Nothing else is exempt: every other source's denies, the
actor's permission boundaries and the session caps still apply to the check, and the grant must still reach the scope
from above.

**The permission.** The package declares `authorization:guardrail.manage` in its own permission catalogue, whatever
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
echo Authorization::for($user)->capped(['posts:edit'])->explain('posts:read')->toText();
```

```text
DENY (session_policy: a session cap does not allow it) at the session stage by session "capped[1]".
  [guardrail] guardrails: uncapped
  [boundary] boundaries: uncapped
  [session] credential: covered
  [session] capped[1]: refused
  not evaluated: allow, administration, implicit
  request "posts:read" about user:1; asked in platform, decided in platform
```

**What they cap.** The session stage runs after every deny, the guardrails and the permission boundaries, and before
any allow, so a session cap caps every allow source alike: a permission held directly or through a role, an allow in
the subject's own or its roles' policies, and a resource policy's allow naming the subject. `withPolicies()` replaces
the check's policies alone, so the caps still apply. An action a cap refuses is never a step-up: the denial is
`session_policy`, never `insufficient_authentication`. A cap has no deny statements, so it adds nothing to the deny
stage, and a deny decides before any cap is weighed. The credential's scopes cap every check about the subject: the
Gate, the `permission:` and `authorize:` middleware, the permission directives and `permissionsFor()` included. The one
exception is whether a principal may use an application, which is asked before it holds a session (see
[Managing roles, permissions and grants](#managing-roles-permissions-and-grants)).
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
missing scopes, it only narrows them further. With the default source, a machine is therefore allowed nothing, though
it is still admitted to an application whose permission it holds, which is decided without session caps.

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

### Delegated administration

Granting, revoking and editing roles, permissions and policies are themselves actions this package checks (AUTHZ-11.1).
A management service called with an acting context decides each change it makes as that actor, through `check()`, the
one decision path, and refuses it when the decision does not allow it. Your administration screens call the same
services with the acting context of the signed-in administrator; seeders, migrations and console commands call them
without one.

```php
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Services\GrantService;

$actor = ActingContext::current(); // the request's subject, its session kept

app(GrantService::class)->revokeRole($user, 'editor', actor: $actor);          // under authorization:role.revoke
app(GrantService::class)->grantPermission($user, 'posts:edit', actor: $actor); // when the actor may hand it out
app(GrantService::class)->grantRole($user, 'editor', actor: $actor);           // when it may hand out all it carries
```

**The actions.** The package declares each administration action as a permission of its own, spelt
`authorization:<noun>.<verb>`, guard-agnostic and filed under the `authorization` category, so `authorization:sync`
writes them and a policy naming them validates:

| Actions                                                                            | What they cover                                                      |
|------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| `role.grant`, `role.revoke`                                                        | A role granted to or revoked from a principal or identity            |
| `permission.grant`, `permission.revoke`                                            | A permission granted directly, or added to or removed from a role    |
| `policy.attach`, `policy.detach`                                                   | A policy attached to or detached from an identity, principal or role |
| `role.create`, `role.rename`, `role.update`, `role.delete`, `role.parent.set`      | A role's lifecycle, its description and rank, and its parent         |
| `permission.create`, `permission.rename`, `permission.update`, `permission.delete` | A permission's lifecycle, its description and category               |
| `policy.create`, `policy.rename`, `policy.update`, `policy.delete`                 | A policy's lifecycle, an inline one included, and its document       |
| `boundary.set`, `boundary.remove`                                                  | A permission boundary set, replaced or removed                       |
| `guardrail.manage`                                                                 | A guardrail set or removed, from above the scope it caps             |
| `resource-policy.attach`, `resource-policy.detach`                                 | A policy attached to or detached from a record or a resource type    |
| `role.read`, `permission.read`, `policy.read`                                      | Reading and listing through the services; not decided yet            |
| `permission.grantable`, `policy.grantable`                                         | Delegating a permission, or one version of a policy, not held        |
| `administration.self`, `administration.impersonated`                               | A change that benefits the actor; a change made while impersonating  |
| `administration.unbounded`                                                         | Replacing a boundary with a wider one, or removing one               |

Each is prefixed with `authorization:`. A sync, `revokeAll()`, `removeAll()` and `detachAll()` decide each change they
make under its own action (there is no blanket action), and every change is decided before any is written, so a batch is
atomic: one refusal leaves nothing written and dispatches no change event, and no change is decided on authority an
earlier one would have handed out. `revokeAll()` removes the grantee's boundaries too, so it decides
`authorization:boundary.remove` for each. A sync decides a grant of each listed row the grantee does not hold live, the
row kept unchanged for each it does hold live, and a revocation of each it drops; it judges which rows are live at one
instant and re-arms as of the same instant, so a row decided as kept unchanged is never re-armed, even when it expires
before it is written. A grant, an attachment or a set is decided whether or not it changes anything; a revocation by
name decides each held row of the name, or, when none is held, the row the lookup ranks first.

A delegated call that finds nothing to change is still decided, on the change it was asked for: a revocation, detach or
removal of what the grantee does not hold, a sync of what it already holds live, and `revokeAll()`, `removeAll()` or
`detachAll()` of a grantee or record that holds nothing, which decide each of their actions at platform scope, since
they reach every scope. A change that changes nothing only narrows, so it needs no scope, self or possession right: an
actor allowed the action makes it, writing nothing, once the rank rule passes for a change to another identity or
principal. An actor not allowed the action, or not senior to the grantee, is refused whether or not there was anything
to change, so a refusal never tells it what a grantee holds. A policy reads whether a change changes nothing as
`resource.unchanged`.

**The acting context.** `ActingContext` holds the resolved subject making the call: its principal, the identity behind
it, its guard, its session and, for a machine, the scopes of its credential, which cap what it may administer as they
cap its other checks. `ActingContext::current()` takes the request's subject as `check()` resolves it, keeping its
session, so a step-up met in the session counts; `ActingContext::for($model)` names another model as
`Authorization::for()` names it, with no session, so an authentication requirement is never met for it, and
`ActingContext::for($subject)` keeps a resolved `Subject` as it is. `capped($actions)` caps the call further, as
`Authorization::capped()` caps a check, and `impersonatedBy($impersonator)` says the actor is being impersonated, which
the package cannot tell by itself. An acting context is never built from a bare reference: a subject that cannot be
resolved, or whose principal is not a saved model, is refused with `AuthorizationException` as `subject_unresolved`, and
never falls back to a trusted call.

| Method                                                  | What it does                                                                                         |
|---------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| `ActingContext::current()`                              | Returns the acting context of the request's subject, its session kept                                |
| `ActingContext::for($actor)`                            | Returns the acting context of the model named, with no session, or of a `Subject` as it is           |
| `capped($actions)`                                      | Returns the acting context with the call capped by the actions as well                               |
| `impersonatedBy($impersonator)`                         | Returns the acting context marked as impersonated by the model or reference given                    |
| `isImpersonating()`                                     | Returns whether someone is impersonating the acting subject                                          |
| `principal()`, `identity()`                             | Return the references to the acting principal and to its identity, null for none                     |
| `check($operationResource)`                             | Decides the resource's action on it, as the service decides it, and returns the `Decision`           |
| `decide($action, $resource)`                            | Decides any action as the acting subject, with the call's caps, and returns the `Decision`           |
| `authorize($operationResource)`                         | Decides as `check()` does and throws when the decision does not allow                                |
| `authorizeIn($operation, ...$changes)`                  | Decides each change of the operation in order, correlated by its id, and throws at the first refused |
| `authorizeChanges($operation, $changes, ...$unchanged)` | Decides the changes as `authorizeIn()` does, or the unchanged ones when there are none               |
| `ActingContext::refusal($decision)`                     | Returns the `AuthorizationException`, with the one `denied` line, the decision refuses with          |

**Trusted calls and delegated calls.** A call with no acting context is trusted system work (N75): nothing is decided,
every structural rule, system-record protection, transaction and event still applies, and its operation is marked
trusted with no actor. Treat it as an integration surface for your own code, never as an endpoint for user-controlled
administration. A call with an acting context is delegated: each change is decided inside the call's transaction, before
anything is written, and its operation carries the actor. `GuardrailService` always takes an acting context.

**The operation resource.** Each change is decided on an `OperationResource`, a resource of type
`authorization:operation` whose id is the operation's id and whose tenant is the scope of what the change changes, never
the tenant the request is in: the tenant a grant is held in, or a definition's owner for a change to a role, permission
or policy. A change in a tenant is decided in that tenant's scope, and one in a tenant outside the actor's scope, an
ancestor of the request's tenant included, is refused as `tenant_scope` unless the actor holds the action through a
platform-wide grant. A change with no tenant, to a platform-wide grant, a platform role or a platform-owned record, is
decided at platform scope, where only a platform-wide grant of the action counts, so an actor that holds the action only
in a tenant is refused it. So who may change a grant row is the scope the actor administers (N79): an actor whose
authority for the action reaches the row's tenant, from a parent tenant by authority over its subtree or from the
platform, changes the row from its own context, and one `revokeAll()` clears a grantee's rows across every tenant the
actor administers; a parent's node-only authority reaches no child's row, and a tenant's no platform-wide row. A change
that may widen authority reaches no further than the actor administers, so one whose reach holds a tenant where the
actor's authority for the action is denied or limited is refused (see *Administered scope* below). A screen that builds
the same resource through the same named constructor (`OperationResource::grant()`, `revoke()`, `unchanged()`,
`definition()` or `rewrite()`) and checks it with `$actor->check($resource)` gets the decision the service makes.
Nothing is ever attached to one operation, so a check on it reads only the resource policies attached to the type
`authorization:operation`. The resource offers what the change names to your policies, under `resource`:

| Key                                                                                          | Type   | What it holds                                                         |
|----------------------------------------------------------------------------------------------|--------|-----------------------------------------------------------------------|
| `resource.id`, `resource.type`, `resource.tenant.type`, `resource.tenant.id`                 | string | The operation's id, `authorization:operation` and the intended tenant |
| `resource.action`                                                                            | string | The administration action                                             |
| `resource.narrowing`                                                                         | bool   | Whether the change can only narrow what anyone may do                 |
| `resource.unchanged`                                                                         | bool   | Set when the change changes nothing; missing otherwise                |
| `resource.target_type`, `resource.target_id`                                                 | string | The record acted on                                                   |
| `resource.role`, `resource.permission`, `resource.policy`                                    | string | The record's name, under its kind                                     |
| `resource.grantee_type`, `resource.grantee_id`                                               | string | The grantee, or the resource type and key (`*`) a policy attaches to  |
| `resource.application`                                                                       | string | The application a grant holds in; missing for every application       |
| `resource.subtree`                                                                           | bool   | Whether a grant reaches the tenants below its tenant                  |
| `resource.expires_at`                                                                        | time   | When a grant expires; missing for one that never does                 |
| `resource.digest`                                                                            | string | The digest of the document a `policy.grantable` descriptor names      |
| `resource.change.name`, `.description`, `.rank`, `.parent`, `.guard`, `.category`, `.digest` | mixed  | A definition's proposed change, a document by its stored digest       |
| `resource.change.owner_type`, `resource.change.owner_id`                                     | string | The grantee an inline policy is created for                           |
| `resource.impersonated`, `resource.impersonator_type`, `resource.impersonator_id`            | mixed  | Whether the actor is impersonated, and by whom                        |

`resource.change.rank` is a number and the rest of `resource.change` strings. An attribute provider you register that
declares one of these keys must declare it with the same type.

```php
// Editors may revoke roles in their own tenant, for the admin application only.
['effect' => 'allow', 'actions' => ['authorization:role.revoke'], 'resources' => ['authorization:operation:*'],
    'conditions' => ['eq' => ['resource.application' => 'admin']]]
```

**What this release enforces.** Every change is decided under its action, through every deny, guardrail, boundary and
session cap, and in its intended tenant. Then an administration stage, after the allow and inside the same decision,
weighs the operation's constraints, in this order, and can only refuse:

- **Impersonation.** A change made while impersonating is refused as `administration.impersonating` unless the actor is
  also allowed `authorization:administration.impersonated` on the same operation, and, for a change that may widen
  authority, across its whole reach by the administered-scope rule below.
- **Administered scope** (N79). The actor must administer the whole reach of a change that may widen authority, or the
  change is refused as `administration.scope`. Its action is decided again in the grant's tenant, standing just below it
  for a grant that reaches the tenants below, so only authority that itself reaches below counts (node-only authority
  cannot issue a subtree grant), or at platform scope for a platform-wide grant, and in the grant's application, so a
  grant to every application needs authority unrestricted by application. A decision at one node reads only what applies
  there, so a reach wider than its node, a platform-wide grant or one reaching the tenants below, is also refused when
  anything of the actor's anywhere in it could deny or limit the action, read as the possession route reads it: a deny
  statement whose actions overlap it, conditional or not, a boundary or guardrail that does not allow it whole, a
  session or credential cap that does not cover it, or a tree, row or document that cannot be read. So an actor allowed
  `authorization:*` at the platform, but denied `authorization:role.grant` by a role it holds in one tenant, cannot
  grant a role platform-wide, and a parent's administrator denied an action in one child cannot take it across the
  parent's subtree, though a node-only change in the parent is still decided there alone. The same rule weighs the reach
  of a definition change and of a resource-policy attachment in the impact check, and every widening change a
  platform-scope `revokeAll()` or `removeAll()` decides. Every further right a widening change needs beside its action,
  `authorization:administration.self`, `authorization:administration.unbounded`,
  `authorization:administration.impersonated` and the grantable rights, is weighed across the same reach by the same
  rule, so a right allowed at the platform but denied or limited by a role the actor holds in one tenant is never used
  on a change that reaches that tenant; a guardrail's removal is weighed across the subtree it caps the same way (see
  [Guardrails](#guardrails)). The further rights inherit the rule's conservatism on purpose: any deny statement whose
  actions overlap the right counts, whatever its application or conditions, so a deny held only for another application,
  or one whose condition would never hold, still refuses the right on a change whose reach is wider than its node, and
  what each right's limits read is read once per decision, however many permissions and policies the change hands out.
- **Rank** (N76). Every change to an identity or a principal, a revocation, a sync, `revokeAll()`, a boundary change and
  a call that changes nothing included, is refused as `administration.rank` unless the actor is strictly senior to the
  grantee, and as `administration.rank_uncomparable` when either side's rank, or the reach, cannot be read. The actor is
  ranked in the grant's own tenant and application, by the roles that reach it (its principal's and its identity's).
  The grantee is ranked across the whole reach of the change: the most senior rank it holds anywhere the change reaches
  counts, its roles held platform-wide, in the grant's tenant and its ancestors, in every tenant below for a grant that
  reaches below, in every tenant for a platform-wide grant, and in any application for a grant to every application.
  Expired grants never count. A role grant is also weighed against the rank the role would give the grantee, so it
  never leaves the grantee equal to or senior to the actor. An unranked grantee is the most junior, an unranked actor
  acts on no one, two unranked sides are equal and refused, and with `authorization.rank.enabled` off rank is no
  constraint.
- **Self.** A change to the actor itself, its principal or its identity, that may widen authority is refused as
  `administration.self` unless the actor is also allowed `authorization:administration.self` on the same operation, at
  the node it is decided at and across the change's whole reach, as its action is: an actor allowed the right at the
  platform, but holding a role in one tenant whose policy denies it, cannot widen its own authority platform-wide, or
  across a subtree holding that tenant. Rank is not weighed against itself. A change to itself that only narrows, such
  as revoking its own permission, needs no such right.
- **Narrowing.** A change that can only narrow what anyone may do is then allowed: revoking a permission (directly or
  from a role), revoking a role no policy attached to it or its ancestors denies anything in, detaching a policy, from a
  grantee or a resource, with no deny statement, setting a boundary where the grantee has none in the scope, or
  replacing one with a boundary that can only narrow it and reaches no fewer tenants, and a grant that only shortens or
  narrows one the grantee holds live in the same scope (it lasts no longer and reaches no further, and revoking the
  grant would only narrow).
- **Possession** (N77). A direct grant of a permission to an identity or a principal, a re-grant, an extension, a wider
  reach and a sync's additions included, is allowed only when the actor provably holds what it grants, or is explicitly
  allowed to grant it. The same permission route decides every permission a role grant, a policy or a definition change
  hands out:
  - *provable possession*: in the grant's reach (its tenant, below it for a subtree grant, or the platform, and its
    application), the actor holds the permission, or a wildcard covering it, through grants lasting at least as long as
    the grant (a permanent grant needs permanent authority, and an extension authority lasting until the new expiry);
    `check()` of the permission there allows it; and no deny, boundary, guardrail or session or credential cap of the
    actor could limit it anywhere in the reach: no deny statement names an action it covers, with conditions or
    resource patterns or none, every boundary and guardrail allows it whole, with no condition and on every resource,
    and every cap covers it. The actor's policies, its roles' and every resource's, its boundaries and the guardrails
    are read as stored, whatever their application, each table in one query bounded to the reach (the platform, the
    grant's tenant and its ancestors, and the tenants below for a grant that reaches below), so what a grant reads
    never grows with other tenants' policies. Two patterns that both hold wildcards, one of them `?` or a `[...]` class,
    are taken to overlap. When in doubt, a tree, row or document that cannot be read included, the route fails;
  - *explicit grantability*: `authorization:permission.grantable` is allowed, in the grant's reach, on the grant's
    descriptor (`OperationResource::grantable()`), the same operation resource under that action, naming the permission,
    the grantee, the reach and the expiry, so a policy may allow exactly one delegation the actor does not hold. A right
    held for one application, or at a tenant's node alone, allows no grant to every application, another application or
    the subtree, and, for a reach wider than its node, nothing that denies or caps the actor anywhere in the reach may
    limit the right, read as the administered-scope rule reads the action, so a right denied in one tenant allows no
    grant reaching it. The right must last as long as the grant: held as a permission, through grants lasting that long;
    allowed by a policy, through an attachment lasting that long (a resource policy's never expires).

  Otherwise the grant is refused as `administration.not_grantable` when the actor does not hold the permission across
  the grant's reach and lifetime, and as `administration.unprovable` when it does but its check there is refused or
  something could limit it.
- **Role grants.** Granting a role hands out its whole active authority: every permission it and its ancestors carry
  live (with the hierarchy enabled), every policy attached to it or to them, and every allow of a resource policy, in
  the grant's reach, that names the role or an ancestor by a `role:<key>` selector, since such an allow reaches
  whoever holds the role, now or later, however the role came by its key. It is read in a fixed number of queries
  outside every tenant scope. Each permission must pass the permission route and each policy, and each such allow, the
  policy route, across the grant's reach and lifetime, so a permission, a policy or a resource policy's allow the actor
  cannot hand out blocks the grant; a resource policy that names a role no one holds yet is weighed when the role, or a
  role below it, is granted, or made the parent of a held role. Every permission, and every action a policy allows, is
  decided in one pass, so a role carrying thirty permissions costs as many queries as one carrying three. A role's
  denies hand nothing out, so they never justify its allows. The role's rank counts as the grantee's, so the grant
  never leaves it equal to or senior to the actor. A re-grant, an extension and a sync's additions are judged the same
  way. A chain that cannot be read whole, a reach whose tenants cannot be read, more resource policies in the reach
  than `authorization.administration.max_impact`, or a resource policy whose document cannot be read, is
  `administration.unprovable`.
- **The stored row.** A delegated change is weighed on the row it writes against: the role, permission or policy
  handed out is read again by its key inside the call's transaction, and a role, permission or policy a call edits is
  read again before it is weighed, discarding changes to the model in hand that were not saved. So a model given a rank,
  a name or a document and not saved, or one read before another write rewrote its row, is judged on the row as
  stored, and a grantable right bound to the old digest never covers the new document.
- **The policy route.** A policy handed out, attached to an identity, a principal or a role, carried by a granted role
  or a new parent, rewritten, or attached to a resource, passes by one of two routes, across the change's reach and
  lifetime:
  - *containment*: every allow names its actions alone (`actions`, with no resource patterns and no conditions, and
    no principals except on a resource policy, whose principals the impact check weighs, or on a resource policy's
    allow a granted role is named by, which reaches the grantee itself), and every action passes the permission route;
  - *`authorization:policy.grantable`*: allowed on the descriptor `OperationResource::policyGrantable()` builds, the
    same operation naming the policy and its document's digest (`DocumentDigest`, as the policy events report it) under
    `resource.digest`. A policy that grants the right on one digest never covers the policy rewritten, so a rewrite
    needs a new right. A rewrite offers its new document's digest, in the same form, as `resource.change.digest`.

  A screen weighing a rewrite builds it with `OperationResource::rewrite($policy, $document, $change)`, passing the
  document it will submit, as a JSON object or its decoded array, and any other change it proposes alongside it (such
  as `['name' => 'support-v2']`). That is the builder the policy service uses: it decodes the document and names it as
  the policy is (by the new name when the change gives one, unless the document names itself), as it would be stored,
  hands it to the stage, which compares it with the stored document, and offers `DocumentDigest::of()` of it as
  `resource.change.digest`, the digest the policy events report and a later `policy.grantable` right is decided on. A
  resource built with `definition()` and no document is not the one the service decides: the stage cannot weigh it, so
  it is refused as `administration.unprovable`; and a digest of the document before it is named matches no right the
  service's decision would.

  A policy that allows nothing passes. Otherwise it is refused with the permission route's reason, for a policy that
  could be contained, or as `administration.unprovable`.
- **The owner rule** (D20). A change to a definition (`role.create`, `.rename`, `.update`, `.delete`, `.parent.set`,
  and the same for permissions and policies), and a change to what a role carries (a permission added or removed, a
  policy attached or detached), is made only from the tenant that owns the definition or the role: the tenant the
  check is made from must be the owner, and a platform definition needs the platform, so a record seen from a
  descendant, another tenant or the platform is refused as `administration.owner`, whether or not the change narrows.
  `RoleService::create()`, `PermissionService::create()` and `PolicyService::create()` take an optional `tenant:` (a
  model, an `AuthorizableTenant` or a `Reference`) that owns what they create, the platform when it is left out, so a
  tenant administrator creates its own tenant's definitions from that tenant's context, and a create is refused as
  `administration.owner` from any other; a screen builds the same new record with its owner's `tenant_type` and
  `tenant_id`, such as `OperationResource::definition('authorization:role.create', new Role(['tenant_type' => 'team',
  'tenant_id' => '7']), ['name' => 'editor'])`. A resource policy's attachment is a grant to a resource, never weighed
  by the rule, and nor is a grant row (N79): who may change one is the administered scope.
- **Definitions.** Creating a definition widens no one, so it passes, but a role is created only junior to the actor
  (`administration.rank`). Describing a role, permission or policy, and renaming a policy, pass. Renaming a role, or a
  permission (or changing a permission's name or guard), changes what every existing grant means, so it is a new grant
  to every holder: the impact check below, and, for a permission, the permission route under the new name across the
  definition's reach, so renaming `posts:read` to `*` passes only when every holder is one the actor administers and
  the actor may hand out `*`. A rank that is no whole number (a fraction, a flag, or text that is not the decimal of
  one) cannot be compared, so it is `administration.rank_uncomparable`. A rank is changed only on a role junior to the
  actor, so a senior or peer role is never demoted or cleared (`administration.rank`), the new rank must leave the role
  junior to the actor, and a rank made more senior is weighed against its holders. Deleting a permission narrows;
  deleting a role narrows unless a policy attached to it or
  an ancestor denies anything, and deleting a policy unless it denies, each otherwise `administration.unprovable`.
- **Role membership and hierarchy.** Adding a permission to a role, attaching a policy to it, and setting or replacing
  its parent hand something new to every holder of the role and of every role below it: the impact check, then the
  route for what is added (the new parent's whole authority, its ancestors' included), across the role's reach.
  Removing a permission, and detaching an allow-only policy, narrow. Clearing or replacing a parent whose chain carries
  a deny, and detaching a denying policy, lift a deny that cannot be bounded, so they are `administration.unprovable`.
- **Policy documents.** A rewrite (`policy.update` with a new document) is compared with the stored document statement
  by statement, conservatively: one that only removes allows or adds denies narrows and passes, the same document in
  authority terms included (key order and sids aside); one that lifts a deny, or either document that cannot be read, is
  `administration.unprovable`; any other adds allows, so it needs the impact check over every holder (the subjects it is
  attached to or bounds, the holders of every role it is attached to, and the principals either document names where it
  is attached to a resource), the policy route for the allows it adds, the grantable right decided on the new digest,
  and, for a policy in use as a boundary, `authorization:administration.unbounded`, weighed across the policy's reach. A
  policy attached as a guardrail is still never edited.
- **The impact check.** A change to a shared definition reaches everyone who holds it. Their set is read in a fixed
  number of queries, outside every tenant scope, whether or not a grant has expired: the grantees of a role and of every
  role below it, the grantees of a permission and the holders of every role carrying it, the subjects a policy is
  attached to or bounds and the holders of the roles it is attached to, and the principals a resource policy names, the
  holders of a role selector included. Then, at a fixed cost however many there are: the operation's action must be
  allowed across the whole reach their grants can have (the owner and every tenant below it, in every application, or
  the platform), or `administration.scope`; the actor must be strictly senior to the most senior rank any holder but
  itself holds there, and to a rank the change gives them, or `administration.rank` (`administration.rank_uncomparable`
  when a rank cannot be read); and a change reaching the actor itself needs `authorization:administration.self` across
  the same reach, or `administration.self`, as a change made while impersonating needs
  `authorization:administration.impersonated` there, or `administration.impersonating`. A change reaching no holder
  widens no one and needs neither the check nor a route. The set is bounded by `authorization.administration.max_impact`
  (1000 by default), counted in distinct holders: a holder that two sets, or one set twice, name counts once, and never
  hides a holder not read yet. A change reaching more holders is refused as `administration.unprovable`, never
  approximated.
- **Boundaries.** Setting a boundary where the grantee has none narrows, and so does replacing one with the same policy
  or one whose document can only narrow it, reaching no fewer tenants. Replacing one with a wider boundary, and removing
  one (`revokeAll()` included), lift a cap whose release cannot in general be bounded, so each is refused as
  `administration.unprovable` unless the actor is also allowed `authorization:administration.unbounded` on the same
  operation, across its whole reach, after the scope, rank and self rules. A delegated change never lifts a boundary on
  possession alone.
- **Resource-policy attachments.** A resource policy grants without any permission held, to every principal its allows
  name, on one record or on the whole type: each principal, and every holder of a role a selector names, is weighed by
  the impact check across the attachment's reach, and the policy must pass the policy route. A principal whose rank
  cannot be read is `administration.rank_uncomparable`. Detaching an allow-only policy narrows; detaching a denying one
  is `administration.unprovable`.
- **Still refused.** Anything the package cannot prove stays `administration.unprovable`. Guardrail changes keep their
  own authority rule, decided from above the scope, under the concurrency protocol below (see
  [the design note](docs/design/delegated-administration.md)).

A batch (a sync, `revokeAll()`) works out its whole change first and decides every item against the authority the actor
held before the call, so no item relies on authority an earlier one hands out, and a refusal of any item writes nothing
and dispatches no change event. Its items are decided kind by kind, then by tenant, application and record, so the
first refusal, and its reason, never depend on the order the rows were read in.

```php
// An editor may hand out posts:edit, for the admin application only, without holding it.
['effect' => 'allow', 'actions' => ['authorization:permission.grantable'], 'resources' => ['authorization:operation:*'],
    'conditions' => ['eq' => ['resource.permission' => 'posts:edit', 'resource.application' => 'admin']]]

// A manager may hand out the approved version of the "support" policy, and no rewrite of it.
['effect' => 'allow', 'actions' => ['authorization:policy.grantable'], 'resources' => ['authorization:operation:*'],
    'conditions' => ['eq' => ['resource.policy' => 'support', 'resource.digest' => '9f2c…']]]
```

`canActOn($target)` on an identity compares rank alone, as the rank rule does, and grants nothing by itself. When
neither side holds a ranked role, the comparison refuses: both count as the most junior, so their ranks are equal, and
strict seniority refuses equal rank (N76). An application that leaves rank on but ranks no role should turn rank off
(`authorization.rank.enabled`), or no delegated change to an identity will pass it.

**Concurrency.** A delegated call never commits on authority that changed under it, and never writes a row its
decisions did not see. Each try runs in a transaction of its own and locks, with `lockForUpdate()` on the write
connection, every row its decisions depend on before it reads it, in one order within the call, each query's keys
sorted:

1. **the actor**, before anything else: the grant rows of its principal and identity, its roles and every role above
   them with the permissions and policies they carry, its boundaries, the guardrails in the reach of the request's
   tenant and the resource policies of `authorization:operation`;
2. **the target**, before the service reads it: the grantee's grant rows, or a role's chain and what it carries, the
   role, permission or policy handed out or taken away, a definition's record and a new parent's chain, and the
   guardrails of the tenant a change holds in. A record the service looked up before its lock, such as a role named by
   its name, is read again under the lock and compared, so a rank or a document changed in between has the call tried
   again rather than decided on what the row no longer holds;
3. **what a decision reaches**, as it reads it: the holders the impact check weighs, and the resource-policy attachments
   and guardrails across a grant's reach with the policies among them. Each such set is locked only when it is no
   larger than `authorization.administration.max_impact`; a larger one is refused as `administration.unprovable`
   without being locked.

The tenant tree is yours and cannot be locked, so the chain of every tenant involved is read afresh and pinned, and a
`treeChanged()` reported while the call runs marks it moved. Once every change is allowed, before anything is written,
the call reads everything again, as the decision read it and under the lock: a grant revoked from the actor, a role
given more, a policy rewritten or attached, or a tenant moved meanwhile has the whole call rolled back and tried again,
decided on what was committed, so it is refused or made as the new state allows. `revokeAll()` and
`BoundaryService::removeAll()` remove exactly the rows they decided, by key, never one granted meanwhile, and a sync
never writes back a row it decided as held that is gone by the write.

A conflict found this way is tried again; so is a deadlock, serialisation failure, lock wait timeout or busy database
the database refuses the call with (as Laravel's concurrency error detector tells them), when the call opened the
transaction. A call is tried again at most `authorization.administration.retries` times (2 by default), so it runs at
most that many times and once more; once every try has conflicted, it is refused with `AuthorizationException` as
`administration.conflict`, at the `administration` stage, writing nothing, and the refusal is recorded and reported like
any other (see **Audit**). Inside a transaction of your own, a database concurrency error is never tried again, since
the database has rolled back, or needs to restart, your whole transaction: it is thrown as
`TransactionConflictException`, whose code is `40001` and whose previous exception is the database's, so restart your
transaction, for example with `DB::transaction($callback, attempts: 3)`, which tells it as a concurrency error. A
changed dependency found by the second read is tried again there only back to the call's savepoint, and on MySQL
(repeatable read) a snapshot your transaction already took is kept across that rollback, so the call can conflict on
every try and be refused as `administration.conflict`: run delegated calls outside your own transaction, or before its
first read. A rollback to a savepoint also keeps the row locks the failed try took on MySQL, so a grant whose retry
there would call its grant hook again is thrown as `TransactionConflictException` instead (see
[Grant hooks](#grant-hooks)).

The order holds within a call, but it cannot stop two calls that cross from deadlocking: one call's actor may be the
other's target (A administers B while B administers A), or one's held role the other's granted one, so each holds a
row the other waits for. PostgreSQL and MySQL detect such a deadlock and refuse one of the calls, which is tried again
as above, or thrown as `TransactionConflictException` inside your own transaction. Deadlocks are detected and retried,
not prevented.

PostgreSQL and MySQL hold the locks until the transaction ends, so a concurrent write of a locked row waits for the
call. SQLite serialises writers and compiles no row lock, so there the second read alone catches a change. The package
takes no lock until the service first reads what the call changes, and the call's work starts inside its transaction
before anything is read or locked, so a scope-widening grant hook (AUTHZ-11.3) run first in that work runs before every
lock. A trusted call keeps its cost: it takes no extra lock and decides nothing, and with no grant hook configured it
runs once, with no retry. With one, a trusted grant is tried again in the same way only when a grant it is about to
write now widens an identity's scope with no hook run for it, up to `administration.retries` times, then refused as
`administration.conflict`; inside your own transaction that conflict is thrown as `TransactionConflictException` (see
[Grant hooks](#grant-hooks)).

**Trusted surfaces.** Each of these is trusted system work when it is used without an actor: nothing is decided, so use
it that way only from your own code, never as an endpoint for user-controlled administration:

| Surface                                                                                    | Warning                                                                  |
|--------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| A management service called without `actor:`                                               | Trusted: decides nothing; pass the acting context of the administrator   |
| A raw Eloquent write on the package's models, pivots or tables                             | Always trusted: takes no actor, and dispatches no event                  |
| An identity's `assignRole()`, `givePermission()`, `attachPolicy()`, `createInlinePolicy()` | Trusted without `actor:`; every write helper takes one and passes it on  |
| The Spatie aliases `givePermissionTo()`, `revokePermissionTo()` and `removeRole()`         | Trusted without `actor:`; each takes one and passes it on                |
| A role's `givePermission()`, `revokePermission()`, `syncPermissions()` and their aliases   | Trusted without `actor:`; each takes one and passes it to `RoleService`  |
| `authorization:grant` and `authorization:revoke`, seeders and migrations                   | Trusted without `--actor`; both commands take one and pass it on         |
| `AccessReview::trusted()`, `trustedPage()`, `trustedStream()`, `trustedExport()`           | Always trusted; `authorization:review` uses `trustedExport()` alone      |

The maintenance commands `authorization:sync`, `authorization:prune` and `authorization:migrate-spatie` define the
catalogue, clear expired and orphaned rows and import from Spatie for whoever runs the console; they are not
administration on anyone's behalf (`authorization:sync` records its `--actor` on what it writes).

With the concurrency protocol, delegated administration is complete: all four parts of
[the design](docs/design/delegated-administration.md) are in this release.

**Reasons and errors.** A refusal throws `AuthorizationException`, or `InsufficientAuthenticationException` for a
step-up, carrying the decision (`getDecision()`), its stage and its trace, for audit; the client sees the one `denied`
line. The administration stage refuses with these reasons, each at the `administration` stage with a trace step naming
it: `administration.impersonating`, `administration.scope`, `administration.rank_uncomparable`, `administration.rank`,
`administration.self`, `administration.owner`, `administration.not_grantable` and `administration.unprovable`; a call
that conflicted on every try is refused as `administration.conflict`, at the same stage, and every call made while a
preview is evaluated as `administration.previewing` (see [Preview](#preview)). The owner rule (D20) applies to
definitions (roles, permissions and policies), what a role carries (its permissions, policies and parent), never to a
resource policy's attachment or to grant rows.

**Audit.** Every decision is reported with `DecisionEvaluated`, and a refusal with `AuthorizationFailed`, as
`authorize()` reports one, each naming the operation resource `authorization:operation:{operation id}`. Each try of a
call that conflicted reports its decisions under the same operation id; a call refused as `administration.conflict` ends
with that refusal, reported with both events under the operation's first action, which marks the allowed decisions of
its earlier tries as superseded, since none of them was written. The change
events of a write are dispatched only after it commits, and their operation carries the same id, the actor's principal
and identity, whether the call was trusted or delegated, any impersonator and the actions its changes fall under, so a
decision and the write it allowed are correlated. The actions are decided through `check()` only when `isTrusted` is
false: a trusted call names its actions too, though nothing was decided, and a sync names both its grant and its revoke
action whichever it made.

A refusal is reported synchronously, inside the operation's transaction, and that transaction then rolls back, taking
with it anything written on the same connection. An audit store that persists denials must therefore write them on a
connection with no part in that transaction:

- write directly, from a listener of `AuthorizationFailed` or `DecisionEvaluated`, on a database connection of its own,
  one that is not `authorization.connection` nor the default connection the package writes through, for example
  `DB::connection('audit')->table('denials')->insert([...])`; or
- queue the write on a queue whose backend shares nothing with the transaction: a non-database driver (Redis, SQS,
  Beanstalkd), or the `database` driver with a `connection` of its own in `config/queue.php`, with `after_commit` off
  for that queue connection and for the listener (`$afterCommit = false`, the default), since a job held until the
  transaction commits is dropped when it rolls back.

The stock `database` queue on the default connection inserts its job inside the same transaction, and the `sync` driver
runs the job inside it, so both are rolled back with the refusal and lose every delegated denial.

### How a check is decided

`Authorization::check()` is the one decision behind `can()`, `cannot()`, `any()`, `all()`, `authorize()`, `explain()`,
the Gate, a Laravel policy class deciding through the package's trait, the `permission:` and `authorize:` middleware and
the permission directives (`role:` and `@role` check membership only, so no stage applies to them, guardrails and
boundaries included). It runs these stages in order, and the first that decides ends it, except that the
administration stage can still refuse an allow; no allow is weighed before every deny and every cap has run:

| Stage            | What it weighs                                                                                                    | Denies as                                                                                                                                                                                                                     |
|------------------|-------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `subject`        | Whether there is a subject, and whether it and its identity are active                                            | `subject_unresolved`, `subject_inactive`                                                                                                                                                                                      |
| `resource`       | Whether the resource argument can be identified                                                                   | `resource_unresolved`                                                                                                                                                                                                         |
| `tenant`         | Whether the resource's tenant is within the check's, or a platform-wide grant of the permission admits it         | `tenant_scope`                                                                                                                                                                                                                |
| `deny`           | Every deny: the subject's, its identity's of either kind, their roles', the resource's, guardrails', boundaries'  | `explicit_deny`, `invalid_policy`                                                                                                                                                                                             |
| `guardrail`      | Every guardrail on the check's tenant, its ancestors and the platform must allow the check, unless it is exempt   | `guardrail`, `invalid_policy`                                                                                                                                                                                                 |
| `boundary`       | Every permission boundary of the principal and of its identity that applies must allow the check                  | `boundary`, `invalid_policy`                                                                                                                                                                                                  |
| `session`        | Every session cap, the credential's scopes and each set of actions `capped()` was given, must cover the action    | `session_policy`                                                                                                                                                                                                              |
| `allow`          | Every allow statement that applies to the subject, a resource policy's naming it included, then a permission held | `invalid_policy`                                                                                                                                                                                                              |
| `administration` | The operation's constraints, for an administration action on its own operation resource; refuses only             | `administration.scope`, `administration.rank_uncomparable`, `administration.rank`, `administration.self`, `administration.owner`, `administration.not_grantable`, `administration.unprovable`, `administration.impersonating` |
| `implicit`       | Nothing allowed                                                                                                   | `insufficient_authentication`, `condition_failed`, `no_match`                                                                                                                                                                 |

Within each stage, the policies are assessed in a fixed order (name, stored key, resource, then document) and each
statement by its position, so the decision and its trace never depend on the order the policies were read in. The
decision records the stage that decided it and every step it took: each statement assessed, each guardrail and boundary
that refused the check as `refused`, naming it, each session cap as `covered` or `refused`, naming it, a cap stage that
capped nothing as `uncapped`, the guardrail stage as `exempt` for a check of `authorization:guardrail.manage`, whose
deny stage weighs no guardrail's denies either, the permission step, which is asked only when no allow statement
matched and none was invalid, and the administration stage as `satisfied` when the operation's constraints hold, or
`refused`, naming the reason, when one does not:

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
catalogue. `assuranceKeys()` declares the names that make a key of those namespaces an assurance key (see
[Assurance keys](#assurance-keys)). It is resolved at boot, which refuses a namespace it adds that is not a name, is
reserved or is listed twice, and a malformed assurance key name. Bind it in a service provider's `register()`:

```php
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;

$this->app->scoped(AuthenticationContext::class, App\Authorization\SessionAuthenticationContext::class);
```

`RequestContext` and `EnvironmentContext` are rebound the same way. The defaults are built per request or job, so queue
workers and Octane read the request and the user they are serving; a binding of your own is kept as you bound it.

`namespaces()` and `assuranceKeys()` must answer the same for the life of the process, and should be cheap and free of
side effects, since the package reads them more than once, though never while providers register: at boot, to validate
them; at the context key catalogue's first use, not when the catalogue is built, which keeps what they said from then
on; each time a policy document is validated, on a write or by `authorization:policy:validate`; and, `namespaces()`
alone, each time the check context factory is built, once per request or job. A context bound in any provider's
`register()` is therefore the one read, whichever provider registers first, even when another resolves the catalogue
or declares keys in it while it registers. Register keys from `boot()`, as above, so the catalogue's first use comes
after every provider has registered.

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
saved, and when `authorization:policy:validate` reads it, with a reason that points at `authentication_requirement`.

Your `AuthenticationContext` declares its own assurance key names in `assuranceKeys()`, beside these fixed ones, which
it can never remove. Each is either an exact name, or a name followed by one trailing `*`, which matches every segment
starting with what comes before it; nothing else is accepted. A name that is not a string, is empty, holds a `.` or
has a `*` anywhere but at its end is refused at boot, and a policy write fails closed on it. A sibling package that
supplies verification proofs and the identity providers a session came through might declare:

```php
public function namespaces(): array
{
    return ['authentication', 'verification', 'federation'];
}

public function assuranceKeys(): array
{
    return ['recovery_code', 'level', 'factor_types', 'last_verification_age_seconds', 'provider_*'];
}
```

`verification.level`, `verification.factors.recovery_code` and `federation.provider_name` are then assurance keys,
and no condition may test them; `verification.enrolled` is not. The shipped `GuardAuthenticationContext` declares none.

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
    $event->operation->actor;      // the acting principal's Reference, or null for trusted work
    $event->operation->identity;   // the identity behind the acting principal, or null
    $event->operation->isTrusted;  // true for a call made without an acting context
    $event->operation->actions;    // the administration actions its changes fall under, decided only when not trusted
    $event->operation->id;         // the same for every event of the call, and every decision made for it
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

Each is dispatched only once its write commits on the package's connection: inside your own transaction it waits for the
outermost commit, and a transaction that rolls back dispatches nothing. Every event of one service call carries the same
operation, with its id, its actor and identity, whether it was trusted, any impersonator and its actions; a write made
through a model outside the services is a trusted operation of its own with no actor. A change `forceSystem()` unlocked
dispatches `SystemOverrideUsed`, naming the record, the change and the actor.

`DecisionEvaluated` and `AuthorizationFailed` implement the marker too, but are dispatched when the decision is made,
not after a commit: a denial is a fact even if the surrounding transaction rolls back. `DecisionEvaluated` is
dispatched for every decision `check()` makes, and `AuthorizationFailed` when `authorize()` refuses. Both are
`final readonly` snapshots of the same references, names and ids (AUTHZ-15.3), never a model, the context the caller
passed, a session, or a condition or attribute value (AUTHZ-15.4):

```php
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;

Event::listen(static function (DecisionEvaluated $event): void {
    $event->subject;        // Reference to the principal the decision was about, or null for a guest
    $event->identity;       // Reference to the identity behind it, or null
    $event->previewer;      // Reference to whoever previewed it, or null for a decision that is not a preview
    $event->action;         // 'posts:update'
    $event->resource;       // 'post:42', 'post:*', the name given, or null for none
    $event->tenant;         // Reference to the tenant the decision was made in, or null
    $event->application;    // the application it was made in, or null
    $event->effect;         // DecisionEffect::ALLOW or DecisionEffect::DENY; $event->isAllowed() reads it
    $event->reason;         // the DecisionReason of a denial, or null for an allow
    $event->statements;     // the StatementReference of each statement that decided it (see below)
    $event->usedBreakGlass; // whether a break-glass grant allowed it; false until break-glass grants arrive
    $event->keys;           // the context keys it read, such as ['resource.status', 'input.reason'], never their values
});
```

The subject and the identity are taken from the subject the decision was about, null when it had none, and never from
the authenticated user, so a decision made with `for($user)` names `$user`. A record that is not saved is named by no
reference. The tenant and the application are the scope the decision was made in, never read from the subject: the
resource's own tenant for a check on a resource of the request's tenant or below it, platform scope for a resource
admitted from outside it and for a delegated change to the platform, a scope put in place around the check (with
`TenantScope::within()` or an `AuthorizationScope`), and otherwise the request's, a guest's decision included. Each
statement is named by its policy's name, the stored policy's key, its index and its sid and, for a statement of a
resource policy, the resource that policy is attached to (`type:id` or `type:*`). The keys are the condition keys the
decision tested, held or failed, and every `${…}` reference that an assessed statement's condition operands or resource
patterns name, each once: a policy that reads `resource.status` or interpolates `${principal.id}` puts that name on the
event, never the value. The decision itself, with its stage and its trace, is not on the event; a listener that needs it
for debugging reads `Authorization::lastDecision()`, which holds it by the time the event is dispatched, and
`Authorization::lastDecisionProvenance()` (see [The programmatic API](#the-programmatic-api)).

### The programmatic API

Every check goes through `SineMacula\Laravel\Authorization\AuthorizationManager`, which the `Authorization` facade
proxies and the container injects. Each method decides about the current subject, as the subject resolver gives it,
or about the subject of the scoped manager it is called on:

| Method                                            | What it does                                                                                                              |
|---------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| `can($action, $resource, $context)`               | Decides the action and returns whether it is allowed                                                                      |
| `cannot($action, $resource, $context)`            | Returns the opposite of `can()`                                                                                           |
| `authorize($action, $resource, $context)`         | Decides the action and throws when it is not allowed                                                                      |
| `check($action, $resource, $context)`             | Decides the action and returns the full `Decision`                                                                        |
| `any($actions, $resource, $context)`              | Returns whether at least one of the actions is allowed                                                                    |
| `all($actions, $resource, $context)`              | Returns whether every one of the actions is allowed                                                                       |
| `checkMany($checks)`                              | Decides each `CheckInput` and returns its `Decision`, keyed as the checks are (see [Bulk checks](#bulk-checks))           |
| `canEach($action, $resources, $context)`          | Decides the action on each resource and returns whether each is allowed, keyed as the resources are                       |
| `filterAuthorized($action, $resources, $context)` | Returns the resources the action is allowed on, with their keys and order, a `Collection` as its own class                |
| `explain($action, $resource, $context)`           | Decides the action in explain mode and returns its `Explanation` (see [Explanations](#explanations))                      |
| `lastDecision()`                                  | Returns the latest decision of the request or job, whichever manager made it                                              |
| `lastDecisionProvenance()`                        | Returns who the latest decision was about, who previewed it and where it was made, or null whenever `lastDecision()` is   |
| `permissionsFor($subject, $scope, $context)`      | Lists the actions of the permission catalogue the subject may take in the scope                                           |
| `for($subject)`                                   | Returns a scoped manager deciding about the model named, in the request's scope, or a `Subject` in its own scope          |
| `forUser($user)`                                  | Returns a scoped manager deciding about the subject the resolver translates the user into                                 |
| `previewFor($subject, $scope)`                    | Returns a preview deciding about the subject as the caller, admitted at every use (see [Preview](#preview))               |
| `capped($actions)`                                | Returns a scoped manager whose checks are capped by the actions given                                                     |
| `withPolicies($policies)`                         | Returns a scoped manager that evaluates only the policies given                                                           |
| `queryScope($model, $action, $context)`           | Returns the scope `whereAuthorized()` puts on a query (see [Query scoping](#query-scoping))                               |
| `GrantScopeQuery::forIdentity()`, `hasGrantIn()`  | Not on the manager: grant scope and presence in a tenant (see [Grant scope query](#grant-scope-query))                    |
| `AccessReview::review()`, `trusted()`             | Not on the manager: holders, holdings, expiries, grants by actor, unused (see [Access reviews](#access-reviews))          |
| `AccessReview::page()`, `stream()`, `export()`    | Not on the manager: a review a keyset page, a lazy stream or JSON Lines at a time, each with a `trusted…()` counterpart   |

`check()` is the one decision, and `checkMany()` the same decision over many checks, `check()` deciding as `checkMany()`
decides a batch of one: every other method but `queryScope()` and `permissionsFor()` adapts one of them, and each
decision they make is recorded as the last decision and reported with `DecisionEvaluated`; `queryScope()` compiles a
scope from the same pipeline without deciding a check, and `permissionsFor()` decides each action through the path
`checkMany()` takes but as introspection, so both record and report nothing, except on a preview, where the admission is
recorded and reported at every use and a listing dispatches each action's `DecisionEvaluated` (see
[Preview](#preview)). `permissionsFor()` takes its subject as an
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
manager, and the next request or job gets a new one. `for()`, `forUser()`, `previewFor()`, `capped()` and
`withPolicies()` never change it: each returns a new scoped manager, which every method above works on, and which shares
the lifecycle's last decision, so `Authorization::lastDecision()` returns the latest decision whichever of them made it.
They chain: a scoped manager made from another keeps its subject, its caps and its policies, and a further cap narrows
its caps:

```php
$scoped = Authorization::for($user)->capped(['posts:*'])->withPolicies([$hypothetical]);

$scoped->all(['posts:read', 'posts:update'], $post);
Authorization::lastDecision();            // the decision of the last action $scoped decided
Authorization::lastDecisionProvenance();  // DecisionProvenance: a Reference to $user as subject and identity
```

**`for()` and the scope.** A model given to `for()` is decided in the request's tenant and application, as the subject
resolver reports them. A resolved `Subject` is taken as it is, keeping its identity, guard and session, and when it
names a tenant or an application, every check through the manager is decided there: its tenant, or the platform when it
names none, and its application, or none, are put in place of the request's, both as the subject's and as the scope of
the grants that count, for each `check()`, `can()`, `cannot()`, `any()`, `all()`, `authorize()`, `checkMany()`,
`canEach()`, `filterAuthorized()`, `explain()` and query scoped through it with `whereAuthorized()`. The request's are
restored once each is decided, even when it throws, and nothing is kept between calls or requests. A `Subject` naming
neither is decided in the request's scope, as a model is. So a subject in another tenant needs no wrapping:

```php
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;

$member = new Subject($principal, $person, $account, 'admin');

Authorization::for($member)->can('posts:update', $post);   // decided in $account, on the admin application

// The same decision, as callers wrote it before: wrapping the call still gives the same result.
$scope = AuthorizationScope::tenant($account, 'admin');
$scope->within(fn () => Authorization::for($scope->subjectIn($member))->can('posts:update', $post));
```

`permissionsFor()` lists in the scope it is given, which wins over the subject's, and a preview from `previewFor()`
keeps its own scope (see [Preview](#preview)). The subject's tenant is read when a check is decided, not by `for()`, so
a `Subject` whose tenant cannot be read, a plain object that is neither a model nor an `AuthorizableTenant`, is refused
with `InvalidTenantException` by each check through the manager, before anything is decided.

The last decision is kept with its provenance, a `DecisionProvenance` of references and names alone: `subject` and
`identity`, references to the principal the decision was about and its identity, null for a guest; `previewer`, whoever
previewed it, null for a decision that is not a preview (`isPreview()` says which); and `tenant` and `application`, the
scope it was made in, as the decision events name it. `lastDecisionProvenance()` returns it exactly when
`lastDecision()` returns the decision, so a decision that read an authentication requirement has none once it stops
being fresh or when asked for in another session. `permissionsFor()` leaves both as they were.

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
metadata say, throws `InvalidPermissionCatalogueException`; an entry of `authorization.permission_enums` or
`authorization.permission_providers` the boot validation would refuse, one changed after boot say, throws
`InvalidAuthorizationConfigException` when the catalogue is read, and is never skipped.

**Generic and resource-specific listings differ.** A listing with no resource answers the check with no resource, so an
allow limited to some records, or conditioned on a resource's attributes, does not list its action there; a listing
for one resource answers for that resource. Use the resource-specific listing for a row's controls, and the generic one
for the controls of a page.

**The server still authorizes.** A listing tells the UI what to show. What is granted can change between rendering and
the request, so authorize the action again when it is taken, with `authorize()`, the `authorize:` middleware or the
Gate.

**It records nothing.** Listing is introspection, not a check: it records no last decision and dispatches no
`DecisionEvaluated` and no `AuthorizationFailed`. On a preview, each action's `DecisionEvaluated` is dispatched, naming
both parties, though none is stored, and the preview's admission is recorded and reported as any check (see
[Preview](#preview)). Break-glass grants, when they arrive, will define how a listing that relies on one is reported.

**What it costs.** The actions are decided together, through the path `checkMany()` takes, so the subject is resolved
once and its grants, roles, policies, boundaries and caps, the guardrails and the resource's tenant, attached policies
and attributes are read once for the listing: listing fifty actions costs the queries listing five costs. The catalogue
is read from code on each call and touches no database. A scope already in place, such as `current()`, is not applied
again, so a listing in it reads what the request's checks have already resolved, and a check after it still does. A
listing in another scope keeps what the request has resolved and puts it back once it returns, unless a write emptied
the cache meanwhile. See [Effective permissions](docs/design/effective-permissions.md) for the design.

### Preview

`previewFor()` answers "what can this person do?" for a support or administration screen: it returns a manager whose
checks are about another subject, while the caller stays who is asking. The package never impersonates: the guard, the
session, the Gate, Blade and the facade stay the caller's.

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;

$preview = Authorization::previewFor($user);                            // the request's tenant and application
$preview = Authorization::previewFor($user, AuthorizationScope::tenant($account, 'admin'));

$preview->can('posts:update', $post);
$preview->checkMany($checks);
$preview->explain('posts:delete', $post);
$preview->permissionsFor(null, AuthorizationScope::tenant($account, 'admin')); // null: the previewed subject

Post::query()->whereAuthorized('posts:view', [], $preview)->select(['id', 'title'])->paginate();
```

**Admission and the right.** A preview is itself an action checked here: the caller must be allowed
`authorization:subject.preview`, a permission the package declares, spelt as its administration actions are. It is
decided through `check()` as the caller, with the caller's own session, denies, boundaries, guardrails and caps, on a
preview resource, `authorization:preview:{type}:{id}`, that names the subject and the scope a decision is made in.
Policies read these keys of it, so an application restricts who may be previewed, and where, by policy; no rank rule is
imposed, so an auditor may inspect senior staff on purpose:

| Key                                              | Value                                                                    |
|--------------------------------------------------|--------------------------------------------------------------------------|
| `resource.id`, `resource.type`                   | The principal previewed as `{type}:{id}`, and `authorization:preview`    |
| `resource.tenant.type`, `resource.tenant.id`     | The tenant the decision is made in; missing at platform scope            |
| `resource.target_type`, `resource.target_id`     | The principal previewed, by morph type and key                           |
| `resource.identity_type`, `resource.identity_id` | The identity behind it; missing when it has none that is a saved record  |
| `resource.application`                           | The application the decision is made in; missing for none                |

```json
{"statements": [
    {"effect": "allow", "actions": ["authorization:subject.preview"]},
    {
        "effect": "deny",
        "actions": ["authorization:subject.preview"],
        "conditions": {"eq": {"resource.target_type": "admin"}}
    }
]}
```

A missing key makes a deny on it undecidable, so it refuses there, as policies fail closed; use an `_if_exists` operator
to let it pass.

**Admission in every scope a decision is made in.** A decision about the subject is made where any check on its resource
is made: in the preview's tenant, in a resource's own tenant when that is the preview's tenant or below it, a child
tenant's included, just below a tenant for a query's rows below it, and at platform scope for a resource of another
tenant that a platform-wide grant admits. Before any decision about the subject is made in such a scope, the caller is
decided the right there, as an ordinary check: on the preview resource of that tenant, or none at platform scope, with
that tenant and application in place. So a parent's right that reaches its subtree admits a preview in a child, a right
held at a parent's node alone admits no answer below it, and a deny of the right in a child tenant refuses every answer
made there; a resource of another tenant needs a platform-wide grant of the right, since it is answered at platform
scope; and a preview for no application needs the right for every application. A platform preview is decided, and
admitted, at platform scope, where a deny the caller holds in one tenant does not apply, as for any check at platform
scope. A preview distributes no authority, so nothing beyond the ordinary check is weighed: a deny, conditional or not,
refuses only the previews and the scopes it matches.

Each scope is admitted once in each use, so a batch over many resources of one tenant costs one admission for the
preview's tenant and one more for each other scope its decisions are made in, never one per resource. A query through
the preview is cut wherever the caller's sources might differ too, so each of its classes of rows is admitted where it
is decided; it is refused when the caller may not preview in one of them, whether that class holds rows or not.

**Revalidation.** The preview is admitted when it is built and again at every use: each check, each batch, each listing
and each compile of a query scoped through it. Nothing is cached between uses, so a right revoked after the preview
or a query is built refuses the next use. A refused admission throws `AuthorizationException`, with the one `denied`
line and the caller's own decision, before anything about the subject is decided in that scope, so it reveals nothing
about the subject there; in a batch, a listing or a query, it refuses the whole call, which returns nothing, though the
decisions already made in it are reported as any decision is. It is recorded and reported as any check about the
caller. A use sets the request's resolution memo aside and restores it afterwards, so the caller's own checks read
nothing again after a preview.

**The subject has no session.** A resolved `Subject` keeps its principal and identity but not its session, and a model
is named as `for()` names it, so no authentication requirement made of the subject is met, whatever the caller has
proved; the caller's step-up counts for the admission alone. A preview's `authorize()` therefore never throws
`InsufficientAuthenticationException`: a denial for a requirement made of the subject throws a plain
`AuthorizationException`, carrying the decision, since no step-up by the caller could meet it. The subject is evaluated
in the caller's request context: the `request`, `environment` and `authentication` namespaces are the caller's
request's, which is no prediction of what the subject would see when signed in.

**What is recorded.** Every decision about the subject dispatches `DecisionEvaluated`, or `AuthorizationFailed` for an
`authorize()` refusal, with `subject` the previewed subject and `previewer` the caller, in the scope the decision was
made in, or the preview's when a listener has meanwhile recorded another decision; previews always dispatch. A
preview `check()` or `checkMany()` stores the last decision with that provenance. A preview `permissionsFor()`
dispatches one event for each action it evaluates, but stores none of them, so the last decision stays its admission.
The admission is a check about the caller, recorded and reported as normal, with no previewer. `explain()` and a
decision's trace are disclosed under the right to preview; they name statements, conditions, caps and requirements,
never a value or a session.

**What is refused.** On a preview, `for()`, `forUser()`, `previewFor()` and `permissionsFor()` naming a subject would
change the target, a listing in another tenant or application would change the scope, and `withPolicies()` would decide
through hypothetical policies: each throws `InvalidPreviewException` before anything is decided, and so does
`previewFor()` on a manager carrying a policy override. `capped()` is allowed and caps the subject's checks alone,
never the caller's admission. A preview never becomes authority to act: an `ActingContext` built while a preview is
evaluated, or from a preview's subject, and every management service call made while a preview is evaluated, from a
callback or a listener, a listener of a preview's `AuthorizationFailed` included, trusted or delegated, is refused with
`AuthorizationException` as `administration.previewing`. There is no override.

**Queries.** `whereAuthorized()` given a preview keeps the rows the previewed subject may take the action on, and its
own writes are refused: an `update()`, a `delete()` or an `insertUsing()` compiled from the preview's own builder, or
from a builder that nests it whole (`whereExists()`, a nested `where()`), is refused as `preview_write`. A preview query
taken into another as SQL text is not (see the limits).

**The disclosure point.** Rows the subject may see are not automatically rows the caller may read. A preview answers
what the subject could do; the application decides what of it to show, with a check of its own about the caller, or by
showing constrained metadata, as the `select()` above does.

**The limits.** A manager clone cannot sandbox everything. A raw Eloquent write on the package's models, pivots or
tables, and a trusted actorless service the application calls outside the preview's evaluation, stay the trusted
integration surfaces they always are. A preview query taken into another as SQL text (`whereIn()`, `fromSub()`,
`joinSub()`, `selectSub()`, `withCount()` or `has()` with a count) is compiled, and admitted, once, when it is taken in;
it is not admitted again when the outer query runs, and it is not refused as `preview_write` when the outer query
writes, so `Post::query()->whereIn('id', $previewQuery->select('id'))->delete()` deletes the rows the subject may see.
Take a preview query in whole, or not into a write at all. See [Preview](docs/design/preview.md) for the design.

### Explanations

`explain()` answers "why can" and "why can't" (AUTHZ-11.5). It decides the check exactly as `check()` does, through the
same path and the same stages, so its verdict is the same, and records and reports it as any check: it is the last
decision and dispatches its `DecisionEvaluated`. It returns an `Explanation`:

```php
$explanation = Authorization::for($user)->explain('posts:publish', $post, ['reason' => 'launch']);

$explanation->isAllowed();
echo $explanation->toText();
return response()->json($explanation); // the versioned schema
```

```text
ALLOW at the allow stage by permission "posts:publish".
  [deny] house-rules[01j...]#0: not_applicable
  [guardrail] guardrails: uncapped
  [boundary] boundaries: uncapped
  [session] session caps: uncapped
  [allow] permission "posts:publish": held
  grant role permission "posts:publish" to principal user:1 through role "editor" < "author" in tenant team:7
  request "posts:publish" on "post:42" about user:1; asked in tenant team:7, decided in tenant team:7
```

**Explain mode and its cost.** `explain()` runs the check in explain mode, a switch on the one decision path (N89). An
everyday check (`check()`, `can()`, the Gate, Blade, the middleware, `checkMany()` and the rest) never turns it on: it
records the trace it always has and costs what it did before explanations. Explain mode decides from what an everyday
check decides from, the resolution cache included, and records more besides, asking no attribute provider more than
the check does. Where each grant came from is read afresh from the grant rows a resolution reads: on a cold cache the
check decides from those rows, in no more queries than an everyday check, and keeps nothing in the cache; on a warm
cache, where an everyday check reads no grant row, an explained check still reads them, once a permission is found held
or the grantee has a policy, in no more queries than a resolution of the names. A grant that the rows no longer give,
one a stale cache still holds, is `unavailable`, never guessed. A preview's `explain()` is admitted, recorded and
reported as any preview check (see [Preview](#preview)).

**What an explanation holds.** It is an immutable value of the decision alone:

- the verdict, the reason and the stage that decided it;
- the statements that decided it, every one when several did, or the cause that is no statement: the guardrail,
  boundary, session cap or administration constraint that refused it, the permission held that allowed it, or the
  reason of an early refusal, such as a check without a subject, whose trace is empty;
- the steps of every stage the decision reached, in order, each statement's condition keys with whether each held and
  the `${…}` references it names, which `keys()` and the events now count too;
- the stages it never reached, marked as not evaluated: after an explicit deny, the caps, the allows and the rest are
  never weighed, nor guessed at;
- each authentication requirement that alone kept an allow from applying, by its part names and its unmet parts;
- for an explained check, each condition test on its own (its key, its operator, whether `_if_exists` lets a missing
  key pass, and its outcome: `held`, `failed`, `missing`, `null`, `wrong_type`, `unresolved`, `undecidable` or
  `invalid`), the keys found missing and every reference that could not be resolved, by key, on the statement that
  read it;
- for an explained allow, where each grant came from: a permission granted to the principal or the identity, or
  through a role, with the role held and each ancestor up to the role that carries it, and the tenant and application
  of the grant; a policy attached to the grantee or to one of its roles, the same way; or a policy attached to the
  resource, by its resource. A source that cannot say, a grantee whose `getPermissions()` or `getPolicies()` is its
  own, a policy store or a policy resolver bound in place of the default, is `unavailable`, never guessed;
- for an explained check, what it asked: the action, the resource, the subject, its identity and any previewer, the
  scope it was asked in and the scope it was decided in.

**The renderers.** `toText()` writes it for reading, every name (policy, statement, key, role, tenant) escaped as a JSON
string is (`<`, `>`, `&` and non-ASCII characters as `\uXXXX`, a control character as its JSON escape, such as `\n` or
`\u0001`), so no name can inject markup or a line of its own.
`toArray()`, which `jsonSerialize()` returns, writes a stable schema carrying `version: 1`. Rendering reads the
explanation alone: it queries nothing, dispatches nothing and leaves the last decision as it is.

**What is never shown.** No value: no context or attribute value, operand, interpolated string, model, raw context,
session, proof or fingerprint, in the text, the schema or the value itself (AUTHZ-8.8). What it shows still discloses
how the policies are built, the names of policies, statements, keys, roles and tenants, so show it to those allowed to
see them; another subject's explanation goes through a preview, whose right discloses it.

**A stored decision.** `Decision::explain()` explains any decision, the last decision of an everyday check included,
with the evidence it has: the verdict, what decided it, the steps of its trace, the stages it never reached and its
requirements. What only explain mode records, the condition tests, the keys found missing, the grants' provenance and
the request, is marked `not recorded (explain mode off)`; nothing is evaluated again to fill it in.

**From the command line.** `authorization:why` explains a saved subject's check under the scope and console context its
options name, without the subject's browser session (see
[Explaining a check from the console](#explaining-a-check-from-the-console)). See
[Explanations](docs/design/explanations.md) for the design.

### Access reviews

`AccessReview` lists, for periodic reviews and their sign-off (AUTHZ-11.6), who holds a role, a permission or a policy
in a scope, what a subject holds and where, which grants expire within a window, which grants an actor last granted or
changed, and, with [usage tracking](#usage-tracking) on, which grants show no use. Resolve it from the container, where
it is a singleton, and run a typed `ReviewQuery`:

```php
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;

$reviews = app(AccessReview::class);
$scope   = ReviewScope::appliesIn($account, ApplicationSelector::named('admin'));

$result = $reviews->review(ReviewQuery::holders($editor, $scope), ActingContext::current());

$result->rows;        // list<ReviewRow>, in one deterministic order
$result->isTruncated; // true only when a row was left out by the limit
$result->isComplete;  // false only when an identity's principals could not all be listed
$result->toArray();   // each row in its versioned shape

$reviews->trusted(ReviewQuery::expiring(ReviewScope::everywhere(), now(), now()->addMonth())); // a scheduled job
```

**What "holds" means.** A review lists grant routes, never effective access: one row for each route by which a subject
holds a target through the stored grants. A route is a direct grant; a role grant reaching a permission or a policy
through the role or a role above it, and a role held through a role below it; a grant to an identity reaching its
principal; and a grant made at the platform, in an ancestor tenant or at a subtree's root that applies in the reviewed
tenant. Every row a route rests on must be live at the review's instant (an expiry equal to the instant has passed), and
a role's policy reaches its holder only where the role's grant and the attachment hold together, in the same tenant and
application, as a check reads them. Alternative routes through different roles are separate rows, each with its own
`route_expires_at`, so the earliest is not when the holding ends. A policy that only denies is held. A review reads
structure alone, with the same tenant chain, application matching, live-grant and definition-visibility rules a check
reads, and never evaluates a statement, condition, deny or cap, so a holder may well be denied what it holds: for what a
subject may actually do, use `check()`, [`permissionsFor()`](#effective-permissions) or a [preview](#preview). A
suspended, inactive or soft-deleted subject keeps its live grants in a review, marked `inactive`, whether it is named
by reference or given as a resolved `Subject`, or `unknown` when its record is gone.

A grant or attachment row that names half a tenant (a type without a key, or the reverse), which the package never
writes, is listed as damaged, never as a clean platform origin: its `grant_state` is `malformed` and its `origin_scope`
shows the tenant columns as stored, the missing half null. It appears exactly where a check reads it today (a check
reads a key without a type at the platform, by its missing type alone, and a type without a key nowhere), and a type
without a key is also listed in a review of everywhere, which needs platform-wide admission, never in one rooted
within a tenant, since it cannot be shown to lie there. A route resting on such a row is `malformed` too. Checks
themselves still read these rows as before.

| Stored tenant    | `appliesIn()` (any tenant, or the platform) | `rootedWithin()` (any tenant) | `everywhere()` |
|------------------|---------------------------------------------|-------------------------------|----------------|
| Key without type | Listed, read at the platform                | Not listed                    | Listed         |
| Type without key | Not listed                                  | Not listed                    | Listed         |

Holders, holdings, expiries and an actor's grants each follow their scope selection.

**The queries.**

| Query                                            | Lists                                                                                                  |
|--------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `ReviewQuery::holders($target, $scope, $direct)` | Every route to a role, permission or policy (a model or reference), or its direct grants alone         |
| `ReviewQuery::holdings($subject, $scope)`        | A `Subject`'s own grants and its identity's that reach it; or an identity's and its listed principals' |
| `ReviewQuery::expiring($scope, $from, $until)`   | Grants, attachments and role permission edges expiring within `[from, until)`, in UTC                  |
| `ReviewQuery::grantedBy($actor, $scope)`         | Grants whose `granted_by` pair is exactly the actor's                                                  |
| `ReviewQuery::unused($scope, $since)`            | Live grants with no observed use since the instant (see [Usage tracking](#usage-tracking))             |
| `withLimit($limit)`                              | The same review returning at most that many rows                                                       |

A permission target means that definition, never a policy statement or wildcard grant that might authorise its action,
and a definition is named by its key, so two sharing a name under another guard or owner are never confused. Holders are
the grantees the grants name: a grant to an identity lists the identity, not its principals. In principal mode
(`holdings()` given a resolved `Subject`) the identity's grants are listed only when they reach the principal (both
machines or neither), each naming the identity as `via_identity`, and a sibling principal's never are. In identity mode
(`holdings()` given an identity's model or reference) the identity's grants and those of every principal the identity
directory lists are read, each row keeping its actual grantee, and `isComplete` is false when the directory says its
list may leave one out; `isComplete` says nothing else, and is true for every other review. Expiring rows are stored
rows, not routes, each marked `live`, `expired` or `malformed` at the review's instant; a role's permission edge and its
policy attachment are kinds of their own. The window's bounds keep their microseconds: an expiry is stored to the whole
second, so a bound with a fraction is compared as the next whole second, which lists exactly the expiries within it.
"Granted by" means the last writer: a regrant, a changed expiry or a changed reach overwrites it, a trusted write names
no actor, and a revoked grant is gone, so the history stays with the audit log the grant events feed.

**The scope.** Each selection is a value of its own, never a null that could mean two things:

| Scope                                      | Reads                                                                                                                     |
|--------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| `ReviewScope::appliesIn($tenant, $app)`    | What a check in the tenant reads: the platform's, the tenant's own and an ancestor's reaching below; null is the platform |
| `ReviewScope::rootedWithin($tenant, $app)` | The grants made in the tenant or below it, wherever else they reach                                                       |
| `ReviewScope::everywhere($app)`            | Every stored grant                                                                                                        |
| `ApplicationSelector::none()`              | The grants for every application, as a check with no application reads them                                               |
| `ApplicationSelector::named($app)`         | Those and the grants for the application named                                                                            |
| `ApplicationSelector::any()`               | Every grant, whatever its application (the default for `rootedWithin()` and `everywhere()`)                               |

Applicability is not containment: a review applying in a tenant includes the platform's grants and an ancestor's that
reach below, never a child's, which is the opposite of what the [grant scope query](#grant-scope-query) counts as
within. In a review applying in a tenant, only the roles and permissions the tenant sees count, and a role it does not
see ends a hierarchy chain, as in a check. A review admitted in a tenant shows the inherited grants that apply there,
such as a platform grant, but never the holders in other tenants those grants also reach.

**The rows.** A row names references alone, each a morph type and a string key, never a name, email, description,
document or value. Its shape is versioned (`version: 1`):

| Field                                    | Holds                                                                                        |
|------------------------------------------|----------------------------------------------------------------------------------------------|
| `row_key`                                | A key of the route, the same every time                                                      |
| `subject`, `grantee`, `target`           | Who holds it, whom the stored grant names, and the role, permission or policy held           |
| `source_kind`, `source_key`              | The kind of stored row the route starts from, and its key                                    |
| `origin_scope`                           | That row's tenant as stored (null for the platform), application (null for every one), reach |
| `via_identity`, `role_path`              | The identity a grant reaches the subject through, and the roles from the one granted upwards |
| `supporting_grants`                      | Every stored row the route rests on, each with its key, scope and expiry                     |
| `created_at`, `updated_at`, `expires_at` | The starting row's times, in UTC                                                             |
| `route_expires_at`                       | The earliest expiry of every row the route rests on                                          |
| `granted_by`                             | The last actor to grant or change the starting row; null for a trusted write                 |
| `grant_state`, `subject_state`           | `live`, `expired` or `malformed`; `active`, `inactive` or `unknown`                          |
| `usage`                                  | `status` (`used`, `unused` or `unknown`), the last observed use and the coverage             |

The rows come in one total order, the same on SQLite, PostgreSQL and MySQL: by source kind, target, grantee, origin
scope (the platform before a tenant, every application before a named one) and route (the first role of its chain, how
many roles the chain runs through, then the rows it rests on), every string compared byte for byte. A review returns at
most `authorization.reviews.limit` rows (1000 by default; a whole number of at least 1, or boot fails), or the limit
`withLimit()` sets, and reads at least one more to say exactly whether any was left out. Every grant is read on the
write connection, never one query per holder: the roles a review involves are read in a fixed number of queries, then
the grants of all of them together, a page of the limit at a time. Each grant read adds a row for every carrying role or
attachment in its chain, so a page may hold more rows than the limit before they are cut. For a policy, only the role
grants that reach one of its attachments are read, and whether they meet in some tenant is settled once for each
attachment's tenant, never once for each tenant a grant is held in. One subject's holdings are read whole, an identity's
principals 500 at a time.

**The review rights.** The package declares `authorization:review.read`, the right to run a review, and
`authorization:review.export`, the right to export one, which needs both. `review()` admits the review before anything
is read, through `check()` as the reviewer, with its real session, denies, boundaries, guardrails and caps, on a review
resource `authorization:review:{query}` in the reviewed tenant and application. No rank rule applies, and policies read
these keys of it to restrict who may review what:

| Key                                                                               | Value                                                                               |
|-----------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `resource.id`, `resource.type`                                                    | The query (`holders`, `holdings`, `expiring`, `granted_by`), `authorization:review` |
| `resource.tenant.type`, `resource.tenant.id`                                      | The reviewed tenant; missing for the platform and everywhere                        |
| `resource.query`, `resource.scope`                                                | The query, and `applies_in`, `rooted_within` or `everywhere`                        |
| `resource.application_selection`, `resource.application`                          | `none`, `named` or `any`, and the application named                                 |
| `resource.target_type`, `resource.target_id`                                      | The role, permission or policy whose holders are listed                             |
| `resource.subject_type`, `resource.subject_id`                                    | The principal or identity whose holdings are listed                                 |
| `resource.actor_type`, `resource.actor_id`                                        | The actor whose last grants are listed                                              |
| `resource.impersonated`, `resource.impersonator_type`, `resource.impersonator_id` | Whether the reviewer is impersonated, and by whom                                   |

A review of one tenant, in one application or none, is decided at that tenant. A review across a reach, rooted within a
tenant, applying at the platform or of everywhere, is decided again across the reach by the rule delegated
administration uses: just below the reach's tenant, where only a right that reaches below counts, or at platform scope,
and refused as `administration.scope` when anything that denies or caps the reviewer anywhere in the reach could limit
the right, a conditional deny included. So a deny the reviewer holds in one child tenant refuses a review of its
parent's subtree. Applications are weighed the same way: a review of `ApplicationSelector::any()` in one tenant needs
the right held for every application, and is refused when a deny, boundary or guardrail held for any one application
could limit it. A review run while the reviewer is impersonated (`ActingContext::impersonatedBy()`) is refused as
`administration.impersonating` unless the reviewer is also allowed `authorization:administration.impersonated` on it,
across the review's whole reach by the same rule, as a delegated change is, since the impersonator is the one shown what
it discloses. A refused review throws `AuthorizationException` with the one generic line, carrying the reviewer's own
decision (a step-up the right needs included), after recording and reporting it as any refused check, and discloses no
row, count, truncation or completeness.

**The trusted path.** `trusted()` runs a review as trusted system work, for a scheduled job or a command, with no
reviewer and no admission. Nothing falls back to it: `review()` always takes an acting context, and one that cannot be
resolved is refused before the review is reached.

**Paging.** `page()` reads a review a page at a time, and `trustedPage()` as trusted work:

```php
$query  = ReviewQuery::holders($editor, ReviewScope::rootedWithin($organisation));
$cursor = null;

do {
    $page = $reviews->page($query, ActingContext::current(), $cursor, limit: 250);

    foreach ($page->rows as $row) {
        // ...
    }

    $cursor = $page->nextCursor;
} while ($cursor !== null);
```

| `ReviewPage`  | Holds                                                                                                    |
|---------------|----------------------------------------------------------------------------------------------------------|
| `rows`        | At most the page's limit of rows (the query's own, `withLimit()` or the configured one, unless given)    |
| `nextCursor`  | The cursor of the next page; null on the last, so a page followed by no row ends the review              |
| `reviewedAt`  | The review's instant, frozen when its first page is read and the same on every page                      |
| `isComplete`  | As a result's: false only when an identity's principals could not all be listed                          |
| `isLast()`    | Whether `nextCursor` is null                                                                             |

A page resumes after the last row of the page before by keyset over the review's one order, never at an offset, so a
page costs the same queries whatever its number, and `review()` is simply the first page of `page()`, through the same
query, admission and rows. A page of a target's direct holders seeks to its keyset through an index leading with the
target and the grantee, and reads no grant before it: on PostgreSQL, the planner can walk the review index in the page's
order and read about the rows it returns; on MySQL, whose index on the target holds digests of the tenant and
application, it reads the target's grants from its keyset on and sorts them for the page, so its work grows with the
target's grants after the page, never with the tenant's. A page of routes through the roles below a target, of an expiry
window or of an actor's grants reads the rows its filter matches from its keyset on and sorts them, so its work grows
with the rows that target's roles, window or actor match; only the sort's top rows are bounded by the page. Every page
is admitted again before anything, its cursor included, is read, so a right revoked between pages refuses the next one
with `AuthorizationException`.

**Cursors.** A cursor is opaque and tamper-evident: an HMAC-SHA256 signature, keyed from the application key
(`app.key`), over its payload and over what it is bound to: the query (its kind, target or subject, scope selection,
tenant, application selector, window, actor and `directOnly`) and the reviewer (its principal and any impersonator) or
the trusted path. Its payload holds the row schema version, the review's instant and the sort key of the last row
returned, whose parts are the references and scope values that row already shows, never a name or a value; a route is
keyed by its first role and its length, so a cursor stays a few kilobytes at most however deep the role hierarchy runs.
A cursor is read only in the one text that encodes it, each part the canonical, unpadded base64url of its bytes. A
cursor used with another query, scope or reviewer, a trusted cursor given to a reviewer and the reverse, one of another
schema version, and one changed in any byte, even to text that decodes to the same bytes, are each refused with
`InvalidReviewCursorException`, whose one message says nothing of why. The limit is not bound, so a client may change
its page size between pages. Signing a cursor needs the application key; without one, `MissingAppKeyException` is thrown
when a cursor is issued or read, and a review that fits on one page needs none.

**The consistency mode: a live scan.** The review's instant is frozen when its first page is read and carried by the
cursor, so every page classifies each expiry at that instant: a grant that expires between pages is still listed, and
still `live`, on a later page. It is not a database snapshot: a row written or revoked between pages may appear or
disappear (a row written where the scan has already passed is never returned, one written ahead of it is), but a row
present for the whole scan is returned exactly once, in its place in the order.

**Streaming.** `stream($query, $reviewer, $chunk = 1000)` and `trustedStream($query, $chunk)` return a lazy iterable of
every row: nothing is read until it is iterated, then each chunk is read through the same keyset pages, and the
reviewer is admitted again before each, so a refusal part way throws `AuthorizationException` from the iteration. What
a stream holds in memory is bounded by the chunk, however large the tenant; one subject's holdings are read whole for
each chunk, by design.

**Exports.** `export($query, $reviewer, $sink, $chunk = 1000)` and `trustedExport($query, $sink, $chunk)` write the
review as versioned JSON Lines to a writable stream resource, each line written whole, or to a callback given each
line, and return how many rows they wrote. Exporting needs both `authorization:review.read` and
`authorization:review.export` (N96): the two are decided together before the header is written and again before every
chunk, each across a broad reach as the read right is. The first line is a header, then one line a row, in the
review's order, then a footer:

```json lines
{"record":"header","version":1,"query":"holders","scope":{"selection":"applies_in","tenant":{"type":"tenant","id":"acct1"},"application":{"selection":"named","name":"admin"}},"reviewed_at":"2026-11-08T12:00:00.250000Z","scan_started_at":"2026-11-08T12:00:00.250000Z","consistency":"live"}
{"record":"row","version":1,"row_key":"004885d0a74311b154e17bb6365cb7332cfd7ae2bb46526880e6be6593bd8ac5","subject":{"type":"user","id":"17"},"grantee":{"type":"user","id":"17"},"target":{"type":"role","id":"01a1be88-d4d3-72cc-b9bc-620cc97d4906"},"source_kind":"role_grant","source_key":"4:role|36:01a1be88-d4d3-72cc-b9bc-620cc97d4906|4:user|2:17|~|~|~","origin_scope":{"tenant":null,"application":null,"include_subtree":true},"via_identity":null,"role_path":[{"type":"role","id":"01a1be88-d4d3-72cc-b9bc-620cc97d4906"}],"supporting_grants":[{"source_key":"4:role|36:01a1be88-d4d3-72cc-b9bc-620cc97d4906|4:user|2:17|~|~|~","scope":{"tenant":null,"application":null,"include_subtree":true},"expires_at":null}],"created_at":"2026-10-01T09:00:00Z","updated_at":"2026-10-01T09:00:00Z","expires_at":null,"route_expires_at":null,"granted_by":null,"grant_state":"live","subject_state":"active","usage":{"status":"unknown","last_observed_at":null,"coverage_from":null,"coverage_until":null}}
{"record":"footer","version":1,"rows":1,"scan_ended_at":"2026-11-08T12:00:00.412000Z","complete":true}
```

| Record   | Fields                                                                                                                                                                       |
|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `header` | `version`, the `query` kind, the `scope` (selection, tenant or null, application selection and name), `reviewed_at`, `scan_started_at` and `consistency`, always `live`      |
| `row`    | The row's versioned shape (see the fields above), references alone                                                                                                           |
| `footer` | `version`, how many `rows` were written, `scan_ended_at`, and whether it is `complete`: false only for an identity's holdings whose directory could not list every principal |

The output is UTF-8 and deterministic: the same rows at the same instants give the same bytes. Each line is one JSON
object with its keys in a fixed order, slashes and Unicode unescaped, the line and paragraph separators escaped, and
invalid UTF-8 refused with `JsonException` rather than replaced. An export the reviewer stops being admitted to part
way (a revoked right, a step-up no longer met, a session cap that no longer covers the rights), or that fails, stops
there with no footer, so a reader can tell it is incomplete. CSV is not offered yet (N97).

**From the console.** `authorization:review` exports a review as JSON Lines on the trusted path (see
[Exporting an access review from the console](#exporting-an-access-review-from-the-console)).

**Indexes.** The migration `2026_11_08_000001_add_access_review_indexes` adds an index on the `granted_by` pair of each
grant table, which a review of an actor's grants is matched on, and one on the permission of the role permission edges,
which the holders of a permission are found by (MySQL already indexes that column for its foreign key, and keeps that
index). On PostgreSQL it also adds an index on each grant table's target and its grantee's type and key, collated `C`,
the order a page of direct holders is read and resumed in. The other review queries are served by the indexes the
tables already have: on MySQL and SQLite, whose reference columns compare their bytes, a target's grants by each grant
table's unique index. The migration honours the configured table names and connection.

**What is left out.** Boundaries, guardrails and resource-policy attachments restrict or extend what a check decides,
but are not held, so no review lists them. Snapshot exports and CSV are not offered. See
[Access reviews](docs/design/access-reviews.md) for the design.

#### Usage tracking

Usage tracking records which grants are used, so a review can tell a grant nobody uses from one whose use was never
watched (N94, N100 to N102). It is off by default, and free when off: a check does no extra work and allocates nothing
for it, no listener is registered and no usage table is read, and every review row's `usage` reads `unknown`. Turn it on
in `config/authorization.php`, or with `AUTHORIZATION_USAGE_ENABLED=true`:

```php
'usage' => [
    'enabled'    => true,
    'interval'   => 3600,   // the bucket, in seconds; at least 60
    'batch'      => 250,    // the most observations one recording job carries
    'connection' => null,   // the queue connection the recording job goes to; null for the default
    'queue'      => null,   // the queue; null for the connection's default
    'retention'  => 400,    // the days coverage is kept
],
```

**The cost.** While tracking is on, a resolution of a grantee's permissions and policies also keeps the routes of the
stored grants behind each, read from the rows it reads already and kept beside its entry in the resolution cache, each
grant and route once however many permissions it gives. A check finds the routes behind its decision only among what it
resolved itself, so a cold check runs the same queries as an untracked one (a subject's identity, say, is never
resolved for tracking when the check did not need it), and a warm check finds the routes at a constant extra cost and
with no query. A cache entry kept before tracking was turned on is never read for one, so turning it on resolves each
grantee once more. The routes are noted in memory and sent to be recorded by a queued job, never on the check. No step
tracking adds ever changes or breaks a check: one that fails is written to the log channel and the decision is
returned as it was made.

**What counts.** Only what a decision rested on counts, by the rules the check itself applied. An allowed decision
counts every live grant route behind the permission that allowed it, redundant ones included: the direct grant, and each
role grant that carried it with the ancestor role it came through. They are the routes of the grantee whose permission
matched: the subject's own, or its identity's only when the subject's did not match, since the check asks for the
identity's only then. A policy counts whenever one of its statements decided, allow or deny, so a policy that only
denies, doing its job, is used, by its attachment to the subject or to its identity. An identity of the other kind (a
machine's person, or a person's machine) gives a check its deny statements alone, so its attachment counts only for a
decision its denies made. These are everyday decisions and count: `check()`, `can()`, `cannot()`, `any()`, `all()`,
`authorize()`, `checkMany()`, `canEach()`, `filterAuthorized()`, the Gate, the Blade directives and the middleware, and
a delegated change's own check. A role check (`hasRole()`, `@role`, `role:`) is no decision and counts nothing.

**What never counts.** Only a decision the application acts on is use, so nothing else counts:

| Path                                                                           | Why it never counts                                                                     |
|--------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| `previewFor()` and its admission                                               | A preview decides about another subject as the caller, who uses none of its grants      |
| `explain()` and `authorization:why`                                            | An explanation runs the check to show it, not to act on it (N89)                        |
| `permissionsFor()`                                                             | A listing of what a subject may do is introspection (N70)                               |
| `whereAuthorized()` and `queryScope()`                                         | A scoped query compiles SQL and decides no record                                       |
| A review's admission and its reads                                             | Reviewing who holds what is introspection, and must not create the use it reports       |
| A delegated change's administration stage                                      | Its further checks weigh the change, and a refused change counts nothing it was allowed |
| A permission from a custom `getPermissions()`                                  | A grantee whose grants the package does not resolve cannot say where they came from     |
| A policy from a store, a resource, `withPolicies()`, a guardrail or a boundary | None of these is a grant a subject holds                                                |
| An identity's grant when the subject's own matched                             | The check never asked for it, so the decision did not rest on it                        |

**The interval.** Observations are bucketed by `interval` seconds, an hour by default: a bucket starts at a whole
multiple of the interval in UTC, so every worker agrees where it starts. Each route is noted at most once a bucket per
worker, and a review says a route was last used within the interval that starts at its `last_observed_at`. A queue
worker or a command notes for as long as it runs; under Octane each request's sandbox notes for itself.

**The queue.** Nothing is sent from within a check, so a check never waits on the queue or the store, the `sync`
connection included. What a worker notes is sent as `RecordGrantUsage` jobs when the request, command or queued job
ends, to the `connection` and `queue` configured. Once a worker notes `batch` observations it sets them aside as a job
of their own, so no job outgrows a queue's limit on a job's size: a job of the default 250 is about 110 KB at worst,
well under SQS's 256 KB, and each observation adds about 450 bytes at worst, so lower `batch` for a queue with a
smaller limit (Beanstalkd's default is 64 KB). A worker sets aside at most ten batches before it ends its request or
job; past that it drops the oldest, and the next job names the earliest bucket dropped, from which the store does not
extend the coverage, so the routes whose use was dropped read `unknown` rather than `unused`. A queue that refuses a
job is written to the log channel, and its observations are dropped and named by the next job in the same way.

**The tables and pruning.** The migration `2026_11_09_000001_create_grant_usage_tables` adds `grant_usage`, one row for
each grant route with the start of the last bucket it was observed in and the creation of the grant it was observed
through, keyed by a stable digest of its source kind, target, grantee, tenant, application and role path (the roles it
runs through, as in `role_path`), and `usage_coverage`, the periods tracking was on, `[from, until)` in UTC. Both honour
the configured table names (`tables.grant_usage`, `tables.usage_coverage`) and connection. A write never moves a route's
last use backwards, so a job delivered twice or out of order changes nothing. The routes are written in the order of
their keys, a hundred to a transaction, with no row read under a lock, so two workers take their locks in the same
order; a transaction that deadlocks or waits too long for a lock is tried again, three times in all, and a job that
still fails extends no coverage. `authorization:usage-prune` removes the usage of every route whose stored grant no
longer exists and the coverage older than `retention` days.

**The heartbeat.** Each recording job extends the current coverage period, or opens a new one when the gap since the
last one ended exceeds two intervals. A site that is tracking but quiet sends no jobs, so schedule the heartbeat at
least once an interval to keep it covered; it records nothing while tracking is off:

```php
Schedule::command('authorization:usage-heartbeat')->hourly();
Schedule::command('authorization:usage-prune')->daily();
```

**The store.** Usage is kept behind `Contracts\GrantUsageStore`: `record(UsageBatch $batch)` keeps a batch, each route
only when its observation is newer, and extends the coverage to the batch's instant, but never across the time since a
`lostSince` the batch names; `lastObserved(array $keys)` returns
what is kept of each route asked about; and `coverage($from, $until)` returns the periods that overlap a window. The
package binds `Usage\DatabaseGrantUsageStore` on the tables above; bind your own to send usage elsewhere.

**Coverage and unknown.** A row's window runs from the later of the review's `since` and the grant's creation to the
review's instant. Its `usage` is `used` when its route was observed in a bucket that ends after the window starts;
`unused` only when the coverage periods, each taken to run two intervals past its end, cover the whole window and the
route was never observed in it; and `unknown` otherwise: tracking is off, coverage of the window is incomplete (a
window that starts before tracking began, or that a gap interrupts), or the route's source cannot report its use (a
role's permission edge or policy attachment, a grantee with its own `getPermissions()` or `getPolicies()`, or, for a
policy, a policy resolver of your own). A missing observation alone is never taken as proof of non-use.
`coverage_from` and `coverage_until` give the latest coverage period overlapping the window.

**Regrants.** A grant revoked and made again is a new row, created later, and never inherits the old grant's use: an
observation made through a grant created before the current one is ignored. A grant whose expiry or reach
(`include_subtree`) is rewritten in place, neither of which is part of its usage key, keeps its creation, and so its
use.

**The unused review.** `ReviewQuery::unused($scope, $since)` lists the live grants in the scope (roles and permissions
granted, policies attached to grantees) with no observed use since the instant, each `unused` or `unknown`, and leaves
out those used. It pages, streams and exports as every review does, admitted by the same `authorization:review.read`
right, which never counts as use; `authorization:review unused --since=…` exports one. It reads the grants a fixed
chunk at a time, never fewer for the rows a page has kept, so the reads grow with the grants it passes over, never one
for each. Every review row carries `usage`, read in one batched lookup a page, or a chunk for the unused review. The
row's shape stays `version: 1`, since the package is unreleased.

```php
$reviews->trusted(ReviewQuery::unused(ReviewScope::everywhere(), now()->subDays(90)));
```

Recording lags: a worker's observations arrive at the store when its request, command or job ends, so a grant used only
in the last moments may read as unused until then. Coverage is kept for the whole site, so observations a worker lost
without naming them (a process killed before it sent them, say) are lost while other workers' jobs keep the coverage
going.

### Grant scope query

`GrantScopeQuery` answers two factual questions about grants for a trusted integration, such as `laravel-iam`
composing SSO's principal scope or a tenant's admission: where the grants of an identity lie against a tenant, and
whether a principal holds a grant that applies in one. Resolve it from the container, where it is a singleton:

```php
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Support\Reference;

$grants = app(GrantScopeQuery::class);

$grants->forIdentity(Reference::of($person), $account);       // GrantScopeStatus::WITHIN, OUTSIDE or UNKNOWN
$grants->hasGrantIn($user, $account);                         // GrantPresence::PRESENT, ABSENT or UNKNOWN
$grants->hasGrantIn($user, $account, application: 'admin');   // only the grants that hold in the admin app
```

**The identity directory.** Principals and their identities live in the application, so the package learns which
principals an identity owns only from the identity directory, a class implementing
`SineMacula\Laravel\Authorization\Contracts\IdentityDirectory`. Its `principalsOf($identity)` returns an
`IdentityPrincipals`: the references to the principals the identity owns, the identity itself left out, and whether
that list is complete. A directory that cannot tell, for an identity it does not know or a store it cannot read,
returns an incomplete list with whatever principals it does know. The package never infers an identity's principals,
from `AuthorizableIdentity` or from anything else.

The shipped default, `GuardUserIdentityDirectory`, knows the answer only under the shipped subject resolver, where
every user is its own identity and owns no other principal, so its list is complete and empty. Under any other
resolver its list is incomplete, so `forIdentity()` never answers `WITHIN`. An application with principals names its
own directory in `config/authorization.php`, or binds the contract itself; like the subject resolver, a class named
there is built per request or job, and null or a class that does not implement the contract is refused at boot:

```php
'identity_directory' => App\Authorization\PrincipalDirectory::class,
```

**In the suite.** `laravel-iam` binds a complete identity directory adapter, so an application using it needs nothing
more. An application with principals that does not use `laravel-iam` binds its own: a directory that lists, for each
identity, every principal it owns, as below, and answers an incomplete list for an identity it cannot read. Left in
place under another subject resolver, `GuardUserIdentityDirectory` answers incomplete for everyone, so a grant to any
principal is treated as widening (`INCOMPLETE_DIRECTORY`) and no grant scope query answers `WITHIN`.

```php
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Support\IdentityPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;

final class PrincipalDirectory implements IdentityDirectory
{
    public function principalsOf(Reference $identity): IdentityPrincipals
    {
        $person = $identity->type === (new Person)->getMorphClass() ? Person::find($identity->id) : null;

        if ($person === null) {
            return IdentityPrincipals::incomplete();
        }

        return IdentityPrincipals::complete($person->principals->map(Reference::of(...))->values()->all());
    }
}
```

**`forIdentity()`.** `forIdentity($identity, $tenant)` takes a `Reference` to the identity and the tenant as a model,
an `AuthorizableTenant` or a `Reference`. It reads the grants of the identity and of every principal the directory
lists, in every application and under every guard, and classifies each grant by its root (the tenant its row names, or
the platform for a row naming none) against the tenant, in the bound tenant tree:

- `GrantScopeStatus::OUTSIDE` when any grant is rooted outside the tenant: at an ancestor, a grant reaching the
  ancestor's subtree included, at a sibling or any other tenant, or at the platform. One grant proven outside is
  enough, whether or not the directory's list is complete;
- `GrantScopeStatus::WITHIN` when the directory's list is complete and every grant is rooted at the tenant or below
  it, or when there is no grant at all, since nothing then lies outside;
- `GrantScopeStatus::UNKNOWN` otherwise: the directory's list is incomplete, the tenant tree cannot be read, or a grant
  row names half a tenant. A tree that cannot be read is written to the log, and a platform-wide grant still proves
  `OUTSIDE` without it.

A tenant tree other than the flat one is read through its `subtree()` query, nested whole in the grant query, so it
must be a query on the package's connection; anything else is a tree that cannot be read. So is a subtree query that
fails as the grant query runs (a closure table that is missing, say, or a column of another type): the grant query
runs in a savepoint of its own, so the failure rolls back only that query and leaves your transaction usable, and the
platform-wide grants are then read alone.

**`hasGrantIn()`.** `hasGrantIn($principal, $tenant, $application = null)` answers whether the principal holds a live
grant that applies in the tenant, as a check there reads it: one made in the tenant, one made in an ancestor that
reaches its subtree, or a platform-wide one. The principal's own grants count, and its identity's when they reach it,
as they do for a check, so a person's grants never count for a machine; a grant held by another principal of the same
identity never counts. A `Subject` is taken as it is, and any other object becomes one as the subject resolver's
`forUser()` makes it. Given an application, only the grants that hold in it count, those made for every application
included; without one, a grant counts whichever application it holds in. The answer is:

- `GrantPresence::PRESENT` when such a grant is found;
- `GrantPresence::ABSENT` when none is found and none could have been missed;
- `GrantPresence::UNKNOWN` when none is found but one could have been missed: the tenant tree cannot be read, so only
  the grants made in the tenant itself and the platform-wide ones are looked for, or a grantee is neither a model nor a
  `Reference` and its grants cannot be read. Uncertainty is never `PRESENT`.

The two questions differ on purpose. A grant made in an ancestor that reaches its subtree applies in a child tenant,
so `hasGrantIn($user, $child)` is `PRESENT`; it is rooted outside the child, so `forIdentity($identity, $child)` is
`OUTSIDE`.

**What counts as a grant.** A live role granted, permission granted directly or policy attached, a policy that only
denies included. Roles are not expanded into their permissions, since a role's root is where it was granted. An
expired grant counts for nothing, and neither does an inline policy attached to a grantee it does not belong to, which
no check applies. Permission boundaries and guardrails cap grants; they are not grants and are never read.

**Neither membership nor authorisation.** Neither answer says whether a principal is a member of a tenant, which is
the application's to know, nor whether it may act there or use an application. `PRESENT` means a grant applies in the
tenant, not that any check there would allow. `check()` stays the one decision path, and
`ApplicationAccess::mayUse()` answers application access.

**A trusted service.** Even a bare answer tells the caller something about grants in other tenants, so call it from
trusted integration code, never from an endpoint a user reaches without the right to know. It returns the status
alone, never the tenants, grants, names, counts or rows behind it.

**What it costs.** Each answer reads the grants in one query on the write connection, so a replica's lag never hides a
grant, however many grants and principals there are and however deep the tree, plus the tree's own reads and the
directory's; only a subtree query that fails as it runs costs a second read, of the platform-wide grants. Nothing is
cached. See [Grant scope](docs/design/grant-scope.md) for the design.

### Grant hooks

Before a grant that widens an identity's scope is written, the grant service calls a grant hook the application binds
(AUTHZ-11.3), inside the call's transaction and before the package takes any lock of its own for the call. The hook
may refuse by throwing. Under the suite, `laravel-iam` binds it to `laravel-sso`'s scope widening, so a grant can never
quietly take an SSO-linked identity outside the tenant its connection allows.

**What widens.** The grants of a call are classified against what the identity already holds: its own grants and those
of every principal the [identity directory](#grant-scope-query) lists, live, in every application. A grant widens the
identity's scope when:

- its grantee is the identity itself, since it holds across every principal of it (`WideningReason::IDENTITY`);
- it is platform-wide (`PLATFORM`);
- it is in a tenant where no grant of the identity or its principals applied before, which covers a new tenant, a
  sibling of one held and an ancestor of one held (`NEW_TENANT`);
- it reaches below its tenant, where no grant of theirs reached below before (`NEW_SUBTREE`).

These do not widen: a permission added to a role the identity holds in one tenant (a change to the role, not to anyone's
scope), a grant in a tenant another principal of the identity already holds a grant in, a grant the grantee already
holds unchanged, and one that only shortens a grant held. A re-arm of an expired grant, an extension of a live one and
a wider reach are classified like a new grant. A grant to a role widens no identity's scope.

**When in doubt, the hook is called.** An incomplete directory (`INCOMPLETE_DIRECTORY`) or a tenant tree that cannot be
read (`UNREADABLE_TREE`) makes a grant widen. A grant whose identity cannot be resolved, because the grantee's model
cannot be found or the subject resolver's `forUser()` throws or names no identity for it, is refused with
`UnresolvableRecipientException`, never written with its hook skipped. The package resolves the identity through the
subject resolver: `forUser($grantee)` names the identity, and the grantee is either that identity or the subject it
was given.

**The contract.** A hook implements `SineMacula\Laravel\Authorization\Contracts\GrantHook`, whose one method is handed
a `GrantWidening`, an immutable value with no model and no mutable date in it: the operation's id and whether the call
is trusted, the actor, the actor's identity and any impersonator, the identity whose scope widens and the grantee the
rows are written for (`isToIdentity()` tells them apart), each widening grant as a `ProposedGrant` (the action, the
target by reference, the tenant, the application, the reach and the expiry as an immutable UTC instant, with its
reasons), every reason of the call once, and when the proposal was observed:

```php
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Exceptions\GrantRefusedException;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;

final class ScopeWideningHook implements GrantHook
{
    public function __construct(private readonly ConnectionLinks $links) {}

    public function beforeWidening(GrantWidening $widening): void
    {
        if (! $this->links->allowsWidening($widening->identity, $widening->changes)) {
            throw new GrantRefusedException('This identity is linked to a tenant it may not leave.');
        }
    }
}
```

**The client.** The widening carries the operation's client, `ip` and `userAgent`, each a nullable string, as the
`Operation` does. A grant made through the services gets its client only from the routed request of a delegated call,
the IP address as Laravel resolves it behind your trusted proxies. A trusted grant, and any grant made from the console
or a queued job, reaches the hook with no client: no service takes one. Code that builds an `Operation` or a
`GrantWidening` itself, such as the membership path below or a hook's own tests, may pass one explicitly, as
`Operation::begin($actor, $actions, $ip, $userAgent)` or the constructors' last two arguments, and a client given there
is kept as it is. Pass only the client of a routed request, never one read from the request Laravel binds for the
console and the queue, which reports `127.0.0.1` and `Symfony`. Both are personal data, so the package hands them to the
grant hook alone: the change events carry the operation without them, and they are never put in a cache key, a decision
event, a log or a stored grant row. A hook that keeps them is answerable for them.

**One binding, with the listed hooks before it.** Exactly one hook is bound on the contract. The default is
`Hooks\GrantHooks` holding no hook, which does nothing; a sibling package or your application may bind its own instead,
before the package registers or after. The classes `grant_hooks` lists in `config/authorization.php` run before
whichever hook is bound, each built from the container and run in the order listed, and the first that throws stops
the rest. The list is validated at boot: each entry must name a class implementing the contract, once. With none listed,
and the default bound, nothing is classified at all. There is no way to add a hook at run time.

**The listed hooks run before whatever is bound.** When `grant_hooks` lists hooks, the package extends the contract with
Laravel's `extend()`, so whatever the contract resolves to is wrapped in `Hooks\ListedGrantHooks`: the listed hooks run
first, in the order listed, then the bound hook, and any of them may refuse, so nothing either would refuse gets
through. Hooks only refuse, so wrapping a hook is never looser than running it alone. Laravel applies the extender each
time it builds the contract, so the hook is wrapped however it was bound: before the package registers or after, with
`bind()`, `singleton()` or `scoped()`, a scoped closure that names the contract by its return type included, by a
deferred provider, or the package's default when nothing else is bound, which holds none of the listed hooks, so none
runs twice. An extender a sibling package registered on the contract before the package applies to the bound hook first,
and the listed hooks run before the hook it returns; an extender registered after the package receives the wrapped hook,
`ListedGrantHooks`, so one typed to another class fails. Laravel applies no extender to an instance it is handed later,
so the grant service wraps the hook it calls as well, unless it already is wrapped: a hook bound with `instance()` after
the package registers, and a hook bound in any way after an instance the package wrapped when it registered, run after
the listed hooks too. When an extender registered after the package decorates the wrapped hook and the grant service
wraps the decoration again, the listed hooks still run once, first. With no hook listed nothing is extended, and the
bound hook stands alone.

The wrapped hook builds the listed hooks from its container at its first use and keeps them, so registering the package
builds none of them, and they share the bound hook's lifetime: built afresh for each queue job and in each Octane
sandbox when it is scoped, bound with `bind()` or the default, and kept with it when it is a singleton or an instance.
The package resolves the bound hook while it registers only when the hook was resolved before and a callback watches
the contract with `rebinding()` or `refresh()`: Laravel then hands that callback the wrapped hook. Registering the
package again in the same container wraps nothing twice.

```php
'grant_hooks' => [
    App\Authorization\ScopeWideningHook::class,
],
```

**Veto only.** A hook may refuse by throwing `GrantRefusedException`, or any other exception: the whole call rolls back,
nothing is written, no change event is dispatched and the call is not tried again. A hook's refusal is never reported as
a denial of the package's: it is thrown on as the hook threw it. The one exception is a database concurrency error
raised by the hook's own preparation, a deadlock or a serialisation failure, say: it is handled as any concurrency error
is (see [Delegated administration](#delegated-administration)), so a call that opened the transaction tries it again,
hook included, and once no tries are left refuses it as `administration.conflict`, and inside your own transaction it is
thrown as `TransactionConflictException`. Returning lets the call go on and decides nothing: a delegated call is still
decided after the hook, and refused when it should be. A hook never changes the grant. While a hook runs, every
management service of the package refuses with `GrantHookRecursionException`, so a hook cannot grant, revoke or edit
anything through the package's services, trusted or delegated; read-only queries, `GrantScopeQuery` among them, stay
allowed. A raw Eloquent write on the package's models, pivots or tables is not refused: it stays the unguarded trusted
surface it always is (see **Raw writes** below), and belongs in no hook. A hook may do the application's own
transactional preparation on the package's connection, which rolls back with the grant.

**Before any lock, and again on a retry.** The hook runs for trusted and delegated calls alike, before the package takes
any lock for the call. A batch, a sync, calls it once with every widening grant, before any lock and any write. Only
then does the call lock, read its records again, rebuild what it writes and decide it. Last, after every other lock, it
classifies what it writes again, reading under a lock the grantee's own rows and the grants of the identity and its
principals that the hook phase relied on: a locking read sees the latest committed rows, whatever snapshot the
transaction reads otherwise, and holds them until the call commits, so a revocation committed meanwhile is seen, and one
made later waits for the call. If what it writes now widens with no hook run for it, because a grant the classification
relied on was revoked meanwhile, say, the try is a conflict and the whole call is tried again from the start, up to
`administration.retries` times, then refused as `administration.conflict`. A hook is never called under the package's
locks. So a hook can run more than once for one call: nothing that leaves the transaction belongs in it, no email, no
remote call and no queued work. Use the events dispatched after commit (see [Listening to events](#listening-to-events))
for those. Only the application's own answers are read as they stand, the identity directory's list of principals and
the tenant tree: a change to those, made concurrently, is the application's to serialise.

**Nested calls and outer transactions.** A grant made inside another management call's work, from a model observer or a
listener that call's own writes fire, may come after that call took the package's locks, so its hook cannot run before
them; one that widens is refused with `NestedGrantException`, never written with its hook skipped. Inside a transaction
of your own, a try that conflicts is rolled back only to its savepoint, and on MySQL the row locks it took stay held
until your transaction ends, so a grant is never tried again there with its hook: a grant that now widens with no hook
run for it, and a retry whose grant would call its hook again after another conflict, are thrown as
`TransactionConflictException`, whose previous exception is the conflict. Restart your transaction, for example with
`DB::transaction($callback, attempts: 3)`. Grant calls made one after another inside a transaction of your own each run
their hooks before their own locks, but the rows an earlier call locked stay locked until your transaction ends. To keep
every hook ahead of every lock the package takes in the transaction, make the grant calls first, before anything else
that takes the package's locks. `authorization:migrate-spatie` does so: it commits the roles, permissions and roles'
permissions first, then makes each grant as a call of its own, so run it outside any transaction of yours; a grant a
hook refuses stops the import, with what was written before it kept.

**What the hook does not cover.**

- **Memberships.** Creating or accepting a membership widens an identity's scope too, but memberships are not this
  package's (AUTHZ-13.9): the application, or `laravel-iam`, calls the same hook on its own membership path, inside the
  membership's transaction:

  ```php
  use Illuminate\Support\Facades\DB;
  use Illuminate\Support\Str;
  use SineMacula\Laravel\Authorization\Contracts\GrantHook;
  use SineMacula\Laravel\Authorization\Enums\WideningReason;
  use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
  use SineMacula\Laravel\Authorization\Hooks\ProposedGrant;
  use SineMacula\Laravel\Authorization\Support\Reference;

  // The client of a routed request alone: console and queued work have none.
  $request = request()->route() === null ? null : request();

  DB::transaction(function () use ($person, $principal, $tenant, $membership, $request) {
      // Saved first, so the hook is handed its key; a refusal rolls it back.
      $membership->save();

      app(GrantHook::class)->beforeWidening(new GrantWidening(
          operationId: (string) Str::uuid(),
          isTrusted: true,
          actor: null,
          actorIdentity: null,
          impersonator: null,
          identity: Reference::of($person),
          grantee: Reference::of($principal),
          changes: [new ProposedGrant(
              action: 'membership.create',
              target: Reference::of($membership),
              tenant: Reference::of($tenant),
              application: null,
              includeSubtree: false,
              expiresAt: null,
              reasons: [WideningReason::MEMBERSHIP],
          )],
          observedAt: now('UTC')->toImmutable(),
          ip: $request?->ip(),
          userAgent: $request?->userAgent(),
      ));
  });
  ```

  The membership is saved before the hook is called, inside the same transaction, so the hook sees its real key and a
  refusal rolls the save back with everything else.

- **Raw writes.** A raw Eloquent write on the package's models, pivots or tables is a trusted integration surface, as
  it is for delegated administration, and runs no hook. Only the grant service's calls, and everything built on them
  (the trait helpers and the console commands), are guaranteed to.
- **Break-glass.** The emergency grant (AUTHZ-11.7) will grant through the same path, so its hook is never skipped
  either: `Hooks\WideningPhase` is the one call point every grant goes through.

See [Grant scope](docs/design/grant-scope.md) for the design.

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
subject, its policy override and its caps, and a preview from `previewFor()` with its previewed subject (see
[Preview](#preview)). A guest keeps no row. The context is the caller's values, read under
`input`, as `check()` reads them.

The scope is compiled when `whereAuthorized()` is called, so a refusal throws there and the builder is left exactly as
it was, and again every time the query is compiled to run, from the state then: a page and its count, each chunk, an
update or a deletion are each decided afresh, so a grant revoked after the call is seen by the next execution, and no
decision is reused. Compiling, at the call or at execution, records no last decision and dispatches no
`DecisionEvaluated`, so an audit of row access needs its own hook, except through a preview, whose every compile admits
it again, recording and reporting that admission as any check. The scope never runs a query on the model's table of
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
  guardrails (except for `authorization:guardrail.manage`), session caps and the policies attached to the model's
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

A tree other than the flat one is read through `TenantTree::subtree()`, nested in the condition whole, so it must run on
the model's connection, and one on another is refused as `subtree_connection` (the [grant scope
query](#grant-scope-query) needs it on the package's connection instead); its contract is that `subtree(T)` selects
exactly the string forms (`tenant_type`, `tenant_id`) of every tenant within `T`, whatever the tenant scope. The rows
are split into classes at the tenants the decision's sources sit at: the subject's grants, policies and boundaries, its
roles', the guardrails and the type's attached policies. Each class is decided once, every time the query runs, so the
number of tenants and classes is bounded:

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
| `preview_write`                                          | A scope given a preview, run as an `update()`, a `delete()` or an insert from its own query or one nesting it whole                                  |

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
or the package itself (its administration actions, `authorization:guardrail.manage` among them) declares, with the
package's decision: true for an allow, false for a deny. Laravel stops at the first before-callback that answers, so
both stand: no `Gate::define` callback, Laravel policy class or `Gate::after` callback can override either.
`Gate::allows()`, `Gate::forUser($user)`, `$user->can()`, `@can`, the `can:` middleware, `Gate::authorize()` and a
controller's `authorize()` all go through it, whatever Laravel policy class the resource's model has:

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
php artisan authorization:revoke user:1 editor
php artisan authorization:revoke user:1 editor --actor=user:7
php artisan authorization:list-roles
php artisan authorization:list-permissions
php artisan authorization:why user:1 posts:delete post:42 --tenant=team:7
php artisan authorization:review holders role:1 --rooted-within=team:7 --output=holders.jsonl
php artisan authorization:policy:validate --database
php artisan authorization:prune --pretend
php artisan authorization:usage-heartbeat
php artisan authorization:usage-prune --pretend
php artisan authorization:check
```

`authorization:check` reports the configuration the application runs with, one `name: state` line per check, and exits
with `0`. It reports whether the Gate hook is enabled:

```text
Gate hook: enabled (the package answers every ability it declares through Gate::before)
```

It is the start of the configuration report: each setting and seam it comes to report adds a line.

Each command's class names its command in a public `NAME` constant, the name its signature declares, so a schedule, a
test or a sibling package can refer to it without repeating the string: `PruneGrantsCommand::NAME` is
`authorization:prune`, and so on for `CheckConfigurationCommand`, `GrantRoleCommand`, `RevokeRoleCommand`,
`ListRolesCommand`, `ListPermissionsCommand`, `SyncPermissionsCommand`, `MigrateSpatieCommand`,
`ValidatePolicyCommand`, `WhyCommand` and `ReviewCommand`, all in `SineMacula\Laravel\Authorization\Console`.

The listing commands are administrative views: they list every role or permission, platform-wide and tenant-owned
alike, and show each one's owner. `grant` and `revoke` write through the grant service and look the role up within the
tenant scope, so without a resolved tenant they find platform-wide roles only. A role the identity already holds with
no expiry, or does not hold, is reported as such and nothing is written. `grant` gives no expiry, so a role the
identity holds on a temporary or expired grant is made permanent and reported as granted. `grant`, `revoke` and
`authorization:sync` take `--actor={morph type}:{key}` to name who made the change; it must name a row that exists, and
without it the change is trusted work that records no actor. For `authorization:grant` and `authorization:revoke` the
actor makes the change as delegated administration, decided as that actor, with no session (see
[Delegated administration](#delegated-administration)), so a role grant passes only when the actor outranks the
identity and may hand out everything the role carries; for `authorization:sync` it is recorded on the trusted
operation's events alone.

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
use SineMacula\Laravel\Authorization\Console\PruneGrantsCommand;

Schedule::command(PruneGrantsCommand::NAME)->daily();
```

`authorization:usage-heartbeat` extends the coverage of [usage tracking](#usage-tracking) to now, so a quiet site stays
covered, and records nothing while tracking is off; `authorization:usage-prune` removes the usage of grants that no
longer exist and coverage older than `authorization.usage.retention` days, and takes `--pretend`.

#### Explaining a check from the console

`authorization:why` prints the explanation of a check about a saved subject (AUTHZ-11.5), the `Explanation` that
`explain()` returns (see [Explanations](#explanations)):

```bash
php artisan authorization:why user:1 posts:publish --tenant=team:7
php artisan authorization:why user:1 posts:publish post:42 --tenant=team:7 --application=admin
php artisan authorization:why user:1 posts:create 'post:*' --tenant=team:7
php artisan authorization:why user:1 reports:read reports:42 --opaque
php artisan authorization:why user:1 posts:publish --context='{"purpose":"support"}' --format=json
```

It explains the named subject under the given scope and console context, without their browser session. The text it
prints says so before the explanation, as the first of these does:

```text
Explanation for the named subject under the given scope and console context, without their browser session:

ALLOW at the allow stage by permission "posts:publish".
  ...
  request "posts:publish" about user:1 (identity user:1); asked in tenant team:7, decided in tenant team:7
```

| Argument or option | What it names                                                                                   | When omitted                                                     |
|--------------------|-------------------------------------------------------------------------------------------------|------------------------------------------------------------------|
| `{subject}`        | The saved subject, as `{morph type}:{key}`, resolved by the console subject resolver            | Required                                                         |
| `{action}`         | The action, passed to the check unchanged                                                       | Required                                                         |
| `{resource}`       | `{morph type}:{key}`, that record; `{morph type}:*`, the type alone; anything else, as given    | A check without a resource, never every resource                 |
| `--tenant`         | The tenant, as `{morph type}:{key}`                                                             | The platform, never the tenant in place                          |
| `--application`    | The application                                                                                 | No application: only the grants for every application count      |
| `--context`        | A JSON object, read as the `input` namespace alone                                              | No input                                                         |
| `--format`         | `text`, the preamble and `toText()`, or `json`, the versioned JSON alone, with no prose or ANSI | `text`                                                           |
| `--opaque`         | The resource is an opaque identifier, used as given, even when it holds a colon                 | A resource with a colon names a record or a type                 |

**The subject.** The reference is resolved by the `ConsoleSubjectResolver` bound in the container, never from whoever is
signed in to the console. The default, `ReferenceSubjectResolver`, takes the type as a morph map alias or an Eloquent
class, loads the row with the key, and maps the model to its principal and identity through the bound subject resolver's
`forUser()`, as the Gate's user is: under the shipped resolver the model is its own principal and identity; under an
application's resolver with principals, a person is mapped to the principal it acts as. It refuses a reference not in
that format, a type that names no model, a key no row has, a mapping about neither the model's principal nor its
identity (ambiguous), a principal that is not a saved authorizable identity (unsupported), and a lookup or mapping that
fails (unresolvable), keeping the failure as the previous exception. The subject keeps its principal, identity and
guard, and nothing else the resolver gives it: the command adds the tenant and application, and there is never a
session.

**The scope.** `--tenant` omitted is the platform: a tenant resolved for the console, or one a job left in place, is
never inherited. A type the morph map or a class name resolves to an Eloquent model must name a row that exists, and
the tenant is named by that model's morph class; any other type is taken as the tenant reference as given. The check
runs on the trusted `for()` path, through the one decision path, with the scope in place both as the ambient grant scope
and as the subject's, in effect:

```php
$scope->within(fn () => Authorization::for($scope->subjectIn($subject))->explain($action, $resource, $input));
```

The scope in place before is restored afterwards, even when the check throws. The check is recorded as the last
decision and dispatches its `DecisionEvaluated`, as any explained check does.

**The resource.** It is passed to the check as `check()` takes it, so the check on it is an ordinary one. A
`{morph type}:{key}` resource, `post:42`, names that record as the `['post', '42']` pair: its tenant comes from the
bound resource tenant resolver, its resource policies and those of its type apply, and its attributes come from the
attribute provider declared for its type. The key keeps any colon after the first (`org:acme:eu` is the key `acme:eu`
of `org`), and the type is used as given, as a pair's is, a model class named by its morph class. `{morph type}:*`,
`post:*`, names the type alone, as a model class does when the type is one: the policies attached to the type apply,
and no record's attributes are read. A resource with no colon, such as `posts/42`, and any resource given with
`--opaque`, such as a URL, is an opaque identifier, used as given, with no tenant, no resource policy and no
attributes. A colon with an empty type or key on either side (`:42`, `post:`) is refused. The command never loads the
record or reads its columns: what the providers do not supply stays missing.

**The context.** `--context` supplies the `input` namespace alone: `{"purpose":"support"}` gives `input.purpose`. It
cannot fill a trusted namespace, so malformed JSON, a value that is not an object, and a key naming `authentication`,
a namespace your `AuthenticationContext` contributes beside it (such as `mfa`), `request`, `environment`, `subject`,
`resource`, or a namespace an application's context source supplies, or a dotted key starting with one
(`request.ip`), are refused. Without the subject's browser session no authentication requirement is met, so an allow
that needs one does not apply, and the explanation names its unmet parts. A key the explanation reports missing is
evidence of what the decision found, not advice to supply it.

**Exit codes and errors.**

| Code | When                                                                                                                                                |
|------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `0`  | An explanation was printed, whether the check allows or denies                                                                                      |
| `2`  | An invalid invocation: an unknown option, a missing argument or option value, the JSON, a reference, or a subject or tenant that cannot be resolved |
| `1`  | The check failed: no explanation is printed, and the error names the exception's class alone                                                        |

Errors go to the standard error, so a `--format=json` run leaves the standard output empty when it fails. They name the
argument or option, never a value given, context value, operand or attribute: a subject or tenant that is malformed,
whose type names no model or whose key no saved row has is refused by its argument or option alone (`The subject names
no saved row.`, `The --tenant option names no saved row.`), and so is a subject the resolver refuses, by what its
refusal's code says is wrong. A subject or tenant whose lookup fails, such as a key the key column cannot hold on
PostgreSQL, a database error or a subject resolver that throws, or refuses it in words of its own, exits `2` too,
naming only the argument (`The subject could not be resolved.`), never the query, the value or the failure's message.
Their console markup, control characters, format and bidirectional characters, in an unknown option's name say, are
escaped as every name in the text output is, and an error holding bytes that are not UTF-8 is escaped whole.

**A trusted operator surface.** The command shows how the policies are built, the names of policies, statements,
conditions, keys, roles and tenants, to whoever can run the console; it admits no caller. An application showing
another subject's explanation to its own users goes through a preview (`previewFor()`), which admits the caller first
(see [Preview](#preview)).

**Your own subject resolver.** An application whose references the default cannot map, or whose principals and
identities its mapping cannot tell apart, binds its own resolver on the contract, which replaces the default:

```php
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;

$this->app->bind(ConsoleSubjectResolver::class, App\Authorization\StaffConsoleSubjects::class);
```

Its `resolve(string $reference): Subject` returns the subject with its principal and identity, and refuses a reference
it cannot resolve by throwing `UnresolvedSubjectException`, which the command reports with exit code `2`, by what the
refusal's code says is wrong (`MALFORMED`, `UNKNOWN_TYPE`, `NOT_FOUND`, `UNSUPPORTED`, `AMBIGUOUS` or `UNRESOLVABLE`,
as the exception's factories set it) and the argument's name alone: its message is never printed, since it may name
the reference. A refusal with any other code, and anything else it throws, is reported as
`The subject could not be resolved.`, with exit code `2` too.

#### Exporting an access review from the console

`authorization:review` exports an access review (see [Access reviews](#access-reviews)) as JSON Lines, as trusted system
work through `AccessReview::trustedExport()`: the console is a trusted operator surface, so it admits no caller, and
never runs as whoever is signed in to it.

```bash
php artisan authorization:review holders role:01a1be88-d4d3-72cc-b9bc-620cc97d4906 --tenant=team:7 --application=admin
php artisan authorization:review holders permission:01a1be88-d4e0-7153-8120-e043891fb9d3 --everywhere --direct-only
php artisan authorization:review holdings user:1 --rooted-within=team:7
php artisan authorization:review expiring --everywhere --from=2026-12-01 --until=2027-01-01 --output=expiring.jsonl
php artisan authorization:review granted_by --actor=user:7 --everywhere --output=granted.jsonl --force
php artisan authorization:review unused --since=2026-09-01 --everywhere --output=unused.jsonl
```

| Argument or option  | What it names                                                                                                                                                                                                               | When omitted                                         |
|---------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| `{query}`           | `holders`, `holdings`, `expiring`, `granted_by` or `unused`                                                                                                                                                                 | Required                                             |
| `{reference}`       | For `holders`, the role, permission or policy as `role:{key}`, `permission:{key}` or `policy:{key}`, or its morph type; for `holdings`, the saved subject as `{morph type}:{key}`, resolved by the console subject resolver | Required for those two; refused for the others       |
| `--tenant`          | Review what applies in the tenant, as `{morph type}:{key}`, read as `authorization:why` reads it                                                                                                                            | The platform, when no scope option is given          |
| `--rooted-within`   | Review the grants made in the tenant or below it                                                                                                                                                                            |                                                      |
| `--everywhere`      | Review every stored grant                                                                                                                                                                                                   |                                                      |
| `--application`     | `none`, `any` or the application's name                                                                                                                                                                                     | `none` for a tenant or the platform, `any` otherwise |
| `--from`, `--until` | For `expiring`, the window `[from, until)`, each a date and time, in UTC when it names no zone                                                                                                                              | Required for `expiring`; refused for the others      |
| `--actor`           | For `granted_by`, the actor as `{morph type}:{key}`, matched exactly as stored                                                                                                                                              | Required for `granted_by`; refused for the others    |
| `--since`           | For `unused`, the instant to look back to, a date and time, in UTC when it names no zone                                                                                                                                    | Required for `unused`; refused for the others        |
| `--direct-only`     | For `holders`, the direct grants alone                                                                                                                                                                                      | Every route; refused for the others                  |
| `--output`          | The file to write, which must not exist                                                                                                                                                                                     | The standard output                                  |
| `--force`           | Overwrite the `--output` file when it exists                                                                                                                                                                                | An existing file is refused                          |

At most one of `--tenant`, `--rooted-within` and `--everywhere` may be given. Nothing but the JSON Lines is written to
the standard output, so it can be piped, and nothing is written there until the review's first page is read. The file
is created only when it does not exist, so a file made at the same moment is never overwritten without `--force`. The
exit codes are those of `authorization:why`:

| Code | When                                                                                                                                                                                                                                       |
|------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `0`  | The export was written                                                                                                                                                                                                                     |
| `2`  | An invalid invocation: an unknown option, a missing argument or option value, an option the query does not take, a reference, tenant, window or subject that cannot be read or resolved, or an output file that exists or cannot be opened |
| `1`  | The review failed, such as on a stored role hierarchy cycle: the error names the exception's class alone, and the export has no footer                                                                                                     |

Errors go to the standard error, name the argument or option and never a value given (a subject or tenant that is
malformed, names no model or no saved row, or cannot be resolved is named by its argument or option alone), and are
escaped as `authorization:why` escapes its own.

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
| [Delegated administration](docs/design/delegated-administration.md)                         | The actions, the acting context and the administration stage  |
| [Events](docs/design/events.md)                                                             | The marker, the snapshots, the operation and after-commit     |
| [Gate authority](docs/design/gate-authority.md)                                             | The `Gate::before` hook, the switch and policy classes        |
| [Query scoping](docs/design/query-scoping.md)                                               | `whereAuthorized()`, what it compiles and what it refuses     |
| [Bulk checks](docs/design/bulk-checks.md)                                                   | `checkMany()`, what it reads once and in bulk, and its events |
| [Effective permissions](docs/design/effective-permissions.md)                               | `permissionsFor()`, its scope, exactness and introspection    |
| [Preview](docs/design/preview.md)                                                           | `previewFor()`, its admission, recording and what it refuses  |
| [Grant scope](docs/design/grant-scope.md)                                                   | The identity directory, the scope query and the grant hooks   |
| [Explanations](docs/design/explanations.md)                                                 | Explain mode, the `Explanation` and `authorization:why`       |
| [Access reviews](docs/design/access-reviews.md)                                             | Grant routes, queries, rows, admission, paging and exports    |

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
