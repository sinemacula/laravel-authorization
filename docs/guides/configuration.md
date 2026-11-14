# Configuration

Publishing and migrating, where the tables live, binding the package's seams, declaring permissions, and every setting
with the checks it is held to.

Publish the config and the migrations, then migrate:

```bash
php artisan vendor:publish --tag=authorization-config
php artisan vendor:publish --tag=authorization-migrations
php artisan migrate
```

The tables live on the application's default connection. To keep them on another, such as the one your identity
tables use, set `AUTHORIZATION_DB_CONNECTION` (or `connection` in `config/authorization.php`) before migrating: the
migrations create the tables there, and the models read and write there.

To keep the package's tables apart from your own, set a prefix before migrating, with `AUTHORIZATION_TABLE_PREFIX` (or
`tables.prefix`): `app_` makes `roles` `app_roles`, and so on for every table. The prefix is put before every table name
left at its default, and before no name you set yourself (`AUTHORIZATION_TABLE_ROLES` and the like, or the `tables`
block), which is used as you write it. Whether you set a name is told by its value alone, since a merged or cached
configuration no longer says where a value came from: a name that differs from the table's own is yours, while one set
to the table's own name, `roles` for the `roles` table, is the default and takes the prefix. Every table's own name is
its key's but the break-glass table's: `tables.break_glass` is `break_glass_activations` by default. The migrations
create the tables under the names the prefix makes, and the models, the services and `Config\TableNames::get()` read
them there, so changing the prefix after migrating points the package at tables that do not exist.

Every check that does not name its subject is about the subject the subject resolver returns. The shipped resolver,
`AuthGuardSubjectResolver`, returns the user Laravel authenticated on its default guard, with no tenant and the guard's
name as the application, so `Authorization::can()`, the package's middleware and the Blade directives decide about the
signed-in user with no setup. A request with no user has no subject, and its checks are denied. Laravel's Gate hands its
user to the same resolver, so `@can`, `can:` and `Gate::forUser($user)` decide about the subject the resolver translates
that user into, and a guest is denied (see [Laravel's Gate](checking-access.md#laravels-gate)).

An application with principals or tenants binds its own resolver, a class implementing
`SineMacula\Laravel\Authorization\Contracts\SubjectResolver`, in `config/authorization.php`. The active tenant comes
only from it: without a tenant, only platform-wide roles and permissions are visible.

```php
'subject_resolver' => App\Authorization\CurrentSubject::class,
```

A resolver can say more about the subject than who and where. `scopes` says what the credential the subject acts with,
such as an API token, carries, for the session policy source to cap its checks with (see [Session caps and
machines](caps.md#session-caps-and-machines)): `CredentialScopes::uncapped()` when the credential carries no cap, and
`CredentialScopes::of([...])` with the scopes it carries, where `of([])` carries none granted and allows nothing. Left
null, the subject says nothing about them, which is not the same as no cap: the source then establishes the scopes of
the credential the subject names, and fails closed when it cannot. `platform` marks a subject acting on the platform, as
a queued job or a console command acting for no tenant does: it names no tenant, and `for()` of it decides on the
platform whatever tenant is in place (see [The programmatic API](checking-access.md#the-programmatic-api)). Marking the
request's subject moves neither `forUser()` nor a model named through `for()` out of the scope in place. The shipped
resolver sets neither.

Every seam the package gives a default for can also be bound directly on its contract, from any service provider: the
subject resolver, the tenant tree, the identity directory, the grant hook, the console subject resolver, the resource
tenant resolver, the policy store, the policy resolver, the action catalogue, the context key catalogue, the
authentication requirement checker, the session policy source, the grant usage store and the authentication, request and
environment contexts. The package binds its default only when nothing is bound to the contract yet, so a binding made
before it registers, by a sibling package or by your application, `instance()` included, stands, and a binding made
afterwards with `bind()`, `singleton()`, `scoped()` or `instance()` replaces the default. A class you name in
`config/authorization.php` is different: when `subject_resolver`, `tenant_tree`, `identity_directory`,
`resource_tenant_resolver`, `requirement_checker` or `session.source` names a class other than the package's default, or
when `policy_store` names any class, the package binds the contract to it even over a binding a sibling package made
before it registered, since your configuration is the explicit choice. The same holds for a sibling package's deferred
provider, which would otherwise bind the contract at its first resolution and so replace your class: the package loads
that provider before binding your class. A value equal to the package's default, or no value, binds nothing over an
earlier binding, and nor does a value that names no class implementing the contract (null, a number or an empty string
among them): the package binds its default as though nothing were configured, so registering never fails on it, and the
boot refuses the setting. `policy_store` differs on both counts: the package has no store of its own, so such a value
binds nothing at all, and null is not refused, since it means no store. From the highest precedence down, a contract
resolves to a binding made after the package registers, then the class your configuration names, then a binding made
before the package registers, then the package's default. Binding your configured class over a contract follows
Laravel's rules for any binding: an extender a sibling package registered on the contract is applied to your class, so
one typed to the sibling's own class fails, and when the contract was already resolved, a callback watching it with
`rebinding()` or `refresh()` is called, which may resolve your class as the application boots. The grant hook is the one
exception: hooks only refuse, so when `grant_hooks` lists any, the package extends the contract and the listed hooks run
before whatever hook it resolves to, rather than replacing it (see [Grant hooks](administration.md#grant-hooks)). The
order your providers register in therefore never lets the package's default replace a binding of yours. It still decides
between other bindings of the same contract: of two bindings made outside the package, by a sibling package and your
application for example, the later one wins as usual, and a `bindIf()`, `singletonIf()` or `scopedIf()` only fills a
contract nothing has bound yet, so one made after the package registers is skipped and the package's default, or your
configured class, stands. To replace a seam whatever order providers register in, bind it unconditionally. A binding of
your own is kept as you bound it across the reset between queue jobs and Octane requests, while the package's defaults
and configured classes, the context key catalogue aside, are built afresh for each.

**When the configured classes are bound.** The package's `register()` records what your configuration names, as names
alone: it loads no class, loads no deferred provider, binds no configured class over another binding and extends no
contract. All of that runs as the application boots, in a `booting()` callback, after every provider has registered and
before any boots, so a deferred provider the application learns of only after the package registers is loaded as one it
knew of before, and the precedence above holds whatever order providers register in. Until then, each contract a
configured class will be bound to resolves to a binding made before the package registered, or else to the package's
default, and the policy store, which has no default, stays unbound unless something bound it, so a provider that
resolves a seam in its own `register()` gets that binding, the package's default or nothing, rather than your class;
resolve seams in `boot()`, or later, as Laravel advises. When the application boots for `authorization:check` on a
refused configuration, none of this runs (see [The diagnostic boot](console.md#the-diagnostic-boot)), and the policy
store your configuration names is never bound.

**When the package decides.** Resolving a seam is not deciding. In an application where this package's provider
registered, every operation the package offers (each listed under [The diagnostic boot](console.md#the-diagnostic-boot))
refuses until the provider's own `boot()` has validated the configuration, even a valid one. A provider that boots
before it, or an application `booting()` callback, therefore cannot make an authorization decision in its own `boot()`:
defer that work with `$app->booted(...)`, or to a later point such as a request or a command. What the container builds
for those operations, such as the manager or the resolved tenant, can still be built before then; only its operations
refuse.

A sibling package that registers after this one and wants to replace only the package's default, never a binding the
application made, asks `AuthorizationServiceProvider::isPackageDefault($app, $contract)`, and so may a check that runs
once the application has booted. It is true exactly when `authorization:check` shows the seam as the package's default,
as it reads what the package recorded when it bound the seam: before the default is resolved and after, whether an
instance of it is held or not. A class your configuration names answers false from the moment the package registers, and
still does after a refused boot (see [The diagnostic boot](console.md#the-diagnostic-boot)) has left it unbound and the
default resolves in its place. An instance you hand the container, a sibling's declared adapter, any other binding made
before the package registered or after, an alias, a deferred provider and an unbound contract all answer false. It
builds nothing. The context key catalogue is the one default the container holds once resolved, so an instance handed
over it after that cannot be told from the default, and answers true, as the report shows it.

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
[Delegated administration](administration.md#delegated-administration), `authorization:guardrail.manage` among them (see
[Guardrails](caps.md#guardrails)), which a policy may always name.

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

Roles, permissions, policies, boundaries and guardrails are read through a resolution cache, kept in memory for the
request or job and, when `cache.store` names a cache store, in that store too. Its entries are versioned, so every
write takes effect on the next check in every worker, and a store that fails is skipped while checks read the database.

To add columns or behaviour to the `Role`, `Permission` or `Policy` model, name a subclass of it under `models` (see
[Model extension](../design/model-extension.md)).

`config/authorization.php` documents every other option: models, tables, the default guard, permission providers, the
Gate switch, the policy store, the policy limits, the query scoping limits, the context keys and sources, the attribute
providers, the subject resolver, the tenant tree, the identity directory, application access, the resource tenant
resolver, the authentication requirement checker, the session policy source and the scope map, the cache, the bulk
checks' chunk size, the role hierarchy and rank, the delegated administration limits, the access reviews' limit, grant
usage tracking (see [Usage tracking](access-reviews.md#usage-tracking)), break-glass, which decisions
`DecisionEvaluated` reports (see [Which decisions are reported](events.md#which-decisions-are-reported)) and the grant
hooks.

## Configuration checks

Every setting is checked when the application boots, and a malformed one stops the boot with an
`InvalidAuthorizationConfigException` naming the setting, rather than being read as something else. The one exception
is a boot for `authorization:check`, which reports every issue while the package refuses every operation instead (see
[The diagnostic boot](console.md#the-diagnostic-boot)):

- A key the package does not define is refused, at the top level and in every block whose keys the package defines
  (`models`, `tables`, `defaults`, `gate`, `policies` and `policies.limits`, `context`, `attributes`, `session`,
  `cache`, `hierarchy`, `rank`, `query_scoping`, `bulk`, `administration`, `reviews`, `usage`, `break_glass`, each
  role's settings under `break_glass.roles`, `events` and `events.decisions`), naming its full path, such as
  `authorization.models.rol`, so a misspelt key never leaves its default in place. The maps you fill in
  (`context.keys`, `context.sources`, the attribute providers, `session.scopes`, `application_access` and
  `break_glass.roles`) take keys of your own; each entry is checked against its own shape instead, and a break-glass
  role's key must be a valid role name.
- A setting left out takes its default, also when the configuration was cached without the package's defaults merged
  into it. A setting set to null is refused, a block set to null among them, except where null means the default or
  none: `connection`, `policy_store`, `cache.store`, `usage.connection`, `usage.queue`, a break-glass role's
  `max_minutes` and `log_channel`. The whole `authorization` configuration must be an array.
- A value read from the environment is checked as it is written, since the config file casts none of them. A whole
  number is an int, or a string written as one in base 10 (`300`, not `300s`, `3e2`, `300.0`, `-0`, one with a space
  around it or an empty value) and no larger than PHP holds. A switch (`gate.enabled`, `hierarchy.enabled`,
  `rank.enabled`, `usage.enabled`, `break_glass.enabled`, `break_glass.notes` and the three switches of
  `events.decisions`) is true or false, which the environment gives for `true`, `false`, `(true)` and `(false)`; `0`,
  `1`, `off` and `no` are refused.
- Each table name is a plain identifier (a letter or an underscore, then letters, digits and underscores) with no
  schema before it, short enough that every index and key name the migrations build from it fits in 63 characters,
  PostgreSQL's limit (from 33 to 51 characters, depending on the table), and the fourteen names are distinct.
- `tables.prefix` is empty, or a lower-case letter, then lower-case letters, digits and underscores, of at most 16
  characters; null is refused. Each name it makes is checked as a name you set is: within its table's bound, which the
  longest prefix allowed keeps every default within, and distinct from the others, so a name you set that the prefix
  gives another table is refused as a duplicate. A prefix that pushed a default past its bound would be refused under
  `authorization.tables.prefix`.
- `defaults.guard` names a guard in `auth.guards`, `log_channel` a channel in `logging.channels`, and
  `usage.connection`, when set, a connection in `queue.connections`. `connection` names a connection in
  `database.connections`, or, when it is null or empty, `database.default` must. Each is read from the configuration as
  it stands when the application boots, and nothing is connected to.
- `cache.prefix` is a string that is not empty, and `cache.ttl` a whole number of seconds of at least 1.
- `hierarchy.enabled` and `rank.enabled` are switches, checked as `gate.enabled` is.

A setting the package reads after boot is read through the same checks, so one changed at run time (by `config()->set()`
in a test, a queue worker or an Octane request) is refused with the same exception when it is read, never read as its
default, cast or skipped. That covers the policy limits, the query scoping limits, the bulk chunk size, the
administration limits, the access reviews' limit, usage tracking, the break-glass settings (through
`Config\BreakGlassConfigValidator::read()`), `cache.ttl` and `cache.prefix`, the three switches, the permission enums
and providers, `application_access` (an entry for an application that is not a permission name, null among it, is
refused rather than opening the application), `session.scopes`, `context.keys` and `context.sources`, the attribute
providers, `grant_hooks` and `events.decisions`, whose sensitive actions are checked after boot for their type only. A
block on the way to a setting that is not an array is refused too, rather than read as one that leaves the setting out.
A setting read on every check is read with a few array lookups and plain comparisons, so the checks add next to nothing
to a request.

The names are checked after boot for their type only. A table name, a model class or `defaults.guard` that is not a
string, or is empty, is refused with the same exception, and so is a `tables.prefix` that is not a string, a
`connection` or `cache.store` that is neither null nor a string, or a `cache.store` that is empty (null, and for
`connection` an empty string, mean the default). Whether the name exists is checked only at boot, so one changed after
boot to a name that does not exist is used as it is, never swapped for the default: a table fails with the database's
own error and a model class with PHP's when they are used, a connection or a cache store with Laravel's own
`InvalidArgumentException` from the database or cache manager, and a lookup by name under a guard that does not exist
finds only the roles and permissions that name no guard. The log channel is checked at boot only, by design: a warning
is written from inside error handling, and writing one never stops a check, so a channel changed after boot to one that
does not exist is written to as the default channel.

A suite package that reads these names reads them the way the package does, through `Config\TableNames::get('roles')`,
`Config\ModelClasses::get('role')` and `Config\DefaultGuard::get()`, each taking an optional configuration repository.
A name the configuration leaves out is the package's own; one that is not a non-empty string is refused as above. A
table's name is the one the package reads, with `tables.prefix` before it when it is left at its default
(`Config\TableNames::prefix()` reads the prefix alone). An installer checks a prefix before writing it with
`Config\TableNames::isValidPrefix($prefix)`, which applies the rule above. The three are part of the package's stable
API.

`authorization:check` lists every issue at once rather than stopping at the first: those the boot found, when the
application booted for it, and otherwise those these checks find again on the configuration as it stands, except the
checks that build what they check (see [Checking the configuration](console.md#checking-the-configuration)).
