# Console commands

The package's Artisan commands: granting, revoking and listing, pruning, the Spatie import, explaining a check,
exporting an access review and checking the configuration.

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

`authorization:check` reports the configuration the application runs with (see
[Checking the configuration](#checking-the-configuration)).

Each command's class names its command in a public `NAME` constant, the name its signature declares, so a schedule, a
test or a sibling package can refer to it without repeating the string: `PruneGrantsCommand::NAME` is
`authorization:prune`, and so on for `CheckConfigurationCommand`, `GrantRoleCommand`, `RevokeRoleCommand`,
`ListRolesCommand`, `ListPermissionsCommand`, `SyncPermissionsCommand`, `MigrateSpatieCommand`,
`ValidatePolicyCommand`, `WhyCommand` and `ReviewCommand`, all in `SineMacula\Laravel\Authorization\Console`.

The listing commands are administrative views: they list every role or permission, platform-wide and tenant-owned alike,
and show each one's owner. `grant` and `revoke` write through the grant service and look the role up within the tenant
scope, so without a resolved tenant they find platform-wide roles only. A role the identity already holds with no
expiry, or does not hold, is reported as such and nothing is written. `grant` gives no expiry, so a role the identity
holds on a temporary or expired grant is made permanent and reported as granted. `grant`, `revoke` and
`authorization:sync` take `--actor={morph type}:{key}` to name who made the change; it must name a row that exists, and
without it the change is trusted work that records no actor. For `authorization:grant` and `authorization:revoke` the
actor makes the change as delegated administration, decided as that actor, with no session (see [Delegated
administration](administration.md#delegated-administration)), so a role grant passes only when the actor outranks the
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
than making checks correct. It never removes a break-glass activation: one that expired without ending has its expiry
recorded on its row and is reported as `Identity\BreakGlassExpired`, counted apart. Like `model:prune`, it takes
`--pretend`, which counts exactly what a run would remove or record, the boundaries apart from the grants as a run does,
and `--chunk`, and is scheduled like any command:

```php
use SineMacula\Laravel\Authorization\Console\PruneGrantsCommand;

Schedule::command(PruneGrantsCommand::NAME)->daily();
```

`authorization:usage-heartbeat` extends the coverage of [usage tracking](access-reviews.md#usage-tracking) to now, so a
quiet site stays covered, and records nothing while tracking is off; `authorization:usage-prune` removes the usage of
grants that no longer exist and coverage older than `authorization.usage.retention` days, and takes `--pretend`.

`authorization:migrate-spatie` copies roles, permissions and grants from `spatie/laravel-permission` through the
management services, its `guard_name` becoming `guard`. It reports and skips any role or permission whose name the
package refuses, and any permission whose name contains `*`, along with its grants. The aliases kept for a port are
listed in [Spatie compatibility](../design/spatie-compatibility.md).

## Checking the configuration

`authorization:check` reports the configuration the application runs with, and every issue the boot's checks find in
it, all at once. Run from the console, the application boots for it even when the configuration is refused, while
every operation of the package refuses (see [The diagnostic boot](#the-diagnostic-boot)):

```bash
php artisan authorization:check
php artisan authorization:check --format=json
```

It reports:

- **Issues**: every setting the checks refuse, listed all at once rather than stopping at the first, each unknown key
  on its own, a check skipped because a setting it depends on was refused, and a part of the report that could not be
  read. Each is structured: the setting's path, a stable code (`unknown_key`, `invalid_type`, `out_of_range`,
  `unknown_class`, `not_implemented`, `unknown_name`, `duplicate`, `required`, `invalid_value`, `invalid_catalogue`,
  `skipped` or `internal`), what the setting expects, written by the package, and the type of the value found, never
  the value or an exception's message. On an application booted for the command, these are what the boot found; on
  one that booted otherwise, the boot's checks passed, so the command runs them again, and an issue shows the
  configuration changed since, such as by `config()->set()`.
- **Settings**: every setting the package defines, and any unknown key set, with its status: `ok`, `refused`, `skipped`
  or `unchecked`, or, for a setting whose check builds what it names (the context sources, the attribute providers, the
  session scopes, the sensitive actions and the cache store), what became of that check as the application booted:
  `checked_at_boot` when it ran and passed, `failed_at_boot` when it ran and failed, and `not_run` when the boot did not
  run it, as another check had already refused the configuration. Such a check is never run again by the command. A
  value is shown only for settings whose values are safe to show: class names, table names, switches, whole numbers,
  guard, connection, store, queue, channel, permission and action names, and the decision events' `allows`. Any other
  value, and every value under an unknown key, is shown by its type alone (`string`, `array(3)`). Whether a set value
  came from the file or the environment is not known once the configuration is merged or cached, so it is `unknown`, and
  `default` for a setting left out.
- **Tables**: the prefix of the tables' default names, and the name each table takes, the one the package reads and
  the migrations create: the name you set, as written, or the table's own with the prefix before it, and whether you
  set it. A prefix or name that is refused, and a default name while the prefix is refused, is not shown.
- **Seams**: for each contract the package binds or reads, where its binding came from (`package_default`, `configured`,
  `earlier_binding`, `later_binding`, `declared`, `deferred`, `deferred_loaded`, `alias`, `external_binding` or
  `unbound`), the class it builds when that is known without building it, how long what it builds lives (of the key a
  forwarding binding resolves, not of the forwarder, and of a class's own binding when a binding names the class), the
  extenders still registered on it, in order (the configured grant hooks as `authorization.grant_hooks`, any other by
  its file and line), and whether it was resolved before. An instance the container holds is what the contract resolves
  to, so an instance handed over any binding is shown by its class, as the binding that supplies the contract. A grant
  hook held as an instance before the package registered, which the configured grant hooks wrap as the application
  boots, is still the earlier binding, shown by the hook it wraps, with the configured hooks listed as
  `authorization.grant_hooks (applied to the held instance)`. One a provider bound after the package registered, which
  the configured hooks wrap as the application boots too, is a later binding, shown by its own class and decorated by
  the configured hooks, listed the same way. A deferred provider the application knew of as the package registered,
  which the package then left the contract to, is `deferred_loaded` once it has loaded. A seam bound to a closure whose
  class is decided when it is first resolved is shown by the closure's file and line, `supplied by custom code`; that is
  a note, and never fails the check. A seam whose class the configuration names is `configured` from the moment the
  package registers, shown by the default the contract resolves to until the boot binds the class, and still when a
  refused boot never binds it. An optional contract nothing binds, such as `PolicyStore` or `ScopeRegistry`, is
  `unbound`.
- **Grant hooks**: the hooks in the order they run: those `authorization.grant_hooks` lists, by class, then the hook
  bound to the contract. The chain stops at the first refusal.
- **Connection**: the database connection's name, whether `authorization.connection` or `database.default` chose it,
  and its driver; the cache store's name and driver; the usage queue's connection, driver and queue. Nothing else of
  a connection's configuration is read, so no host, user, password or URL is shown, and each name and driver is shown
  by the rules the settings are: one that is not made of the characters names are, such as a queue's URL, is shown
  as `value not shown`, and listed under `redacted` in the JSON.
- **Integrations**: whether the Gate hook is enabled, the Blade directives, the query macros and the route middleware
  aliases are registered.

Building the report builds no seam, store, catalogue or provider, resolves nothing that was not resolved before,
connects to nothing and runs no query, so it is safe before the migrations have run, and the connection shows
`connectivity: not_tested`.

**The text.** The default format prints one line per issue first, then a section each for the settings, the tables, the
seams, the grant hooks, the connection and the integrations, each line `[subject] state`, and a last line, `Every check
passed.`, `A check failed.` or `The check could not be completed.`:

```text
[setting authorization.models.rol] unknown key; expected one of role, permission, policy

Settings
[setting authorization.models.role] ok; SineMacula\Laravel\Authorization\Models\Role
[setting authorization.cache.prefix] ok; value not shown (string)
[setting authorization.models.rol] refused; unknown key; value not shown (string)

Tables
[table prefix] app_
[table roles] app_roles; the default, with the prefix
[table permissions] identity_permissions; set explicitly, so used as written

Seams
[seam SubjectResolver] package default; SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver; scoped
[seam TenantTree] bound after the package registered, over its binding; supplied by custom code (app/T.php:9); ...
[seam PolicyStore] not bound; none

Grant hooks, in the order they run; the chain stops at the first refusal
[grant hook 1] App\Authorization\AuditGrants; listed in authorization.grant_hooks
[grant hook 2] SineMacula\Laravel\Authorization\Hooks\GrantHooks; bound to the contract, package default; ...

Connection
[connection database] mysql; chosen by database.default; driver mysql; not connected to
[connection cache] none (entries are kept for the request or job alone)
[connection queue] redis; chosen by queue.default; driver redis; queue the default

Integrations
[integration gate] enabled (the package answers every ability it declares through Gate::before)
[integration blade_directives] registered

A check failed.
```

(Lines are shortened here, `...` standing for what a line goes on to say; the report lists every setting, table, seam
and integration.) Every name is printed with its console markup and control characters escaped.

**The JSON.** `--format=json` prints the report's versioned JSON alone on the standard output, with no prose or
styling. Its keys are stable; version 1 is:

```json
{
    "version": 1,
    "status": "passed | refused | incomplete",
    "settings": [
        {"path": "authorization.models.role", "known": true, "set": true, "value": "...", "redacted": false,
         "type": "string", "source": "default | unknown",
         "status": "ok | refused | skipped | unchecked | checked_at_boot | failed_at_boot | not_run"}
    ],
    "tables": {
        "prefix": "... | null",
        "names": [{"key": "roles", "name": "... | null", "explicit": false}]
    },
    "seams": [
        {"contract": "...", "origin": "package_default", "class": "... | null", "classes": ["..."],
         "decides": "... | null", "factory": "file:line | null",
         "lifetime": "transient | singleton | scoped | instance | null",
         "extenders": ["authorization.grant_hooks", "file:line"], "config_key": "... | null", "alias": "... | null",
         "deferred_provider": "... | null", "deferred_provider_at_registration": "... | null",
         "previously_resolved": false,
         "declaration": {"owner": "...", "classes": ["..."], "decides": "... | null", "lifetime": "scoped",
                         "state": "standing | instance_over_it | overridden | unverified"}}
    ],
    "grant_hooks": [
        {"position": 1, "source": "configured | bound", "class": "... | null", "type": "... | null",
         "origin": "... | null", "factory": "file:line | null", "runs": true}
    ],
    "connection": {
        "database": {"name": "... | null", "chosen": "configured | default", "driver": "... | null",
                     "connectivity": "not_tested", "redacted": ["name", "driver"]},
        "cache": {"store": "... | null", "chosen": "configured | none", "driver": "... | null", "redacted": []},
        "queue": {"connection": "... | null", "chosen": "configured | default", "driver": "... | null",
                  "queue": "... | null", "redacted": ["queue"]}
    },
    "integrations": [
        {"name": "gate | blade_directives | query_macro | grammar_macro | middleware.{alias}",
         "state": "...", "detail": "... | null"}
    ],
    "issues": [
        {"path": "authorization.models.rol", "code": "unknown_key", "kind": "refusal | skipped | internal",
         "expected": "... | null", "got_type": "... | null", "depends_on": "... | null", "exception": "class | null"}
    ]
}
```

`value` is null when it is not shown, and `redacted` is then true for a setting that is set; a setting mapping names
to classes or permissions shows its `value` as an object, empty or not. `previously_resolved` is true only when the
contract was resolved: an instance handed to the container and never resolved was not. `deferred_provider` is the
deferred provider not loaded yet, and `deferred_provider_at_registration` the one the application knew of as the
package registered, loaded since or not. `declaration` is null when no sibling package declared the seam; its `state`
is `instance_over_it` while the declared closure is bound but an instance handed to the container supplies the
contract. Each part of `connection` is null when the connection could not be read, and `redacted` lists the fields
of a part withheld as they are not names. `tables.prefix` is empty when no prefix is set, and null, as is a table's
`name`, when it is not shown; `explicit` is true for a name set to something other than the table's own. `exception`
names the class alone of what a check that could not be
completed threw.

**Exit codes.**

| Code | When                                                                                          |
|------|-----------------------------------------------------------------------------------------------|
| `0`  | Every check passed; a seam supplied by custom code never changes it                           |
| `1`  | A setting is refused, whether or not the report is also incomplete                            |
| `2`  | An invalid invocation: an unknown option, or a `--format` other than `text` or `json`         |
| `3`  | The report could not be completed (a check or a part of it failed), and no setting is refused |

The command catches what fails inside it, ending with `1` for a refused configuration or `3` for anything else and
naming the exception's class alone on the standard error, so a command calling it in-process, through
`Artisan::call()` or the console kernel's `call()`, gets its exit code and its text on the output it gives, never a
throw. It cannot catch what fails before it runs: the console kernel's own bootstrap, a deferred provider the kernel
loads before the command runs, and an application booted without the diagnostic boot on, whose refused configuration
stops the boot as it always has.

**For suite packages.** A package that binds its own adapter to one of the package's contracts can declare it, so the
report names the adapter and its owner rather than custom code. It declares in its `register()`, after binding the
contract, through `Diagnostics\Declarations`, a container instance each application holds its own of:

```php
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;

$this->app->scoped('acme.tenants', AcmeTenantTree::class);

$binding = static fn (Application $app): TenantTree => $app->make('acme.tenants');

$this->app->bind(TenantTree::class, $binding);

Declarations::of($this->app)->adapter(
    TenantTree::class,
    'acme/tenants',
    AcmeTenantTree::class,
    Lifetime::SCOPED,
    $binding,
);
```

A binding that decides among several classes as it is resolved declares them with `factory()`, naming the classes it
may build and when it decides (`'per tenant, at first use'`); the report shows the set, never one class. Naming the
closure bound lets the report tell the declared adapter, still bound, from a binding made later over it, which it
shows as `declared by acme/tenants as ..., but overridden later`, and from an instance handed to the container over
it, `but an instance is bound over it`; a declaration naming no closure is shown beside whatever is bound as
unverified. A declaration is data alone: nothing is loaded or built to read it.

**Resetting between units of work.** Everything the package keeps for one request or job is bound with `scoped()`, so
the queue worker and Octane forget it with the rest of the scoped state. A long-running command doing several units of
work in one process, which must not forget what Laravel or another package keeps scoped (the command's context, the
callbacks deferred with `defer()`), calls `Support\RequestState::forget($app)` between them instead. It forgets exactly
the scoped instances held under the package's own names (its class names, `authorization` and the `authorization.`
keys), whatever the package binds now or later, so the caller keeps no list of its own; the package's state after boot
is kept. `RequestState::abstracts($app)` lists what it would forget. Both are part of the package's stable API.

## The diagnostic boot

A refused configuration stops the boot, so on its own every command would fail before `authorization:check` could say
what is wrong. The application therefore boots the package for diagnosis while the process runs a check command: a
broken configuration no longer stops the boot, and the package refuses every operation instead.

**When it is on.** The diagnostic boot is decided as the application boots, after every provider has registered and
before any boots, and it is on only when:

- the process runs in the console and the command its arguments name is `authorization:check`, or a command a sibling
  package declared as running it in the same process. The arguments are read as the console reads them: Symfony's
  global options and Laravel's `--env` (`--env=staging` or `--env staging`) may come before the command, and `--`
  ends the options. A valid option given before the command's name, with its value after `=`, still runs the
  diagnostic boot, as the console reads past it to the name: the command's own option, as in
  `php artisan --format=json authorization:check`, or a global option your application adds as the console starts.
  `--help` or `--version` anywhere before `--`, any other option the console's global options do not define, such as
  one given its value apart (`--format json`), or a value given to an option that takes none means no command runs as
  named, and an abbreviated name is never matched, so none of them turns it on;
- or the explicit switch is on (see below).

A flag a sibling package sets once its own check is running, after the application has booted, comes too late to
count. Everywhere else, in a web request, a queue worker or any other command, the boot validates the configuration as
it always has and throws the first refusal.

**Declaring a composing command.** A suite package whose own command runs `authorization:check` in the same process,
through `Artisan::call()` or the console kernel's `call()`, declares that command in its `register()`, so the
application boots for diagnosis when the process runs it:

```php
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;

public function register(): void
{
    Declarations::of($this->app)->composingCommand('acme:doctor');
}
```

The declaration is data alone, and counts whether the sibling registers before this package or after it, as long as
its provider is eager. A deferred provider registers only when it is first needed, which is after the boot has decided,
so a declaration it makes then comes too late.

**The switch, for cold callers.** Code that creates and boots an application itself, then calls the check through the
console kernel's `call()`, such as a deployment script or a test, turns the switch on before the application boots:

```php
use Illuminate\Contracts\Console\Kernel;
use SineMacula\Laravel\Authorization\Diagnostics\DiagnosticMode;

DiagnosticMode::enable($app);

$code = $app->make(Kernel::class)->call('authorization:check');
```

The kernel's `call()` bootstraps the application before it runs the command, so the command cannot catch what that
bootstrap throws; without the switch, a refused configuration fails there. The switch is held in the application's
container, never statically or in the environment, so it reaches that application alone.

**What the boot does.** The configuration's structural checks run first, collecting every issue. When they find any, the
package refuses every operation and runs none of the registration work it leaves to the boot: no configured class is
loaded or bound, no deferred provider is loaded for it, and the grant hooks do not extend the contract. Otherwise that
work runs as on any boot, then the checks that build what the configuration names (the authentication context and the
context sources, the attribute providers, the session scopes' catalogue, the sensitive actions, read against the action
catalogue, and the cache store), each recording whether it passed, failed or did not run. The configured permission
providers may run there, as the session scopes and the sensitive actions are checked against the actions they declare
while the configuration is validated, never as the report is written, which shows what the boot recorded. The package is
healthy, and boots exactly as it otherwise would, only when every check passed; any issue, including a check that failed
in a way the package did not foresee, refuses.

In the refusing state the package registers `authorization:check` alone among its commands (none that writes grants or
syncs), does not install its Gate hook and does not wire usage tracking. The Blade directives, the query macros and
the route middleware aliases stay registered, so a compiled view, a query builder or a route reaches a refusal rather
than literal text, a missing macro or an unknown middleware. `authorization:check` reports what the boot found, exits
`1` for a refused configuration and `3` for one that could not be checked completely, the refusal winning.

**What refuses.** Each of these throws `InvalidAuthorizationConfigException` naming the first refusal, by its path and
code, never the value configured (or, with no refusal, a fixed reason under the `internal` code), before it resolves a
seam, reads a cache or returns early:

- every decision, listing, explanation and preview of `AuthorizationManager` and the `Authorization` facade, `any()`,
  `all()` and `authorize()` among them, a manager obtained before the boot decided included, and every scoped manager,
  `for()`, `forUser()`, `withPolicies()`, `capped()` and `previewFor()` among them;
- the `role`, `permission` and `authorize` middleware, the Blade helpers and directives, `whereAuthorized()` and
  `AuthorizedScope`;
- the model traits' decisions: `hasPermission()`, `getPermissions()`, `hasRole()` and the other role and permission
  checks, `canActOn()` and the rank comparisons;
- `TenantScope`'s `apply()`, `within()` and tenant getters, and the `ResolvedTenant` factory;
- `ApplicationAccess::mayUse()`, on every path, and `GrantScopeQuery`'s `forIdentity()`, `hasGrantIn()`,
  `granteesReaching()` and `granteesWithin()`;
- the management services: grants, revocations, roles, permissions, policies, resource policies, boundaries and
  guardrails;
- the access reviews' public methods and the grant pruner;
- the grant usage recorder and the package's usage store, when the container builds them;
- `PermissionCatalogue::definitions()`, which runs the permission providers, and `PermissionCatalogue::declared()` and
  the package's `ActionCatalogue`, which run them too, so setting a `Policy` model's document refuses rather than run
  them.

What the container builds for these operations (the manager, the `ResolvedTenant`, the grant usage recorder and
store), and what the boot's own checks build and read (the context sources, the declared permissions and the action
catalogue), refuse as they are built only in the refusing state. While the package is pending, as it is until its
configuration has been validated, they are built, so a context source handed one of them as the boot validates it
still boots healthy, and only the operations refuse.

**What does not.** The guarantee covers what the package itself runs:

- **The application's own Gate rules.** The package's abilities are denied by default, since nothing defines them and
  no hook answers them, but a `Gate::before` the application registered that answers, or its own `Gate::define` of
  the same ability, stays the application's decision, and the package does not intercept it.
- **Raw relations and models.** Eloquent relations such as `roles()` and `permissions()`, and the package's models
  queried directly, read rows rather than decide, and are outside the boundary.
- **Code the package does not run.** The console kernel loads every deferred provider left once it bootstraps, and the
  application's `booting()` callbacks and sibling providers run their own code, whatever the configuration; a usage
  store held by outside code is outside the boundary too.

**Outside the diagnostic boot.** Boot refuses as before: the first refusal is thrown and the application does not boot.
Should that application go on to serve another request or command anyway, as a long-lived worker might, since Laravel
marks the providers booted before it boots them, every operation in the list above refuses rather than run on a
configuration that was never validated. The same holds on a valid configuration until the package's provider has booted:
a provider that boots before it, or an application `booting()` callback, gets a refusal from any operation in the list,
and defers such work with `$app->booted(...)` (see [When the package decides](configuration.md#configuration)). An
application whose provider never registered the package, as when a test builds the package's classes directly, refuses
nothing.

## Explaining a check from the console

`authorization:why` prints the explanation of a check about a saved subject (AUTHZ-11.5), the `Explanation` that
`explain()` returns (see [Explanations](preview-and-explanations.md#explanations)):

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

| Argument or option | What it names                                                                                   | When omitted                                                |
|--------------------|-------------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| `{subject}`        | The saved subject, as `{morph type}:{key}`, resolved by the console subject resolver            | Required                                                    |
| `{action}`         | The action, passed to the check unchanged                                                       | Required                                                    |
| `{resource}`       | `{morph type}:{key}`, that record; `{morph type}:*`, the type alone; anything else, as given    | A check without a resource, never every resource            |
| `--tenant`         | The tenant, as `{morph type}:{key}`                                                             | The platform, never the tenant in place                     |
| `--application`    | The application                                                                                 | No application: only the grants for every application count |
| `--context`        | A JSON object, read as the `input` namespace alone                                              | No input                                                    |
| `--format`         | `text`, the preamble and `toText()`, or `json`, the versioned JSON alone, with no prose or ANSI | `text`                                                      |
| `--opaque`         | The resource is an opaque identifier, used as given, even when it holds a colon                 | A resource with a colon names a record or a type            |

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
decision, and its `DecisionEvaluated` is dispatched when `events.decisions` reports it, as for any explained check.

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
(see [Preview](preview-and-explanations.md#preview)).

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

## Exporting an access review from the console

`authorization:review` exports an access review (see [Access reviews](access-reviews.md#access-reviews)) as JSON Lines,
as trusted system work through `AccessReview::trustedExport()`: the console is a trusted operator surface, so it admits
no caller, and never runs as whoever is signed in to it.

```bash
php artisan authorization:review holders role:01a1be88-d4d3-72cc-b9bc-620cc97d4906 --tenant=team:7 --application=admin
php artisan authorization:review holders permission:01a1be88-d4e0-7153-8120-e043891fb9d3 --everywhere --direct-only
php artisan authorization:review holdings user:1 --rooted-within=team:7
php artisan authorization:review holdings user:1 --everywhere --action=audit:read
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
| `--action`          | For `holdings`, only the routes whose permission or policy gives the action, named literally                                                                                                                                | Every route; refused for the others                  |
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

| Code | When                                                                                                                                                                                                                                      |
|------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `0`  | The export was written                                                                                                                                                                                                                    |
| `2`  | An invalid invocation: an unknown option, a missing argument or option value, an option the query does not take, a reference, tenant, window, action or subject that cannot be read or resolved, or an existing or unwritable output file |
| `1`  | The review failed, such as on a stored role hierarchy cycle: the error names the exception's class alone, and the export has no footer                                                                                                    |

Errors go to the standard error, name the argument or option and never a value given (a subject or tenant that is
malformed, names no model or no saved row, or cannot be resolved is named by its argument or option alone), and are
escaped as `authorization:why` escapes its own.
