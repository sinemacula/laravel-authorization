# Roles, permissions and grants

How a user model takes part in authorisation, how permissions are declared in code and synced to the database, and
how roles, permissions and policies are created and granted.

## The user model

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
[Session caps and machines](caps.md#session-caps-and-machines).

## Declaring permissions

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
catalogue, answered through the Gate, `@can` and the `can:` middleware like an enum's, checked through the
`Authorization` facade and `hasPermission()`, and listed by `permissionsFor()`:

```php
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

final class MediaPermissions implements PermissionProvider
{
    public function permissions(): array
    {
        return [
            new PermissionDefinition(
                name: 'media:upload',
                description: 'Upload media',
                category: 'Media',
                guard: 'web',
            ),
        ];
    }
}
```

List the enums and providers under `permission_enums` and `permission_providers` in `config/authorization.php` (see
[Configuration](configuration.md)).

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

## Managing roles, permissions and grants

Every write goes through nine services, which you inject or resolve from the container: `RoleService`,
`PermissionService` and `PolicyService` for the records, `GrantService` for what a grantee holds,
`ResourcePolicyService` for the policies attached to resources (see [Resource-based
policies](policies.md#resource-based-policies)), `BoundaryService` for the permission boundaries of principals and
identities (see [Permission boundaries](caps.md#permission-boundaries)), `GuardrailService` for the guardrails of
tenants and the platform, whose acting context is required (see [Guardrails](caps.md#guardrails)),
`RoleExclusionService` for the pairs of mutually exclusive roles (see [Separation of
duties](separation-of-duties.md#separation-of-duties)), and `BreakGlassService` for emergency activations of a role (see
[Break-glass](break-glass.md#break-glass)). Each call runs in one transaction on the package's connection
(`authorization.connection`), through the models `authorization.models` configures, and takes an optional `actor`, the
`ActingContext` making the call. A call without one is trusted system work, as seeders, migrations and console commands
are, and is not decided; a call with one is delegated administration, each change decided as that actor (see [Delegated
administration](administration.md#delegated-administration)). Every event the call dispatches carries its operation, and
every grant row it writes records the actor in `granted_by_type` and `granted_by_id`; it is never read from the
signed-in user:

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
$roles->setParent($author, $editor); // the team's author inherits the editor's permissions

$grants->grantRole($user, $editor, now()->addMonth()); // GrantOutcome::GRANTED
$grants->syncPermissions($user, ['posts:delete']);     // SyncResult

// Delegated administration: decided as the request's subject.
$grants->revokeRole($user, 'editor', actor: ActingContext::current()); // 1, the roles revoked
```

Grants are idempotent: granting what the grantee holds, with the same expiry, changes nothing, dispatches no event and
returns `GrantOutcome::UNCHANGED`, and a concurrent duplicate never raises a unique-constraint violation. Re-granting a
grant that has expired re-arms it with the new expiry (`REARMED`), and a new expiry on a live grant is reported as
`EXPIRY_CHANGED`. A sync re-arms a listed grant that has expired with the sync's expiry, or with none when it is given
none, and leaves a live one as it is, unless it is a role listed with a reach of its own and held with the other (see
below). A role's permissions work the same way: `RoleService::grantPermission()` and `syncPermissions()`, and the
role's `givePermission()` and `syncPermissions()`, each take an optional expiry. The
identity traits' sync methods take no expiry, so a lapsed temporary grant they list comes back permanent; to re-arm it
for a limited time, call `GrantService::syncRoles()` (or `syncPermissions()`, `syncPolicies()`) with an expiry. Setting
a role's parent locks the roles involved and refuses a cycle. A role with children cannot be deleted
(`RoleHasChildrenException`), so no one holding a child loses what it inherited by surprise: move the children to
another parent or delete them first. A target of the wrong kind, such as a role in a policy sync, is refused with
`InvalidGrantTargetException`; a grantee that is not a saved model with a key with `InvalidGranteeException`; and an
unsaved role, permission or policy handed to its service, which would otherwise be created or clear a parent, with
`UnsavedRecordException`.

Roles and permissions are Eloquent models with UUID keys, granted through polymorphic pivots, and a grant's expiry is
stored in UTC whatever zone it is given in. A name is made of letters, digits and `_ - : . *`, and anything else is
refused when it is saved. A permission can be a wildcard: `posts:*`, `posts.*`, `*:create`, or `*` for everything,
while `*:*` matches only names with a `:`. With the role hierarchy enabled, a role inherits its parent's permissions.

A role, permission or policy flagged `is_system` cannot be edited, deleted or have the flag cleared unless
`forceSystem()` on the model unlocks the next change.

`authorization:sync` is the one writer that does not go through the services: it writes the permission catalogue
through the permission model, in one transaction on the package's connection and as one operation, and decides
nothing as an actor.

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
reach](policies.md#permissions-held-and-the-resources-they-reach)). Granting a tenant's own role outside that tenant and
the tenants below it, or platform-wide, is refused with `GrantScopeMismatchException`. A revocation removes the grant in
the same scope, and a sync replaces the grants of one scope: the tenant named, else the tenant that owns every target,
else the platform. A grant is for every application unless the call names one.

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
(see [Session caps and machines](caps.md#session-caps-and-machines)).

A role takes only the platform's permissions and parent roles, its own tenant's and its tenant's ancestors', so a
platform role takes only the platform's; anything else is refused with `OwnerMismatchException`. Guards follow the same
rule as a role and its permissions: two concrete guards must match, and a guard-agnostic side suits any. A parent of
another guard is refused with `ParentGuardMismatchException`, and a role or permission granted to a grantee of another
guard with `GranteeGuardMismatchException`. The tenant that owns a role, permission or policy is fixed once it is
created (`OwnerChangedException`): to move one, create it in the new tenant and grant it again.

A role's or permission's name is unique within its tenant and guard, so two tenants can each have their own `manager`,
though a tenant cannot take the name of a platform system role. Revoking a name removes every held grant of it, the
platform's and the tenant's, and `hasRole()` given a role model matches only that row.

**How a tenant is named.** A tenant is an Eloquent model, or any object implementing
`SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant`, and the package names it by its morph type and its
`getKey()` everywhere: in the `tenant_type` and `tenant_id` of every grant and owned row, in the tenant tree's questions
and answers, in the resolution cache's keys, in events and in a `Support\Reference`. `getKey()` is the contract's
identifier, and for a model it is the primary key, so a tenant that also carries a public identifier of its own (a slug,
an external id) is still named by its key. A sibling package, or the application, naming a tenant to this one passes
the tenant, a `Reference` made from it, or its morph type and key, never the other identifier. A non-Eloquent tenant
returns from `getKey()` the value its rows are to be keyed by, and keeps it for the tenant's life.

**A row naming half a tenant.** A row is the platform's only when both `tenant_type` and `tenant_id` are null, and a
tenant's when both name it. The package never writes one without the other, and refuses to save a role, permission or
policy that way (`InvalidTenantColumnsException`). A row changed past it to name half a tenant, a type without a key or
a key without a type, is neither the platform's nor any tenant's, and fails closed both ways:

- **What grants applies nowhere.** A role grant, permission grant, policy attachment, a role's policy attachment, the
  allows of a resource policy, and the ownership of a role or permission stored that way grant nothing, at the
  platform, in any tenant or below one; a role or permission owned that way is seen in no tenant, nor at the platform.
- **What restricts applies everywhere.** A boundary or guardrail stored that way caps, and the denies of a policy
  attachment, a role's policy attachment or a resource policy stored that way deny, at the platform, in every tenant
  and below every tenant, as a platform row does.
- **An attachment that both allows and denies is split.** Its allows apply nowhere and its denies everywhere. An
  attachment of a policy naming half a tenant is read the same way, whatever scope the attachment names.

This holds in a check, a bulk check, `permissionsFor()` and query scoping alike, cold or from the resolution cache. A
check reads such rows through queries of their own, each a range of an index, so with none it does no more work than it
would without them; the `2026_11_11_000001_add_half_tenant_indexes` migration adds the `tenant_id` indexes of
`guardrails`, `resource_policies` and `policies` these reads use. An explanation never names such a row as the
platform's or as where an allow came from. A role, permission or policy owned that way is never granted, attached or
linked to a role anywhere (`InvalidTenantColumnsException`); a link to one already stored applies nowhere, so it never
keeps the guard of a role or permission from changing. A rewrite of a policy that a boundary stored that way uses is
decided at platform scope, since the boundary caps everywhere. Such a row is removed by a removal in every scope:
`revokeAll()`, `BoundaryService::removeAll()` and `ResourcePolicyService::detachAll()`, which `authorization:prune`
runs, and, for a guardrail, removing its policy's guardrail at the platform. Each decides it at platform scope, in its
application, so an acting context needs the platform authority for the action, never a tenant's; it is removed as
stored, counted, and, once the removal commits, written to the log as malformed rather than reported by an event, and
the cache forgets it. A row another writer removed first is neither counted nor written. An expired one is pruned the
same way. `authorization:list-roles` and `authorization:list-permissions` show such an owner as
`malformed (tenant_type=..., tenant_id=...)`, a policy's guardrail refusal counts such guardrails as malformed, and an
[access review](access-reviews.md#access-reviews) lists such a row as `malformed`.

Tenants can form a tree (an organisation above its accounts, say). The package never stores it: bind a class
implementing `SineMacula\Laravel\Authorization\Contracts\TenantTree` as `tenant_tree` in `config/authorization.php`,
answering a tenant's ancestors, whether one tenant is within another, and a tenant's subtree as a query. The subtree
query selects exactly the `tenant_type` and `tenant_id` of every tenant within, whatever the tenant scope. Two readers
nest it whole in a query of their own, so each needs it on that query's connection: [query
scoping](query-scoping.md#query-scoping) needs it on the connection of the models it scopes, and the [grant scope
query](administration.md#grant-scope-query) needs it on the package's connection (`authorization.connection`). A tree
kept on the connection of both the scoped models and the package's tables serves both. The default is a flat set of
tenants. With a tree, a grant in a tenant also applies in every tenant below it, unless it is limited to that tenant,
and a tenant sees the roles, permissions and policies its ancestors own as well as its own and the platform's; the
nearest owner's wins a lookup by name. Granting again with the other reach changes it, reported as
`GrantOutcome::REACH_CHANGED`. When the tree changes (a tenant moved under another parent, or deleted), report it so
cached answers below it are dropped and the move takes effect at once:

```php
$user->assignRole('admin', tenant: $organisation);                          // the organisation and its accounts
$user->assignRole('billing', tenant: $organisation, includeSubtree: false); // the organisation alone

Authorization::treeChanged($account);
```

Reporting a move runs no grant hook. An integration that widens a scope on a move asks the
[grant scope query](administration.md#grant-scope-query) whose grants now reach the moved tenant.

A sync gives every role it grants one reach, `includeSubtree`, and leaves the reach of a role held live as it is. To
sync roles of both reaches in one call, list a role with its own reach, as `Support\RoleReach::of($role, false)`, beside
role models and names. Such a role is compared with its reach: one held live with the other reach has its reach changed
in place, in one write that keeps its row, its expiry and when it was granted, reported with `RoleAssigned` carrying the
new reach and listed in the result's `reachChanged`, and a delegated call needs the right to grant it with that reach,
as `grantRole()` does. Roles not listed are revoked and new ones granted, in the same transaction. In a tenant, a role
listed with both reaches is refused with `InvalidArgumentException` before anything is written. A sync that writes
platform-wide grants, with no tenant named or owning every role, writes them reaching everywhere whatever their entries
say, so there both entries name the same reach and the sync goes ahead:

```php
use SineMacula\Laravel\Authorization\Support\RoleReach;

$user->syncRoles([
    'admin',                                         // the organisation and its accounts
    RoleReach::of('billing', includeSubtree: false), // the organisation alone
], tenant: $organisation);
```

Every row of a subtree is typed, so tenants of different types sharing an id are never confused. A tree whose source
keeps ids alone, with tenants of more than one type, projects them onto typed rows in SQL, joining whatever records each
tenant's type, and never types every tenant below with the type of the one asked about, nor looks tenants up one at a
time. A row without both columns is never guessed. Where the package nests the subtree in SQL, the database reports the
missing column; an access review nests it too, and a row it reads in PHP without both throws an
`UnexpectedValueException` naming the tree, either stopping the review (`authorization:review` reports the exception's
class). The reach of a delegated grant (`includeSubtree` through `actor:`) reads the rows in PHP and throws the same,
but the administration rules reading it catch it and fail closed, with neither the exception nor a log entry: the rank
rule, when enabled, answers `administration.rank_uncomparable`; the possession route counts every permission as limited,
so it proves none (`administration.unprovable`); and a role's resource policies count as unreadable, so the role's
grant, or a new parent, is `administration.unprovable`. The kit below catches such a tree before it reaches either.

**Testing a tree.** `SineMacula\Laravel\Authorization\Testing\Concerns\TenantTreeContract` checks a tree against this
contract. Use it in a test case for the tree, seed the tree's own storage, and give the tree and the shape seeded, each
tenant with its parent, or null for one at the top:

```php
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Testing\Concerns\TenantTreeContract;

final class OrganisationTreeTest extends TestCase
{
    use TenantTreeContract;

    protected function setUp(): void
    {
        parent::setUp();

        foreach ($this->tenantTreeNodes() as [$tenant, $parent]) {
            TenantNode::create([
                'type'        => $tenant->type,
                'id'          => $tenant->id,
                'parent_type' => $parent?->type,
                'parent_id'   => $parent?->id,
            ]);
        }
    }

    protected function tenantTree(): TenantTree
    {
        return new OrganisationTree;
    }

    protected function tenantTreeNodes(): array
    {
        return [
            [new Reference('organisation', '1'), null],
            [new Reference('team', '1'), new Reference('organisation', '1')],
            [new Reference('team', '7'), new Reference('team', '1')],
            [new Reference('organisation', '7'), null],
        ];
    }

    protected function hasMixedTenantTypes(): bool
    {
        return true;
    }
}
```

Each check is a test of its own (`testTenantTree...`), run for every tenant of the fixture: its ancestors are its parent
chain, nearest first; `isWithin()` holds for the tenant and those below it alone, and never, either way, for a tenant
outside the fixture; and its subtree is a query on the package's connection, whose every row carries a `tenant_type` and
a `tenant_id`, and whose pairs, compared as strings, are exactly the tenant and those below it, read alone, nested in a
query as the grant scope query nests it, and inside the tenant scope of another tenant. A pair returned more than once
passes, since every reader asks only whether a pair exists. A failure names the tenant and the pairs missing or extra.

A tree claiming mixed types (`hasMixedTenantTypes()`) needs a fixture on which confusing them fails, and the kit fails
any other: one tenant must have a tenant of another type below it, so a subtree typing every tenant with its root's type
misses it, and, below it or itself, a tenant sharing its id with one of another type outside it, so a subtree matching
tenants by id alone finds one too many. The fixture above does both: `team` 7 below `organisation` 1, and `organisation`
7 outside it.

Three hooks are protected, for a test case to override: `tenantTreeConnection()` names another connection than the
package's (null for the application's default); `hasMixedTenantTypes()` claims mixed types; and `tenantTreeOutsider()`
returns the tenant outside the fixture that the checks ask the tree about. By default that tenant has the first tenant's
type and an id shaped as the fixture's are, so integer or UUID key columns can hold it: the largest id plus one when
every id is digits, a new UUID when every id is a UUID, else `outside`. A tree whose keys take another shape overrides
it with one its storage can hold.

**A fake tree for tests.** To test the rest of an application under a hierarchy without a tree table of its own, bind
`SineMacula\Laravel\Authorization\Testing\FakeTenantTree`, an in-memory tree built from typed tenants, each with its
parent, or null for one at the top, every parent before its children, or added one at a time:

```php
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Testing\FakeTenantTree;

$tree = FakeTenantTree::of([
    [new Reference('organisation', '1'), null],
    [new Reference('team', '1'), new Reference('organisation', '1')],
]);

$tree->add(new Reference('team', '2'), new Reference('organisation', '1'));

$this->app->instance(TenantTree::class, $tree);
```

Tenants are told apart by type and id together, byte for byte, so tenants of different types sharing an id are never
confused, and a tenant the tree does not hold is one at the top with nothing below it. Adding a tenant held already, or
one under a parent not held, throws an `InvalidArgumentException`. The fake keeps the contract above: the package's own
tests pass the kit against it, with mixed types, on SQLite, PostgreSQL and MySQL. Its subtree is a query of literal
rows, reading no table, however many tenants it holds, on the application's default connection as it stands when the
subtree is asked for, so it nests in `whereAuthorized()` for models on that connection, and in the grant scope query
when the package's tables are there too. When the models, or the package's tables, are on another connection, name it as
the second argument of `of()`, or the first of the constructor: `new FakeTenantTree('tenants')`.

The fake can change once bound: `move()` puts a tenant it holds under another parent, or at the top for null, carrying
the tenants below it, and refuses a parent that is the tenant or below it. As with a real tree, the package keeps what
it has read of the tree for the request, so report the move before asking again:

```php
$tree->move(new Reference('team', '2'), null);

Authorization::treeChanged(new Reference('team', '2'));
```

The trait methods (`assignRole()`, `givePermission()`, `attachPolicy()`, `$role->givePermission()` and the others) go
through the same services. Without `actor:` they are trusted; given `actor:`, they pass it on, so the change is decided
as that administrator (see [Trusted surfaces](administration.md#delegated-administration)). A raw relation write such as
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
supplies it (see [The check's context](context.md#the-checks-context)).

`Authorization::check()` returns the full `Decision`: `isAllowed()`, the denial's reason code (`reason`), the stage that
decided it (`stage`), the statements that did (`statements`) and a trace of every step. `can()`, `cannot()`, `any()`,
`all()` and `authorize()` are shortcuts over it (see [The programmatic API](checking-access.md#the-programmatic-api)). A
check runs in stages, stopping at the first that decides: the subject (`subject_unresolved`, `subject_inactive`), the
resource (`resource_unresolved`), its tenant (`tenant_scope`), then the denies in every applicable policy, a guardrail's
and a permission boundary's included (`explicit_deny`, or `invalid_policy` for a statement that cannot be evaluated),
then the caps: the [guardrails](caps.md#guardrails) and the [permission boundaries](caps.md#permission-boundaries), each
of which must allow the check (`guardrail` or `boundary`, or `invalid_policy` for a cap's statement that cannot be
evaluated), and the [session caps](caps.md#session-caps-and-machines), every one of which must cover the action
(`session_policy`), then the allows (an allow statement, then a permission held), then, for an administration action on
its own operation resource, the operation's constraints, which can only refuse an allow (the `administration.*` reasons,
see [Delegated administration](administration.md#delegated-administration)), then the implicit deny
(`insufficient_authentication` when an allow statement names the check and only its [authentication
requirement](context.md#authentication-requirements) is unmet, `condition_failed` when an allow statement names the
check but its conditions do not hold, else `no_match`). [How a check is decided](policies.md#how-a-check-is-decided)
sets the stages out in full. Each stage assesses its statements in a fixed order, so the decision is the same whatever
order the policies are read in, and the trace records condition key names and whether each held, never their values:

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
implementing `QueryableResource` takes its tenant from its declaration instead (see [Query
scoping](query-scoping.md#query-scoping)). Any other string is never given a tenant, so a tenant-owned resource that is
not a model should implement `AuthorizableResource` and carry its tenant.

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
`InsufficientAuthenticationException` instead (see [Authentication
requirements](context.md#authentication-requirements)). `Authorization::lastDecision()` returns the decision too; the
`AuthorizationFailed` event carries its reason, statements and keys (see [Listening to
events](events.md)). To reword the message, add a locale or word a message per reason, see
[Localisation](localisation.md#localisation).
