# Checking access

The ways to ask for a decision: the `Authorization` facade, Laravel's Gate and policy classes, route middleware and
Blade, bulk checks over many resources, and the list of actions a subject may take in a scope.

## The programmatic API

Every check goes through `SineMacula\Laravel\Authorization\AuthorizationManager`, which the `Authorization` facade
proxies and the container injects. Each method decides about the current subject, as the subject resolver gives it,
or about the subject of the scoped manager it is called on:

| Method                                            | What it does                                                                                                                           |
|---------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `can($action, $resource, $context)`               | Decides the action and returns whether it is allowed                                                                                   |
| `cannot($action, $resource, $context)`            | Returns the opposite of `can()`                                                                                                        |
| `authorize($action, $resource, $context)`         | Decides the action and throws when it is not allowed                                                                                   |
| `check($action, $resource, $context)`             | Decides the action and returns the full `Decision`                                                                                     |
| `any($actions, $resource, $context)`              | Returns whether at least one of the actions is allowed                                                                                 |
| `all($actions, $resource, $context)`              | Returns whether every one of the actions is allowed                                                                                    |
| `checkMany($checks)`                              | Decides each `CheckInput` and returns its `Decision`, keyed as the checks are (see [Bulk checks](#bulk-checks))                        |
| `canEach($action, $resources, $context)`          | Decides the action on each resource and returns whether each is allowed, keyed as the resources are                                    |
| `filterAuthorized($action, $resources, $context)` | Returns the resources the action is allowed on, with their keys and order, a `Collection` as its own class                             |
| `explain($action, $resource, $context)`           | Decides the action in explain mode and returns its `Explanation` (see [Explanations](preview-and-explanations.md#explanations))        |
| `lastDecision()`                                  | Returns the latest decision of the request or job, whichever manager made it                                                           |
| `lastDecisionProvenance()`                        | Returns who the latest decision was about, who previewed it and where it was made, or null whenever `lastDecision()` is                |
| `forgetLastDecision()`                            | Clears the latest decision of the request or job                                                                                       |
| `forgetDecisionsFor($session, $identity)`         | Forgets everything the request or job remembers towards its decisions (see [Forgetting](context.md#forgetting-decisions))              |
| `permissionsFor($subject, $scope, $context)`      | Lists the actions of the permission catalogue the subject may take in the scope                                                        |
| `heldPermissionsFor($subject, $scope, $context)`  | Lists the same actions, each a `HeldPermission` naming the authentication requirements its decision read                               |
| `for($subject)`                                   | Returns a scoped manager deciding about the model named, in the request's scope, or a `Subject` in its own scope                       |
| `forUser($user)`                                  | Returns a scoped manager deciding about the subject the resolver translates the user into                                              |
| `previewFor($subject, $scope)`                    | Returns a preview deciding about the subject as the caller, admitted at every use (see [Preview](preview-and-explanations.md#preview)) |
| `capped($actions)`                                | Returns a scoped manager whose checks are capped by the actions given                                                                  |
| `withPolicies($policies)`                         | Returns a scoped manager that evaluates only the policies given                                                                        |
| `queryScope($model, $action, $context)`           | Returns the scope `whereAuthorized()` puts on a query (see [Query scoping](query-scoping.md#query-scoping))                            |
| `GrantScopeQuery::forIdentity()`, `hasGrantIn()`  | Not on the manager: grant scope and presence in a tenant (see [Grant scope query](administration.md#grant-scope-query))                |
| `granteesReaching()`, `granteesWithin()`          | Not on the manager: whose grants reach a tenant or lie within it (see [Grant scope query](administration.md#grant-scope-query))        |
| `AccessReview::review()`, `trusted()`             | Not on the manager: holders, holdings, expiries, grants by actor, unused (see [Access reviews](access-reviews.md#access-reviews))      |
| `AccessReview::page()`, `stream()`, `export()`    | Not on the manager: a review a keyset page, a lazy stream or JSON Lines at a time, each with a `trusted…()` counterpart                |

`check()` is the one decision, and `checkMany()` the same decision over many checks, `check()` deciding as `checkMany()`
decides a batch of one: every other method but `queryScope()` and the listings adapts one of them, and each decision
they make is recorded as the last decision and reported with `DecisionEvaluated` when `events.decisions` selects it (see
[Which decisions are reported](events.md#which-decisions-are-reported)); `queryScope()` compiles a scope from the same
pipeline without deciding a check, and `permissionsFor()` decides each action through the path `checkMany()` takes but
as introspection, so both record and report nothing, except on a preview, where the admission is recorded at every use,
and reported as any check is, and a listing dispatches each action's `DecisionEvaluated` (see
[Preview](preview-and-explanations.md#preview)). `permissionsFor()` and `heldPermissionsFor()` take their subject as an
argument, null for the one the manager's checks are about (see [Effective permissions](#effective-permissions)). The
resource and the context take the same forms everywhere: a model, a `[type, id]` pair, a `ResourceReference`, an
`AuthorizableResource`, a model class or a string names the resource (see [Managing roles, permissions and
grants](grants.md#managing-roles-permissions-and-grants)), and the context is the caller's values, read under `input`
(see [The check's context](context.md#the-checks-context)).

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

**`for()` and the scope.** A model given to `for()` is decided in the scope in place: the request's tenant and
application, as the subject resolver reports them, or those an `AuthorizationScope::within()` puts in place. A resolved
`Subject` is taken as it is, keeping its identity, guard and session, and when it names a tenant or an application,
every check through the manager is decided there: its tenant, or the platform when it names none, and its application,
or none, are put in place of the request's, both as the subject's and as the scope of the grants that count, for each
`check()`, `can()`, `cannot()`, `any()`, `all()`, `authorize()`, `checkMany()`, `canEach()`, `filterAuthorized()`,
`explain()` and query scoped through it with `whereAuthorized()`. The request's are restored once each is decided, even
when it throws, and nothing is kept between calls or requests. A `Subject` naming neither, and not on the platform (see
below), is decided in the scope in place, as a model is. So a subject in another tenant needs no wrapping:

```php
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;

$member = new Subject($principal, $person, $account, 'admin');

Authorization::for($member)->can('posts:update', $post);   // decided in $account, on the admin application

// The same decision, as callers wrote it before: wrapping the call still gives the same result.
$scope = AuthorizationScope::tenant($account, 'admin');
$scope->within(fn () => Authorization::for($scope->subjectIn($member))->can('posts:update', $post));
```

**A subject on the platform.** A `Subject` built with `platform: true` acts on the platform, as a queued job or a
console command acting for no tenant does, and names no tenant, so one naming a tenant too is refused with
`InvalidArgumentException`. Every check through `for()` of it is decided on the platform, on its application, or on
none, whatever tenant is in place, the request's or one an `AuthorizationScope::within()` puts there, so a grant held
only in that tenant does not allow it, and the scope in place is restored afterwards, exactly as for a subject naming a
tenant. Only a `Subject` the caller passes is moved so. A request whose own subject is on the platform, and so names no
tenant, is already decided on the platform, and so are a model it names through `for()` and a user through `forUser()`,
with the Gate, `@can`, `can:` and application access, which decide through `forUser()`. Inside an explicit
`AuthorizationScope::within()` of a tenant, every one of them is decided in that tenant, and only a `Subject` passed
with `platform: true` still decides on the platform:

```php
use SineMacula\Laravel\Authorization\Subject;

// In a queued job: decided on the platform's grants, never the tenant in place.
Authorization::for(new Subject($user, platform: true))->can('reports:export');
```

`permissionsFor()` lists in the scope it is given, which wins over the subject's, a subject on the platform included,
and a preview from `previewFor()` keeps its own scope (see [Preview](preview-and-explanations.md#preview)). The
subject's tenant is read when a check is decided, not by `for()`, so a `Subject` whose tenant cannot be read, a plain
object that is neither a model nor an `AuthorizableTenant`, is refused with `InvalidTenantException` by each check
through the manager, before anything is decided.

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

## Laravel's Gate

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
`input` (see [The check's context](context.md#the-checks-context)).

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
directives still decide them. Only true or false is accepted: any other value of `authorization.gate.enabled` is refused
at boot. `authorization:check` reports whether the hook is enabled. While the package refuses every operation after a
diagnostic boot, the hook is not registered at all, so Laravel denies the package's abilities, unless the application's
own Gate rules answer them (see [The diagnostic boot](console.md#the-diagnostic-boot)). The contract behind the hook is
in [Gate authority](../design/gate-authority.md).

## Laravel policy classes

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
current locale; read the code to word a message per reason (see [Localisation](localisation.md#localisation)). A denial
is never a not-found response, so Laravel answers it with a `403`:

```php
Gate::inspect('archive', $post)->code();     // 'explicit_deny'
Gate::inspect('archive', $post)->message();  // 'This action is unauthorized.'
```

An `insufficient_authentication` denial keeps its own code, but the trait raises no
`InsufficientAuthenticationException` and the response carries no requirements, so it is answered as any other `403`. A
caller that needs to ask for a step-up decides the action with `authorize()`, which raises that exception, or with
`check()`, whose decision names the requirements (see [Authentication
requirements](context.md#authentication-requirements)).

For an ability whose exact name the package declares, the [Gate hook](#laravels-gate) answers before any policy class
runs, so a policy method is never called for it. The trait is for the abilities outside the catalogue's exact names,
such as `archive` above, which the hook leaves to Laravel and its policy classes, and for applications that turn the
hook off, where Laravel's policy classes answer the Gate for every ability.

## Middleware and Blade

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
with an `InvalidCheckArgumentException`. A request without a subject throws Laravel's `AuthenticationException` (`401`)
with the translated `authorization::authorization.unauthenticated` line. A denial throws the package's
`AuthorizationException` (`403`) with the reason code and the translated `authorization::authorization.denied` line,
whatever the reason. A denial of `permission:` or `authorize:` is a decision: it is recorded as the last decision and
fires `AuthorizationFailed` once, for the list's last action, before its denial is thrown, or, when that action is
denied as `insufficient_authentication`, an `InsufficientAuthenticationException` (see [Authentication
requirements](context.md#authentication-requirements)). A denial of `role:` is not a decision: it carries `no_match`, or
`subject_inactive` for an inactive subject, and records nothing and fires no event.

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

## Bulk checks

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
decision and, when `events.decisions` selects it, reported with its own `DecisionEvaluated` as soon as it is decided,
before the next one, in the order of the checks; there is no event for the batch as a whole.
`Authorization::lastDecision()` is then the last check decided, and an empty batch leaves it as it was. A check that
throws where `check()` would throw (an attribute provider that fails, say) stops the batch there: the checks before it
are recorded and reported, nothing is returned, and the tenant scope is restored however the batch ends.

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

## Effective permissions

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
`DecisionEvaluated` and no `AuthorizationFailed`. On a preview, each action's `DecisionEvaluated` is dispatched while
`events.decisions.previews` is on, as it is by default, naming both parties, though none is stored, and the preview's
admission is recorded and reported as any check (see [Preview](preview-and-explanations.md#preview)). An action listed
through a break-glass activation is reported by no event either, except on a preview, whose listing reports it whatever
the settings, with `usedBreakGlass` set.

**Held permissions and their requirements.** `heldPermissionsFor()` takes the same arguments as `permissionsFor()` and
lists the same actions, in the same order, through the same path, each as a
`SineMacula\Laravel\Authorization\Evaluation\HeldPermission`: its `action`, and its `requirements`, the name of every
part of every authentication requirement its decision read (`multifactor`, `phishing_resistant` and so on, as the policy
document names them), once each, sorted. A requirement counts wherever the decision read it: on a statement that allowed
or on one that denied, a boundary's or a guardrail's included, or in a further check the decision made, such as the
right to act while impersonated on an administration operation or an access review, whether it was met or not. The list
names every requirement read, not only those that decided the answer, so an entry can be conditional even when no
requirement would change the answer today: an allow whose other conditions failed, or one beside another allow that
needs nothing, is still read, and its requirement still named. The guarantee runs one way. `isUnconditional()`, true
when `requirements` is empty, is the safe test: no requirement was read, so none could change the answer, and the action
is held whatever the session has proved. A conditional entry may depend on the session's authentication state, a fresh
multifactor step say, or a deny guarded by a requirement that does not apply while it is unmet, and should be treated as
possibly held only while that state lasts. Everything else is as for `permissionsFor()`: the subject, the scope and
the context are taken the same way, an action whose check would be `insufficient_authentication` is not listed, and the
listing records nothing, refuses and throws alike. The model's `HasPermissions` trait lists its own, with
`$user->heldPermissionsFor($scope, $context)`.

```php
use SineMacula\Laravel\Authorization\Evaluation\HeldPermission;

$held = Authorization::heldPermissionsFor($user, AuthorizationScope::current());

// [HeldPermission('posts:create', []), HeldPermission('posts:export', ['multifactor'])]
$unconditional = array_filter($held, fn (HeldPermission $permission): bool => $permission->isUnconditional());
```

For an audit of what a subject holds, list for the real subject and its session, a resolved `Subject` or null for the
request's own, and treat a conditional entry as not unconditionally held: it says what the subject may do now, in this
session, not what it holds in every session, though it may hold it in every session too. A model named as `for()` names
it has no session, so a requirement made of it is never met: an allow that needs one is not listed, and a deny guarded
by one does not apply, its action listed as conditional.

**What it costs.** The actions are decided together, through the path `checkMany()` takes, so the subject is resolved
once and its grants, roles, policies, boundaries and caps, the guardrails and the resource's tenant, attached policies
and attributes are read once for the listing: listing fifty actions costs the queries listing five costs. The catalogue
is read from code on each call and touches no database. A scope already in place, such as `current()`, is not applied
again, so a listing in it reads what the request's checks have already resolved, and a check after it still does. A
listing in another scope keeps what the request has resolved and puts it back once it returns, unless a write emptied
the cache meanwhile. See [Effective permissions](../design/effective-permissions.md) for the design.
