# Boundaries, guardrails and session caps

The caps that bound what a check may allow whatever the grants say: permission boundaries on a principal or an
identity, guardrails on a tenant or the platform, and session caps from a credential's scopes or the caller.

## Permission boundaries

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

## Guardrails

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
guardrail is read for it, neither its denies nor its allows apply, and the trace records the stage as
`[guardrail] guardrails: exempt`. For a tenant's guardrails it is decided just below the tenant's parent, so a grant
held at an ancestor of the tenant counts when it reaches the tenants below it, a platform-wide grant counts, and a grant
held within the tenant itself never does: a tenant's own administrators never lift the guardrails their tenant is set
under. A tenant with no parent, and the platform, are changed only through a platform-wide grant. A removal lifts a cap
across the scope's whole subtree, so it is also weighed across that subtree, or across every tenant for a platform
guardrail, by the administered-scope rule of delegated administration: the right, and
`authorization:administration.impersonated` for an impersonated actor, are refused when anything that denies or caps the
actor anywhere there could limit them, read as stored and as conservatively as for the action (any overlapping deny
counts, whatever its application or conditions), the guardrails still never counting against the right itself. So an
organisation's administrator denied the right by a role it holds in one team cannot remove the guardrails of the account
above it. Setting a guardrail only adds a cap, so it is decided from above alone. The check keeps the request's
application and is recorded and reported like any other decision. An actor without the right is refused with
`GuardrailException`, whose `getReason()` is `not_permitted` and `getActor()` the actor's principal, before anything is
read or written. An impersonated actor is refused with `AuthorizationException` as `administration.impersonating` unless
`authorization:administration.impersonated` is allowed it from above the scope too. Every change runs under the
[concurrency protocol](administration.md#delegated-administration) of delegated administration: the actor's authority,
the policy's row and the guardrails of the scope and the scopes above it are locked before the right is decided and read
again before anything is written, so a right revoked or a policy rewritten meanwhile has the change tried again, and
refused as `administration.conflict` once every try has conflicted.

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
service, and the table's foreign key refuses a delete made past the model. A guardrail row naming half a tenant is in no
scope: the refusal counts it as malformed, and removing the policy's guardrail at the platform removes it too. A
guardrail's statements are named in the decision, the trace and `explain()` as any policy's are, at the `deny` stage for
its denies and the `guardrail` stage for its allows.

The guardrails that apply are read in one query, apart from the policies, so a custom `PolicyResolver` never drops
them, and are cached with the rest of the resolution: once warm, a check reads none.

## Session caps and machines

A session cap bounds what a check may allow, whatever the subject's grants allow. It is a set of actions and action
patterns, not a policy: every cap present must cover the action, so the caps intersect, and an action a cap does not
cover is denied as `session_policy` at the `session` stage. A cap grants nothing: an action it covers is still decided
by every other stage, and needs an allow statement or a permission held. A check can be capped in two ways:

- **The credential's scopes.** The bound `SessionPolicySource` answers the scopes the credential of the check's subject
  carries, such as an API token's or a service account's, or null when it carries no cap, and `[]`, allowing nothing,
  when it cannot establish them.
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
[Managing roles, permissions and grants](grants.md#managing-roles-permissions-and-grants)).
An explicit cap caps only the checks made through the manager `capped()` returned, so the Gate and the middleware never
see it. `hasPermission()`, `hasRole()`, the `role:` middleware and `@role` report what is granted, not what a cap lets
through, so a cap never stops a role check.

**The source.** A class implementing `SineMacula\Laravel\Authorization\Contracts\SessionPolicySource` answers
`scopesFor(Subject $subject): ?array`, the scopes as a list of strings, or null for no cap. It is asked once for each
check that gets past the subject, resource and tenant stages and whose policies, guardrails and boundaries could then be
read; a check denied as `invalid_policy` before then asks no source. It is given the check's `Subject`, also one named
with `for()`, and answers in this order:

1. **The subject says what its credential carries.** A subject resolver that knows the credential puts it on the
   `Subject` as `scopes`, a `SineMacula\Laravel\Authorization\Support\CredentialScopes`: `CredentialScopes::uncapped()`
   for a credential carrying no cap, answered as null, and `CredentialScopes::of([...])` with the scopes it carries,
   answered as that list, `[]` included. The source answers from it.
2. **The subject says nothing (`scopes` is null) but names a credential.** It names a session, or a guard whose caller
   is now the subject's own model, the same instance or one with the same key, as an API key or a client-credentials
   token with no session does. The source establishes that credential's scopes from what the subject names, never from
   the request around it, and answers `[]` when it cannot, such as for a session it cannot resolve. A guard whose caller
   is another model names no credential of the subject's.
3. **The subject names no credential.** With no session and no guard whose caller is its model, as a queued job's or a
   console command's subject, or another model named through `for()`, the source answers null, no cap, unless it knows
   the credential that subject acts with. A machine principal is still allowed nothing without scopes (see
   [Machines](#session-caps-and-machines)).

A source never throws because it could not establish a credential's scopes; it answers `[]` instead. One that throws
for any other reason aborts the check, so no decision is made.

```php
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\CredentialScopes;

final class TokenScopes implements SessionPolicySource
{
    public function __construct(private CredentialStore $credentials) {}

    public function scopesFor(Subject $subject): ?array
    {
        if ($subject->scopes !== null) {
            return $subject->scopes->scopes(); // what the subject says its credential carries
        }

        // Its session, or its guard when the guard's caller is the subject's own model.
        $credential = $this->credentials->namedBy($subject);

        if ($credential === null) {
            return null; // a job's or a console command's subject, or another model
        }

        // CredentialScopes, or null when the store cannot read them: then nothing is allowed.
        return ($this->credentials->scopesOf($credential) ?? CredentialScopes::of([]))->scopes();
    }
}
```

A resolver filling the scopes, and a hand-built subject, say what the credential carries:

```php
new Subject($user, $user, session: $id, scopes: CredentialScopes::of(['posts:read'])); // capped to posts:read
new Subject($user, $user, session: $id, scopes: CredentialScopes::uncapped());         // no cap
new Subject($user, $user, session: $id, scopes: CredentialScopes::of([]));             // allowed nothing
new Subject($user, $user, session: $id); // the source establishes the session's scopes, or allows nothing
```

`CredentialScopes::of()` refuses anything but a list of strings that are not empty with `InvalidArgumentException`. The
subject reaches the source as the resolver made it. `for()` of another model makes a subject that is no request's
credential: it carries no session and says nothing of its scopes, so it names a credential only when its guard's caller
is that model. Only the request's own model, named while its subject has no session, is that subject itself, scopes
included.

Name it in `config/authorization.php`, where it is checked at boot and built per request or job, or bind the contract
yourself. The default, `NoSessionPolicy`, knows no credential: it answers from the subject's own `scopes`, and null
when the subject says nothing, so without a resolver filling them no credential caps a person's checks. Under
the suite, `sinemacula/laravel-iam` binds a source that reads the scopes of the caller's credential from
`laravel-authentication`.

```php
'session' => [
    'source' => App\Authorization\TokenScopes::class,
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
