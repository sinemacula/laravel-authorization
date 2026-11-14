# Delegated administration and grant hooks

How the management services decide a change as the subject making it, the hooks that may refuse a grant widening an
identity's scope, and the grant scope query trusted integrations ask.

## Delegated administration

Granting, revoking and editing roles, permissions and policies are themselves actions this package checks. A
management service called with an acting context decides each change it makes as that actor, through `check()`, the
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
| `role-exclusion.declare`, `role-exclusion.remove`                                  | A pair of mutually exclusive roles declared or removed               |
| `break-glass.activate`, `break-glass.grant`, `break-glass.revoke`                  | A break-glass activation for oneself or another, or its end          |
| `resource-policy.attach`, `resource-policy.detach`                                 | A policy attached to or detached from a record or a resource type    |
| `role.read`, `permission.read`, `policy.read`                                      | Reading and listing through the services; declared, never decided    |
| `permission.grantable`, `policy.grantable`                                         | Delegating a permission, or one version of a policy, not held        |
| `administration.self`, `administration.impersonated`                               | A change that benefits the actor; a change made while impersonating  |
| `administration.unbounded`                                                         | Replacing a boundary with a wider one, or removing one               |

Each is prefixed with `authorization:`. A sync, `revokeAll()`, `removeAll()` and `detachAll()` decide each change they
make under its own action (there is no blanket action), and every change is decided before any is written, so a batch is
atomic: one refusal leaves nothing written and dispatches no change event, and no change is decided on authority an
earlier one would have handed out. `revokeAll()` removes the grantee's boundaries too, so it decides
`authorization:boundary.remove` for each. A row naming half a tenant is decided at platform scope, in its application,
since it is neither the platform's nor any tenant's and what restricts of it holds everywhere: an actor whose authority
is held only within a tenant is refused while the grantee or record has one. A sync decides a grant of each listed row
the grantee does not hold live, the row kept unchanged for each it does hold live, and a revocation of each it drops; it
judges which rows are live at one instant and re-arms as of the same instant, so a row decided as kept unchanged is
never re-armed, even when it expires before it is written. A grant, an attachment or a set is decided whether or not it
changes anything; a revocation by name decides each held row of the name, or, when none is held, the row the lookup
ranks first.

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
| `principal()`, `identity()`                             | Return the references to the acting principal and to its identity, or null for no identity           |
| `check($operationResource)`                             | Decides the resource's action on it, as the service decides it, and returns the `Decision`           |
| `decide($action, $resource)`                            | Decides any action as the acting subject, with the call's caps, and returns the `Decision`           |
| `authorize($operationResource)`                         | Decides as `check()` does and throws when the decision does not allow                                |
| `authorizeIn($operation, ...$changes)`                  | Decides each change of the operation in order, correlated by its id, and throws at the first refused |
| `authorizeChanges($operation, $changes, ...$unchanged)` | Decides the changes as `authorizeIn()` does, or the unchanged ones when there are none               |
| `ActingContext::refusal($decision)`                     | Returns the `AuthorizationException`, with the one `denied` line, the decision refuses with          |

**Trusted calls and delegated calls.** A call with no acting context is trusted system work: nothing is decided, every
structural rule, system-record protection, transaction and event still applies, and its operation is marked trusted,
with no actor unless a console command names one for the record. Treat it as an integration surface for your own code,
never as an endpoint for user-controlled administration. A call with an acting context is delegated: each change is
decided inside the call's transaction, before anything is written, and its operation carries the actor.
`GuardrailService` always takes an acting context.

**The operation resource.** Each change is decided on an `OperationResource`, a resource of type
`authorization:operation` whose id is the operation's id and whose tenant is the scope of what the change changes,
never the tenant the request is in: the tenant a grant is held in, or a definition's owner for a change to a role,
permission or policy. A change in a tenant is decided in that tenant's scope, and one in a tenant outside the actor's
scope, an ancestor of the request's tenant included, is refused as `tenant_scope` unless the actor holds the action
through a platform-wide grant. A change with no tenant, to a platform-wide grant, a platform role or a platform-owned
record, is decided at platform scope, where only a platform-wide grant of the action counts, so an actor that holds the
action only in a tenant is refused it. So who may change a grant row is the scope the actor administers: an actor whose
authority for the action reaches the row's tenant, from a parent tenant by authority over its subtree or from the
platform, changes the row from its own context, and one `revokeAll()` clears a grantee's rows across every tenant the
actor administers; a parent's node-only authority reaches no child's row, and a tenant's no platform-wide row. A change
that may widen authority reaches no further than the actor administers, so one whose reach holds a tenant where the
actor's authority for the action is denied or limited is refused (see *Administered scope* below). A screen that builds
the same resource through the same named constructor (`OperationResource::grant()`, `revoke()`, `unchanged()`,
`definition()`, `rewrite()`, `exclusion()` or `breakGlass()`) and checks it with `$actor->check($resource)` gets the
decision the service makes. Nothing is ever attached to one operation, so a check on it reads only the resource
policies attached to the type `authorization:operation`. The resource offers what the change names to your policies,
under `resource`:

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

**What is enforced.** Every change is decided under its action, through every deny, guardrail, boundary and session cap,
and in its intended tenant. Then an administration stage, after the allow and inside the same decision, weighs the
operation's constraints, in this order, and can only refuse:

- **Impersonation.** A change made while impersonating is refused as `administration.impersonating` unless the actor is
  also allowed `authorization:administration.impersonated` on the same operation, and, for a change that may widen
  authority, across its whole reach by the administered-scope rule below.
- **Administered scope.** The actor must administer the whole reach of a change that may widen authority, or the
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
  [Guardrails](caps.md#guardrails)). The further rights inherit the rule's conservatism on purpose: any deny statement
  whose actions overlap the right counts, whatever its application or conditions, so a deny held only for another
  application, or one whose condition would never hold, still refuses the right on a change whose reach is wider than
  its node, and what each right's limits read is read once per decision, however many permissions and policies the
  change hands out.
- **Rank.** Every change to an identity or a principal, a revocation, a sync, `revokeAll()`, a boundary change and a
  call that changes nothing included, is refused as `administration.rank` unless the actor is strictly senior to the
  grantee, and as `administration.rank_uncomparable` when either side's rank, or the reach, cannot be read. The actor is
  ranked in the grant's own tenant and application, by the roles that reach it (its principal's and its identity's). The
  grantee is ranked across the whole reach of the change: the most senior rank it holds anywhere the change reaches
  counts, its roles held platform-wide, in the grant's tenant and its ancestors, in every tenant below for a grant that
  reaches below, in every tenant for a platform-wide grant, and in any application for a grant to every application, a
  role held through a live break-glass activation included. Expired grants never count. A role grant is also weighed
  against the rank the role would give the grantee, so it never leaves the grantee equal to or senior to the actor. An
  unranked grantee is the most junior, an unranked actor acts on no one, two unranked sides are equal and refused, and
  with `authorization.rank.enabled` off rank is no constraint.
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
- **Possession.** A direct grant of a permission to an identity or a principal, a re-grant, an extension, a wider
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
- **The owner rule.** A change to a definition (`role.create`, `.rename`, `.update`, `.delete`, `.parent.set`,
  and the same for permissions and policies), and a change to what a role carries (a permission added or removed, a
  policy attached or detached), is made only from the tenant that owns the definition or the role: the tenant the
  check is made from must be the owner, and a platform definition needs the platform, so a record seen from a
  descendant, another tenant or the platform is refused as `administration.owner`, whether or not the change narrows.
  `RoleService::create()`, `PermissionService::create()` and `PolicyService::create()` take an optional `tenant:` (a
  model or an `AuthorizableTenant`) that owns what they create, the platform when it is left out, so a tenant
  administrator creates its own tenant's definitions from that tenant's context, and a create is refused as
  `administration.owner` from any other; a screen builds the same new record with its owner's `tenant_type` and
  `tenant_id`, such as `OperationResource::definition('authorization:role.create', new Role(['tenant_type' => 'team',
  'tenant_id' => '7']), ['name' => 'editor'])`. A resource policy's attachment is a grant to a resource, never weighed
  by the rule, and nor is a grant row: who may change one is the administered scope.
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
- **Break-glass.** An activation for oneself or another (`break-glass.activate`, `break-glass.grant`) and the end of
  another's (`break-glass.revoke`) are weighed, after impersonation, by the administered-scope rule alone: holding the
  right across the reach is the gate, so rank, self and what the role hands out are not weighed, while denies,
  boundaries, guardrails and caps still apply to what the activated role grants (see [Break-glass](break-glass.md)).
- **Still refused.** Anything the package cannot prove stays `administration.unprovable`. Guardrail changes keep their
  own authority rule, decided from above the scope, under the concurrency protocol below (see
  [the design note](../design/delegated-administration.md)).

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
    'conditions' => ['eq' => ['resource.policy' => 'support', 'resource.digest' => $approvedDigest]]]
```

`canActOn($target)` on an identity compares rank alone, as the rank rule does, and grants nothing by itself. When
neither side holds a ranked role, the comparison refuses: both count as the most junior, so their ranks are equal, and
strict seniority refuses equal rank. An application that leaves rank on but ranks no role should turn rank off
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
before anything is read or locked, so a scope-widening grant hook run first in that work runs before every lock. A
trusted call keeps its cost: it takes no extra lock and decides nothing, and with no grant hook configured it runs
once, with no retry. With one, a trusted grant is tried again in the same way only when a grant it is about to
write now widens an identity's scope with no hook run for it, up to `administration.retries` times, then refused as
`administration.conflict`; inside your own transaction that conflict is thrown as `TransactionConflictException` (see
[Grant hooks](#grant-hooks)).

**Trusted surfaces.** Each of these is trusted system work when it is used without an actor: nothing is decided, so use
it that way only from your own code, never as an endpoint for user-controlled administration:

| Surface                                                                                    | Warning                                                                 |
|--------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| A management service called without `actor:`                                               | Trusted: decides nothing; pass the acting context of the administrator  |
| A raw Eloquent write on the package's models, pivots or tables                             | Always trusted: no actor; pivot and builder writes dispatch no event    |
| An identity's `assignRole()`, `givePermission()`, `attachPolicy()`, `createInlinePolicy()` | Trusted without `actor:`; every write helper takes one and passes it on |
| The Spatie aliases `givePermissionTo()`, `revokePermissionTo()` and `removeRole()`         | Trusted without `actor:`; each takes one and passes it on               |
| A role's `givePermission()`, `revokePermission()`, `syncPermissions()` and their aliases   | Trusted without `actor:`; each takes one and passes it to `RoleService` |
| `authorization:grant` and `authorization:revoke`, seeders and migrations                   | Trusted without `--actor`; both commands take one and pass it on        |
| `AccessReview::trusted()`, `trustedPage()`, `trustedStream()`, `trustedExport()`           | Always trusted; `authorization:review` uses `trustedExport()` alone     |

The maintenance commands `authorization:sync`, `authorization:prune` and `authorization:migrate-spatie` define the
catalogue, clear expired and orphaned rows and import from Spatie for whoever runs the console; they are not
administration on anyone's behalf (`authorization:sync` records its `--actor` on what it writes).

[The design note](../design/delegated-administration.md) gives the whole design of delegated administration.

**Reasons and errors.** A refusal throws `AuthorizationException`, or `InsufficientAuthenticationException` for a
step-up, carrying the decision (`getDecision()`), its stage and its trace, for audit; the client sees the one `denied`
line. The administration stage refuses with these reasons, each at the `administration` stage with a trace step naming
it: `administration.impersonating`, `administration.scope`, `administration.rank_uncomparable`, `administration.rank`,
`administration.self`, `administration.owner`, `administration.not_grantable` and `administration.unprovable`; a call
that conflicted on every try is refused as `administration.conflict`, at the same stage, and every call made while a
preview is evaluated as `administration.previewing` (see [Preview](preview-and-explanations.md#preview)). The owner rule
applies to definitions (roles, permissions and policies), what a role carries (its permissions, policies and
parent), never to a resource policy's attachment or to grant rows.

**Audit.** Each decision is reported with `DecisionEvaluated` when `events.decisions` selects it (an allow only when
`allows` is `all`, or is `sensitive` and `sensitive_actions` lists its action, see [Which decisions are
reported](events.md#which-decisions-are-reported)), and every refusal with `AuthorizationFailed`, as `authorize()`
reports one, each naming the operation resource `authorization:operation:{operation id}`. Each try of a call that
conflicted reports its decisions under the same operation id; a call refused as `administration.conflict` ends with that
refusal, reported with both events under the operation's first action, which marks the allowed decisions of its earlier
tries as superseded, since none of them was written. The change events of a write are dispatched only after it commits,
and their operation carries the same id, the actor's principal and identity, whether the call was trusted or delegated,
any impersonator and the actions its changes fall under, so a decision and the write it allowed are correlated. The
actions are decided through `check()` only when `isTrusted` is false: a trusted call names its actions too, though
nothing was decided, and a sync names both its grant and its revoke action whichever it made.

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

## Grant hooks

Before a grant that widens an identity's scope is written, the grant service calls a grant hook the application binds,
inside the call's transaction and before the package takes any lock of its own for the call. The hook may refuse by
throwing. Under the suite, `laravel-iam` binds it to `laravel-sso`'s scope widening, so a grant can never
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

A break-glass activation is asked about as a grant of its role in its scope until its expiry, through the same hook
phase, so its hook is never skipped either. A live activation is never a grant already held here: a grant beside one
widens as it would without it.

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
`ListedGrantHooks`, so one typed to another class fails. A `GrantHook` instance a provider binds after this package
registers, but before the application boots, is wrapped by the listed hooks as the application boots. Laravel applies no
extender to an instance it is handed later, so the grant service wraps the hook it calls as well, unless it already is
wrapped: a hook bound with `instance()` after the application boots, and a hook bound in any way after an instance the
package wrapped as the application booted, run after the listed hooks too. When an extender registered after the package
decorates the wrapped hook and the grant service wraps the decoration again, the listed hooks still run once, first.
With no hook listed nothing is extended, and the bound hook stands alone.

The wrapped hook builds the listed hooks from its container at its first use and keeps them, so registering the package
builds none of them, and they share the bound hook's lifetime: built afresh for each queue job and in each Octane
sandbox when it is scoped, bound with `bind()` or the default, and kept with it when it is a singleton or an instance.
The package extends the contract as the application boots, after every provider has registered, rather than while it
registers (see [When the configured classes are bound](configuration.md#configuration)), so an extender a provider
registers after the package still receives the wrapped hook, and a hook instance held by then is wrapped too. It
resolves the bound hook only when the hook was resolved before and a callback watches the contract with `rebinding()` or
`refresh()`: Laravel then hands that callback the wrapped hook. Registering the package again in the same container
wraps nothing twice.

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
remote call and no queued work. Use the events dispatched after commit (see [Listening to
events](events.md)) for those. Only the application's own answers are read as they stand, the
identity directory's list of principals and the tenant tree: a change to those, made concurrently, is the application's
to serialise.

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
  package's: the application, or `laravel-iam`, calls the same hook on its own membership path, inside the
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

- **Raw writes.** A raw Eloquent write on the package's models, pivots or tables is a trusted integration surface, as it
  is for delegated administration, and runs no hook. Only the grant service's and the break-glass service's calls, and
  everything built on them (the trait helpers and the console commands), are guaranteed to.

## Grant scope query

`GrantScopeQuery` answers factual questions about grants for a trusted integration, such as `laravel-iam` composing
SSO's principal scope or a tenant's admission: where the grants of an identity lie against a tenant, whether a
principal holds a grant that applies in one, and who holds a grant reaching a tenant or within it. Resolve it from the
container, where it is a singleton:

```php
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Support\Reference;

$grants = app(GrantScopeQuery::class);

$grants->forIdentity(Reference::of($person), $account);       // GrantScopeStatus::WITHIN, OUTSIDE or UNKNOWN
$grants->hasGrantIn($user, $account);                         // GrantPresence::PRESENT, ABSENT or UNKNOWN
$grants->hasGrantIn($user, $account, application: 'admin');   // only the grants that hold in the admin app
$grants->granteesReaching($account);                          // list<Reference>: whoever holds a grant reaching it
$grants->granteesWithin($organisation, application: 'admin'); // list<Reference>: whoever holds one made in or below it
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
included; without one, a grant counts whichever application it holds in. A grant row naming half a tenant applies
nowhere, so it never counts. The answer is:

- `GrantPresence::PRESENT` when such a grant is found;
- `GrantPresence::ABSENT` when none is found and none could have been missed;
- `GrantPresence::UNKNOWN` when none is found but one could have been missed: the tenant tree cannot be read, so only
  the grants made in the tenant itself and the platform-wide ones are looked for, or a grantee is neither a model nor a
  `Reference` and its grants cannot be read. Uncertainty is never `PRESENT`.

The two questions differ on purpose. A grant made in an ancestor that reaches its subtree applies in a child tenant,
so `hasGrantIn($user, $child)` is `PRESENT`; it is rooted outside the child, so `forIdentity($identity, $child)` is
`OUTSIDE`.

**`granteesReaching()` and `granteesWithin()`.** `treeChanged()` runs no grant hook, so a sibling that reports a
tenant moved under another parent to its own scope widening asks whose grants the move concerns. Each takes the tenant
as a model, an `AuthorizableTenant` or a `Reference`, and an optional application, matched as `hasGrantIn()` matches
it, and returns a `list<Reference>` of the grantees, principals or identities as their rows store them, each once,
ordered by type and then key, byte by byte:

- `granteesReaching($tenant)` lists whoever holds a live grant that reaches the tenant, as a check there reads it: one
  made in the tenant, one made in an ancestor that reaches its subtree, or a platform-wide one. The ancestors are read
  from the tenant tree afresh each time, never an answer a batch of checks kept;
- `granteesWithin($tenant)` lists whoever holds a live grant made in the tenant or any tenant below it, whether or not
  the grant reaches below its own tenant, read through the tree's `subtree()` query nested whole, like
  `forIdentity()`'s.

A subtree moved under a new parent comes to be reached by the grants reaching that parent from above it or made there
reaching below it, while the grants made within the subtree keep their reach. So ask `granteesReaching()` about the
moved tenant once it has moved, or about the new parent at any time, which also lists whoever holds a grant made there
for the parent alone; `granteesWithin()` about the moved tenant lists whose grants moved with it:

```php
Authorization::treeChanged($account);

$widened = $grants->granteesReaching($account); // the account's grantees, now including its new ancestors'
$carried = $grants->granteesWithin($account);   // the grantees of the grants inside the moved subtree
```

What counts as a grant is as below, and a grant row naming half a tenant, which the package never writes, is never
listed. Nor is a role a policy is attached to, which is no principal or identity: whoever holds the role is listed
through their own grant of it. A list has no `UNKNOWN` to fall back on, so neither guesses: a tree that throws is
thrown, a subtree query on another connection than the package's is refused with an `UnexpectedValueException`, and a
subtree query that fails as it runs is thrown as its `QueryException`, once the savepoint it runs in has rolled back, so
your transaction stays usable.

**What counts as a grant.** A live role granted, permission granted directly or policy attached, a policy that only
denies included. A live break-glass activation counts as a grant of its role in its scope, as a check reads it: none
while break-glass is disabled, none of a machine, and an identity's reaches none of its principals. Roles are not
expanded into their permissions, since a role's root is where it was granted. An expired grant counts for nothing, and
neither does an inline policy attached to a grantee it does not belong to, which no check applies. Permission boundaries
and guardrails cap grants; they are not grants and are never read.

**Neither membership nor authorisation.** No answer says whether a principal is a member of a tenant, which is the
application's to know, nor whether it may act there or use an application. `PRESENT` means a grant applies in the
tenant, not that any check there would allow. `check()` stays the one decision path, and
`ApplicationAccess::mayUse()` answers application access.

**A trusted service.** Even a bare answer tells the caller something about grants in other tenants, so call it from
trusted integration code, never from an endpoint a user reaches without the right to know. `forIdentity()` and
`hasGrantIn()` return the status alone, never the tenants, grants, names, counts or rows behind it; the two lists
return the grantees alone, never their grants or where they were made.

**What it costs.** Each answer reads the grants in one query on the write connection, so a replica's lag never hides a
grant, however many grants and grantees there are and however deep the tree, plus the tree's own reads and the
directory's; only a subtree query that fails as it runs costs `forIdentity()` a second read, of the platform-wide
grants. Nothing is cached. See [Grant scope](../design/grant-scope.md) for the design.
