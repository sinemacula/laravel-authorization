# Management Services

Every write of a role, permission, policy, grant, resource attachment, permission boundary, guardrail, role exclusion
or break-glass activation goes through one of nine injectable services, so each write runs in one transaction on the
package's connection, reads the configured models and reports only what it changed. The identity traits, the role's
permission helpers, the grant and revoke commands and the Spatie import all delegate to them. The one exception is
`authorization:sync`, which writes the permission catalogue through the permission model in its own transaction on the
package's connection, rather than through `PermissionService`.

## Purpose

- `RoleService`: create, rename, describe, re-parent, delete, find and list roles; grant, revoke and sync the
  permissions a role carries.
- `PermissionService`: create, rename, describe, delete, find and list permissions.
- `PolicyService`: create, rename, describe, rewrite, delete and list policies, and create a grantee's inline policies
  (`createInline()`).
- `GrantService`: grant, revoke and sync roles, permissions and policies to a grantee, an identity or a role, with an
  optional expiry.
- `ResourcePolicyService`: attach a policy to a resource, a record or a whole resource type, and detach it.
- `BoundaryService`: set, replace and remove the permission boundary of a principal or an identity, platform-wide or in
  a tenant.
- `GuardrailService`: set and remove the guardrails of a tenant or of the platform, for an acting subject allowed to.
- `RoleExclusionService`: declare, remove and list pairs of mutually exclusive roles, and report who holds both roles
  of a pair (see [Separation of duties](separation-of-duties.md)).
- `BreakGlassService`: activate, surrender and revoke a break-glass activation of a role (see
  [Break-glass](break-glass.md)).

Each is a final class bound as a singleton (it holds no state), resolved from the container or injected. Every method
that writes, and every `list()`, takes the acting context making the call as an optional `$actor`, an
`Administration\ActingContext`: null for trusted system work, such as seeders, migrations and console commands, whose
changes are not decided. A call with one is delegated administration: each change it makes is decided as the actor,
through `check()`, on the change's operation resource, inside the call's transaction and before anything is written (see
[Delegated administration](delegated-administration.md)). `GuardrailService` requires it, since it decides whether the
actor may make the change, and so does `BreakGlassService::surrender()`, which ends the actor's own activation. Every
event the call dispatches carries the call's operation, and every grant row it writes records the actor in
`granted_by_type` and `granted_by_id`. It is never read from the authenticated user or the subject resolver. The events
themselves are described in [Events](events.md).

## Invariants

1. **One transaction per call, on the package's connection.** Each call, the lookups included, runs in one
   transaction on `authorization.connection` (the default connection when unset). A failure part-way rolls back every
   write the call made. Called inside an application transaction on the same connection, the call nests as a
   savepoint, so a provisioning transaction that creates a principal and its grants commits or rolls back as one.

2. **The configured models.** Names are looked up, rows created and events built through the classes
   `authorization.models.*` configures. A role or permission named by a string is looked up under the grantee's guard
   (its `getAuthorizationGuard()`, when it declares one) or, for a role's permissions, under the role's guard, else the
   package default.

3. **Grants are idempotent.** A grant inserts its row with insert-or-ignore against the table's unique key, then reads
   the row back under a lock when it was already there. Granting what the grantee holds (the same target, grantee and
   scope) with the same expiry changes nothing and is reported as `GrantOutcome::UNCHANGED`; a concurrent
   duplicate is the same case, so it never surfaces a unique-constraint violation. A role's permissions are attached
   through the role permission pivot, so guard parity is enforced, inside a savepoint that a concurrent duplicate rolls
   back alone.

4. **Expiry.** Re-granting a grant that has expired re-arms it with the new expiry (`REARMED`). A different expiry on a
   live grant is a change of its own (`EXPIRY_CHANGED`). A sync grants what is missing with the sync's expiry, re-arms a
   listed grant that has expired with the same expiry, leaves a live grant as it is, and revokes what is not listed. A
   role listed with its own reach (`Support\RoleReach::of($role, $includeSubtree)`) is compared with that reach: held
   live with the other, its reach is changed in place, one write keeping its row and expiry, reported as `REACH_CHANGED`
   with the granted event and in `SyncResult::$reachChanged`; listed with both reaches in a tenant, the sync is refused
   with `InvalidArgumentException` before anything is written; a platform-wide sync writes every grant reaching
   everywhere, so there both entries name the same reach and the sync goes ahead. A sync given no expiry, as every
   identity trait sync is, re-arms a lapsed temporary grant as a permanent one. A role's grants of permissions behave
   the same way through `RoleService::grantPermission()` and `syncPermissions()`, which take the expiry before the
   actor.

5. **One scope per grant.** A grant holds in one tenant or platform-wide. The tenant that owns the target fixes it, or a
   tenant below it that the call names, and naming any other is refused with `GrantScopeMismatchException`; a platform
   target is granted in the tenant the call names as `$tenant`, else platform-wide. A name is looked up among the rows
   visible in the tenant named, else the current tenant. A grant, a re-arm, a read of what is held and a revocation each
   stay in their scope, so a role held in two tenants is two grants; a sync replaces the grants of one scope, the tenant
   named, else the tenant that owns every target, else the platform. Only a grantee's deletion revokes in every scope. A
   grant is for the application the call names, else every application.

6. **Reported once it commits, and nothing for a no-op.** Each call is one operation: every event it dispatches carries
   the same operation, its id, its actor and mode and its actions, and is dispatched once the write commits on the
   package's connection, at the outermost commit when the call runs inside an application transaction, and never when
   that transaction rolls back. Only a write that changed something is reported: granting what is held, revoking what is
   not held and a sync that changes nothing dispatch nothing. A re-armed grant or a changed expiry dispatches the
   granted event as well as the expiry-changed one. Every dispatched event bumps the resolution cache versions it
   affects, so the change takes effect on the next check. Record writes go through the models, so their observers report
   them, as part of the call's operation.

7. **The hierarchy is checked under a lock.** `setParent()` locks the role and the parent, in key order, then the
   observer walks the parent's ancestors, each locked for update and read outside the tenant scope. Reaching the role
   refuses the parent with `RoleHierarchyCycleException`, so two concurrent re-parentings cannot close a cycle between
   them, and a cycle through another tenant's role is refused as well. A chain that loops without reaching the role is
   corrupt and refused too.

8. **The wrong target is refused.** A grant, revocation or sync handed anything that is not a saved model of its kind
   (a policy sync given a role, a role sync given a permission, a name for a policy, an unsaved role) throws
   `InvalidGrantTargetException` before anything is written. `attachPolicy()` and `detachPolicy()` take a `Policy`.
   A grantee that is not a saved model with a key, or a `Reference` with an empty type or key, throws
   `InvalidGranteeException` before the transaction opens, so no grant is keyed to an empty identity. A role,
   permission or policy model handed to its record service unsaved (to change, delete or re-parent, or as a parent)
   throws `UnsavedRecordException`, so a change never creates a record outside `create()` and an unsaved parent never
   clears a role's parent.

9. **An inline policy is attached to its grantee alone.** `PolicyService::createInline()` and the
   grantee's `createInlinePolicy()` create a policy that names its grantee in `owner_type` and `owner_id`, validated as
   any policy's document is, and do not attach it. A grant or a sync that would attach it to any other grantee throws
   `InlinePolicyAttachmentException` before anything is written, and so does a write through a grantee's `policies()`
   relation, through the pivot's observer. Both read the grantee from the stored row on the write connection, inside
   the grant's transaction, never from the model in hand, which may have been loaded without its owner columns or
   changed since; a policy whose row is gone is refused with `InvalidGrantTargetException`. A resolution leaves out an
   attachment to another grantee all the same. Its name is unique among that grantee's inline policies; a managed
   policy, with neither owner column, keeps the uniqueness it has. An inline policy is never a system policy
   (`SystemInlinePolicyException`), so nothing stops its deletion with its grantee: deleting the grantee deletes its
   inline policies through the model, each reported as `Policy\Deleted` with its attachments, and
   `authorization:prune` deletes those of a grantee that no longer exists, once it has revoked that grantee's grants.

10. **A role's policies are its grants.** A policy attached to a role is a row of `authorizable_policies` with the role
    as the grantee, written, reported and invalidated as any grant is (the events name the role as the grantee).
    Deleting a role detaches its policies through `revokeAll()`, each reported as detached, since the grantee columns
    carry no foreign key.

11. **A name reaches every held row.** A role or permission name answers every row of it under the guard, the current
   tenant's and the platform's alike. A revocation by name revokes each of them the grantee or role holds, and a sync
   that names one keeps each held row of the name, granting the row the lookup ranks first only when none is held.

12. **A resource's policies are attached like grants.** `ResourcePolicyService::attach()` writes a row of
    `resource_policies`: the policy, the resource's morph type and its key (null for the whole type), and the scope,
    worked out as a grant's is (`GrantScopes::of()`), so a tenant's policy is attached in that tenant or below it and
    anywhere else is refused with `GrantScopeMismatchException`. The write is insert-or-ignore on a null-folding unique
    key over the policy, the resource and the scope, so it is idempotent under concurrency and returns `GRANTED`,
    `REACH_CHANGED` or `UNCHANGED`; `detach()` removes the attachment in the scope it names and returns how many it
    removed, and `detachAll()` removes every attachment of one record, in every scope, never a whole type's. The stored
    policy must suit a resource (`PolicyPrincipals`): an inline policy, or one with an allow naming no principals, is
    refused with `ResourcePolicyException` before anything is written, and a resource that names no type, an unsaved
    model, or a record whose key is `*` (which the whole type stands for), with `InvalidResourceException`. A pair names
    its record without asking the resource tenant resolver, since the call names the scope. A policy naming principals
    is refused the other way, by every grant path to an identity or a role. Each call is one transaction and one
    operation, dispatches `Resource\PolicyAttached` or `Resource\PolicyDetached` after commit only when it changed
    something, and refreshes the resolution cache for the resource's type. The rows carry no actor column; the events
    carry the actor.

13. **A boundary is one row per grantee per scope.** `BoundaryService::set()` writes a row of
    `authorizable_boundaries`: the grantee's morph type and key, the policy, the tenant (null platform-wide) with its
    `include_subtree`, and the actor. The scope is worked out as a grant's is (`GrantScopes::of()`), so a tenant's
    policy is set in that tenant or below it and anywhere else is refused with `GrantScopeMismatchException`; a
    boundary has no application. A null-folding unique key over the grantee and the tenant keeps one boundary per
    scope: the write is insert-or-ignore followed by a locked read-back (`Services\Support\BoundaryTable`), so a
    concurrent duplicate never raises, and returns `GRANTED`, `REPLACED` (another policy was the boundary there),
    `REACH_CHANGED` or `UNCHANGED`. An ignored insert that leaves no row to read back is tried once more, and when that
    leaves none either the call is refused, so it never reports a boundary no row bears out: a policy deleted at the
    same moment (on MySQL, `INSERT IGNORE` turns the foreign key failure into a warning) with
    `InvalidGrantTargetException`, any other failure with `UnwrittenGrantException`. `ResourcePolicyService::attach()`
    reads its attachment back the same way. `remove()` removes the boundary in the tenant named, else the platform-wide
    one, and returns whether there was one. A grantee that is never a subject's principal or identity (a role, a
    permission or a policy) and an inline policy (`BoundaryException`), a policy naming `principals`
    (`ResourcePolicyException`), a policy whose row is gone (`InvalidGrantTargetException`) and an unsaved grantee or
    one without a key (`InvalidGranteeException`) are refused before anything is written. `GrantService::revokeAll()`
    removes the grantee's boundaries in every scope with its grants, so deleting a grantee removes them too;
    `removeAll()` removes them alone, which the grant pruner does for a grantee that is gone, counting them apart from
    its grants. Each call is one transaction and one operation, dispatches `Identity\BoundarySet` (with the
    `previous` policy it replaced) or `Identity\BoundaryRemoved` after commit only when it changed something, and
    refreshes the grantee's cached resolutions through its version.

14. **A guardrail is one row per policy per scope, and only an acting subject allowed to may write it.**
    `GuardrailService::set()` writes a row of `guardrails`: the policy, the tenant (both columns null for the platform)
    and the actor. A null-folding unique key over the policy and the tenant keeps a policy once per scope, while a scope
    may have any number of guardrails; the write is insert-or-ignore followed by a read-back
    (`Services\Support\GuardrailTable`), retried once as a boundary's is, and returns `GRANTED` or `UNCHANGED`. A
    guardrail has no application and no reach flag: it holds in every application and, on a tenant, in its subtree. A
    tenant's policy is set on that tenant or below it, and anywhere else, the platform included, is refused with
    `GrantScopeMismatchException`. `remove()` removes the policy's guardrail from the scope named and returns whether
    there was one. Inside the call's transaction, before it reads or writes anything else,
    `Services\Support\GuardrailAuthority` decides through `check()`, as the acting context's subject, whether it holds
    `authorization:guardrail.manage` from above the scope: for a tenant, just below its parent, so a grant held at an
    ancestor counts only when it reaches below it, a platform-wide grant counts, and one held within the tenant never
    does; for a root tenant and the platform, at platform scope. The check is exempt from the guardrails, as every check
    of that exact action is, so no guardrail caps it; every other deny and cap still does. A removal, which lifts a cap
    across the scope's whole subtree, is also refused when anything that denies or caps the actor anywhere in that
    subtree could limit the right (`Administration\AdministeredScope`). An actor refused, and every actor when no
    authorization manager is bound, is refused with `GuardrailException` (`not_permitted`); an actor someone is
    impersonating is refused as `administration.impersonating`, with `AuthorizationException`, unless it is also allowed
    `authorization:administration.impersonated` there. `set()` reads the policy under a lock on its row, which the
    policy observer takes too before it reads a policy's guardrails, so an edit and a guardrail set at the same moment
    are serialised and the edit is refused once the guardrail is there. An inline policy (`GuardrailException`,
    `inline`), a policy naming `principals` (`ResourcePolicyException`), a policy whose row is gone and one deleted
    while the row is written (`InvalidGrantTargetException`) and a row a concurrent change kept from being written
    (`UnwrittenGrantException`) are refused as a boundary's are. Each call is one transaction and one operation,
    dispatches `Guardrail\GuardrailSet` or `Guardrail\GuardrailRemoved` after commit only when it changed something, and
    refreshes every cached guardrail entry through the version they share.

## Success Path

```php
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;

$roles  = app(RoleService::class);
$grants = app(GrantService::class);

// Trusted system work, as a seeder or a command makes it: no acting context.
$editor = $roles->create('editor', 'web', 'Edits posts');
$roles->grantPermission($editor, 'posts:update');

$grants->grantRole($user, $editor, now()->addMonth()); // GrantOutcome::GRANTED
$grants->grantRole($user, $editor, now()->addMonth()); // UNCHANGED if the expiry is the same
$grants->syncPermissions($user, ['posts:delete']);     // SyncResult

// Delegated administration: decided as the request's subject under authorization:role.revoke.
$grants->revokeRole($user, 'editor', actor: ActingContext::current()); // 1
```

A call with an acting context is weighed by the administration rules once its action is allowed: scope, owner, rank,
self, possession and the impact on every holder. A change that widens authority and that no rule proves is refused as
`administration.unprovable` (see [Delegated administration](delegated-administration.md)).

The trait methods (`assignRole()`, `givePermission()`, `attachPolicy()`, `$role->givePermission()` and the rest) keep
working: each forwards to the matching service method, with the `actor` it is given, none by default.

## Failure / Edge Cases

- **A row naming half a tenant**, which the services never write, holds in no scope a call can name. A removal in
  every scope removes it as stored: `GrantService::revokeAll()`, `BoundaryService::removeAll()` and
  `ResourcePolicyService::detachAll()`, which the grant pruner runs; and removing a policy's guardrail at the platform
  removes its guardrail rows stored that way. Each decides such a row at platform scope, in its application, so an
  acting context needs the platform authority for the action, never a tenant's, and is refused while one remains when
  its authority is held only within a tenant. The row is removed as stored, found by the same read as the rest, counted,
  and, once the removal commits, written to the log as malformed (`Support\TenantColumns::reportRemoved()`) rather than
  reported by an event, which would name it the platform's or a tenant's, and the resolution cache is invalidated as
  that event would (`OperationScope::invalidate()`); a row another writer removed first is neither counted nor written.
  The pruner removes an expired one the same way. A role, permission or policy owned that way is never granted, attached
  or linked to a role (`InvalidTenantColumnsException`); a link to one already stored is passed over when the guard of
  the other record changes, as it applies nowhere. A delegated rewrite of a policy a boundary stored that way uses is
  weighed at platform scope (`Administration\PolicyRewrite`), since the boundary caps everywhere.
- **Raw relation writes bypass the services.** `$user->roles()->attach()`, `$role->permissions()->sync()` and their
  kin write the pivot directly: no transaction, no idempotency, no event and a stale resolution cache. They are
  unsupported for any change that must be audited.
- **A grantee whose class is not loadable** is named with `Reference` (its morph type and key), as the Spatie
  import does for Spatie's `model_type` and `model_id`. A reference carries no guard.
- **An inline policy created is not attached.** The caller attaches it to its grantee, in the scope it should hold in,
  with `attachPolicy()`.
- **Without the service provider** the traits refuse to write (`LogicException`) rather than lose the write.
- **List methods are reads** and run outside a transaction. `list()` takes the actor as the writes do, but decides
  nothing with it. The other reads, `find()` and `RoleExclusionService`'s `pairs()`, `conflicts()` and
  `conflictsForAll()`, take none.
- **`authorization:grant` gives no expiry**, so granting a role the identity holds on a temporary or expired grant makes
  it permanent and is reported as granted; only a role already held with no expiry is reported as held.
- **`authorization:sync` writes directly.** The permission catalogue sync saves and deletes through the permission
  model, in one transaction on the package's connection and as one operation, rather than through
  `PermissionService`, so it decides nothing (see [Permission Catalogue Sync](permission-catalogue-sync.md)).
- **A resource's attachments outlive the resource.** They name it by type and key, with no foreign key, so deleting the
  record leaves them in place until they are detached, through `detachAll()` or by `authorization:prune`, which
  detaches those of every record that no longer exists, resolving the morph type to its model class as it does a
  grantee's, and reports each as `Resource\PolicyDetached`; a type that names no model class is reported and left, and
  a whole type's attachments are never pruned. Deleting the policy removes them with its row.
- **A boundary's policy cannot be deleted.** The policy observer refuses the delete with `BoundaryException`, naming
  every grantee it bounds, and the foreign key on `authorizable_boundaries.policy_id` restricts a delete made past the
  model; remove each boundary first. A boundary left by a grantee deleted past its model events keeps the policy
  undeletable until `authorization:prune` finds the grantee gone and removes it, counting it apart from the grants.
- **A guardrail's policy cannot be edited or deleted.** The policy observer refuses either with `GuardrailException`
  (`in_use`), naming every scope the policy caps, and the foreign key on `guardrails.policy_id` restricts a delete made
  past the model; remove each guardrail through `GuardrailService` first, then set the edited policy again.
- **No guardrail locks the guardrails.** The actor's right is decided through `check()`, but a check of exactly
  `authorization:guardrail.manage` is exempt from the guardrails: none is read for it, so a guardrail that does not
  allow the permission, one that denies it and one that cannot be read, a platform guardrail included, keep no actor
  from changing the guardrails of any scope, its own removal included. The actor's other denies and its boundaries
  still count.
- **The commands name no actor by default.** `authorization:grant`, `authorization:revoke` and `authorization:sync`
  take `--actor={morphType}:{key}`, which must name a row that exists; without it they record no actor. Given one,
  `authorization:grant` and `authorization:revoke` are delegated administration, decided as that actor with no
  session, while `authorization:sync` only records it on the events its writes dispatch.
- **The operation reads the routed request for its client.** `Operation::begin()` reads the container's current
  request, through `Support\RequestClient`, for the IP address and the user agent, as `Context\RoutedRequestContext`
  reads it for the `request` namespace: only when a delegated operation is begun with no client given, and it takes
  them only when that request is routed. A trusted operation reads nothing, and one begun in the console or a queued
  job, whose request is not routed, has no client; no service takes one. The request is read when the operation
  begins, never kept.
- **Each command names itself once.** Every package command declares its name in a public `NAME` constant
  (`PruneGrantsCommand::NAME` is `authorization:prune`) and builds its signature from it, so a schedule, a test or a
  sibling package refers to the constant and the two cannot drift; each command's test pins the name it registers.

## Implementation Anchors

- `Services\GrantService`, `Services\RoleService`, `Services\PermissionService`, `Services\PolicyService`.
- `Services\RoleExclusionService` and `Services\Support\RoleExclusionTable`: the pairs of exclusive roles and their
  writes.
- `Services\BreakGlassService`: the break-glass activations and their end.
- `Services\Support\GrantTable`: the scoped row writes, insert-or-ignore and the locked read-back.
- `Services\Support\RecordWriter`: the record saves and deletes, each in one transaction.
- `Enums\GrantTarget`: each kind's configured model, grant table and events.
- `Support\InlinePolicies` and `Observers\AuthorizablePolicyPivotObserver`: the grantee an inline policy belongs to, the
  refusals and its deletion with that grantee.
- `Services\ResourcePolicyService`, `Services\Support\ResourcePolicyTable` and `Support\PolicyPrincipals`: a
  resource's attachments, their scoped writes and the principals rule.
- `Services\BoundaryService`, `Services\Support\BoundaryTable` and `Support\PolicyBoundaries`: a grantee's boundaries,
  their scoped writes and the refused delete of a boundary's policy.
- `Services\GuardrailService`, `Services\Support\GuardrailTable`, `Services\Support\GuardrailAuthority` and
  `Support\PolicyGuardrails`: the guardrails of a scope, their writes, who may make them and the refused edit and delete
  of a guardrail's policy; `Support\PackagePermissions`: the permission the package declares for it.
- `Enums\GrantOutcome` and `Services\SyncResult`: what a call changed.
- `Observers\RoleObserver::assertNoHierarchyCycle()`: the locked, unscoped ancestor walk.

## Authoritative Tests

- `GrantServiceTest`, `GrantTableTest`, `GrantTargetTest`: idempotency, re-arming, scope, events, the transaction and
  the connection.
- `RoleServiceTest`, `RoleObserverTest`: the lock order, cycles across tenants, role permissions and guard parity.
- `PermissionServiceTest`, `PolicyServiceTest`, `RecordWriterTest`: the record writes, inline policies among them.
- `InlinePoliciesTest`, `AuthorizablePolicyPivotObserverTest`, `OwnerUniquenessTest`, `GrantPrunerTest`: the grantee an
  inline policy belongs to, its refusals on every write path, its name per grantee and its deletion with the grantee.
  `GrantPrunerTest` and `PruneGrantsCommandTest` also pin the pruning of a gone record's resource policies.
- `ResourcePolicyServiceTest`, `ResourcePolicyTableTest`, `PolicyPrincipalsTest`: a resource's attachments, their
  scope, idempotency, events and refusals.
- `BoundaryServiceTest`, `BoundaryTableTest`, `PolicyBoundariesTest`: a grantee's boundaries, their scope, one per
  scope, the replacement, events and refusals; `GrantServiceTest` and `GrantPrunerTest`: their removal with a deleted
  or pruned grantee.
- `GuardrailServiceTest`, `GuardrailTableTest`, `GuardrailAuthorityTest`, `PolicyGuardrailsTest`: the guardrails of a
  scope, the refusals, the events, who may change them and from where, and the refused edit and delete.
- `RoleExclusionServiceTest`, `RoleExclusionTableTest`: the pairs of exclusive roles, their refusals and events.
- `BreakGlassServiceTest`: the activations, their refusals, their end and their events.
- `HasRolesTest`, `HasPermissionsTest`, `HasPoliciesTest`, `ManagesPermissionsTest`: the traits delegate.

## Change Triggers

- A service is added, or a method's arguments, return value or refusals change.
- The scope a grant, revocation or sync is written in is worked out differently.
- An administration rule is added to or removed from what a delegated call is weighed by (see
  [Delegated administration](delegated-administration.md)).
- The permission catalogue sync moves onto `PermissionService`.
