# Management Services

Every write of a role, permission, policy or grant goes through one of four injectable services, so each write runs
in one transaction on the package's connection, reads the configured models and reports only what it changed. The
identity traits, the role's permission helpers, the grant and revoke commands and the Spatie import all delegate to
them. The one exception today is `authorization:sync`, which writes the permission catalogue through the permission
model in its own transaction on the package's connection; it moves onto `PermissionService` later.

## Purpose

- `RoleService`: create, rename, describe, re-parent, delete and list roles; grant, revoke and sync the permissions a
  role carries.
- `PermissionService`: create, rename, describe, delete and list permissions.
- `PolicyService`: create, rename, describe, rewrite, delete and list policies.
- `GrantService`: grant, revoke and sync roles, permissions and policies to a grantee, with an optional expiry.

Each is a final class bound as a singleton (it holds no state), resolved from the container or injected. Every public
method takes the actor making the call as an optional `$actor`, a model or a `Support\Reference`: null for console and
system work. Every event the call dispatches carries it, and every grant row it writes records it in
`granted_by_type` and `granted_by_id`. It is never read from the authenticated user or the subject resolver. The
events themselves are described in [Events](events.md).

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
   platform scope) with the same expiry changes nothing and is reported as `GrantOutcome::UNCHANGED`; a concurrent
   duplicate is the same case, so it never surfaces a unique-constraint violation. A role's permissions are attached
   through the role permission pivot, so guard parity is enforced, inside a savepoint that a concurrent duplicate rolls
   back alone.

4. **Expiry.** Re-granting a grant that has expired re-arms it with the new expiry (`REARMED`). A different expiry on
   a live grant is a change of its own (`EXPIRY_CHANGED`). A sync grants what is missing with the sync's expiry,
   re-arms a listed grant that has expired with the same expiry, leaves a live grant as it is, and revokes what is not
   listed. A sync given no expiry, as every trait sync is, re-arms a lapsed temporary grant as a permanent one.

5. **Platform-wide only.** The grant tables carry tenant and application columns, but nothing reads them yet, so a
   grant in a tenant or application scope would count everywhere. The services therefore take no tenant or
   application argument and write platform-wide grants for every application only. A grant reads only the
   platform-wide row as held, so a scoped row written by hand is never taken for it. A revocation removes the
   grantee's rows for the target in every scope, since each of them counts platform-wide today.

6. **Reported once it commits, and nothing for a no-op.** Each call is one operation: every event it dispatches
   carries the same operation id and the caller's actor, and is dispatched once the write commits on the package's
   connection, at the outermost commit when the call runs inside an application transaction, and never when that
   transaction rolls back. Only a write that changed something is reported: granting what is held, revoking what is
   not held and a sync that changes nothing dispatch nothing. A re-armed grant or a changed expiry dispatches the
   granted event as well as the expiry-changed one. Every dispatched event bumps the resolution cache versions it
   affects, so the change takes effect on the next check. Record writes go through the models, so their observers
   report them, as part of the call's operation.

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

9. **A name reaches every held row.** A role or permission name answers every row of it under the guard, the current
   tenant's and the platform's alike. A revocation by name revokes each of them the grantee or role holds, and a sync
   that names one keeps each held row of the name, granting the row the lookup ranks first only when none is held.

## Success Path

```php
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;

$roles  = app(RoleService::class);
$grants = app(GrantService::class);

$editor = $roles->create('editor', 'web', 'Edits posts', actor: $admin);
$roles->grantPermission($editor, 'posts:update', actor: $admin);

$grants->grantRole($user, $editor, now()->addMonth(), actor: $admin); // GrantOutcome::GRANTED
$grants->grantRole($user, $editor, now()->addMonth(), actor: $admin); // UNCHANGED if the expiry is the same
$grants->syncPermissions($user, ['posts:delete'], actor: $admin);     // SyncResult
$grants->revokeRole($user, 'editor', actor: $admin);                  // 1
```

The trait methods (`assignRole()`, `givePermission()`, `attachPolicy()`, `$role->givePermission()` and the rest) keep
working: each forwards to the matching service method with no actor.

## Failure / Edge Cases

- **Raw relation writes bypass the services.** `$user->roles()->attach()`, `$role->permissions()->sync()` and their
  kin write the pivot directly: no transaction, no idempotency, no event and a stale resolution cache. They are
  unsupported for any change that must be audited.
- **A grantee whose class is not loadable** is named with `Reference` (its morph type and key), as the Spatie
  import does for Spatie's `model_type` and `model_id`. A reference carries no guard.
- **Without the service provider** the traits refuse to write (`LogicException`) rather than lose the write.
- **List methods are reads** and run outside a transaction. They take the actor like every other method, so the
  delegated administration checks can read it there too.
- **`authorization:grant` gives no expiry**, so granting a role the identity holds on a temporary or expired grant makes
  it permanent and is reported as granted; only a role already held with no expiry is reported as held.
- **`authorization:sync` writes directly.** The permission catalogue sync saves and deletes through the permission
  model, in one transaction on the package's connection and as one operation, rather than through
  `PermissionService`.
- **The commands name no actor by default.** `authorization:grant`, `authorization:revoke` and `authorization:sync`
  take `--actor={morphType}:{key}`, which must name a row that exists; without it they record no actor.

## Implementation Anchors

- `Services\GrantService`, `Services\RoleService`, `Services\PermissionService`, `Services\PolicyService`.
- `Services\Support\GrantTable`: the platform-wide row writes, insert-or-ignore and the locked read-back.
- `Services\Support\RecordWriter`: the record saves and deletes, each in one transaction.
- `Enums\GrantTarget`: each kind's configured model, grant table and events.
- `Enums\GrantOutcome` and `Services\SyncResult`: what a call changed.
- `Observers\RoleObserver::assertNoHierarchyCycle()`: the locked, unscoped ancestor walk.

## Authoritative Tests

- `GrantServiceTest`, `GrantTableTest`, `GrantTargetTest`: idempotency, re-arming, scope, events, the transaction and
  the connection.
- `RoleServiceTest`, `RoleObserverTest`: the lock order, cycles across tenants, role permissions and guard parity.
- `PermissionServiceTest`, `PolicyServiceTest`, `RecordWriterTest`: the record writes.
- `HasRolesTest`, `HasPermissionsTest`, `HasPoliciesTest`, `ManagesPermissionsTest`: the traits delegate.

## Change Triggers

- Scoped grants (tenant and application): the services gain scope arguments, and revocation narrows to the scope it
  names.
- Delegated administration: the services check the actor before they write.
- The permission catalogue sync moves onto `PermissionService`.
