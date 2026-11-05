# Events

Every event the package dispatches implements one marker, `Contracts\AuthorizationEvent`, so one listener or one
audit mapper registration covers them all. The change events are snapshots of plain values, carry the actor the caller
named and the operation they belong to, and are dispatched only once the write commits.

## Purpose

- **Decision events.** `DecisionEvaluated` for every decision, `AuthorizationFailed` when `authorize()` refuses.
- **Record events.** `Role\Created`, `Role\Updated`, `Role\Deleted`, and the same three under `Permission\` and
  `Policy\`.
- **Role permission events.** `Role\PermissionGranted` (with the grant's expiry), `Role\PermissionRevoked` and
  `Role\PermissionExpiryChanged`, and `Role\PermissionExpired` when `authorization:prune` removes an expired grant.
- **Grant events.** Under `Identity\`: `RoleAssigned`, `RoleRevoked`, `RoleExpiryChanged`, `PermissionGranted`,
  `PermissionRevoked`, `PermissionExpiryChanged`, `PolicyAttached`, `PolicyDetached` and `PolicyExpiryChanged`. Each
  also implements `Contracts\IdentityEvent` and names its `grantee`.
- **Expiry events.** Under `Identity\`: `RoleExpired`, `PermissionExpired` and `PolicyExpired`, dispatched when
  `authorization:prune` removes an expired grant, with its expiry and an operation that names no actor (the sweep is
  system work).
- **`SystemOverrideUsed`.** A change to a system role, permission or policy that `forceSystem()` unlocked.

## Invariants

1. **One marker.** Every event class implements `AuthorizationEvent`; `IdentityEvent` extends it for the grant events.

2. **Snapshots of plain values.** Every change event is a `final readonly` class whose constructor takes only scalars,
   arrays of scalars or of references, the package's value objects (`Support\Operation`, `Support\Reference`,
   `Support\GrantScope`, `Support\DocumentDigest`) and dates. No event carries a model, a lazy relation, a secret or a
   condition or attribute value, so a listener sees what was written whatever happens to the rows afterwards, and a
   queued listener serialises the event as it is.

3. **References.** A record (a grantee, a role, permission or policy, an actor, a tenant) is a `Reference`: its morph
   class under the application's morph map, never a hard-coded class name, and its key as a string, each at most 191
   bytes. The references every member of the suite writes therefore match.

4. **The actor the caller passed.** Every change event carries `operation->actor`: the actor the management service
   call named, as a model or a reference, or null for console and system work. It is never read from `Auth::user()` or
   the subject resolver. Every grant row the call writes records it in `granted_by_type` and `granted_by_id`. The
   commands that write take `--actor={morphType}:{key}`.

5. **One operation per call.** Every event one service call dispatches carries the same `operation->id`, a UUID, and
   `operation->at`, when the call was made. A write made through a model outside the services is an operation of its
   own, with no actor, shared by the events of that one save or delete.

6. **After commit.** A change event is dispatched once its write commits, through `afterCommit()` on the package's
   connection, the connection every row it writes lives on. Inside an application transaction it waits for the
   outermost commit, and nested calls dispatch each event once there; a transaction that rolls back dispatches
   nothing. A write made while that connection has no transaction open has already committed, so its events are
   dispatched straight away, even while another connection's transaction is open.

7. **Nothing for a no-op.** Granting what is held, revoking what is not held and a sync that changes nothing dispatch
   nothing.

8. **Deletes say who lost access.** `Role\Deleted` lists every grantee that held the role and every permission it
   carried; `Permission\Deleted` every grantee that held the permission directly and every role that carried it;
   `Policy\Deleted` every grantee it was attached to. Each list is read before the row goes, inside the delete's
   transaction, in every scope and whether or not the grant had expired; the grantees are ordered by type and key.

9. **Digests, not documents.** A policy event carries its document's version and the SHA-256 of its canonical JSON
   (keys sorted at every depth, lists in order, slashes and Unicode unescaped) as a `DocumentDigest`.
   `Policy\Updated` carries the digest after the update and, when the update rewrote the document, the one before it.
   `changes` never holds the document.

10. **Before and after.** The updated events carry `changes`: the fields the update changed, before and after, as plain
    values (dates as ISO 8601 strings in UTC, backed enums as their values).

11. **Every override is reported.** A change `forceSystem()` unlocked dispatches `SystemOverrideUsed` with the record,
    its name before the change, its tenant, the change allowed (`delete`, `unprotect`, `rename`, `document-rewrite` or
    `modify`) and the operation, alongside the record's own event and with the same operation.

## Success Path

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;

Event::listen(static function (AuthorizationEvent $event): void {
    // Every event the package dispatches.
});

Event::listen(static function (RoleAssigned $event): void {
    $event->grantee;            // Reference: type 'user', id '42'
    $event->role;               // Reference to the role
    $event->name;               // 'editor'
    $event->scope;              // GrantScope::platform()
    $event->expiresAt;          // DateTimeImmutable in UTC, or null
    $event->operation->id;      // shared by every event of the call
    $event->operation->actor;   // Reference to the actor, or null
});

app(GrantService::class)->grantRole($user, 'editor', actor: $admin);
```

## Failure / Edge Cases

- **Decision events are not snapshots yet.** `DecisionEvaluated` and `AuthorizationFailed` implement the marker but
  still carry the principal object, the context and the result as they were evaluated, and are dispatched when the
  decision is made, not after a commit: a denial is a fact even if the surrounding transaction rolls back. Their
  payload is redesigned with the decision trace.
- **The resolution cache is invalidated around the commit.** `OperationScope::dispatch()` bumps the versions the
  events affect inside the transaction, so a store that fails rolls the write back, and again once it commits, before
  any listener runs, so an entry a concurrent check stored from the rows before the commit never holds (see
  `Cache\Invalidation`).
- **Raw writes report nothing.** A pivot written through a relation (`$role->permissions()->attach()`), a query builder
  update or delete, and `saveQuietly()` or `deleteQuietly()` dispatch no event.
- **A delete outside a transaction** reads its grantees and removes the row in separate statements; through the
  services both run in the call's transaction.
- **A role with children is never deleted** (D18), so no child's holders lose what a deleted role passed down; the
  children are moved or deleted first, each reported as its own update or delete.
- **Grants carry their scope.** Every grant event reports the tenant the grant holds in, or none for platform-wide;
  the application is always every application until applications are read.

## Implementation Anchors

- `Contracts\AuthorizationEvent`, `Contracts\IdentityEvent` and the classes under `Events\`.
- `Support\Reference`, `Support\Operation`, `Support\GrantScope`, `Support\DocumentDigest`.
- `Support\OperationScope`: the call's operation and the after-commit dispatch.
- `Observers\RoleObserver`, `Observers\PermissionObserver`, `Observers\PolicyObserver` and
  `Observers\Support\RecordChanges`: the record events, the before and after, and the grantees a delete reads.
- `Enums\GrantTarget`: the grant events and the holders of a row.
- `Concerns\HasSystemProtection`: the override event.
- `Console\Support\ActorOption`: the commands' `--actor`.

## Authoritative Tests

- `EventSnapshotsTest`: every event implements the marker; every change event takes only plain values.
- `OperationScopeTest`: after-commit dispatch, nesting, rollback and the current operation.
- `GrantServiceTest`, `RoleServiceTest`, `PermissionServiceTest`, `PolicyServiceTest`, `RecordWriterTest`: the actor,
  the grantor columns, one operation id per call, rollback and the morph map.
- `RoleObserverTest`, `PermissionObserverTest`, `PolicyObserverTest`, `RecordChangesTest`: the payloads, the deleted
  grantees and the digests.
- `HasSystemProtectionTest`: the override event.
- `InvalidationTest`, `OperationScopeTest`: the versions each write bumps, before and after its commit, and a rollback
  when the cache store fails.
- `ActorOptionTest`, `GrantRoleCommandTest`, `RevokeRoleCommandTest`, `SyncPermissionsCommandTest`: `--actor`.

## Change Triggers

- The decision payload: the subject as a reference, the deciding policy and statement, and the keys a decision
  depended on.
- Applications: the grant events report the application written.
- Grant expiry, boundaries, guardrails and break-glass: their events join the set.
