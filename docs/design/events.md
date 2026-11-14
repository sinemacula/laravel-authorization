# Events

Every event the package dispatches implements one marker, `Contracts\AuthorizationEvent`, so one listener or one
audit mapper registration covers them all. Every event is a snapshot of plain values. The change events carry the actor
the caller named and the operation they belong to, and are dispatched only once the write commits; the decision events
carry references, names and ids, never a value the decision read, and are dispatched when the decision is made.

## Purpose

- **Decision events.** `DecisionEvaluated` for each decision `check()` makes that `events.decisions` selects (query
  scoping and `permissionsFor()` dispatch none), `AuthorizationFailed` whenever `authorize()` refuses. Both extend
  `DecisionEvent`, the abstract, readonly shape they share, which is never dispatched itself.
- **Record events.** `Role\Created`, `Role\Updated`, `Role\Deleted`, and the same three under `Permission\` and
  `Policy\`.
- **Role permission events.** `Role\PermissionGranted` (with the grant's expiry), `Role\PermissionRevoked` and
  `Role\PermissionExpiryChanged`, and `Role\PermissionExpired` when `authorization:prune` removes an expired grant.
- **Grant events.** Under `Identity\`: `RoleAssigned`, `RoleRevoked`, `RoleExpiryChanged`, `PermissionGranted`,
  `PermissionRevoked`, `PermissionExpiryChanged`, `PolicyAttached`, `PolicyDetached` and `PolicyExpiryChanged`. Each
  also implements `Contracts\IdentityEvent` and names its `grantee`, which for a policy attached to a role is the role.
- **Resource policy events.** Under `Resource\`: `PolicyAttached` and `PolicyDetached`, when a policy is attached to
  or detached from a resource or a whole resource type (AUTHZ-7.3), each with the resource's type, its key (null for
  the whole type), the policy, its name and the scope. A re-attachment with another reach dispatches `PolicyAttached`
  again, carrying the new reach, and `authorization:prune` dispatches `PolicyDetached` for each attachment of a record
  that no longer exists, with an operation that names no actor. Both extend `Resource\ResourcePolicyEvent`, the
  abstract, readonly shape they share, which is never dispatched itself. They name no grantee, so they implement
  `AuthorizationEvent` alone.
- **Boundary events.** Under `Identity\`: `BoundarySet` and `BoundaryRemoved`, when a policy is set as a principal's or
  an identity's permission boundary in a scope, or the boundary there is removed (AUTHZ-7.4), each with the grantee, the
  policy, its name and the scope. `BoundarySet` also carries `previous`, the policy the boundary replaced, or null for a
  new boundary or one whose reach alone changed; there is no separate replaced event. `BoundarySet` is dispatched only
  once the boundary's row is read back, never for an insert that wrote none. A grantee's boundaries removed with its
  other grants, once it is deleted, are each reported as `BoundaryRemoved` in that operation, and those of a grantee
  pruned as gone in an operation of their own, before its grants are revoked. Both
  extend `Identity\BoundaryEvent`, the abstract, readonly shape they share, which is never dispatched itself, and
  implement `IdentityEvent`, so the grantee's cached resolutions are refreshed as a grant's are.
- **Guardrail events.** Under `Guardrail\`: `GuardrailSet` and `GuardrailRemoved`, when a policy is set as a guardrail
  on a tenant or on the platform, or that guardrail is removed (AUTHZ-7.6), each with the policy, its name and the
  scope, and the actor in `operation`. Setting a policy where it is already a guardrail, or removing one that is not
  there, dispatches nothing, and `GuardrailSet` is dispatched only once the guardrail's row is read back. Both extend
  `Guardrail\GuardrailEvent`, the abstract, readonly shape they share, which is never dispatched itself. They name no
  grantee, so they implement `AuthorizationEvent` alone; the cached guardrails are refreshed through the version every
  guardrail entry shares.
- **Role exclusion events.** Under `Role\`: `ExclusionDeclared` and `ExclusionRemoved`, when two roles are declared
  mutually exclusive or that pair is removed (AUTHZ-11.8), each with the pair's two roles and their names, the lower
  key first, the tenant that owns the pair, and the actor in `operation`. Declaring a pair already declared, or
  removing one that is not, dispatches nothing, and a role deleted takes its pairs with it unreported, its deletion
  reported as `Deleted`. Both extend `Role\ExclusionEvent`, the abstract, readonly shape they share, and name no
  grantee: a pair hands out nothing, and nothing cached reads it.
- **Expiry events.** Under `Identity\`: `RoleExpired`, `PermissionExpired` and `PolicyExpired`, dispatched when
  `authorization:prune` removes an expired grant, with its expiry and an operation that names no actor (the sweep is
  system work).
- **Break-glass events.** Under `Identity\`: `BreakGlassActivated`, with the role, the scope, the activation's key, the
  justification code and the expiry, never the note; `BreakGlassSurrendered` and `BreakGlassRevoked`, with when it
  ended, only for an end that ended one; and `BreakGlassExpired`, when `authorization:prune` records the expiry of one
  that expired without ending, keeping its row, with an operation that names no actor. The actor is the granter, the
  grantee who surrendered or the revoker. Surrendered and revoked extend `Identity\BreakGlassEnded`, the abstract,
  readonly shape they share, which is never dispatched itself. Each implements `IdentityEvent`, naming the grantee
  (see [Break-glass](break-glass.md)).
- **`SystemOverrideUsed`.** A change to a system role, permission or policy that `forceSystem()` unlocked.

## Invariants

1. **One marker.** Every event class implements `AuthorizationEvent`; `AuthorizationMutation` extends it for every
   change event (all but the decision events and `SystemOverrideUsed`), and `IdentityEvent` extends that for the grant,
   boundary and break-glass events.

2. **Snapshots of plain values.** Every event is a `final readonly` class whose constructor takes only scalars, backed
   enums, arrays of scalars or of the package's value objects, those value objects (`Support\Operation`,
   `Support\Reference`, `Support\GrantScope`, `Support\DocumentDigest`, `Evaluation\StatementReference`) and dates.
   No event carries a model, a lazy relation, a secret or a condition or attribute value, so a listener sees what was
   written or decided whatever happens to the rows afterwards, and a queued listener serialises the event as it is.

3. **References.** A record (a grantee, a role, permission or policy, an actor, a tenant) is a `Reference`: its morph
   class under the application's morph map, never a hard-coded class name, and its key as a string, each at most 191
   bytes. The references every member of the suite writes therefore match.

4. **The call's actor and mode.** Every change event carries `operation`: `actor`, the acting context's principal, or
   null for trusted work (a reference a trusted command names for the record alone); `identity`, the identity behind
   it; `isTrusted`, true for a call made without an acting context; `impersonator`, whoever was impersonating the
   actor; and `actions`, the administration actions the call's changes fall under, decided through `check()` only when
   `isTrusted` is false (a trusted call names them too, a sync names both its grant and its revoke action, and a write
   made through a model outside the services, or `authorization:sync`, names none). The actor is never read from
   `Auth::user()` or the subject resolver. Every grant row the call writes records it in `granted_by_type` and
   `granted_by_id`. The commands that write take `--actor={morphType}:{key}`. A delegated call's decisions name the
   operation resource `authorization:operation:{operation id}`, so a decision and the write it allowed share the id.
   The operation an event carries never has a client: its `ip` and `userAgent` are null, since the client is personal
   data handed to the grant hook alone (see `docs/design/grant-scope.md`).

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
   transaction, in every scope and whether or not the grant had expired; the grantees are ordered by type and key. A
   deleted role's own policy attachments are each reported as `Identity\PolicyDetached`, as a deleted identity's grants
   are, and a deleted grantee's inline policies each as `Policy\Deleted`, in an operation of their own with no actor. A
   deleted policy's attachments to resources go with its row, through the foreign key, and are not reported one by one:
   `Policy\Deleted` stands for them. A policy in use as a permission boundary is never deleted: the delete is refused
   with `BoundaryException` before anything is read or written, so no `Policy\Deleted` and no `BoundaryRemoved` is
   dispatched for it. Nor is a policy in use as a guardrail, which is not edited either: the delete or the update is
   refused with `GuardrailException`, so no `Policy\Deleted` or `Policy\Updated` is dispatched for it until each
   guardrail is removed, each reported as `GuardrailRemoved`.

9. **Decisions as references (AUTHZ-15.3, AUTHZ-15.4).** A decision event carries `subject` and `identity`, references
   to the principal the decision was about and its identity, null for a guest and never filled from the authenticated
   user; `previewer`, whoever previewed it through `previewFor()` (see [Preview](preview.md)), null for a decision that
   is not a preview; the `action`; the `resource` as `type:id`, `type:*` or the name given; the `tenant` and
   `application` the decision was made in, as `TenantScope` held them where the pipeline decided it (the resource's own
   tenant, platform scope for a resource admitted from outside the request's tenant and for a delegated change to the
   platform, a scope put in place, or the request's, a guest's decision included), never read from its subject; its
   `effect` and `reason`; the `statements` that decided it, each a `StatementReference` naming its policy's name, the
   stored policy's key, its index and its sid and, for a statement of a resource policy, the resource that policy is
   attached to (`type:id` or `type:*`); `usedBreakGlass`, whether a grant that allowed it came through a live
   break-glass activation, and `activations`, the key of each such activation, sorted, never its note (see
   [Break-glass](break-glass.md)); and `keys`, the name of
   each condition key the decision tested, held or failed, and of each `${…}` reference named by a condition operand or
   resource pattern of a statement it assessed, each once and never its value (see [Explanations](explanations.md)).
   Neither the caller's context nor the decision, with its trace, is carried: the last decision holds the decision,
   stored before the event is dispatched, with its provenance (`Evaluation\DecisionProvenance`), so a listener that
   needs it reads `Authorization::lastDecision()` and `lastDecisionProvenance()`. Dispatching the event and storing the
   last decision are separate switches of `Evaluation\CheckBatch`: `check()` and `checkMany()` do both,
   `permissionsFor()` neither, and a preview's `permissionsFor()` dispatches alone (N86).

10. **Digests, not documents.** A policy event carries its document's version and the SHA-256 of its canonical JSON
    (keys sorted at every depth, lists in order, slashes and Unicode unescaped) as a `DocumentDigest`.
    `Policy\Updated` carries the digest after the update and, when the update rewrote the document, the one before
    it. `changes` never holds the document.

11. **Before and after.** The updated events carry `changes`: the fields the update changed, before and after, as plain
    values (dates as ISO 8601 strings in UTC, backed enums as their values).

12. **Every override is reported.** A change `forceSystem()` unlocked dispatches `SystemOverrideUsed` with the record,
    its name before the change, its tenant, the change allowed (`delete`, `unprotect`, `rename`, `document-rewrite` or
    `modify`) and the operation, alongside the record's own event and with the same operation.

13. **Audit accessors.** Every change event implements `Contracts\AuthorizationMutation`, so an audit mapper reads it
    through accessors rather than its properties: `operation()`, a stable identifier unique to the event class (such as
    `identity.role.assigned`, `role.permission.granted`, `policy.deleted`, `resource.policy.attached` or
    `guardrail.set`, listed in the README); `subject()`, the record the change is about (the grantee of a grant or
    boundary event, the role, permission or policy written, the role of a role permission event, the pair's first role
    of a role exclusion event, the resource record of a resource policy event and the tenant of a guardrail event, null
    for a whole resource type or the platform); `tenant()` and `application()`, the scope's for a grant, boundary,
    resource policy or guardrail event, the owning tenant and no application for the others; `grantees()`, whose access
    the change altered (the grantee, the role of a role permission event, the grantees a delete lists, a deleted
    permission's roles after them, else none); and `auditProperties()`, every other property, flat and serialisable
    through `Support\AuditProperties`: snake case keys, dotted keys for a scope, a digest or the before and after of an
    update, a reference as `type:id`, a date as ISO 8601 in UTC. It never holds the operation, which carries the client,
    a model or a closure, and refuses any object other than the package's value objects. The call that made the change
    is read from the event's operation through `operationId()`, `isTrusted()`, `actor()`, `actorIdentity()`,
    `impersonator()` and `occurredAt()` (in UTC); the call's IP address and user agent are personal data for the grant
    hook alone, so no accessor returns them. Each family implements the accessors once:
    `Events\Concerns\DescribesGrantChange` for the grant, boundary and break-glass events,
    `Events\Concerns\DescribesRecordChange` for the record, role permission and role exclusion events, and the resource
    policy and guardrail base classes for theirs, each reading the call through `Events\Concerns\DescribesOperation`;
    each event class names its own identifier.

14. **Selective decision events (N137).** Which decisions `DecisionEvaluated` reports is set by
    `authorization.events.decisions`: `denials`, `insufficient_authentication` and `previews` (each on by default),
    `allows` (`sensitive` by default, `all` or `none`) and `sensitive_actions` (exact catalogue action names, none by
    default). Each setting reports its kind of decision on its own, and a decision is reported when any setting that is
    on reports it. The event names why with `reportedBecause()`, an `Evaluation\Enums\DecisionReport`: the first
    reason, in the order break-glass, preview, insufficient authentication, denial, sensitive action, all allows, that
    applies to the decision and is reported; `isSensitiveAction()` says whether its action is listed, whatever the
    reason. Both are set as the event is dispatched (`Evaluation\DecisionReporting`) and held privately, so the payload
    and its properties are unchanged; an event made by hand names the most specific reason its decision has, as though
    every setting were on. The settings are read once for each batch that dispatches (none for a batch that dispatches
    nothing or has no dispatcher), so each decision costs a few comparisons, and filtering changes neither the decision
    nor the last decision: a bulk check reports one event for each reported decision, in the order of its checks (N70),
    and a preview's listing reports each action while `previews` is on, storing none (N86). `AuthorizationFailed` is not
    filtered: every refusal `authorize()` throws dispatches it, for the reason it has with every setting on, so a
    listener of both tells an observation from a failure by the event's class. An allow that used break-glass is
    reported whatever the settings, `allows: none` and a preview's listing with every setting off included, as
    `BREAK_GLASS` (N142); a listing that dispatches nothing reports none.

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
    $event->operation->actor;   // Reference to the acting principal, or null for trusted work
});

app(GrantService::class)->grantRole($user, 'editor'); // trusted work
```

## Failure / Edge Cases

- **Decision events are dispatched when the decision is made.** `DecisionEvaluated` and `AuthorizationFailed` are
  dispatched straight away, not after a commit: a denial is a fact even if the surrounding transaction rolls back. A
  subject that is no saved record, such as an unsaved model or an object that is not a model, is named by no reference.
  Which decisions `DecisionEvaluated` reports is set by `events.decisions` (invariant 14); by default an ordinary allow
  is not reported, so a listener that needs every allow sets `allows` to `all`.
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
- **Grants carry their scope.** Every grant event reports the tenant the grant holds in, or none for platform-wide,
  whether it also holds in the tenants below (`includeSubtree`, always true platform-wide), and its application, or
  none for every application. A grant re-made with another reach dispatches the granted event again, carrying the new
  reach. A boundary holds in every application, so its events' scope names none; one set again with another reach
  dispatches `BoundarySet` again, with no `previous`. A guardrail holds in every application and, on a tenant, always
  in the tenants below it, so its events' scope names no application and reaches below; on the platform it is
  `GrantScope::platform()`.
- **Refused changes are never reported.** A delegated change that is refused, and a guardrail change by an actor that
  does not hold `authorization:guardrail.manage` from above the scope, is refused inside the call's transaction before
  anything is written, so it dispatches no change event; the check that refused it is a decision like any other, so it
  dispatches `DecisionEvaluated`, and a delegated refusal `AuthorizationFailed`, straight away. The transaction rolls
  back, so an audit store must persist a denial outside it.

## Implementation Anchors

- `Contracts\AuthorizationEvent`, `Contracts\AuthorizationMutation`, `Contracts\IdentityEvent` and the classes under
  `Events\`.
- `Events\Concerns\DescribesGrantChange`, `Events\Concerns\DescribesRecordChange`, `Events\Concerns\DescribesOperation`
  and `Support\AuditProperties`: the audit accessors, the call accessors and the flat details.
- `Events\DecisionEvent`: the decision payload; `Evaluation\DecisionProvenance`: who a decision was about and where;
  `Evaluation\DecisionReporting`, `Evaluation\Enums\DecisionReport` and `Config\EventConfigValidator`: which
  decisions are reported, and why; `Evaluation\BreakGlassAttribution`: the activations behind an allow;
  `Evaluation\LastDecisionStore`: the last decision and its provenance; `Evaluation\CheckBatch`: the dispatch and
  store switches.
- `Support\Reference`, `Support\Operation`, `Support\GrantScope`, `Support\DocumentDigest`.
- `Support\OperationScope`: the call's operation and the after-commit dispatch.
- `Observers\RoleObserver`, `Observers\PermissionObserver`, `Observers\PolicyObserver` and
  `Observers\Support\RecordChanges`: the record events, the before and after, and the grantees a delete reads.
- `Enums\GrantTarget`: the grant events and the holders of a row.
- `Services\BoundaryService`: the boundary events; `Support\PolicyBoundaries`: the refused delete of a boundary's
  policy.
- `Services\GuardrailService`: the guardrail events; `Support\PolicyGuardrails`: the refused edit and delete of a
  guardrail's policy.
- `Services\RoleExclusionService`: the role exclusion events.
- `Services\BreakGlassService`, `Services\Support\ExpiredActivations`: the break-glass events.
- `Concerns\HasSystemProtection`: the override event.
- `Console\Support\ActorOption`: the commands' `--actor`.

## Authoritative Tests

- `EventSnapshotsTest`: every event implements the marker; every event, the decision events included, takes only plain
  values; every change event implements `AuthorizationMutation`, with a unique operation identifier and serialisable
  details.
- `AuditPropertiesTest`, `DescribesGrantChangeTest`, `DescribesRecordChangeTest`, `DescribesOperationTest` and each
  event class's own test: the audit and call accessors' values, and that none reports the call's client.
- `DecisionEventTest`, `DecisionEvaluatedTest`, `AuthorizationFailedTest`: the decision payload, and no value a decision
  read anywhere in the serialised event, and `reportedBecause()` and `isSensitiveAction()`; `DecisionReportingTest`,
  `DecisionReportTest` and `EventConfigValidatorTest`: which decisions each setting reports, the order of the reasons
  and the settings' checks; `DecisionProvenanceTest`, `LastDecisionStoreTest` and the manager's
  `AuthorizationManagerTest`: the provenance of the last decision; `CheckBatchTest`: the dispatch and store switches;
  `BreakGlassAttributionTest`: the activations an allow names, and its report, through a check, a bulk check, a
  listing and a preview's listing, cold and warm.
- `OperationScopeTest`: after-commit dispatch, nesting, rollback and the current operation.
- `ResourcePolicyServiceTest`, `PolicyAttachedTest`, `PolicyDetachedTest`, `ResourcePolicyEventTest`: the resource
  policy events and the shape they share, after commit and only for a change.
- `BoundaryServiceTest`, `BoundarySetTest`, `BoundaryRemovedTest`, `BoundaryEventTest`: the boundary events, the policy
  replaced and the shape they share, after commit and only for a change; `GrantServiceTest` and `GrantPrunerTest`: a
  deleted or pruned grantee's boundaries reported as removed; `PolicyObserverTest`: a boundary's policy refused
  deletion.
- `BreakGlassServiceTest`, `ExpiredActivationsTest`, `BreakGlassActivatedTest`, `BreakGlassSurrenderedTest`,
  `BreakGlassRevokedTest`, `BreakGlassEndedTest`, `BreakGlassExpiredTest`: the break-glass events and the shape the
  ended ones share, after commit and only for a change, and never the note.
- `GuardrailServiceTest`, `GuardrailSetTest`, `GuardrailRemovedTest`, `GuardrailEventTest`: the guardrail events and
  the shape they share, after commit and only for a change; `PolicyObserverTest`: a guardrail's policy refused editing
  and deletion.
- `RoleExclusionServiceTest`, `ExclusionDeclaredTest`, `ExclusionRemovedTest`, `ExclusionEventTest`: the role exclusion
  events and the shape they share, after commit and only for a change.
- `GrantServiceTest`, `RoleServiceTest`, `PermissionServiceTest`, `PolicyServiceTest`, `RecordWriterTest`: the actor,
  the grantor columns, one operation id per call, rollback and the morph map.
- `RoleObserverTest`, `PermissionObserverTest`, `PolicyObserverTest`, `RecordChangesTest`: the payloads, the deleted
  grantees and the digests.
- `HasSystemProtectionTest`: the override event.
- `InvalidationTest`, `OperationScopeTest`: the versions each write bumps, before and after its commit, and a rollback
  when the cache store fails.
- `ActorOptionTest`, `GrantRoleCommandTest`, `RevokeRoleCommandTest`, `SyncPermissionsCommandTest`: `--actor`.

## Change Triggers

- A change to which decisions name a break-glass activation, or to which of them are reported whatever the
  settings.
- Applications: the grant events report the application written.
- Grant expiry: its events join the set.
