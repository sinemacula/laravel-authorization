# Events

The events the package dispatches, reading a change for an audit log, and choosing which decisions are reported.

Every event the package dispatches implements `SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent`, so one
listener, or one audit mapper registration, covers them all. The grant and boundary events also implement
`IdentityEvent` and name their `grantee`; the guardrail events name no grantee, so they implement the marker alone:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;

Event::listen(static function (AuthorizationEvent $event): void {
    // Every role, permission, policy, grant and guardrail change, every override and every reported decision.
});

Event::listen(static function (RoleDeleted $event): void {
    $event->role;               // Reference: the role's morph type and key
    $event->grantees;           // a Reference to every grantee that held it
    $event->operation->actor;      // the acting principal's Reference, or null for trusted work
    $event->operation->identity;   // the identity behind the acting principal, or null
    $event->operation->isTrusted;  // true for a call made without an acting context
    $event->operation->actions;    // the administration actions its changes fall under, decided only when not trusted
    $event->operation->id;         // the same for every event of the call, and every decision made for it
});
```

The change events (roles, permissions and policies created, updated and deleted; permissions granted to and revoked from
a role; roles, permissions and policies granted to, revoked from and re-dated on a grantee; break-glass activations
activated, surrendered, revoked and expired; policies attached to and detached from a resource,
`Resource\PolicyAttached` and `Resource\PolicyDetached`; permission boundaries set and removed, `Identity\BoundarySet`
and `Identity\BoundaryRemoved`; guardrails set and removed, `Guardrail\GuardrailSet` and `Guardrail\GuardrailRemoved`;
and `SystemOverrideUsed`) are `final readonly` snapshots of plain values: a record is a `Reference`, its morph class
under your morph map and its key as a string, never a model, alongside names, the scope, expiries and times. An update
carries the fields it changed, before and after. A policy event carries its document's version and SHA-256 digest, never
the document. A delete lists every grantee that held the role, permission or policy, so the evidence says who lost
access.

Each is dispatched only once its write commits on the package's connection: inside your own transaction it waits for the
outermost commit, and a transaction that rolls back dispatches nothing. Every event of one service call carries the same
operation, with its id, its actor and identity, whether it was trusted, any impersonator and its actions; a write made
through a model outside the services is a trusted operation of its own with no actor. A change `forceSystem()` unlocked
dispatches `SystemOverrideUsed`, naming the record, the change and the actor.

## Reading a change for an audit log

Every change event also implements `SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation`, so an audit
mapper typed against it reads each change through the same accessors, without reading the event's properties. The
decision events and `SystemOverrideUsed` do not implement it:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;

Event::listen(static function (AuthorizationMutation $event): void {
    $event->operation();       // 'identity.role.assigned': the kind of change, stable and unique per event class
    $event->subject();         // Reference to the record the change is about, or null
    $event->tenant();          // Reference to the tenant it holds in, or that owns the record; null for the platform
    $event->application();     // the application it holds in, or null for every application
    $event->grantees();        // a Reference to every grantee whose access it changed, or none
    $event->auditProperties(); // ['role' => 'role:3', 'name' => 'editor', 'scope.include_subtree' => true, ...]

    // The call that made the change
    $event->operationId();     // the call's id, shared by every event it dispatched and every decision made for it
    $event->isTrusted();       // true for trusted system work, made without an acting context
    $event->actor();           // Reference to the acting principal, the reference a trusted command names, or null
    $event->actorIdentity();   // Reference to the identity behind the acting principal, or null
    $event->impersonator();    // Reference to whoever was impersonating the acting subject, or null
    $event->occurredAt();      // DateTimeImmutable: when the call was made, in UTC
});
```

`auditProperties()` returns every other detail of the event, flat and serialisable: each key is the property's name in
snake case, a scope, a document digest or the before and after of an update sit under dotted keys
(`scope.include_subtree`, `document.digest`, `changes.before.name`), a reference is written as `type:id`, a date as an
ISO 8601 string in UTC, and a list of references as a list of strings. It never holds a model, a closure or the
operation: the call that made the change is read through the call accessors above. The grantee, the grantees and the
tenant are left out, since the other accessors return them.

The IP address and the user agent the call came from are deliberately absent: they are personal data, carried to the
grant hook alone, so no accessor returns them and `auditProperties()` never holds them.

| Event                              | `operation()`                        | `subject()`                          | `grantees()`                     |
|------------------------------------|--------------------------------------|--------------------------------------|----------------------------------|
| `Identity\RoleAssigned`            | `identity.role.assigned`             | the grantee                          | the grantee                      |
| `Identity\RoleRevoked`             | `identity.role.revoked`              | the grantee                          | the grantee                      |
| `Identity\RoleExpiryChanged`       | `identity.role.expiry_changed`       | the grantee                          | the grantee                      |
| `Identity\RoleExpired`             | `identity.role.expired`              | the grantee                          | the grantee                      |
| `Identity\PermissionGranted`       | `identity.permission.granted`        | the grantee                          | the grantee                      |
| `Identity\PermissionRevoked`       | `identity.permission.revoked`        | the grantee                          | the grantee                      |
| `Identity\PermissionExpiryChanged` | `identity.permission.expiry_changed` | the grantee                          | the grantee                      |
| `Identity\PermissionExpired`       | `identity.permission.expired`        | the grantee                          | the grantee                      |
| `Identity\PolicyAttached`          | `identity.policy.attached`           | the grantee                          | the grantee                      |
| `Identity\PolicyDetached`          | `identity.policy.detached`           | the grantee                          | the grantee                      |
| `Identity\PolicyExpiryChanged`     | `identity.policy.expiry_changed`     | the grantee                          | the grantee                      |
| `Identity\PolicyExpired`           | `identity.policy.expired`            | the grantee                          | the grantee                      |
| `Identity\BoundarySet`             | `identity.boundary.set`              | the grantee                          | the grantee                      |
| `Identity\BoundaryRemoved`         | `identity.boundary.removed`          | the grantee                          | the grantee                      |
| `Identity\BreakGlassActivated`     | `identity.break_glass.activated`     | the grantee                          | the grantee                      |
| `Identity\BreakGlassSurrendered`   | `identity.break_glass.surrendered`   | the grantee                          | the grantee                      |
| `Identity\BreakGlassRevoked`       | `identity.break_glass.revoked`       | the grantee                          | the grantee                      |
| `Identity\BreakGlassExpired`       | `identity.break_glass.expired`       | the grantee                          | the grantee                      |
| `Role\Created`                     | `role.created`                       | the role                             | none                             |
| `Role\Updated`                     | `role.updated`                       | the role                             | none                             |
| `Role\Deleted`                     | `role.deleted`                       | the role                             | every grantee that held it       |
| `Role\PermissionGranted`           | `role.permission.granted`            | the role                             | the role                         |
| `Role\PermissionRevoked`           | `role.permission.revoked`            | the role                             | the role                         |
| `Role\PermissionExpiryChanged`     | `role.permission.expiry_changed`     | the role                             | the role                         |
| `Role\PermissionExpired`           | `role.permission.expired`            | the role                             | the role                         |
| `Permission\Created`               | `permission.created`                 | the permission                       | none                             |
| `Permission\Updated`               | `permission.updated`                 | the permission                       | none                             |
| `Permission\Deleted`               | `permission.deleted`                 | the permission                       | every grantee, then every role   |
| `Policy\Created`                   | `policy.created`                     | the policy                           | none                             |
| `Policy\Updated`                   | `policy.updated`                     | the policy                           | none                             |
| `Policy\Deleted`                   | `policy.deleted`                     | the policy                           | every grantee it was attached to |
| `Resource\PolicyAttached`          | `resource.policy.attached`           | the record, or null for a whole type | none                             |
| `Resource\PolicyDetached`          | `resource.policy.detached`           | the record, or null for a whole type | none                             |
| `Guardrail\GuardrailSet`           | `guardrail.set`                      | the tenant, or null for the platform | none                             |
| `Guardrail\GuardrailRemoved`       | `guardrail.removed`                  | the tenant, or null for the platform | none                             |
| `Role\ExclusionDeclared`           | `role.exclusion.declared`            | the pair's first role                | none                             |
| `Role\ExclusionRemoved`            | `role.exclusion.removed`             | the pair's first role                | none                             |

The table's `operation()` values are the cases of `SineMacula\Laravel\Authorization\Enums\MutationOperation`, so a
mapper can match on the enum, as in `MutationOperation::tryFrom($event->operation())`.

A grant, boundary, resource policy or guardrail event holds in its scope's tenant and application; a role, permission
or policy event holds in the tenant that owns the record, and a role exclusion event in the tenant that owns the pair,
each in no one application.

`DecisionEvaluated` and `AuthorizationFailed` implement the marker too, but are dispatched when the decision is made,
not after a commit: a denial is a fact even if the surrounding transaction rolls back. `DecisionEvaluated` reports the
decisions `check()` makes that `events.decisions` selects (see [Which decisions are
reported](#which-decisions-are-reported)), and `AuthorizationFailed` is dispatched whenever `authorize()` refuses. Both
are `final readonly` snapshots of the same references, names and ids (AUTHZ-15.3), never a model, the context the caller
passed, a session, or a condition or attribute value (AUTHZ-15.4):

```php
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;

Event::listen(static function (DecisionEvaluated $event): void {
    $event->subject;        // Reference to the principal the decision was about, or null for a guest
    $event->identity;       // Reference to the identity behind it, or null
    $event->previewer;      // Reference to whoever previewed it, or null for a decision that is not a preview
    $event->action;         // 'posts:update'
    $event->resource;       // 'post:42', 'post:*', the name given, or null for none
    $event->tenant;         // Reference to the tenant the decision was made in, or null
    $event->application;    // the application it was made in, or null
    $event->effect;         // DecisionEffect::ALLOW or DecisionEffect::DENY; $event->isAllowed() reads it
    $event->reason;         // the DecisionReason of a denial, or null for an allow
    $event->statements;     // the StatementReference of each statement that decided it (see below)
    $event->usedBreakGlass; // whether a grant that allowed it came through a live break-glass activation
    $event->activations;    // the key of each such activation, sorted, never its note; [] when it used none
    $event->keys;           // the context keys it read, such as ['resource.status', 'input.reason'], never their values
    $event->reportedBecause();   // the DecisionReport it was reported for, such as DecisionReport::DENIAL
    $event->isSensitiveAction(); // whether its action is one of events.decisions.sensitive_actions
});
```

The subject and the identity are taken from the subject the decision was about, null when it had none, and never from
the authenticated user, so a decision made with `for($user)` names `$user`. A record that is not saved is named by no
reference. The tenant and the application are the scope the decision was made in, never read from the subject: the
resource's own tenant for a check on a resource of the request's tenant or below it, platform scope for a resource
admitted from outside it and for a delegated change to the platform, a scope put in place around the check (with
`TenantScope::within()` or an `AuthorizationScope`), and otherwise the request's, a guest's decision included. Each
statement is named by its policy's name, the stored policy's key, its index and its sid and, for a statement of a
resource policy, the resource that policy is attached to (`type:id` or `type:*`). The keys are the condition keys the
decision tested, held or failed, and every `${…}` reference that an assessed statement's condition operands or resource
patterns name, each once: a policy that reads `resource.status` or interpolates `${principal.id}` puts that name on the
event, never the value. The decision itself, with its stage and its trace, is not on the event; a listener that needs it
for debugging reads `Authorization::lastDecision()`, which holds it by the time the event is dispatched, and
`Authorization::lastDecisionProvenance()` (see [The programmatic API](checking-access.md#the-programmatic-api)).

## Which decisions are reported

An application makes far more allows than anything else, and most of them say nothing an audit needs, so by default
`DecisionEvaluated` reports every denial, every insufficient authentication, every decision made through a preview and
the allows of the actions you list as sensitive, and no other allow. `config/authorization.php` sets which:

```php
'events' => [
    'decisions' => [
        'denials'                     => true,        // every denial
        'insufficient_authentication' => true,        // every denial whose only unmet requirement is authentication
        'previews'                    => true,        // every decision made through previewFor()
        'allows'                      => 'sensitive', // 'all', 'sensitive' (the listed actions alone) or 'none'
        'sensitive_actions'           => ['invoices:refund', 'authorization:role.grant'],
    ],
],
```

A listener that needs every allow, a usage report say, sets `allows` to `all`. An application whose listeners expect a
`DecisionEvaluated` for every check, allows included, sets `AUTHORIZATION_EVENTS_ALLOWS=all` and leaves the three
switches on.

Each setting reports its kind of decision on its own, and a decision is reported when any setting that is on reports
it. The event says why with `reportedBecause()`, a `DecisionReport`, naming the most specific reason that applies and
is reported, in this order: `BREAK_GLASS`, `PREVIEW`, `INSUFFICIENT_AUTHENTICATION`, `DENIAL`, `SENSITIVE_ACTION`, then
`ALL_ALLOWS`. A preview's denial is therefore reported as `PREVIEW` while `previews` is on, and as `DENIAL` while it is
off and `denials` is on; an allow of a sensitive action is `SENSITIVE_ACTION` with `allows` set to `all` as well, and is
not reported with `allows` set to `none`. `isSensitiveAction()` says whether the action is listed, whatever the reason
it was reported for, so an audit mapper can record the allows of sensitive actions alone.

An allow that used break-glass is always reported, whatever these settings say, `allows` set to `none` included, as
`BREAK_GLASS`. An allow used break-glass when a permission covering the action, or a policy whose statement allowed it,
is carried by a role the subject holds through a live activation, directly or through the role's ancestors, even when a
normal grant gives it too, or when a resource policy allowed it through a role selector naming such a role and no
selector names the subject itself; its event sets `usedBreakGlass` and lists the activations' keys under `activations`,
as `Authorization::lastDecision()->activations` does. A denial never used break-glass, nor does a decision about a
machine, one allowed by an identity's grants, or any decision while break-glass is switched off.

`sensitive_actions` names catalogue actions exactly, with no wildcard: each is letters, digits and `_ - : .`, and must
be declared by the package or by your permission enums or providers. Whether each is declared is checked at boot, as the
session scopes are, by reading the action catalogue, and only when the list names one; `authorization:check` lists the
setting as `checked_at_boot`. Every other value is checked as written: a switch is true or false, `allows` one of its
three values, and null is refused for each.

The settings are read once for each `check()`, bulk check or listing that reports its decisions, so each decision costs
a few comparisons more. Which decisions are reported changes nothing else: every decision is decided, and stored as the
last decision, as before, a bulk check reports the decisions it reports one event each in the order of its checks, and a
preview's listing stores none of its decisions and, while `previews` is on, reports each action it evaluates (see
[Preview](preview-and-explanations.md#preview)).

`AuthorizationFailed` is not filtered: it is dispatched for every refusal `authorize()` throws, whatever these settings,
and its `reportedBecause()` names the reason the refusal would be reported for with every setting on. A refusal is
usually reported by both events, so a listener of both tells an observation (`DecisionEvaluated`) from a failure
(`AuthorizationFailed`) by the event's class, and counts a refusal once.
