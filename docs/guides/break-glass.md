# Break-glass

Break-glass is opt-in emergency access (AUTHZ-11.7): a principal with the break-glass right grants itself, or another
person, a configured emergency role for a limited time, with a justification code from a configured list, reported
every time and never needing prior approval. It is off by default. To enable it, list the emergency roles under
`roles`, list at least one code under `justifications`, set `AUTHORIZATION_BREAK_GLASS_ENABLED=true`, and grant the
break-glass rights to whoever may use them.

**The settings.** `config/authorization.php` holds a `break_glass` block, checked at boot like every other:

```php
'break_glass' => [
    'enabled'         => env('AUTHORIZATION_BREAK_GLASS_ENABLED', false),
    'max_minutes'     => env('AUTHORIZATION_BREAK_GLASS_MAX_MINUTES', 60),
    'roles'           => [
        'incident-responder' => ['max_minutes' => 30],
        'database-admin'     => [],
    ],
    'justifications'  => ['incident', 'customer-escalation'],
    'notes'           => env('AUTHORIZATION_BREAK_GLASS_NOTES', false),
    'note_max_length' => env('AUTHORIZATION_BREAK_GLASS_NOTE_MAX_LENGTH', 500),
],
```

- `enabled` is a switch, false by default, read from `AUTHORIZATION_BREAK_GLASS_ENABLED` as written.
- `max_minutes` is the longest any activation lasts, a whole number of at least 1. A longer request will be refused,
  never shortened.
- `roles` maps each emergency role, named as a role is named anywhere, to its own `max_minutes`: from 1 up to the
  global maximum, or null or left out for the global maximum. A maximum above the global one is refused. Whether a
  role of that name exists is checked when it is activated, never at boot.
- `justifications` lists the codes an activation gives one of, each a lower-case letter, then lower-case letters,
  digits, `.`, `_` and `-`, of at most 64 characters, each once. It may be empty only while break-glass is disabled.
- `notes` says whether an activation may carry a free-text note, false by default, and `note_max_length` bounds it, a
  whole number of at least 1 (500 by default). A note is personal data: it is never cached, logged, put on an event or
  shown in an explanation.

Any other key is refused, as is null for any setting but a role's `max_minutes`. `authorization:check` reports each
setting on its own.

**The record.** Each activation is a row of its own in `break_glass_activations` (`tables.break_glass`, which
`tables.prefix` prefixes like every default name), created by the package's migration on its connection, beside any
normal grant of the same role and never merged with it. It holds the role, the grantee, who activated it (or no one),
the scope (the platform, or a tenant with or without its subtree, and an application or every application), the
justification code, the note, when it was activated and when it expires (both UTC), and, once it ends, when, by whom and
why (`surrendered`, `revoked`, or `expired`, which `authorization:prune` records). `Models\BreakGlassActivation` reads
and writes it. Run the package's migrations when you upgrade: the roles every check reads now include this table.

**How it grants.** While an activation has not ended and its expiry is still to come, its role counts for the grantee
exactly as a grant of the role in the activation's scope does, through the same resolution, cache and tenant chain:
`check()`, `checkMany()`, `permissionsFor()`, `whereAuthorized()`, `hasRole()`, the `role:` middleware and Blade all
see it, and denies, permission boundaries, guardrails and session caps still apply. The resolution cache never keeps
it past its expiry, and a change saved through the model is seen on the next check. Only a human principal is
counted: an activation naming a machine, or the identity behind a principal, grants nothing, and one naming half a
tenant applies nowhere. An explanation names a grant that came through an activation as `break_glass_permission` or
`break_glass_policy`, with the activation's key, and never the note. A decision an activation allowed names its key,
and its `DecisionEvaluated` is dispatched whatever the settings (see [Which decisions are
reported](events.md#which-decisions-are-reported)).

**Activating and ending.** `Services\BreakGlassService` writes and ends activations:

```php
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Services\BreakGlassService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

$breakGlass = app(BreakGlassService::class);
$actor      = ActingContext::current();
$scope      = new GrantScope(Reference::of($tenant)); // the tenant and its subtree, every application

$activation = $breakGlass->activate($user, 'incident-responder', $scope, 20, 'incident', actor: $actor);

$breakGlass->surrender($activation, $actor); // by the grantee alone
$breakGlass->revoke($activation, $actor);    // by a holder of the revoke right
```

- `activate()` writes a record of its own, live from now for exactly the minutes given (in UTC), naming the acting
  principal as its granter, or no one for a trusted call. A platform-wide scope reaches every tenant.
- The rights are `authorization:break-glass.activate` (for oneself), `authorization:break-glass.grant` (for another)
  and `authorization:break-glass.revoke` (to end another's), decided through `check()` in the activation's tenant and
  application, across its reach. Holding the right is enough: the rank, self and possession rules of a role grant do
  not apply, while denies, boundaries, guardrails and caps still limit what the role grants. A call with no acting
  context is trusted and skips the right, but none of the limits below.
- Each limit refuses with `BreakGlassRefusedException`, whose `getReason()` names it: break-glass disabled, a machine
  or a model read as another subject's identity, a role not listed under `roles`, minutes below 1 or above the
  role's maximum (never shortened), a justification not listed, a note while `notes` is false or one longer than
  `note_max_length` characters, and a scope naming half a tenant. An unknown role throws `UnknownRoleException`, an
  unsaved grantee `InvalidGranteeException`, and a role is held to its owner and guard as a grant of it is.
- An activation that would leave the grantee holding both roles of a pair of mutually exclusive roles where their
  reach overlaps is refused with `RoleExclusionConflictException`, trusted or delegated, and nothing is written (see
  [Separation of duties](separation-of-duties.md#separation-of-duties)).
- The grant hooks are asked about an activation as about a grant of its role in its scope until its expiry, and a
  hook's refusal refuses it. A delegated call locks what a delegated role grant locks, in the same order.
- `surrender()` is for the grantee alone, acting as itself; anyone else is refused, as is the grantee while
  impersonated. `revoke()` needs the revoke right, or a trusted call. Each returns how many it ended: an activation
  already ended or expired changes nothing and returns 0.

**Events.** Each activation dispatches `Identity\BreakGlassActivated`, carrying the role, the scope, the activation's
key, the justification code and the expiry, never the note. A surrender or revocation that ended one dispatches
`Identity\BreakGlassSurrendered` or `Identity\BreakGlassRevoked`, with when it ended; ending one already ended or
expired dispatches nothing. The operation's actor is the granter, the grantee who surrendered or the revoker, and none
for a trusted call. `authorization:prune` records the expiry of every activation that expired without ending, keeping
its row, and dispatches `Identity\BreakGlassExpired` with no actor. Each is dispatched once its write commits, never for
a refusal or a rollback, whether break-glass is enabled or not.

**Listings, reviews and deletion.** The grant scope query's answers and its lists of grantees reaching or within a
tenant count a live activation as a grant of its role in its scope, as a check does: none while break-glass is off,
none of a machine, and an identity's reaches none of its principals. The access reviews list every activation not
ended or expired, whether break-glass is on or off, since it grants again once it is on: each is a row of its own
beside any grant of the same role, with its own `source_key`, `expires_at` and `granted_by`, and a `break_glass`
field holding its key (`activation`) and justification code, never the note; its `usage` is always `unknown`. Deleting
a role deletes its activations, and `Role\Deleted` lists their grantees among the role's, each once. Whether a grant
widens what an identity holds, for the grant hooks, never counts an activation as a grant already held, and grant
usage tracking never counts one as the use of a role grant.

**Switching it off.** While `enabled` is false no activation counts anywhere, at once: checks, listings, query scopes
and delegated administration all read none, and the rows stay for audit. The setting is read once a request or job,
and the resolution cache keeps what it resolved while break-glass was on apart from what it resolved while off, so
switching it either way is seen on the next request. `activate()` refuses while it is off; an activation can still
be ended.

See [Break-glass](../design/break-glass.md) for the invariants.

See [Grant scope](../design/grant-scope.md) for the design.
