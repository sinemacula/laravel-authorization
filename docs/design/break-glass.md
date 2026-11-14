# Break-glass

## Purpose

Break-glass is opt-in emergency access: a principal with the break-glass right grants itself, or another person, a
configured emergency role for a configured maximum time, with a justification code from a configured list. It is made
of:

1. **Storage, configuration and resolution**: the `break_glass` settings, validated at boot; the activations table and
   its model; and the resolution that reads a live activation as a grant of its role.
2. **Activation and revocation**: the service that activates, surrenders and revokes, its rights, its limits, the
   grant hooks and its concurrency, and the switch that stops every activation at once.
3. **Expiry, reviews and attribution**: the lifecycle events, the listings and access reviews of activations, and the
   attribution of decisions to the activations behind them.

This note records the invariants they fix.

## Invariants

1. **An opt-in switch.** `break_glass.enabled` is a switch, false by default, read from
   `AUTHORIZATION_BREAK_GLASS_ENABLED` and never cast: anything but a boolean is refused. True is accepted at boot
   with the block's other checks (invariant 2), at least one justification code among them.

2. **The settings fail closed.** The block sets only `enabled`, `max_minutes`, `roles`, `justifications`,
   `notes` and `note_max_length`; any other key is refused under its own path, and so is a key a role's entry sets
   beside `max_minutes`. Whole numbers are ints or strings written as whole numbers; switches are booleans; null is
   refused everywhere but a role's `max_minutes`, where it means the global maximum. `max_minutes` is at least 1 (60 by
   default). A role's `max_minutes` is from 1 up to the global maximum, and one above it is refused, never truncated.
   A role is named as a role is named anywhere (`ValidatesAuthorizationName`); whether a role of that name exists is
   checked when it is activated, since boot reads no database. `justifications` is a list of distinct codes, each a
   lower-case letter, then lower-case letters, digits, `.`, `_` and `-`, of at most 64 characters; it may be empty
   only while break-glass is disabled. `notes` is a switch, false by default, and `note_max_length` at least 1 (500 by
   default). `BreakGlassConfigValidator::read()` reads the block through the same checks after boot, and
   `authorization:check` checks each setting on its own (`Diagnostics\Checks\BlockChecks`).

3. **One record per activation.** Each activation is a row of its own in `tables.break_glass` (default
   `break_glass_activations`, prefixed by `tables.prefix` as every default name is, bounded at 47 characters by its
   longest built name, `_role_id_foreign`), keyed by a UUID, beside any role grant of the same role, never
   deduplicated and never rewriting a role grant. It names the role, the grantee (morph type and key), the granter
   (or none), the scope (both tenant columns null for the platform, else a tenant and `include_subtree`), the
   application (or every application), the justification code, the note (or none), `activated_at` and `expires_at`
   (both UTC; an activation always expires), and, once it ends, `ended_at`, `ended_by` and `end_reason`
   (`surrendered`, `revoked` or `expired`). The reference columns compare their exact bytes on every database
   (`ExactReferences`). A role's deletion deletes its activations.

4. **Live means not ended and not expired.** An activation counts while `ended_at` is null and `expires_at` is after
   now, compared in UTC (`Database\BreakGlassActivations::live()`). Expiry is exact: it needs no sweep (one only
   records it, invariant 15), and a resolution that counts an activation lives no longer than its expiry, as for a
   grant's.

5. **It grants through the role grant path.** A grantee's `roles()` relation reads its role grants and its live
   activations as one set of rows (`BreakGlassActivations::roleGrants()`, joined in place of the role grant table by
   `GrantRelation::readingRows()`), so an activation reaches every check, bulk check, `permissionsFor()` listing,
   `whereAuthorized()` query, role check and explanation exactly as a grant of its role in its scope would: the
   role's ancestry, permissions and policies, the tenant chain with `include_subtree`, the application, the resolution
   cache and its versions. Denies, boundaries, guardrails, session caps and tenant admission apply to it as to any
   grant. `whereAuthorized()` reads each activation's tenant among the anchors of the subject's sources
   (`Query\ScopeAnchors`), and refuses unless the table's tenant columns compare bytes (`Query\ScopeClasses`). A write
   through the relation still goes to the role grant table.

6. **Delegated administration weighs it as a grant.** What limits an administrator reads a live activation as it reads
   a role grant: the denies on the roles the actor holds across a reach (`Administration\PossessionLimits`, the
   principal's activations alone, never its identity's or a machine's), the rank a target or a definition's holders
   hold across a reach (`Administration\RankComparison::rankAcrossAll()`), the holders a change to a role reaches
   (`Administration\AffectedHolders`), and the authority rows a delegated operation locks and pins
   (`Administration\AuthorityRows`). The rank and the holders read a machine's activations too, which can only refuse
   more. Whether a grant only shortens one already held (`Administration\Narrowing`) is judged against role grants
   alone, since a grant is a row of its own and never shortens an activation.

7. **Only a human principal.** An activation naming a machine (`AuthorizableMachine`) counts for nothing. Nor does
   one naming a model read as another subject's separate identity: `SubjectGrants` marks the identity it reads
   (`BreakGlassActivations::markIdentity()`, scoped to the request or job), so none of its activations reaches the
   principal, and the instance counts none for the rest of the request or job; its resolutions are kept under kinds of
   their own (prefixed `identity-`) so they never mix with those of the same grantee read as a subject. An activation
   naming half a tenant applies nowhere, as a grant row naming one does not.

8. **A change is seen on the next check.** A save or delete through `Models\BreakGlassActivation` bumps the versions
   a grant to its grantee bumps, the one it named before a move included, at once and again after the caller's
   transaction commits (`Observers\BreakGlassActivationObserver`). A row written to the table by other means bumps
   nothing, as a grant row written so does not.

9. **Provenance without the note.** Each role read through an activation carries the activation's key on its pivot
   (`break_glass_id`, null for a role grant). An explanation names such a route as `break_glass_permission` or
   `break_glass_policy`, with the activation's key under `activation`, and never the note. Usage tracking starts no
   route from an activation, so its use never counts as the use of a role grant. The note is hidden from the model's
   array and JSON forms, and is never cached, logged or put on an event.

10. **Off means none counts.** While `enabled` is false no activation counts anywhere, at once, and the rows
    stay: `BreakGlassActivations::isCounted()` counts none, `live()` reads none, so the roles relation, delegated
    administration (possession limits, rank, affected holders, authority rows) and `ScopeAnchors` read none either.
    Whether break-glass is on is read through `BreakGlassConfigValidator::read()` once a request or job, when the
    container builds the scoped `BreakGlassActivations` (`isEnabled()`), never once a check; without that record,
    none counts. The resolution cache built in the same request or job keeps its persistent entries under
    `{prefix}:break-glass` while break-glass is on and under `{prefix}` while it is off, sharing the version tokens, so
    an entry that counted an activation never reaches a request in which none counts, nor the reverse; the memo lasts
    no longer than the request whose state it was built in, and its hit costs what it did.

11. **The write path.** `Services\BreakGlassService` writes every activation and ends it, through the model, so the
    observer bumps the grantee's versions (invariant 8). `activate()` refuses with `BreakGlassRefusedException`, its
    `BreakGlassRefusal` naming why, while break-glass is disabled, for a machine or a model read as another subject's
    identity, a role not listed, minutes below 1 or above the role's maximum (never shortened), a justification not
    listed, a note while `notes` is false or one longer than `note_max_length` characters, and a scope naming half a
    tenant; an unknown role throws `UnknownRoleException` and an unsaved grantee `InvalidGranteeException`. It writes
    `activated_at` now and `expires_at` now plus the minutes, in UTC, the acting principal as the granter (none for a
    trusted call), the scope (a platform-wide one always reaching below) and the application. `surrender()` ends an
    activation for its grantee alone, acting as itself and not impersonated (`NOT_GRANTEE` otherwise), and `revoke()`
    for a holder of the revoke right or a trusted call; either takes the activation or its key, throws
    `ModelNotFoundException` for a key that names none, records `ended_at`, `ended_by` and `end_reason`, and may end
    an activation while break-glass is disabled. Each returns how many it ended, as a revocation does: one already
    ended or expired changes nothing and returns 0. A surrender's operation is begun with the grantee's acting
    context, so it is delegated and names the grantee as its actor, though it decides no right. An activation
    dispatches `Identity\BreakGlassActivated` (the role, scope, key, justification code and expiry, never the note), and
    an end that ended one `Identity\BreakGlassSurrendered` or `Identity\BreakGlassRevoked` (with `endedAt`), through
    `OperationScope::dispatch()` inside the operation, so each fires once the write commits and never for a refusal, an
    end that changed nothing or a rollback, whether break-glass is enabled or not. The operation's actor is the granter,
    the grantee who surrendered or the revoker, none for a trusted call.

12. **Holding the right is the gate.** A delegated activation is decided through `check()` on
    `OperationResource::breakGlass()`, in the activation's tenant and application, under
    `authorization:break-glass.activate` for the actor itself or `authorization:break-glass.grant` for another, and a
    delegated end under `authorization:break-glass.revoke`. The administration stage weighs them by the scope rule
    alone (`OperationConstraints`): the actor must hold the right across the activation's reach, an end only narrows,
    and neither rank, the self rule nor what the role hands out is weighed. Denies, boundaries, guardrails and caps
    still apply to what the activated role grants. A trusted call skips the right and none of the other refusals.

13. **Hooks and locks as a grant.** The grant hooks are asked about an activation as about a grant of its role in its
    scope until its expiry (`Hooks\WideningPhase`, a `ProposedGrant` under `authorization:role.grant`), before any
    lock, and checked again with locking reads after a delegated call's right is decided and before the role's row is
    locked; a hook's refusal refuses it. A delegated activation or end locks the actor's authority, then the grantee's
    rows and the role (`DependencyPins`), as a delegated role grant does, and every activation locks the role's row
    shared before it writes, so a deletion of the role either waits and takes the activation with it or refuses it as
    `UnknownRoleException`; a revocation of the right or another activation meanwhile has a delegated call tried again.

14. **The grantee must be able to hold the role.** `BreakGlassService::assertHoldable()` holds the role to what a grant
    of it is held to (its owner's tenant and below, the grantee's guard). Once the role's row is locked shared,
    `ExclusionGuard::assertActivatable()` refuses an activation that would leave the grantee holding both roles of a
    declared pair where their reach overlaps with `RoleExclusionConflictException` (see [separation of
    duties](separation-of-duties.md)). The activation so locks its role, then the pair, then the rows the report reads,
    in a grant's order: two trusted activations of one role share the role's lock, and a trusted one racing a grant or
    an activation of its pair's other role queues on the pair. An update lock on the role would deadlock with that
    write, which locks the pair and then reads the role shared; a delegated activation has taken one through its pins,
    as a delegated grant has, so it can still be refused as a deadlock there (see invariant 12 of separation of duties).

15. **An expiry is recorded, never pruned.** `authorization:prune` (`Services\GrantPruner`, through
    `Services\Support\ExpiredActivations`) sets `ended_at` to `expires_at`, `end_reason` to `expired` and `ended_by`
    to null on every activation that expired without ending, whether break-glass is enabled or not, keeps the row, and
    dispatches one `Identity\BreakGlassExpired` for each, with no actor, a chunk at a time, each chunk one operation. It
    writes through a query, and each event's dispatch bumps the grantee's versions as any grant event's does. It writes
    only where `ended_at` is still null, so an activation a surrender or revocation ended meanwhile is neither
    overwritten nor reported. One naming half a tenant is recorded and counted with no event. `--pretend` counts
    them, and `PruneResult::$activations` reports how many.

16. **A decision names the activations behind it.** An allow used break-glass when a permission of the
    principal's that covers the action, or a policy whose statement allowed it, is carried by a role the principal
    holds through a live activation, directly or through the role's ancestry, or when a resource policy's statement
    allowed it through a role selector naming such a role and no selector names the subject itself; one held through
    a role grant as well still counts, so an emergency use is never hidden. The decision names the key of each such
    activation, sorted (`Decision::$activations`), and its event says `usedBreakGlass` and carries them as
    `activations`, never the note. A denial, a decision of a machine or of an identity's grants, and any decision
    while break-glass is disabled name none. The resolution reads which activation is behind each permission, policy
    and role key from the rows it already reads, by role only when a role came through an activation
    (`BreakGlassActivations::behind()`); while break-glass is enabled the resolution cache keeps them beside the entry
    (`ResolutionCache::activationsOf()`), and the pipeline notes the principal's as they resolve, before the scope a
    resource's policies or guardrails are read in empties the memo (`BreakGlassAttribution`). Naming them costs no
    query, and a principal holding no activation is resolved as before. `DecisionEvaluated` reports such an allow
    whatever `events.decisions` says (`DecisionReport::BREAK_GLASS`), a preview's listing included; a listing that
    dispatches nothing reports none.

17. **Listings count a live activation.** The grant scope query (`Services\GrantScopeQuery`, through
    `Support\GrantRoots`) counts a live activation (`BreakGlassActivations::live()`) as a grant of its role in its
    scope, as a check does: `forIdentity()` its principals', `hasGrantIn()` the principal's, never an identity's or a
    machine's, and `granteesReaching()` and `granteesWithin()` list the grantee of every live activation but a
    machine's, once beside any grant, in the same one query. None counts while break-glass is disabled.

18. **The widening counts none.** Whether a grant widens what an identity holds (`Hooks\WideningClassifier`) reads
    role grants alone: an activation is never a grant already held, so a grant beside one widens as without it.

19. **Reviews list every unexpired activation.** The access reviews (`Reviews\Support\GrantRows::held()`, read by
    `HolderRoutes`, `HoldingRoutes` and `StoredRows`, through `RoleChains` and `RoleCarriers` as a grant is) list every
    activation not ended or expired at the review's instant, whatever the switch, since it grants again once
    break-glass is enabled, as separation of duties counts it: a row of its own beside any grant of the same role, keyed
    by the activation, ordered after a grant of the same scope, with its expiry and granter as the row's own and
    `break_glass { activation, justification }`, never the note. A machine's, or one naming half a tenant, is listed as
    such a grant is; an identity's never reaches a principal's holdings. Its `usage` is `unknown`.

20. **Usage never counts one.** Grant usage tracking starts no route from an activation (`Usage\RouteSources`), so
    its use is never a role grant's, and `Usage\UsagePruner` matches usage against the grant tables alone, so an
    activation keeps no use alive.

21. **A role's deletion reports its activations.** `Enums\GrantTarget::holders()` lists the grantees of a role's
    activations not ended or expired, which the deletion deletes, beside its grantees, each once, so
    `Role\Deleted::grantees()` names them. `Services\GrantPruner` never deletes an activation, a grantee that no
    longer exists included: it only records an expiry (invariant 15).

## Success Path

1. An application lists `incident-responder` under `break_glass.roles` and `incident` under `justifications`, and
   sets `AUTHORIZATION_BREAK_GLASS_ENABLED=true`, which is accepted at boot.
2. An administrator holding `authorization:break-glass.grant` activates the role for a principal in a tenant with its
   subtree for 60 minutes through `BreakGlassService::activate()`, which writes a row of `break_glass_activations`.
3. A check in that tenant, or below it, reads the role through the principal's `roles()`, and allows what the role's
   permissions allow, unless a deny, a cap or a guardrail refuses it; a check anywhere else does not. Each such allow
   names the activation, and its `DecisionEvaluated` is dispatched whatever the settings, with `usedBreakGlass` set.
4. The principal surrenders it, or an hour later the cached resolution has lapsed, and the next check allows nothing
   through the activation.

## Failure / Edge Cases

- `enabled` true with no justification code, a role's maximum above the global one, an unknown key, a malformed code,
  a duplicate code, or a value written loosely is refused at boot under its path, and by `read()` after boot.
- An activation breaking a limit is refused before anything is written, each with its reason; a hook's refusal, a
  refused right, a role deleted meanwhile or a conflict with a pair of exclusive roles leaves nothing written either.
- Switching `enabled` off stops every activation at once from the next request or job; switching it on counts them
  again.
- An activation that has ended, or expired, grants nothing; one of a machine, of an identity, or naming half a tenant
  grants nothing anywhere.
- A normal grant of the same role and an activation are separate: ending the activation leaves the grant's access, and
  revoking the grant leaves the activation's.
- The roles relation reads a table the activations migration creates: an application upgrading the package runs its
  migrations before serving checks, as for any table the package adds.

## Implementation Anchors

- `Config\BreakGlassConfigValidator` -- the block's checks and `read()`.
- `Config\TableNames::DEFAULTS`, `Config\TableConfigValidator::LENGTHS` -- the table's default name and its bound.
- `database/migrations/2026_11_12_000001_create_break_glass_activations_table.php` -- the table.
- `Models\BreakGlassActivation`, `Observers\BreakGlassActivationObserver` -- the record and its version bumps.
- `Database\BreakGlassActivations`, `Database\GrantRelation::readingRows()`, `Concerns\HasRoles::roles()` -- the rows
  the roles relation reads, who counts, the switch read once a request, and the identity marks.
- `Support\SubjectGrants`, `Cache\ResolutionCache`, `Cache\PrincipalCacheKey` -- the identity marked, its entries
  kept apart, and the entries of either state of the switch kept apart.
- `Services\BreakGlassService`, `Enums\BreakGlassRefusal`, `Exceptions\BreakGlassRefusedException`,
  `Exclusions\Support\ExclusionGuard::assertActivatable()` -- the write path, its refusals, and `assertHoldable()` and
  the exclusion check under the role's lock.
- `Support\PackagePermissions`, `Administration\OperationResource::breakGlass()`,
  `Administration\OperationConstraints` -- the three rights and how a delegated call is weighed.
- `Query\ScopeAnchors`, `Query\ScopeClasses` -- the activations' tenants among the anchors, compared as bytes.
- `Administration\PossessionLimits`, `Administration\RankComparison`, `Administration\AffectedHolders`,
  `Administration\AuthorityRows` -- delegated administration weighing an activation.
- `Resolvers\GrantProvenanceResolver`, `Evaluation\GrantProvenance`, `Evaluation\Enums\GrantSource` -- the route named.
- `Usage\RouteSources` -- no route from an activation.
- `Events\Identity\BreakGlassActivated`, `BreakGlassSurrendered` and `BreakGlassRevoked` (sharing `BreakGlassEnded`),
  `BreakGlassExpired` -- the lifecycle events.
- `Services\GrantPruner`, `Services\Support\ExpiredActivations`, `Services\PruneResult` -- the recorded expiry.
- `Support\GrantRoots`, `Services\GrantScopeQuery`, `Hooks\WideningClassifier` -- the listings and the widening.
- `Reviews\Support\GrantRows::held()`, `GrantRow`, `RowCollector`, `ReviewRow`, `ReviewUsage` -- the reviews.
- `Enums\GrantTarget::holders()`, `Events\Role\Deleted` -- a role's deletion.
- `Usage\UsagePruner` -- usage matched against the grant tables alone.
- `Evaluation\BreakGlassAttribution`, `Evaluation\Decision::$activations`, `Database\BreakGlassActivations::behind()`,
  `Cache\ResolutionCache::activationsOf()`, `Evaluation\DecisionReporting` -- the activations an allow names, and its
  report.

## Authoritative Tests

- `Evaluation\BreakGlassAttributionTest` (Feature) -- the activations an allow names through a permission, a pattern
  beside a direct grant, an ancestor's permission, a policy statement and a resource policy's role selector, on
  another tenant's resource, a role held both ways, two activations, a denial, the switch off, a machine and an
  identity, the memo, the store and an explanation, and the report through a check, a bulk check, a listing and a
  preview's listing; `DecisionPipelineTest`, `DecisionReportingTest`, `DecisionEvaluatedTest`,
  `AuthorizationFailedTest`, `GrantResolverTest`, `RolePoliciesTest`, `ResolutionCacheTest` (Feature),
  `DecisionEventTest` (Unit) -- each part on its own.
- `BreakGlassConfigValidatorTest`, `ConfigValidatorTest`, `Diagnostics\Checks\BlockChecksTest` (Feature) -- every
  setting's default, type, bound and unknown key, `enabled` accepted, the role maximums and the codes required once
  enabled.
- `Database\BreakGlassActivationsTest` (Feature) -- the scopes an activation grants in through a check, a bulk check,
  `permissionsFor()` and `whereAuthorized()`, cold and warm; expiry and ending; a normal grant beside it; denies,
  boundaries and guardrails; the cache entry's lifetime; a change through the model; machines, identities and half
  tenants; and the explanation without the note.
- `Database\BreakGlassActivationsMigrationTest`, `Database\TablePrefixMigrationTest`, `TableConfigValidatorTest`
  (Feature) -- the table under an explicit name and under the prefix, every built name within 63 characters, on
  SQLite, PostgreSQL and MySQL, and dropped cleanly.
- `Services\BreakGlassServiceTest` (Feature) -- every refusal, trusted and delegated activations for oneself and for
  another, the exact expiry and the granter, the role granted in the scope alone, surrender (refused to anyone else and
  to the grantee impersonated) and revocation, ending twice, a normal grant untouched, the grant hooks, the rights
  decided in the activation's scope, the locks a role grant takes and each end takes, a conflict on every try refused
  under its right, and the races with a role's deletion, a revocation of the right, a second activation and a hook's
  coverage, on SQLite, PostgreSQL and MySQL; an activation refused by a pair of exclusive roles, on SQLite,
  PostgreSQL and MySQL; and, in forked processes on PostgreSQL and MySQL, two activations of one role sharing its lock
  while a deletion of it waits, and an activation racing a grant or an activation of its pair's other role queueing on
  the pair.
- `Services\BreakGlassServiceTest` (Feature) -- each lifecycle event once, with its fields and actor, a surrender's
  actor the grantee; none for a refusal, a rollback, an end that changed nothing; a revocation reported while
  disabled. `Events\Identity\BreakGlass{Activated,Ended,Surrendered,Revoked,Expired}Test` (Unit) -- the identifiers,
  the shared shape and the audit properties, with no note.
- `Services\ExpiredActivationsTest`, `Services\GrantPrunerTest`, `PruneGrantsCommandTest` (Feature) -- the expiry
  recorded and reported once, the row kept, a live, an ended and a surrendered one left, one ended meanwhile left,
  half a tenant recorded with no event, one operation a chunk, pretending, a second run, and while disabled.
- `Database\BreakGlassActivationsTest`, `ResolutionCacheTest`, `Query\ScopeAnchorsTest` (Feature) -- the switch: none
  counts while it is off, in the next request and a fresh container, from the memo and the store, and every one again
  once it is on.
- `Administration\OperationConstraintsTest`, `Administration\OperationResourceTest` (Feature),
  `Support\PackagePermissionsTest` (Unit) -- the rights, their resource and the scope rule alone.
- `HasRolesTest`, `SubjectGrantsTest`, `ResolutionCacheTest`, `Query\ScopeAnchorsTest`, `Query\ScopeClassesTest`,
  `Resolvers\GrantProvenanceResolverTest`, `Usage\RouteSourcesTest`, `BreakGlassActivationObserverTest`,
  `Models\BreakGlassActivationTest`, `Administration\PossessionLimitsTest`, `Administration\RankComparisonTest`,
  `Administration\AffectedHoldersTest`, `Administration\AuthorityRowsTest` (Feature) -- each part on its own.
- `Support\GrantRootsTest`, `Services\GrantScopeQueryTest`, `Hooks\WideningClassifierTest` (Feature) -- live,
  ended, expired, disabled, machine and identity activations in the answers and the lists, and none in the widening.
- `Reviews\Support\HolderRoutesTest`, `HoldingRoutesTest`, `StoredRowsTest`, `GrantRowsTest`, `RowCollectorTest`,
  `Usage\ReviewUsageTest` (Feature), `ReviewRowTest`, `GrantRowTest` (Unit) -- every unexpired activation reviewed
  beside a grant, whatever the switch, never the note, an identity's left out of a principal's holdings, paged once
  each, and its use unknown.
- `Services\GrantTargetTest`, `Services\RoleServiceTest`, `Services\GrantPrunerTest`, `Usage\UsagePrunerTest`,
  `Usage\RouteSourcesTest` (Feature) -- a role's deletion naming its activations' grantees once, an orphaned grantee's
  activation kept, and no use counted.

## Change Triggers

Update this note when the write path, its rights, its refusals or its events change, when the exclusion check moves
relative to the role's lock, when the prune stops recording an expiry, when what a decision names or reports of an
activation changes, when a reader of role grants starts or stops reading activations, or when an activation starts or
stops counting anywhere a role grant counts.
