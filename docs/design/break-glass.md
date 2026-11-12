# Break-glass

## Purpose

Break-glass is opt-in emergency access (AUTHZ-11.7, N133): a principal with the break-glass right grants itself, or
another person, a configured emergency role for a configured maximum time, with a justification code from a configured
list. It arrives in three releases (N138), and stays switched off until the third:

1. **Storage, configuration and resolution** (this release, BL-70a): the `break_glass` settings, validated at boot; the
   activations table and its model; and the resolution that reads a live activation as a grant of its role. Nothing in
   the package creates or ends an activation yet, so the feature is inert.
2. **Activation and revocation** (BL-70b): the API that activates, surrenders and revokes, its rights, its limits, the
   grant hooks and its concurrency.
3. **Expiry, reviews and attribution** (BL-70c): the lifecycle events, the access reviews of activations, the
   attribution of decisions to the activation behind them, and the switch that lets `enabled` be true.

This note records the invariants the first release fixes, so the next two extend them rather than change them.

## Invariants

1. **Off until its audit trail ships.** `break_glass.enabled` is a switch, false by default, read from
   `AUTHORIZATION_BREAK_GLASS_ENABLED` as written, never cast. While `Config\BreakGlassConfigValidator::AVAILABLE` is
   false, true is refused at boot, under `authorization.break_glass.enabled`, with the reason "break-glass is not
   available until its audit trail ships; leave it disabled." BL-70c flips that one constant; nothing else reads it.

2. **The settings fail closed (N116, N117).** The block sets only `enabled`, `max_minutes`, `roles`, `justifications`,
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
   (both UTC; an activation always expires), and, once it ends early, `ended_at`, `ended_by` and `end_reason`
   (`surrendered`, `revoked` or `expired`). The reference columns compare their exact bytes on every database
   (`ExactReferences`). A role's deletion deletes its activations.

4. **Live means not ended and not expired.** An activation counts while `ended_at` is null and `expires_at` is after
   now, compared in UTC (`Database\BreakGlassActivations::live()`). Expiry is exact: no sweeper runs, and a
   resolution that counts an activation lives no longer than its expiry, as for a grant's.

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
   their own (`identity-…`) so they never mix with those of the same grantee read as a subject. An activation naming
   half a tenant applies nowhere, as a grant row naming one does not.

8. **A change is seen on the next check.** A save or delete through `Models\BreakGlassActivation` bumps the versions
   a grant to its grantee bumps, the one it named before a move included, at once and again after the caller's
   transaction commits (`Observers\BreakGlassActivationObserver`). A row written to the table by other means bumps
   nothing, as a grant row written so does not.

9. **Provenance without the note.** Each role read through an activation carries the activation's key on its pivot
   (`break_glass_id`, null for a role grant). An explanation names such a route as `break_glass_permission` or
   `break_glass_policy`, with the activation's key under `activation`, and never the note. Usage tracking starts no
   route from an activation, so its use never counts as the use of a role grant. The note is hidden from the model's
   array and JSON forms, and is never cached, logged or put on an event.

## Success Path

1. An application lists `incident-responder` under `break_glass.roles` and `incident` under `justifications`, leaving
   `enabled` false; boot accepts it.
2. A row of `break_glass_activations` names a principal, the role, a tenant with its subtree, and an expiry an hour
   away (BL-70b will write it; until then only tests write one, through the model).
3. A check in that tenant, or below it, reads the role through the principal's `roles()`, and allows what the role's
   permissions allow, unless a deny, a cap or a guardrail refuses it; a check anywhere else does not.
4. An hour later the cached resolution has lapsed, and the next check allows nothing through the activation.

## Failure / Edge Cases

- `enabled` true, a role's maximum above the global one, an unknown key, a malformed code, a duplicate code, or a value
  written loosely is refused at boot under its path, and by `read()` after boot.
- An activation that has ended, or expired, grants nothing; one of a machine, of an identity, or naming half a tenant
  grants nothing anywhere.
- A normal grant of the same role and an activation are separate: ending the activation leaves the grant's access, and
  revoking the grant leaves the activation's.
- The roles relation reads a table the activations migration creates: an application upgrading the package runs its
  migrations before serving checks, as for any table the package adds.

## Plan for BL-70b and BL-70c

- **BL-70b.** Activation, surrender and revocation through a service, as trusted or delegated calls: the two rights
  (for oneself, for another), the configured roles and their maximums, the justification codes, the note within
  `note_max_length` when `notes` allows one, human principals alone, half-tenant rows refused at write, grant hooks
  and separation of duties (BL-71), and the concurrency of the other grant writes.
- **BL-70c.** The activated, surrendered, revoked and expired events (the granted event carries the justification
  code, the role, the grantee, the granter and the expiry, never the note), the reviews of activations, the
  attribution of a decision to the activation behind it (from the pivot's `break_glass_id`), break-glass reporting on
  decision events (BL-72), and `AVAILABLE` flipped to true. What lists or reviews holdings reads role grants alone
  until then, and BL-70c decides how each shows an activation:
  - the grantee listings and the grant scope query (`Support\GrantRoots`, `Services\GrantScopeQuery`), and the
    widening a grant hook is asked about, which therefore never counts an activation as a grant already held;
  - the access reviews (`Reviews\Support\ReviewRun`, `StoredRows`, `HolderRoutes`, `HoldingRoutes`, `RoleChains`,
    `RoleCarriers`, `GrantRows`);
  - grant usage (`Usage\RouteSources`, which starts no route from an activation, and `Usage\UsagePruner`);
  - the grantees a role's deletion reports (`Enums\GrantTarget::holders()`), and the grant pruner
    (`Services\GrantPruner`), which never prunes an activation.

## Implementation Anchors

- `Config\BreakGlassConfigValidator` -- the block's checks, `read()`, and `AVAILABLE`.
- `Config\TableNames::DEFAULTS`, `Config\TableConfigValidator::LENGTHS` -- the table's default name and its bound.
- `database/migrations/2026_11_12_000001_create_break_glass_activations_table.php` -- the table.
- `Models\BreakGlassActivation`, `Observers\BreakGlassActivationObserver` -- the record and its version bumps.
- `Database\BreakGlassActivations`, `Database\GrantRelation::readingRows()`, `Concerns\HasRoles::roles()` -- the rows
  the roles relation reads, who counts, and the identity marks.
- `Support\SubjectGrants`, `Cache\ResolutionCache`, `Cache\PrincipalCacheKey` -- the identity marked and its entries
  kept apart.
- `Query\ScopeAnchors`, `Query\ScopeClasses` -- the activations' tenants among the anchors, compared as bytes.
- `Administration\PossessionLimits`, `Administration\RankComparison`, `Administration\AffectedHolders`,
  `Administration\AuthorityRows` -- delegated administration weighing an activation.
- `Resolvers\GrantProvenanceResolver`, `Evaluation\GrantProvenance`, `Evaluation\Enums\GrantSource` -- the route named.
- `Usage\RouteSources` -- no route from an activation.

## Authoritative Tests

- `BreakGlassConfigValidatorTest`, `ConfigValidatorTest`, `Diagnostics\Checks\BlockChecksTest` (Feature) -- every
  setting's default, type, bound and unknown key, `enabled` refused, the role maximums and the codes required once
  enabled.
- `Database\BreakGlassActivationsTest` (Feature) -- the scopes an activation grants in through a check, a bulk check,
  `permissionsFor()` and `whereAuthorized()`, cold and warm; expiry and ending; a normal grant beside it; denies,
  boundaries and guardrails; the cache entry's lifetime; a change through the model; machines, identities and half
  tenants; and the explanation without the note.
- `Database\BreakGlassActivationsMigrationTest`, `Database\TablePrefixMigrationTest`, `TableConfigValidatorTest`
  (Feature) -- the table under an explicit name and under the prefix, every built name within 63 characters, on
  SQLite, PostgreSQL and MySQL, and dropped cleanly.
- `HasRolesTest`, `SubjectGrantsTest`, `ResolutionCacheTest`, `Query\ScopeAnchorsTest`, `Query\ScopeClassesTest`,
  `Resolvers\GrantProvenanceResolverTest`, `Usage\RouteSourcesTest`, `BreakGlassActivationObserverTest`,
  `Models\BreakGlassActivationTest`, `Administration\PossessionLimitsTest`, `Administration\RankComparisonTest`,
  `Administration\AffectedHoldersTest`, `Administration\AuthorityRowsTest` (Feature) -- each part on its own.

## Change Triggers

Update this note when an activation is created or ended by the package (BL-70b), when `AVAILABLE` changes or the
lifecycle events, reviews or attribution land (BL-70c), or when an activation starts or stops counting anywhere a role
grant counts.
