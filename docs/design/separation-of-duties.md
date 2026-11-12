# Separation of Duties

## Purpose

Separation of duties (AUTHZ-11.8) keeps one person from holding two roles that must stay apart, such as a clerk who
raises payments and an approver who signs them off. Roles may be declared mutually exclusive, so that no grantee holds
both in one scope. This note explains the first of the two parts that deliver it (BL-71a): how a pair is stored and
owned, how it is declared and removed through the administration services, and the conflict report that says who holds
both roles of a pair today. The second part (BL-71b) checks every declared pair on every grant written, and on a change
to a role's parents; until then a grant made after a pair is declared is not refused, and the report finds it.

## Invariants

1. **A pair is data, naming roles by key (N135).** A pair is one row of `role_exclusions`
   (`authorization.tables.role_exclusions`, honouring `tables.prefix` through `Config\TableNames`, created by its own
   migration on the package's connection with the collision guard). It names its two roles by key, never by name, so a
   rename keeps it and a tenant's roles can be paired. Its roles are stored in a canonical order, the lower key first,
   and the primary key spans both, so the pair `(A, B)` and the pair `(B, A)` are one row. The row records the tenant
   that owns the pair (both columns null for the platform), who declared it (`granted_by_type`, `granted_by_id`) and
   when. A role deleted takes its pairs with it, through the foreign keys. The table's name is bounded by
   `TableConfigValidator::LENGTHS`: every index and key the migration builds is named after it with a short suffix, the
   longest `_excluded_foreign` (17 characters), so the bound is 46.

2. **A pair is owned as a definition is (D20).** A definition takes only the platform's roles and those of its own
   tenant and its tenant's ancestors, as a role takes its parent and its permissions (see `Support\RoleParity`). So a
   pair is owned by the owner of its role owned furthest down: the platform when both roles are the platform's; else
   the tenant owning one role when the other is the platform's, that tenant's own, or an ancestor's. Two roles owned by
   tenants neither of which lies within the other, siblings included, cannot be named by any definition, so they are
   never paired: `OwnerMismatchException`, its kind `excluded role`. A role is never paired with itself
   (`InvalidRoleExclusionException`), and a role naming half a tenant, which belongs to no one, never is
   (`InvalidTenantColumnsException`).

3. **Idempotent declaration.** Declaring a pair already declared changes nothing and is reported as
   `GrantOutcome::UNCHANGED`, as re-granting a live grant is; a new pair is `GrantOutcome::GRANTED`. The row is written
   with insert-or-ignore against the primary key, so a concurrent declaration never surfaces a unique-constraint
   violation, and a pair whose row is neither written nor found is refused with `UnwrittenGrantException` rather than
   reported declared.

4. **Administration (AUTHZ-11.1).** `declare()` and `remove()` take an optional acting context: none is trusted system
   work (N75), one is delegated and decided through `check()` on the pair's operation resource
   (`OperationResource::exclusion()`), under `authorization:role-exclusion.declare` or
   `authorization:role-exclusion.remove`, spelt as the other actions are (N78). The resource is a definition change,
   owned where the pair is and naming its owning role, with the other role, as stored, among the proposed changes
   (`resource.change.excluded`, `resource.change.excluded_role`). The administration stage weighs it by the owner rule
   (`administration.owner`, see `Administration\DefinitionConstraints`), then by `Administration\ExcludedRoles`: both
   roles junior to the actor, the more senior of the two weighed (`administration.rank`); and, for a removal, which
   lifts the pair across its owner's whole reach, the administered-scope rule across that reach
   (`administration.scope`), with `authorization:administration.impersonated` needed across it while impersonating. A
   declaration only adds a constraint, so it is decided at its node, as a guardrail set is. Neither is marked narrowing,
   since each changes what may be granted later. Both roles are locked and pinned, under the concurrency protocol,
   before the change is decided, and the change is decided before anything is read for the report or written. A removal
   is decided on the owner stored on the pair's row, read under a row lock, its owning role the one that owner owns, so
   a pair stays removable after a tree move leaves its roles' owners neither within the other; removing a pair that is
   not declared is decided as declaring it would be.

5. **One operation, one event.** Each call is one operation, its id on the decision and on the event, and dispatches
   `Role\ExclusionDeclared` or `Role\ExclusionRemoved` once it commits, only when it changed something. Both extend
   `Role\ExclusionEvent`, implement `AuthorizationMutation` (BL-92) with the operation identifiers
   `role.exclusion.declared` and `role.exclusion.removed`, and carry the pair's two roles and their names, in its
   order, and its owner; they are about the pair's first role and name no grantee.

6. **Where two holdings conflict (N136).** Two routes, one to each role, conflict where a check sees both roles held:
   their applications meet (either for every application, or both the same one), and the tenants where each role is
   held meet (the same tenant, one reaching below a tenant the other is in or below, per the bound tenant tree, or
   either platform-wide). Disjoint tenants never conflict, and nor does a grant limited to its own tenant against one in
   a tenant below it. The tenant rule is `Reviews\Support\TenantRelations::canHoldTogether()`, which the access reviews
   weigh a role's policy attachment by.

7. **What counts as holding a role.** A live grant of the role, or of a role below it while the role hierarchy is
   enabled, each one route naming the path from the role granted up to the pair's role. A grant holds a role wherever a
   check sees it held, no more and no less. A check in a tenant counts the platform's grants, the tenant's own and its
   ancestors' that reach below them (`TenantChain::grants()`), and sees the platform's roles and those of the tenant and
   its ancestors (`TenantChain::owners()`). So a role a tenant owns is held where the grant and the owner's subtree hold
   together, by the same `canHoldTogether()`: a grant in the owner or below it holds the role where the grant holds; a
   grant above the owner that reaches below holds it in the owner's subtree; one limited to its own tenant does not
   hold it; and a grant at the platform holds it in the owner's subtree. Each role of the chain narrows where it is held
   (`ExclusionRoute::$reach`), and the chain ends at the first role a check holding the roles before it cannot see, or
   one naming half a tenant, as `RoleGraph` ends it: a tenant moved away from a parent role's owner stops holding what
   that role carries, and a parent owned beside the role below it is held nowhere. An expired grant holds nothing, and
   nor does a grant naming half a tenant, which grants nowhere (N130).
   A principal's own holdings and its identity's are weighed together, as a check weighs them, when the identity's
   grants reach the principal (both machines or neither, see `SubjectGrants::grantingIdentity()`); the identity
   directory lists each holder's principals (N81), and a conflict that came through the identity names it. Sibling
   principals of one identity are never weighed together. A report is complete only when the directory listed every
   holder's principals completely.

8. **A bounded read.** The report reads through the access reviews' machinery, never a resolver of its own: the roles
   below the pair in one recursive query (`Reviews\Support\RoleChains::descendants()`) and one read of them and of the
   roles whose parent is among them, repeated only for a role that read finds; the live grants of all of them together,
   a chunk of roles at a time (`Reviews\Support\GrantRows`, at one instant through `ReviewRun`), all on the write
   connection. Whether a grant's tenant and the owners of its chain lie within one another, and whether a tenant of one
   route lies within the tenant of a route reaching below it, are each settled for every pair of tenants together, the
   subtrees of their ancestors read in one query a chunk of pairs at a time
   (`Reviews\Support\TenantRelations::settleWithin()`). Nothing is read once for each holder or tenant; the identity
   directory, the application's seam, is asked once for each holder. `conflictsForAll()` reads the holdings of every
   role of every pair together.

9. **Refused, never repaired.** `declare()` reads the report under the locks it writes under, both roles' rows locked
   first in key order, outside the tenant scope, so a delegated grant of either, whose concurrency protocol locks the
   role it grants, waits for it (BL-71b has every grant check the pairs under the same locks). Each role and grant row
   the report reads is read under a shared lock, so it is the row as last committed, whatever snapshot the transaction
   already holds (MySQL's repeatable read keeps the one its first read took), and a grant committed after the
   declaration began is still found; `conflicts()` and `conflictsForAll()` read without locks. It refuses with
   `RoleExclusionConflictException`, carrying the report (references and scopes only, never a model), while it holds any
   conflict, whether or not it is complete. Nothing is written and nothing is removed: an administrator resolves each
   conflict and declares the pair again.

10. **Trusted reads.** `pairs()`, `conflicts()` and `conflictsForAll()` are not decided; they read every pair and grant
    stored, whatever tenant owns it, so a screen shows them only to whom it should. Every operation refuses while the
    package is not healthy (`PackageState`), before it reads or writes.

## Success Path

1. An administrator calls `declare($clerk, $approver, $actor)` from the context of the tenant that owns the pair.
2. Both roles are resolved and put in the pair's order, the owner is found, both are locked and pinned, and the change
   is decided as the actor under `authorization:role-exclusion.declare`.
3. Both roles' rows are locked, the pair is found not declared, and the report, read locked, finds no holder of both.
4. The row is written with its owner and the actor, and `ExclusionDeclared` is dispatched once the call commits.
5. Later, a tenant moves under another, or an identity is linked to a principal, and `conflictsForAll()` reports the
   holder that now holds both roles.

## Failure / Edge Cases

- A role paired with itself, an unknown name, an unsaved model or a role naming half a tenant is refused before
  anything is written; a role gone by the write is refused as unknown, or, for a delegated change, as an invalid grant
  target.
- Roles of two tenants neither within the other are refused with `OwnerMismatchException`.
- A delegated change from any context but the owner's is refused as `administration.owner`; one naming a role not
  junior to the actor as `administration.rank`; a removal by an actor that does not administer the owner's whole reach
  as `administration.scope`.
- Someone holding both roles where their reach overlaps refuses the declaration with the report, and nothing changes.
- An incomplete identity directory leaves the report incomplete; a conflict it does find still refuses.
- Removing a pair that is not declared returns false and dispatches nothing; declaring one that is returns `UNCHANGED`.
- After a tree move, a pair is still removed on its stored owner, and a role held through a parent the grant's tenant
  no longer sees no longer conflicts.
- After a tree move puts a role's owner below the grants' tenant, a grant there reaching below still holds the role in
  the owner's subtree, and conflicts there, as a check there finds; one limited to its tenant no longer holds it.

## Implementation Anchors

- `Services\RoleExclusionService` -- `declare()`, `remove()`, `pairs()`, `conflicts()` and `conflictsForAll()`.
- `Services\Support\ExclusionPair` -- the canonical order, the refusals of a pair and the owner rule.
- `Services\Support\RoleExclusionTable` -- the row written, read and removed.
- `Administration\OperationResource::exclusion()`, `Administration\DefinitionChange::$related` -- the decided resource.
- `Administration\DefinitionConstraints`, `Administration\ExcludedRoles` -- the owner, rank and scope rules.
- `Exclusions\Support\ExclusionHoldings`, `Exclusions\Support\ConflictReader` -- the report's reads and its rules.
- `Reviews\Support\RoleChains::descendants()`, `Reviews\Support\TenantRelations::settleWithin()` -- the bounded reads.
- `Exclusions\ConflictReport`, `ExclusionConflict`, `ExclusionRoute`, `RoleExclusion` -- what the reads return.
- `Exceptions\RoleExclusionConflictException`, `Exceptions\InvalidRoleExclusionException` -- the refusals.
- `Events\Role\ExclusionEvent`, `ExclusionDeclared`, `ExclusionRemoved` -- the events.
- `database/migrations/2026_11_12_000002_create_role_exclusions_table.php`, `Config\TableConfigValidator` -- storage.

## Authoritative Tests

- `Services\RoleExclusionServiceTest` (Feature) -- declaring once in either order, removing, refusals, owners, removal
  after a tree move, holdings wherever a check sees them with the tree either way up, the refusal with the report and
  the locks it reads under, a grant committed by another session
  during a declaration (MySQL and PostgreSQL), delegated decisions and their locks, the owner and rank rules, events
  with the operation id, listing, the report of every pair and the bound directory.
- `Exclusions\Support\ConflictReaderTest` (Feature) -- one tenant, the platform, subtrees and nodes, disjoint tenants,
  applications, parent roles and a parent no longer seen, routes held only below their grant's tenant and a platform
  grant of a tenant's role, a principal and its identity, siblings and machines under a
  morph alias, expired and half-tenant grants, a mixed-type closure tree, an incomplete directory and a fixed number
  of queries and tree reads.
- `Exclusions\Support\ExclusionHoldingsTest` (Feature) -- the routes, their paths, scopes and expiries, where each
  role is held through a grant above, below or beside its owner or at the platform, the locked read and the queries the
  roles below cost.
- `Reviews\Support\TenantRelationsTest`, `Reviews\Support\RoleChainsTest` (Feature) -- the pairs settled together
  and the roles below.
- `Administration\ExcludedRolesTest`, `Administration\DefinitionConstraintsTest` (Feature) -- the rank and scope rules.
- `Services\ExclusionPairTest`, `Services\RoleExclusionTableTest` (Feature) -- the pair and its row.
- `Database\RoleExclusionsMigrationTest`, `TableConfigValidatorTest`, `Database\TablePrefixMigrationTest` (Feature) --
  the table, its bound and its prefix.
- `Performance\RoleExclusionQueryBudgetTest` -- the report costs the same queries for two holders as for forty, in
  shared tenants or each in tenants of its own.

## Change Triggers

- BL-71b checks every declared pair on every grant written and on a change to a role's parents, with no override for
  trusted calls or break-glass grants; its refusal reuses this report and its overlap rule.
- A decided read of the pairs or the report would need an action of its own and an admission like the reviews'.
- A tenant tree that cannot be read stops the report with the tree's exception; a fallback would need a status of its
  own.
