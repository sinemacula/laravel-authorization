# Separation of duties

Two roles may be declared mutually exclusive, so that no grantee holds both where their reach overlaps: a clerk who
raises payments and an approver who signs them off, say. A pair is declared and removed through
`RoleExclusionService`, which also reports who holds both roles of a pair, and once declared it is enforced on every
write that could let someone hold both (see [Enforcement](#enforcement) below).

```php
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException;
use SineMacula\Laravel\Authorization\Services\RoleExclusionService;

$exclusions = app(RoleExclusionService::class);

try {
    $exclusions->declare('clerk', 'approver', ActingContext::current()); // GrantOutcome::GRANTED, or UNCHANGED
} catch (RoleExclusionConflictException $exception) {
    foreach ($exception->getReport()->conflicts as $conflict) {
        $conflict->holder;   // Reference to the principal or grantee holding both
        $conflict->identity; // Reference to the identity one role came through, or null
        $conflict->first;    // ExclusionRoute to the pair's first role: grantee, path, scope, reach and expiry
        $conflict->second;   // ExclusionRoute to the second
    }
}

$exclusions->remove('clerk', 'approver');      // whether the pair was declared
$exclusions->pairs();                          // every RoleExclusion declared, or those naming a role given
$exclusions->conflicts('clerk', 'approver');   // the ConflictReport of two roles, declared as a pair or not
$exclusions->conflictsForAll();                // the ConflictReport of every pair declared, in the order pairs() lists
```

**Declaring a pair.** A pair names its two roles by key, never by name, so it holds when a role is renamed, and it is
stored in a canonical order, the lower key first, so declaring `(A, B)` and `(B, A)` is one pair: declaring a pair that
is declared already changes nothing and returns `GrantOutcome::UNCHANGED`, as an idempotent grant does. A role named by
a string is looked up as `RoleService` looks one up, under the default guard and in the tenant scope; a model must be
saved. A role paired with itself is refused with `InvalidRoleExclusionException`, an unknown name with
`UnknownRoleException`, and a role naming half a tenant with `InvalidTenantColumnsException`. Deleting a role takes its
pairs with it.

**Owners.** A pair is a definition, owned as the others are. A definition may name the platform's roles and those
of its own tenant and its tenant's ancestors, as a role takes its parent and its permissions, so a pair is owned by the
owner of its role owned furthest down: the platform for two platform roles, else the tenant whose role is paired with
one of the platform's, its own or an ancestor's. Two roles owned by tenants neither of which lies within the other, two
siblings say, cannot be paired, and are refused with `OwnerMismatchException`. The owner is stored with the pair, and a
removal is decided on it, so a pair stays removable after a tree move leaves its roles' owners neither within the
other.

**Administration.** `declare()` and `remove()` take an optional acting context, as the other management services do: a
call without one is trusted system work, and a call with one is decided through `check()` on the pair's operation
resource (`OperationResource::exclusion()`), under `authorization:role-exclusion.declare` or
`authorization:role-exclusion.remove`, before anything is read for the report or written. It is made only from the
tenant that owns the pair, a platform pair's from the platform (`administration.owner`); both roles must be junior to
the actor (`administration.rank`); and a removal, which lifts the pair across its owner's whole reach, needs an actor
that administers all of it (`administration.scope`), while a declaration only adds a constraint and is decided at its
node, as a guardrail set is. Each call is one operation, recorded on the row it writes, and dispatches
`Role\ExclusionDeclared` or `Role\ExclusionRemoved` once it commits, only when it changed something, with the two roles,
their names, the owner and the actor.

**The conflict report.** Two roles conflict for a holder where its routes to them overlap:

- **Reach.** Two grants overlap where a check sees both roles held: in the same tenant, where one reaches below a
  tenant the other is in or below, per the bound tenant tree, or where either is platform-wide. A grant in a parent
  that reaches below it overlaps one in a child; one limited to the parent itself does not, and grants in disjoint
  tenants never do.
- **Applications.** A grant for every application overlaps one for any application; two for the same application
  overlap, and two for different applications do not.
- **Inheritance.** A role held through its parents counts, while the role hierarchy is enabled: holding a role below
  one of the pair is holding it, and the route names the path from the role granted up to the pair's role.
- **Owners.** A role counts wherever a check sees it held, no more and no less. A check in a tenant sees the platform's
  roles and those of the tenant and its ancestors, so a tenant's role is held where the grant and the owner's subtree
  meet: a grant in the owner or below it holds it where the grant holds; a grant above the owner holds it in the
  owner's subtree when it reaches below, and not at all when it is limited to its own tenant; a platform-wide grant
  holds it in the owner's subtree. A chain of parent roles ends at the first role no such check sees, so a tenant moved
  away from a parent role's owner no longer holds what that role carries. Each route's `reach` says where it is held.
- **Identities.** A principal's own grants and its identity's are weighed together, as a check weighs them, when the
  identity's grants reach the principal (both machines or neither): the identity directory lists each holder's
  principals, and a principal holding one role itself and the other through its identity conflicts, the identity
  named. Sibling principals of one identity are never weighed together. A report is `isComplete` only when the
  directory listed every holder's principals completely.
- **Break-glass.** An activation not ended or expired holds its role as a grant in its scope would, even while
  break-glass is switched off; one naming a machine holds nothing, and an identity's never reaches its principals.
- **What holds nothing.** An expired grant, and a grant naming half a tenant, which grants nowhere, hold no role.

The report reads every holder of both roles, and of every role below either, in a fixed number of queries on the write
connection, never one for each holder or tenant, through the access reviews' role chains; the tree is asked about every
pair of tenants the routes weigh together in one query, a chunk of pairs at a time, and the identity directory once for
each holder. `declare()` reads it under the locks it writes under, both roles' rows locked first and then every role
below them, so a grant of any of them waits for it, and reads each role and grant row under a shared lock, so a grant
another session commits while the declaration runs is still found, whatever snapshot the transaction holds. It refuses
with `RoleExclusionConflictException`, carrying the report, when it holds any conflict: nothing is written and nothing
is removed, so an administrator resolves each conflict, revoking a grant or narrowing its reach, and declares the pair
again. `conflictsForAll()` finds the conflicts a tenant moved, an identity linked to a principal, or a grant written
past the package left behind. The reads, `pairs()`, `conflicts()` and `conflictsForAll()`, are trusted and not decided:
they read every pair and grant stored, whatever tenant owns it, so show them only to those who should see them.

## Enforcement

Once a pair is declared, every write that could let someone hold both its roles where their reach overlaps is refused
with `RoleExclusionConflictException`, trusted or delegated, with no override:

- **Role grants.** `GrantService::grantRole()` and `syncRoles()`, and `assignRole()` and `syncRoles()` on the
  `HasRoles` trait, which call them; a re-armed grant, a later expiry and a reach widened below its tenant count as
  grants. A sync is weighed as it leaves the grantee's roles, so swapping one role of a pair for the other in one sync
  goes through. A grant that leaves a role as it was, a shorter expiry, a narrower reach and a revocation are never
  weighed, so a conflict already stored can always be narrowed away.
- **Parents.** `RoleService::setParent()`, or a role saved with a new `parent_id`, while the role hierarchy is enabled:
  every holder of the role, and of every role below it, is weighed as holding the new parent and its ancestors. A
  parent a pair touches must be saved inside a transaction on the package's connection, as `setParent()` saves it, so
  the check's locks hold until the save commits; a model saved outside one is refused with `LogicException`.
- **Break-glass.** `BreakGlassService::activate()` weighs an activation as a live grant of its role once the role's
  row is locked shared. An activation not ended or expired counts as a holding for every other write, even while
  break-glass is switched off, since it grants again once break-glass is switched on.
- **Commands.** `authorization:grant` prints the refusal and fails; `authorization:migrate-spatie` stops at the refused
  grant, keeping what it imported before it, as for any failed grant.

A role's owner never changes, and no write moves a grant to another tenant or application, so neither needs a check.

```php
try {
    $user->assignRole('approver'); // the user holds 'clerk', declared exclusive with 'approver'
} catch (RoleExclusionConflictException $exception) {
    $exception->getReport()->conflicts; // only the conflicts this write would create
}
```

The refusal carries the report of the conflicts the write would create, never one already stored, references and scopes
only, and nothing is written: the grant, or the parent, is rolled back and no event is dispatched. A delegated write is
decided first, so an actor not allowed it is refused as such; a grant hook has already run by then, since hooks run
before the package takes any lock. A write is weighed under the locks a declaration takes, so a grant and a declaration
racing each other never both commit. Two writes that could together create a conflict for a pair, such as grants of its
two roles, a grant and an activation of them or a grant and a parent change, both lock the pair's row before either
writes, whatever other pairs their roles are in, so they never both commit: the second waits and is weighed against what
the first committed. An activation locks its role, then the pair, then the holdings it reads, as a grant does: shared,
unless a delegated call has already locked it for update, so two trusted activations of one role share the role's lock
and a trusted activation queues on the pair with a write of the pair's other role instead of deadlocking with it. The
database can still refuse a write as a deadlock when the writes climb several levels of parents or hand out several
roles, when a delegated write, which locks its role for update before the pair, races a write of the pair's other role,
or when a write races a declaration, a parent change or the deletion of the other role of one of its pairs. Only a
delegated call, made with an acting context, is tried again: in a transaction the package opened, or thrown as
`TransactionConflictException` in one the application opened. A trusted call, `setParent()` without an actor and the
commands among them, and a model saved directly throw the database's deadlock error for the caller to retry. A grant no
pair touches costs one query for each level of its role's ancestry, its own included, so one for a role with no parent;
one a pair touches costs one more to lock the pairs, then reads the report in a fixed number of queries however many
hold the roles. See [docs/design/separation-of-duties.md](../design/separation-of-duties.md).
