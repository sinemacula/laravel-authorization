# Grant Scope

An integration such as `laravel-iam` needs two facts about grants that no check gives: whether everything an identity
has been granted lies within a tenant, which SSO's principal scope is composed from (AUTHZ-14.2), and whether a
principal holds a grant that applies in a tenant, an input to a tenant's admission (AUTHZ-13.8). This note explains the
identity directory that says whose grants count, the shared reader of grant roots, `GrantScopeQuery::forIdentity()` and
`GrantScopeQuery::hasGrantIn()`, and why neither is membership or authorisation.

## Invariants

1. **The identity directory (N81).** `Contracts\IdentityDirectory::principalsOf($identity)` returns an
   `IdentityPrincipals`: the references to the principals the identity owns, the identity left out, and `isComplete`.
   Principals and identities are the application's (AUTHZ-13.9), so the package never infers them, from
   `AuthorizableIdentity` or from anything else. The default, `Resolvers\GuardUserIdentityDirectory`, is complete and
   empty under the shipped `AuthGuardSubjectResolver`, where every user is its own identity, and incomplete under any
   other resolver; it reads the bound resolver on every call. The class is named by `authorization.identity_directory`,
   validated at boot (a missing key falls back to the default, null or a class that does not implement the contract is
   refused) and bound as a scoped default, built per request or job, which a binding of the contract replaces.

2. **What counts as a grant (N82).** A live row of a role granted, a permission granted directly or a policy attached,
   a policy that only denies included. Roles are not expanded: a role's root is where it was granted. A row
   `LiveGrants` reads as expired is no grant, nor is an inline policy attached to a grantee it does not belong to
   (`InlinePolicies::attachedToTheirGrantee()`), which no check applies. Boundaries and guardrails cap grants and are
   never read. A grant's root is the tenant its row names, or the platform for a row naming none.

3. **One reader.** `Support\GrantRoots` reads the grantees' roots from the three grant tables in one `UNION ALL` query
   on the write connection (AUTHZ-12.4), across every tenant and application, matching each grantee by its exact morph
   type and key, each grantee once. It shares the predicates the decision path uses rather than copying them:
   `LiveGrants::only()` for expiry, `TenantChain::grants()` for applicability and `GrantApplications::only()` for the
   application. An empty list of grantees runs no query.

4. **Containment.** A root is within when it is the tenant or below it in the bound tree. For `FlatTenantTree` that is
   the tenant's own pair; any other tree's `subtree()` query is nested whole inside the grant query, never loaded, so
   it must be a query on the package's connection, and anything else is refused with `UnexpectedValueException`. A
   root at an ancestor, a subtree grant reaching the tenant included, at a sibling or any other tenant, or at the
   platform is outside. A row naming one tenant column without the other cannot be read.

5. **`forIdentity()` answers (N81, N82).** It reads the roots of the identity's grants and of every principal the
   directory lists, in every application and under every guard. `OUTSIDE` on any root proven outside, whether or not
   the list is complete. `WITHIN` only when the list is complete, the tree was read and every root is within, or there
   is no grant at all. `UNKNOWN` otherwise: an incomplete list, a tree that cannot be read (a platform-wide grant still
   proves `OUTSIDE` then) or a row that cannot be read. The tenant is a model, an `AuthorizableTenant` or a
   `Reference`, and every form gives the same answer.

6. **`hasGrantIn()` answers.** It reads whether a grant of the principal, or of its identity when
   `SubjectGrants::grantingIdentity()` says that identity's grants reach it (so a person's never reach a machine),
   applies in the tenant as a check there reads it: made in the tenant, made in an ancestor and reaching its subtree,
   or platform-wide. A grant held only by another principal of the same identity never counts. A null application
   applies no application filter; a named one counts the grants made for it or for every application. `PRESENT` only
   when a grant is found; `UNKNOWN` when none is found but one could have been missed, because the tree cannot be read
   (only the tenant itself and the platform are then looked in) or a grantee is neither a model nor a `Reference`;
   `ABSENT` otherwise. Uncertainty never becomes `PRESENT`.

7. **Two questions, not two decision paths (D22).** The answers differ on purpose: a subtree grant made in an ancestor
   makes `hasGrantIn($principal, $child)` `PRESENT` and `forIdentity($identity, $child)` `OUTSIDE`. Neither authorises
   anything, says whether a principal is a member of a tenant, or whether it may act there or use an application;
   `check()` stays the one decision path, and `ApplicationAccess` its adapter for application access.

8. **A trusted service.** Even the bare status reveals a fact about other tenants, so the service is for trusted
   integration code, never an endpoint for users. It returns the status alone, never tenant ids, grant names, counts
   or rows.

9. **Bounded cost.** Each answer is one grant query, plus the tree's own reads and the directory's, whatever the number
   of grants, grantees or tenants and the depth of the tree. Nothing is cached: completeness across an identity's
   principals would need invalidation the resolution cache does not have.

## Success Path

`forIdentity(Reference::of($person), $account)` asks the directory for the person's principals and gets a complete
list of two. It asks the bound tree for the account's subtree query and runs one query over the role, permission and
policy grant tables for the person and both principals, selecting the live rows whose root is the platform, is outside
the subtree, or names half a tenant. No row comes back, so the answer is `WITHIN`. `hasGrantIn($user, $child)` makes
the user a subject through the bound resolver, reads the child's chain from the tree, and asks whether any live grant
of the user, or of its identity, applies in the child; an ancestor's subtree grant does, so the answer is `PRESENT`.

## Failure / Edge Cases

- **An incomplete directory.** `UNKNOWN`, unless a grant already proves `OUTSIDE`.
- **No grants.** `WITHIN` with a complete directory (N82), `UNKNOWN` with an incomplete one.
- **A tree that throws, or a subtree on another connection.** The failure is written to the log; `forIdentity()` is
  `OUTSIDE` on a platform-wide grant, else `UNKNOWN`; `hasGrantIn()` looks only in the tenant and the platform, and is
  `UNKNOWN` when it finds nothing.
- **A row naming half a tenant.** `UNKNOWN` for `forIdentity()`, unless another root is outside.
- **The same key under two types.** Never confused: grantees are matched by type and key together.
- **Expired grants, boundaries, guardrails and policies attached to roles.** Never read as the grantees' grants.

## Implementation Anchors

- `Contracts\IdentityDirectory`, `Support\IdentityPrincipals` and `Resolvers\GuardUserIdentityDirectory` -- the seam,
  its answer and the default.
- `Support\GrantRoots` -- the union over the grant tables, `within()`, `against()` and `appliesIn()`.
- `Services\GrantScopeQuery` -- `forIdentity()`, `hasGrantIn()`, the grantees and the tree's failures.
- `Enums\GrantScopeStatus` and `Enums\GrantPresence` -- the answers.
- `Config\ImplementationConfigValidator` and `Config\ConfigValidator` -- the `identity_directory` validation.
- `AuthorizationServiceProvider::registerConfiguredDefaults()` and `registerManagementServices()` -- the scoped
  directory and the singleton service.

## Authoritative Tests

- `Feature\Services\GrantScopeQueryTest` -- the containment matrix (the tenant, descendants, ancestors, siblings, the
  platform, no grants, an incomplete directory, every application, morph collisions, expiry, several principals,
  deny-only policies, boundaries and guardrails ignored) and presence against containment (ancestor subtree grants,
  node-only grants, principal isolation, identity inheritance, machines, applications, unreadable trees and
  grantees), under the closure-table and flat trees, and the status carrying nothing else.
- `Feature\Support\GrantRootsTest` -- the classification, half-tenant rows, one query naming each grantee once,
  applicability, inline policies, nested subtrees, refused subtrees and the write connection.
- `Performance\GrantScopeQueryBudgetTest` -- the query count is the same for one grant and ten of each kind, and at
  depth one and depth eight.
- `Feature\Resolvers\GuardUserIdentityDirectoryTest`, `Feature\ConfigValidatorTest` and
  `Feature\AuthorizationServiceProviderTest` -- the default directory, its validation and its binding.

## Not Yet

- **Widening hooks (BL-66 part 2, AUTHZ-11.3, N80).** Widening classification, the `GrantHook` contract and its one
  binding with an optional ordered composite, the run before the package's first lock with retry validation, and the
  recursion guard that refuses mutation services while a hook runs. Part 2 extends this note.

## Change Triggers

- Counting any other row as a grant, or leaving one out, changes invariant 2 and N82.
- Inferring principals from anything but the directory breaks invariant 1 and N81.
- Returning anything beyond the status breaks invariant 8.
- A per-grant or per-tenant query, or loading a subtree's ids, breaks invariant 9.
- Caching an answer needs invalidation across every principal of an identity.
