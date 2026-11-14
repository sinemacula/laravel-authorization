# Grant Scope

An integration such as `laravel-iam` needs facts about grants that no check gives: whether everything an identity has
been granted lies within a tenant, which SSO's principal scope is composed from, whether a principal holds a grant that
applies in a tenant, an input to a tenant's admission, and whose grants reach a tenant or lie within its subtree, which
a move of a tenant widens or carries. This note explains the identity directory that says whose grants count, the shared
reader of grant roots, `GrantScopeQuery::forIdentity()`, `GrantScopeQuery::hasGrantIn()`, `granteesReaching()` and
`granteesWithin()`, and why none is membership or authorisation. It then explains the grant hooks that build on them:
which grants widen an identity's scope, the hook contract and its binding, and where the hook runs in a grant call.

## Invariants

1. **The identity directory.** `Contracts\IdentityDirectory::principalsOf($identity)` returns an `IdentityPrincipals`:
   the references to the principals the identity owns, the identity left out, and `isComplete`. Principals and
   identities are the application's, so the package never infers them, from `AuthorizableIdentity` or from anything
   else. The default, `Resolvers\GuardUserIdentityDirectory`, is complete and empty under the shipped
   `AuthGuardSubjectResolver`, where every user is its own identity, and incomplete under any other resolver; it reads
   the bound resolver on every call. The class is named by `authorization.identity_directory`, validated at boot (a
   missing key falls back to the default, null or a class that does not implement the contract is refused) and bound as
   a scoped default, built per request or job, which a binding of the contract replaces.

2. **What counts as a grant.** A live row of a role granted, a permission granted directly or a policy attached, a
   policy that only denies included. Roles are not expanded: a role's root is where it was granted. A row `LiveGrants`
   reads as expired is no grant, nor is an inline policy attached to a grantee it does not belong to
   (`InlinePolicies::attachedToTheirGrantee()`), which no check applies. Boundaries and guardrails cap grants and are
   never read. A grant's root is the tenant its row names, or the platform for a row naming none. A live break-glass
   activation (`BreakGlassActivations::live()`) is a grant of its role in its scope for the answers and the lists, as a
   check reads it: none while break-glass is disabled, none of a machine, and an identity's reaches none of its
   principals, so `forIdentity()` counts its principals' activations and `hasGrantIn()` the principal's alone. The
   widening (invariant 10) never counts one.

3. **One reader.** `Support\GrantRoots` reads the grantees' roots from the three grant tables in one `UNION ALL` query
   on the write connection, across every tenant and application, matching each grantee by its exact morph type and key,
   each grantee once. It shares the predicates the decision path uses rather than copying them: `LiveGrants::only()` for
   expiry, `TenantChain::grants()` for applicability and `GrantApplications::only()` for the application. An empty list
   of grantees runs no query. Given the grantees whose activations count, it reads their live activations in the same
   query, as role grant rows.

4. **Containment.** A root is within when it is the tenant or below it in the bound tree. For `FlatTenantTree` that is
   the tenant's own pair; any other tree's `subtree()` query is nested whole inside the grant query, never loaded, so
   it must be a query on the package's connection, and anything else is refused with `UnexpectedValueException`. A
   root at an ancestor, a subtree grant reaching the tenant included, at a sibling or any other tenant, or at the
   platform is outside. A row naming one tenant column without the other cannot be read.

5. **`forIdentity()` answers.** It reads the roots of the identity's grants and of every principal the directory lists,
   in every application and under every guard. `OUTSIDE` on any root proven outside, whether or not the list is
   complete. `WITHIN` only when the list is complete, the tree was read and every root is within, or there is no grant
   at all. `UNKNOWN` otherwise: an incomplete list, a tree that cannot be read (a platform-wide grant still proves
   `OUTSIDE` then) or a row that cannot be read. The tenant is a model, an `AuthorizableTenant` or a `Reference`, and
   every form gives the same answer.

6. **`hasGrantIn()` answers.** It reads whether a grant of the principal, or of its identity when
   `SubjectGrants::grantingIdentity()` says that identity's grants reach it (so a person's never reach a machine),
   applies in the tenant as a check there reads it: made in the tenant, made in an ancestor and reaching its subtree,
   or platform-wide. A grant held only by another principal of the same identity never counts. A null application
   applies no application filter; a named one counts the grants made for it or for every application. `PRESENT` only
   when a grant is found; `UNKNOWN` when none is found but one could have been missed, because the tree cannot be read
   (only the tenant itself and the platform are then looked in) or a grantee is neither a model nor a `Reference`;
   `ABSENT` otherwise. Uncertainty never becomes `PRESENT`.

7. **Two questions, not two decision paths.** The answers differ on purpose: a subtree grant made in an ancestor makes
   `hasGrantIn($principal, $child)` `PRESENT` and `forIdentity($identity, $child)` `OUTSIDE`. Neither authorises
   anything, says whether a principal is a member of a tenant, or whether it may act there or use an application;
   `check()` stays the one decision path, and `ApplicationAccess` its adapter for application access, which decides
   without session caps: a principal being admitted holds no session yet, so neither the request's credential scopes nor
   a machine's missing ones refuse it, while its denies, guardrails and boundaries still do.

8. **A trusted service.** Even the bare status reveals a fact about other tenants, so the service is for trusted
   integration code, never an endpoint for users. `forIdentity()` and `hasGrantIn()` return the status alone, never
   tenant ids, grant names, counts or rows; `granteesReaching()` and `granteesWithin()` return the grantees alone,
   never their grants or where they were made (invariant 17).

9. **Bounded cost.** Each answer is one grant query, plus the tree's own reads and the directory's, whatever the number
   of grants, grantees or tenants and the depth of the tree; only a subtree query that fails as it runs costs
   `forIdentity()` a second query, of the platform-wide grants. Nothing is cached: completeness across an identity's
   principals would need invalidation the resolution cache does not have.

10. **Widening.** `Hooks\WideningClassifier` classifies the grants a call proposes. A grant the grantee holds live in
    the same scope, unchanged or only shortened (an earlier expiry, a narrower or equal reach), is never classified.
    Every other grant is evaluated: a new one, a re-arm of an expired one, an extension and a wider reach. An evaluated
    grant widens when its grantee is the identity itself (`IDENTITY`), when it is platform-wide (`PLATFORM`), when no
    live grant of the identity or of a principal the directory lists applied in its tenant (`NEW_TENANT`: a new tenant,
    a sibling or an ancestor of one held), and when it reaches below its tenant where none of those grants reached below
    (`NEW_SUBTREE`). It is read with `GrantRoots::appliesIn()`, over the identity, the grantee and every listed
    principal, in every application. `Narrowing` is not the trigger: a permission added to a role is no grant to an
    identity, and a grant to a role is never classified. A break-glass activation is never a grant already held here: a
    grant beside one widens as it would without it.

11. **When in doubt, the hook.** An incomplete directory (`INCOMPLETE_DIRECTORY`) or a tree that cannot be read
    (`UNREADABLE_TREE`) makes an evaluated grant widen. The identity is resolved through the subject resolver's
    `forUser()` on the grantee's model: the grantee is the identity, or the subject whose identity it names. A grantee
    whose model cannot be read, or for which the resolver throws or names neither, is refused with
    `UnresolvableRecipientException`, never classified as not widening.

12. **The contract.** `Contracts\GrantHook::beforeWidening(GrantWidening $widening)`. `Hooks\GrantWidening` and
    `Hooks\ProposedGrant` are immutable values of references, strings and immutable UTC instants: the operation's id and
    mode, the actor references, the recipient identity and the actual grantee, each widening grant with its action,
    target, tenant, application, reach, expiry and reasons, the reasons of the call once each, and when the proposal was
    observed. Exactly one hook is bound: by default `Hooks\GrantHooks` holding no hook, or the hook a sibling package or
    the application binds on the contract. The classes `authorization.grant_hooks` lists, validated at boot
    (`Config\GrantHookConfigValidator`), run before whichever hook is bound, in order, stopped by the first that throws.
    With none listed, and the default bound, nothing is classified. There is no runtime registrar. When hooks are
    listed, the package extends the contract with Laravel's `extend()` as the application boots, so whatever it resolves
    to is wrapped in `Hooks\ListedGrantHooks`: the listed hooks first, then the bound hook, any of which may refuse.
    Hooks only refuse, so every one runs and none is dropped. Laravel applies the extender each time it builds the
    contract, so a hook bound before the package registered or after, with `bind()`, `singleton()` or `scoped()`, a
    scoped closure naming the contract by its return type, or a deferred provider, is wrapped, and so is the default,
    which holds none of the listed hooks, so none runs twice. An extender registered before the package's decorates the
    bound hook before it is wrapped; one registered after receives the wrapped hook. Laravel applies no extender to an
    instance it is handed later, so `Hooks\WideningPhase` wraps the hook it calls as well, with
    `ListedGrantHooks::wrap()`, which leaves a wrapped hook as it is: a hook bound with `instance()` after the
    application boots, or bound in any way after an instance the package wrapped as the application booted, runs after
    the listed hooks too. A decorator called while another runs its hook for the same widening calls its own hook alone,
    so when an extender registered after the package decorates the wrapped hook and the grant service wraps the
    decoration again, the listed hooks still run once. The wrapped hook builds the listed hooks from its container at
    its first use and keeps them, so registering builds none of them, and they share the bound hook's lifetime, in a
    queue worker and in each Octane sandbox. Extending resolves the bound hook only when it was resolved before and a
    callback watches the contract for rebinding, which Laravel hands the wrapped hook. A wrapped hook is never wrapped
    again, so registering the package twice runs the listed hooks once. `Registrars\SeamBindings` binds the default and
    registers the extender as the application boots. With none listed nothing is extended, and the bound hook stands
    alone. The widening also carries the operation's client, `ip` and `userAgent`, both nullable, the last two
    constructor arguments with defaults, so a widening built by hand without them still builds (see invariant 16).

13. **Veto only.** A hook refuses by throwing, `Exceptions\GrantRefusedException` or anything else: the call rolls back
    with nothing written and no event, and is not tried again, unless what it threw is a concurrency error
    `ConflictRetries` recognises, raised by the hook's own preparation, which a call handles as any other; the package
    records no denial for it. A hook never changes the grant, and while it runs `OperationScope::run()` refuses every
    operation with `GrantHookRecursionException` (`OperationScope::whileHookRuns()`, cleared in `finally`), so every
    management service refuses; read-only queries stay allowed. A raw Eloquent write is not guarded: it stays the
    trusted surface it always is.

14. **Placement.** `Hooks\WideningPhase` is the one call point, for trusted and delegated grants alike and for a
    break-glass activation. In `GrantService::grant()` and `sync()`, and in `BreakGlassService::activate()`, first in
    the work of `OperationScope::run()`: a non-locking preliminary proposal (the target, the scope, the reach, the
    expiry; a sync's additions and re-arms, and the roles it holds live with the other reach than their entry's
    `RoleReach` names, with the expiry each keeps, never another row held live), its classification, and one hook call
    with every widening grant, before any lock and any write. The call then locks, rebuilds its grants, decides them,
    and hands them to `assertCovers()`, which classifies them again, after every other lock, with locking reads: the
    grantee's own rows (`GrantTable::liveRows()` and `liveRow()` under a row lock), and the evidence the hook was
    skipped or limited on, the grants of the identity, the grantee and every listed principal that apply in the tenant,
    read table by table with `GrantRoots::appliesUnderLock()`, never as a union, locked through
    `DependencyPins::lockCoverage()` as the last part of the protocol (`DependencyPhase::COVERAGE`). A break-glass
    activation proposes its role once, decides it, and locks the role's row only after the coverage check. A locking
    read sees the latest committed rows on MySQL whatever the snapshot, and holds them until commit on PostgreSQL and
    MySQL, so a revocation committed after the hook phase is seen and one made later waits. A grant that now widens
    with no hook run for it throws `DependencyChangedException::widening()`. A delegated call is tried again by
    `ConflictRetries`; a trusted call is tried again for this conflict alone, up to the same `retries`, then refused as
    `administration.conflict`. The hook may run on each try; it is never called under the package's locks. Only the
    application's answers, the directory's list and the tenant tree, are read as they stand.

15. **Nested calls and outer transactions.** A grant made while another operation's work runs
    (`OperationScope::isNested()`) may follow that operation's locks, so one that widens is refused with
    `NestedGrantException`. Inside the application's own transaction a try is rolled back only to its savepoint, whose
    row locks MySQL keeps, so a grant is never tried again there with its hook: a coverage conflict is thrown as
    `TransactionConflictException`, and so is a retry after any other conflict whose grant would call its hook
    (`OperationScope::retriedInPlace()`). Grant calls made one after another in the application's own transaction are
    each a call of their own; `authorization:migrate-spatie` commits its catalogue, then makes each grant as one.
    A binding of the contract to anything that is not a `GrantHook` is refused, never taken as none.

16. **The client is personal data, for the hook alone.** `Support\Operation` and `Hooks\GrantWidening` carry the IP
    address and the user agent of the call. `Operation::begin()` takes a client the caller passes as it is; otherwise a
    delegated operation reads the routed request it is begun in through `Support\RequestClient` (the IP behind the
    trusted proxies), and a trusted one, or any begun with no routed request (console, queue), has none. The grant
    service hands `WideningPhase::before()` the operation as begun, with its client, while `OperationScope` gives the
    call's work, and so every event it dispatches and every write its observers report, the operation without it
    (`Operation::withoutClient()`). The client is never put in a cache key, a decision event, a log or a stored grant
    row. No service takes a client: each begins its own operation with none given, so a service grant reaches the hook
    with the client of the routed request of a delegated call, or with none for a trusted, console or queued call. An
    explicit client applies only to an `Operation` or a `GrantWidening` a caller builds itself, such as a hook's own
    tests, and is the client of a routed request or none, never one read from the request Laravel binds for the console
    and the queue.

17. **The grantees reaching or within a tenant.** `treeChanged()` runs no grant hook, so a sibling that reports a move
    of a tenant to its sign-on scope widening asks whose grants the move concerns. `granteesReaching($tenant,
    $application = null)` lists every grantee, a principal or an identity as its rows store it, holding a live grant
    that reaches the tenant as a check there reads it (`TenantChain::grants()`): made in the tenant, for it alone or
    reaching below it, made in an ancestor and reaching below it, or platform-wide. The ancestors are read from the
    bound tree afresh (`TenantChain::of(..., isFresh: true)`), never a batch's kept answer. `granteesWithin($tenant,
    $application = null)` lists every grantee holding a live grant made in the tenant or below it, through
    `GrantRoots::within()`: the tenant's own pair for the flat tree, else the tree's `subtree()` nested whole. A subtree
    moved under a new parent comes to be reached by the grants that reach the parent from above it or were made there
    reaching below it, so the sibling asks `granteesReaching()` of the moved tenant once it has moved, or of the new
    parent at any time, which lists as well whoever holds a grant made there for the parent alone; the grants within the
    subtree, which `granteesWithin()` lists, keep their reach. What counts as a grant is invariant 2, and a row naming
    half a tenant never counts: a check takes a row with no tenant type for a platform-wide grant, but neither list
    does. A role a policy is attached to is never listed, wherever the policy is attached: it is no principal or
    identity, and whoever holds the role is listed through their own grant of it. A named application counts the grants
    made for it or for every application, as `hasGrantIn()` does; none counts every grant. Each grantee is listed once,
    ordered by type and then key byte by byte, in PHP (`Reference::sorted()`), so every database lists them alike. A
    machine's activation lists no one, and a grantee holding both a grant and an activation is listed once. Each list is
    one `UNION` query over the three grant tables and the activations on the write connection, plus the tree's read of
    the ancestors for `granteesReaching()`, and refuses first while the package is not healthy. A list cannot say
    `unknown`, so a tree that throws is thrown, a subtree on another connection than the package's is refused with
    `UnexpectedValueException`, and a subtree query that fails as it runs is thrown as its `QueryException` once
    `granteesWithin()`'s savepoint has rolled back, never answered as an empty list.

## Success Path

`forIdentity(Reference::of($person), $account)` asks the directory for the person's principals and gets a complete
list of two. It asks the bound tree for the account's subtree query and runs one query over the role, permission and
policy grant tables for the person and both principals, selecting the live rows whose root is the platform, is outside
the subtree, or names half a tenant. No row comes back, so the answer is `WITHIN`. `hasGrantIn($user, $child)` makes
the user a subject through the bound resolver, reads the child's chain from the tree, and asks whether any live grant
of the user, or of its identity, applies in the child; an ancestor's subtree grant does, so the answer is `PRESENT`.

An application moves an account under a second organisation and calls `treeChanged($account)`. `laravel-iam` then asks
`granteesReaching($account)`: the package reads the account's new ancestors from the tree and, in one query, the
grantees of the live grants made in the account, made in the second organisation reaching below it, or platform-wide,
and returns their references, each once and in order; it reports them to its sign-on scope widening.

A trusted `grantRole($principal, 'editor', tenant: $account)` with a hook configured opens the transaction, resolves
the role and the scope without locking, and classifies the grant: the subject resolver names the person behind the
principal, the directory lists its principals completely, and none of their grants applies in the account, so the
grant widens as `NEW_TENANT`. The hook is called once with that grant and returns. The call writes the row, classifying
it again first; it is still covered, so the role is granted and `RoleAssigned` is dispatched after commit.

## Failure / Edge Cases

- **An incomplete directory.** `UNKNOWN`, unless a grant already proves `OUTSIDE`.
- **No grants.** `WITHIN` with a complete directory, `UNKNOWN` with an incomplete one.
- **A tree that throws, or a subtree on another connection.** The failure is written to the log; `forIdentity()` is
  `OUTSIDE` on a platform-wide grant, else `UNKNOWN`; `hasGrantIn()` looks only in the tenant and the platform, and is
  `UNKNOWN` when it finds nothing.
- **A subtree query that fails as it runs.** A closure table that is missing, or a column of another type, fails only
  inside the grant query. That query runs in a savepoint of its own, so the failure rolls back only that query and the
  caller's transaction stays usable, as PostgreSQL otherwise would not leave it. Only the `QueryException` is caught:
  it is written to the log, and `forIdentity()` reads the platform-wide grants alone, answering as for a tree that
  throws. `hasGrantIn()` never runs the subtree query, so it is unaffected.
- **A row naming half a tenant.** `UNKNOWN` for `forIdentity()`, unless another root is outside; never a grant for
  `hasGrantIn()`, since a check applies a grant stored that way nowhere (what restricts of such a row applies everywhere
  instead, see `Support\TenantColumns`); never listed by `granteesReaching()` or `granteesWithin()`.
- **A tree that cannot be read, for a list.** `granteesReaching()` and `granteesWithin()` throw what the tree throws; a
  subtree on another connection is refused with `UnexpectedValueException`; a subtree query that fails as it runs is
  thrown once only its savepoint has rolled back. Neither answers an empty list it cannot vouch for.
- **The same key under two types.** Never confused: grantees are matched by type and key together.
- **Expired grants, boundaries, guardrails and policies attached to roles.** Never read as the grantees' grants; a
  role a policy is attached to is never listed by `granteesReaching()` or `granteesWithin()`.
- **A hook that refuses.** Everything rolls back, a sync's revocations included; no event, no retry, no denial. A
  concurrency error the hook's own preparation meets is handled as any other (invariant 13).
- **A grant relied on vanishes before the locks.** The final classification, read under the lock, finds the grant
  widening, the try is a conflict, and the retry runs the hook; inside the application's transaction the conflict is
  thrown as `TransactionConflictException` instead.
- **A hook that calls a service.** Refused with `GrantHookRecursionException`; the guard is lifted when the hook
  returns or throws.
- **An unresolvable identity.** Refused with `UnresolvableRecipientException` when a grant is evaluated; a grant held
  unchanged needs no identity.
- **No hook configured.** Nothing is proposed, classified or checked, so a call costs what it did before.
- **Raw writes and memberships.** Raw writes run no hook; the application, or `laravel-iam`, calls the hook on its own
  membership path with `WideningReason::MEMBERSHIP`.

## Implementation Anchors

- `Contracts\IdentityDirectory`, `Support\IdentityPrincipals` and `Resolvers\GuardUserIdentityDirectory` -- the seam,
  its answer and the default.
- `Support\GrantRoots` -- the union over the grant tables, `within()`, `against()` and `appliesIn()`.
- `Services\GrantScopeQuery` -- `forIdentity()`, `hasGrantIn()`, the grantees and the tree's failures, and
  `granteesReaching()` and `granteesWithin()` with their one query over the grant tables (`holding()`).
- `Enums\GrantScopeStatus` and `Enums\GrantPresence` -- the answers.
- `Config\SeamConfigValidator` and `Config\ConfigValidator` -- the `identity_directory` validation.
- `AuthorizationServiceProvider::registerConfiguredDefaults()` and `registerManagementServices()` -- the scoped
  directory and the singleton service.
- `Contracts\GrantHook`, `Hooks\GrantHooks`, `Hooks\GrantWidening`, `Hooks\ProposedGrant` and
  `Enums\WideningReason` -- the hook contract, its default binding and what it is handed.
- `Hooks\WideningClassifier` and `Hooks\WideningPhase` -- the classification, the call point and the coverage check.
- `Support\OperationScope::whileHookRuns()`, `isNested()`, `retriedInPlace()` and the trusted retry -- the recursion
  guard, nesting and retries inside the application's transaction.
- `Support\GrantRoots::appliesUnderLock()`, `Administration\DependencyPins::lockCoverage()` and
  `Services\Support\GrantTable::liveRows()` and `liveRow()` under a lock -- the locking reads of the coverage check.
- `Services\GrantService::grant()`, `sync()` and `plan()`, `Services\Support\SyncPlan` and
  `Services\BreakGlassService::activate()` -- the placement.
- `Exceptions\GrantRefusedException`, `GrantHookRecursionException`, `NestedGrantException` and
  `UnresolvableRecipientException`; `Config\GrantHookConfigValidator`.

## Authoritative Tests

- `Feature\Services\GrantScopeQueryTest` -- the containment matrix (the tenant, descendants, ancestors, siblings, the
  platform, no grants, an incomplete directory, every application, morph collisions, expiry, several principals,
  deny-only policies, boundaries and guardrails ignored) and presence against containment (ancestor subtree grants,
  node-only grants, principal isolation, identity inheritance, machines, applications, unreadable trees, subtree queries
  that fail as they run, and grantees), under the closure-table and flat trees, and the status carrying nothing else;
  the grantees reaching and within a tenant (the tenant, an ancestor with and without its subtree, a descendant, a
  sibling, another organisation and the platform, expired, half-tenant and stray inline rows, a role a policy is
  attached to, the clashing ids of a mixed-type tree, principals and identities each once in byte order, applications, a
  model tenant, the query count, a simulated move, ancestors read afresh in a batch, a tree that throws, a subtree on
  another connection, a subtree query failing in its savepoint and the write connection).
- `Unit\Support\ReferenceTest` -- references sorted by type and then key, byte by byte, whatever order they come in.
- `Feature\Support\GrantRootsTest` -- the classification, half-tenant rows, one query naming each grantee once,
  grantees sharing a key under two types, applicability, applicability under a lock table by table, inline policies,
  nested subtrees, refused subtrees and the write connection, on a connection outside the test's transaction.
- `Performance\GrantScopeQueryBudgetTest` -- the query count is the same for one grant and ten of each kind, and at
  depth one and depth eight, for each answer and each list of grantees.
- `Feature\Resolvers\GuardUserIdentityDirectoryTest`, `Unit\Config\SeamConfigValidatorTest`,
  `Feature\ConfigValidatorTest` and `Feature\AuthorizationServiceProviderTest` -- the default directory, its validation
  and its binding.
- `Feature\Hooks\WideningClassifierTest` -- the classification matrix: an identity grantee, the platform, a new
  tenant, an ancestor, a tenant held, siblings, a re-arm, a wider reach, an extension, a shortening, an unchanged
  grant, an incomplete directory, an unreadable tree and unresolvable identities, a grantee by reference, a chain read
  afresh inside a batch, and a locked classification answering as an unlocked one.
- `Feature\Hooks\WideningPhaseTest` -- the hook before the first lock, a veto rolling back with no event, the coverage
  conflict, the check after the locks reading the evidence under the lock, a revocation landing between the hook phase
  and that check, tried again with the hook or, inside the application's transaction, thrown as
  `TransactionConflictException`, a retry there never calling the hook again, trusted and delegated, the recursion
  guard, the grant scope query from a hook, nested calls and a binding that is no hook.
- `Feature\Services\GrantServiceTest` and `Feature\Hooks\GrantHookEntryPointsTest` -- every entry point (the service,
  the trait helpers, `authorization:grant`), trusted and delegated, a sync's hooks all run before any lock or write
  (`GrantServiceTest::testASyncRunsEveryHookBeforeAnyLockOrWrite`), the coverage race of a grant and a sync, a delegated
  refusal after the hook, a hook run again on a retried try, and a refusal not retried.
- `Feature\Services\BreakGlassServiceTest` -- an activation's hooks asked and able to refuse, and its coverage race
  tried again with the hook, trusted and delegated.
- `Feature\MigrateSpatieCommandTest` -- the Spatie import's grants each made once its catalogue has committed.
- `Feature\Services\GrantTableTest` and `Feature\Administration\DependencyPinsTest` -- the grantee's rows read under a
  lock, and the coverage check's locks last in the lock order.
- `Feature\Hooks\GrantHooksTest`, `Unit\Config\GrantHookConfigValidatorTest` and `Feature\OperationScopeTest` -- the
  composite's order and stop, its validation, the guard and the trusted retry.
- `Unit\Support\OperationTest`, `Unit\Support\RequestClientTest`, `Unit\Hooks\GrantWideningTest`,
  `Feature\OperationScopeTest` and `GrantServiceTest::testTheHookAloneIsHandedTheRequestsClient` -- the client read
  from a routed request for a delegated operation, none for trusted, console and queued work, an explicit client kept,
  the work and its events given the operation without it, and the hook handed it.
- `Feature\Hooks\ListedGrantHooksTest` -- the listed hooks run before whatever the contract resolves to: a hook bound
  before or after the package registered, every way of binding it, a deferred provider's, the default without running
  twice, and an earlier extender's decoration, either refusing; a wrapped hook not wrapped again and a later decoration
  wrapped again running the listed hooks once, nothing extended with none listed, the bound hook's lifetime kept in a
  queue worker and each Octane sandbox, nothing built while registering, a rebinding watcher handed the wrapped hook,
  and nothing wrapped twice. `Feature\Hooks\WideningPhaseTest` -- the grant service running the listed hooks before an
  instance bound after registration and a hook bound after a wrapped instance. `Feature\Registrars\SeamBindingsTest` --
  the default bound with no hook, and the extender registered only when hooks are listed.

## Change Triggers

- Counting any other row as a grant, or leaving one out, changes invariant 2.
- Inferring principals from anything but the directory breaks invariant 1.
- Returning anything beyond the status, or for a list anything beyond the grantees, breaks invariant 8.
- Listing a grantee whose grant does not reach the tenant or lie within it, or answering an empty list for a tree that
  cannot be read, breaks invariant 17.
- A per-grant or per-tenant query, or loading a subtree's ids, breaks invariant 9.
- Caching an answer needs invalidation across every principal of an identity.
- Handing the client to anything but the grant hook (an event, a cache key, a log or a stored row) breaks invariant 16.
- Classifying from anything but the identity and every principal the directory lists, or skipping the hook in doubt,
  breaks invariants 10 and 11.
- Letting a hook change the grant, or a service run while a hook does, breaks invariant 13.
- Calling a hook after the package's first lock, or skipping the coverage check, breaks invariant 14.
