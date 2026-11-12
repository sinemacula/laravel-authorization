# Delegated Administration

Granting, revoking and editing roles, permissions and policies are themselves actions this package checks (AUTHZ-11.1).
This note gives the whole design of delegated administration, built in four parts (N78), all of which this release
enforces: the action catalogue, the acting context, the operation resources decided through `check()` and the audit
correlation (part 1), the scope, rank, self, expiry and possession rules of direct grants, with atomic batches (part 2),
role grants, grantable policies, the owner rule on definitions, the impact of a change on every existing holder,
boundaries and resource-policy attachments (part 3), and the concurrency protocol, guardrail changes under it, the
trusted integration surfaces and the adversarial tests (part 4). What no rule proves is refused, so delegated
administration never grants anything it cannot justify.

## Invariants

1. **Every administration action is a declared permission (in this release).** `Support\PackagePermissions` declares
   each action as `authorization:<noun>.<verb>`, guard-agnostic and under the `authorization` category, so
   `authorization:sync` writes them, they can be granted and a policy naming them validates: `role.grant`,
   `role.revoke`, `permission.grant`, `permission.revoke`, `policy.attach`, `policy.detach`, `role.create`,
   `role.rename`, `role.update`, `role.delete`, `role.parent.set`, `permission.create`, `permission.rename`,
   `permission.update`, `permission.delete`, `policy.create`, `policy.rename`, `policy.update`, `policy.delete`,
   `boundary.set`, `boundary.remove`, `guardrail.manage`, `resource-policy.attach`, `resource-policy.detach`,
   `role.read`, `permission.read`, `policy.read`, `permission.grantable`, `policy.grantable`, `administration.self`,
   `administration.impersonated`, `administration.unbounded`, `role-exclusion.declare` and `role-exclusion.remove`,
   the last two weighed by the owner rule and by `Administration\ExcludedRoles` (see
   [Separation of duties](separation-of-duties.md)). The right to manage guardrails was
   `authorization:guardrails:manage`; it is renamed, with no alias, since the package is unreleased.

2. **Trusted or delegated, never in between (N75, in this release).** A management service call without an acting
   context is trusted system work: nothing is decided, and its operation is marked trusted with no actor. A call with
   one is delegated: every change is decided as the actor. An actor that cannot be resolved refuses as
   `subject_unresolved` and never falls back to trusted. `GuardrailService` always takes an acting context.

3. **The acting context is a resolved subject (in this release).** `Administration\ActingContext` holds the `Subject`
   (principal, identity, guard, session, and a machine's credential scopes through the session policy source) and any
   caps the call adds. `current()` keeps the request's session; `for($model)` names a model as `Authorization::for()`
   does, with no session, so session requirements fail closed; `for($subject)` keeps a resolved subject as it is. It is
   never built from a bare `Reference`. Its checks are decided in the scope in place, the reach the call puts in place
   included, through the manager's internal `forActor()`, never in the tenant the actor's `Subject` names, which
   `Authorization::for()` would decide in (N109).

4. **One decision path (D22, in this release).** Each service builds an `Administration\OperationResource` for each
   change and decides `check($action, $operationResource)` as the actor, inside the call's transaction
   (`OperationScope::run()`), before anything is written. A screen building the same resource gets the same decision.
   The operation's constraints are an `administration` stage of that same decision, after the allow, which can only
   refuse (`Administration\OperationConstraints`); nothing refuses afterwards in a separate engine.

5. **The operation resource names the change (in this release).** Its reference is `authorization:operation:{id}`, the
   id the call's operation id, its tenant the scope of what the change changes, never the tenant the request is in (the
   tenant a grant is held in, a definition's owner), so the change is decided in that tenant's scope and one outside the
   actor's scope, an ancestor of the request's tenant included, is `tenant_scope`. A change with no tenant, to a
   platform-wide grant, a platform role or a platform-owned record, is decided at platform scope
   (`Support\ResourceScope`), where only a platform-wide grant of the action counts, so an actor holding the action only
   in a tenant is refused it. Who may change a grant row is therefore the scope the actor administers (N79): an actor
   whose authority for the action reaches the row's tenant, from a parent by authority over its subtree or from the
   platform, changes it from its own context, and one `revokeAll()` clears a grantee's rows across every tenant the
   actor administers, and a change that may widen authority reaches no further than the actor administers: one whose
   reach holds a tenant where the actor's authority for the action is denied or limited is `administration.scope`
   (invariant 11). Nothing is attached to one operation, so only the resource policies attached to the type
   `authorization:operation` are read for it, under one cache entry every operation shares. Its attributes reach
   policies under `resource` through the package's `Administration\OperationAttributes` provider, which no configured
   provider replaces: the action, whether it only narrows, whether it changes nothing, the target, its name under its
   kind, the grantee, the application, the reach, the expiry, a policy grantable descriptor's digest, a definition's
   proposed change and the impersonator.

6. **Batches decompose and are atomic (in this release).** A sync, `revokeAll()`, `removeAll()` and `detachAll()` decide
   each change under its own action, all before any is written, so one refusal writes and reports nothing, and no change
   is decided on authority an earlier change would have handed out. There is no blanket action. `revokeAll()` decides
   `boundary.remove` for each boundary it removes. A sync judges which kept rows are live at one instant and re-arms as
   of the same instant, so a row it decided as kept unchanged is never re-armed undecided, even when it expires before
   it is written. A role a sync lists with its own reach (`Support\RoleReach`) and holds live with the other is decided
   as a grant with that reach and the expiry the row keeps, as `grantRole()` decides a changed reach, so a wider one
   needs the scope its subtree reaches and a narrower one is judged narrowing.

7. **A call that changes nothing is still decided (in this release).** A delegated call that finds nothing to change
   decides the change it was asked for (`OperationResource::unchanged()`, or the revocation of the first candidate of a
   name the grantee does not hold): a removal of what is not held, a sync of what is held live, and `revokeAll()`,
   `removeAll()` or `detachAll()` of a grantee or record holding nothing, each of whose actions is decided at platform
   scope. Such a change only narrows, so it needs no scope, self or possession right: an actor allowed the action makes
   it, writing nothing, once the rank rule passes for a change to another identity or principal. An actor not allowed
   the action, or not senior to the grantee, is refused whether or not anything was there, so a refusal never tells it
   what a grantee holds. Policies read it as `resource.unchanged`.

8. **What cannot be proved is refused (in this release).** Once the action is allowed, a change that may widen what
   anyone may do and that no rule of this release proves is refused as `administration.unprovable`. A change that can
   only narrow (`Administration\Narrowing`) is allowed once the rank rule passes: revoking a permission,
   revoking a role no policy attached to it or its ancestors denies anything in, read across every tenant on the write
   connection, so a screen and the service judge alike and an ancestor the tenant scope hides still counts, detaching a
   policy with no deny statement, and a grant that only shortens or narrows one the grantee holds live in the same scope
   (`Narrowing::isShortening()`), and a boundary that only adds or tightens a cap. A chain that cannot be read whole is
   taken to deny. What the rules of parts 2 and 3 cannot prove, a detach of a denying policy, a lifted deny, a holder
   set over its limit, a document or chain that cannot be read, is unprovable.

9. **Impersonation (in this release).** A delegated change made while impersonating (`ActingContext::impersonatedBy()`)
   is refused as `administration.impersonating` unless the actor is also allowed
   `authorization:administration.impersonated` on the same operation, at its node and, for a change that may widen
   authority, across the change's whole reach by the administered-scope rule (invariant 11), so a deny of the right in
   any tenant the change reaches refuses it. Both actors are reported.

10. **Rank is a comparison, never an allow (N76, in this release).** `Administration\RankComparison` compares the actor
    and the target through the same scope-aware path (the roles each holds in the scope, expired grants and other
    applications never counting): strictly senior, an unranked target the most junior, an unranked actor acting on no
    one, an uncomparable side failing closed, and rank turned off passing every comparison. Roles are read on the write
    connection, as every other source of `check()` is. When neither side holds a
    ranked role, the comparison refuses: both count as the most junior, so their ranks are equal, and strict seniority
    refuses equal rank; an application that leaves rank on but ranks no role should turn it off. An actor given as a
    resolved `Subject` is ranked by the roles that reach it, its principal's and its granting identity's, and a rank
    the change would grant the target counts as the target's. `canActOn()` returns the comparison alone.

11. **Direct grants (part 2, in this release).** The administration stage (`Administration\OperationConstraints`)
    weighs every change to an identity or a principal (`Administration\OperationGrantee`), in order, each further check
    decided as the actor through every stage up to the allow but never through the stage again
    (`Administration\FurtherChecks`):
    - **scope** (N79, `Administration\AdministeredScope`): the actor must administer the whole reach of a change that
      may widen authority, or it is `administration.scope`. The change decides its own action again in the grant's
      tenant, standing just below it for a subtree grant (`TenantScope::within(..., isBelow: true)`), so only authority
      that itself reaches below counts, or at platform scope for a platform-wide grant, and in the grant's application,
      so a grant to every application needs authority in every application. A decision at one node reads only what
      applies there, so a reach wider than its node, platform-wide or reaching below, is also refused when anything that
      denies or caps the actor anywhere in it could limit the action itself, read exactly as the possession route reads
      a granted permission (`Administration\PossessionLimits`, bounded by `max_impact`): a deny statement whose actions
      overlap it, a conditional one counting as a deny, a boundary or guardrail not allowing it whole, a session cap not
      covering it, or a tree, row or document that cannot be read. An actor allowed `authorization:*` at the platform
      but denied `authorization:role.grant` by a role it holds in one tenant administers no platform-wide reach, and a
      parent's administrator denied an action in one child administers no subtree holding the child; a node-only change
      is decided at its node alone. Every further right a widening change needs beside its action,
      `administration.self`, `administration.unbounded`, `administration.impersonated` and the grantable rights, is
      weighed across the same reach by the same rule (`AdministeredScope::isAllowedAcross()`: allowed at the node the
      operation is decided at and again at the reach's node, with nothing anywhere in a wider reach that could limit it;
      `AdministeredScope::isLimited()` for a grantable right already decided in the reach), each refusing with its own
      reason, so a right allowed at the platform but denied by a role the actor holds in one tenant is never used on a
      change that reaches that tenant. The further rights inherit the rule's conservatism deliberately: any deny
      statement whose actions overlap the right counts, whatever its application or conditions, so a deny held only for
      another application, or a conditional one that would never hold, still refuses it across a reach wider than its
      node. What could limit a right across a reach is read once per decision for each right, reach and scope in place
      (`FurtherChecks::limited()`), so a role grant carrying many policies reads the grantable rights' limits once. A
      guardrail's removal is weighed across the subtree it caps by the same rule (invariant 14);
    - **rank**: unless the grantee is the actor, the actor, ranked in the grant's own tenant and application, must be
      strictly senior to the most senior rank the grantee holds, by a grant or a live break-glass activation, anywhere
      the change reaches (platform-wide, the grant's tenant and its ancestors, the tenants below for a grant reaching
      below, every tenant for a platform-wide grant, any application for a grant to every application,
      `RankComparison::rankAcross()`), and to the rank a role grant would give it, or the change is
      `administration.rank` (`administration.rank_uncomparable` when a side or the reach cannot be read), a revocation,
      a sync, `revokeAll()`, a boundary change and a call that changes nothing included, so a refusal never depends on
      what the grantee holds;
    - **self**: a change to the actor's principal or identity that may widen authority needs
      `authorization:administration.self` on the same operation, at its node and across the change's whole reach as its
      action is, or it is `administration.self`: an actor allowed `authorization:*` at the platform but denied
      `authorization:administration.self` by a role it holds in one tenant cannot widen its own authority platform-wide,
      or across a subtree holding that tenant; a change to itself that only narrows needs no self right;
    - **possession** (N77, `Administration\Possession`): a direct grant of a permission is allowed when the actor
      provably holds it across the grant's reach (tenant, subtree, application) and lifetime
      (`Administration\HeldLifetime`), its `check()` there allows it, and nothing that denies or caps the actor could
      limit it anywhere in the reach (`Administration\PossessionLimits`: any deny statement naming an action it covers,
      a boundary or guardrail not allowing it whole, unconditionally and on every resource, a cap not covering it, or a
      tree, row or document that cannot be read, the actor's policies, its roles', every resource's, its boundaries and
      the guardrails read as stored whatever their application, a table at a time with the reach in the query
      (`Administration\GrantReach`) and every policy found in one more query, so the cost never grows with other
      tenants' rows; two patterns that both hold wildcards, one of them `?` or a `[...]` class, are taken to overlap);
      or when `authorization:permission.grantable` is allowed, in the grant's reach, on the grant's descriptor
      (`OperationResource::grantable()`), with nothing that denies or caps the actor anywhere in a reach wider than its
      node that could limit the right (read as the scope rule reads the action, and only once the right is allowed, once
      per decision however many permissions and policies a role hands out), through a source lasting as long as the
      grant (`HeldLifetime::of()` for a permission held, `HeldLifetime::ofPolicy()` for a stored policy, a resource
      policy never expiring). Otherwise it is `administration.not_grantable` when the actor does not hold the permission
      across the reach and lifetime, and `administration.unprovable` when it does but cannot be proved contained. An
      extension needs authority lasting until the new expiry; a shortening only narrows;
    - **batches** are decided kind by kind, then by tenant, application and record (`ActingContext::authorizeIn()`), so
      the first refusal never depends on the order rows were read in;
    - the owner rule (D20, `Administration\OwnerConstraint`) does not apply to grant rows (N79): part 3 applies it to
      definitions, their membership and attachments.

12. **Roles, grantable rights, definitions and impact (part 3, in this release).** Every widening change distributes
    authority, so it passes only when the actor may hand out everything it adds and it reaches only holders the actor
    administers. Each rule runs in the same administration stage (`Administration\OperationConstraints`, and
    `Administration\DefinitionConstraints` for anything but a change to a subject):
    - **role grants**: a role's whole active authority, the permissions it and its ancestors carry live, the policies
      attached to them, and the allows of every resource policy in the grant's reach that names the role or an ancestor
      by a `role:<key>` selector, since such an allow reaches whoever holds the role, now or later
      (`Administration\RoleAuthority`, read in a fixed number of queries outside every tenant scope, the resource
      policies bounded by `max_impact`, and anything it cannot read whole unprovable), each passing its route across the
      grant's reach and lifetime; every permission, and every action of a policy, is decided in one pass
      (`Possession::refusalOfEach()`), so the cost never grows with what the role carries; a role's denies never
      justify its allows, and its rank counts as the grantee's;
    - **the stored row**: a delegated change is weighed on the row it writes against, read again by key inside the
      transaction (`Services\Support\StoredRecords`, and a fresh read of a record a definition change edits), so a
      model with unsaved changes, or one read before a rewrite, is never judged on a rank, name or document the row
      does not hold;
    - **the policy route** (`Administration\PolicyRoute`): containment, every allow naming its actions alone, no
      resource pattern, condition or principal (a resource policy's principals are weighed by the impact check, and the
      allows that select a granted role reach the grantee itself), each action passing the permission route; or
      `authorization:policy.grantable` on the descriptor `OperationResource::policyGrantable()` builds, naming the
      policy and its document's digest (`DocumentDigest`) under `resource.digest`, so a right bound to one digest never
      covers a rewritten document. A rewrite is built by `OperationResource::rewrite()`, for a screen as for the
      service, with the document as it would be stored and its digest under `resource.change.digest`;
    - **the owner rule** (D20): a change to a definition, or to a role's permissions, policies or parent, is made from
      the tenant that owns it, a platform definition's from the platform (`FurtherChecks::$from`, the tenant the check
      is made from), or it is `administration.owner`, narrowing or not; a resource policy's attachment is a grant to a
      resource, which the rule never weighs (N79). The record services create a definition owned by the tenant a call
      names (`tenant:`), else the platform, so a tenant administrator creates its own tenant's definitions from its own
      context;
    - **definitions**: creating passes, a created role junior to the actor; renaming a role or a permission (or changing
      a permission's name or guard) is a new grant to every holder, under the new name; a rank that is no whole number
      cannot be compared (`administration.rank_uncomparable`); a rank changes only on a role junior to the actor and
      must leave it junior, so a senior role is never demoted; a rank made more senior is weighed against the role's
      holders; deleting narrows by `Narrowing`'s rules;
    - **membership and hierarchy**: adding a permission or a policy to a role, and setting or replacing its parent, hand
      what is added to every holder of the role and of the roles below it (`Administration\RoleParent` for a parent);
      clearing or replacing a parent whose chain carries a deny is unprovable;
    - **policy documents** (`Administration\PolicyRewrite`): compared with the stored document statement by statement
      (`Administration\DocumentComparison`), a rewrite that only removes allows or adds denies narrows; one that lifts a
      deny is unprovable; one that adds allows needs the impact check, the policy route for what it adds and, for a
      boundary policy, `authorization:administration.unbounded`, weighed across the policy's reach;
    - **the impact check** (`Administration\Impact`, `Administration\AffectedHolders`): every holder a change reaches,
      read set by set (direct grantees, grantees of the roles below, subjects a policy is attached to or bounds,
      principals a resource policy names), is weighed at once, at a fixed cost: the action across the definition's whole
      reach, by the same administered-scope rule as a grant (`Administration\AdministeredScope`), the actor strictly
      senior to every holder but itself (`RankComparison::rankAcrossAll()`), and `administration.self`, weighed across
      the same reach, for a change reaching the actor, as `administration.impersonated` is for a change made while
      impersonating; more than `authorization.administration.max_impact` distinct holders (1000 by default, validated at
      boot) is unprovable, never approximated: each set asks for its distinct holders, at most one more than the limit,
      whatever the sets before it hold, so a holder named twice never hides one not read yet;
    - **boundaries**: a boundary that only adds or tightens a cap narrows; replacing one with a wider boundary, and
      removing one, cannot in general be bounded, so the package takes one fail-closed rule: each is unprovable unless
      the actor is also allowed `authorization:administration.unbounded` on the same operation, across its whole reach,
      after the scope, rank and self rules;
    - **resource-policy attachments**: every principal the allows name, and every holder of a role a selector names, on
      one record or the whole type, is weighed by the impact check across the attachment's reach, with the policy
      route.

13. **The concurrency protocol (part 4, in this release).** A delegated decision never commits on authority that
    changed under it, and a delegated operation never writes a row its decisions did not see. Inside
    `OperationScope::run()`, each try of a delegated operation holds `Administration\DependencyPins`, which lock every
    dependency before it is read, in one order within the operation (`Enums\DependencyPhase`):
    - **the actor**, once, before anything else: the grant rows of its principal and identity (roles, live break-glass
      activations, permissions, policies, boundaries), the guardrails on the platform and on the chain of the request's
      tenant, the resource policies of the type `authorization:operation`, the roles held and every role above them with
      the permissions and policies they carry, then the permission and policy rows all of these name
      (`Administration\AuthorityRows`);
    - **the target**, before the service reads it: the grantee's grant rows, or a role grantee's chain and what it
      carries (`DependencyPins::lockGrantees()`, the first step of every grant, revocation, sync, `revokeAll()` and
      boundary change), then, before the first change is decided (`ActingContext::authorizeIn()`), for each change the
      chain of the tenant it holds in and the guardrails there, the resource policies of the resource type a policy is
      attached to, the role, permission or policy handed out or taken away, and a definition's record, with a new
      parent's chain. A role, permission or policy the service read before its lock, such as one named, is read again
      under the lock and compared column by column with what the service read, and one that differs, or is gone, throws
      `Exceptions\DependencyChangedException`, so no decision uses a rank, document or guard the row no longer holds;
    - **what a decision reaches**, as it reads it: every set of holder rows the impact check weighs
      (`Administration\AffectedHolders`), the roles named, with those below them and every role whose parent is one of
      them, a role's row locked whether or not the hierarchy is on, so a resource policy naming a role and a concurrent
      grant of that role always meet on its row; and the resource-policy attachments and guardrails across a grant's
      reach, with the policies among them, that a role grant's authority (`RoleAuthority`) and a possession check
      (`PossessionLimits`) read. Each such set is locked only when it holds no more than
      `authorization.administration.max_impact` holders or rows (`DependencyPins::lockWithin()`); a larger one is
      refused as `administration.unprovable` without being locked, so one change never locks more than that;
    - **the coverage check**, last, once every change is decided and before the write, in a grant whose hooks run
      (AUTHZ-11.3): the grantee's own rows and the grants of the identity, the grantee and every principal the
      directory lists that apply in a tenant the grant is written in, read table by table, at most one row of each
      (`DependencyPins::lockCoverage()`, `Support\GrantRoots::appliesUnderLock()`). A trusted grant, which has no pins,
      reads them under the lock directly.

    Within a part, the rows are locked in `AuthorityRows`' fixed order, each query's keys sorted, and a part never
    locks before an earlier one (a `LogicException`). Every lock is `lockForUpdate()` on the write connection, outside
    every tenant scope, expired grants included. The tenant tree is the application's and cannot be locked, so the
    chain of each tenant is read afresh and pinned, and `treeChanged()` reported meanwhile marks every running
    delegated operation moved (`OperationScope::treeChanged()`).

    Once every change is allowed, and before anything is written, every pinned set is read again, once as a decision
    reads it and once under the lock, and every chain afresh; anything that differs (a row written, inserted or
    removed, a snapshot older than the locks, a tenant moved) throws `DependencyChangedException`. The write then
    touches only what was decided: `revokeAll()` and `BoundaryService::removeAll()` delete exactly the decided rows by
    key, and a row decided as held by a sync, or a boundary decided as removed, that is not there by the write throws
    `DependencyChangedException` too. A conflicting try is rolled back and run again from the start
    (`Administration\ConflictRetries`), up to `authorization.administration.retries` times (2 by default, validated at
    boot), each try reading every record afresh rather than reusing a model the rolled-back try changed
    (`Services\Support\RecordWriter`, `StoredRecords`). A PostgreSQL serialisation failure or deadlock, a MySQL
    deadlock or lock wait timeout, a busy SQLite database, or Laravel's `DeadlockException` for one met in a nested
    transaction, is tried again the same way when the operation opened the outermost transaction. Inside the
    application's own transaction it is thrown as `Exceptions\TransactionConflictException` (SQLSTATE `40001`, the
    database's error as its previous), since the database rolled the whole transaction back or needs it restarted,
    which only the application can do; a changed dependency is tried again there only back to the operation's
    savepoint, and on MySQL (repeatable read) a snapshot the application's transaction already took is kept across
    that rollback, so the operation may conflict on every try. Once every try has conflicted, the call is refused with
    `AuthorizationException` as `administration.conflict`, at the `administration` stage, recorded and reported as the
    acting subject's refusal with `DecisionEvaluated` and `AuthorizationFailed`, as `check()` and `authorize()` record
    one.

    Deadlocks are detected and retried, not prevented. The order holds within one operation, but two operations that
    cross can still deadlock: one's actor may be the other's target, or one's held role the other's granted role, so
    each holds a row the other waits for. PostgreSQL and MySQL detect the deadlock and refuse one of the two, which is
    tried again, or thrown as `TransactionConflictException` inside the application's transaction.

    What each database gives: PostgreSQL and MySQL hold the row locks until the transaction ends, so a concurrent write
    of a locked row waits, and the second read catches an insertion the locks do not cover (PostgreSQL's read committed)
    or a snapshot older than the locks (MySQL's repeatable read, whose next-key locks also hold back most insertions).
    SQLite serialises writers and compiles no row lock, so the locks are a no-op there and the second read alone catches
    a change; the tests reach that path by making the change between a read and the write from a listener.

    The protocol takes no lock until the service first reads what the operation changes, and a service's work starts
    inside the call's transaction before it reads or locks anything. The grant hooks (AUTHZ-11.3, N80) run there:
    `Hooks\WideningPhase::before()`, first in the work of a grant or sync, classifies a non-locking preliminary proposal
    and calls the bound hook with every widening grant before the first lock and any write, for trusted and delegated
    calls alike. The call then locks, rebuilds and decides its grants, and `assertCovers()` classifies them again
    before the write, after every other lock, reading the grantee's rows and the grants the classification relied on
    under a lock, the last part of the order (`DependencyPhase::COVERAGE`): a grant that now widens with no hook run
    for it is a `DependencyChangedException`, and the whole call is tried again from the proposal, so the hook may run
    on each try and is never called under the package's locks. Inside the application's transaction a try is rolled
    back only to its savepoint, whose row locks MySQL keeps, so a grant is never tried again there with its hook: that
    conflict, and a retry after any other conflict whose grant would call its hook, is thrown as
    `TransactionConflictException`. A hook only vetoes and never replaces a decision here: a call it lets go on is
    still decided, and refused when it should be. While a hook runs every service refuses
    (`GrantHookRecursionException`), and a widening grant made inside another operation's work is refused
    (`NestedGrantException`). See [Grant scope](grant-scope.md). A trusted call keeps today's cost: with no hook
    configured it runs once, with no pins, no extra lock and no retry; with one, it is tried again only for that
    coverage conflict, and only when it opened the transaction.

14. **Guardrails (part 4, in this release).** Guardrail changes always take an acting context and run under the
    concurrency protocol: the actor's authority, the policy's row and the guardrails of the scope and of the scopes
    above it are locked and pinned before the right is decided, and read again once it is allowed. The right keeps its
    own rule (`GuardrailAuthority`, decided through `check()` from above the scope, inside the change's transaction). A
    removal lifts a cap across the scope's whole subtree, or every tenant for a platform guardrail, so it is also
    weighed across that reach by the administered-scope rule (invariant 11): `authorization:guardrail.manage`, and
    `authorization:administration.impersonated` for an impersonated actor, are refused when anything that denies or caps
    the actor anywhere in it could limit them, through the acting context's further checks
    (`ActingContext::furtherChecks()`), as `GuardrailException` or `administration.impersonating`. The guardrails never
    count against `authorization:guardrail.manage` there either (`PossessionLimits` reads none for it alone). A set only
    adds a cap, so it narrows and is decided from above alone. The exemption from the guardrail stage covers exactly
    `authorization:guardrail.manage`: no guardrail ever blocks it, but the actor's own denies, boundaries and the call's
    caps still refuse it, and every other action, the impersonation right decided beside it included, stays capped by
    the guardrails. A policy in use as a guardrail is never edited or deleted, through the policy service, trusted or
    delegated, or through the model, until every guardrail it is has been removed (`Support\PolicyGuardrails`).

15. **Trusted surfaces (part 4, in this release).** Each of these is trusted system work, an integration surface for
    the application's own code and never an endpoint for user-controlled administration:
    - a management service called without an acting context;
    - a raw Eloquent write on the package's models, pivots or tables, which never takes an actor and runs no grant
      hook;
    - the trait helpers called without `actor:`: every write helper of `HasRoles`, `HasPermissions`, `HasPolicies`
      (`createInlinePolicy()` included) and a role's `ManagesPermissions`, the Spatie aliases included, takes an
      optional `actor:` and hands it to its service;
    - seeders, migrations and the console commands run without `--actor` (`authorization:grant` and
      `authorization:revoke` take one, through `Console\Support\ActorOption`). The maintenance commands
      `authorization:sync` (which records its `--actor`), `authorization:prune` and `authorization:migrate-spatie` are
      operator tooling, never administration on anyone's behalf.

## Success Path

1. An administrator's screen builds `ActingContext::current()` and an `OperationResource` for the change it offers, and
   shows the control when `$actor->check($resource)` allows.
2. The screen calls the service with `actor: $actor`. The service resolves the records, runs its structural checks,
   begins the operation (delegated, with the actor's principal, identity and the call's actions), and inside its
   transaction decides every change as the actor, each on its operation resource stamped with the operation's id.
3. Each decision goes through every stage: the subject, the tenant (the intended tenant), the denies, the guardrails,
   the boundaries, the session caps, the allows, then the administration stage. `DecisionEvaluated` reports it when
   `events.decisions` selects it: a refusal by default, an allow only with `allows: all` or a listed sensitive action
   (events.md invariant 14).
4. Every change allowed, the service writes, and the change events are dispatched after commit, each carrying the
   operation, whose id the decisions named.

## Failure / Edge Cases

- **Not allowed.** A decision that refuses throws `AuthorizationException` (or `InsufficientAuthenticationException` for
  a step-up) with the decision, after `AuthorizationFailed` is dispatched; the transaction rolls back, nothing is
  written and no change event is dispatched. The client sees the one `denied` line.
- **Allowed but refused by a constraint.** The administration stage refuses with the constraint's reason, with a trace
  step naming it; a widening change no rule of this release proves is `administration.unprovable`.
- **Conflict.** A try whose decisions read something that changed before the write, or that the database refused as
  a concurrency error, is rolled back and run again; once the first try and all `authorization.administration.retries`
  retries have conflicted, the call is refused as `administration.conflict`, nothing written and no change event
  dispatched, the refusal recorded and reported with `DecisionEvaluated` and `AuthorizationFailed`. Inside the
  application's own transaction, a database concurrency error is thrown as `TransactionConflictException` for the
  application to restart its transaction.
- **Rolled-back audit.** A denial is reported synchronously inside a transaction that rolls back, so an audit store that
  persists it must write on a connection with no part in that transaction: directly on a database connection of its own,
  or through a queue whose backend shares nothing with it (a non-database driver, or the `database` driver on a
  connection of its own), with `after_commit` off for the queue and the listener. The stock `database` queue on the
  default connection, and the `sync` driver, are rolled back with the refusal.
- **No operation resource.** A check of an administration action with no operation resource, such as a menu deciding
  whether to show the administration area at all, decides the action alone; the administration stage never runs, and the
  service's own decision is still made on the operation.
- **Console.** `authorization:grant` and `authorization:revoke` with `--actor` make the change as that actor, delegated,
  with no session, so a role grant passes only when the actor outranks the identity and may hand out everything the
  role carries; without it they are trusted.
  `authorization:sync`'s `--actor` is recorded on its trusted operation alone.
- **Attribute keys.** An application attribute provider declaring one of the operation resource's keys must declare it
  with the same type, or the context key catalogue refuses it.

## Implementation Anchors

- `Support\PackagePermissions` -- the action catalogue.
- `Administration\ActingContext` -- the acting context, `check()`, `authorize()`, `authorizeIn()`, `authorizeChanges()`
  and `refusal()`.
- `Administration\OperationResource` -- `grant()`, `revoke()`, `unchanged()`, `definition()` and `actedBy()`.
- `Support\ResourceScope::decide()` -- an operation resource with no tenant decided at platform scope;
  `Resolvers\ResourcePolicyResolver` -- an operation's record attachments never read.
- `Administration\OperationAttributes` -- the provider of the resource's attributes, registered by
  `Context\AttributeProviders::fromConfig()`.
- `Administration\OperationConstraints` -- the administration stage, called from `DecisionPipeline::decideGrants()`,
  with `Administration\FurtherChecks`, the further checks it asks of the pipeline and the tenant the check is made from.
- `Administration\OperationChange` -- the grant or removal an operation proposes, as values;
  `Administration\OperationGrantee` -- whether it is for a subject, whether that is the actor, and its model.
- `Administration\Narrowing` -- which removals, and which grants, only narrow; `Services\Support\GrantTable::liveRow()`
  -- the grant held live that a shortening is judged against.
- `Administration\RankComparison` -- the rank comparison, behind `HasRoles::canActOn()`.
- `Administration\OwnerConstraint` -- only the owner edits, applied to definitions by
  `Administration\DefinitionConstraints`, with `Administration\DefinitionChange`, the change to a definition as values.
- `Administration\RoleAuthority`, `Administration\PolicyRoute`, `Administration\RoleParent`,
  `Administration\PolicyRewrite`, `Administration\DocumentComparison` -- role grants, the policy route, parents, policy
  rewrites and the comparison of documents.
- `Administration\Impact`, `Administration\AffectedHolders`, `Config\AdministrationConfigValidator` -- the impact
  check, the holders it reads and its limit.
- `Administration\Possession`, `Administration\HeldLifetime`, `Administration\HeldLifetimes`,
  `Administration\PossessionLimits` -- the possession and grantable routes of a permission handed out, one or many in
  one pass; `Administration\GrantReach` -- the tenants a grant reaches, read once and put into each query.
- `Support\Operation` -- the operation's actor, identity, impersonator, mode and actions.
- `Services\Support\RecordWriter`, `Services\Support\GrantChanges`, `Services\Support\StoredRecords` and every
  management service -- the changes they decide, on the rows as stored, before they write.
- `Services\Support\GuardrailAuthority` -- the guardrail right, decided inside the transaction;
  `Services\GuardrailService` -- guardrail changes under the concurrency protocol; `Support\PolicyGuardrails` -- a
  guardrail's policy never edited or deleted.
- `Administration\DependencyPins`, `Administration\AuthorityRows`, `Enums\DependencyPhase` -- the locks, the pins,
  their order, the bounded locks of what a decision reaches and the validation before the write;
  `Administration\ConflictRetries`, `Exceptions\DependencyChangedException`, `Exceptions\TransactionConflictException`
  -- the retries, `administration.conflict` and a conflict inside the application's transaction;
  `Support\OperationScope` -- the tries of a delegated operation, `pins()` and `treeChanged()`.
- `Evaluation\Enums\DecisionReason`, `DecisionStage::ADMINISTRATION`, `TraceOutcome::SATISFIED` -- the reasons, the
  stage and its trace.

## Authoritative Tests

- `DelegatedAdministrationTest` -- every service method, called with an actor, refused without its action, deciding its
  own action, and made or refused per this release; screens and services agreeing; atomic batches;
  impersonation; the audit fields and the correlation id.
- `ActingContextTest` -- resolution, its failure, the session, caps, a machine's credential caps and refusals.
- `DelegatedGrantsTest` -- part 2 end to end: the rank table over grants, revocations and syncs, the resulting rank, the
  grantee ranked across the reach, self, node-only and application-limited authority, platform grants, the administered
  scope deciding who changes a grant row, possession and its lifetime, every limit that fails it, wildcards of one
  character, explicit grantability across the reach and lifetime, shortening, atomic batches decided on the authority
  held before them, and a screen and the service agreeing over random grants.
- `DelegatedGrantQueryBudgetTest` -- a delegated grant and a sync's additions read as much with unrelated resource
  policies and guardrails as without.
- `DelegatedDefinitionsTest` -- part 3 end to end: role grants over the whole chain, a resource policy naming a role
  reaching its later holders, `policy.grantable` bound to the digest, the owner rule, definitions created from their
  owner's context, a role created senior, renames, role membership against senior, out-of-scope and self holders,
  parents, policy rewrites decided on their digest, the impact limit, boundaries and resource-policy attachments, a
  screen and the service agreeing throughout.
- `AdministrationImpactQueryBudgetTest` -- the impact check reads as much for thirty holders as for three.
- `DelegatedRoleGrantQueryBudgetTest` -- a role grant reads as much for a role carrying thirty permissions, or a policy
  allowing thirty actions, as for three.
- `DefinitionConstraintsTest`, `DefinitionChangeTest`, `RoleAuthorityTest`, `PolicyRouteTest`, `PolicyRewriteTest`,
  `RoleParentTest`, `DocumentComparisonTest`, `ImpactTest`, `AffectedHoldersTest`,
  `HeldLifetimesTest`, `StoredRecordsTest`, `AdministrationConfigValidatorTest` -- each rule of part 3.
- `OperationResourceTest`, `OperationChangeTest`, `OperationGranteeTest`, `OperationAttributesTest`,
  `OperationConstraintsTest`, `FurtherChecksTest`, `NarrowingTest`, `RankComparisonTest`, `OwnerConstraintTest`,
  `PossessionTest`, `HeldLifetimeTest`, `PossessionLimitsTest`, `GrantReachTest` -- the operation resource, its change,
  its grantee, its attributes, the administration stage and each of its constraints.
- `GuardrailAuthorityTest`, `GuardrailServiceTest`, `DecisionPipelineTest` -- the guardrail right inside the
  transaction, impersonation, the exemption of exactly `authorization:guardrail.manage` with the actor's own denies,
  boundaries and caps still refusing, a right revoked or a policy rewritten meanwhile, and a guardrail's policy never
  edited or deleted.
- `EscalationPropertyTest` -- the seeded property (`AUTHZ_PARITY_SEED`, `AUTHZ_PARITY_RUNS`, 150 by default): over
  random tenants, roles with hierarchy and ranks, permissions with wildcards, policies with allows and denies,
  boundaries, guardrails, resource policies and a random actor, with random rights and now and then a grantable right
  to one permission, making random delegated grants, syncs, resource-policy attachments, revocations, boundary and
  definition changes, no committed operation leaves a subject with authority beyond what the actor could hand out,
  judged by `permissionsFor()` before and after at the platform and in every tenant, with no resource and on a post,
  nor leaves a subject the actor outranked as senior as the actor, and no refused one changes anything or dispatches a
  change event.
- `DelegatedRacesTest` -- a concurrent revocation of the actor, a role that grows, a policy rewritten and a tenant moved
  between the decision and the write, a rank or a document changed between the service's read and its lock, and a
  resource policy naming a role attached while the role is granted, each tried again and refused; a harmless race tried
  again and made once; a conflict on every try refused as `administration.conflict`, recorded and reported; a trusted
  call never tried again.
- `GrantServiceTest`, `BoundaryServiceTest`, `RoleServiceTest`, `RecordWriterTest` -- a row revoked or granted while a
  grant, a revocation, a sync, `revokeAll()` or `removeAll()` reads it, or gone by the write, tried again and refused,
  and a row granted after the validation left as it is; each try of a delegated write started from the record as
  stored, a deadlock in a nested transaction included.
- `DependencyPinsTest`, `AuthorityRowsTest`, `ConflictRetriesTest`, `DependencyPhaseTest`,
  `DependencyChangedExceptionTest`, `OperationScopeTest` -- the locks and their order, the validation both ways, the
  chains and a tree reported moved, the retries, serialisation failures and the refusal.
- `HasRolesTest`, `HasPermissionsTest`, `HasPoliciesTest`, `ManagesPermissionsTest` -- each write helper, the Spatie
  aliases and `createInlinePolicy()` included, hands its `actor:` to the service.
- `PackagePermissionsTest`, `OperationTest`, `RecordWriterTest`, `GrantChangesTest` -- the catalogue, the operation and
  the changes the services decide.
- `GrantServiceTest`, `RoleServiceTest`, `BoundaryServiceTest`, `ResourcePolicyServiceTest` -- each service's delegated
  refusals, its calls that change nothing, platform and ancestor scopes, the hidden denying ancestor and the re-arm that
  never runs undecided.
- `ResourceScopeTest`, `ResourcePolicyResolverTest`, `ExpiringGrantsTest`, `LiveGrantsTest` -- platform scope for an
  operation, its attachments, and liveness judged at one instant.

## Change Triggers

- Part 2 (in this release) replaced the `administration.unprovable` refusal of direct permission grants with the scope,
  rank, self, expiry and possession rules, wiring `RankComparison` into every change to a subject; who changes a grant
  row is the administered scope (N79), never the owner rule.
- Part 3 (in this release) did the same for roles, definition edits, boundaries, resource policies and impact, applying
  `OwnerConstraint` to definitions, role membership and policies, and deciding `policy.grantable` and
  `administration.unbounded`.
- Part 4 (in this release) added the concurrency protocol, ran guardrail changes under it, documented the trusted
  surfaces and passed an actor through the trait helpers, and added the escalation property and the race tests, so
  delegated administration is complete.
- The further rights (in this release) are weighed across a change's reach by the administered-scope rule, as its action
  is (#122): the escalation property found an actor allowed `authorization:*` at the platform but denied
  `authorization:administration.self` in one tenant widening its own authority platform-wide, since the self right was
  decided at the change's node alone. `administration.self`, `administration.unbounded`, `administration.impersonated`
  (a review's included) and the grantable rights now pass only when nothing anywhere in the reach could limit them, and
  a guardrail's removal is weighed the same way across the subtree it caps.
- Adding an administration action, or an attribute of the operation resource, changes `PackagePermissions` or
  `OperationAttributes` and their tests, and the README's tables.
