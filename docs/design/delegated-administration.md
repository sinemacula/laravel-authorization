# Delegated Administration

Granting, revoking and editing roles, permissions and policies are themselves actions this package checks (AUTHZ-11.1).
This note gives the whole design of delegated administration, built in four parts (N78), and marks what this release
enforces: the action catalogue, the acting context, the operation resources decided through `check()` and the audit
correlation (part 1), the scope, rank, self, expiry and possession rules of direct grants, with atomic batches (part 2),
and role grants, grantable policies, the owner rule on definitions, the impact of a change on every existing holder,
boundaries and resource-policy attachments (part 3). Part 4 is listed as **Not yet**: until it lands, what it would
prove is refused, so delegated administration never grants anything it cannot justify.

## Invariants

1. **Every administration action is a declared permission (in this release).** `Support\PackagePermissions` declares
   each action as `authorization:<noun>.<verb>`, guard-agnostic and under the `authorization` category, so
   `authorization:sync` writes them, they can be granted and a policy naming them validates: `role.grant`,
   `role.revoke`, `permission.grant`, `permission.revoke`, `policy.attach`, `policy.detach`, `role.create`,
   `role.rename`, `role.update`, `role.delete`, `role.parent.set`, `permission.create`, `permission.rename`,
   `permission.update`, `permission.delete`, `policy.create`, `policy.rename`, `policy.update`, `policy.delete`,
   `boundary.set`, `boundary.remove`, `guardrail.manage`, `resource-policy.attach`, `resource-policy.detach`,
   `role.read`, `permission.read`, `policy.read`, `permission.grantable`, `policy.grantable`, `administration.self`,
   `administration.impersonated` and `administration.unbounded`. The right to manage guardrails was
   `authorization:guardrails:manage`; it is renamed, with no alias, since the package is unreleased.

2. **Trusted or delegated, never in between (N75, in this release).** A management service call without an acting
   context is trusted system work: nothing is decided, and its operation is marked trusted with no actor. A call with
   one is delegated: every change is decided as the actor. An actor that cannot be resolved refuses as
   `subject_unresolved` and never falls back to trusted. `GuardrailService` always takes an acting context.

3. **The acting context is a resolved subject (in this release).** `Administration\ActingContext` holds the `Subject`
   (principal, identity, guard, session, and a machine's credential scopes through the session policy source) and any
   caps the call adds. `current()` keeps the request's session; `for($model)` names a model as `Authorization::for()`
   does, with no session, so session requirements fail closed; `for($subject)` keeps a resolved subject as it is. It is
   never built from a bare `Reference`.

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
   actor administers. Nothing is attached to one operation, so only the resource policies attached to the type
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
   it is written.

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
   `authorization:administration.impersonated` on the same operation. Both actors are reported.

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
    - **scope**: a change that may widen authority decides its own action again in the grant's tenant, standing just
      below it for a subtree grant (`TenantScope::within(..., isBelow: true)`), so only authority that itself reaches
      below counts, and in the grant's application, so a grant to every application needs authority in every
      application, or it is `administration.scope`; a platform-wide change already needs platform authority;
    - **rank**: unless the grantee is the actor, the actor, ranked in the grant's own tenant and application, must be
      strictly senior to the most senior rank the grantee holds anywhere the change reaches (platform-wide, the
      grant's tenant and its ancestors, the tenants below for a grant reaching below, every tenant for a
      platform-wide grant, any application for a grant to every application, `RankComparison::rankAcross()`), and to
      the rank a role grant would give it, or the change is `administration.rank` (`administration.rank_uncomparable`
      when a side or the reach cannot be read), a revocation, a sync, `revokeAll()`, a boundary change and a call that
      changes nothing included, so a refusal never depends on what the grantee holds;
    - **self**: a change to the actor's principal or identity that may widen authority needs
      `authorization:administration.self` on the same operation, or it is `administration.self`;
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
      (`OperationResource::grantable()`), through a source lasting as long as the grant (`HeldLifetime::of()` for a
      permission held, `HeldLifetime::ofPolicy()` for a stored policy, a resource policy never expiring). Otherwise it
      is `administration.not_grantable` when the actor does not hold the permission across the reach and lifetime, and
      `administration.unprovable` when it does but cannot be proved contained. An extension needs authority lasting
      until the new expiry; a shortening only narrows;
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
      boundary policy, `authorization:administration.unbounded`;
    - **the impact check** (`Administration\Impact`, `Administration\AffectedHolders`): every holder a change reaches,
      read set by set (direct grantees, grantees of the roles below, subjects a policy is attached to or bounds,
      principals a resource policy names), is weighed at once, at a fixed cost: the action across the definition's whole
      reach, the actor strictly senior to every holder but itself (`RankComparison::rankAcrossAll()`), and
      `administration.self` for a change reaching the actor; more than `authorization.administration.max_impact`
      distinct holders (1000 by default, validated at boot) is unprovable, never approximated: each set asks for its
      distinct holders, at most one more than the limit, whatever the sets before it hold, so a holder named twice never
      hides one not read yet;
    - **boundaries**: a boundary that only adds or tightens a cap narrows; replacing one with a wider boundary, and
      removing one, cannot in general be bounded, so the package takes one fail-closed rule: each is unprovable unless
      the actor is also allowed `authorization:administration.unbounded` on the same operation, after the scope, rank
      and self rules;
    - **resource-policy attachments**: every principal the allows name, and every holder of a role a selector names, on
      one record or the whole type, is weighed by the impact check across the attachment's reach, with the policy
      route.

13. **Guardrails and concurrency (part 4, Not yet).** Guardrail changes join the operation-resource path. Every
    authorization dependency of a change is locked or version-checked, so a concurrent revocation, role growth, policy
    rewrite or tenant move never commits on stale authority, and the trusted paths are documented as integration
    surfaces. Until then, guardrails keep their own authority rule (`GuardrailAuthority`, decided inside the change's
    transaction) and the exact-action exemption of `authorization:guardrail.manage` from the guardrail stage.

## Success Path

1. An administrator's screen builds `ActingContext::current()` and an `OperationResource` for the change it offers, and
   shows the control when `$actor->check($resource)` allows.
2. The screen calls the service with `actor: $actor`. The service resolves the records, runs its structural checks,
   begins the operation (delegated, with the actor's principal, identity and the call's actions), and inside its
   transaction decides every change as the actor, each on its operation resource stamped with the operation's id.
3. Each decision goes through every stage: the subject, the tenant (the intended tenant), the denies, the guardrails,
   the boundaries, the session caps, the allows, then the administration stage. `DecisionEvaluated` reports it.
4. Every change allowed, the service writes, and the change events are dispatched after commit, each carrying the
   operation, whose id the decisions named.

## Failure / Edge Cases

- **Not allowed.** A decision that refuses throws `AuthorizationException` (or `InsufficientAuthenticationException` for
  a step-up) with the decision, after `AuthorizationFailed` is dispatched; the transaction rolls back, nothing is
  written and no change event is dispatched. The client sees the one `denied` line.
- **Allowed but refused by a constraint.** The administration stage refuses with the constraint's reason, with a trace
  step naming it; a widening change no rule of this release proves is `administration.unprovable`.
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
- `Services\Support\GuardrailAuthority` -- the guardrail right, decided inside the transaction.
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
  transaction, impersonation, and the exemption of exactly `authorization:guardrail.manage`.
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
- Part 4 moves guardrail changes onto the operation-resource path and adds the concurrency protocol.
- Adding an administration action, or an attribute of the operation resource, changes `PackagePermissions` or
  `OperationAttributes` and their tests, and the README's tables.
