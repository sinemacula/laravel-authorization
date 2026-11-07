# Delegated Administration

Granting, revoking and editing roles, permissions and policies are themselves actions this package checks (AUTHZ-11.1).
This note gives the whole design of delegated administration, built in four parts (N78), and marks what this release
enforces: the action catalogue, the acting context, the operation resources decided through `check()` and the audit
correlation (part 1), and the owner, scope, rank, self, expiry and possession rules of direct grants, with atomic
batches (part 2). Parts 3 and 4 are listed as **Not yet**: until each lands, what it would prove is refused, so
delegated administration never grants anything it cannot justify.

## Invariants

1. **Every administration action is a declared permission (in this release).** `Support\PackagePermissions` declares
   each action as `authorization:<noun>.<verb>`, guard-agnostic and under the `authorization` category, so
   `authorization:sync` writes them, they can be granted and a policy naming them validates: `role.grant`,
   `role.revoke`, `permission.grant`, `permission.revoke`, `policy.attach`, `policy.detach`, `role.create`,
   `role.rename`, `role.update`, `role.delete`, `role.parent.set`, `permission.create`, `permission.rename`,
   `permission.update`, `permission.delete`, `policy.create`, `policy.rename`, `policy.update`, `policy.delete`,
   `boundary.set`, `boundary.remove`, `guardrail.manage`, `resource-policy.attach`, `resource-policy.detach`,
   `role.read`, `permission.read`, `policy.read`, `permission.grantable`, `policy.grantable`, `administration.self` and
   `administration.impersonated`. The right to manage guardrails was `authorization:guardrails:manage`; it is renamed,
   with no alias, since the package is unreleased.

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
   in a tenant is refused it. Nothing is attached to one operation, so only the resource policies attached to the type
   `authorization:operation` are read for it, under one cache entry every operation shares. Its attributes reach
   policies under `resource` through the package's `Administration\OperationAttributes` provider, which no configured
   provider replaces: the action, whether it only narrows, whether it changes nothing, the target, its name under its
   kind, the grantee, the application, the reach, the expiry, a definition's proposed change and the impersonator.

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
   scope. Such a change only narrows, so an actor allowed the action makes it, and one not allowed it is refused whether
   or not anything was there, so a refusal never tells it what a grantee holds.

8. **What cannot be proved is refused (in this release).** Once the action is allowed, a change that may widen what
   anyone may do and that no rule of this release proves is refused as `administration.unprovable`. A change that can
   only narrow (`Administration\Narrowing`) is allowed once the owner and rank rules pass: revoking a permission,
   revoking a role no policy attached to it or its ancestors denies anything in, read across every tenant on the write
   connection, so a screen and the service judge alike and an ancestor the tenant scope hides still counts, detaching a
   policy with no deny statement, and a grant that only shortens or narrows one the grantee holds live in the same scope
   (`Narrowing::isShortening()`). A chain that cannot be read whole is taken to deny. Every role grant, policy
   attachment and boundary set, every boundary removal, every detach of a denying policy, every resource-policy
   attachment, every change to a role's permissions or policies and every change to a definition is unprovable until
   parts 3 and 4 prove it.

9. **Impersonation (in this release).** A delegated change made while impersonating (`ActingContext::impersonatedBy()`)
   is refused as `administration.impersonating` unless the actor is also allowed
   `authorization:administration.impersonated` on the same operation. Both actors are reported.

10. **Rank is a comparison, never an allow (N76, in this release).** `Administration\RankComparison` compares the actor
    and the target through the same scope-aware path (the roles each holds in the scope, expired grants and other
    applications never counting): strictly senior, an unranked target the most junior, an unranked actor acting on no
    one, an uncomparable side failing closed, and rank turned off passing every comparison. When neither side holds a
    ranked role, the comparison refuses: both count as the most junior, so their ranks are equal, and strict seniority
    refuses equal rank; an application that leaves rank on but ranks no role should turn it off. An actor given as a
    resolved `Subject` is ranked by the roles that reach it, its principal's and its granting identity's, and a rank
    the change would grant the target counts as the target's. `canActOn()` returns the comparison alone.

11. **Direct grants (part 2, in this release).** The administration stage (`Administration\OperationConstraints`)
    weighs every change to an identity or a principal (`Administration\OperationGrantee`), in order, each further check
    decided as the actor through every stage up to the allow but never through the stage again
    (`Administration\FurtherChecks`):
    - **owner** (D20): the tenant the check is made from, the request's, must be the tenant that holds the grant row
      the change edits, the platform for a platform-wide row (`Administration\OwnerConstraint`, a reusable piece part 3
      applies to definitions, role membership and policies), or the change is `administration.owner`; granting an
      ancestor's record to a local grantee edits the local row alone; a call that changes nothing edits nothing;
    - **scope**: a change that may widen authority decides its own action again in the grant's tenant, standing just
      below it for a subtree grant (`TenantScope::within(..., isBelow: true)`), so only authority that itself reaches
      below counts, and in the grant's application, so a grant to every application needs authority in every
      application, or it is `administration.scope`; a platform-wide change already needs platform authority;
    - **rank**: unless the grantee is the actor, the actor must be strictly senior to it in the grant's scope, and to
      the rank a role grant would give it, or the change is `administration.rank` (`administration.rank_uncomparable`
      when a side cannot be read), a revocation, a sync, `revokeAll()`, a boundary change and a call that changes
      nothing included, so a refusal never depends on what the grantee holds;
    - **self**: a change to the actor's principal or identity that may widen authority needs
      `authorization:administration.self` on the same operation, or it is `administration.self`;
    - **possession** (N77, `Administration\Possession`): a direct grant of a permission is allowed when the actor
      provably holds it across the grant's reach (tenant, subtree, application) and lifetime
      (`Administration\HeldLifetime`), its `check()` there allows it, and nothing that denies or caps the actor could
      limit it anywhere in the reach (`Administration\PossessionLimits`: any deny statement naming an action it covers,
      a boundary or guardrail not allowing it whole, unconditionally and on every resource, a cap not covering it, or a
      document that cannot be read, the actor's policies, its roles', every resource's, its boundaries and the
      guardrails read as stored whatever their application); or when `authorization:permission.grantable` is allowed on
      the grant's descriptor (`OperationResource::grantable()`). Otherwise it is `administration.not_grantable` when the
      actor does not hold the permission across the reach and lifetime, and `administration.unprovable` when it does but
      cannot be proved contained. An extension needs authority lasting until the new expiry; a shortening only narrows.

12. **Roles, grantable rights and impact (part 3, Not yet).** Granting a role covers its whole transitive authority:
    direct and inherited permissions and policies. An explicit `policy.grantable` decision can allow an exact delegation
    of a policy the actor does not itself hold (N77), as `permission.grantable` already does for a direct permission. A
    policy right is bound to the policy's digest, so a rewrite needs a new one. A change to a role's content or parent,
    a permission rename, a policy rewrite and a boundary or resource policy change are re-checked against every holder
    they reach, as a new distribution of authority. Definitions are edited only from their owner's tenant (D20).

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
  step naming it; in this release every widening change but a direct grant of a permission is
  `administration.unprovable`.
- **Rolled-back audit.** A denial is reported synchronously inside a transaction that rolls back, so an audit store that
  persists it must write on a connection with no part in that transaction: directly on a database connection of its own,
  or through a queue whose backend shares nothing with it (a non-database driver, or the `database` driver on a
  connection of its own), with `after_commit` off for the queue and the listener. The stock `database` queue on the
  default connection, and the `sync` driver, are rolled back with the refusal.
- **No operation resource.** A check of an administration action with no operation resource, such as a menu deciding
  whether to show the administration area at all, decides the action alone; the administration stage never runs, and the
  service's own decision is still made on the operation.
- **Console.** `authorization:grant` and `authorization:revoke` with `--actor` make the change as that actor, delegated,
  with no session, so a role grant is refused as `administration.unprovable` in this release; without it they are
  trusted.
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
- `Administration\OwnerConstraint` -- only the owner edits.
- `Administration\Possession`, `Administration\HeldLifetime`, `Administration\PossessionLimits` -- the possession and
  grantable routes of a direct permission grant.
- `Support\Operation` -- the operation's actor, identity, impersonator, mode and actions.
- `Services\Support\RecordWriter`, `Services\Support\GrantChanges` and every management service -- the changes they
  decide, before they write.
- `Services\Support\GuardrailAuthority` -- the guardrail right, decided inside the transaction.
- `Evaluation\Enums\DecisionReason`, `DecisionStage::ADMINISTRATION`, `TraceOutcome::SATISFIED` -- the reasons, the
  stage and its trace.

## Authoritative Tests

- `DelegatedAdministrationTest` -- every service method, called with an actor, refused without its action, deciding its
  own action, and made or refused per this release; screens and services agreeing; atomic batches;
  impersonation; the audit fields and the correlation id.
- `ActingContextTest` -- resolution, its failure, the session, caps, a machine's credential caps and refusals.
- `DelegatedGrantsTest` -- part 2 end to end: the rank table over grants, revocations and syncs, the resulting rank,
  self, node-only and application-limited authority, platform grants, an ancestor's records edited from a descendant,
  possession and its lifetime, every limit that fails it, explicit grantability, shortening, atomic batches decided on
  the authority held before them, and a screen and the service agreeing over random grants.
- `OperationResourceTest`, `OperationChangeTest`, `OperationGranteeTest`, `OperationAttributesTest`,
  `OperationConstraintsTest`, `FurtherChecksTest`, `NarrowingTest`, `RankComparisonTest`, `OwnerConstraintTest`,
  `PossessionTest`, `HeldLifetimeTest`, `PossessionLimitsTest` -- the operation resource, its change, its grantee, its
  attributes, the administration stage and each of its constraints.
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
  owner, rank, self, expiry and possession rules, wiring `RankComparison` into every change to a subject.
- Part 3 does the same for roles, definition edits and impact, applies `OwnerConstraint` to definitions, role membership
  and policies, and decides `policy.grantable`.
- Part 4 moves guardrail changes onto the operation-resource path and adds the concurrency protocol.
- Adding an administration action, or an attribute of the operation resource, changes `PackagePermissions` or
  `OperationAttributes` and their tests, and the README's tables.
