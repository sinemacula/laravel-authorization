# Evaluation Order and Deny Precedence

## Purpose

Document the staged decision every check goes through, the interaction between policy statements, guardrails, permission
boundaries, session caps and RBAC, the invariants that govern deny precedence and the caps, and how a decision fails
closed when a statement cannot be decided or a policy cannot be evaluated. This note is the authoritative reference for
why the decision behaves the way it does -- the code and tests encode the *what*; this note encodes the *why*.

## The Decision

`AuthorizationManager::check()` is the one core decision (D22), and `checkMany()` the same decision over many checks,
`check()` deciding as `checkMany()` decides a batch of one; `can()` and `cannot()` read whether it allows, `any()` and
`all()` read it for each action they decide, `canEach()` and `filterAuthorized()` read it for each resource,
`authorize()` throws when it does not, and a Laravel policy class deciding through
`Concerns\DecidesThroughAuthorization` turns it into a policy response. It makes no decision of its own:
`Evaluation\DecisionPipeline` admits the check and gathers its sources, the policy evaluator decides it, and
`Evaluation\CheckBatch` alone records and reports the result (see [Bulk checks](bulk-checks.md)). It returns a
`Decision`:

- `effect` -- `DecisionEffect::ALLOW` or `DecisionEffect::DENY`; `isAllowed()` reads it.
- `reason` -- why it denies, a `DecisionReason` (AUTHZ-7.10); null when it allows.
- `stage` -- the `DecisionStage` that decided it.
- `statements` -- the statements that decided it, each a `StatementReference` (the policy's name, its stored key, the
  statement's position, its `sid` when it has one and, for a resource policy, the resource the policy is attached to,
  shown as `name[key]#position sid="…" on "post:7"`); none for a permission held, a guardrail or boundary that allows
  nothing the check names, a session cap that does not cover the action, or another denial no statement made. The `sid`
  only names the statement: it never changes the decision or the order.
- `trace` -- every step taken, in order, each a `TraceEntry`: its stage, its `TraceOutcome`, the statement it assessed
  (none for the permission step, a guardrail or boundary that refused the check, a session cap, or a cap stage that
  capped nothing), the cap it names when it is a guardrail's or a boundary's refusal (`cap`, as `name[key]`) or a
  session cap's step (`cap`, by the session cap's name), the held permission that allowed when it is the permission
  step and found one (`permission`, as it was granted, a pattern such as `posts:*` included), and the condition keys
  (their dot paths) it tested with whether each held. A step that assessed a statement also carries the path of every
  `${…}` reference the statement names in its condition operands and resource patterns (`dependencies`), on every
  check, and `Decision::keys()` names these beside the condition keys. A step of an explained check also carries each
  condition test with its outcome (`tests`, a list of `ConditionResult`, null on an everyday check) and the keys of the
  references its resource patterns could not resolve (`unresolved`), a statement whose target did not match included
  (see [Explanations](explanations.md)).
- `requirements` -- for an `insufficient_authentication` denial, one `UnmetRequirement` for each statement in
  `statements`, in the same order: the authentication requirement that alone kept it from applying and its unmet parts.
  They are alternatives: any one of them met would allow the check. Empty for every other decision.
- `freshness` -- for a decision that read an authentication requirement, a `RequirementFreshness`: a fingerprint of
  the session it was made in (its SHA-256 hash, never the session id itself) and the earliest instant a met requirement
  it read stops being met. `isFreshFor($session)` fingerprints the session it is given and says whether the decision
  may still be reused; null when it read none, and such a decision may always be.

The trace never carries a context or attribute value, only key names and results (AUTHZ-8.8), and the freshness holds
only a session fingerprint, so a decision is safe to log, store and put on an event.

## Statements

A statement names its actions with `actions`, or with `not_actions` (every action none of its patterns matches), and its
resources with `resources`, with `not_resources` (every resource none of its patterns matches), or with neither (every
resource, and a check that names none). Its `conditions` map each operator to the context keys it tests, each a dot
path into the check's context, and every test must hold:
`{"ip_not_in": {"request.ip": ["10.0.0.0/8"]}, "eq": {"resource.owner.id": "${subject.id}"}}`. A key the context lacks
makes a test undecidable, except under the `_if_exists` suffix, which passes it, and for `null`, which decides it.

The check's context is built once a check, in `AuthorizationManager`, after the subject and resource stages: the
caller's values under `input`, the `authentication`, `request` and `environment` namespaces and those of the
application's sources from their own sources, and the `subject` and `resource` namespaces from the subject, the
resource reference and their attribute providers, each built only when a statement assessed reads it and then kept for
the rest of the check, so a deny stage and an allow stage reading `request.ip` see one value. A decision that ends
before the statements are assessed builds none of them. An attribute provider that throws aborts the check with
`AttributeProviderFailed` rather than letting it be decided: no decision is made, recorded or dispatched. The shape,
the operators, the operands and the namespaces are in [Wildcard and Condition
Semantics](wildcard-and-condition-semantics.md).

An allow statement of a resource policy also names its `principals`, the subjects it applies to (see [Resource
Policies](#resource-policies)); a deny takes none.

`not_resources` counts as resource scoping: a statement with it never covers a check that names no resource, so
`{"effect": "deny", "actions": ["posts:delete"], "not_resources": ["post:1"]}` denies deleting every post but `post:1`
and leaves a resource-less `posts:delete` check alone. Only a statement without either resource list, or whose
`resources` include `*`, covers a resource-less check.

## Where Policies Come From

A check's policies are gathered by the bound `PolicyResolver`, then from the subject's identity when that is a separate
model (whole when it is of the same kind, both machines or neither, `SubjectGrants::grantingIdentity()`, and only its
deny statements otherwise), and then from the policies attached to the check's resource and its type. The default
resolver, `DefaultPolicyResolver`, unions three sources (AUTHZ-6.9, AUTHZ-7.2):

- **The policy store.** The `PolicyStore` bound as `policy_store`, asked on every check, for policies shipped in code
  or kept outside the package's tables.
- **The identity's own attachments.** Managed policies, stored once and attached to any number of grantees, and the
  identity's inline policies, each of which belongs to it alone, attached through `authorizable_policies` in the
  current scope.
- **Its roles' policies.** The policies attached to each role the identity holds, through the same table with the role
  as the grantee, and, with the hierarchy enabled, to every role above it, read through `RoleGraph` exactly as the
  roles' permissions are. A role's policy applies only where both grants hold: the identity's grant of the role and
  the role's attachment of the policy each hold in the current tenant (through a tenant above it only when that grant
  reaches its subtree) and application, and neither has expired.

An attachment of an inline policy to any grantee but the one it belongs to is left out of the resolution, should one
reach the table past the write paths that refuse it.

Two more sources follow the resolver's, in `DecisionPipeline::gatherPolicies()`, after the bound `PolicyResolver` rather
than through it, so a custom resolver controls neither:

- **A separate identity's policies.** When the subject's identity is a separate model, that identity's own and
  role-attached policies, through `SubjectGrants::identityPolicies()`: whole when it is of the same kind, both machines
  or neither (`SubjectGrants::grantingIdentity()`), and otherwise only those with a deny statement, each with its deny
  statements alone, at their positions, so a deny still narrows the check while no allow crosses.
- **The resource's policies (AUTHZ-7.3).** The managed policies attached through `resource_policies` to the check's
  record and to its type, through `ResourcePolicyResolver::policiesFor()`. A check on a type alone reads those attached
  to the type; a check on an opaque identifier, or on no resource, reads none and runs no query. A record whose key no
  attachment can name (empty, `*`, holding a NUL byte or longer than the table stores) still reads its type's, its
  denies included. Only the attachments that hold in the tenant and application the check is decided in count, as a
  grant's do, and a policy attached to the record and to its type is listed once, as the record's. A check on a
  tenant's resource that the tenant stage decides at platform scope also reads the denies attached in the resource's
  own tenant (invariant 9). Each is hydrated with the resource it is attached to
  (`Policy::withResource()`, `type:id` or `type:*`), which makes it a resource policy (see [Resource
  Policies](#resource-policies)).

`withPolicies()` replaces every source, the resource's included; a supplied policy given a resource is evaluated as a
resource policy. It replaces policies alone: the guardrails, the subject's permission boundaries, the session caps and
the permissions it holds still count, so an override never lifts a cap.

The subject's permission boundaries are no policy source: they are read apart, through `SubjectGrants::boundaries()`,
after the bound `PolicyResolver` and outside it, so a custom resolver can never drop them (see [Permission
Boundaries](#permission-boundaries)). Nor are the guardrails, read apart through `GuardrailResolver::guardrailsFor()`
for every check, whatever the subject (see [Guardrails](#guardrails)), and kept when `withPolicies()` replaces the
policies.

Within one grantee's resolution, its own attachments and its roles', a policy held more than one way (attached to the
grantee and to a role, or to two of its roles) is listed once. A policy held by both the subject and its separate
identity may be listed twice, and a policy may be held and set as a guardrail or a boundary too, or be the boundary of
both: the evaluator gathers each policy once for each part it plays (`StatementEntries`), its denies once, its allows
once as a policy, once as a guardrail and once as a boundary, so the decision is unchanged and names each statement
once. The stored policies are read through the resolution cache; a change to any role's policy attachments refreshes
every identity's cached policies, and a change to the hierarchy refreshes those of the identities whose roles it
reaches. The order the sources are read in is never relied on: invariant 2 orders the policies within each stage, so a
deny in a role's policy, or in the resource's, is decided exactly as one attached to the identity, and wins over every
allow and every permission.

The resource's policies are read in one query, on the write connection, through the resolution cache, keyed by the
resource, the tenant, the application and the policy limits; a type alone is kept under a kind of its own, so no
record's entry is ever the type's. Attaching or detaching a policy refreshes the cached entries of the resource's type,
and updating or deleting any policy refreshes every cached resource-policy entry, since one query reads the attachments
and the documents together.

## Resource Policies

A resource policy is a managed policy attached to a record or a whole resource type, through
`ResourcePolicyService::attach()` and `detach()`. It answers who may act on the resource rather than what a grantee may
do, so its statements are read the other way round:

- **Each allow names its principals.** `principals` is a non-empty list of selectors: `<morph type>:<id>`, the
  subject's principal or identity by morph class and key, or `role:<role id>`, whoever holds that role (by its key,
  never its name) in the tenant and application the check is decided in. `role:<id>` follows the role hierarchy: with
  it enabled, it also names whoever holds a role below that role, read through `RoleGraph` as the role's permissions
  and policies are; with it disabled, only whoever holds that role itself. A selector is an exact name, never a
  pattern.
- **Each deny applies to everyone.** A deny takes no `principals`; it applies to every subject checking the resource,
  also one the tenant stage admits at platform scope through a platform-wide permission: a deny a tenant attaches to
  its own resource holds across that fallback.
- **The rule follows the attachment.** `PolicyValidator` refuses a malformed selector and `principals` on a deny when a
  policy is saved. A policy attached to a resource must name principals on every allow, and may not be inline; a policy
  attached to an identity or a role may name none. Each attachment is refused with `ResourcePolicyException` when the
  stored policy breaks the rule for it, and a rewrite of an attached policy that would break it is refused as well
  (`PolicyPrincipals`).

## Permission Boundaries

A permission boundary (AUTHZ-7.4) is a managed policy set on a principal or an identity, through
`BoundaryService::set()` and `remove()`, that caps what the grantee may do whatever its grants allow:

- **One per scope.** A grantee has at most one boundary platform-wide and one in each tenant, held in
  `authorizable_boundaries` with a null-folding unique index; setting another in a scope replaces it, reported as
  `GrantOutcome::REPLACED` and by `BoundarySet` naming the `previous` policy. A boundary in a tenant reaches the tenants
  below it unless `include_subtree` is false, and a tenant-owned policy is set in its tenant or one below it, as a grant
  is. A boundary has no application column: it holds in every application, since the scope a boundary caps is a
  tenant's.
- **Which apply.** A check reads the boundaries of the subject's principal and, when it is a separate model, of its
  identity, whichever contracts each implements, so a boundary set on a saved model is never ignored. It reads those
  that hold in the tenant the check is decided in: the platform-wide one, the tenant's own, and an ancestor's
  that reaches down, through `TenantScope::currentChain()->grants()` as a grant reaches (`BoundaryResolver`). A
  tenant-owned resource the tenant stage admits is decided in its own tenant, so that tenant's boundaries apply; a
  check that falls back to platform scope reads the platform-wide ones.
- **Intersection.** Every boundary that applies must allow the check. A tenant's boundary never replaces the platform's,
  and the principal's never replaces its identity's, so a boundary can only narrow what the grantee may do.
- **They cap, and grant nothing.** A boundary's allow statements are assessed at the boundary stage as an ordinary
  policy's allows would be, conditions and `not_actions` included; passing it only lets the allows be weighed. Its deny
  statements are explicit denies at the deny stage, after every policy's. It never names `principals`, so its allows
  apply to every subject it bounds.
- **What is refused.** A grantee that is never a subject's principal or identity, a role (whose holders never read its
  boundary), a permission or a policy, is refused with `BoundaryException`, and so is an inline policy, which belongs to
  one grantee and is deleted with it. A policy naming `principals` is refused as a boundary, and a rewrite of a
  boundary's document that adds `principals` is refused with `ResourcePolicyException`. A boundary is reported set only
  once its row is read back on the write connection: an insert that is ignored and leaves no row is tried again, and
  when that leaves none either, a policy deleted at the same moment is refused with `InvalidGrantTargetException` (on
  MySQL, `INSERT IGNORE` turns the foreign key failure into a warning) and any other failure with
  `UnwrittenGrantException`, so `BoundarySet` is never dispatched for a boundary that is not there. A policy in use as a
  boundary is never deleted: `PolicyObserver::deleting` refuses the delete with `BoundaryException`, naming every
  grantee it bounds, and the table's foreign key restricts a delete made past the model. Removing the boundary, deleting
  its grantee (`GrantService::revokeAll()`) or pruning a grantee that is gone frees the policy.

The boundaries and their documents are read in one query on the write connection, through the resolution cache, as a
grantee's policies are (`ResolutionCache::rememberBoundaries()`), so a warm check reads none. Every boundary entry pins
one shared boundaries version, which updating or deleting any policy bumps, rather than a version per policy: a
coarser invalidation that saves a second cold query. Setting or removing a boundary bumps the grantee's version through
its `IdentityEvent`.

## Guardrails

A guardrail (AUTHZ-7.6, N41) is a managed policy set on a tenant, or on the platform, through
`GuardrailService::set()` and `remove()`, that caps what any subject may do in its scope whatever its grants allow:

- **Storage.** A scope may have any number of guardrails, a policy at most once in each, held in `guardrails` with a
  null-folding unique index over the policy and the tenant (both tenant columns null for the platform), the actor in
  `granted_by_type` and `granted_by_id`. Setting a policy a scope already has is `GrantOutcome::UNCHANGED`. A guardrail
  has no application column and no reach flag: it holds in every application, and a tenant's always reaches below it.
  A tenant-owned policy is set on its tenant or a tenant below it, as a grant is.
- **Which apply.** The guardrails of a check are the platform's and those of the check's tenant and of each of its
  ancestors, through `TenantScope::currentChain()` as the tenant tree reaches down (AUTHZ-5.3, `GuardrailResolver`).
  The check's tenant is the resource's when the resource has one, also when the tenant stage admitted a resource of a
  tenant outside the subject's scope through a platform-wide permission and decides the rest at platform scope (N43):
  the guardrails are then read in the resource's tenant, so a tenant's guardrails cap every check on its resources.
  With no resource tenant, the guardrails are those of the tenant the check is decided in; with no tenant, the
  platform's alone.
- **Intersection.** Every guardrail that applies must allow the check: a tenant's never replaces its ancestors' or the
  platform's, so a guardrail can only narrow what anyone may do in its scope. They apply to every subject, whatever its
  principal, identity or grants.
- **They cap, and grant nothing.** A guardrail's allow statements are assessed at the guardrail stage as an ordinary
  policy's allows would be, conditions and `not_actions` included; passing it only lets the boundaries and the allows
  be weighed. Its deny statements are explicit denies at the deny stage, after every policy's and before every
  boundary's. It never names `principals`, so its allows apply to every subject.
- **Who may change them.** Only an actor holding `authorization:guardrail.manage`, a permission the package declares
  in its own catalogue (`Support\PackagePermissions`), from above the scope. The right is decided through `check()`
  (D22), so every deny and boundary that applies to the actor counts, run just below the parent of the tenant changed
  (`TenantScope::within()` with `isBelow`): a grant held at an ancestor counts only when it reaches below it, a
  platform-wide grant counts, and one held within the tenant itself never does. A tenant with no parent, and the
  platform, are decided at platform scope, where only a platform-wide grant counts (`GuardrailAuthority`). An actor
  refused is refused with `GuardrailException` (`not_permitted`) before anything is read or written.
- **No guardrail lockout (N49).** A check of exactly `authorization:guardrail.manage`, the guardrail service's or any
  other, is exempt from the guardrail stage: `AuthorizationManager` reads no guardrail for it and gives the evaluator
  none at all (`null`), so no guardrail's deny or allow applies, nor does a guardrail that cannot be read, and the
  stage records `[guardrail] guardrails: exempt`. No guardrail, a platform guardrail included, can therefore keep an
  actor from changing the guardrails of any scope, its own removal included. Every other source's denies, the
  boundaries and the session caps still apply, and the grant must still reach the scope from above.
- **What is refused.** An inline policy (`GuardrailException`, `inline`), a policy naming `principals`
  (`ResourcePolicyException`) and a policy whose row is gone (`InvalidGrantTargetException`) are refused before
  anything is written; a guardrail is reported set only once its row is read back, as a boundary is. A policy in use as
  a guardrail is neither edited nor deleted: `PolicyObserver::updating` and `deleting` refuse either with
  `GuardrailException` (`in_use`), naming every scope it caps, so the cap never changes or lifts past the guardrail
  service's check, and the table's foreign key restricts a delete made past the model.

The guardrails and their documents are read in one query on the write connection, through the resolution cache
(`ResolutionCache::rememberGuardrails()`), keyed by the tenant, the application and the policy limits, so a warm check
reads none. Every guardrail entry pins one shared guardrails version, which setting or removing a guardrail and
updating or deleting any policy bump. The guardrail service's own check reads no guardrail, being exempt, but the
grants it reads, decided just below a tenant, are keyed apart (`:below`), so they never stand for a tenant's.

## Session Caps

A session cap (AUTHZ-7.5, N42) is a set of action patterns that bounds what one check may allow. It is no policy: it has
no statements, no conditions and no denies, and it grants nothing. A check has up to two kinds:

- **The credential's.** The bound `SessionPolicySource` (AUTHZ-13.3, `authorization.session.source`) answers the scopes
  the credential of the check's subject carries, or null when it carries no cap. It is asked once for each check that
  gets past the subject, resource and tenant stages and whose policies, guardrails and boundaries could then be read; a
  check denied as `invalid_policy` before then asks no source. It is given the check's `Subject`, a subject named with
  `for()` included, so a source answers null for a subject whose credential it does not know. The default,
  `NoSessionPolicy`, answers null for every subject. A source that throws aborts the check: no decision is made,
  recorded or dispatched, as for an attribute provider that throws.
- **The caller's.** `AuthorizationManager::capped($actions)` returns a scoped manager, as `for()` and `withPolicies()`
  do (D22: `check()` stays the one decision), whose checks are capped by the actions given, for a delegated or a
  restricted call. Capping a capped manager adds another cap rather than replacing the first. The Gate, the middleware
  and the directives decide through the unscoped manager, so an explicit cap reaches only the checks made through the
  manager `capped()` returned.

How they decide:

- **Intersection.** Every cap present must cover the action: the credential's and each explicit cap, outermost first.
  None replaces another, so an explicit cap only narrows what a credential allows. A cap covers an action when one of
  its patterns equals the action or matches it with `fnmatch` and `FNM_NOESCAPE`, as a statement's `actions` match
  ([Wildcard and Condition Semantics](wildcard-and-condition-semantics.md)).
- **No cap differs from an empty cap.** No cap at all (a source answering null, a manager never capped) caps nothing,
  and the stage records `uncapped`. An empty cap (a source answering `[]`, `capped([])`) covers nothing, so it denies
  every check as `session_policy`.
- **The scope map.** The credential's scopes are mapped to action patterns through `authorization.session.scopes`
  (`SessionScopes`): a scope the map names stands for its patterns, and any other scope, one listed on its own
  included, names itself as an action or an action pattern. The map is checked at boot (`SessionConfigValidator`):
  each scope is a non-empty string named once and mapped to a non-empty list of non-empty patterns, and every pattern,
  a scope listed on its own included, must cover at least one permission the package or the application declares, as
  a policy's `actions` must (`PolicyValidator`). A bad map is refused with `InvalidAuthorizationConfigException`. The
  bound `ActionCatalogue` is resolved for it only when the map names a scope, so with the default empty map booting
  reads no permission provider; it never reads the package's tables. A scope the credential carries that the map does
  not name is not checked against the catalogue at decision time: one that names no declared permission simply covers
  nothing a check could allow. The scope registry is what keeps such a scope off a credential.
- **Machines (AUTHZ-2.4).** A principal implementing `AuthorizableMachine` must have its credential's scopes. When the
  source answers null for a machine, the check is capped by an empty cap in their place, named `credential:missing`,
  so it is denied as `session_policy` whatever it holds and whatever explicit caps are passed: `capped()` never stands
  in for the missing scopes, it only narrows them. A credential answering `[]` for a machine allows nothing either.
- **Admission is not capped (N105).** Whether a principal may use an application (`ApplicationAccess::mayUse()`) is
  decided through the manager's `withoutSessionCaps()`, for people and machines alike: the source is not asked, so
  neither the request's credential scopes nor a machine's missing ones cap it, while the explicit caps, every deny,
  guardrail and boundary still apply. Every other check, once the session exists, keeps its session caps.
- **A machine is never a person.** The grants of a subject's identity, its roles, its permissions and the allow
  statements of its policies, reach the subject only when the subject and the identity are both machines or neither is
  (`SubjectGrants::grantingIdentity()`), so a person's grants never reach a machine principal acting for them and a
  machine's never reach a person. A resource policy's selector naming the identity by reference, or a role only the
  identity holds, does not name such a subject either (`PrincipalSelectors`). What only narrows a check still crosses:
  the deny statements of the identity's own and role-attached policies join the deny stage, its permission boundaries
  cap the subject, and an inactive identity denies it everything, so the rule never lifts a deny or a cap. An identity
  policy that cannot be read denies the check as `invalid_policy` whatever the identity's kind. No resolver the package
  ships attaches an identity of another kind: `AuthGuardSubjectResolver` and `Subject::withSubject()` make the subject
  its own identity, and an application's resolver that pairs a machine with a person gets the separation above.
- **The scope registry (AUTHZ-13.5).** `ScopeRegistry` answers which scopes a credential may carry. The package ships
  `CatalogueScopeRegistry`, backed by the permission catalogue and the scope map, and binds none: a scope is valid when
  the map names it, or when it equals or matches a declared permission, the package's own included, and `scopes()`
  lists the mapped scopes, then each declared permission the map does not name. It reads the catalogue once, on first
  use. An application, or `sinemacula/laravel-iam` for `laravel-authentication`'s scope registry (AUTH-4.5), binds it
  where scopes are issued.

The caps read nothing from the database: a check a cap covers runs the same queries as one with no cap, and one a cap
refuses never reads the permissions, since the session stage runs before the allow stage asks for them.

## Invariants

1. **The stages run in order, and the first that decides ends the decision (AUTHZ-7.1).** No allow of any source is
   weighed before every deny and every cap has run, so a deny, or a cap that does not allow the check, beats every
   allow: a policy's, a resource policy's, a permission held and an `insufficient_authentication` candidate alike. An
   allow is final except where the administration stage (7) refuses it.
   1. *Admission*, three stages that run before any policy is read:
      - *Subject*: no subject denies as `subject_unresolved`; an inactive subject, or one whose identity is inactive,
        denies as `subject_inactive`. Nothing else is read.
      - *Resource*: a resource argument that cannot be identified (an unsaved model, a number, an empty pair, a route
        parameter the route lacks) denies as `resource_unresolved` (N1).
      - *Tenant*: a resource whose tenant is the decision's tenant, or below it in the tenant tree, is decided in its
        own tenant, so grants there and those above it that reach down count. A resource of any other tenant (every
        tenant-owned resource when no tenant is active) denies as `tenant_scope` before any policy is read, unless the
        subject holds the action's permission through a platform-wide grant, when the rest runs at platform scope
        (AUTHZ-4.4, AUTHZ-5.5, N9).
   2. *Deny*: every deny statement of every applicable source is assessed: the subject's and its identity's own and
      role-attached policies (the identity's whatever its kind), the policy store's, the resource's and its type's (for
      every subject), the guardrails' and the boundaries' (a session cap has no deny statements, so it adds none). One
      that matches, or whose test cannot be decided, denies as `explicit_deny`. Failing that, a deny statement that
      cannot be evaluated denies as `invalid_policy`. A stored policy, guardrail or boundary that cannot be read, or
      whose document is over a configured limit, denies as `invalid_policy` before any statement is assessed.
   3. *Guardrail*: every guardrail on the check's tenant, its ancestors and the platform must allow the check, each
      through its allow statements, conditions included (see [Guardrails](#guardrails)). One whose statement cannot be
      evaluated denies as `invalid_policy`; failing that, one with no allow that matches, one with no allow statement
      at all included, denies as `guardrail`, and each guardrail that refuses adds a `refused` step naming it. An allow
      whose authentication requirement is unmet does not allow, so the guardrail denies as `guardrail`, never as a
      step-up. With no guardrail the stage records `uncapped` and caps nothing. A check of exactly
      `authorization:guardrail.manage` is exempt: the stage records `exempt`, and the deny stage weighs no guardrail's
      denies for it (N49).
   4. *Boundary*: every permission boundary of the principal and of its identity that applies must allow the check,
      each through its allow statements, conditions included (see [Permission Boundaries](#permission-boundaries)).
      One whose statement cannot be evaluated denies as `invalid_policy`; failing that, one with no allow that matches,
      one with no allow statement at all included, denies as `boundary`, and each boundary that refuses adds a
      `refused` step naming it. An allow whose authentication requirement is unmet does not allow, so the boundary
      denies as `boundary`, never as a step-up. With no boundary the stage records `uncapped` and caps nothing.
   5. *Session*: every session cap, the credential's scopes mapped through the scope map and each explicit cap, must
      cover the action (see [Session Caps](#session-caps)). One that does not, an empty one included, denies as
      `session_policy`; each cap adds a step naming it, `covered` or `refused`, so every cap is recorded even once one
      refuses. A machine whose credential carries no cap is capped by an empty cap (`credential:missing`). With no cap
      the stage records `uncapped` and caps nothing.
   6. *Allow*: every allow statement is assessed. An allow applies only to the subjects its source admits (invariant
      9); one that does not is recorded as `principal_mismatch` and decides nothing. One that cannot be evaluated
      denies as `invalid_policy`; failing that, one that matches allows, a resource policy's with no permission held.
      Failing that, a permission the subject holds that the action names, directly or through a role, allows, when the
      grant it came from reaches the check (invariant 13). The permission is asked once, and only when no allow
      statement matched and none was invalid, and its step names the held permission that allowed. This is the only
      place a permission held is weighed: no stage, and no entry point, answers a check from the permissions before
      every deny and cap has run, and the tenant stage's platform-wide grant only admits a resource, never allows it.
   7. *Administration* (AUTHZ-11.1): runs only for a check of an administration action whose resource is that action's
      own operation resource (`authorization:operation:*`, see [Delegated administration](delegated-administration.md)),
      and only once the allow stage allowed. It weighs the operation's constraints and can only refuse, never allow: the
      first that fails denies with its `administration.*` reason (`administration.impersonating`, then, for a change to
      a subject, `administration.scope`, `administration.rank_uncomparable`, `administration.rank`,
      `administration.self`, and `administration.not_grantable` or `administration.unprovable`, and, for a change to a
      definition, `administration.owner` and the impact check's reasons) and adds a `refused` step naming it; when
      every one holds, it adds one `satisfied` step and the allow stands. A further check a constraint needs, such as
      `authorization:administration.impersonated`, is decided as the subject through every stage up to the allow, in the
      scope in place, never through the administration stage again. A check of an administration action with no
      operation resource, or with another action's, passes the stage untouched and records nothing.
   8. *Implicit*: nothing allowed. The denial is `insufficient_authentication` when an allow statement names the action
      and the resource and only its authentication requirement is unmet (invariant 7); `condition_failed` when an allow
      statement names them but its conditions do not hold or cannot be decided; and `no_match` otherwise.

   Each cap stage can only deny or let the check through: none allows. A cap stage that is reached is always recorded,
   so the trace shows that the caps ran even when none applied, and a guardrail, boundary or session cap that refuses is
   named, so the trace shows which cap refused the check, an empty or deny-only one included.

2. **The decision is deterministic (AUTHZ-7.9).** Within each stage, policies are assessed in order of name, then stored
   key, then the resource a resource policy is attached to, then document, and each statement in order of position, and
   every statement of the stage is assessed whatever is found first, so the decision, the statements that decided it and
   the trace are the same whatever order the policies were read in. A guardrail's and a boundary's deny statements are
   assessed with the deny stage's, after every policy's, the guardrails' before the boundaries', and each cap's allow
   statements together at its own stage, the guardrails and the boundaries each in the same order. A stage that decides
   ends the decision: once a deny decided, no cap and no allow statement is assessed (N4), and once a cap denied, no
   allow is; an allow is final except where the administration stage refuses it. What each policy gives (its statements
   split by effect, their references and its sort key) is worked out once per policy object (`StatementEntries`), not
   once a check.

3. **RBAC is additive / allow-only, and an allow source at the allow stage alone (AUTHZ-7.7, N43).** Direct
   permission grants and role-inherited permissions are unioned on read. There is no RBAC-layer deny: every permission
   a subject holds contributes an allow and nothing else, and only when no statement has decided the check and every
   cap has let it through: a guardrail, a boundary or a session cap caps a permission held as it caps a policy's allow.
   A held name is matched against the action by the wildcard rules (`HeldPermissions`), and the trace names the one
   that allowed. The subject's own permissions are read first and its granting identity's only when none of the
   subject's covers the action; within that grantee, the action itself is named when held, else the first covering
   pattern in byte order, so the trace does not depend on the order the grants were read in.

4. **All deny semantics live exclusively in policies.** "Everyone in role X except these three users" is a deny
   policy, not an RBAC construct, so an administrator reviewing effective permissions never reasons about negative
   grants.

5. **A deny statement is skipped only when its test definitely fails.** A deny whose conditions definitely do not hold
   is recorded as `condition_failed` and decides nothing. A deny whose test cannot be decided -- a condition key missing
   from the context, a `${…}` reference that cannot be resolved, a value or interpolated operand of the wrong type --
   **applies**. This deliberately departs from AWS IAM, where a missing key silently disables a conditional deny: a
   caller that leaves a key out of the context never gets past a deny written against it, and since the caller's values
   are held under `input` alone, no caller can supply a trusted key such as `request.ip` to get past one either. A check
   outside a routed request has no `request` namespace, so a deny on `request.ip` applies to it unless written with
   `_if_exists`. An allow is the mirror image: it applies only when its test definitely holds.

6. **A policy that cannot be evaluated denies the check; it is never skipped.** Skipping a malformed statement or an
   unreadable policy row would also drop the denies it carries, so both deny as `invalid_policy`, and RBAC never
   overrides that, even when the subject holds the permission.

7. **Insufficient authentication is reported apart from other failures, and never beats a denial (AUTHZ-7.8, N35).** An
   `authentication_requirement` condition is one test, judged by the bound `AuthenticationRequirementChecker` for the
   subject's session: it holds when met, definitely does not hold when unmet, and is undecidable when the checker
   throws. A subject without a session (one the caller names with `for()`, or one outside a request's session) meets no
   requirement, and the checker is not asked. The check is denied as `insufficient_authentication` only when no deny
   applies, no invalid statement or policy blocks, every cap lets the check through, no allow statement matches and no
   permission held allows, and at least one allow statement names the action and the resource with every other test
   definitely holding and only its requirement unmet. An undecidable requirement, or an undecidable resource pattern or
   other test beside it, makes the statement no candidate, so the denial is `condition_failed` instead. It is concluded
   at the implicit stage, so RBAC still allows over it, and it ranks above `condition_failed`, so a step-up is asked for
   whenever one would help. On a deny statement an unmet requirement is a test that does not hold, so the deny does not
   apply, and an undecidable one applies it, as invariant 5 says. The decision names each candidate statement and its
   requirement with the unmet parts; `authorize()` and the route middleware raise `InsufficientAuthenticationException`
   for it (AUTHZ-9.6), which extends Laravel's `AuthorizationException` and carries the reason code and the candidates,
   once each, and never a policy, a statement, the trace or a proof.

8. **A decision that read a requirement is never reused beyond its freshness (AUTHZ-12.3, N37).** The last decision is
   returned only in the session of the request that recorded it, as the subject resolver gives it, whichever subject the
   decision was about, and until the earliest instant a met requirement it read stops being met. The checker is asked
   for every requirement of every check and nothing it answers is remembered, so an unmet or undecidable result is never
   reused. Every other entry point (`can()`, `cannot()`, `any()`, `all()`, the Gate, a policy class's `decide()`, the
   Blade directives and `permissionsFor()`) decides afresh, and the resolution cache holds grants and policies,
   never decisions.

9. **An allow applies only to the subjects its source admits (AUTHZ-7.3, N39).** A resource policy's allow applies only
   when one of its `principals` names the subject, and then allows without the subject holding any permission; an allow
   in a policy attached any other way applies only when it names no principals, so a statement with `principals` from
   the policy store, a `withPolicies()` override or a row written past the refusals never allows. A mismatched allow is
   recorded as `principal_mismatch` before its resource and conditions are read, and counts for nothing: it is no
   `condition_failed` and no `insufficient_authentication` candidate. A resource policy's allow is reached only after
   the tenant stage and every deny, so it never admits a resource of another tenant (`tenant_scope` still decides that
   first) and never beats a deny. When the tenant stage admits a subject at platform scope, through a platform-wide
   permission, to a resource of a tenant outside its own, the denies attached to the resource in its own tenant (and
   above it, reaching down) still apply, read in that tenant's scope; that tenant's resource-policy allows do not, so
   only the platform-wide attachments' allows and the subject's own grants decide what remains. The principals are
   judged lazily: a reference costs no query, and the subject's roles are read at most once a check, only when a role
   selector is reached and no reference matched, through the resolution cache as the grantee's roles are, so once warm
   a check reads no role.

10. **A permission boundary caps, intersects and grants nothing (AUTHZ-7.4, N40).** Every boundary that applies to the
    check, the principal's and the identity's, platform-wide and in each tenant that reaches the check's, must allow
    it; one that does not denies as `boundary`, whatever else would allow it. No boundary means no cap. A boundary
    never allows by itself: passing the boundary stage only lets the allow stage decide. An allow in a boundary whose
    authentication requirement is unmet does not allow the check, so the boundary denies as `boundary`, never as
    `insufficient_authentication`: a step-up never gets past a cap. A boundary that cannot be read or evaluated denies
    as `invalid_policy` rather than being skipped (invariant 6), so a broken boundary never lifts the cap.

11. **A guardrail caps every subject in its scope, intersects and grants nothing (AUTHZ-7.6, N41).** Every guardrail
    that applies to the check, the platform's and those of the check's tenant and each of its ancestors, must allow it;
    one that does not denies as `guardrail`, whatever else would allow it, before any boundary is weighed. No guardrail
    means no cap. A guardrail never allows by itself, its unmet authentication requirement never asks for a step-up,
    and one that cannot be read or evaluated denies as `invalid_policy` (invariant 6). The check's tenant is the
    resource's when it has one, so a platform-wide permission that admits a resource of another tenant never gets past
    that tenant's guardrails. A guardrail changes only through `GuardrailService`, for an actor holding
    `authorization:guardrail.manage` from above the scope, decided through `check()`, and its policy is neither
    edited nor deleted while it is one, so a tenant can never lift the guardrails it is set under. That one check is
    exempt from the guardrails (N49), so no guardrail can ever lock the guardrails.

12. **A session cap caps, intersects and grants nothing; a machine needs its scopes (AUTHZ-7.5, AUTHZ-2.4, N42).**
    Every session cap present, the credential's and each explicit one, must cover the action; one that does not denies
    as `session_policy`, after every deny, guardrail and boundary and before any allow, so it caps a permission held, a
    policy's allow and a resource policy's allow alike, and `withPolicies()` never lifts it. No cap caps nothing; an
    empty cap allows nothing. A cap never allows by itself and is never a step-up: a check it refuses is never
    `insufficient_authentication`. A machine principal without credential scopes is allowed nothing, and an explicit
    cap never stands in for them. A machine is never treated as a person: an identity's grants and allow statements
    reach its subject only when both are machines or neither is, while the identity's deny statements, its boundaries
    and its inactivity still apply.

13. **A permission allows only what the grant it came from reaches (AUTHZ-7.7, AUTHZ-5, N43).** For a resource of a
    tenant, a grant counts when it was made in that tenant, in an ancestor and reaches the tenants below it
    (`include_subtree`), or platform-wide; the tenant stage has already denied a resource outside the active tenant's
    subtree as `tenant_scope` unless a platform-wide grant of the permission admits it, and then only platform-wide
    grants count. For a resource with no tenant, a type alone, an opaque identifier or no resource, only the grants that
    hold in the active tenant count (its own, its ancestors' that reach below, and platform-wide ones), and with no
    active tenant only platform-wide grants. A grant's application and expiry hold for every kind of resource. The
    reach is carried by the scope the permissions are resolved in: the check is decided in the resource's tenant (or
    at platform scope after an admission), the grant query keeps the grants that reach that scope
    (`TenantChain::grants()`), and the resolution cache keys each scope's permissions by its tenant, whether it stands
    below it, and its application, so the resolutions form a map from scope to the permissions that reach it. A check
    on a resource therefore costs no query beyond the first resolution of its scope, and none once that is warm. A
    resource admitted at platform scope is still capped by its own tenant's guardrails (invariant 11).

    `can()`, `cannot()`, `any()`, `all()`, the Gate, a policy class's `decide()`, the `permission:` and `authorize:`
    middleware and the permission directives decide through `check()` (D22), and `permissionsFor()` through the same
    path, so they apply this invariant and every other. `hasPermission()`, `hasPermissionTo()`, `getPermissions()` and
    `assertHasPermission()` keep their documented meaning: they report what is granted in the current scope and decide
    nothing.

## Trace

Each statement adds one entry: in the deny stage for a deny statement, a guardrail's and a boundary's included; in the
guardrail stage for a guardrail's allow statement; in the boundary stage for a boundary's allow statement; and in the
allow stage for any other allow statement. Each guardrail or boundary that refuses the check adds one entry naming it
(`[guardrail] organisation-cap[<key>]: refused`, `[boundary] read-only[<key>]: refused`). A cap stage that caps nothing
adds one entry with no statement (`[guardrail] guardrails: uncapped`, `[boundary] boundaries: uncapped`, `[session]
session caps: uncapped`), and so does the guardrail stage for a check exempt from it (`[guardrail] guardrails:
exempt`). Each session cap adds one entry naming it, whether it covers the action or not: `credential` for the
credential's scopes, `credential:missing` for the empty cap standing in for a machine's missing scopes, and `capped[n]`
for the n-th explicit cap, outermost first (`[session] credential: covered`, `[session] capped[1]: refused`). The
permission step adds one more when it is asked, naming the held permission when one allowed (`[allow] permission
"posts:*": held`) and the permission alone when none did (`[allow] permission: not_held`):

| What the step found                                                 | Outcome              |
|---------------------------------------------------------------------|----------------------|
| The statement does not name the action or the resource              | `not_applicable`     |
| An allow that names the action but does not apply to the subject    | `principal_mismatch` |
| It names them and its conditions hold                               | `matched`            |
| It names them but its conditions do not hold                        | `condition_failed`   |
| It names the action but a value it needs is missing or unresolvable | `undecidable`        |
| It cannot be evaluated                                              | `invalid`            |
| The subject holds a permission the action names (the step names it) | `held`               |
| The subject does not hold it                                        | `not_held`           |
| A cap no allow statement of its own lets the check through          | `refused`            |
| A session cap none of whose patterns covers the action              | `refused`            |
| A session cap one of whose patterns covers the action               | `covered`            |
| A cap stage has nothing to cap the check by                         | `uncapped`           |
| The check is exempt from the cap stage                              | `exempt`             |

An authentication requirement is recorded as the condition key `authentication`, with whether it held, and never a
proof or anything the checker answered: a statement whose requirement alone is unmet is `condition_failed` with
`authentication` not held, and one whose checker threw is `undecidable`. The decision's `requirements` say which
parts were unmet, and `explain()` lists them after the statements.

Policy names in the trace are the stored policy's name: when a policy row is hydrated, the model's name replaces any
`name` inside the document, so a document cannot claim another policy's name.

## Failure / Edge Cases

- **No subject**: `subject_unresolved` at the subject stage, without consulting any policy. This covers anonymous
  requests and a subject resolver that resolves no subject.
- **Malformed policy document**: writes are refused -- the `Policy` model validates the document on assignment with
  `PolicyValidator`, which refuses whatever `Policy::fromArray()` and `Statement::fromArray()` refuse (unknown keys, a
  malformed or repeated `sid`, both or neither of `actions` and `not_actions`, both `resources` and `not_resources`, an
  empty pattern list, conditions that do not map operators to key tests, an unknown operator, a malformed literal
  operand and a malformed `${…}` reference), a document over the configured limits, a condition key or `${…}` reference
  the context key catalogue does not declare, a condition on an untestable key or with an operator its type does not
  suit, and an `actions` or `not_actions` pattern that matches no declared permission. A row that still cannot be
  hydrated on read is never skipped: `HasPolicies::getPolicies()` logs a warning on the package's log channel and
  rethrows, and the decision is `invalid_policy`. A custom `PolicyResolver` must do the same: throw
  `InvalidPolicyDocumentException` rather than leave a policy out.
- **Limits on read**: `PolicyDocument::hydrate()` checks a stored document, named after its row, against
  `authorization.policies.limits` before it is evaluated, and one over a limit throws `InvalidPolicyDocumentException`,
  so it denies as `invalid_policy`: it is never skipped and never partly evaluated. The resolution cache keys cached
  policies by the limits they were checked under, so a changed limit makes every cached entry miss and the policies be
  read through `hydrate()` again. Lowering a limit therefore makes every stored document over it deny until it is
  fixed; `authorization:policy:validate --database` lists them.
- **Invalid statement at decision time**: a directly constructed statement with an unknown operator, conditions that do
  not map operators to key tests, a malformed literal operand or a malformed `${…}` reference in a condition is
  `invalid` as soon as it is assessed, whatever the context holds. An interpolated operand that resolves to a value of
  the wrong type is `undecidable`, not invalid. A statement whose action or resource does not cover the check is
  `not_applicable` before its conditions are looked at, so it never makes the check invalid.
- **Resource references**: every check names its resource the same way (`ResourceReferences::of()`): a model as
  `type:id` with the tenant the bound `ResourceTenantResolver` gives it (none by default, N10), a `(type, id)` pair the
  same way, its type a model class's morph class and its tenant the resolver's `tenantOfRecord()` (N17), a model class
  as `type:*` (N6), an `AuthorizableResource` as the reference it returns (N8), and any other string as an opaque
  identifier with no tenant (N7). A pair whose tenant the resolver cannot tell, an abstract model class, and any
  reference whose identifier holds a NUL byte (which names nothing, so it never reaches a pattern match; the resolver is
  never asked about such a pair) deny as `resource_unresolved`. A record of an anonymous model class is one, since its
  class name holds a NUL byte, unless the morph map names it. A type alone is covered only by a pattern that covers
  every record of the type (`*`, `post:*`), never by one that needs an id character (`post:?`). Through the Gate, the
  arguments Laravel spreads from `['post', 42]` name the pair, and a route parameter no binding resolved is an opaque
  identifier.
- **Resource-less check**: a check without a resource matches only statements with neither `resources` nor
  `not_resources`, or whose `resources` include `*`. An argument that cannot be identified as a resource denies as
  `resource_unresolved` at the resource stage, without reading any policy or permission, rather than becoming a
  resource-less check; the denial is recorded and reported like any other decision.
- **Empty statements list**: a policy with zero statements contributes nothing to the trace and does not affect the
  decision.
- **No requirement checker bound**: the default `RefusingRequirementChecker` finds every part of every requirement
  unmet, so an allow that states one never applies and, when nothing else allows, the check is denied as
  `insufficient_authentication`.
- **Requirement checker that throws**: the requirement is undecidable. The failure is logged at debug level, by the
  checker's class and the exception's class alone, so no proof reaches the log; an allow it guards does not apply and a
  deny it guards does.
- **Several candidates**: every allow statement that only its requirement kept from applying is a candidate, so the
  decision lists one requirement per statement, and the exception lists each distinct requirement once.
- **A boundary with no allow for the check**: a boundary with no statement, of deny statements alone, or whose allows
  name other actions, denies every check it does not allow as `boundary`; the decision names no statement, and the
  trace lists each of its allows as assessed at the boundary stage, then a `refused` step naming the boundary, so
  `explain()` says which boundary capped the check.
- **An unreadable boundary**: a boundary whose document cannot be hydrated, or is over a limit, denies every check about
  its grantee in the scopes it applies to as `invalid_policy` at the deny stage (every check, for a platform-wide
  boundary), logged as an unreadable policy is, until it is fixed or removed.
- **A boundary and `withPolicies()`**: the override replaces the policies, never the boundaries or the permissions, so a
  test or a caller supplying policies is still capped by the subject's boundaries: an override never lifts a cap.
- **A boundary in another application**: a boundary has no application, so it holds in every application the grantee
  is checked in.
- **A boundary on a role, a permission or a policy**: refused with `BoundaryException` when it is set, as no check is
  ever about one. A role's holders are capped only by their own boundaries; a role's policies are ordinary policies,
  never a cap.
- **A grantee of the narrow contracts**: a principal or identity that holds grants through `SupportsRoles`,
  `SupportsPermissions` or `SupportsPolicies` without being an `AuthorizableIdentity` is capped by its boundaries as any
  saved model is.
- **A policy reached twice**: a policy held and set as a boundary, or the boundary of both the principal and its
  identity, denies once at the deny stage, is assessed once as a policy and once as a boundary, and is named once.
- **A grantee deleted past its model events**: its boundary rows stay until `authorization:prune` finds the grantee
  gone, a grantee whose only rows are boundaries included, and removes its boundaries through
  `BoundaryService::removeAll()`, counted apart from its grants, before it revokes its grants through
  `GrantService::revokeAll()`; until then the boundary's policy cannot be deleted.
- **A guardrail with no allow for the check**: as a boundary's, it denies every check in its scope it does not allow as
  `guardrail`, names no statement, and adds a `refused` step naming it after its allows' steps.
- **An unreadable guardrail**: a guardrail whose document cannot be hydrated, or is over a limit, denies every check in
  its scope as `invalid_policy` at the deny stage (every check, for a platform guardrail), logged as an unreadable
  policy is. Its policy cannot be edited while it is a guardrail, so it is fixed by removing the guardrail, correcting
  the policy and setting it again. The check of `authorization:guardrail.manage` reads no guardrail, so an unreadable
  guardrail, a platform one included, never blocks its own removal through the service.
- **A guardrail and `withPolicies()`**: the override replaces the policies, never the guardrails, so an override never
  lifts a guardrail.
- **A guardrail in another application**: a guardrail has no application, so it holds in every application.
- **A resource admitted from outside the scope**: a subject admitted at platform scope to another tenant's resource
  through a platform-wide permission is capped by that tenant's guardrails and its ancestors', read in the resource's
  tenant, besides the platform's.
- **A guardrail that does not allow managing guardrails**: the check of `authorization:guardrail.manage` is exempt
  from the guardrails, so such a guardrail, or one that denies the permission, caps every other check in its scope but
  never that one, and keeps no actor from changing the guardrails of any scope, its own removal included.
- **A check of another `authorization:` action**: only the exact action `authorization:guardrail.manage` is exempt;
  any other action, one a pattern of it would match included, is capped by the guardrails as ever.
- **No authorization manager bound**: `GuardrailAuthority` refuses every actor, so no guardrail is changed unchecked.
- **No session policy source bound**: the default `NoSessionPolicy` answers null for every subject, so no credential
  caps a person's checks and only `capped()` caps them; every check about a machine principal is denied as
  `session_policy` until a source answers its scopes.
- **A subject named with `for()`**: the source is asked about that subject, which is no request's caller, so it answers
  null unless it knows the credential that subject acts with; a machine named so is then allowed nothing.
- **An empty cap**: a credential carrying `[]`, and `capped([])`, deny every check as `session_policy`, a machine's
  included; neither is the same as no cap.
- **A scope the map does not name**: it names itself as an action or a pattern. One that covers no declared permission
  is not refused at decision time; it covers nothing a check could allow, and a bound `ScopeRegistry` keeps it off the
  credential in the first place.
- **A bad scope map**: a scope that is empty, named twice, mapped to anything but a non-empty list of non-empty
  strings, or naming a pattern that covers no declared permission is refused at boot with
  `InvalidAuthorizationConfigException`, and so is a null or unknown `session.source`.
- **An explicit cap and the Gate**: `capped()` scopes the manager it returns; `Gate::allows()`, `can:` and the
  middleware decide through the unscoped manager, so only the credential's scopes cap them.
- **A machine paired with a person**: a subject whose principal is a machine and whose identity is a person, or the
  reverse, gets none of the identity's roles, permissions or allow statements, and no resource policy selector naming
  the identity names it; the identity's deny statements still deny it, its boundaries still cap it and its inactivity
  still denies it.
- **A session policy source that throws**: the check is aborted with the exception, and no decision is made, recorded
  or dispatched.
- **Nothing declared**: the package declares its own administration actions, `authorization:guardrail.manage` among
  them, whatever the application configures, but the shipped `DeclaredActionCatalogue` holds the application's
  declarations alone. With none, a policy whose patterns need any action but the package's own is refused with the one
  reason that nothing is declared (`PolicyValidator::NOTHING_DECLARED`), and one naming only the package's own, such
  as `authorization:*`, is written (N50).

## Implementation Anchors

- `AuthorizationManager::check()` -- the core decision and its recording; `DecisionPipeline::decide()` -- the subject
  and resource stages; `DecisionPipeline::sources()` -- the check's context (`CheckContextFactory::make()`), the
  policies, the guardrails (none at all, `null`, for the exempt `authorization:guardrail.manage`), the boundaries, the
  permission callback and the session caps; `DecisionPipeline::weigh()` -- the evaluator given those sources under the
  session caps; `DecisionPipeline::decideGrants()` -- `invalid_policy` when the sources cannot be gathered, and the
  weighed decision passed through `Administration\OperationConstraints::weigh()`;
  `Administration\OperationConstraints::weigh()` -- the administration stage, which can only refuse an allow of an
  administration action on its own operation resource;
  `AuthorizationManager::capped()` and `DecisionPipeline::capped()` -- the scoped manager carrying the explicit caps;
  `AuthorizationManager::any()` and `all()`, over `Support\ActionList` -- several actions decided in order, stopping at
  the first that settles the answer.
- `ResourceReferences::of()` -- every resource argument's reference; `ResourceScope::decide()` -- the tenant stage.
- `SubjectGrants::permissionFor()` -- the held permission that allows the check, the subject's before its granting
  identity's, read in the scope the check is decided in; `HeldPermissions::match()` -- the wildcard rules and the
  deterministic choice, shared with `HasPermissions::hasPermission()`; `HasPermissions::getPermissions()`,
  `GrantResolver::permissions()` and `TenantChain::grants()` -- the permissions whose grants reach the scope, kept per
  scope by `ResolutionCache::rememberPermissions()`.
- `ResourcePolicyResolver::policiesFor()` -- the resource's and its type's policies, in one query;
  `PrincipalSelectors` and `CheckContext::isSubjectNamedBy()` -- whether a selector names the subject;
  `PolicyEvaluator::isForSubject()` -- whether an allow applies to the subject; `PolicyPrincipals` -- the attachment
  and rewrite refusals; `ResourcePolicyService` -- attaching and detaching.
- `DefaultPolicyResolver::policiesFor()` -- the policy store and the identity's policies;
  `HasPolicies::getPolicies()` and `GrantResolver::policies()` -- the identity's own attachments and its roles';
  `RolePolicies` -- where a role's policy applies; `RoleGraph::keysHeldBy()` and `RoleGraph::keysWithin()` -- the roles
  reached, shared with the permissions; `InlinePolicies` -- the grantee an inline policy belongs to and the refusals;
  `SubjectGrants::identityPolicies()` -- the policies of a separate identity, appended after the resolver's, whole or,
  across kinds, as their deny statements alone.
- `PolicyEvaluator::evaluate()` -- the deny, cap, allow and implicit stages, each assessing its statements in a fixed
  order; `cap()` -- the guardrail, boundary and session stages in order; `capBy()` -- a cap stage's intersection, the
  guardrails' and the boundaries'; `capped()` and `capBySession()` -- the session caps a check is decided under and
  their intersection; `allow()` -- the allow statements, then the permission asked lazily, its step naming the held
  permission; `conclude()` -- the order of the outcomes, `insufficient_authentication` among them. `StatementEntries`
  -- the statements of the policies, the guardrails and the boundaries, split by stage and ordered, worked out once per
  policy.
- `GuardrailResolver::guardrailsFor()` -- the guardrails of the platform, the check's tenant and its ancestors, in the
  resource's tenant when it has one, in one query through `ResolutionCache::rememberGuardrails()`; `GuardrailService`,
  `Services\Support\GuardrailTable` and `Services\Support\GuardrailAuthority` -- setting and removing them and who may;
  `PolicyGuardrails` -- the refused edit and delete, serialised with a guardrail set on the policy's row;
  `Support\PackagePermissions` -- the permission the package declares, which `PolicyValidator` accepts whatever the
  action catalogue holds.
- `SubjectGrants::boundaries()` and `BoundaryResolver::boundariesFor()` -- the boundaries of the principal and the
  identity that hold in the check's tenant, in one query through `ResolutionCache::rememberBoundaries()`;
  `BoundaryService` and `Services\Support\BoundaryTable` -- setting, replacing and removing them; `PolicyBoundaries` --
  the refused delete and, with `PolicyPrincipals`, the refused rewrite.
- `SessionCapResolver::capsFor()` -- the check's session caps: the source asked once, the scopes mapped, the explicit
  caps added and the machine rule; `SessionCaps` -- the caps, their trace names and `covers()`; `SessionScopes` -- the
  scope map; `Contracts\SessionPolicySource` and `Resolvers\NoSessionPolicy` -- the source and its default;
  `Config\SessionConfigValidator` -- the boot checks of the source and the map; `Contracts\AuthorizableMachine` --
  the machine marker; `SubjectGrants::grantingIdentity()` -- the identity whose grants reach the subject, shared by the
  roles, permissions, policies and `PrincipalSelectors`; `Contracts\ScopeRegistry` and
  `Support\CatalogueScopeRegistry` -- the scope registry.
- `RequirementCheck` -- one check's requirements put to the checker, the session rule and the freshness;
  `CheckContext::assessRequirement()` -- where a statement's requirement is judged; `LastDecisionStore::get()`,
  `LastDecisionStore::wasRecordedIn()` and `AuthorizationManager::lastDecision()` -- the freshness of the last decision
  and the session of the request that recorded it.
- `InsufficientAuthenticationException` and `AuthorizationManager::authorize()` -- the exception and when it is raised.
- `Statement::assess()` -- the assessment, with each condition key's result.
- `PolicyValidator` -- the write-time checks; `PolicyDocument::hydrate()` and `PolicyLimits` -- the limits on read.
- `Decision`, `TraceEntry`, `StatementReference`, and the `DecisionEffect`, `DecisionReason`, `DecisionStage` and
  `TraceOutcome` enums.

## Authoritative Tests

- `PolicyEvaluatorTest` -- every outcome and stage, the stage order and its trace, deny precedence, fail-closed
  undecidable denies, `invalid_policy`, `condition_failed` and `no_match`, the guardrail and boundary stages
  (intersection, conditions, a cap's denies, an invalid cap, the guardrails before the boundaries,
  `insufficient_authentication` only after them), the permission asked lazily,
  and the same decision whatever order the policies arrive in; `StatementEntriesTest` -- the fixed order and the work
  done once per policy.
- `BoundaryServiceTest`, `BoundaryTableTest`, `BoundaryResolverTest` and `PolicyBoundariesTest` -- setting, replacing
  and removing a boundary, its scope and reach, the refusals, the events, which boundaries apply in a tenant, and the
  refused delete; the Feature `AuthorizationManagerTest` -- a boundary capping every allow source and granting nothing,
  the platform and tenant and the principal and identity intersections, an unreadable boundary, the cache refreshed on
  every change, and the queries taken.
- `GuardrailServiceTest`, `GuardrailTableTest`, `GuardrailAuthorityTest`, `GuardrailResolverTest` and
  `PolicyGuardrailsTest` -- setting and removing a guardrail, its scope, the refusals, the events, who may change it
  and from where, which guardrails apply to a check, and the refused edit and delete; the Feature
  `AuthorizationManagerTest` -- a guardrail capping every allow source and granting nothing, the platform, tenant and
  ancestor intersection, the resource's tenant after a platform-wide admission, an unreadable guardrail, the cache
  refreshed on every change, and the queries taken.
- `SessionCapsTest`, `SessionScopesTest`, `SessionCapResolverTest` and `NoSessionPolicyTest` -- covering, the trace
  names, the scope map, the machine rule and the default source; `PolicyEvaluatorTest` -- the session stage, its
  intersection, an empty cap against none, its place after the denies, guardrails and boundaries and before
  `insufficient_authentication`; the Feature `AuthorizationManagerTest` -- the credential's cap, an explicit cap, nested
  caps, their intersection, a cap capping every allow source and granting nothing, a machine with and without scopes,
  identity grants never crossing between a machine and a person while the identity's denies still deny, and the queries
  taken; `SubjectGrantsTest` and `PrincipalSelectorsTest` -- the identity whose grants reach the subject;
  `SessionConfigValidatorTest` -- the boot checks; `CatalogueScopeRegistryTest` -- the scope registry.
- `DecisionTest` and `TraceEntryTest` -- the decision's construction, the explanation, the cap stages' steps and the
  freshness.
- `PolicyEvaluatorTest` and `StatementTest` -- `insufficient_authentication` and where it ranks, an unmet and an
  undecidable requirement on an allow and on a deny, and the trace's `authentication` key.
- `RequirementCheckTest`, `RequirementFreshnessTest` and `LastDecisionStoreTest` -- the session rule, a checker that
  throws, the met-until instant and the last decision's freshness; `InsufficientAuthenticationExceptionTest` -- the
  exception.
- `AuthorizationManagerTest` (Unit and Feature) -- the subject stage, the RBAC allow, deny over RBAC and over a role,
  `invalid_policy` over a held permission, and the caller's values under `input` and nowhere else; the Feature
  `AuthorizationManagerTest` -- a permission held allowing only after every deny and cap, with its step naming it, a
  grant's reach over a tenant's resources, its subtree, a sibling and another tree, platform-wide grants, tenantless
  checks with and without an active tenant, applications and expiry, and `permissionsFor()` agreeing with
  `check()`; `RequirePermissionTest` -- the middleware agreeing with `check()` in a tenant; `RbacQueryBudgetTest` -- no
  query once each scope a check reads is warm; `HeldPermissionsTest`, `SubjectGrantsTest` and `HasPermissionsTest` --
  the match, the permission named, and `hasPermission()` reporting what is granted without deciding.
- `RolePoliciesTest` and `GrantResolverTest` -- a role's policy in and out of scope (tenant, application, expiry and
  subtree), inheritance down the hierarchy, a deny in a role's policy, a policy held several ways listed once, every
  source in one order, the queries taken and a hierarchy that moves while the policies are read;
  `InlinePoliciesTest`, `HasPoliciesTest` and `AuthorizablePolicyPivotObserverTest` -- inline policies attached to
  their grantee alone, left out when attached to another, and deleted with their grantee.
- `ResourcePolicyResolverTest`, `PrincipalSelectorsTest` and the Feature `AuthorizationManagerTest` -- a record's and
  its type's policies, a type alone and an opaque identifier, selectors by reference and by role in and out of scope
  and down the hierarchy, a deny for everyone, an allow with no permission held, `tenant_scope` before any resource
  policy, and the queries taken; `PolicyPrincipalsTest`, `ResourcePolicyServiceTest` and `InlinePoliciesTest` -- the
  attachment and rewrite refusals; `PolicyEvaluatorTest` -- `principal_mismatch` and the order with resources.
- `FailClosedPolicyHydrationTest` -- an unreadable row, or one over a limit, is never skipped.
- `PolicyValidatorTest` and `PolicyDocumentTest` -- the write-time checks and the limits on read.
- `GateRegistrarTest` and `AuthorizeActionTest` -- an argument that cannot be identified denies as
  `resource_unresolved`.
- `ResourceReferencesTest` and `ResourceScopeTest` -- resource references and the tenant stage.
- `DecisionPipelineTest` -- each admission stage, the policy sources, the override and the explicit caps, the session
  caps, an unreadable policy, the exempt guardrail permission, and the caller's values with and without a context
  factory; `ActionListTest` and the Unit and Feature `AuthorizationManagerTest` -- `cannot()`, `any()` and `all()` on
  the current subject and on every scoped manager, stopping at the first decision that settles the answer, each
  decision recorded and reported, `insufficient_authentication` as a refusal, every resource form, and an empty list
  refused before anything is decided.

## Change Triggers

- Letting a session cap allow by itself, replace another cap rather than intersect with it, or treat no cap and an empty
  cap alike; letting `capped()` stand in for a machine's missing credential scopes; letting an identity's grants or
  allow statements cross between a machine and a person; or dropping a cross-kind identity's deny statements, boundaries
  or inactivity would violate invariant 12 and requires a design decision before implementation. Adding any other stage
  requires a design decision before implementation.
- Letting a guardrail allow by itself, be skipped when it cannot be read or evaluated, reach only some of its tenant's
  subtree, or be changed by an actor whose right is held within the tenant it caps would violate invariant 11 and
  requires a design decision before implementation.
- Letting a boundary allow by itself, replace another boundary rather than intersect with it, or be skipped when it
  cannot be read or evaluated would violate invariant 10 and requires a design decision before implementation.
- Letting `insufficient_authentication` win over a deny, an invalid policy or another allow, or reusing a decision that
  read a requirement in another session or past its met-until instant, would violate invariants 7 and 8 and requires a
  design decision before implementation.
- Adding a source of policies requires updating the section on where policies come from, and the new source's policies
  must be ordered with the rest under invariant 2.
- Letting a resource policy's allow apply to a subject its principals do not name, a deny take `principals`, or an
  allow with `principals` apply outside a resource policy would violate invariant 9 and requires a design decision
  before implementation. Every cap ranks above a resource policy's allow.
- Changing deny semantics (e.g. deny-unless, deny-with-exception) requires a new invariant entry above.
- Introducing RBAC-layer deny (negative permissions) would violate invariant 3 and requires a design decision before
  implementation.
- Answering a check from the permissions held before the allow stage (a fast path ahead of the denies or the caps),
  letting a permission count on a resource its grant does not reach, or letting `hasPermission()` stand in for a
  decision would violate invariants 3 and 13 and requires a design decision before implementation.
- Letting an undecidable deny, an invalid statement or an unreadable policy be skipped would violate invariants 5 and 6
  and requires a design decision before implementation.
