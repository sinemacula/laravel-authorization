# Evaluation Order and Deny Precedence

## Purpose

Document the staged decision every check goes through, the interaction between policy statements and RBAC, the
invariants that govern deny precedence, and how a decision fails closed when a statement cannot be decided or a policy
cannot be evaluated. This note is the authoritative reference for why the decision behaves the way it does -- the
code and tests encode the *what*; this note encodes the *why*.

## The Decision

`AuthorizationManager::check()` is the one core decision (D22); `can()` reads whether it allows and `authorize()`
throws when it does not. It returns a `Decision`:

- `effect` -- `DecisionEffect::ALLOW` or `DecisionEffect::DENY`; `isAllowed()` reads it.
- `reason` -- why it denies, a `DecisionReason` (AUTHZ-7.10); null when it allows.
- `stage` -- the `DecisionStage` that decided it.
- `statements` -- the statements that decided it, each a `StatementReference` (the policy's name, its stored key and
  the statement's position, shown as `name[key]#position`); none for a permission held or a denial no statement made.
- `trace` -- every step taken, in order, each a `TraceEntry`: its stage, its `TraceOutcome`, the statement it
  assessed (none for the permission step), and the condition keys it tested with whether each held.

The trace never carries a context or attribute value, only key names and results (AUTHZ-8.8), so a decision is safe to
log, store and put on an event.

## Invariants

1. **The stages run in order, and the first that decides ends the decision (AUTHZ-7.1).**
   1. *Subject*: no subject denies as `subject_unresolved`; an inactive subject, or one whose identity is inactive,
      denies as `subject_inactive`. Nothing else is read.
   2. *Resource*: a resource argument that cannot be identified (an unsaved model, a number, an empty pair, a route
      parameter the route lacks) denies as `resource_unresolved` (N1).
   3. *Tenant*: a resource whose tenant is the decision's tenant, or below it in the tenant tree, is decided in its own
      tenant, so grants there and those above it that reach down count. A resource of any other tenant (every
      tenant-owned resource when no tenant is active) denies as `tenant_scope` before any policy is read, unless the
      subject holds the action's permission through a platform-wide grant, when the rest runs at platform scope
      (AUTHZ-4.4, AUTHZ-5.5, N9).
   4. *Deny*: every deny statement of every applicable policy is assessed. One that matches, or whose test cannot be
      decided, denies as `explicit_deny`. Failing that, a deny statement that cannot be evaluated denies as
      `invalid_policy`. A stored policy that cannot be read denies as `invalid_policy` before any statement is
      assessed.
   5. *Allow*: only when no deny decided, every allow statement is assessed. One that cannot be evaluated denies as
      `invalid_policy`; failing that, one that matches allows. Failing that, a permission the subject holds that the
      action names (directly or through a role) allows.
   6. *Implicit*: nothing allowed. The denial is `condition_failed` when an allow statement names the action and the
      resource but its conditions do not hold or cannot be decided, and `no_match` otherwise.

   Guardrails, permission boundaries and session policies take their places between the deny and allow stages as they
   arrive (BL-48 to BL-50).

2. **The decision is deterministic (AUTHZ-7.9).** Within each stage, policies are assessed in order of name, then stored
   key, then document, and each statement in order of position, and every statement of the stage is assessed whatever is
   found first, so the decision, the statements that decided it and the trace are the same whatever order the policies
   were read in. A stage that decides ends the decision: once a deny decided, no allow statement is assessed (N4).

3. **RBAC is additive / allow-only.** Direct permission grants and role-inherited permissions are unioned on read.
   There is no RBAC-layer deny: every permission a subject holds contributes an allow and nothing else, and only when no
   statement has decided the check.

4. **All deny semantics live exclusively in policies.** "Everyone in role X except these three users" is a deny
   policy, not an RBAC construct, so an administrator reviewing effective permissions never reasons about negative
   grants.

5. **A deny statement is skipped only when its test definitely fails.** A deny whose conditions definitely do not hold
   is recorded as `condition_failed` and decides nothing. A deny whose test cannot be decided -- a condition key missing
   from the context, a `${…}` reference that cannot be resolved, a value or interpolated operand of the wrong type --
   **applies**. This deliberately departs from AWS IAM, where a missing key silently disables a conditional deny: a
   caller that leaves a key out of the context never gets past a deny written against it. An allow is the mirror
   image: it applies only when its test definitely holds.

6. **A policy that cannot be evaluated denies the check; it is never skipped.** Skipping a malformed statement or an
   unreadable policy row would also drop the denies it carries, so both deny as `invalid_policy`, and RBAC never
   overrides that, even when the subject holds the permission.

## Trace

Each statement adds one entry, in the deny stage for a deny statement and the allow stage for an allow statement, and
the permission step adds one more when the statements allowed nothing:

| What the step found                                                 | Outcome            |
|---------------------------------------------------------------------|--------------------|
| The statement does not name the action or the resource              | `not_applicable`   |
| It names them and its conditions hold                               | `matched`          |
| It names them but its conditions do not hold                        | `condition_failed` |
| It names the action but a value it needs is missing or unresolvable | `undecidable`      |
| It cannot be evaluated                                              | `invalid`          |
| The subject holds the permission the action names                   | `held`             |
| The subject does not hold it                                        | `not_held`         |

Policy names in the trace are the stored policy's name: when a policy row is hydrated, the model's name replaces any
`name` inside the document, so a document cannot claim another policy's name.

## Failure / Edge Cases

- **No subject**: `subject_unresolved` at the subject stage, without consulting any policy. This covers anonymous
  requests and a subject resolver that resolves no subject.
- **Malformed policy document**: writes are refused -- the `Policy` model validates the document on assignment, and
  `Statement::fromArray()` refuses unknown keys, an empty resource list, an empty operator map, a non-string operator
  key, an unknown operator, a malformed literal operand and a malformed `${…}` reference. A row that still cannot be
  hydrated on read is never skipped: `HasPolicies::getPolicies()` logs a warning on the package's log channel and
  rethrows, and the decision is `invalid_policy`. A custom `PolicyResolver` must do the same: throw
  `InvalidPolicyDocumentException` rather than leave a policy out.
- **Invalid statement at decision time**: a directly constructed statement with an unknown operator, a malformed
  literal operand or a malformed `${…}` reference in a condition is `invalid` as soon as it is assessed, whatever the
  context holds. An interpolated operand that resolves to a value of the wrong type is `undecidable`, not invalid. A
  statement whose action or resource does not cover the check is `not_applicable` before its conditions are looked
  at, so it never makes the check invalid.
- **Resource references**: every check names its resource the same way (`ResourceReferences::of()`): a model as
  `type:id` with the tenant the bound `ResourceTenantResolver` gives it (none by default, N10), a `(type, id)` pair the
  same way, a model class as `type:*` (N6), an `AuthorizableResource` as the reference it returns (N8), and any other
  string as an opaque identifier with no tenant (N7).
- **Resource-less check**: a check without a resource matches only statements whose resources include `*`. An argument
  that cannot be identified as a resource denies as `resource_unresolved` at the resource stage, without reading any
  policy or permission, rather than becoming a resource-less check; the denial is recorded and reported like any
  other decision.
- **Empty statements list**: a policy with zero statements contributes nothing to the trace and does not affect the
  decision.

## Implementation Anchors

- `AuthorizationManager::check()` -- the core decision; `decide()` -- the subject and resource stages;
  `decideGrants()` -- `invalid_policy` when policies cannot be gathered, the statements, and the permission step.
- `ResourceReferences::of()` -- every resource argument's reference; `ResourceScope::decide()` -- the tenant stage.
- `PolicyEvaluator::evaluate()` -- the deny, allow and implicit stages, each assessing its statements in a fixed
  order.
- `Statement::assess()` -- the assessment, with each condition key's result.
- `Decision`, `TraceEntry`, `StatementReference`, and the `DecisionEffect`, `DecisionReason`, `DecisionStage` and
  `TraceOutcome` enums.

## Authoritative Tests

- `PolicyEvaluatorTest` -- every outcome and stage, deny precedence, fail-closed undecidable denies, `invalid_policy`,
  `condition_failed` and `no_match`, and the same decision whatever order the policies arrive in.
- `DecisionTest` -- the decision's construction, the permission step and the explanation.
- `AuthorizationManagerTest` (Unit and Feature) -- the subject stage, the RBAC allow, deny over RBAC and over a role,
  and `invalid_policy` over a held permission.
- `FailClosedPolicyHydrationTest` -- an unreadable row is never skipped.
- `GateRegistrarTest` and `AuthorizeActionTest` -- an argument that cannot be identified denies as
  `resource_unresolved`.
- `ResourceReferencesTest` and `ResourceScopeTest` -- resource references and the tenant stage.

## Change Triggers

- Adding a stage (guardrails, boundaries, session policies) requires updating this note, `DecisionStage` and, for a
  new kind of denial, `DecisionReason`.
- Changing deny semantics (e.g. deny-unless, deny-with-exception) requires a new invariant entry above.
- Introducing RBAC-layer deny (negative permissions) would violate invariant 3 and requires a design decision before
  implementation.
- Letting an undecidable deny, an invalid statement or an unreadable policy be skipped would violate invariants 5 and 6
  and requires a design decision before implementation.
