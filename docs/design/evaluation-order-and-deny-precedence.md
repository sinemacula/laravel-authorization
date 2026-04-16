# Evaluation Order and Deny Precedence

## Purpose

Document the four-step decision order used by the policy evaluator, the interaction between policy evaluation and RBAC,
and the invariants that govern deny precedence. This note is the authoritative reference for why the evaluator behaves
the way it does -- the code and tests encode the *what*; this note encodes the *why*.

## Invariants

1. **RBAC is additive / allow-only.** Direct permission grants and role-inherited permissions are unioned on read
   (`HasPermissions::getPermissions()`). There is no RBAC-layer deny mechanism -- every permission a principal holds
   (directly or via roles) contributes an allow signal and nothing else.

2. **All deny semantics live exclusively in policies.** A consumer who needs "everyone in role X except these three
   users" must express that exception as a deny policy, not as an RBAC construct. This keeps the role/permission model
   simple and auditable -- an admin reviewing a principal's effective permissions never has to reason about negative
   permission grants or RBAC-layer overrides.

3. **The four-step evaluation order is: explicit deny, explicit allow, RBAC, implicit deny.** The evaluator walks every
   statement from every policy in document order. Within that walk:
   - A matching **deny** statement short-circuits immediately -- the evaluator returns `EXPLICIT_DENY` and stops.
   - A matching **allow** statement is recorded but does not short-circuit -- a subsequent deny in the same or a later
     policy still wins.
   - After all statements have been walked: if at least one allow was recorded, the evaluator returns `EXPLICIT_ALLOW`.
   - If no policy produced a decisive result, the manager falls back to RBAC: if the principal holds the action as a
     permission (directly or via a role), the result is `RBAC_ALLOW`.
   - If RBAC also does not match, the result is `IMPLICIT_DENY`.

4. **A deny statement whose conditions do not match is skipped, not treated as an explicit deny.** The trace records it
   as `skipped` with the reason `conditions not satisfied`. This is the AWS IAM-compatible behaviour -- a conditional
   deny that does not apply is a non-event, not a fallback deny.

5. **Direct-user-permission grants sit alongside role-inherited permissions as equal citizens.** There is no precedence
   between them; the union wins. A principal who holds `posts:create` directly and also inherits it from a role sees
   the same effective decision as one who holds it from either source alone.

## Success Path

A typical evaluation for `Authorization::for($user)->can('posts:create')`:

1. The manager resolves the principal (the `$user` override from `for()`).
2. Policies are gathered via the `PolicyResolver` (which may consult a cache).
3. The evaluator walks every statement of every policy in order, building a trace.
4. No deny matches, one allow matches -- the evaluator returns `EXPLICIT_ALLOW`.
5. The manager records the result in the `LastDecisionStore` and emits `DecisionEvaluated`.

When no policy matches at all:

1-3. Same as above, but every statement is traced as `skipped`.
4. The evaluator returns `IMPLICIT_DENY` (no allow, no deny).
5. The manager checks RBAC: `$user->hasPermission('posts:create')` returns true (direct grant or role-inherited).
6. The manager returns `RBAC_ALLOW`, preserving the evaluator's trace for audit.

## Failure / Edge Cases

- **Null principal**: the manager short-circuits to `IMPLICIT_DENY` without consulting the evaluator. This covers
  anonymous requests and misconfigured principal resolvers.
- **Malformed policy document**: the `HasPolicies` trait drops the bad row from the evaluation set and logs through the
  `authorization` channel. The remaining policies continue to evaluate. A malformed row can never contribute an allow
  because it was never hydrated.
- **Empty statements list**: a policy with zero statements contributes nothing to the trace and does not affect the
  outcome. It is a no-op, not an error.

## Implementation Anchors

- `PolicyEvaluator::evaluate()` -- the statement walk and deny short-circuit.
- `AuthorizationManager::evaluateFor()` -- the RBAC fallback after policy evaluation.
- `EvaluationResult` factory methods -- one per branch of the four-step order.
- `DecisionReason` enum -- typed representation of the four possible outcomes.

## Authoritative Tests

- `PolicyEvaluatorTest::testExplicitDenyOverridesAllow` -- deny after allow still returns deny.
- `PolicyEvaluatorTest::testDenyShortCircuits` -- deny stops the trace at one entry.
- `PolicyEvaluatorTest::testConditionMismatchSkips` -- conditional deny that does not match is skipped.
- `AuthorizationManagerTest::testRbacAllowedWhenPolicyDoesNotMatch` (Unit) -- RBAC fallback produces `RBAC_ALLOW`.
- `AuthorizationManagerTest::testExplicitDenyOverridesRbac` (Unit) -- deny policy beats RBAC permission.
- `AuthorizationManagerTest::testExplicitDenyOverridesRoleAllow` (Feature) -- end-to-end deny over role grant.

## Change Triggers

- Adding a fifth evaluation step (e.g. a conditional RBAC layer) requires updating this note, the `DecisionReason`
  enum, and the `EvaluationResult` factory set.
- Changing deny semantics (e.g. deny-unless, deny-with-exception) requires a new invariant entry above.
- Introducing RBAC-layer deny (negative permissions) would violate invariant 1 and requires a design decision before
  implementation.
