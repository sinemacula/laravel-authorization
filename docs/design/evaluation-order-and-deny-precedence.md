# Evaluation Order and Deny Precedence

## Purpose

Document the four-step decision order used by the policy evaluator, the interaction between policy evaluation and RBAC,
the invariants that govern deny precedence, and how the evaluator fails closed when a statement cannot be decided or a
policy cannot be evaluated. This note is the authoritative reference for why the evaluator behaves the way it does --
the code and tests encode the *what*; this note encodes the *why*.

## Invariants

1. **RBAC is additive / allow-only.** Direct permission grants and role-inherited permissions are unioned on read
   (`HasPermissions::getPermissions()`). There is no RBAC-layer deny mechanism -- every permission a principal holds
   (directly or via roles) contributes an allow signal and nothing else.

2. **All deny semantics live exclusively in policies.** A consumer who needs "everyone in role X except these three
   users" must express that exception as a deny policy, not as an RBAC construct. This keeps the role/permission model
   simple and auditable -- an admin reviewing a principal's effective permissions never has to reason about negative
   permission grants or RBAC-layer overrides.

3. **The four-step evaluation order is: explicit deny, explicit allow, RBAC, implicit deny.** The evaluator walks every
   statement from every policy in document order and assesses it as matching, not matching, undecidable or invalid (see
   [Wildcard and condition semantics](wildcard-and-condition-semantics.md#match-outcomes)). Within that walk:
   - An **invalid** statement short-circuits immediately -- the evaluator returns `InvalidPolicy` and stops, whatever
     its effect and whatever was recorded before it.
   - A **deny** statement that matches, or whose test is undecidable, short-circuits immediately -- the evaluator
     returns `ExplicitDeny` and stops.
   - An **allow** statement that matches is recorded but does not short-circuit -- a subsequent deny in the same or a
     later policy still wins. An allow whose test is undecidable is skipped.
   - After all statements have been walked: if at least one allow was recorded, the evaluator returns `ExplicitAllow`.
   - Only when the evaluator returns `ImplicitDeny` does the manager fall back to RBAC: if the principal holds the
     action as a permission (directly or via a role), the result is `RbacAllow`. An `ExplicitDeny`, an
     `ExplicitAllow` and an `InvalidPolicy` all stand.
   - If RBAC also does not match, the result is `ImplicitDeny`.

4. **A deny statement is skipped only when its test definitely fails.** A deny whose conditions definitely do not match
   is a non-event, not a fallback deny: the trace records it as `skipped` with the reason `conditions not satisfied`. A
   deny whose test cannot be decided -- a condition key missing from the context, a `${…}` reference that cannot be
   resolved, a context value or an interpolated operand of the wrong type -- **applies**, and the trace records
   `explicit deny: <detail>`. This deliberately departs from AWS IAM, where a missing key silently disables a
   conditional deny: a caller that leaves a key out of the context must never get past a deny written against it. An
   allow is the mirror image: it applies only when its test definitely matches.

5. **Direct-user-permission grants sit alongside role-inherited permissions as equal citizens.** There is no precedence
   between them; the union wins. A principal who holds `posts:create` directly and also inherits it from a role sees
   the same effective decision as one who holds it from either source alone.

6. **A policy that cannot be evaluated denies the check; it is never skipped.** Skipping a malformed statement or an
   unreadable policy row would also drop the denies it carries. An invalid statement, and a stored document that cannot
   be hydrated, both produce `InvalidPolicy` (`allowed = false`, reason `invalid_policy`, no matched statement), and
   RBAC never overrides it, even when the principal holds the permission.

## Success Path

A typical evaluation for `Authorization::for($user)->can('posts:create')`:

1. The manager resolves the principal (the `$user` override from `for()`).
2. Policies are gathered via the `PolicyResolver` (which may consult a cache).
3. The evaluator walks every statement of every policy in order, building a trace.
4. No deny matches, one allow matches -- the evaluator returns `ExplicitAllow`.
5. The manager records the result in the `LastDecisionStore` and emits `DecisionEvaluated`.

When no policy matches at all:

1-3. Same as above, but every statement is traced as `skipped`.
4. The evaluator returns `ImplicitDeny` (no allow, no deny, no invalid statement).
5. The manager checks RBAC: `$user->hasPermission('posts:create')` returns true (direct grant or role-inherited).
6. The manager returns `RbacAllow`, preserving the evaluator's trace for audit.

Each statement the evaluator assesses adds one trace entry. The `<detail>` names what decided the outcome (for
example `key 'ip' is missing from the context`) and never carries a context value:

| Statement outcome                           | Trace decision | Trace reason                     |
|---------------------------------------------|----------------|----------------------------------|
| Action or resource does not cover the check | `skipped`      | `action/resource did not match`  |
| Conditions definitely do not match          | `skipped`      | `conditions not satisfied`       |
| Allow whose test is undecidable             | `skipped`      | `could not be decided: <detail>` |
| Allow that matches                          | `matched`      | `explicit allow`                 |
| Deny that matches                           | `matched`      | `explicit deny`                  |
| Deny whose test is undecidable              | `matched`      | `explicit deny: <detail>`        |
| Invalid statement (either effect)           | `matched`      | `invalid statement: <detail>`    |

Policy names in the trace are the stored policy's name: when a policy row is hydrated, the model's name replaces any
`name` inside the document, so a document cannot claim another policy's name.

## Failure / Edge Cases

- **Null principal**: the manager short-circuits to `ImplicitDeny` without consulting the evaluator. This covers
  anonymous requests and misconfigured principal resolvers.
- **Malformed policy document**: writes are refused -- the `Policy` model validates the document on assignment, and
  `Statement::fromArray()` refuses unknown keys, an empty resource list, an empty operator map, a non-string operator
  key, an unknown operator, a malformed literal operand (including an empty string for `starts_with`, `ends_with` or
  `string_like`, and `NAN` or an infinity for a numeric comparison) and a malformed `${…}` reference in a resource
  pattern or a condition. A row that still cannot be hydrated on read (one written around the model, or one an older
  release accepted) is never skipped: `HasPolicies::getPolicies()` logs a warning on the package's log channel (`authorization.log_channel`)
  (with `policy_id`, `policy_name` and `reason`) and rethrows, and the manager returns `InvalidPolicy`. Every check for
  that identity denies, whatever it holds, until the document is fixed. A custom `PolicyResolver` must do the same:
  throw `InvalidPolicyDocumentException` rather than leave a policy out.
- **Unknown document version or key**: a document whose `version` is not `1`, or which carries a top-level key other
  than `version`, `name` and `statements`, is refused like any other malformed document. A document without a
  `version` is version 1.
- **Invalid statement at evaluation time**: a directly constructed statement with an unknown operator, a malformed
  literal operand or a malformed `${…}` reference in a condition returns `InvalidPolicy` as soon as it is assessed,
  whatever the context holds: a condition's shape is checked before its key is looked up, so a missing key does not
  turn it into an undecidable test. An interpolated operand that resolves to a value of the wrong type is undecidable,
  not invalid: a deny applies and an allow is skipped. A statement whose action or resource does not cover the check
  is skipped before its conditions are looked at, so it never makes the check invalid.
- **Resource-less check**: a check without a resource matches only statements whose resources include `*`. Through the
  Gate, a `null` argument means no resource; an argument that cannot be identified as a resource (an unsaved model, a
  model with an empty key, a number, a boolean, a list, an object without `__toString()`) denies without evaluating
  policies or RBAC, rather than becoming a resource-less check. The denial is recorded like any other decision: it is
  an `ImplicitDeny` (reason `implicit_deny`), it becomes the last decision, and one `DecisionEvaluated` event is
  dispatched with a `null` resource. An `AuthorizableResource` is identified by `toResourceIdentifier()`, even when it
  is also an Eloquent model.
- **Empty statements list**: a policy with zero statements contributes nothing to the trace and does not affect the
  outcome. It is a no-op, not an error.

## Implementation Anchors

- `PolicyEvaluator::evaluate()` -- the statement walk, the deny and invalid-statement short-circuits and the trace.
- `Statement::assess()` -- the four-outcome assessment the walk acts on.
- `AuthorizationManager::evaluateFor()` -- the RBAC fallback on `ImplicitDeny` only; `evaluatePolicies()` -- the
  `InvalidPolicy` denial when policies cannot be gathered; `refuseUnidentifiedResource()` -- the recorded
  `ImplicitDeny` for a Gate argument that cannot be identified as a resource.
- `HasPolicies::getPolicies()` -- logs and rethrows on a row that cannot be hydrated.
- `EvaluationResult` factory methods -- one per branch of the four-step order, plus `invalidPolicy()`.
- `DecisionReason` enum -- typed representation of the five possible outcomes, including `INVALID_POLICY`.

## Authoritative Tests

- `PolicyEvaluatorTest::testExplicitDenyOverridesAllow` -- deny after allow still returns deny.
- `PolicyEvaluatorTest::testDenyShortCircuits` -- deny stops the trace at one entry.
- `PolicyEvaluatorTest::testConditionMismatchSkips` -- a statement whose conditions do not match is skipped.
- `PolicyEvaluatorTest::testDenyWithMissingConditionKeyApplies` -- an undecidable deny applies.
- `PolicyEvaluatorTest::testAllowWithMissingConditionKeyIsSkipped` -- an undecidable allow is skipped.
- `PolicyEvaluatorTest::testDenyWithFalseConditionIsSkippedDespiteUndecidableCondition` -- a definite failure wins.
- `PolicyEvaluatorTest::testResourceLessCheckDoesNotMatchResourceScopedAllow` -- resource-less checks need `*`.
- `PolicyEvaluatorTest::testInvalidStatementReturnsInvalidPolicyAndShortCircuits` -- an invalid statement denies.
- `AuthorizationManagerTest::testRbacAllowedWhenPolicyDoesNotMatch` (Unit) -- RBAC fallback produces `RbacAllow`.
- `AuthorizationManagerTest::testExplicitDenyOverridesRbac` (Unit) -- deny policy beats RBAC permission.
- `AuthorizationManagerTest::testExplicitDenyOverridesRoleAllow` (Feature) -- end-to-end deny over role grant.
- `AuthorizationManagerTest::testMalformedStoredPolicyDeniesDespiteHeldPermission` (Feature) -- `invalid_policy` beats
  RBAC.
- `FailClosedPolicyHydrationTest::testMalformedPolicyRowDeniesEveryCheckDespiteRbacAndAllow` -- an unreadable row is
  never skipped.
- `GateRegistrarTest` -- a Gate argument that cannot be identified as a resource is recorded as an implicit deny.

## Change Triggers

- Adding a fifth evaluation step (e.g. a conditional RBAC layer) requires updating this note, the `DecisionReason`
  enum, and the `EvaluationResult` factory set.
- Changing deny semantics (e.g. deny-unless, deny-with-exception) requires a new invariant entry above.
- Introducing RBAC-layer deny (negative permissions) would violate invariant 1 and requires a design decision before
  implementation.
- Letting an undecidable deny, an invalid statement or an unreadable policy be skipped would violate invariants 4 and 6
  and requires a design decision before implementation.
