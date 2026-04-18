# Wildcard and Condition Semantics

Permission checks and policy statement matching both use `fnmatch` for pattern evaluation, and policy statements support
a condition operator catalogue for context-sensitive decisions. This note documents the wildcard matching direction, the
`FNM_NOESCAPE` flag choice, the condition operator set, and the interaction between wildcards and the RBAC fallback.

## Invariants

1. **The held permission is the pattern; the asked permission is the literal.** When `hasPermission('posts:create')` is
   called, the engine iterates every permission the principal holds and calls `fnmatch($held, $asked, FNM_NOESCAPE)`.
   A principal holding `posts:*` satisfies `hasPermission('posts:create')`. The reverse does **not** match: holding
   `posts:create` does not satisfy `hasPermission('posts:*')`. This direction ensures that wildcards are a privilege
   escalation granted to the holder, not a query broadening requested by the caller.

2. **The same direction applies inside policy statements.** A statement's `actions` and `resources` arrays are patterns
   matched against the literal action and resource supplied to `evaluate()`. A statement with `actions: ['posts:*']`
   matches an evaluation for `posts:create`. A statement with `actions: ['posts:create']` does not match an evaluation
   for `posts:*`.

3. **`FNM_NOESCAPE` is always set.** The flag causes backslashes to be compared literally instead of being interpreted
   as shell-glob escape sequences. This is critical because fully-qualified class names regularly appear in action and
   resource strings (e.g. `App\Models\Post:42`). Without the flag, the backslashes would be consumed as escape
   characters and the match would silently fail.

4. **Missing context keys cause a condition to fail, not throw.** When a condition references a key that does not exist
   in the `$context` array, the condition evaluates to `false`. The statement is traced as `skipped` with the reason
   `'conditions not satisfied'`. This matches AWS IAM behaviour -- a missing key is a non-match, not an error.

5. **Unknown operators evaluate to false.** When a condition uses an operator not in the catalogue, it evaluates to
   `false` and a debug-level log line is emitted (when a logger is available). The evaluation does not throw -- the
   engine stays fail-closed rather than fail-loud.

## Wildcard Matching

Both RBAC permission checks and policy statement matching use PHP's `fnmatch` function. The matching supports the full
glob pattern syntax:

| Pattern    | Matches                          | Does not match         |
|------------|----------------------------------|------------------------|
| `posts:*`  | `posts:create`, `posts:delete`   | `comments:create`      |
| `*:*`      | Everything (super-admin path)    | --                     |
| `posts:c*` | `posts:create`, `posts:clone`    | `posts:delete`         |
| `*:create` | `posts:create`, `users:create`   | `posts:delete`         |

The `*:*` pattern is the canonical super-admin wildcard -- it satisfies every `hasPermission()` check.

### RBAC interaction

Wildcard matching applies at the RBAC fallback step (step 3 of the four-step evaluator). When no policy matches, the
manager checks `$principal->hasPermission($action)`. A principal holding `posts:*` satisfies an RBAC check for
`posts:create`, yielding `RbacAllow`. An explicit deny from a policy statement still wins -- wildcard RBAC grants do
not override policy-layer denials.

## Condition Operators

Policy statement conditions are expressed as a map of context keys to operator payloads. When a statement's
action/resource patterns match, the evaluator calls `evaluateConditions($context)` before committing the effect. Every
condition entry must pass for the statement to apply.

| Operator      | Operand type             | Semantics                                         |
|---------------|--------------------------|---------------------------------------------------|
| `eq`          | scalar                   | Strict equality (`===`)                           |
| `neq`         | scalar                   | Strict inequality (`!==`)                         |
| `in`          | `array`                  | Context value is in the operand array (strict)    |
| `not_in`      | `array`                  | Context value is not in the operand array (strict)|
| `cidr`        | `string` (CIDR)          | IPv4 address falls within the CIDR range          |
| `starts_with` | `string`                 | Context value starts with the operand             |
| `ends_with`   | `string`                 | Context value ends with the operand               |
| `before`      | time-like                | Context timestamp is before the operand           |
| `after`       | time-like                | Context timestamp is after the operand            |
| `between`     | `[time-like, time-like]` | Context timestamp falls within the inclusive range|

Time-like values are coerced via `strtotime()` (strings) or used directly (integer UNIX timestamps). Non-parseable
values cause the condition to fail silently.

### Shorthand form

When the operand is a scalar (not an array with operator keys), the condition uses implicit strict equality --
`{"tenant": "org-1"}` is equivalent to `{"tenant": {"eq": "org-1"}}`.

### Example: tenant-scoped allow with IP restriction

```json
{
  "effect": "allow",
  "actions": ["billing:*"],
  "resources": ["*"],
  "conditions": {
    "tenant": { "eq": "org-42" },
    "source_ip": { "cidr": "10.0.0.0/8" }
  }
}
```

This statement allows any `billing:*` action, but only when the context carries `tenant = 'org-42'` and the
`source_ip` falls within the `10.0.0.0/8` range. If either condition fails, the statement is skipped.

## Failure / Edge Cases

- **Empty actions list:** rejected at hydration time with an `InvalidArgumentException`.
- **Empty resources list:** normalised to `['*']` (match all resources).
- **Non-string operator key:** evaluates to false without throwing.
- **CIDR with no slash:** treated as an exact IP match. Invalid prefix length (>32) returns false.

## Implementation Anchors

- `HasPermissions::hasPermission()` -- the RBAC wildcard match loop with `fnmatch($held, $asked, FNM_NOESCAPE)`.
- `Statement::matchesAction()`, `Statement::matchesResource()` -- policy-level `fnmatch` matching.
- `Statement::evaluateConditions()` -- the condition walk.
- `Statement::evaluateOperator()` -- the operator dispatch table.
- `ConditionEvaluator` -- the internal helper for CIDR, time comparisons, and unknown-operator logging.

## Authoritative Tests

- `WildcardPermissionTest::testHeldWildcardSatisfiesNarrowerAsk` -- `posts:*` satisfies `posts:create`.
- `WildcardPermissionTest::testHeldConcreteDoesNotSatisfyWildcardAsk` -- `posts:create` does not satisfy `posts:*`.
- `WildcardPermissionTest::testSuperAdminWildcardSatisfiesEverything` -- `*:*` satisfies any action.
- `WildcardPermissionTest::testStatementMatchesBackslashBearingResourceLiterally` -- `FNM_NOESCAPE` preserves
  backslashes.
- `WildcardPermissionTest::testIdentityInheritsRoleWildcard` -- role-inherited wildcard satisfies narrower ask.
- `PolicyEvaluatorTest::testConditionMismatchSkips` -- condition mismatch skips the statement.

## Change Triggers

- Adding a new condition operator requires a new `match` arm in `Statement::evaluateOperator()` and a new row in the
  operator catalogue above.
- Changing the matching direction (e.g. allowing the caller to supply wildcards) would violate invariant 1 and requires
  a design decision before implementation.
- Switching from `fnmatch` to a regex-based matcher would change the pattern syntax and require a migration guide.
