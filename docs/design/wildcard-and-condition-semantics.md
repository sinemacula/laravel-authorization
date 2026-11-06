# Wildcard and Condition Semantics

Permission checks and policy statement matching both use `fnmatch` for pattern evaluation, and policy statements support
a condition operator catalogue for context-sensitive decisions. This note documents the wildcard matching direction, how
backslashes and substituted values are kept literal, the four outcomes a statement test can have, the condition operator
set, `${…}` interpolation, and the interaction between wildcards and the RBAC fallback.

## Invariants

1. **The held permission is the pattern; the asked permission is the literal.** When `hasPermission('posts:create')` is
   called, the engine iterates every permission the principal holds and calls `fnmatch($held, $asked, FNM_NOESCAPE)`.
   A principal holding `posts:*` satisfies `hasPermission('posts:create')`. The reverse does **not** match: holding
   `posts:create` does not satisfy `hasPermission('posts:*')`. This direction ensures that wildcards are a privilege
   escalation granted to the holder, not a query broadening requested by the caller.

2. **The same direction applies inside policy statements.** A statement's `actions` and `resources` arrays are patterns
   matched against the literal action and resource supplied to `check()`. A statement with `actions: ['posts:*']`
   matches an evaluation for `posts:create`. A statement with `actions: ['posts:create']` does not match an evaluation
   for `posts:*`.

3. **A check without a resource is covered only by `*`.** When `check()` or `can()` is called without a resource, a
   statement matches only when its `resources` include the literal `*` (which is also the default when the key is
   omitted). A statement scoped to particular resources, even one as broad as `posts:*`, never matches a resource-less
   check, so leaving the resource out can never widen a statement written for specific resources.

4. **Backslashes in a pattern are always literal.** Fully-qualified class names regularly appear in action and resource
   strings (e.g. `App\Models\Post:42`), and a backslash consumed as a shell-glob escape would make the match silently
   fail. RBAC permission patterns and statement `actions` are matched with `FNM_NOESCAPE`. Statement `resources` and
   `string_like` operands are matched **without** `FNM_NOESCAPE`, so that substituted values can be escaped (see
   invariant 5); the pattern's own text has every backslash doubled first, which gives the same literal comparison.

5. **A substituted value only ever matches itself.** When a resource pattern or a `string_like` operand contains a
   `${…}` reference, the resolved value is escaped (`\`, `*`, `?`, `[` and `]`) before it is spliced into the pattern.
   A context value of `*` therefore matches only a literal `*`; it never turns `posts:${context.post}` into `posts:*`.
   The pattern's own glob characters keep their meaning.

6. **Every statement test has one of four outcomes, and none of them skips a deny by accident.** A test that cannot be
   decided from the check (a missing context key, an unresolved `${…}` reference, a context value or an interpolated
   operand of the wrong type) is *undecidable*, not false: a deny statement applies, an allow statement does not. A
   malformed test (an unknown operator, a literal operand of the wrong type, a malformed `${…}` reference in a
   condition) is *invalid* whatever the context holds, and denies the whole check with the `invalid_policy` reason.
   This deliberately departs from AWS IAM, where a missing key is a plain non-match that silently disables a
   conditional deny.

7. **Malformed statements are refused when they are written and when they are read.** `Statement::fromArray()` refuses
   unknown keys, an empty resource list, an empty operator map, a non-string operator key, an unknown operator, a
   malformed literal operand and a malformed `${…}` reference in a resource pattern or a condition, so a policy row
   with any of these cannot be saved. The evaluation-time `invalid` outcome is the backstop for statements constructed
   directly; an operand whose value is known only after interpolation is never invalid, only undecidable.

## Wildcard Matching

Both RBAC permission checks and policy statement matching use PHP's `fnmatch` function:

| Pattern    | Matches                          | Does not match         |
|------------|----------------------------------|------------------------|
| `posts:*`  | `posts:create`, `posts:delete`   | `comments:create`      |
| `posts.*`  | `posts.create`, `posts.delete`   | `comments.create`      |
| `*`        | Everything (super-admin path)    | --                     |
| `*:*`      | `posts:create`, `users:delete`   | `posts.edit`, `admin`  |
| `posts:c*` | `posts:create`, `posts:clone`    | `posts:delete`         |
| `*:create` | `posts:create`, `users:create`   | `posts:delete`         |

A `.` in a pattern matches only itself, so `posts.*` does not match `postsXcreate`.

The `*` pattern is the canonical super-admin wildcard -- it satisfies every `hasPermission()` check. `*:*` matches
only names that contain a `:`, so it does not satisfy dotted names such as `posts.edit` or names with no separator such
as `platform-admin`.

### Names

Role and permission names are strings of letters, digits and `_ - : . *`, so `posts:edit`, `posts.edit` and
`sso.connection.trust` are all valid. `*` is the only wildcard a held permission can carry: whitespace and the other
glob metacharacters (`?`, `[`, `]`, `{`, `}`) are refused with an `InvalidAuthorizationNameException` when the name is
saved, so a malformed name cannot match unrelated permissions. `authorization:migrate-spatie` applies the same rule
before it writes a row, and reports and skips any role or permission whose name fails it, along with its grants. It also
reports and skips any permission whose name contains `*`, along with its grants: Spatie compares `*` literally unless its
wildcard permissions are enabled, while here it would become a wildcard that grants other permissions. Role names are
compared literally, so a role name containing `*` is migrated.

### RBAC interaction

Wildcard matching applies at the RBAC fallback step (step 3 of the four-step evaluator). The manager consults RBAC only
when the evaluator returns `ImplicitDeny`; it then checks `$principal->hasPermission($action)`. A principal holding
`posts:*` satisfies an RBAC check for `posts:create`, yielding `RbacAllow`. An explicit deny from a policy statement,
including one applied because its test was undecidable, and an `invalid_policy` denial still win -- wildcard RBAC
grants never override a policy-layer decision.

## Match Outcomes

`Statement::assess()` answers with a `MatchResult`: one `MatchOutcome` and a detail string for the trace. The detail
names what decided the outcome (a missing key, an unknown operator) and never carries a context value.

| Outcome          | Meaning                                    | Deny statement           | Allow statement          |
|------------------|--------------------------------------------|--------------------------|--------------------------|
| `MATCHES`        | Every part of the test holds               | Applies: `ExplicitDeny`  | Applies (recorded)       |
| `DOES_NOT_MATCH` | At least one part definitely does not hold | Skipped                  | Skipped                  |
| `UNDECIDABLE`    | No part fails; one could not be decided    | Applies: `ExplicitDeny`  | Skipped                  |
| `INVALID`        | The statement is malformed                 | Denies: `invalid_policy` | Denies: `invalid_policy` |

A statement whose action or resource definitely does not cover the check is `DOES_NOT_MATCH` without its conditions
being looked at, so only a statement that covers the check (or whose resource test is undecidable) can be `INVALID`.
Otherwise the resource test and every condition, and every operator inside a condition, are combined as a conjunction
in which the strongest outcome wins, in the order **invalid, does not match, undecidable, matches**. One part that
definitely fails decides the conjunction even when another could not be decided: a deny with the conditions
`{"tenant": "org-1", "mfa": {"bool": false}}` is skipped for a check in `org-2`, whether or not the context carries
`mfa`. A condition's shape is checked before its key is looked up, so a malformed condition is invalid even when its
key is missing from the context.

A test is **undecidable** when:

- a condition key is missing from the context (a key present with a `null` value is not missing, although most
  operators find `null` the wrong type);
- a `${…}` reference cannot be resolved in a resource pattern (unless another of the statement's resource patterns
  matches), in a plain-value condition or in an operator operand, or a resource pattern of a directly constructed
  statement holds a malformed reference;
- the context value has the wrong type for the operator (see the catalogue below);
- an interpolated operand resolves to a value of the wrong type for the operator (for example a `${…}` `cidr` operand
  that resolves to something other than an address or range), with the detail
  `condition '<key>': the substituted operand is an invalid operand for operator '<operator>'`;
- a `starts_with`, `ends_with` or `string_like` operand is empty after interpolation.

A test is **invalid** when (reachable only on a directly constructed statement, since `Statement::fromArray()` refuses
each of these):

- the operator is unknown (a debug-level log line is also emitted when a logger is available);
- an operator key is not a string, or a condition's operator map is empty;
- a condition key is not a string;
- a literal operand has the wrong type for the operator, including an empty string for `starts_with`, `ends_with` or
  `string_like` and `NAN` or an infinity for `gt`, `gte`, `lt` or `lte`;
- a plain-value condition or a string operand holds a malformed `${…}` reference.

The detail of an invalid condition names the condition and the fault, in the same words `Statement::fromArray()` uses
to refuse it: for example `condition 'tenant' has an unknown operator 'unknown_op'`.

## Condition Operators

Policy statement conditions are expressed as a map of context keys to operator payloads. When a statement's
action/resource patterns match, the evaluator assesses every condition before committing the effect. Every condition
entry, and every operator within an entry, must match for an allow statement to apply. A literal operand that is not
of the listed type makes the statement invalid; a context value, or an operand produced by interpolation, that is not of
the listed type makes the test undecidable.

| Operator      | Operand                  | Context value | Semantics                                             |
|---------------|--------------------------|---------------|-------------------------------------------------------|
| `eq`          | any                      | any           | Strict equality (`===`)                               |
| `neq`         | any                      | any           | Strict inequality (`!==`)                             |
| `in`          | `array`                  | any           | Context value is in the operand array (strict)        |
| `not_in`      | `array`                  | any           | Context value is not in the operand array (strict)    |
| `null`        | ignored                  | any           | Context value is `null`                               |
| `not_null`    | ignored                  | any           | Context value is not `null`                           |
| `cidr`        | address or range         | IP address    | IPv4 or IPv6 address falls within the range           |
| `starts_with` | non-empty `string`       | `string`      | Context value starts with the operand                 |
| `ends_with`   | non-empty `string`       | `string`      | Context value ends with the operand                   |
| `string_like` | non-empty glob           | `string`      | Context value matches the glob pattern                |
| `before`      | time-like                | time-like     | Context time is strictly before the operand           |
| `after`       | time-like                | time-like     | Context time is strictly after the operand            |
| `between`     | `[time-like, time-like]` | time-like     | Context time falls within the inclusive range         |
| `gt`          | numeric                  | numeric       | Context value is greater than the operand             |
| `gte`         | numeric                  | numeric       | Context value is greater than or equal to the operand |
| `lt`          | numeric                  | numeric       | Context value is less than the operand                |
| `lte`         | numeric                  | numeric       | Context value is less than or equal to the operand    |
| `bool`        | boolean form             | boolean form  | Context value has the operand's boolean meaning       |

- **Time-like** values are a `DateTimeInterface`, an integer UNIX timestamp, a finite float (truncated) or a non-empty
  string that `strtotime()` can parse.
- **Numeric** values are integers, floats and numeric strings, compared as floats. `NAN`, `INF` and `-INF` (and a
  numeric string that overflows to an infinity) are not numbers: as an operand they are invalid, as a context value
  undecidable (`operator 'gt' needs a number`).
- **Non-empty `string`** operands are refused when empty as written; an operand that becomes empty only after
  interpolation is undecidable.
- **Boolean forms** are `true`, `false`, `1`, `0`, `'1'`, `'0'`, `'true'` and `'false'`, on both sides.
- **`cidr`** accepts IPv4 and IPv6. An operand without `/` is an exact address match; the prefix length must be digits
  no greater than 32 for IPv4 or 128 for IPv6. An address of the other family does not match (it is decided, not
  undecidable), so `::ffff:10.0.0.1` is not within `10.0.0.0/8`.
- **`string_like`** follows invariants 4 and 5: the operand's own backslashes are literal and substituted values are
  escaped.

### Shorthand form

When the operand is a scalar (not an array with operator keys), the condition uses implicit strict equality --
`{"tenant": "org-1"}` is equivalent to `{"tenant": {"eq": "org-1"}}`. A string value is interpolated first, and an
unresolved reference makes the test undecidable. An array value is always read as an operator map; use `in` to compare
against a list.

### Interpolation

Resource patterns, plain-value conditions and string operands may reference the check through `${namespace.key}`:

| Token                | Resolves to                                                                    |
|----------------------|--------------------------------------------------------------------------------|
| `${principal.id}`    | `getKey()` for an Eloquent model, the public `id` property for other objects   |
| `${principal.type}`  | `getMorphClass()` when the object has it, otherwise its class name             |
| `${principal.<key>}` | A model attribute or a public property; never a hidden attribute or a relation |
| `${context.<path>}`  | A dot-notation path into the context array                                     |
| `${resource.type}`   | The resource before its first `:`, or the whole resource when it has none      |
| `${resource.id}`     | The resource after its first `:`; unresolved when it has none                  |

A token is `${`, a body matching `[a-zA-Z_][a-zA-Z0-9_.]*`, and `}`. The namespace is the body up to its first `.`
and the key everything after it, so `${context.request.ip}` reads the context path `request.ip`. A well-formed token
whose namespace is not `principal`, `context` or `resource`, or which has no key (`${context}`, `${context.}`), is
accepted when written and unresolved when evaluated. Any other `${` that is not the `\${` escape --
`${context.tenant-id}`, `${}`, `${1x}`, an unclosed `${foo` -- is a **malformed reference**: `Statement::fromArray()`
refuses it in a resource pattern, a plain-value condition or a string operand, and on a directly constructed statement
it makes a resource pattern unresolved (undecidable) and a condition invalid.

A model's **hidden attributes** are never read: an attribute listed in `$hidden`, or left out of a non-empty
`$visible`, is unresolved, as is any relation. `${principal.id}` is the model's key whatever `$hidden` says. A
principal that is not an Eloquent model is read only through its public properties.

A token that does not resolve to a scalar (an unknown namespace or key, a missing path, an array value, a check without
a principal or resource) makes the **whole string** unresolved: the test is undecidable, never compared against an empty
substitution. Every substituted value is a string: numbers are cast (`42` becomes `'42'`) and booleans become `'true'`
or `'false'`. An interpolated plain value, like an interpolated `eq` or `neq` operand, is therefore compared strictly
against a string, so `{"owner": "${principal.id}"}` matches a context `owner` of `'42'` but not the integer `42`: pass
such context values as strings. The numeric, time and `bool` operators read a substituted string as they read any other
(`'true'` and `'false'` are boolean forms). Write `\${` for a literal `${`; the escape is undone only in the string's
own text, never inside a substituted value. An operand holding only the escape contains no reference, so it is checked
as written: a `gt` operand of `\${x}` is refused.

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
`source_ip` falls within the `10.0.0.0/8` range. If either condition fails, or the context lacks either key or carries
a `source_ip` that is not an address, the statement is skipped. Written with `"effect": "deny"`, the same statement
would apply when a key is missing or the address cannot be read, and be skipped only when a condition definitely fails.

## Failure / Edge Cases

- **Empty actions list:** rejected at hydration time with an `InvalidArgumentException`.
- **Empty resources list:** rejected at hydration time; omit the `resources` key to cover every resource (`['*']`).
- **Unknown statement key** (e.g. a mistyped `condition`): rejected at hydration time, so a typo can never turn a
  conditional statement into an unconditional one.
- **Empty operator map, non-string operator key, unknown operator, malformed literal operand, malformed `${…}`
  reference:** rejected at hydration time. A malformed literal operand includes an empty string for `starts_with`,
  `ends_with` or `string_like` and `NAN` or an infinity for `gt`, `gte`, `lt` or `lte`. A string operand containing a
  well-formed `${…}` reference is not type-checked, since its value is known only at evaluation time; if it resolves
  to a value of the wrong type, or to an empty string, the test is undecidable. Only string operands are interpolated,
  so the members of an `in` list and the bounds of `between` are literal.
- **Same faults on a directly constructed statement:** the statement is invalid and the check denies with
  `invalid_policy`, whatever the context holds and even when the condition's key is missing. A malformed reference in
  a resource pattern makes the resource test undecidable instead, like an unresolved one.
- **CIDR with no slash:** treated as an exact address match. A prefix length above 32 (IPv4) or 128 (IPv6), or a
  malformed address, is invalid.
- **Resource-less check:** matches only statements whose resources include `*`.

## Implementation Anchors

- `HasPermissions::hasPermission()` -- the RBAC wildcard match loop with `fnmatch($held, $asked, FNM_NOESCAPE)`.
- `Statement::assess()` -- the action, resource and condition walk producing a `MatchResult`; `Statement::matches()`
  and `Statement::conditionsSatisfiedBy()` are its boolean views, true only on `MATCHES`.
- `StatementValidator` and `ConditionEvaluator::operandError()` -- the hydration-time refusals;
  `StatementValidator::conditionError()` is the single description of a malformed condition, used both to refuse it
  on hydration and to make it invalid on assessment, and `assertValidResource()` refuses a malformed resource pattern.
- `ConditionEvaluator::evaluate()` -- the operator dispatch, `OPERATORS` the catalogue and `PATTERN_OPERATORS` the
  operators whose operand is a glob.
- `ContextInterpolator::containsReference()` and `hasMalformedReference()` -- the token grammar as the validator sees
  it.
- `MatchOutcome::precedence()` and `MatchResult::and()` -- the conjunction order.
- `ContextInterpolator::interpolate()`, `interpolatePattern()` and `literalPattern()` -- token resolution and the
  escaping of pattern text and substituted values.

## Authoritative Tests

- `WildcardPermissionTest::testHeldWildcardSatisfiesNarrowerAsk` -- `posts:*` satisfies `posts:create`.
- `WildcardPermissionTest::testHeldConcreteDoesNotSatisfyWildcardAsk` -- `posts:create` does not satisfy `posts:*`.
- `WildcardPermissionTest::testSuperAdminWildcardSatisfiesEverything` -- `*` satisfies any action.
- `WildcardPermissionTest::testColonWildcardSatisfiesOnlyColonNames` -- `*:*` satisfies only names containing `:`.
- `WildcardPermissionTest::testStatementMatchesBackslashBearingResourceLiterally` -- backslashes in a resource pattern
  compare literally.
- `WildcardPermissionTest::testIdentityInheritsRoleWildcard` -- role-inherited wildcard satisfies narrower ask.
- `PolicyEvaluatorTest::testConditionMismatchSkips` -- condition mismatch skips the statement.
- `MatchOutcomeTest`, `MatchResultTest` -- the four outcomes and their conjunction order.
- `StatementValidatorTest` -- the hydration-time refusals.
- `StatementTest`, `ConditionEvaluatorTest`, `ContextInterpolatorTest` -- resource-less matching, the per-operator
  outcomes, and interpolation and escaping.

## Change Triggers

- Adding a new condition operator requires a new entry in `ConditionEvaluator::OPERATORS`, its dispatch in
  `ConditionEvaluator::evaluate()` (an entry in `EQUALITY_OPERATORS`, `STRING_OPERATORS` or `NUMERIC_OPERATORS`, or a
  new arm), its operand rule in `ConditionEvaluator::isValidOperand()`, an entry in `PATTERN_OPERATORS` when its
  operand is a glob or in `LITERAL_OPERAND_OPERATORS` when its operand is never interpolated, and a new row in the
  operator catalogue above, including which operands are invalid and which context values are undecidable.
- Changing the matching direction (e.g. allowing the caller to supply wildcards) would violate invariant 1 and requires
  a design decision before implementation.
- Letting an undecidable test skip a deny, or letting a resource-less check match a scoped statement, would violate
  invariants 3 and 6 and requires a design decision before implementation.
- Switching from `fnmatch` to a regex-based matcher would change the pattern syntax and require a migration guide.
