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

2. **The same direction applies inside policy statements.** A statement's `actions` and `resources` patterns are matched
   against the literal action and resource supplied to `check()`. A statement with `actions: ['posts:*']` matches an
   evaluation for `posts:create`. A statement with `actions: ['posts:create']` does not match an evaluation for
   `posts:*`. `not_actions` and `not_resources` invert the list: the statement names every action, or every resource,
   that none of their patterns matches, so `not_actions: ['posts:read']` names `posts:delete` and not `posts:read`.

3. **A check without a resource is covered only by a statement that is not resource-scoped.** When `check()` or `can()`
   is called without a resource, a statement matches only when it has neither `resources` nor `not_resources`, or its
   `resources` include the literal `*`. A statement scoped to particular resources, even one as broad as `posts:*`,
   never matches a resource-less check, and neither does one with `not_resources`, which counts as resource scoping: a
   deny of every resource but `post:1` does not cover a check that names no resource. Leaving the resource out can never
   widen a statement written for specific resources.

4. **Backslashes in a pattern are always literal.** Fully-qualified class names regularly appear in action and resource
   strings (e.g. `App\Models\Post:42`), and a backslash consumed as a shell-glob escape would make the match silently
   fail. RBAC permission patterns and statement `actions` and `not_actions` are matched with `FNM_NOESCAPE`. Statement
   `resources`, `not_resources` and `like` operands are matched **without** `FNM_NOESCAPE`, so that substituted values
   can be escaped (see invariant 5); the pattern's own text has every backslash doubled first, which gives the same
   literal comparison.

5. **A substituted value only ever matches itself.** When a resource pattern or a `like` operand contains a `${…}`
   reference, the resolved value is escaped (`\`, `*`, `?`, `[` and `]`) before it is spliced into the pattern. A
   context value of `*` therefore matches only a literal `*`; it never turns `posts:${context.post}` into `posts:*`. The
   pattern's own glob characters keep their meaning.

6. **Every statement test has one of four outcomes, and none of them skips a deny by accident.** A test that cannot be
   decided from the check (a missing context key, an unresolved `${…}` reference, a context value or an interpolated
   operand of the wrong type) is *undecidable*, not false: a deny statement applies, an allow statement does not. Two
   tests decide a missing key instead: one whose operator carries the `_if_exists` suffix passes, and `null` holds or
   fails by its operand. A malformed test (an unknown operator, conditions that do not map operators to key tests, a
   literal operand of the wrong type, a malformed `${…}` reference in a condition) is *invalid* whatever the context
   holds, and denies the whole check with the `invalid_policy` reason. This deliberately departs from AWS IAM, where a
   missing key is a plain non-match that silently disables a conditional deny.

7. **Malformed documents are refused when they are written and when they are read.** `Statement::fromArray()` refuses
   unknown keys, a malformed `sid`, both `actions` and `not_actions` (or neither), both `resources` and `not_resources`,
   a pattern list that is empty or holds anything but non-empty strings, conditions that are not a map of operators to
   key tests, an unknown operator, a malformed literal operand and a malformed `${…}` reference in a resource pattern or
   a condition. `Policy::fromArray()` refuses statements that share a `sid`. On write, `PolicyValidator` adds the
   limits, the condition key syntax and the action catalogue (see [Writing a policy](#writing-a-policy)), so a policy
   row with any of these faults cannot be saved; on read, a stored document over a limit, or one that no longer parses,
   denies as `invalid_policy`. The evaluation-time `invalid` outcome is the backstop for statements constructed
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

Wildcard matching applies at the permission step of the allow stage. The manager consults RBAC only when the policies
leave the check at the implicit stage (`no_match` or `condition_failed`: no deny and no allow statement decided it); it
then checks whether the subject holds the action as a permission. A subject holding `posts:*` satisfies the check for
`posts:create`, and the decision allows at the allow stage with a `held` permission step. An explicit deny from a policy
statement, including one applied because its test was undecidable, and an `invalid_policy` denial still win --
wildcard grants never override a policy-layer decision.

## Statements

A statement is a map of these keys, and any other key is refused:

| Key             | Holds                                                                                      |
|-----------------|--------------------------------------------------------------------------------------------|
| `sid`           | Optional: 1 to 64 letters, digits, `_`, `-`, `:` or `.`, unique within its policy          |
| `effect`        | `allow` or `deny`                                                                          |
| `actions`       | The action patterns the statement names                                                    |
| `not_actions`   | Action patterns the statement does not name; it names every action none of them matches    |
| `resources`     | The resource patterns the statement names                                                  |
| `not_resources` | Resource patterns the statement does not name; it names every resource none of them match  |
| `conditions`    | Optional: a map of operator to key tests (see [Condition Operators](#condition-operators)) |

A statement takes exactly one of `actions` and `not_actions`, and at most one of `resources` and `not_resources`; with
neither, it names every resource and a check that names none (AUTHZ-6.6). Each list, when present, is a non-empty list
of non-empty strings. The `sid` names the statement in the decision: its `StatementReference` carries it, and
`toString()` appends it JSON-encoded, as `name[key]#index sid="deny-deletes"`. It never changes how the statement is
evaluated or in what order. `Statement::toArray()` returns exactly the keys the statement was given, so a statement
without `resources` stays without them.

A resource that names a type alone (`post:*`, N6) is covered only by a pattern that covers every record of the type
(`*`, `post:*`), never by one that needs an id character (`post:?`). The same rule decides `not_resources`: a type alone
is excluded when one of its patterns covers it that way, so `not_resources: ["post:?"]` names `post:*`. A
`not_resources` pattern whose `${…}` reference cannot be resolved makes the resource test undecidable unless another of
its patterns covers the resource, exactly as for `resources`.

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
Otherwise the resource test and every key test of every operator are combined as a conjunction in which the strongest
outcome wins, in the order **invalid, does not match, undecidable, matches**. One part that definitely fails decides the
conjunction even when another could not be decided: a deny with the conditions
`{"eq": {"tenant": "org-1"}, "bool": {"mfa": false}}` is skipped for a check in `org-2`, whether or not the context
carries `mfa`. A test's shape is checked before its key is looked up, so a malformed test is invalid even when its key
is missing from the context.

A test is **undecidable** when:

- its key is missing from the context, unless its operator carries `_if_exists` or is `null` (a key present with a
  `null` value is not missing, although most operators find `null` the wrong type);
- a `${…}` reference cannot be resolved in a resource pattern (unless another of the statement's patterns covers the
  resource) or in an operand, or a resource pattern of a directly constructed statement holds a malformed reference;
- the context value has the wrong type for the operator (see the catalogue below), including a value that is not a valid
  IP address for `ip_in` or `ip_not_in` and one that is not a list of scalars for `any_value_in` or `all_values_in`;
- an interpolated operand resolves to a value of the wrong type for the operator (for example a `${…}` `ip_in` operand
  that resolves to something other than an address or range), with the detail
  `condition '<key>': the substituted operand is an invalid operand for operator '<operator>'`;
- a `starts_with`, `ends_with` or `like` operand is empty after interpolation.

A test is **invalid** when (reachable only on a directly constructed statement, since `Statement::fromArray()` refuses
each of these):

- an operator is unknown, including the key-first shape (`{"tenant": {"eq": "org-1"}}`), whose first level names a key
  rather than an operator, and the bare value (`{"tenant": "org-1"}`);
- the conditions are a list, or an operator does not map one or more context keys to operands;
- a literal operand has the wrong type for the operator, including a list for `eq` or `neq`, an empty string for
  `starts_with`, `ends_with` or `like`, `NAN` or an infinity for `gt`, `gte`, `lt` or `lte`, anything but `true` or
  `false` for `null`, and a set holding `null` or an array;
- a string operand holds a malformed `${…}` reference.

The detail of an invalid test names it and the fault, in the same words `Statement::fromArray()` uses to refuse it: for
example `conditions have an unknown operator 'unknown_op'` or
`condition 'tenant' has an invalid operand for operator 'eq'`. A fault of the operator entry as a whole has no key to
name, so it adds no key to the trace; a fault in one key's operand records that key as not held.

## Condition Operators

Conditions are a map of operator to key tests, and each key test maps a context key to an operand:

```json
{
  "ip_not_in": { "request.ip": ["10.0.0.0/8", "192.168.0.0/16"] },
  "eq": { "tenant": "${principal.tenant}" },
  "gte": { "mfa.level": 2 }
}
```

When a statement's action and resource patterns match, the evaluator assesses every key test before committing the
effect, and every one must hold for an allow to apply. One key may be tested by several operators
(`{"gte": {"age": 18}, "lt": {"age": 65}}`); the trace records each key once, held only when all of its tests held. A
literal operand that is not of the listed type makes the statement invalid; a context value, or an operand produced by
interpolation, that is not of the listed type makes the test undecidable.

| Operator        | Operand                     | Context value   | Holds when                                             |
|-----------------|-----------------------------|-----------------|--------------------------------------------------------|
| `eq`            | scalar                      | any             | The value is strictly equal to the operand (`===`)     |
| `neq`           | scalar                      | any             | The value is not strictly equal to the operand         |
| `in`            | non-empty list of scalars   | any             | The value is in the list (strict)                      |
| `not_in`        | non-empty list of scalars   | any             | The value is not in the list (strict)                  |
| `starts_with`   | non-empty `string`          | `string`        | The value starts with the operand                      |
| `ends_with`     | non-empty `string`          | `string`        | The value ends with the operand                        |
| `like`          | non-empty glob              | `string`        | The value matches the glob pattern                     |
| `gt`            | numeric                     | numeric         | The value is greater than the operand                  |
| `gte`           | numeric                     | numeric         | The value is greater than or equal to the operand      |
| `lt`            | numeric                     | numeric         | The value is less than the operand                     |
| `lte`           | numeric                     | numeric         | The value is less than or equal to the operand         |
| `before`        | time-like                   | time-like       | The value is strictly before the operand               |
| `after`         | time-like                   | time-like       | The value is strictly after the operand                |
| `between`       | `[time-like, time-like]`    | time-like       | The value falls within the inclusive range             |
| `bool`          | boolean form                | boolean form    | The value has the operand's boolean meaning            |
| `null`          | `true` or `false`           | any, or missing | `true`: missing or null; `false`: present and not null |
| `ip_in`         | address or range, or a list | IP address      | The address is within any of the ranges                |
| `ip_not_in`     | address or range, or a list | IP address      | The address is valid and within none of the ranges     |
| `any_value_in`  | non-empty list of scalars   | list of scalars | Some element of the value is in the operand            |
| `all_values_in` | non-empty list of scalars   | list of scalars | The value is not empty and every element is in it      |

- **Scalars** are strings, integers, floats and booleans. A set (the operand of `in`, `not_in`, `any_value_in` and
  `all_values_in`) holds only scalars, never `null` or an array, and its members are compared strictly, so `"1"` is not
  `1`. `eq` and `neq` compare one scalar and never a list: use `in` to compare against several values.
- **Time-like** values are a `DateTimeInterface`, an integer UNIX timestamp, a finite float (truncated) or a non-empty
  string that `strtotime()` can parse.
- **Numeric** values are integers, floats and numeric strings, compared as floats. `NAN`, `INF` and `-INF` (and a
  numeric string that overflows to an infinity) are not numbers: as an operand they are invalid, as a context value
  undecidable (`operator 'gt' needs a number`).
- **Non-empty `string`** operands are refused when empty as written; an operand that becomes empty only after
  interpolation is undecidable.
- **Boolean forms** are `true`, `false`, `1`, `0`, `'1'`, `'0'`, `'true'` and `'false'`, on both sides.
- **`null`** takes strictly `true` or `false` (N20), and decides a missing key rather than finding it undecidable:
  `{"null": {"deleted_at": true}}` holds when the context lacks `deleted_at` or carries it as `null`, and
  `{"null": {"email": false}}` holds only when `email` is present and not `null`.
- **`ip_in` and `ip_not_in`** take one IPv4 or IPv6 address or CIDR range, or a non-empty list of them read as one set
  of ranges. An operand without `/` is an exact address match; the prefix length must be digits no greater than 32 for
  IPv4 or 128 for IPv6. An address of the other family is within none of a range's addresses (it is decided, not
  undecidable), so `::ffff:10.0.0.1` is not within `10.0.0.0/8`. A context value that is not a valid address is
  undecidable for both, so `ip_not_in` never reads an unreadable address as outside every range, and a deny written with
  it still applies.
- **`any_value_in` and `all_values_in`** test a multi-valued key, such as a token's scopes or a principal's groups. The
  context value must be a list of scalars; anything else is undecidable. An empty list never holds for `all_values_in`
  (N22), so a principal with no scopes does not pass a test that every scope is allowed.
- **`like`** follows invariants 4 and 5: the operand's own backslashes are literal and substituted values are escaped.

### `_if_exists`

Any operator but `null` may be written with the `_if_exists` suffix (`ip_in_if_exists`, `eq_if_exists`), and only one
case changes: a key the context lacks passes that test. A key present with a `null` value, a malformed operand, a
context value of the wrong type and an unresolved interpolation are decided exactly as without the suffix. A deny whose
test passes only because of `_if_exists` still applies, since the test holds like any other. `null_if_exists` is an
unknown operator, as `null` already decides a missing key.

```json
{ "ip_in_if_exists": { "request.ip": "10.0.0.0/8" } }
```

holds for a check from `10.1.2.3` and for a queued job whose context carries no `request.ip`, does not hold for a check
from `203.0.113.7`, and is undecidable for a `request.ip` of `unknown`.

### Interpolation

Resource patterns and string operands may reference the check through `${namespace.key}`:

| Token                | Resolves to                                                                    |
|----------------------|--------------------------------------------------------------------------------|
| `${principal.id}`    | `getKey()` for an Eloquent model, the public `id` property for other objects   |
| `${principal.type}`  | `getMorphClass()` when the object has it, otherwise its class name             |
| `${principal.<key>}` | A model attribute or a public property; never a hidden attribute or a relation |
| `${context.<path>}`  | A dot-notation path into the context array                                     |
| `${resource.type}`   | The resource before its first `:`, or the whole resource when it has none      |
| `${resource.id}`     | The resource after its first `:`; unresolved when it has none                  |

A token is `${`, a body matching `[a-zA-Z_][a-zA-Z0-9_.]*`, and `}`. The namespace is the body up to its first `.` and
the key everything after it, so `${context.request.ip}` reads the context path `request.ip`. A well-formed token whose
namespace is not `principal`, `context` or `resource`, or which has no key (`${context}`, `${context.}`), is accepted
when written and unresolved when evaluated. Any other `${` that is not the `\${` escape -- `${context.tenant-id}`,
`${}`, `${1x}`, an unclosed `${foo` -- is a **malformed reference**: `Statement::fromArray()` refuses it in a resource
pattern or a string operand, and on a directly constructed statement it makes a resource pattern unresolved
(undecidable) and a condition invalid.

A model's **hidden attributes** are never read: an attribute listed in `$hidden`, or left out of a non-empty
`$visible`, is unresolved, as is any relation. `${principal.id}` is the model's key whatever `$hidden` says. A
principal that is not an Eloquent model is read only through its public properties.

A token that does not resolve to a scalar (an unknown namespace or key, a missing path, an array value, a check without
a principal or resource) makes the **whole string** unresolved: the test is undecidable, never compared against an empty
substitution. Every substituted value is a string: numbers are cast (`42` becomes `'42'`) and booleans become `'true'`
or `'false'`. An interpolated `eq` or `neq` operand is therefore compared strictly against a string, so
`{"eq": {"owner": "${principal.id}"}}` matches a context `owner` of `'42'` but not the integer `42`: pass such context
values as strings. The numeric, time and `bool` operators read a substituted string as they read any other (`'true'` and
`'false'` are boolean forms). Write `\${` for a literal `${`; the escape is undone only in the string's own text, never
inside a substituted value. An operand holding only the escape contains no reference, so it is checked as written: a
`gt` operand of `\${x}` is refused.

Only a string operand is interpolated. The operands of `in`, `not_in`, `between`, `null`, `any_value_in` and
`all_values_in` are never interpolated, and neither are the members of an `ip_in` or `ip_not_in` list, so each of them
is checked as written.

### Example: tenant-scoped allow from the office network

```json
{
  "sid": "billing-from-office",
  "effect": "allow",
  "actions": ["billing:*"],
  "conditions": {
    "eq": { "tenant": "org-42" },
    "ip_in": { "source_ip": ["10.0.0.0/8", "2001:db8::/32"] }
  }
}
```

This statement allows any `billing:*` action, on any resource or none, but only when the context carries
`tenant = 'org-42'` and a `source_ip` within one of the two ranges. If either test fails, or the context lacks either
key or carries a `source_ip` that is not an address, the statement is skipped. Written with `"effect": "deny"`, the same
statement would apply when a key is missing or the address cannot be read, and be skipped only when a test definitely
fails.

## Writing a Policy

`PolicyValidator::errors()` gives every reason a document cannot be written, and the `Policy` model's `document` setter,
and so every write of `PolicyService`, refuses a document with any of them through `assertValid()`, which joins the
reasons into one `InvalidPolicyDocumentException` message, separated by semicolons. The reasons are:

- **Structure**: whatever `Policy::fromArray()` refuses, including statements sharing a `sid`.
- **Limits** (AUTHZ-6.10), from `authorization.policies.limits`: `document_bytes` (65536) on the document's JSON
  encoding, `statements` (100), `conditions` (50) on the key tests of one statement, each key of each operator counting
  as one, and `pattern_length` (512) on the characters of any action or resource pattern and any string operand, strings
  inside list operands included. The same limits are checked when a stored document is read
  (`PolicyDocument::hydrate()`), so a stored document over a limit denies as `invalid_policy` and is never skipped or
  partly evaluated. Lowering a limit therefore makes every stored document over it deny until it is fixed.
- **Condition keys**: a letter or `_`, then letters, digits and `_`, then any number of `.`-separated segments of
  letters, digits, `_` and `-`, at most 128 characters (`request.ip`, `mfa.level`, `token.scopes`).
- **Actions** (N19): every `actions` and `not_actions` pattern must match at least one permission the code declares in
  `permission_enums` or `permission_providers`, compared with `fnmatch($pattern, $name, FNM_NOESCAPE)` or as the same
  string, so a misspelt action cannot be stored. The bound `ActionCatalogue` answers; the default,
  `DeclaredActionCatalogue`, reads the declared names once per request or job. With nothing declared, every document is
  refused with one reason that says so.

`php artisan authorization:policy:validate` checks documents with the same validator: JSON files given as paths (one
document, or an array of documents, per file; a directory's `*.json` files), or every stored policy row of every tenant
with `--database`, the default when no path is given. Stored rows are read as stored, not through hydration, so the
command finds the rows a lowered limit has made invalid. It prints one line for each invalid document, then a summary,
and exits 1 when any is invalid.

## Failure / Edge Cases

- **Missing, empty or non-string actions:** rejected at hydration time with an `InvalidArgumentException`, as is a
  statement with both `actions` and `not_actions`.
- **Empty resources list:** rejected at hydration time; omit `resources` to cover every resource and a resource-less
  check. A statement with both `resources` and `not_resources` is rejected too.
- **Unknown statement key** (e.g. a mistyped `condition`): rejected at hydration time, so a typo can never turn a
  conditional statement into an unconditional one.
- **Key-first or bare-value conditions, a list of conditions, an operator with no key tests, an unknown operator
  (including `cidr`, `string_like`, `not_null` and `null_if_exists`), a malformed literal operand, a malformed `${…}`
  reference:** rejected at hydration time. There is no reader for an earlier shape. A string operand containing a
  well-formed `${…}` reference is not type-checked, since its value is known only at evaluation time; if it resolves to
  a value of the wrong type, or to an empty string, the test is undecidable.
- **Same faults on a directly constructed statement:** the statement is invalid and the check denies with
  `invalid_policy`, whatever the context holds and even when the test's key is missing. A malformed reference in a
  resource pattern makes the resource test undecidable instead, like an unresolved one.
- **IP range with no slash:** treated as an exact address match. A prefix length above 32 (IPv4) or 128 (IPv6), a
  malformed address, an empty list or a list holding anything but addresses and ranges is invalid.
- **Resource-less check:** matches only statements with neither `resources` nor `not_resources`, or whose `resources`
  include `*`.

## Implementation Anchors

- `HasPermissions::hasPermission()` -- the RBAC wildcard match loop with `fnmatch($held, $asked, FNM_NOESCAPE)`.
- `Statement::assess()` -- the action, resource and condition walk producing a `MatchResult`; `Statement::matches()` and
  `Statement::conditionsSatisfiedBy()` are its boolean views, true only on `MATCHES`; `Statement::coversAction()` -- the
  `actions` and `not_actions` test, asked first.
- `StatementValidator` -- the statement keys, the `sid`, the targets and the pattern lists;
  `StatementValidator::operatorErrors()` and `conditionTests()` -- the single description of malformed conditions, used
  both to refuse them on hydration and to make them invalid on assessment; `assertValidResource()` refuses a malformed
  resource pattern.
- `ConditionEvaluator::evaluate()` -- the operator dispatch, `OPERATORS` the catalogue, `operatorOf()` the `_if_exists`
  suffix, `PATTERN_OPERATORS` the operators whose operand is a glob; `ConditionOperands::isValid()` -- each operator's
  literal operand rule; `IpRanges` -- the ranges of `ip_in` and `ip_not_in`.
- `PolicyValidator`, `PolicyLimits` and the `ActionCatalogue` contract -- the write-time checks, and the limits on read.
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
- `PolicyEvaluatorTest::testDenyWithFailedConditionsDecidesNothing` and `testDenyWithMissingConditionKeyApplies` -- a
  deny whose test fails is skipped, and one whose key is missing applies.
- `PolicyEvaluatorTest::testDenyPassingUnderIfExistsApplies`, `testNotActionsDenyCoversEveryOtherAction` and
  `testNotResourcesDenyCoversEveryOtherResourceButNoResourcelessCheck` -- `_if_exists`, `not_actions` and
  `not_resources` in a decision.
- `MatchOutcomeTest`, `MatchResultTest` -- the four outcomes and their conjunction order.
- `StatementValidatorTest`, `PolicyTest` -- the hydration-time refusals and `sid` uniqueness.
- `StatementTest`, `ConditionEvaluatorTest`, `ConditionOperandsTest`, `IpRangesTest`, `ContextInterpolatorTest` --
  resource-less matching, `not_resources`, the per-operator outcomes, `_if_exists`, and interpolation and escaping.
- `PolicyValidatorTest`, `PolicyLimitsTest`, `DeclaredActionCatalogueTest`, `ValidatePolicyCommandTest` and
  `PolicyDocumentTest` -- the write-time checks, the limits on read, and the command.

## Change Triggers

- Adding a new condition operator requires a new entry in `ConditionEvaluator::OPERATORS` and `FAMILIES`, its evaluation
  in `ConditionEvaluator::evaluate()`, its operand rule in `ConditionOperands`, an entry in `PATTERN_OPERATORS` when its
  operand is a glob or in `LITERAL_OPERAND_OPERATORS` when its operand is never interpolated, and a new row in the
  operator catalogue above, including which operands are invalid and which context values are undecidable.
- Changing the matching direction (e.g. allowing the caller to supply wildcards) would violate invariant 1 and requires
  a design decision before implementation.
- Letting an undecidable test skip a deny, or letting a resource-less check match a resource-scoped statement, would
  violate invariants 3 and 6 and requires a design decision before implementation.
- Switching from `fnmatch` to a regex-based matcher would change the pattern syntax and require a migration guide.
