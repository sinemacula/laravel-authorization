# Wildcard and Condition Semantics

Permission checks and policy statement matching both use `fnmatch` for pattern evaluation, and policy statements support
a condition operator catalogue for context-sensitive decisions. This note documents the wildcard matching direction, how
backslashes and substituted values are kept literal, the four outcomes a statement test can have, the check's context
(the subject and resource attributes among it) and the keys a policy may read from it, the condition operator set,
the authentication requirement and the assurance keys no condition may test, `${…}` interpolation, and the interaction
between wildcards and the RBAC fallback.

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
   context value of `*` therefore matches only a literal `*`; it never turns `posts:${input.post}` into `posts:*`. The
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
   key tests, an unknown operator, a malformed literal operand, a resource pattern holding a NUL byte, a malformed
   `${…}` reference in a resource pattern or a condition, and `principals` on a deny or that are not a non-empty list of
   well-formed selectors. `Policy::fromArray()` refuses statements that share a `sid`.
   On write, `PolicyValidator` adds the limits, the context key catalogue and the action catalogue (see [Writing a
   policy](#writing-a-policy)), so a policy row with any of these faults cannot be saved; on read, a stored document
   over a limit, or one that no longer parses, denies as `invalid_policy`. The evaluation-time `invalid` outcome is the
   backstop for statements constructed directly; an operand whose value is known only after interpolation is never
   invalid, only undecidable.

8. **A condition key is a dot path, and the caller supplies only `input`.** The context of a check is nested
   namespaces, and a condition key or a `${…}` reference is read one segment at a time through them by one strict
   resolver, never as a literal key. Whatever the caller passes is held under `input` and never promoted into another
   namespace, so `authentication`, `request` and `environment` hold only what their trusted sources supply, and
   `subject` and `resource` only the package's built-ins and the declared attributes of their providers (see [The
   check's context](#the-checks-context)).

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
| `principals`    | An allow in a resource policy only: the subjects it applies to (see below)                 |
| `conditions`    | Optional: a map of operator to key tests (see [Condition Operators](#condition-operators)) |

A statement takes exactly one of `actions` and `not_actions`, and at most one of `resources` and `not_resources`; with
neither, it names every resource and a check that names none (AUTHZ-6.6). Each list, when present, is a non-empty list
of non-empty strings. The `sid` names the statement in the decision: its `StatementReference` carries it, and
`toString()` appends it JSON-encoded, as `name[key]#index sid="deny-deletes"`. It never changes how the statement is
evaluated or in what order. `Statement::toArray()` returns exactly the keys the statement was given, so a statement
without `resources` stays without them.

`principals` (AUTHZ-7.3) is a non-empty list of selectors, each `<morph type>:<id>` (a subject by reference) or
`role:<role id>` (whoever holds the role, by its key), and each part 1 to 191 bytes with no space, `*`, `${` or NUL
byte. A selector is an exact name, never a pattern and never interpolated. A deny takes none and is refused with one,
since a resource policy's deny applies to everyone. Only an allow of a policy attached to a resource applies through
its principals; an allow with them in any other policy never applies. How they are matched and where they may be
attached are in [Evaluation Order and Deny Precedence](evaluation-order-and-deny-precedence.md#resource-policies).

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
`{"eq": {"input.tenant": "org-1"}, "bool": {"input.mfa": false}}` is skipped for a check in `org-2`, whether or not the
context carries `input.mfa`. A test's shape is checked before its key is looked up, so a malformed test is invalid even
when its key is missing from the context.

A test is **undecidable** when:

- its key is missing from the context, unless its operator carries `_if_exists` or is `null` (a key present with a
  `null` value is not missing, although most operators find `null` the wrong type);
- a `${…}` reference cannot be resolved in a resource pattern (unless another of the statement's patterns covers the
  resource) or in an operand, or a resource pattern of a directly constructed statement holds a malformed reference;
  a resource pattern left holding a NUL byte, by a substituted value or as written on a directly constructed
  statement, is unresolved the same way;
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
`condition 'input.tenant' has an invalid operand for operator 'eq'`. A fault of the operator entry as a whole has no key
to name, so it adds no key to the trace; a fault in one key's operand records that key as not held.

## The Check's Context

The context a check's statements read is nested namespaces (N24), each made by one source:

| Namespace        | Keys the package declares                 | Source                                                |
|------------------|-------------------------------------------|-------------------------------------------------------|
| `authentication` | `guard`, `user_id`, `user_type` (strings) | `AuthenticationContext`; `GuardAuthenticationContext` |
| `request`        | `ip` (ip), `method`, `route` (strings)    | `RequestContext`; `RoutedRequestContext`              |
| `environment`    | `time` (time)                             | `EnvironmentContext`; `ClockEnvironmentContext`       |
| `subject`        | `id`, `type`, `tenant.type`, `tenant.id`  | The check's subject; a `SubjectAttributeProvider`     |
| `resource`       | `id`, `type`, `tenant.type`, `tenant.id`  | The check's resource; a `ResourceAttributeProvider`   |
| `input`          | none                                      | What the caller passes                                |
| Any other        | none                                      | A `ContextSource` in `authorization.context.sources`  |

- **Trusted namespaces.** `authentication` holds the default guard's name and, when someone is signed in on it, the
  user's key as a string and morph type; with nobody signed in only `guard`. An `AuthenticationContext` may supply
  further namespaces beside it (`mfa`, `sso`), named by its `namespaces()`. `request` holds Laravel's trusted-proxy
  `ip()`, the method and the route name, and only when the container's request has a route, so in a queued job or a
  console command the namespace is absent. `environment.time` is `now()` in UTC as `Y-m-d\TH:i:s\Z`, fixed the first
  time the check reads `environment`, then kept for the rest of the check. Each is replaced only by rebinding its
  contract.
- **Subject and resource** (N29). `subject` and `resource` describe who the check is about and what it is on, and
  their built-in keys are strings. `subject.id` is the subject's key (`getKey()` for a model), `subject.type` its morph
  class or, without one, its class name, and `subject.tenant.type` and `subject.tenant.id` its tenant, as `TenantScope`
  extracts it. `resource.id`, `resource.type`, `resource.tenant.type` and `resource.tenant.id` come from the check's
  `ResourceReference`: a record has an id and a type, a type alone has only a type, and an opaque identifier has
  neither, since it is never split at its `:`. A tenant key is absent without a tenant, and the whole namespace without
  a subject or a resource.
- **Attribute providers** (N30, AUTHZ-8.4, AUTHZ-8.5). Every other key of `subject` and `resource` comes from the
  provider registered for the subject's or the record's morph type in `authorization.attributes.subjects` or
  `authorization.attributes.resources`, resolved from the container. Its `attributes()` declares dot paths within the
  namespace with their types, and its `values()` returns them nested by key: a `SubjectAttributeProvider` is given the
  subject, and a `ResourceAttributeProvider` the record's reference and the model the check was given, if any, so it
  need not query for it; a model implementing `AuthorizableResource` is handed on too, when the reference it returns
  names one record and carries no model. Only the keys the matching provider declares are exposed; any other value it
  returns is dropped, and so is everything under a declared key. A declared key's value is kept when it is a scalar or
  null, or a list of them declared as `list`; any other array is swapped for a placeholder no path reads into, so the
  key stays present but undecidable (never missing, which `_if_exists` would pass) and `${…}` leaves it unresolved. A
  provider declaring a key under another it declares (`owner` and `owner.id`) is refused at boot. The model's columns
  are never read directly, and there is no `principal` namespace.
- **Attribute fallbacks and failures** (N31). A type alone, an opaque identifier, no resource and a type with no
  provider leave only the built-ins that apply, so an attribute key is missing (undecidable, or decided by `null` and
  `_if_exists`). A provider that throws, or cannot be resolved, aborts the check with `AttributeProviderFailed`, its
  failure kept as the previous exception: the check is never decided with the attribute missing, so a failing provider
  never allows anything. The message names the provider's class and the namespace, never a value, and nothing the
  provider returned or threw reaches the decision, an event or the trace (AUTHZ-8.8).
- **Caller values** (N27). The `$context` of `check()` and every helper over it (`can()`, `authorize()`, `explain()`,
  `effectivePermissions()`, the Gate's string-keyed and associative arguments and the testing assertions) is wrapped
  under `input` once, where the manager builds the check's context. A caller passing
  `['request' => ['ip' => '10.0.0.1']]` supplies `input.request.ip`, never `request.ip`.
- **Application namespaces** (N26). A `ContextSource` names one namespace and returns its values, nested by key. A
  source that does not implement the contract, one claiming a reserved namespace (`authentication`, `request`,
  `environment`, `input`, `subject`, `resource`), two sources claiming one namespace, and a source claiming a namespace
  the `AuthenticationContext` contributes are refused at boot, as is an `AuthenticationContext` contributing
  a namespace that is not a name, is reserved or is listed twice. A source returning nothing leaves its namespace
  absent.
- **Lazy and once a check** (N32). A namespace is built the first time a check reads a path in it, through a
  condition key or a `${…}` reference in an operand or a resource pattern, by `CheckContext::find()` and `lookup()`,
  and kept for the rest of the check. So every statement of one check sees the same values, a namespace is built at
  most once for the check, and a check that reads nothing of the request never builds it. Reading any key of `subject`
  or `resource`, a built-in included, builds the whole namespace and so asks its provider, once. A build that throws is
  not retried: the check is aborted. Each check has a context of its own, and nothing is kept for the next.

A condition key is a dot path read one segment at a time over these namespaces: `request.ip` reads the `ip` key of the
`request` namespace. It is never a literal key: a context whose top level holds a key named `request.ip` does not supply
`request.ip`, and an `input` of `['post.status' => 'draft']` does not supply `input.post.status`. A key is **missing**
when its namespace is absent, when a segment is absent, or when a segment is read through a value that is not an array;
a key present with a `null` value is not missing. A missing key makes a test undecidable, passes under `_if_exists`, and
is decided by `null`. Every `${…}` reference goes through the same resolver, so a condition and a reference naming one
path always see the same value.

### The key catalogue

Every key a policy reads must be declared in the bound `ContextKeyCatalogue` (N25), as a full dot path with a type and
whether a condition may test it (by default it may). The default, `DeclaredContextKeyCatalogue`, is held by the
container and has no static state. It declares the package's fifteen keys (`PACKAGE_KEYS`: seven of the trusted
namespaces and the eight built-ins of `subject` and `resource`), those of `authorization.context.keys`
(`namespace => [path => type]`, checked by the configuration validator at boot) and those the attribute providers
declare, each under its namespace, and a service provider registers more with `register($namespace, [$path => $type])`
or `declare($path, $type, $isTestable)`. Keys of `input` are declared like any other. Declaring a key again as it was
changes nothing; with another type or testability it is refused. A key under `subject` or `resource` is refused when
declared or registered (`ContextSource::ATTRIBUTE_NAMESPACES`): their keys come only from the package and the
providers. At boot, `AttributeConfigValidator` refuses a provider that does not implement its contract or cannot be
resolved, one declaring a built-in (`id`, `type` or anything under `tenant`), and two declaring one key with different
types; two providers may declare one key alike.

A key's type decides the operators a condition may test it with. The `_if_exists` form of an operator follows it, and
`null` suits every type:

| Type     | Operators                                                       |
|----------|-----------------------------------------------------------------|
| `string` | `eq`, `neq`, `in`, `not_in`, `starts_with`, `ends_with`, `like` |
| `number` | `eq`, `neq`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`           |
| `bool`   | `eq`, `neq`, `bool`                                             |
| `time`   | `before`, `after`, `between`                                    |
| `ip`     | `eq`, `neq`, `in`, `not_in`, `ip_in`, `ip_not_in`               |
| `list`   | `any_value_in`, `all_values_in`                                 |

The type is a write-time rule only: at evaluation a value is checked exactly as the operator table below says, so a
value of the wrong type is undecidable whatever the key was declared as. An untestable key may be read by a `${…}`
reference but not tested by a condition. An assurance key is always untestable, and not even a reference may read it
(see [Assurance keys](#assurance-keys)). The catalogue is given the namespaces the authentication context contributes,
so it knows them.

## Condition Operators

Conditions are a map of operator to key tests, and each key test maps a context key, a dot path, to an operand:

```json
{
  "ip_not_in": { "request.ip": ["10.0.0.0/8", "192.168.0.0/16"] },
  "eq": { "resource.owner.id": "${subject.id}" },
  "gte": { "input.post.revision": 2 }
}
```

When a statement's action and resource patterns match, the evaluator assesses every key test before committing the
effect, and every one must hold for an allow to apply. One key may be tested by several operators
(`{"gte": {"input.age": 18}, "lt": {"input.age": 65}}`); the trace records each key once, held only when all of its
tests held. A literal operand that is not of the listed type makes the statement invalid; a context value, or an operand
produced by interpolation, that is not of the listed type makes the test undecidable.

| Operator        | Operand                     | Context value   | Holds when                                             |
|-----------------|-----------------------------|-----------------|--------------------------------------------------------|
| `eq`            | scalar                      | scalar or null  | The value is strictly equal to the operand (`===`)     |
| `neq`           | scalar                      | scalar or null  | The value is not strictly equal to the operand         |
| `in`            | non-empty list of scalars   | scalar or null  | The value is in the list (strict)                      |
| `not_in`        | non-empty list of scalars   | scalar or null  | The value is not in the list (strict)                  |
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
  `1`. `eq` and `neq` compare one scalar and never a list: use `in` to compare against several values. For all four, a
  context value that is a list, a map or an object is the wrong type and undecidable, so `neq` and `not_in` never hold
  for it; a present `null` equals no operand, so `neq` and `not_in` hold for it.
- **Time-like** values are a `DateTimeInterface`, an integer UNIX timestamp, a finite float (truncated) or a non-empty
  string that `strtotime()` can parse. A string holding a NUL byte is not time-like, since `strtotime()` would read
  only the part before it: as a written operand it is refused, as a context value or substituted operand undecidable.
- **Numeric** values are integers, floats and numeric strings, compared as floats. `NAN`, `INF` and `-INF` (and a
  numeric string that overflows to an infinity) are not numbers: as an operand they are invalid, as a context value
  undecidable (`operator 'gt' needs a number`).
- **Non-empty `string`** operands are refused when empty as written; an operand that becomes empty only after
  interpolation is undecidable. A NUL byte is refused in a written `starts_with`, `ends_with` or `like` operand, even
  one with a `${…}` reference, and a context value or substituted operand holding one is undecidable for them, since
  `fnmatch()` cannot test it.
- **Boolean forms** are `true`, `false`, `1`, `0`, `'1'`, `'0'`, `'true'` and `'false'`, on both sides.
- **`null`** takes strictly `true` or `false` (N20), and decides a missing key rather than finding it undecidable:
  `{"null": {"input.post.deleted_at": true}}` holds when the context lacks `input.post.deleted_at` or carries it as
  `null`, and `{"null": {"input.user.email": false}}` holds only when `input.user.email` is present and not `null`.
- **`ip_in` and `ip_not_in`** take one IPv4 or IPv6 address or CIDR range, or a non-empty list of them read as one set
  of ranges. An operand without `/` is an exact address match; the prefix length must be digits no greater than 32 for
  IPv4 or 128 for IPv6. An address of the other family is within none of a range's addresses (it is decided, not
  undecidable), so `::ffff:10.0.0.1` is not within `10.0.0.0/8`. PHP's `FILTER_VALIDATE_IP` decides what an address
  is, as an operand and as a context value, so the answer is the same on every platform: a zone id (`fe80::1%en0`), an
  IPv4 part with a leading zero (`010.0.0.1`, `010.0.0.0/8`) and a NUL byte are not addresses, though some platforms'
  `inet_pton()` accepts the first two. A context value that is not a valid address is undecidable for both, so
  `ip_not_in` never reads an unreadable address as outside every range, and a deny written with it still applies.
- **`any_value_in` and `all_values_in`** test a multi-valued key, such as a token's scopes or a principal's groups. The
  context value must be a list of scalars; anything else is undecidable. An empty list never holds for `all_values_in`
  (N22), so a principal with no scopes does not pass a test that every scope is allowed.
- **`like`** follows invariants 4 and 5: the operand's own backslashes are literal and substituted values are escaped.

### `authentication_requirement`

The `authentication_requirement` operator (AUTHZ-8.3, N33) states an authentication requirement rather than testing a
context value. It is valid only on the reserved key `authentication`, and its operand is a non-empty map of parts to
their options:

```json
{
  "authentication_requirement": {
    "authentication": { "multifactor": { "max_age": 900 }, "phishing_resistant": {} }
  }
}
```

| Part                      | Options                                     |
|---------------------------|---------------------------------------------|
| `additional_verification` | `{}` or `{"max_age": n}`                    |
| `multifactor`             | `{}` or `{"max_age": n}`                    |
| `phishing_resistant`      | `{}` or `{"max_age": n}`                    |
| `assurance_level`         | `{"min": "<level>"}`, with `max_age` or not |

- **One test, judged whole.** The operand becomes an `AuthenticationRequirement` (each part with its maximum age, and
  the minimum level), and the bound `AuthenticationRequirementChecker` judges all of it at once for the subject's
  session, from the session's proofs, which it fetches itself. The package never reads `authentication` through the
  context resolver for it, never passes proofs or `amr` in, and never splits it into scalar tests that a fresh weak
  proof and a stale strong one could meet together. It counts as one key test for the `conditions` limit.
- **Outcomes.** Met is `MATCHES`; unmet is `DOES_NOT_MATCH`, carrying the requirement and its unmet parts; a checker
  that throws makes it `UNDECIDABLE`. A subject without a session, no subject and the default
  `RefusingRequirementChecker` all find every part unmet, and the checker is not asked without a session. A met result
  whose `metUntil` has passed is unmet, every part; an unmet result keeps only the requirement's own parts, and all of
  them when it names none. Nothing the checker answers is remembered: every requirement of every check is put to it
  afresh.
- **Insufficient authentication.** On an allow statement whose action and resource definitely match and whose every
  other test holds, an unmet requirement is kept on the `MatchResult` (`unmetRequirement`), so the evaluator can deny
  as `insufficient_authentication` with it (see [Evaluation Order and Deny
  Precedence](evaluation-order-and-deny-precedence.md)). On a deny statement it is a test that does not hold, so the
  deny does not apply; an undecidable one applies it.
- **Refused on write.** Any key but `authentication`; an operand that is not a non-empty map; an unknown part; options
  that are not a map, or that hold an unknown option; a `max_age` that is not an integer of at least 1; an
  `assurance_level` without a `min` that is a non-blank string. `authentication_requirement_if_exists` is refused with
  a reason of its own: a requirement has no `_if_exists` form. A statement constructed directly with any of these is
  invalid. The operand is never interpolated.
- **Trace.** The requirement is recorded as the condition key `authentication`, with whether it held, never a proof.
- **Catalogue.** The requirement reads no context key, so it skips the key catalogue: `authentication` need not be
  declared for it, and its type rules do not apply.

### Assurance keys

Scalar assurance keys may be in the context, for display and logging, but no policy may decide on them (AUTHZ-8.9,
N37). A key is an assurance key when its namespace is `authentication`, or one the bound `AuthenticationContext`
contributes beside it (such as `mfa`), and any segment of its path after the namespace is one of
`AssuranceKeys::NAMES`: `assurance_level`, `auth_time`, `seconds_since_step_up`, `last_verified_at`,
`verification_age`, `multifactor` and `amr`. So `authentication.amr`, `mfa.multifactor` and `mfa.multifactor.enabled`
are assurance keys, and `request.amr` and `authentication.guard` are not. The package declares none of them;
`DeclaredContextKeyCatalogue` declares any of them untestable whatever the declaring context, provider or configuration
says, and `PolicyValidator` refuses a condition on one, and a `${…}` reference to one in an operand or a resource
pattern, whatever the catalogue says, with a reason that names the key and points at `authentication_requirement`.

### `_if_exists`

Any operator but `null` and [`authentication_requirement`](#authentication_requirement) may be written with the
`_if_exists` suffix (`ip_in_if_exists`, `eq_if_exists`), and only one case changes: a key the context lacks passes that
test. A key present with a `null` value, a malformed operand, a context value of the wrong type and an unresolved
interpolation are decided exactly as without the suffix. A deny whose test passes only because of `_if_exists` still
applies, since the test holds like any other. `null_if_exists` is an unknown operator, as `null` already decides a
missing key, and `authentication_requirement_if_exists` is refused, as a requirement has no `_if_exists` form.

```json
{ "ip_in_if_exists": { "request.ip": "10.0.0.0/8" } }
```

holds for a check from `10.1.2.3` and for a queued job, whose context has no `request` namespace, does not hold for a
check from `203.0.113.7`, and is undecidable for a `request.ip` of `unknown`. A caller passing
`['request' => ['ip' => '203.0.113.7']]` changes nothing: it supplies `input.request.ip`, which the test never reads.

### Interpolation

Resource patterns and string operands may reference the check through `${namespace.key}`:

| Token                   | Resolves to                                                                    |
|-------------------------|--------------------------------------------------------------------------------|
| `${subject.id}`         | The subject's key; unresolved when it has none                                 |
| `${subject.type}`       | The subject's morph class, or its class name                                   |
| `${resource.id}`        | The record's id; unresolved for a type alone or an opaque identifier           |
| `${resource.type}`      | The record's or the type's type; unresolved for an opaque identifier           |
| `${<namespace>.<path>}` | The context key at that dot path, as a condition reads it (`${request.ip}`)    |

A token is `${`, a body matching `[a-zA-Z_][a-zA-Z0-9_.]*`, and `}`. The namespace is the body up to its first `.` and
the path everything after it. Every namespace, `subject` and `resource` included, is read from the check's context by
the resolver condition keys use, so `${request.ip}` reads `ip` within `request` and never a top-level key named
`request.ip`, and reading it builds the namespace like a condition would. There is no `context` or `principal`
namespace. A well-formed token naming a key the catalogue does not declare, `${context.…}` and a token without a path
(`${input}`, `${input.}`) among them, is refused by `PolicyValidator` when a policy is written, and is unresolved when a
statement built without the validator is evaluated. Any other `${` that is not the `\${` escape -- `${input.tenant-id}`,
`${}`, `${1x}`, an unclosed `${foo` -- is a **malformed reference**: `Statement::fromArray()` refuses it in a resource
pattern or a string operand, and on a directly constructed statement it makes a resource pattern unresolved
(undecidable) and a condition invalid.

A reference never reads a model's columns or an object's properties: `${subject.department}` resolves only when the
subject's provider declares `department` and returns a value for it, as `${resource.owner.id}` does for the record's.

A token that does not resolve to a scalar (an unknown namespace or key, a missing path, an array value, a check without
a subject or resource) makes the **whole string** unresolved: the test is undecidable, never compared against an empty
substitution. Every substituted value is a string: numbers are cast (`42` becomes `'42'`) and booleans become `'true'`
or `'false'`. An interpolated `eq` or `neq` operand is therefore compared strictly against a string, so
`{"eq": {"input.owner": "${subject.id}"}}` matches an `input.owner` of `'42'` but not the integer `42`: pass such
context values as strings. The numeric, time and `bool` operators read a substituted string as they read any other
(`'true'` and `'false'` are boolean forms). Write `\${` for a literal `${`; the escape is undone only in the string's
own text, never inside a substituted value. An operand holding only the escape contains no reference, so it is checked
as written: a `gt` operand of `\${x}` is refused.

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
    "eq": { "input.tenant": "org-42" },
    "ip_in": { "request.ip": ["10.0.0.0/8", "2001:db8::/32"] }
  }
}
```

This statement allows any `billing:*` action, on any resource or none, but only when the caller passes
`tenant = 'org-42'` (read as `input.tenant`) and the request comes from an address within one of the two ranges. If
either test fails, or either key is missing (a check outside a routed request has no `request.ip`), or the address
cannot be read, the statement is skipped. Written with `"effect": "deny"`, the same
statement would apply when a key is missing or the address cannot be read, and be skipped only when a test definitely
fails.

## Writing a Policy

`PolicyValidator::errors()` gives the reasons a document cannot be written, and the `Policy` model's `document` setter,
and so every write of `PolicyService`, refuses a document with any of them through `assertValid()`, which joins the
reasons into one `InvalidPolicyDocumentException` message, separated by semicolons. The reasons are:

- **Structure**: whatever `Policy::fromArray()` refuses, including statements sharing a `sid`. This reason stops the
  check: when `Policy::fromArray()` refuses the document, only its first fault and the limits it breaks are reported,
  and the context-key and catalogue checks do not run. Every other reason is reported at once.
- **Limits** (AUTHZ-6.10), from `authorization.policies.limits`: `document_bytes` (65536) on the document's JSON
  encoding, `statements` (100), `conditions` (50) on the key tests of one statement, each key of each operator counting
  as one, and `pattern_length` (512) on the characters of any action or resource pattern and any string operand, strings
  inside list operands and an authentication requirement's `min` included. A document that cannot be encoded as JSON
  (one holding NaN, an infinity or a string that is not valid UTF-8) can be neither measured nor stored, so it is
  refused too. The same limits are checked when a stored document is read (`PolicyDocument::hydrate()`), on the document
  as it is evaluated, named after its row, so a stored document over a limit denies as `invalid_policy` and is never
  skipped or partly evaluated. The resolution cache keys cached policies by the limits they were checked under, so a
  changed limit makes them be read and checked again. Lowering a limit therefore makes every stored document over it
  deny until it is fixed.
- **Context keys** (N25): every condition key must be declared in the context key catalogue, may not be one declared
  untestable, and must be of a type its operator suits; every `${…}` reference in an operand or a resource pattern
  must name a declared key, so a `${principal.…}` reference is refused (see [The key catalogue](#the-key-catalogue)).
  A condition key or reference that is an assurance key is refused whatever the catalogue says, and an
  `authentication_requirement` test skips the catalogue (see [Assurance keys](#assurance-keys)). A
  declared key is always a valid path: a letter or `_`, then letters, digits and `_`, then any number of `.`-separated
  segments of letters, digits, `_` and `-`, at most 128 characters, so a malformed key is refused as undeclared. Each
  reason is given once for its statement; a reason naming an undeclared key says how to declare it.
- **Actions** (N19): every `actions` and `not_actions` pattern must match at least one permission the code declares in
  `permission_enums` or `permission_providers`, compared with `fnmatch($pattern, $name, FNM_NOESCAPE)` or as the same
  string, so a misspelt action cannot be stored. The bound `ActionCatalogue` answers; the default,
  `DeclaredActionCatalogue`, reads the declared names once per request or job. With nothing declared, every document is
  refused with one reason that says so.

`php artisan authorization:policy:validate` checks documents with the same validator: JSON files given as paths (one
document, or an array of documents, per file; a directory's `*.json` files, in name order), or every stored policy row
of every tenant with `--database`, the default when no path is given. A file or directory that cannot be read is
reported as invalid. Stored rows are read from the column and named after the row, as hydration names them, but not
hydrated, so the command finds exactly the rows a lowered limit has made deny. It prints one line for each invalid
document, then a summary, and exits 1 when any is invalid.

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
- `CheckContext::lookup()` and `find()` -- the one strict dot-path resolver for conditions and references, and the
  per-check memo of built namespaces; `CheckContextFactory::make()` -- a check's context, the caller's values under
  `input` and every other namespace from its source; `AuthorizationManager::decideGrants()` -- where the caller's values
  are wrapped.
- `AttributeNamespaces::builders()` -- the `subject` and `resource` namespaces of a check, their built-ins and their
  providers' values; `AttributeProviders` -- the providers by morph type, the declared keys only, and
  `AttributeProviderFailed`; the `SubjectAttributeProvider` and `ResourceAttributeProvider` contracts;
  `AttributeConfigValidator` -- `authorization.attributes` at boot.
- `ContextInterpolator::references()` -- the paths a string references.
- `AuthenticationRequirement` -- the operand's rules (`errorOf()`) and the requirement it builds;
  `StatementValidator` -- the operator on `authentication` alone and no `_if_exists` form; `RequirementCheck` -- one
  check's requirements put to the bound `AuthenticationRequirementChecker` (default `RefusingRequirementChecker`) and
  the `RequirementResult` read; `MatchResult::unmet()` -- the unmet outcome with its parts.
- `AssuranceKeys` -- the names and `isAssuranceKey()`; `DeclaredContextKeyCatalogue` and `PolicyValidator` -- where
  they are made untestable and refused.
- The `ContextKeyCatalogue` contract, `DeclaredContextKeyCatalogue`, `ContextKey` and `ContextKeyType::suits()` -- the
  declared keys and the type and operator rules; `ContextConfigValidator` -- `authorization.context` at boot.
- The `AuthenticationContext`, `RequestContext`, `EnvironmentContext` and `ContextSource` contracts and their defaults,
  `GuardAuthenticationContext`, `RoutedRequestContext` and `ClockEnvironmentContext`; `ContextBindings` -- the
  bindings.
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
- `CheckContextTest::testALiteralDottedTopLevelKeyIsNotAPath` and `testANamespaceIsBuiltOnFirstReadAndOnce` -- the
  strict resolver and the memo; `CheckContextFactoryTest::testCallerValuesStayUnderInput` and
  `testSourcesAreReadLazilyAndOncePerCheck` -- the factory.
- `AuthorizationManagerTest::testCallerValuesLandUnderInputAndNeverInTheRequest`,
  `GateArgumentForwardingTest::testGateArgumentsLandUnderInputAndNeverInAnotherNamespace` and `AuthorizeActionTest` --
  caller values under `input` through every entry point, and the `request` namespace of a routed request.
- `AuthenticationRequirementTest`, `StatementValidatorTest`, `StatementTest` and `RequirementCheckTest` -- the
  requirement's operand rules, its outcomes and the checker; `AssuranceKeysTest`, `DeclaredContextKeyCatalogueTest` and
  `PolicyValidatorTest` -- the assurance keys made untestable and refused.
- `DeclaredContextKeyCatalogueTest`, `ContextKeyTypeTest` and `ContextConfigValidatorTest` -- the catalogue, the type
  rules and the configuration; `GuardAuthenticationContextTest`, `RoutedRequestContextTest` and
  `ClockEnvironmentContextTest` -- the trusted sources.
- `AttributeNamespacesTest`, `AttributeProvidersTest`, `AttributeConfigValidatorTest` and
  `CheckContextTest::testABuilderThatThrowsIsNeverRetried` -- the built-ins, the providers, the declared keys only, the
  boot checks and a failed build; `AuthorizationManagerTest::testTheSubjectAndResourceBuiltInsDecideTheCheck`,
  `testAttributeProvidersSupplyTheDeclaredAttributes` and `testAFailingAttributeProviderAbortsTheCheck` -- the
  attributes through a check.

## Change Triggers

- Adding a new condition operator requires a new entry in `ConditionEvaluator::OPERATORS` and `FAMILIES`, its evaluation
  in `ConditionEvaluator::evaluate()`, its operand rule in `ConditionOperands`, an entry in `PATTERN_OPERATORS` when its
  operand is a glob or in `LITERAL_OPERAND_OPERATORS` when its operand is never interpolated, the key types it suits in
  `ContextKeyType`, and a new row in the operator catalogue above, including which operands are invalid and which
  context values are undecidable.
- Adding a part to an authentication requirement requires a new entry in `AuthenticationRequirement::PARTS`, its
  options in `partError()`, and a row in the requirement table above; adding an assurance key name requires a new entry
  in `AssuranceKeys::NAMES`.
- Letting a condition test an assurance key, or splitting an authentication requirement into separate tests, would let
  a fresh weak proof and a stale strong one meet a requirement together, and requires a design decision before
  implementation.
- Letting a caller's value reach a namespace other than `input`, reading a condition key as a literal flat key, or
  reading a model's columns or an undeclared attribute into `subject` or `resource`, would violate invariant 8 and
  requires a design decision before implementation.
- Changing the matching direction (e.g. allowing the caller to supply wildcards) would violate invariant 1 and requires
  a design decision before implementation.
- Letting an undecidable test skip a deny, or letting a resource-less check match a resource-scoped statement, would
  violate invariants 3 and 6 and requires a design decision before implementation.
- Switching from `fnmatch` to a regex-based matcher would change the pattern syntax and require a migration guide.
