# Query Scoping

`whereAuthorized()`, and the model-level `AuthorizedScope`, restrict an Eloquent query to the rows the subject may take
an action on (AUTHZ-10.1), or refuse when they cannot do so exactly (AUTHZ-10.2). This note condenses the design: the
contract, how the condition is compiled from the decision pipeline itself, the guards, and every refusal.

## Purpose

A list of records the subject may see must agree with `check()` row for row, and keep the application's pagination
and counts correct. A filter applied after loading cannot do both, so the scope only adds a condition the database
evaluates, and refuses whatever it cannot prove (N64).

## Invariants

1. **The contract.** For a builder `Q` over a model, an action and a context, at one instant with the authorization
   state unchanged, the rows `Q->whereAuthorized()` keeps are exactly the rows of `Q`'s candidate set, before any
   limit or offset, on which `check()` allows the action for a model loaded with every column, whatever columns `Q`
   selects. A row on which `check()` throws for that model is not kept.

2. **Refuse rather than approximate.** When the compiler cannot prove the equality it throws
   `QueryScopeRefusedException` before the builder is changed. There is no post-filter. A refusal names reasons,
   policies, statements, keys and fixed phrases, never an operand, a pattern, a context value, a row's value or a tenant
   id.

3. **Compiled at the call and at every execution.** The macro compiles once, so a refusal throws there, then registers
   a global scope with an identifier unique to the call. Laravel applies global scopes to a clone of the builder for
   every execution (a page and its count, a chunk, an update, `toSql()`); the scope's condition is compiled again, from
   the state then, each time the grammar compiles the query. No decision is cached and none is reused, so a revocation
   is seen by the next execution (N68). A builder another query takes whole (`whereHas()`, `whereExists()`,
   `where($column, $builder)`) and a base query taken with `toBase()` are compiled again each time they are. Compiling
   records no last decision and dispatches no `DecisionEvaluated`, except through a preview, whose every compile admits
   the preview again in each scope its classes of rows are decided in, recording and reporting each admission as any
   check (see [Preview](preview.md)). A query taken into another as SQL text (`whereIn()`, `fromSub()`, `joinSub()`,
   `selectSub()`, `withCount()` or `has()` with a count) is compiled once, when it is taken in, and never again when
   the outer query runs. A query scoped through `Authorization::for()` of a `Subject` naming a tenant or an
   application is compiled, each time, inside that scope's `within()`, so its active tenant and application are the
   subject's, with the request's restored after the compile (N109).

4. **The place, the group and the condition, no bindings.** The macro holds the scope's place on the builder with a
   condition of its own type (`AuthorizedScope`), which the grammar compiles through a macro the registrar adds. When
   the scope is applied it takes its place out, puts every other constraint of the query in one nested group, with its
   bindings, and adds its condition after it, joined with `and`, so a top-level `OR` in a raw condition or an
   expression cannot reach past it, and a comment ending a raw condition leaves the group unclosed, an SQL error. Where
   the scope is never applied (removed, or the builder nested in a `where` group or merged into a relation's existence
   or count query, which copy only the constraints), the place reaches the grammar and refuses as `scope_removed`.
   Values are inlined as the hex of their bytes, or as digits or a uuid proved to be one, so the condition never needs
   escaping and never misaligns the application's bindings.

5. **The guard and the grammar.** A `beforeQuery` callback the scope registers on the clone it applies to, after every
   callback the application registered, groups again any constraint added since and refuses a query that would escape
   the condition: the scope's condition is missing from the top of the query (`scope_removed`), a top constraint after
   the first is joined with `or` (`query_or`), the query has a union (`query_union`), or it selects from anything but
   the model's table (`query_from`). The grammar, compiling the condition last of all, refuses the same and any
   constraint at the top that is neither a group nor a scope's condition (`query_changed`), so a change made after the
   guard, or to a base query run again, cannot escape either.

6. **One decision path (D22).** The compiler reuses the pipeline's resolvers and `Statement::assess()` rather than
   reimplementing evaluation: `DecisionPipeline::sources()` gathers a check's sources exactly as `check()` does, in the
   scope `check()` decides each class of rows in, each statement's conditions are assessed by `Statement::assess()`
   itself, and the stages are joined as `PolicyEvaluator` joins them.

## Success Path

The rows of the model are split into classes, each decided in one scope, as `ResourceScope` decides a check
(`ScopeClasses`):

| Class   | Rows                                                                                                                              | Decided in                                                             |
|---------|-----------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| A       | every row of a tenantless model, or a row of no tenant (either tenant column null)                                                | the request's scope, `isBelow` included                                |
| B(D,=)  | a row whose tenant is the anchor D, within the active tenant's subtree, byte for byte                                             | `within(D, app)`                                                       |
| B(D,<)  | a row strictly below D within the subtree, with no anchor between                                                                 | `within(D, app, isBelow: true)`                                        |
| C(X,=)  | when a platform-wide grant admits it, a row of the anchor X outside the active tenant's subtree (every tenant's with none active) | platform sources; X's guardrails and attached denies, `within(X, app)` |
| C(X,<)  | when a platform-wide grant admits it, a row strictly below X, outside the subtree, with no anchor between                         | as C(X,=), X's own sources read standing below it                      |
| C(none) | when a platform-wide grant admits it, every other row of a tenant                                                                 | platform sources alone                                                 |

The anchors are the tenants the decision's sources may sit at (`ScopeAnchors`), read on the authorization connection
with no filter on tenant, expiry or application, so they are never fewer than the tenants a check's sources sit at: the
grants, break-glass activations, policies and boundaries of the subject and its identity, the policies of the roles they
hold, through a grant or an activation, and every role above, the owners of those roles and of the permissions granted,
every guardrail, and every policy attached to the type or its records. The B classes are cut at the active tenant and
the anchors within its subtree; the C classes at the guardrail and attachment anchors outside it. A row strictly below
an anchor D with no anchor between reads exactly the sources `within(D, isBelow)` reads: `TenantChain::grants()` then
needs `include_subtree` at D, as at any ancestor, and no source sits between. Under `FlatTenantTree` there are no
`(·,<)` classes, and the only anchor within the active tenant's subtree is the active tenant. A platform-wide grant
admits the rows outside the subtree when the subject holds the action's permission at platform scope, as `ResourceScope`
asks it, once; without that grant `check()` denies every row outside the subtree as `tenant_scope`, and no C class keeps
a row. More anchors than `max_anchors`, or more classes than `max_scopes` (`authorization.query_scoping`), refuse as
`too_many_scopes`. Both are counted before any class is cut, and the classes are cut from each anchor's chain of
ancestors, read once through the tree, so the tree is asked a number of times bounded by the anchors, never by their
pairs.

Membership compares tenants as PHP does, while `check()` matches sources to tenants in SQL, so whenever a class is cut
below an anchor or admitted from outside, the tenant columns of every authorization table must compare bytes (null or
`BINARY` on SQLite, a deterministic collation on PostgreSQL, `utf8mb4_0900_bin` or `binary` on MySQL), or the query
refuses as `column_collation`. A subtree is the tree's own `subtree()` query, nested whole; its connection must be the
model's (`subtree_connection`), and its contract is that it selects exactly the string forms of every tenant within.

Each class is decided from the sources the pipeline gathers inside the class's scope for a reference to the type's
records, `T:*`, whose key `*` no attachment can name, so it reads the type's attachments alone; the principal selectors
are fresh for the class. A C class composes the platform's sources with the guardrails and the deny statements of the
type's attachments that its anchor's chain reads, both through the production resolvers under `within(X, app[,
isBelow])`. The policies attached to the type's records in the class's scope are read too (`RecordAttachments`), once
for each scope a compile decides classes in, at most `max_attachments` of them naming the action, and at most four
times as many in all whatever their actions, so the read is bounded by the rows it scans (`too_many_attachments`); in
a C class the platform's whole, and the anchor chain's denies alone.

The class's condition is compiled stage by stage, as `PolicyEvaluator` decides (`DecisionFormula`): no deny applies,
every guardrail (unless the action is `authorization:guardrail.manage`) and every boundary has a matching allow,
every session cap covers the action, and an allow matches or the permission is held in the class's scope. Each
statement a check would weigh is compiled by the statement screen (`StatementScreen`): its conditions are assessed
once by `Statement::assess()` on the statement without its resources, which they never read; its target is compiled
from its resource patterns, resolved as `check()` resolves them and decoded as `fnmatch()` reads them
(`ResourcePatterns`), into conditions on the row's key (`KeyConditions`). A statement's outcome on a row is its
target's joined with its conditions', as `assess()` joins them: an allow needs both to match, a deny applies where its
target is not a mismatch and its conditions are not; a pattern whose reference cannot be resolved makes the target
undecidable unless another covers the row.

| Pattern, decoded                   | The rows it names                                                                                             |
|------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `*`, or a prefix of `T:`, then `*` | every row                                                                                                     |
| a literal `T:k`                    | the row whose key is `k`, unless `k` is `*` or ends in `:*`, which `covers()` decides on the whole identifier |
| `T:p*`, `p` not empty              | the rows whose key's text starts with `p`, the key exactly `p` left out when `p` is `*` or ends in `:*`       |
| anything else                      | no row                                                                                                        |

A policy attached to a record weighs on that record alone: `EXISTS` over the attachments matching the policy, the type,
the row's key text and the class's tenant chain and application, written by `TenantChain::grants()` and
`GrantApplications::only()` and inlined, with the key one an attachment can name (1 to 191 bytes, not `*`). Its denies
apply to everyone, its allows to the subjects their principals name. A `withPolicies()` override reads no attachment.

That `EXISTS`, and a nested subtree, are inlined by the package's own code (`InlinedQuery`), never through Laravel's
`toRawSql()` or the connection's escaping: each binding, in order, becomes the literal the dialect writes for it
(`Dialect::parameter()`), which the database reads as it reads the value bound, with no character of a string written
as it is. SQLite reads `+CAST(X'…' AS TEXT)`, text with no affinity, as a bound string is; PostgreSQL reads a string of
no type with every character escaped by its code point, `U&'\0061'`, and an integer's digits quoted, as it receives
every bound value, untyped; MySQL reads `_utf8mb4 X'…'`, which takes the collation of what it is compared with, and an
integer's digits. A value no literal can stand for (a NUL byte or a string that is not UTF-8 on PostgreSQL, a string
that is not UTF-8 on MySQL), and a query whose text holds a question mark that is not a placeholder (which a
PostgreSQL `??` operator would), refuse as `inline_value`. `check()` reads the attachments and the pairs of a declared
model on the write connection, and a replica that lags could miss a deny `check()` sees, so such a condition must run
on the write connection too. With no separate read connection, or inside a transaction, it already does. Otherwise
the grammar's macro, compiling the condition, asks whether the query it compiles is the one its builder is running
(`InlinedQuery::isRunning()`, read from the call stack: the builder's own `runSelect()`, `cursor()` and its generator,
`exists()`, `update()`, `delete()` or `updateFrom()`), and if so sets `useWritePdo()` on it: Laravel passes
`! $this->useWritePdo` to the connection after `toSql()` or `compileExists()` in the same call, so that execution reads
on the write connection. Every way a scoped query runs itself goes through those (`get()`, `first()`, `pluck()`, the
aggregates, `paginate()`'s count and page, `chunk()`, `chunkById()`, `lazy()` and `lazyById()` through `get()`).
Anything else carrying the condition refuses as `read_replica`: a query nested whole in another (`whereHas()`,
`whereExists()`, the model-level scope on a related model), one compiled to text (`toSql()`, `toRawSql()`, `whereIn()`,
`fromSub()`, `withCount()`, `withExists()`, `has()` with a count), and a grouped query's page count, which Laravel runs
as another query wrapped around the compiled text. A condition that reads no authorization table, told by the aliases
the attachments and the subtree are read under, leaves the query where Laravel puts it.

The condition is `KeyGuard ∧ ⋁ (Member_c ∧ Decision_c ∧ LongGuard_c)` over the classes:

| Fragment                | SQLite                                                                                                                                        | PostgreSQL                                                                          | MySQL                                                                                      |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| KeyGuard, short form    | `K IS NOT NULL`, for a key cast to an integer only                                                                                            | `K IS NOT NULL`, for a key cast to an integer or a column that is not a string      | the same as PostgreSQL                                                                     |
| KeyGuard, full form     | `K IS NOT NULL AND length(CAST(K AS BLOB)) > 0 AND instr(CAST(K AS BLOB), X'00') = 0`, for every other key, whatever its declared type        | `K IS NOT NULL AND octet_length(K) > 0`, for a string column not cast to an integer | `K IS NOT NULL AND OCTET_LENGTH(K) > 0 AND LOCATE(X'00', CAST(K AS BINARY)) = 0`, likewise |
| Member A                | `(Tt IS NULL OR Ti IS NULL)`, or `Ti IS NULL` for a fixed type, with `typeof(x) IN ('null', 'integer', 'text', 'blob')` on each tenant column | `(Tt IS NULL OR Ti IS NULL)`, or `Ti IS NULL`                                       | the same as PostgreSQL                                                                     |
| Equal, the index's part | `x IN (CAST(X'…' AS TEXT), X'…')`                                                                                                             | `x = convert_from(decode('…', 'hex'), 'UTF8')`, `x = digits` or `x = 'uuid'`        | `x = _utf8mb4 X'…'` or `x = digits`                                                        |
| Equal, the exact part   | `typeof(x) IN ('integer', 'text', 'blob') AND CAST(x AS BLOB) = X'…'`                                                                         | `convert_to(CAST(x AS TEXT), 'UTF8') = decode('…', 'hex')`                          | `CAST(x AS BINARY) = X'…'`                                                                 |
| Within D                | `EXISTS (SELECT 1 FROM (subtree) AS s WHERE CAST(s.tenant_type AS BLOB) = CAST(Tt AS BLOB) AND …)`                                            | the same with `convert_to(CAST(x AS TEXT), 'UTF8')`                                 | the same with `CAST(CAST(x AS CHAR CHARACTER SET utf8mb4) AS BINARY)`                      |
| Key equals an integer   | `K = digits`, the least 64-bit value as a sum                                                                                                 | the same                                                                            | the same                                                                                   |
| Key starts with `p`     | `substr(CAST(K AS BLOB), 1, n) = X'…'`                                                                                                        | `substring(convert_to(CAST(K AS TEXT), 'UTF8') from 1 for n) = decode(…)`           | `LEFT(CAST(K AS BINARY), n) = X'…'`                                                        |
| Inlined value           | `NULL`, digits, `(-digits)` or `+CAST(X'…' AS TEXT)`                                                                                          | `NULL`, `'digits'` or `U&'\XXXX…'`                                                  | `NULL`, digits, `(-digits)` or `_utf8mb4 X'…'`                                             |
| Attached key            | `rp.resource_id = CAST(K AS TEXT) COLLATE BINARY`                                                                                             | `convert_to(rp.resource_id, 'UTF8') = convert_to(CAST(K AS TEXT), 'UTF8')`          | `rp.resource_id = CAST(K AS CHAR CHARACTER SET utf8mb4) COLLATE <its own collation>`       |
| LongGuard               | `length(CAST(K AS BLOB)) <= PHP_MAXPATHLEN - strlen(T) - 2`, unless cast to an integer                                                        | `octet_length(K) <= …`, for a string key                                            | `OCTET_LENGTH(K) <= …`, for a string key                                                   |

Member A keeps a row of no tenant only when PHP reads each tenant column as a string, an integer or null, as
`ResourceTenancy::tenantOf()` requires before it looks for a null: on SQLite an integer column can hold a real number,
on which `check()` throws; every class of a tenant needs both columns so read and each at most 191 bytes, as
`Reference` requires. An equality compares the bytes PHP reads: an integer as its decimal digits, a uuid as its
canonical lower-case text, a string as its bytes, whatever the column's collation, so `T1`, `t1` with a trailing space
or `05` never stand for `t1` or `5`. Its first part compares the bare column, which an index can serve, and keeps
every row the exact part keeps. A key is compared with a value only where the column proves what PHP reads: an integer
key must be SQLite's rowid, which a column declared `INTEGER PRIMARY KEY DESC` is not (SQLite gives such a key an index
of its own, `PRAGMA index_list` origin `pk`, and lets it hold reals and text), and neither an unsigned `BIGINT` nor
`ZEROFILL` on MySQL, whose text PHP reads padded with zeros (`column_type`); a string key's collation must be exact
(`column_collation`); a canonical integer id beyond 64 bits refuses (`resource_pattern`). On PostgreSQL a column's
collation is looked up in the table Laravel names, the connection's prefix before the table's own name and after any
schema, and a table or column not found there is not exact. The attached key is
compared under the attachment column's own collation, as the resolver compares it: byte for byte on SQLite and
PostgreSQL, whose column must compare so (`attachment_collation`), and under its utf8mb4 collation on MySQL; the
attachments must be on the model's connection (`attachment_connection`). A negation counts a condition the database
cannot decide as met, so it never lets a row through. LongGuard applies when a statement weighed on every row of the
class has a pattern that resolves, since `fnmatch()` refuses an identifier of `PHP_MAXPATHLEN` bytes or more and
`check()` then throws; an attached policy's statements are weighed only on keys of at most 191 bytes.

## Failure / Edge Cases

| Reason                                                   | Raised for                                                                                                                                                                                           |
|----------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `model_undeclared`                                       | A model that does not implement `QueryableResource`                                                                                                                                                  |
| `model_contract`                                         | A model implementing `AuthorizableResource`, or a morph type within 65 bytes of `PHP_MAXPATHLEN`                                                                                                     |
| `model_override`                                         | An override of `getMorphClass`, `newFromBuilder`, `getKey`, `getKeyName`, `getAttribute`, `getAttributes`, `getAttributeValue` or `setRawAttributes`                                                 |
| `model_listener`                                         | A `retrieved` listener or observer, or a `retrieved` entry in `$dispatchesEvents`                                                                                                                    |
| `column_accessor`                                        | An accessor on the key or a tenant column                                                                                                                                                            |
| `column_cast`                                            | A cast on a tenant column, or on the key other than its own kind's (`int` for an integer key, `string` for a string or uuid one)                                                                     |
| `column_type`                                            | A missing column, a kind the dialect cannot compare (`bpchar`, decimals, binaries, MySQL strings not in utf8mb4), a tenant type column that is not a string, or an inexact integer key once compared |
| `connection_charset`                                     | SQLite's `PRAGMA encoding`, PostgreSQL's server or client encoding, or MySQL's client, connection or results character set, other than UTF-8                                                         |
| `driver`                                                 | Any driver but `sqlite`, `pgsql` and `mysql` (Laravel's `mariadb` included)                                                                                                                          |
| `tenant_resolver`                                        | A resource tenant resolver bound in place of `DeclaredResourceTenant`                                                                                                                                |
| `subtree_connection`                                     | A tree whose `subtree()` query runs on another connection than the model's                                                                                                                           |
| `column_collation`                                       | A string key compared under a collation that is not exact, or an authorization table's tenant column so, once a class is cut below an anchor or admitted from outside                                |
| `attachment_connection`, `attachment_collation`          | Record attachments on another connection, or whose key column cannot be compared with the key, once one is attached                                                                                  |
| `too_many_scopes`, `too_many_attachments`                | More anchors, classes or record attachments than `authorization.query_scoping` allows, or four times `max_attachments` attached to the type's records in one scope whatever their actions            |
| `inline_value`                                           | A value of a record attachment's or a subtree's query that no literal can stand for as the database reads it bound, or a subtree query whose text holds a question mark that is not a placeholder    |
| `read_replica`                                           | A record attachment or a nested subtree in a query that is not itself run, so cannot be put on the write connection, on a model connection with a separate read connection outside a transaction     |
| `resource_pattern`                                       | A material pattern with `?` or `[`, a `*` not at its end or more than one, a trailing `\`, one too long for `fnmatch()`, or an integer id beyond 64 bits                                             |
| `resource_namespace`                                     | A material statement reading `resource`, in a condition, an operand or a pattern                                                                                                                     |
| `scope_variant_source`                                   | A material statement reading a namespace, or stating a requirement, through an unmarked seam                                                                                                         |
| `invalid_statement`, `invalid_policy`                    | A material statement that cannot be evaluated, or any document that cannot be read                                                                                                                   |
| `query_union`, `query_from`, `query_or`, `query_changed` | A query that would escape the condition, at the call or when it runs                                                                                                                                 |
| `scope_removed`                                          | A scope removed after the call, or never applied: called inside a `where` group or a relation's definition, or its query run past its scopes                                                         |
| `reentrant`                                              | The model-level scope applied while a scope is decided, or on the subject's own model                                                                                                                |
| `preview_write`                                          | A scope given a preview manager, compiled for an `update()`, `updateFrom()`, `delete()` or an insert from its own query or one nesting it whole                                                      |

- A guest, an inactive subject, or a morph type holding a NUL byte keeps no row, as `check()` denies every row.
- A model's promise (`QueryableResource`) is that its key and tenant columns are read raw, with no hook changing them
  on load; the detectable breaches refuse, and the resolver the provider binds (`DeclaredResourceTenant`, wrapping the
  configured one) reads a declared model's tenant from the same columns, raw, so `check()` agrees.
- SQLite stores any value in any column: the guards and comparisons read bytes, never the declared type, so a text
  value in an integer column, or a real one, is compared as PHP reads it.
- A material statement is refused even when another statement already decides the class: there is no pruning. A
  statement whose target names no row of the type is not material, since `check()` never reaches its conditions.
- `whereAuthorized()` is called on the query that runs. Inside a `where()`, `orWhere()` or `whereNot()` group, or in a
  relation's definition used by `whereHas()`, `has()`, `withCount()` or `withExists()`, its scope is never applied and
  the query refuses. A relation scoped in its definition is honoured when it is loaded; to filter by a relation, pass
  the scope in the relation's constraint.
- A pair naming a declared model is looked up on the write connection, and never with a key the key column could not
  hold, which PostgreSQL would answer with an error that aborts the transaction around it: such a key denies as
  `resource_unresolved`.

## Limits

What the scope cannot see, and so does not refuse:

- **A query taken in as SQL text.** `whereIn()`, `fromSub()`, `joinSub()`, `selectSub()`, `insertUsing()`, a
  `withCount()` or `withExists()` constraint and `has()` with a count compile the scoped builder to SQL when they take
  it in. The other query reuses that decision each time it runs; Laravel gives no sign that a compile is for such a
  text, so it cannot be told from a compile to run. Build the other query again to decide again, or scope it instead.
- **A `beforeQuery()` callback registered after the guard.** A global scope applied after `whereAuthorized()`'s own
  that registers a callback runs it after the guard; the grammar still refuses what it adds at the top, but a callback
  that removes the scope's condition leaves nothing to refuse.
- **A base query nested by hand.** A base query taken with `toBase()` and passed to `addNestedWhereQuery()` is judged
  as the group it is, not as part of the query around it.

## The Model-Level Scope

`Scopes\AuthorizedScope`, added in a model's `booted()`, applies `whereAuthorized()`'s scope to every query of the model
for the current subject: at each execution it compiles once, so a refusal throws from the executing call, then applies
the same `AuthorizedQuery`, which groups, guards and compiles again at the grammar. `withoutGlobalScope()` with its
class opts a query out, with no refusal, as the application's explicit choice; a `whereAuthorized()` scope removed
still refuses. Every compile is marked as deciding (`Query\Reentrancy`, a container key); the model-level scope applied
while it is set, or on the subject's own model, refuses as `reentrant`, so a scope on a model the decision reads never
recurses.

## Implementation Anchors

- `src/Registrars/QueryScopeRegistrar.php`: the macro.
- `src/AuthorizationManager.php`: `queryScope()`.
- `src/Query/AuthorizedQuery.php`: the scope, its place, its group, its guard and the grammar's macro.
- `src/Query/QueryAuthorizer.php`: deciding each class in its scope, and the condition.
- `src/Query/ScopeClasses.php`, `ScopeAnchors.php`, `ScopeClass.php` and `TenantMembership.php`: the classes.
- `src/Query/DecisionFormula.php`, `StatementScreen.php`, `ResourcePatterns.php`, `KeyTarget.php`, `KeyConditions.php`
  and `Conditions.php`: what compiles, and how.
- `src/Query/RecordAttachments.php` and `ResourcePolicyResolver::recordPoliciesFor()`: record attachments.
- `src/Query/InlinedQuery.php` and `Dialect::parameter()`: nested queries with their values inlined, and where they
  read.
- `src/Scopes/AuthorizedScope.php` and `src/Query/Reentrancy.php`: the model-level scope.
- `src/Query/ResourceShape.php`, `src/Query/SchemaInspector.php` and `src/Query/Dialects/`: the model, the columns and
  the SQL.
- `src/Evaluation/DecisionPipeline.php`: `sources()`, `weigh()` and `queryAuthorizer()`.
- `src/Contracts/QueryableResource.php`, `src/Support/ResourceTenancy.php` and
  `src/Resolvers/DeclaredResourceTenant.php`: the declarations.

## Authoritative Tests

- `tests/Integration/QueryScoping/ParityPropertyTest.php`: random scenarios on SQLite, PostgreSQL and MySQL, seeded by
  `AUTHZ_PARITY_SEED` and run `AUTHZ_PARITY_RUNS` times (150 by default), over a flat tree and a closure-table tree,
  grants reaching a subtree or not, platform-wide grants, type and record attachments, literal ids and prefixes over
  edge keys, integer keys at the edges of 64 bits, uuid keys on PostgreSQL and the model-level scope, comparing the
  rows kept with `check()` on freshly loaded models byte for byte, and asserting that constructs outside the subset
  refuse when material.
- `tests/Feature/Query/ScopeClassesTest.php`, `TenantMembershipTest.php`, `RecordAttachmentsTest.php`,
  `KeyConditionsTest.php` and `tests/Feature/Scopes/AuthorizedScopeTest.php`: tenant transitions, platform admission
  under guardrails, own-tenant denies, attachments under their column's collation and in their application, tenants
  and applications holding `?`, `??`, quotes, backslashes and NUL bytes, the key-kind proofs, the limits at their
  boundaries, every new refusal reason, and reentrancy.
- `tests/Feature/Query/InlinedQueryTest.php`: each inlined value finding exactly what the value bound finds, on every
  database, the read connection, and which compiles are of the query being run.
- `tests/Feature/Query/AuthorizedQueryTest.php`: on a connection whose read connection lags behind every write, each way
  a scoped query runs itself, by either scope, reading the attachments or a subtree on the write connection, and each
  shape that cannot be moved there refusing as `read_replica`.
- `tests/Feature/Registrars/QueryScopeRegistrarTest.php`: grouping, raw and expression conditions holding `OR`, a
  comment ending a raw condition, refusals at the call and at execution, nested and relation-definition use, subqueries
  taken whole and as text, `beforeQuery()` callbacks, base queries run again, pagination, chunks and counts,
  revocation between the call and execution, and the leaks of a broader scope: `-0`, a literal `*` key, a record's id,
  a `retrieved` listener and an overridden `getAttribute()`.
- `tests/Feature/Query/QueryAuthorizerTest.php`, `StatementScreenTest.php`, `ResourceShapeTest.php` and
  `AuthorizedQueryTest.php`: every refusal reason and every class, rows of no tenant `check()` cannot read, and the
  index's part of the active tenant's match.
- `tests/Feature/Resolvers/DeclaredResourceTenantTest.php`: the pair lookup on the write connection, and keys the key
  column could not hold, inside a transaction, on PostgreSQL too.

## Change Triggers

Update this note when the decision pipeline gathers a new source or a new scope-dependent query, when a new kind of
statement or tenancy compiles, when a dialect's fragment changes, or when Laravel changes how it nests, merges or
embeds a query.
