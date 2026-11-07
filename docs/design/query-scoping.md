# Query Scoping

`whereAuthorized()` restricts an Eloquent query to the rows the subject may take an action on (AUTHZ-10.1), or refuses
when it cannot do so exactly (AUTHZ-10.2). This note condenses the design for what this release implements: the
contract, how the condition is compiled from the decision pipeline itself, the guards, and every refusal. What a later
release adds is listed at the end as not yet compiled; until then it refuses.

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
   records no last decision and dispatches no `DecisionEvaluated`.

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
   reimplementing evaluation: `DecisionPipeline::sources()` gathers a check's sources exactly as `check()` does, and
   `DecisionPipeline::weigh()` decides them through the policy evaluator.

## Success Path

The rows of the model are split into classes, each decided in one scope, as `ResourceScope` decides a check:

| Class | Rows                                                                               | Decided in                              |
|-------|------------------------------------------------------------------------------------|-----------------------------------------|
| A     | every row of a tenantless model, or a row of no tenant (either tenant column null) | the request's scope, `isBelow` included |
| B     | a row whose tenant is the active tenant, byte for byte                             | the active tenant's own scope           |

Every other row of a tenant-bearing model is denied by `check()` as `tenant_scope`, so it is left out. That holds only
under `FlatTenantTree` and when the subject holds no platform-wide grant of the action (the admission
`ResourceScope` computes), so a tenant-bearing model is refused otherwise. With no active tenant there is no class B.

Each class is decided once: the pipeline gathers its sources inside `ResourceScope::decide()` for a reference to the
type's records, `T:*`, whose key `*` no attachment can name, so it reads the type's attachments alone; the principal
selectors are fresh for the class, since each class builds its own context. The statement screen then proves the
decision is every row's in the class: each material statement (one naming the action and, for an allow, applying to
the subject, as `PolicyEvaluator::isForSubject()` tells) must

- read only foldable namespaces: `input`, the subject's when its attribute provider is absent or marked, those whose
  sources are marked `ScopeInvariant`, and those no source supplies; authentication requirements need a marked checker;
- match only patterns, resolved as `check()` resolves them, that cover every record of the type, so no key changes the
  match (`ResourcePatterns`): `*`, `T:*`, or a shorter literal prefix of `T:` and then `*`. A pattern that could cover
  no record of the type, such as another type's or a record of it, is refused too: this release compiles only the
  whole-type shapes, and refuses when in doubt;
- be evaluable.

Policies attached to a record of the type are read for every tenant and application, a page at a time on the write
connection, until one names the action, whatever its principals; that refuses the query, as one `record_attachment`
naming no policy, since this release compiles no attachment to a record. A `withPolicies()` override replaces the
attached policies, as it does for `check()`, so nothing is read.

The condition is `KeyGuard ∧ ⋁ (Member_c ∧ LongGuard_c)` over the classes whose decision allows:

| Fragment                   | SQLite                                                                                                                                        | PostgreSQL                                                                          | MySQL                                                                                      |
|----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| KeyGuard, short form       | `K IS NOT NULL`, for a key cast to an integer only                                                                                            | `K IS NOT NULL`, for a key cast to an integer or a column that is not a string      | the same as PostgreSQL                                                                     |
| KeyGuard, full form        | `K IS NOT NULL AND length(CAST(K AS BLOB)) > 0 AND instr(CAST(K AS BLOB), X'00') = 0`, for every other key, whatever its declared type        | `K IS NOT NULL AND octet_length(K) > 0`, for a string column not cast to an integer | `K IS NOT NULL AND OCTET_LENGTH(K) > 0 AND LOCATE(X'00', CAST(K AS BINARY)) = 0`, likewise |
| Member A                   | `(Tt IS NULL OR Ti IS NULL)`, or `Ti IS NULL` for a fixed type, with `typeof(x) IN ('null', 'integer', 'text', 'blob')` on each tenant column | `(Tt IS NULL OR Ti IS NULL)`, or `Ti IS NULL`                                       | the same as PostgreSQL                                                                     |
| Member B, the index's part | `x IN (CAST(X'…' AS TEXT), X'…')` on each tenant column                                                                                       | `x = convert_from(decode('…', 'hex'), 'UTF8')`, `x = digits` or `x = 'uuid'`        | `x = _utf8mb4 X'…'` or `x = digits`                                                        |
| Member B, the exact part   | `typeof(x) IN ('integer', 'text', 'blob') AND CAST(x AS BLOB) = X'…'`                                                                         | `convert_to(CAST(x AS TEXT), 'UTF8') = decode('…', 'hex')`                          | `CAST(x AS BINARY) = X'…'`                                                                 |
| LongGuard                  | `length(CAST(K AS BLOB)) <= PHP_MAXPATHLEN - strlen(T) - 2`, unless cast to an integer                                                        | `octet_length(K) <= …`, for a string key                                            | `OCTET_LENGTH(K) <= …`, for a string key                                                   |

Member A keeps a row of no tenant only when PHP reads each tenant column as a string, an integer or null, as
`ResourceTenancy::tenantOf()` requires before it looks for a null: on SQLite an integer column can hold a real number,
on which `check()` throws. Member B compares the bytes PHP reads: an integer as its decimal digits, a uuid as its
canonical lower-case text, a string as its bytes, whatever the column's collation, so `T1`, `t1` with a trailing space
or `05` never stand for `t1` or `5`. Its first part compares the bare column, which an index on the tenant columns can
serve, and keeps every row the exact part keeps (a collation only adds matches); when no value of the column's kind
could be the tenant (text that is not UTF-8 or holds a NUL byte on PostgreSQL, digits that are not an integer's text)
it is no row, as the exact part would be. A fixed tenant type is compared in PHP. A row of the active tenant has a
tenant of at most 191 bytes, so no row kept is one `Reference` refuses. LongGuard applies only when a material
statement of the class has a pattern that resolves, since `fnmatch()` refuses an identifier of `PHP_MAXPATHLEN` bytes
or more and `check()` then throws; a kind that bounds the key's text folds it away.

## Failure / Edge Cases

| Reason                                                   | Raised for                                                                                                                                                     |
|----------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `model_undeclared`                                       | A model that does not implement `QueryableResource`                                                                                                            |
| `model_contract`                                         | A model implementing `AuthorizableResource`, or a morph type within 65 bytes of `PHP_MAXPATHLEN`                                                               |
| `model_override`                                         | An override of `getMorphClass`, `newFromBuilder`, `getKey`, `getKeyName`, `getAttribute`, `getAttributes`, `getAttributeValue` or `setRawAttributes`           |
| `model_listener`                                         | A `retrieved` listener or observer, or a `retrieved` entry in `$dispatchesEvents`                                                                              |
| `column_accessor`                                        | An accessor on the key or a tenant column                                                                                                                      |
| `column_cast`                                            | A cast on a tenant column, or on the key other than its own kind's (`int` for an integer key, `string` for a string or uuid one)                               |
| `column_type`                                            | A missing column, a kind the dialect cannot compare (`bpchar`, decimals, binaries, MySQL strings not in utf8mb4), or a tenant type column that is not a string |
| `connection_charset`                                     | SQLite's `PRAGMA encoding`, PostgreSQL's server or client encoding, or MySQL's client, connection or results character set, other than UTF-8                   |
| `driver`                                                 | Any driver but `sqlite`, `pgsql` and `mysql` (Laravel's `mariadb` included)                                                                                    |
| `tenant_resolver`                                        | A resource tenant resolver bound in place of `DeclaredResourceTenant`                                                                                          |
| `tenant_tree`, `platform_admission`                      | A tenant-bearing model under a tree that is not flat, or when the subject holds the action platform-wide                                                       |
| `resource_pattern`                                       | A material pattern other than the whole-type shapes, `-0`, `T:\*` and another type's included, or one too long for `fnmatch()`                                 |
| `resource_namespace`                                     | A material statement reading `resource`, in a condition, an operand or a pattern                                                                               |
| `scope_variant_source`                                   | A material statement reading a namespace, or stating a requirement, through an unmarked seam                                                                   |
| `record_attachment`                                      | A policy attached to a record of the type that names the action, whatever its principals                                                                       |
| `invalid_statement`, `invalid_policy`                    | A material statement that cannot be evaluated, or any document that cannot be read                                                                             |
| `query_union`, `query_from`, `query_or`, `query_changed` | A query that would escape the condition, at the call or when it runs                                                                                           |
| `scope_removed`                                          | A scope removed after the call, or never applied: called inside a `where` group or a relation's definition, or its query run past its scopes                   |

- A guest, an inactive subject, or a morph type holding a NUL byte keeps no row, as `check()` denies every row.
- A model's promise (`QueryableResource`) is that its key and tenant columns are read raw, with no hook changing them
  on load; the detectable breaches refuse, and the resolver the provider binds (`DeclaredResourceTenant`, wrapping the
  configured one) reads a declared model's tenant from the same columns, raw, so `check()` agrees.
- SQLite stores any value in any column: the guards and comparisons read bytes, never the declared type, so a text
  value in an integer column, or a real one, is compared as PHP reads it.
- A material statement is refused even when another statement already decides the class: there is no pruning.
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

## Not Yet

A later release adds, each refused until then:

- tenant subtrees (a tree that is not flat) and rows admitted at platform scope by a platform-wide grant;
- policies attached to records, compiled per row;
- statements naming records: literal ids and other patterns that compare keys, with the column-kind proofs they need;
- a model-level scope class (`AuthorizedScope`) for use in `booted()`.

## Implementation Anchors

- `src/Registrars/QueryScopeRegistrar.php`: the macro.
- `src/AuthorizationManager.php`: `queryScope()`.
- `src/Query/AuthorizedQuery.php`: the scope, its place, its group, its guard and the grammar's macro.
- `src/Query/QueryAuthorizer.php`: the classes and the condition.
- `src/Query/StatementScreen.php` and `src/Query/ResourcePatterns.php`: what compiles.
- `src/Query/ResourceShape.php`, `src/Query/SchemaInspector.php` and `src/Query/Dialects/`: the model, the columns and
  the SQL.
- `src/Evaluation/DecisionPipeline.php`: `sources()`, `weigh()` and `queryAuthorizer()`.
- `src/Contracts/QueryableResource.php`, `src/Support/ResourceTenancy.php` and
  `src/Resolvers/DeclaredResourceTenant.php`: the declarations.

## Authoritative Tests

- `tests/Integration/QueryScoping/ParityPropertyTest.php`: random scenarios on SQLite, PostgreSQL and MySQL, seeded by
  `AUTHZ_PARITY_SEED` and run `AUTHZ_PARITY_RUNS` times (150 by default), comparing the rows kept with `check()` on
  freshly loaded models byte for byte, and asserting that constructs outside the subset refuse when material.
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

Update this note when the decision pipeline gathers a new source, when a new kind of statement or tenancy compiles,
when a dialect's fragment changes, when Laravel changes how it nests, merges or embeds a query, or when a later release
lands.
