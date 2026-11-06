# Query Scoping

`whereAuthorized()` restricts an Eloquent query to the rows the subject may take an action on (AUTHZ-10.1), or refuses
when it cannot do so exactly (AUTHZ-10.2). This note condenses the design for what the first release implements: the
contract, how the condition is compiled from the decision pipeline itself, the guards, and every refusal. What the
second release adds is listed at the end as not yet compiled; until then it refuses.

## Purpose

A list of records the subject may see must agree with `check()` row for row, and keep the application's pagination
and counts correct. A filter applied after loading cannot do both, so the scope only adds a condition the database
evaluates, and refuses whatever it cannot prove (N64).

## Invariants

1. **The contract.** For a builder `Q` over a model, an action and a context, at one instant with the authorization
   state unchanged, the rows `Q->whereAuthorized()` keeps are exactly the rows of `Q`'s candidate set, before any
   limit or offset, on which `check()` allows the action for a model loaded with every column. A row on which `check()`
   throws is not kept.

2. **Refuse rather than approximate.** When the compiler cannot prove the equality it throws
   `QueryScopeRefusedException` before the builder is changed. There is no post-filter. A refusal names reasons,
   policies, statements, keys and fixed phrases, never an operand, a pattern, a context value, a row's value or a tenant
   id.

3. **Compiled at the call and at every execution.** The macro compiles once, so a refusal throws there, then registers
   a global scope with an identifier unique to the call. Laravel applies global scopes to a clone of the builder for
   every execution (a page and its count, a chunk, an update, `toSql()`), and the scope compiles again from the state
   then. No decision is cached and none is reused, so a revocation is seen by the next execution (N68).

4. **One grouped condition, no bindings.** The scope adds one nested condition holding one raw condition, after every
   constraint of the application's, which Laravel groups first when they hold an `or`. Values are inlined as the hex of
   their bytes, so the condition never needs escaping and never misaligns the application's bindings, also inside
   `parseSub()`.

5. **The guard.** A `beforeQuery` callback, copied with every clone, refuses a query that would escape the condition:
   the scope's own nested condition is missing from the top of the query (`scope_removed`, the scope was removed after
   the call), a top condition after the first is joined with `or` (`query_or`), the query has a union (`query_union`),
   or it selects from anything but the model's table (`query_from`). The nested conditions are marked on the scope
   instance in a `WeakMap`, never in static state.

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
  no record of the type, such as another type's or a record of it, is refused too: the first release compiles only
  the whole-type shapes, and refuses when in doubt;
- be evaluable.

Policies attached to a record of the type are read for every tenant and application, and any that names the action
refuses the query, as `record_attachment`, since the first release compiles no attachment to a record. A
`withPolicies()` override replaces the attached policies, as it does for `check()`, so nothing is read.

The condition is `KeyGuard ∧ ⋁ (Member_c ∧ LongGuard_c)` over the classes whose decision allows:

| Fragment                                                  | SQLite                                                                                      | PostgreSQL                                                 | MySQL                                                                            |
|-----------------------------------------------------------|---------------------------------------------------------------------------------------------|------------------------------------------------------------|----------------------------------------------------------------------------------|
| KeyGuard, a key cast to an integer or a non-string column | `K IS NOT NULL`                                                                             | same                                                       | same                                                                             |
| KeyGuard, any other                                       | `K IS NOT NULL AND length(CAST(K AS BLOB)) > 0 AND instr(CAST(K AS BLOB), X'00') = 0`       | `K IS NOT NULL AND octet_length(K) > 0`                    | `K IS NOT NULL AND OCTET_LENGTH(K) > 0 AND LOCATE(X'00', CAST(K AS BINARY)) = 0` |
| Member A                                                  | `Tt IS NULL OR Ti IS NULL`, or `Ti IS NULL` for a fixed type                                | same                                                       | same                                                                             |
| Member B                                                  | `typeof(x) IN ('integer', 'text', 'blob') AND CAST(x AS BLOB) = X'…'` on each tenant column | `convert_to(CAST(x AS TEXT), 'UTF8') = decode('…', 'hex')` | `CAST(x AS BINARY) = X'…'`                                                       |
| LongGuard                                                 | `length(CAST(K AS BLOB)) <= PHP_MAXPATHLEN - strlen(T) - 2`                                 | `octet_length(K) <= …`                                     | `OCTET_LENGTH(K) <= …`                                                           |

Member B compares the bytes PHP reads: an integer as its decimal digits, a uuid as its canonical lower-case text, a
string as its bytes, whatever the column's collation, so `T1`, `t1` with a trailing space or `05` never stand for `t1`
or `5`. A fixed tenant type is compared in PHP. A row of the active tenant has a tenant of at most 191 bytes, so no row
kept is one `Reference` refuses. LongGuard applies only when a material statement of the class has a pattern that
resolves, since `fnmatch()` refuses an identifier of `PHP_MAXPATHLEN` bytes or more and `check()` then throws; a kind
that bounds the key's text folds it away.

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
| `record_attachment`                                      | A policy attached to a record of the type that names the action                                                                                                |
| `invalid_statement`, `invalid_policy`                    | A material statement that cannot be evaluated, or any document that cannot be read                                                                             |
| `query_union`, `query_from`, `query_or`, `scope_removed` | A query that would escape the condition, at the call or when it runs                                                                                           |

- A guest, an inactive subject, or a morph type holding a NUL byte keeps no row, as `check()` denies every row.
- A model's promise (`QueryableResource`) is that its key and tenant columns are read raw, with no hook changing them
  on load; the detectable breaches refuse, and the resolver the provider binds (`DeclaredResourceTenant`, wrapping the
  configured one) reads a declared model's tenant from the same columns, raw, so `check()` agrees.
- SQLite stores any value in any column: the guards and comparisons read bytes, never the declared type, so a text
  value in an integer column, or a real one, is compared as PHP reads it.
- A material statement is refused even when another statement already decides the class: there is no pruning.

## Not Yet

The second release adds, each refused until then:

- tenant subtrees (a tree that is not flat) and rows admitted at platform scope by a platform-wide grant;
- policies attached to records, compiled per row;
- statements naming records: literal ids and other patterns that compare keys, with the column-kind proofs they need;
- a model-level scope class (`AuthorizedScope`) for use in `booted()`.

## Implementation Anchors

- `src/Registrars/QueryScopeRegistrar.php`: the macro.
- `src/AuthorizationManager.php`: `queryScope()`.
- `src/Query/AuthorizedQuery.php`: the scope, its marker and its guard.
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
- `tests/Feature/Registrars/QueryScopeRegistrarTest.php`: grouping, refusals at the call and at execution, pagination,
  chunks and counts, revocation between the call and execution, and the critique's leaks.
- `tests/Feature/Query/QueryAuthorizerTest.php`, `StatementScreenTest.php`, `ResourceShapeTest.php` and
  `AuthorizedQueryTest.php`: every refusal reason and every class.

## Change Triggers

Update this note when the decision pipeline gathers a new source, when a new kind of statement or tenancy compiles,
when a dialect's fragment changes, or when the second release lands.
