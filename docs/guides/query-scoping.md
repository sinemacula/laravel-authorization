# Query scoping

`whereAuthorized()` restricts an Eloquent query to the rows the subject may take an action on, alongside the
application's own filters, ordering, selects and pagination:

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;

Post::query()->where('status', 'live')->whereAuthorized('posts:view')->paginate();

Post::query()->whereAuthorized('posts:view', ['channel' => 'web'], Authorization::forUser($user))->get();
```

The rows it keeps are exactly the rows of the query's candidate set, before any limit or offset, that `check()` would
allow the subject on for the record loaded with every column, whatever columns the query selects, with the same
context, under the state at the instant the query runs; a row on which `check()` would throw for that record is not
kept. When the scope cannot prove that, it throws a `QueryScopeRefusedException` instead: it never filters rows after
loading them, and never keeps a row it has not proved `check()` allows. A model loaded without its key or its tenant
columns cannot itself be passed to `check()` (it throws, or denies as `resource_unresolved`), so select those columns
if you mean to check the results.

The subject is the one `check()` decides about: the current manager's, or that of the manager passed as the third
argument, so a scoped manager from `for()`, `forUser()`, `withPolicies()` or `capped()` scopes the query with its
subject, its policy override and its caps, and a preview from `previewFor()` with its previewed subject (see
[Preview](preview-and-explanations.md#preview)). A guest keeps no row. The context is the caller's values, read under
`input`, as `check()` reads them.

The scope is compiled when `whereAuthorized()` is called, so a refusal throws there and the builder is left exactly as
it was, and again every time the query is compiled to run, from the state then: a page and its count, each chunk, an
update or a deletion are each decided afresh, so a grant revoked after the call is seen by the next execution, and no
decision is reused. Compiling, at the call or at execution, records no last decision and dispatches no
`DecisionEvaluated`, so an audit of row access needs its own hook, except through a preview, whose every compile admits
it again, recording and reporting that admission as any check. The scope never runs a query on the model's table of
its own.

When the query runs, every constraint of the application's, those added before the call, after it and by other global
scopes alike, is put in one group, and the scope's condition, with no bindings, is joined to it with `and`: an
`orWhere()`, or a raw condition or expression holding `OR`, never reaches past it, and a comment at the end of a raw
condition leaves the group unclosed, so the database refuses the query rather than drop the condition. To compare the
tenant columns exactly, byte for byte, the condition also compares the bare columns with the active tenant, which an
index on them can serve; whether the planner uses it beside the rows of no tenant is the database's choice.

A query is refused when it runs if it would escape the condition: one with a union, one that selects from anything but
the model's table (an alias or a subquery included), one joined with `or` at the top after the condition (a
`beforeQuery()` callback adding one included), one whose scopes were removed after the call (remove scopes before
calling `whereAuthorized()`), and one changed at the top after the scope's own last check. `whereAuthorized()` is
called on the query that runs: called inside a `where()`, `orWhere()` or `whereNot()` group, or in a relation's
definition that `whereHas()`, `has()`, `withCount()` or `withExists()` then uses, its scope is never applied, and the
query refuses rather than keep every row. A relation scoped in its definition works when it is loaded, lazily or
eagerly; to filter by a relation, pass the scope in its constraint:
`Owner::whereHas('posts', fn ($query) => $query->whereAuthorized('posts:view'))`.

A scoped builder another query takes whole, as `whereHas()`, `whereExists()` and `where($column, $builder)` take it,
is decided each time that query runs, and so is a base query taken with `toBase()`, which refuses once it is widened
with `or` or given a condition outside the group. One taken in as SQL text, by `whereIn()`, `fromSub()`, `joinSub()`,
`selectSub()`, `insertUsing()`, a `withCount()` or `withExists()` constraint, or `has()` with a count, is decided when
it is taken in, and the other query reuses that decision every time it runs: Laravel gives no sign of a compile that is
for such a text, so this one shape is not refused. Build the other query again to decide again, or call
`whereAuthorized()` on it. A `beforeQuery()` callback registered by a global scope applied after `whereAuthorized()`'s
own runs after the scope's last check, and is the application's to keep honest.

## Declaring a model

A model whose queries are scoped implements `QueryableResource` and declares where its records keep their tenant:

```php
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

final class Post extends Model implements QueryableResource
{
    public static function resourceTenancy(): ResourceTenancy
    {
        return ResourceTenancy::columns('tenant_type', 'tenant_id');
    }
}
```

| Declaration                                 | The records' tenant                                                           |
|---------------------------------------------|-------------------------------------------------------------------------------|
| `ResourceTenancy::tenantless()`             | None                                                                          |
| `ResourceTenancy::columns($type, $id)`      | The morph type and key in the two columns                                     |
| `ResourceTenancy::ofType($tenantType, $id)` | Always of the type given (a morph type or a model class), keyed by the column |

The resource tenant resolver the package binds answers a declared model's tenant from its declaration, so `check()`
reads the same columns the scope compares, raw; every other model is still answered by the resolver
`authorization.resource_tenant_resolver` configures. A record whose type or id is null has no tenant.

By declaring its tenancy a model promises that its key and its tenant columns are read raw, as the database holds
them: no accessor, cast or override changes them on load, and no hook, such as a `retrieved` listener or observer,
changes them once a record is loaded. The scope refuses every breach it can detect.

## What compiles

The scope compiles every statement it can compare with each row's key in SQL exactly as `check()` matches it:

- the actions and `not_actions` of every statement;
- resources absent, or `resources` and `not_resources` whose patterns, resolved as `check()` resolves them, are `*`,
  a literal, or a literal and then `*`: a literal naming a record of the type (`T:5`, `T:abc`, `T` being the model's
  morph type) compares the key, a literal and then `*` longer than `T:` (`T:ab*`) compares the start of the key's
  text byte for byte, and any other names every record of the type or none. A key that is `*` or ends in `:*` is
  matched on the whole identifier, as `check()` matches it, so `T:${input.k}` with a `*` substituted names no record;
- an integer key equals only an integer's canonical decimal text within 64 bits (`-0`, `+1`, `01` and `1.0` name no
  record), a uuid key on PostgreSQL only a uuid's canonical lower-case text, and a string key a value byte for byte;
- conditions on `input`, on the subject's namespace, built-in keys included, when the subject's type has no attribute
  provider or one marked `ScopeInvariant`, and on the namespaces of sources marked `ScopeInvariant`, the package's
  defaults included, and authentication requirements a checker so marked judges;
- the permissions held, the subject's and its identity's policies, its roles' policies, permission boundaries,
  guardrails (except for `authorization:guardrail.manage`), session caps and the policies attached to the model's
  type or to its records, whose allows apply to the subjects their `principals` name, by reference or by role, and
  whose denies apply to everyone; a policy attached to a record weighs on that record alone, compared in SQL under
  the attachment column's own collation, and a `withPolicies()` override reads no attachment;
- tenantless models, and tenant-bearing models under any tenant tree: the rows of no tenant are decided in the
  request's scope; the rows within the active tenant's subtree in their own tenant's scope, every grant there, above
  them reaching below, or platform-wide counting; and, when the subject holds the action through a platform-wide
  grant for the request's application, every other tenant's rows at platform scope, each still capped by its own
  tenant chain's guardrails and denied by the denies attached in its tenant chain. Without that grant `check()` denies
  those rows as `tenant_scope`, and they are left out;
- rows whose key cannot identify a record (null, empty or holding a NUL byte), rows whose tenant columns hold something
  other than a string, an integer or null (a real number SQLite keeps in an integer column) or a part over 191 bytes,
  and, when a statement matches a pattern against the identifier, rows whose identifier is too long for `fnmatch()`,
  are left out, as `check()` denies or throws on them.

A tree other than the flat one is read through `TenantTree::subtree()`, nested in the condition whole, so it must run on
the model's connection, and one on another is refused as `subtree_connection` (the [grant scope
query](administration.md#grant-scope-query) needs it on the package's connection instead); its contract is that
`subtree(T)` selects exactly the string forms (`tenant_type`, `tenant_id`) of every tenant within `T`, whatever the
tenant scope. The rows are split into classes at the tenants the decision's sources sit at: the subject's grants,
policies and boundaries, its roles', the guardrails and the type's attached policies. Each class is decided once, every
time the query runs, so the number of tenants and classes is bounded:

```php
// config/authorization.php
'query_scoping' => [
    'max_anchors'     => 64, // the active tenant and those the sources may sit at, over which `too_many_scopes`
    'max_scopes'      => 16, // classes one query is decided in, over which `too_many_scopes`
    'max_attachments' => 64, // record attachments naming the action in a scope, over which `too_many_attachments`
],
```

`max_anchors` counts the active tenant and every other tenant the decision's sources may sit at: those of the grants,
policies and boundaries of the subject and its identity, of the policies of the roles they hold and every role above
those, of the tenants owning those roles and the granted permissions, of the guardrails, and of the policies attached to
the type or its records. Under the flat tree, where only a platform-wide grant cuts the rows, only the guardrail and
attached-policy tenants count. Both limits are checked before any class is cut, so the work of cutting is bounded by
them. `max_attachments` bounds the policies attached to records of the type, in one scope, that name the action; the
read also stops, and refuses as `too_many_attachments`, once four times as many are attached there whatever their
actions, so it is bounded by the rows it scans as well as by those it keeps. Each scope's attachments are read once per
compile. Each limit is a whole number of at least 1.

The comparisons are exact only where the database compares bytes as PHP does. When the rows are cut below a tenant
or admitted from outside the active tenant's subtree, the tenant columns of every authorization table must compare
bytes: no collation or `BINARY` on SQLite, a deterministic collation on PostgreSQL, and `utf8mb4_0900_bin` or `binary`
on MySQL, as the package's migrations create them. A string key compared with a value must compare bytes the same
way. An integer key compared with a value must hold only integers PHP reads as they are: on SQLite it must be the
table's rowid (`INTEGER PRIMARY KEY`, never `INTEGER PRIMARY KEY DESC`, which SQLite does not make the rowid), and on
MySQL it must be neither an unsigned `BIGINT` nor `ZEROFILL`, whose digits PHP reads padded. The column of an attached
record's key must compare bytes on SQLite and PostgreSQL; on MySQL its own utf8mb4 collation is followed. On PostgreSQL
a table is looked up as Laravel finds it, the connection's prefix before the table's own name and after any schema, and
a column not found there is treated as not exact.

A record attachment, and a subtree of a tree other than the flat one, are read in the condition itself, with every value
they are bound to (a tenant, an application, a policy) inlined as the database reads it bound, its characters written
as hex or escaped code points, so a quote, a backslash, a question mark or a NUL byte is never read as SQL; a value that
cannot be written so, and a subtree query whose text holds a question mark that is not a placeholder, refuse as
`inline_value`.

`check()` reads the authorization tables on the write connection, and a condition that reads them must too. On a model
connection with a separate read connection, outside a transaction (where Laravel already reads on the write
connection), the query carrying such a condition is put on the write connection when it is the query being run: a
scoped query's own `get()`, `first()`, `pluck()`, `count()` and other aggregates, `exists()`, `paginate()` (its count
and its page), `cursor()`, `chunk()`, `chunkById()`, `lazy()`, `lazyById()`, `update()` or `delete()`, with
`whereAuthorized()` or the model-level scope alike. Laravel passes the query's choice of connection only after
compiling it, so this holds for that execution alone. A query that carries the condition but is not itself run cannot
be moved, and refuses as `read_replica`: one nested whole in another (`whereHas()`, `whereExists()`, a relation's
existence query, the model-level scope on a related model), one compiled to text (`toSql()`, `toRawSql()`, and every
shape that takes it in as text, such as `whereIn()`, `fromSub()`, `withCount()`, `withExists()` and `has()` with a
count), and `paginate()` on a grouped query, whose count Laravel runs as another query around it. A condition that
reads no authorization table (no record attachment and no nested subtree) leaves the query on the read connection.

A statement gathered for the type is refused only when a check would weigh it: it names the action, its target can
name a row and, for an allow, it applies to the subject. A document that cannot be read always refuses. Everything
else that could change a decision refuses, with no pruning:

| Reason                                                   | Refused                                                                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `model_undeclared`                                       | A model that does not implement `QueryableResource`                                                                                                  |
| `model_contract`                                         | A model implementing `AuthorizableResource`, or a morph type too long to identify a record                                                           |
| `model_override`                                         | An override of `getMorphClass`, `newFromBuilder`, `getKey`, `getKeyName`, `getAttribute`, `getAttributes`, `getAttributeValue` or `setRawAttributes` |
| `model_listener`                                         | A `retrieved` listener or observer, or a model dispatching its own event when retrieved                                                              |
| `column_accessor`, `column_cast`                         | An accessor, or a cast other than the key's own kind, on the key or a tenant column                                                                  |
| `column_type`                                            | A key or tenant column missing, or of a type that cannot be compared exactly; an integer key PHP may read otherwise, once it is compared             |
| `column_collation`                                       | A string key compared under a collation that is not exact, or an authorization table's tenant column so, once rows are cut below or admitted         |
| `connection_charset`, `driver`                           | A connection that is not UTF-8, or not SQLite, PostgreSQL or MySQL                                                                                   |
| `tenant_resolver`                                        | A resource tenant resolver bound in place of the package's                                                                                           |
| `subtree_connection`                                     | A tenant tree whose subtree query runs on another connection than the model's                                                                        |
| `attachment_connection`, `attachment_collation`          | Policies attached to records kept on another connection, or whose key column cannot be compared with the key, once one is attached                   |
| `too_many_scopes`, `too_many_attachments`                | More tenants, classes or record attachments than `authorization.query_scoping` allows                                                                |
| `inline_value`                                           | A tenant, application or policy value, or a subtree query, that cannot be inlined exactly as the database reads it bound                             |
| `read_replica`                                           | A record attachment or subtree read by a query that is not itself run, on a separate read connection outside a transaction                           |
| `resource_pattern`                                       | A pattern with `?` or `[`, a `*` not at its end or more than one, a trailing `\`, one too long for `fnmatch()`, or an integer id beyond 64 bits      |
| `resource_namespace`, `scope_variant_source`             | A statement reading the resource, or a source not marked `ScopeInvariant`                                                                            |
| `invalid_statement`, `invalid_policy`                    | A statement that cannot be evaluated, or a document that cannot be read                                                                              |
| `query_union`, `query_from`, `query_or`, `query_changed` | A query that would escape the condition                                                                                                              |
| `scope_removed`                                          | A scope removed after the call, or never applied: called inside a `where` group or a relation's definition, or run past its scopes                   |
| `reentrant`                                              | The model-level scope on the subject's model, or on a model the decision reads                                                                       |
| `preview_write`                                          | A scope given a preview, run as an `update()`, a `delete()` or an insert from its own query or one nesting it whole                                  |

## The model-level scope

`AuthorizedScope` keeps every query of a model to the rows the current subject may take an action on, added in the
model's `booted()`:

```php
use SineMacula\Laravel\Authorization\Scopes\AuthorizedScope;

protected static function booted(): void
{
    static::addGlobalScope(new AuthorizedScope('posts:view'));
}
```

It shares `whereAuthorized()`'s compiler and behaves as it does: it is compiled every time a query of the model runs,
for the subject `check()` would decide about then, with no decision cached; a refusal throws from the call that runs
the query; and its condition is grouped and guarded the same way. `withoutGlobalScope(AuthorizedScope::class)` opts a
query out, and it then runs unscoped with no refusal, since that is the application's explicit choice; removing a
`whereAuthorized()` scope, by contrast, refuses as `scope_removed`. It must never be on the subject's own model, nor on
a model the decision reads while deciding (the grants, roles, policies and tenants): such a query refuses as
`reentrant` rather than recurse.

## The exception

`QueryScopeRefusedException` is a `RuntimeException`, not an `AuthorizationException`, thrown alike by
`whereAuthorized()` and `AuthorizedScope`: a refusal is a developer or configuration fault, which Laravel renders as a
500. It carries the `action`, the model's `resourceType` (its morph
type, through the morph map when it has one) and every `refusal`, each with its `reason`, the `policy` and `statement`
it names, the condition key, namespace, column or seam class (`key`) and a fixed `detail`, and `reasons()` lists their
reasons. Neither it nor its message ever carries an operand, a pattern, a context value, a row's value or a tenant id,
and a refusal for record attachments names no policy, however many there are.
