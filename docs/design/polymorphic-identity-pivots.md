# Polymorphic Identity Pivots

Role, permission, and policy grants are stored in three polymorphic pivot tables (`authorizable_roles`,
`authorizable_permissions`, `authorizable_policies`) that use `authorizable_type` + `authorizable_id` columns instead of
a fixed `user_id` foreign key. This design lets any Eloquent model participate in the authorization surface -- a `User`,
`ServiceAccount`, `Team`, or any future identity model -- without schema changes. This note explains the schema, the
scope each grant carries, the temporal-grant mechanism, the pivot class hierarchy, and the configuration seam.

## Invariants

1. **Any model can be an authorizable identity.** The `morphToMany` relation binds the pivot to the model's morph class
   and primary key at runtime. Integer, UUID, and ULID primary keys all work because the `authorizable_id` column is a
   `string` -- the widest common denominator that covers every key strategy Laravel supports. Grantee types and ids are
   bounded to 191 characters, as the suite bounds references.

2. **Each pivot table is structurally identical.** Every table carries the related entity's foreign key (`role_id`,
   `permission_id`, or `policy_id`), the grantee (`authorizable_type`, `authorizable_id`), the scope (`tenant_type`,
   `tenant_id`, `include_subtree`, `application`), a nullable `expires_at`, who made the grant (`granted_by_type`,
   `granted_by_id`) and the grant's timestamps. A secondary index on `(authorizable_type, authorizable_id)` services the
   reverse lookup.

3. **A target is granted to a grantee once per scope.** The unique key covers the target, the grantee, the tenant pair
   and the application. Null tenant columns (a platform-wide grant) and a null application (every application) each
   count as one value: the key compares them through `COALESCE(column, '')`, because MySQL, PostgreSQL and SQLite all
   treat nulls as distinct inside a unique index. On MySQL the three scope columns are compared by their SHA-256
   digest, since the key would otherwise exceed InnoDB's 3072-byte limit under `utf8mb4`.

4. **The entity FK side carries a real foreign key; the authorizable side does not.** The migration adds
   `->foreign('role_id')->references('id')->on($rolesTable)->cascadeOnDelete()` (and the equivalent for permissions and
   policies). No FK constraint is possible on the `authorizable_id` column because the referenced table varies by morph
   class -- this is the fundamental trade-off of polymorphic pivots. A grantee deleted without its model's events
   therefore leaves its rows behind, and `authorization:prune` revokes them.

5. **Temporal grants are a pivot-level concern, not a model-level one.** A grant with `expires_at = null` is permanent.
   A grant with a future `expires_at` is live until the clock passes that instant, at which point the relation's
   `where()` clause filters it out on read. No sweeper job is required for correctness -- the package ships query-time
   filtering on every relation access.

6. **A role is a grantee of policies too.** `authorizable_policies` takes a role as its grantee as readily as an
   identity, with the role's morph class and key, so a role's policies are scoped, expire and are reported like any
   other attachment (AUTHZ-7.2). An inline policy names the one grantee it belongs to in the policy's own `owner_type`
   and `owner_id`, a morph with no foreign key for the same reason, kept apart from the policy's tenant columns; its
   deletion with that grantee is the package's work, not the database's (AUTHZ-6.9).

7. **References compare their exact bytes on every database.** The grantee, tenant, application and granted-by
   columns, like every reference column of the package's tables, are matched byte for byte, as the package compares
   references in PHP: `org`, `ORG` and `org` followed by a space are three tenants. PostgreSQL and SQLite compare them
   so already; on MySQL, whose usual collations fold case and pad trailing spaces, the migrations give each reference
   column `utf8mb4_0900_bin` through `ExactReferences`. Other columns, such as role and permission names, keep the
   table's collation.

## Schema

The `authorizable_roles` migration (the other two are structurally identical):

```php
$schema->create($table, static function (Blueprint $blueprint) use ($table, $rolesTable, $exact): void {
    $blueprint->uuid('role_id');
    $blueprint->string('authorizable_type', 191);
    $blueprint->string('authorizable_id', 191);

    $blueprint->string('tenant_type', 191)->nullable();
    $blueprint->string('tenant_id', 191)->nullable();
    $blueprint->boolean('include_subtree')->default(true);
    $blueprint->string('application', 191)->nullable();

    $blueprint->dateTime('expires_at')->nullable();

    $blueprint->string('granted_by_type', 191)->nullable();
    $blueprint->string('granted_by_id', 191)->nullable();

    $blueprint->timestamps();

    $blueprint->index(['authorizable_type', 'authorizable_id'], $table . '_morph_index');
    $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');
    $blueprint->index('expires_at', $table . '_expires_at_index');

    $blueprint->foreign('role_id')->references('id')->on($rolesTable)->cascadeOnDelete();

    $exact->apply($blueprint);
});

(new NullFoldingUniqueIndex($schema->getConnection()))->createDigested(
    $table,
    $table . '_unique',
    ['role_id', 'authorizable_type', 'authorizable_id'],
    ['tenant_type', 'tenant_id', 'application'],
);
```

The expiry is a `dateTime` rather than a `timestamp`, which stops at 2038 on MySQL. A `dateTime` keeps no zone, so
the expiry is stored in UTC: the grant pivots' `UtcDateTime` cast converts an expiry given in any zone to UTC before
writing it and reads it back as UTC, and the relations compare it with the current time in UTC, so a grant lapses at
the instant it names whatever the caller's or the application's zone.

## Scope

Each grant has a scope: both tenant columns null grant platform-wide, a tenant pair grants within that tenant, and
`include_subtree` (true by default) says whether the grant reaches the tenant's subtree. A null application grants in
every application. The grant service, which the trait methods (`assignRole`, `givePermission`, `attachPolicy`) and the
Spatie import write through, writes each grant in the tenant its target's owner fixes or the call names, else
platform-wide, and for the application the call names, else every application. A check reads the grants made
platform-wide, in the current tenant and in its ancestors (those that reach below), for every application or for the
check's application.

## Pivot Class Hierarchy

A shared abstract base, `AuthorizableGrantPivot`, extends Laravel's `MorphPivot` and casts `expires_at` with
`UtcDateTime`, so consumers inspecting `$role->pivot->expires_at` receive a UTC `Carbon|null`. It also names the
package's connection (the application's default when `authorization.connection` is unset), since Laravel would
otherwise hand a pivot the connection of the grantee the relation starts from. Three leaf subclasses
exist -- one per table:

- `AuthorizableRolePivot` -- bound via `->using(...)` on `HasRoles::roles()`.
- `AuthorizablePermissionPivot` -- bound via `->using(...)` on `HasPermissions::permissions()`.
- `AuthorizablePolicyPivot` -- bound via `->using(...)` on `HasPolicies::policies()`.

The per-table split is intentional even though the subclasses are currently empty. Future per-table behaviour -- an
approval workflow on policy attachments, for example -- lands on the specific subclass without leaking the cast surface
across the other two tables.

## Configuration Seam

Every table name is configurable through the `authorization.tables.*` config block, and the connection the tables live
on through `authorization.connection`. A consumer who needs to rename `authorizable_roles` to `user_role_assignments`
sets:

```php
'tables' => [
    'authorizable_roles' => 'user_role_assignments',
],
```

The column names are fixed: the relations, the migrations and the grant reads all use the names above.

## Temporal Grant Mechanics

Each grant method (`assignRole`, `givePermission`, `attachPolicy`) accepts an optional `$expiresAt` parameter. The
relation's `where()` clause filters expired rows at query time -- rows whose `expires_at` is null or in the future are
included; everything else is invisible. The resolution cache honours this by inspecting the nearest `expires_at` across
the role, permission and policy pivot rows and capping the lifetime of both the in-memory and the persistent cache entry
accordingly, so a temporal grant that lapses at 3:00 PM does not remain cached past 3:00 PM, even within a long-running
job. Once an in-memory entry has lapsed, the grants are read from the database again rather than from relations already
loaded on the identity, so the lapse holds when the same identity instance is reused.

## Trade-offs

- **No FK on the authorizable side.** Orphaned pivot rows can accumulate when an identity model is deleted without
  cascading the pivot. Consumers should clean up via model events or a periodic sweep.
- **String `authorizable_id`.** Slightly wider than a typed integer column, but necessary to accommodate UUID, ULID,
  and integer keys in the same table without schema branching.
- **A digested key on MySQL.** The scope columns take part in MySQL's unique key as SHA-256 digests, to keep the key
  within InnoDB's limit. A digest is of the column's bytes, so it keeps apart what the byte-exact collation does.
- **Byte-exact references on MySQL.** A host query that compares a reference column with one of its own columns
  compares them by bytes, since MySQL prefers a `_bin` collation over a `_ci` one of the same character set.
- **No sweeper shipped in v1.0.0.** Expired rows are invisible at query time but remain in the database. The
  `expires_at` index exists so a consumer-side purge job can `DELETE WHERE expires_at < NOW()` efficiently.

## Implementation Anchors

- `AuthorizableGrantPivot` -- shared base with the `expires_at` cast and the connection.
- `AuthorizableRolePivot`, `AuthorizablePermissionPivot`, `AuthorizablePolicyPivot` -- per-table leaf classes.
- `HasRoles::roles()`, `HasPermissions::permissions()`, `HasPolicies::policies()` -- the `morphToMany` definitions
  with `->using(...)`, the grant timestamps and the expiry filter `where()` clause.
- `ResolvesPivotExpiry` -- the shared trait that computes nearest-expiry TTL and resolves the grant service.
- `Services\Support\GrantTable` -- the grant service's scoped row writes and locked read-back.
- `NullFoldingUniqueIndex` -- the unique key in which a null counts as a value.
- `ExactReferences` -- the byte-exact collation of the reference columns on MySQL.

## Authoritative Tests

- `PolymorphicIdentityTest::testTwoDistinctIdentityModelsShareARole` -- two different morph types share a role via the
  same pivot table.
- `GrantScopeColumnsTest` -- the scope columns, their defaults and the once-per-scope unique key on every grant table.
- `ExactReferenceMatchingTest` -- grantees and tenants that differ only by case or a trailing space are distinct to a
  check and to the unique keys, on every database.
- `TemporalGrantsTest::testFutureExpiryIsPresentThenFiltered` -- a temporal grant is visible before expiry and
  invisible after.
- `TemporalGrantsTest::testPivotExpiresAtIsCastToCarbon` -- pivot `expires_at` is a `Carbon` instance.
- `TemporalGrantsTest::testForeverGrantIsTheDefaultBehaviour` -- null `expires_at` creates a permanent grant.
- `TemporalGrantsTest::testForeverAndTemporalGrantsCoexist` -- permanent and temporal grants on the same identity
  coexist correctly.

## Change Triggers

- Adding a new entity type to the pivot surface (e.g. a `scope` grant) requires a new migration, a new pivot subclass,
  and a new trait method following the same pattern.
- Introducing a sweeper command requires reading the `expires_at` index and should not change the query-time filter.
- Moving from polymorphic pivots to per-model join tables would eliminate the no-FK trade-off but require a migration
  and a breaking config change.
