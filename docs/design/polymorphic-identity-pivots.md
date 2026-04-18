# Polymorphic Identity Pivots

Role, permission, and policy grants are stored in three polymorphic pivot tables (`authorizable_roles`,
`authorizable_permissions`, `authorizable_policies`) that use `authorizable_type` + `authorizable_id` columns instead of
a fixed `user_id` foreign key. This design lets any Eloquent model participate in the authorization surface -- a `User`,
`ServiceAccount`, `Team`, or any future identity model -- without schema changes. This note explains the schema, the
temporal-grant mechanism, the pivot class hierarchy, and the configuration seam that lets consumers rename everything.

## Invariants

1. **Any model can be an authorizable identity.** The `morphToMany` relation binds the pivot to the model's morph class
   and primary key at runtime. Integer, UUID, and ULID primary keys all work because the `authorizable_id` column is a
   `string` -- the widest common denominator that covers every key strategy Laravel supports.

2. **Each pivot table is structurally identical.** Every table carries `authorizable_type`, `authorizable_id`, the
   related entity's foreign key (`role_id`, `permission_id`, or `policy_id`), and a nullable `expires_at` timestamp. A
   unique composite index on `(entity_fk, authorizable_type, authorizable_id)` prevents duplicate grants, and a
   secondary index on `(authorizable_type, authorizable_id)` services the reverse lookup.

3. **The entity FK side carries a real foreign key; the authorizable side does not.** The migration adds
   `->foreign('role_id')->references('id')->on($rolesTable)->cascadeOnDelete()` (and the equivalent for permissions and
   policies). No FK constraint is possible on the `authorizable_id` column because the referenced table varies by morph
   class -- this is the fundamental trade-off of polymorphic pivots.

4. **Temporal grants are a pivot-level concern, not a model-level one.** A grant with `expires_at = null` is permanent.
   A grant with a future `expires_at` is live until the clock passes that instant, at which point the relation's
   `where()` clause filters it out on read. No sweeper job is required for correctness -- the package ships query-time
   filtering on every relation access.

## Schema

The `authorizable_roles` migration (the other two are structurally identical):

```php
Schema::create($table, static function (Blueprint $table) use ($rolesTable): void {
    $table->uuid('role_id');
    $table->string('authorizable_type');
    $table->string('authorizable_id');
    $table->timestamp('expires_at')->nullable();

    $table->unique(['role_id', 'authorizable_type', 'authorizable_id']);
    $table->index(['authorizable_type', 'authorizable_id']);
    $table->index('expires_at');

    $table->foreign('role_id')
        ->references('id')->on($rolesTable)->cascadeOnDelete();
});
```

## Pivot Class Hierarchy

A shared abstract base, `AuthorizableGrantPivot`, extends Laravel's `MorphPivot` and casts `expires_at` to `datetime`
so consumers inspecting `$role->pivot->expires_at` receive a `Carbon|null`. Three leaf subclasses exist -- one per
table:

- `AuthorizableRolePivot` -- bound via `->using(...)` on `HasRoles::roles()`.
- `AuthorizablePermissionPivot` -- bound via `->using(...)` on `HasPermissions::permissions()`.
- `AuthorizablePolicyPivot` -- bound via `->using(...)` on `HasPolicies::policies()`.

The per-table split is intentional even though the subclasses are currently empty. Future per-table fields -- tenant
scoping on roles, `granted_by` audit on permissions, an approval workflow on policy attachments -- land on the specific
subclass without leaking the cast surface across the other two tables.

## Configuration Seam

Every table name and pivot column name is configurable through the `authorization.tables.*` and
`authorization.pivots.*` config blocks. A consumer who needs to rename `authorizable_roles` to
`user_role_assignments` sets:

```php
'tables' => [
    'authorizable_roles' => 'user_role_assignments',
],
```

The pivot column names are similarly overridable per-table (type, id, FK, and `expires_at`), supporting legacy schemas
that use different naming conventions.

## Temporal Grant Mechanics

Each grant method (`assignRole`, `givePermission`, `attachPolicy`) accepts an optional `$expiresAt` parameter. The
relation's `where()` clause filters expired rows at query time -- rows whose `expires_at` is null or in the future are
included; everything else is invisible. The resolution cache honours this by inspecting the nearest `expires_at` across
pivot rows and capping the cache entry's lifetime accordingly, so a temporal grant that lapses at 3:00 PM does not
remain cached past 3:00 PM.

## Trade-offs

- **No FK on the authorizable side.** Orphaned pivot rows can accumulate when an identity model is deleted without
  cascading the pivot. Consumers should clean up via model events or a periodic sweep.
- **String `authorizable_id`.** Slightly wider than a typed integer column, but necessary to accommodate UUID, ULID,
  and integer keys in the same table without schema branching.
- **No sweeper shipped in v1.0.0.** Expired rows are invisible at query time but remain in the database. The
  `expires_at` index exists so a consumer-side purge job can `DELETE WHERE expires_at < NOW()` efficiently.

## Implementation Anchors

- `AuthorizableGrantPivot` -- shared base with the `expires_at` cast.
- `AuthorizableRolePivot`, `AuthorizablePermissionPivot`, `AuthorizablePolicyPivot` -- per-table leaf classes.
- `HasRoles::roles()`, `HasPermissions::permissions()`, `HasPolicies::policies()` -- the `morphToMany` definitions
  with `->using(...)` and the expiry filter `where()` clause.
- `ResolvesPivotExpiry` -- the shared trait that computes nearest-expiry TTL and reads raw pivot rows.

## Authoritative Tests

- `PolymorphicIdentityTest::testTwoDistinctIdentityModelsShareARole` -- two different morph types share a role via the
  same pivot table.
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
