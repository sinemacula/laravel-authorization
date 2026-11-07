# Bulk Checks

A check over many resources (AUTHZ-10.3) loads what the checks share once and reads the resources' own data in bulk,
never one query per resource. This note explains `checkMany()`, the one bulk decision (D22), and its adapters
`canEach()` and `filterAuthorized()`: why every check still takes the one decision path, what is read once and what in
bulk, the contracts through which a custom resolver or provider reads in bulk, the events and the last decision, and
the boundary within which a batch sees a write.

## Invariants

1. **One decision path.** `check()` is `checkMany()` given one check, and `checkMany()` decides each check through the
   decision pipeline exactly as a single check is decided: the same admission stages, the same `ResourceScope` and the
   same policy evaluator. Reading ahead only supplies data and never decides, so each decision, its effect, reason,
   stage, deciding references, requirements, freshness and trace, is the one `check()` would make under the same state.
   `canEach()` and `filterAuthorized()` adapt `checkMany()` and decide nothing of their own.

2. **Keys, order and occurrences.** The result of `checkMany()` and `canEach()` is keyed as the input is, in its order,
   with one entry for every check: a resource named twice is decided, recorded and reported twice. Reads are shared,
   never results or events. `filterAuthorized()` keeps the allowed resources' keys, order and objects, and returns a
   collection as a collection of its own class. An `insufficient_authentication` decision is a refusal for both
   adapters, as for `can()`. Neither stops at a denial, and an empty input returns an empty result.

3. **Refused before anything is decided.** A `checkMany()` input holding anything other than a `CheckInput` is refused
   with `InvalidCheckArgumentException::notACheck()` before any check is decided, recorded or reported.

4. **What is read once.** The subject is resolved once for the batch. What its grants, roles, policies, permission
   boundaries and session caps, the guardrails and the resource types' policies resolve to is read once in each scope
   (tenant and application) a check is decided in. The resolution cache does this: while a batch is open
   (`ResolutionCache::batch()`), the memo sets each scope's entries aside when the scope changes, keyed by
   `TenantScope::scopeKey()`, rather than dropping them, and takes them back when that scope is decided in again. A
   projection is never shared across scopes, and once the outermost batch closes, however it ends, the memo holds what
   it would have held without one.

5. **What is read in bulk.** For each chunk, before its first check is decided, the resources' tenants are read in
   bulk through `PrefetchedResourceTenants`, and the policies attached to the records through
   `DecisionPipeline::prepare()` and `ResourcePolicyResolver::policiesForMany()`: one query per type and scope, a
   record's own attachment winning over the same policy attached to its type, and a resource decided at platform scope
   outside its tenant keeping that tenant's denies alone, exactly as `policiesFor()` decides them. The records'
   attributes are read in bulk through `ResourceAttributeBatch` when the chunk's first check on a type reads
   `resource`. Reads are partitioned by connection, morph type and scope and keyed by type and key or by the model
   object, never by a bare id. A batch of one reads nothing ahead, so a single check reads exactly what it read before.

6. **Bulk is optional for extensions.** `Contracts\BulkResourceTenantResolver` (`tenantsOf()` and
   `tenantsOfRecords()`, keeping `null` for no tenant apart from `false` for one the resolver cannot tell) and
   `Contracts\BulkResourceAttributeProvider` (`valuesMany()`, keyed by item tokens) extend the single-item contracts.
   `DeclaredResourceTenant` and `NoResourceTenant` implement the tenant contract. A resolver or provider without the
   bulk contract is asked about each resource through its single-item method, so correctness holds but the
   one-query guarantee does not; a key left out of a bulk answer, or every key of a bulk call that throws, is asked
   about the same way.

7. **Failures stay with their item.** A resource whose tenant cannot be read fails its own check, when that check is
   reached. A bulk attribute answer may be an item's exception: it is thrown only when that item's own check reads
   `resource`, so it never changes another item's decision. Two models with the same key are two items, since each may
   hold other attributes in memory.

8. **One event per check, in order.** Each check is recorded as the last decision and dispatches its own
   `DecisionEvaluated`, with the payload `check()` gives it, as soon as it is decided and before the next is decided.
   There is no aggregate event. The last decision is the last check completed: an empty batch leaves it untouched, and
   a check that throws leaves the one before it. The tenant scope is restored in `finally` on every exception.

9. **The consistency boundary.** A batch sees a write as a sequence of `check()` calls in the same request would. An
   authorization write made while the batch runs (a grant, revocation, policy, attachment, boundary or guardrail
   change), by a listener reacting to an earlier check included, empties the resolution cache in every scope, so every
   later check reads it. The resources' tenants are read as a chunk starts and their attributes when the chunk first
   reads them, so a change to a resource's tenant or attributes made while a chunk is decided is seen from the next
   chunk.

10. **Bounded chunks.** The checks are decided in chunks of `authorization.bulk.chunk_size` (500 by default, a whole
    number of at least 1, validated at boot by `BulkConfigValidator`), and what a chunk read is released once it is
    decided; each decided item's attributes are released as it is decided. The decisions are all returned at once,
    so the result is not streamed: a caller deciding a very large set pages it.

## Success Path

`Authorization::canEach('posts:read', $pairs)` over 100 `[type, id]` pairs of one type in the active tenant builds 100
`CheckInput`s and decides them as one chunk. The tenants of the 100 records, which their model declares
(`QueryableResource`), are read by `DeclaredResourceTenant` in one query, the records' attachments are read in one query
and kept per record in the resolution cache, and the first check that reads `resource.status` asks the bulk provider for
all 100 at once. Each check is then decided in turn, through the tenant stage, the denies, the caps and the allows,
reading the subject's grants and policies from the memo after the first, and its decision is recorded and reported
before the next. The 100 checks cost the queries one costs.

## Failure / Edge Cases

- **A failing record.** A record whose tenant read throws, or whose attribute provider fails, throws when its own check
  is reached, as `check()` would: the checks before it are recorded and reported, the batch stops there, and nothing
  is returned.
- **A listener that writes.** A listener on `DecisionEvaluated` that revokes a grant makes every later check of the
  batch deny exactly as the next `check()` would.
- **Attributes asked ahead.** The first check on a type that reads `resource` asks the provider about every record of
  that type the chunk has still to decide, so a provider can be asked about a record whose own check never reads
  `resource`. That answer, value or exception, is used by no check, so no decision changes.
- **Reading one by one.** Record attachments are read one record at a time when the attachments table does not compare
  keys byte for byte (a case-folding collation, told by `SchemaInspector`), and a string-keyed declared record not
  found under its exact spelling is asked about on its own. Both keep each decision exact at the cost of the one-query
  guarantee; the package's own tables compare byte for byte.
- **Unreadable records.** A record whose identifier is not UTF-8, or whose attached document cannot be read, is left to
  its own check, so it fails or is logged exactly as on its own.
- **Unsaved models.** An unsaved model keeps `check()`'s semantics: one without a key denies as `resource_unresolved`.
- **A generator's repeated key.** An iterable that yields a key twice keeps the last resource under it.

## Implementation Anchors

- `AuthorizationManager::checkMany()`, `canEach()` and `filterAuthorized()` -- the methods; `check()` as a batch of one.
- `Evaluation\CheckInput` -- one check's action, resource and context.
- `Evaluation\CheckBatch` -- the refusal, the chunks, the bulk reads, each check decided and recorded in order.
- `Evaluation\DecisionPipeline::prepare()` and `Support\ResourceScope::prepare()` -- the attachments read ahead, by the
  scope each record is decided in.
- `Resolvers\ResourcePolicyResolver::policiesForMany()` and `Cache\ResolutionCache::rememberResourcePoliciesMany()` --
  the attachments read per type and scope and kept per record.
- `Support\PrefetchedResourceTenants`, `Contracts\BulkResourceTenantResolver` and
  `Resolvers\DeclaredResourceTenant` -- the tenants read in bulk.
- `Context\ResourceAttributeBatch` and `Contracts\BulkResourceAttributeProvider` -- the attributes read in bulk, kept
  per item.
- `Cache\ResolutionCache::batch()` and `Cache\ResolutionMemo` -- each scope's entries kept apart for the batch.
- `Config\BulkConfigValidator` -- the chunk size.
- `Concerns\HasPermissions` -- the `canEach()` and `filterAuthorized()` delegates.

## Authoritative Tests

- `ParityPropertyTest` -- generated batches across types, tenants, applications, expiry, roles, boundaries,
  guardrails, caps, overrides, attachments, bulk and single-item providers, duplicates, keys and unsaved models, each
  decision, event, last decision and exception compared with a fresh `check()`, with cold and warm caches (seeded by
  `AUTHZ_PARITY_SEED`, `AUTHZ_PARITY_RUNS` runs).
- `BulkCheckQueryBudgetTest` -- one resource and a hundred cost the same queries, one each for the tenants, the
  attachments and the attributes.
- `CheckBatchTest` -- event order and count, the last decision, a failure stopping the batch and restoring the scope,
  a provider's failure isolated, a grant revoked by a listener, chunking, the refusal and a single check reading
  nothing ahead.
- `AuthorizationManagerTest` -- keys, collections and generators, `insufficient_authentication` and the facade;
  `HasPermissionsTest` -- the delegates.
- `PrefetchedResourceTenantsTest`, `ResourceAttributeBatchTest`, `DeclaredResourceTenantTest`,
  `ResourcePolicyResolverTest`, `ResolutionMemoTest` and `ResolutionCacheTest` -- the bulk reads, their fallbacks and
  each scope kept apart.
- `BulkConfigValidatorTest` -- the chunk size.

## Change Triggers

- A second evaluator, or a bulk read that decides anything, breaks invariant 1 and the parity property.
- An aggregate event, a dispatch policy (BL-72) or a change to the event payload changes invariant 8 and the README.
- Reading a resource's tenant or attributes once for the whole batch, rather than per chunk, moves the consistency
  boundary of invariant 9 and must be documented.
- `permissionsFor()` (AUTHZ-10.4) introspects without recording; it must not change how `checkMany()` records.
