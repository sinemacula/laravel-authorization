# Access Reviews

## Purpose

Periodic access reviews and their sign-off need five lists no check gives (AUTHZ-11.6): who holds a role, permission or
policy in a scope, what a subject holds and where, which grants expire within a window, which grants an actor last
granted or changed, and which grants show no use. This note explains what a review means by "holds" (N93), the typed
query and its scope selections, the rows and their order, how a review is admitted (N96), how it is paged, streamed and
exported (part 2 of BL-69, N97, N98), how grant usage is tracked and reported (part 3, N94, N100 to N102), and what is
still left out.

## Invariants

1. **Grant routes, not effective access (N93).** A row is one route by which a subject holds a target through the
   stored grants: a direct grant; a role grant reaching a permission or policy through the role or a role above it,
   and a role held through a role below it, since a child role inherits its ancestors; a grant to an identity reaching
   its principal; a grant at the platform, an ancestor tenant or a subtree's root that applies in the reviewed tenant.
   A policy that only denies is held. Boundaries, guardrails and resource-policy attachments restrict or extend a
   decision but are not held, and no review lists them.

2. **Structural reads only (D22).** A review shares the structural predicates of forward resolution, never copies
   them: `LiveGrants::only()` for expiry, `TenantChain::grants()` for applicability, `TenantChain::owners()` for the
   definitions a tenant sees, `GrantRoots::within()` for a root within a tenant, `GrantApplications::only()` for an
   application, and `InlinePolicies::attachedToTheirGrantee()`. It never evaluates a statement, condition, deny or cap,
   so a holder may be denied what it holds; `check()`, `permissionsFor()` and a preview answer what a subject may do.

3. **Every edge live, every route kept.** A grant, a role's permission edge and a role's policy attachment count while
   `expires_at` is after the review's instant, frozen in UTC for the run; equality has expired. A role's policy reaches
   a holder only where the role's grant and the attachment hold together, as `RolePolicies` reads them in a check: in a
   review of what applies in a tenant both apply there, so only their applications must meet; in any other, their
   tenants must meet too (either the platform's, one tenant's, or one reaching below the other's tenant, the tree asked
   once for each pair in a run). Alternative routes through different roles are separate rows, each with its own
   `route_expires_at`, the earliest expiry of the rows it rests on.

4. **The hierarchy (`Reviews\Support\RoleChains`).** The holders of a role are found through the grants of every role
   below it, in one recursive query and one read of those roles, and what a role's holder holds through every role
   above it, in one recursive query and one read. A chain ends at a missing role, and, in a review applying in a tenant,
   at a role the tenant does not see, which holds nothing there itself. A chain that returns to a role it has passed
   refuses the review with `RoleHierarchyCycleException`, as a check refuses; the role service never writes one. With
   the hierarchy disabled a chain is its role alone.

5. **Scope selections, never an overloaded null.** `ReviewScope::appliesIn($tenant, $application)` reads what a check
   decided there reads (the platform's grants, the tenant's own, and an ancestor's reaching below; the platform's alone
   for no tenant), and only the roles and permissions the tenant sees. This is applicability, the opposite of
   `GrantScopeQuery`'s containment, which counts a tenant's own and those below it as within; a review never reuses
   containment as applicability. `rootedWithin($tenant)` reads the grants made at the tenant or below it, and
   `everywhere()` every stored grant. `ApplicationSelector::none()`, `named()` and `any()` say whether a review reads
   the grants of a check with no application, of one in a named application, or every grant.

6. **The queries (`Reviews\ReviewQuery`).** An immutable value, built from plain values, models and resolved subjects,
   never a request. `holders()` names a role, permission or policy; a permission means that definition, never a policy
   statement or wildcard grant that might authorise its action; a definition is named by its key, so two sharing a name
   under another guard or owner are never confused; a grant to an identity lists the identity, whose principals the
   directory lists only the other way round. `holdings()` given a resolved `Subject` is principal mode: the principal's
   grants and its identity's when `SubjectGrants::grantingIdentity()` says they reach it, naming it as `via_identity`,
   never a sibling principal's. Given an identity it is identity mode: the identity's grants and those of every
   principal the `IdentityDirectory` lists, each row keeping its actual grantee, and the result incomplete when the
   directory says its list may leave one out (N81). `expiring()` lists the stored grants, attachments and role edges
   whose expiry falls in the UTC half-open window `[from, until)`, a role's permission edge and its policy attachment
   kinds of their own, each marked `live`, `expired` or `malformed` at the review's instant. The bounds keep their
   microseconds: an expiry is stored to the whole second, its fraction dropped, so a bound with a fraction is compared
   as the next whole second, which selects exactly the stored expiries in the window on every database. In a review
   applying in a tenant, an edge is listed only when the tenant sees its role and permission, and a role's policy
   attachment only when it sees the role, as a check reaches either only through that role. `grantedBy()` lists the
   stored grants whose `granted_by` pair is exactly the actor's: the last writer (N95), since a regrant, a changed
   expiry or reach overwrites it, a trusted write names no actor, and a revoked grant is gone.

7. **Reference-only, versioned rows.** A `ReviewRow` names references alone (a morph type and a string key) and plain
   values, never a name, email, description, document or value. Its shape is `version: 1`: `row_key`, `subject`,
   `grantee`, `target`, `source_kind`, `source_key`, `origin_scope`, `via_identity`, `role_path`, `supporting_grants`,
   `created_at`, `updated_at`, `expires_at`, `route_expires_at`, `granted_by`, `grant_state` and `subject_state`. A
   stored row's key is built from the columns that make it unique (target, grantee, tenant and application; role and
   permission for an edge), each part length-prefixed so no two lists of parts share one. A subject is `inactive` when
   it, or the identity of a resolved subject, reports itself inactive or is deleted softly, `unknown` when its record
   is gone or its type names no model, read one query for each morph type among the rows returned; a resolved subject
   is weighed as given, its principal and identity models included. `isComplete` says only whether an identity's
   principals could all be listed, and is true for every other review.

   A grant or attachment row that names half a tenant (a type without a key, or a key without a type), which the
   package never writes, is listed and marked as damaged (N99), never presented as a clean platform origin: its
   `grant_state` is `malformed`, whether or not it has expired, and its `origin_scope` shows the tenant columns as
   stored (`Reviews\OriginScope`), the missing half null. It is listed exactly where a check reads it today: a check
   reads a key without a type at the platform, by its missing type alone, so such a row is listed wherever what applies
   is read, and a type without a key nowhere, so no review of what applies lists it. A review of everywhere, which
   needs platform-wide admission, lists a type without a key all the same, and so do its expiries and an actor's
   grants. No review rooted within a tenant lists either: a key without a type is read at the platform, and a type
   without a key cannot be shown to lie within the tenant, and a scoped review never discloses another tenant's
   holders (N96). A route resting on such a row is `malformed` too: one without a type meets an attachment, or a
   grant, as the platform's does, and one without a key meets only a row that holds everywhere. Forward resolution is
   unchanged; a later backlog item makes checks ignore these rows.

   | Stored tenant    | `appliesIn()` (any tenant, or the platform) | `rootedWithin()` (any tenant) | `everywhere()` |
   |------------------|---------------------------------------------|-------------------------------|----------------|
   | Key without type | Listed, read at the platform                | Not listed                    | Listed         |
   | Type without key | Not listed                                  | Not listed                    | Listed         |

   The same holds for holders, holdings, expiries and an actor's grants, each following its scope selection.

8. **One total order (`Reviews\Support\ReviewOrder`).** By source kind (in `SourceKind`'s declared order), target,
   grantee, origin scope and route (the first role of its chain, how many roles the chain runs through, then the keys
   of the rows it rests on: a chain runs up through one parent at a time, so these name a route among those of its
   stored row), each nullable component tagged so the platform comes before a tenant and every application before a
   named one, every string compared byte for byte: SQLite through its binary collation, PostgreSQL through `C`, MySQL
   as binary strings, PHP through `strcmp()`. A reference column is compared as it is stored wherever that is already
   byte for byte (bare on MySQL, whose reference columns are `utf8mb4_0900_bin`; only collated `C` on PostgreSQL), so
   an index on it serves the order; any other column is cast. The same rows come in the same order on every supported
   database.

9. **Bounded, on the writer, no query per holder.** A review returns at most its limit (`authorization.reviews.limit`,
   1000 by default and validated at boot as a whole number of at least 1, or `withLimit()`), reading at least one more
   to say exactly whether one was left out. The holders of a target are read a page at a time in the review's order,
   each page resuming by keyset after the last grant read (see invariant 15), never at an offset, and no larger than the
   room left (the limit and its one extra, less the rows held), so the grants read stay bounded by the limit; a grant
   adds one row for each carrying role or attachment in its chain, so the rows held may pass the limit and its one extra
   before they are cut. The roles a review involves are read first, then the grants of all of them together. For a
   policy, only the role grants that reach one of its attachments are read, the attachment's application, chain and
   subtree in the query, so a grant that would add no row is never read, and whether a page's grants meet the
   attachments in some tenant is settled in a fixed number of queries, one for each attachment's tenant, never one for
   each tenant a grant is held in. One subject's holdings are read whole, then sorted; an identity's principals a chunk
   of 500 at a time, so no query's bindings grow with them. Every read is on the package's write connection.

10. **Admission through `check()` (N96).** `authorization:review.read` and `authorization:review.export` are package
    permissions; exporting needs both. `AccessReview::review($query, $reviewer)` admits the review before anything is
    read: the reviewer's own manager, with its session, denies, boundaries, guardrails and the acting context's caps,
    decides the right on a `ReviewResource` (`authorization:review:{query}`, in the reviewed tenant), with the reviewed
    tenant, or the platform, and the named application, or none, in place. The resource's attributes (see
    `ReviewAttributes`) let policies restrict who may review what; no rank rule applies.

11. **A broad reach is administered whole.** A review of one tenant's node, in one application or in none, is decided
    there. At the administration stage of the same check, a review rooted within a tenant, applying at the platform or
    of everywhere is weighed by `AdministeredScope::refusalOf()`, the #122 rule, with no lock, rank or self rule: the
    right is decided again just below the reach's tenant, or at platform scope, and refused as `administration.scope`
    when anything that denies or caps the reviewer anywhere in the reach could limit it (`PossessionLimits`), a
    conditional deny included. The application dimension is treated as the tenant one: a review of any application
    applying in one tenant is decided at the tenant with no application, and is weighed across every application there,
    so a deny, boundary or guardrail held for one application refuses it, while a review of none or one application
    is not.

    An impersonated reviewer is weighed as a delegated change made while impersonating is: the impersonator is the
    one shown the disclosure, so the review resource names it (`resource.impersonated`, `impersonator_type`,
    `impersonator_id`), and the review is refused as `administration.impersonating` unless the reviewer is also
    allowed `authorization:administration.impersonated` on the same review.

12. **Refusal discloses nothing.** A refused review is recorded and reported as `authorize()` records and reports a
    refusal and throws `AuthorizationException` with the one generic line, carrying the reviewer's own decision, a
    step-up the right needs included; no row, count, truncation flag or completeness is computed.

13. **An explicit trusted path (N75).** `AccessReview::trusted($query)` runs a review as trusted system work, for a
    scheduled job or a command. Nothing falls back to it: `review()` always takes an `ActingContext`, and one that
    cannot be resolved is refused as `subject_unresolved` before a review is reached.

14. **Scoped disclosure.** A review admitted in a tenant reads only what applies there: an inherited grant, such as a
    platform grant or a parent's reaching below, is listed, but never the holders in other tenants it also reaches.

15. **Keyset paging (`Reviews\Support\Keyset`, `RowCollector`).** `AccessReview::page()` reads a review a page at a
    time over its one total order (invariant 8), never by offset, so a page costs the same queries whatever its number.
    A page's position is the sort key of the last row returned: the kind's position, the target, the stored row's
    grantee and scope (each nullable part tagged), then the route. A later page passes over every source whose kind
    comes before that row's without reading it; the source of that row's kind resumes from the stored row the row
    starts from, by a condition written column by column (greater, or equal and the rest after), each comparison byte
    for byte as the order sorts (`ReviewOrder::compared()`), a null before any value and false before true; on
    PostgreSQL the leading text columns are bounded together as a row too (`ReviewOrder::atLeast()`), which an index
    seeks by. A target's direct grants are all of the one target, so they are ordered and resumed by grantee and scope
    alone, from the stored row's own key, never the target as the query spells it; a target's key is read in its
    canonical lowercase form, so a key in capitals finds the same holders on every database. A grant
    through roles is read again from that row, one more than the room left, since it may carry routes still to come,
    and every route at or before the position is passed over; a stored row, one row of the review, resumes after itself.
    One subject's holdings are read whole for each page and the rows after the position kept, by design. `review()`
    is the first page of `page()`: every review, page, stream and export reads through one `AccessReview::read()`, one
    query construction, admission and projection (D22), and only shapes its pages differently.

16. **Signed cursors bound to their review (`Reviews\Support\ReviewCursor`).** A page's cursor carries its position
    between pages: its payload (the row schema version, the review's instant to the microsecond, and the sort key, each
    string part base64-encoded so any bytes survive) and an HMAC-SHA256 signature, keyed by a key derived from `app.key`
    for cursors alone, over the payload, the schema version with it, and over what the cursor is bound to: the query's
    kind, scope selection, tenant, application selector and name, target, subject (its principal and identity, and which
    mode), window, actor and `directOnly`, and the reviewer (its principal and impersonator) or the trusted path, each
    part length-prefixed. A sort key holds a fixed number of parts however deep the hierarchy runs (invariant 8), each a
    reference, scope value or stored row's key of at most 191 characters a part, so a cursor stays a few kilobytes, well
    under the 16384 characters read. A cursor is read only once its signature verifies, in constant time, for the query
    and reviewer it is presented with, and only in the one text that encodes it: each part must be exactly the
    canonical, unpadded base64url of its bytes, so a line break, padding, the standard alphabet or spare bits that are
    not zero are refused even where they decode to the same bytes. Anything else, a changed byte, another query, scope,
    reviewer or path, another schema version, a payload of another shape or no cursor at all, is refused with
    `InvalidReviewCursorException`, whose one message says nothing of why. The cursor discloses nothing a page did not:
    the parts of its sort key are references and scope values its last row shows. The limit is not bound. No key refuses
    to sign or read one (`MissingAppKeyException`); a review that fits on its first page issues none.

17. **Readmission and the frozen instant: a live scan.** Every page is admitted again before anything, its cursor
    included, is read, and a stream or an export is admitted before each chunk, so a right revoked, a step-up no longer
    met or a session cap that no longer covers the right between pages refuses the next. The review's instant is
    frozen when the first page is read (`ReviewPosition`) and carried to every later page, so each expiry is
    classified at the same instant throughout: a grant expiring between pages is still listed, and live, later. The
    scan is live, not a database snapshot: a row written or revoked between pages may appear or disappear, a row
    written where the scan has passed never appears and one written ahead of it does, but a row present for the whole
    scan is returned exactly once, in its place.

18. **Streams and JSON Lines exports (N97).** `stream()` returns a lazy iterable: nothing is read until it is iterated,
    then each chunk is read through the same pages, so memory is bounded by the chunk, not the tenant (the paging
    budget measures it against what was held before the stream began). `export()`
    writes versioned JSON Lines (`Reviews\Support\JsonLinesExport`) to a writable stream, each line written whole, or
    to a callback: a header (`record` `header`, `version`, the `query` kind, the `scope`, `reviewed_at`,
    `scan_started_at`, `consistency` `live`), one line a row (`record` `row` and the row's shape), and a footer
    (`record` `footer`, `version`, `rows`, `scan_ended_at`, `complete`). Each line is encoded with its keys in a fixed
    order, slashes and Unicode unescaped, the line and paragraph separators escaped, invalid UTF-8 refused rather than
    replaced, so the output is UTF-8 and the same bytes for the same rows at the same instants. Exporting needs both
    `authorization:review.read` and `authorization:review.export`, decided together before the header and again before
    every chunk; nothing is written before admission, and an export refused or failing part way has no footer.

19. **The console (`Console\ReviewCommand`).** `authorization:review` exports a review on the trusted path, as
    scheduled system work. Its scope options mirror `authorization:why` (`--tenant`, with `--rooted-within` and
    `--everywhere` beside it, at most one, and `--application` `none`, `any` or a name), with `--from` and `--until`,
    `--actor` and `--direct-only` taken by their own queries alone; a holdings subject is resolved by the console
    subject resolver. It writes nothing but the JSON Lines to the standard output, or to `--output`, created only when
    it does not exist unless `--force` is given, and exits as `authorization:why` does: 0 written, 2 for an invalid
    invocation, 1 when the review fails. Its errors name the argument or option alone, never a value given: a subject
    or tenant that is malformed, names no model or no saved row, or cannot be resolved included
    (`UnresolvedSubjectException::namingOnly()`).

20. **Indexes and what a page reads (N95).** A new migration, `2026_11_08_000001_add_access_review_indexes`, adds
    `{table}_granted_by_index` on the `granted_by` pair of each grant table, `{table}_permission_id_index` on the role
    permission edges, whose primary key leads with the role (MySQL already indexes that column for its foreign key and
    keeps that index), and, on PostgreSQL, `{table}_review_order_index` on each grant table's target and its grantee's
    type and key collated `C`. Checked against the review queries with `EXPLAIN` and measured by the paging budget. A
    page of a target's direct holders matches the target exactly and orders by grantee and scope, so it seeks to its
    keyset and reads no grant before it. On PostgreSQL the planner can walk the order index, sorting only each grantee's
    grants of the target (an incremental sort), and read about the rows it returns, or, for a target with few grants
    left, read those from the keyset on and sort them. On MySQL the unique index leads with the target and the grantee,
    whose columns compare their bytes, but holds digests of the tenant and application, not their values, so a page
    reads the target's grants from its keyset on and sorts them: its work grows with the target's grants after the page,
    never with those before it or with the tenant's. A page of routes through the roles below a target, of an expiry
    window (each table's `expires_at` index) or of an actor's grants (the new `granted_by` index) reads the rows its
    filter matches from its keyset on and sorts them, so its work grows with the rows those roles, that window or that
    actor match; only the sort's top rows are bounded by the page. A grantee's holdings are read on its morph index. The
    migration honours the configured table names and connection.

21. **Usage tracking is opt-in and free when off (N94).** `authorization.usage.enabled` is false by default. While it is
    off, no listener is registered, no usage table is read, the resolution cache keeps no routes, the manager hands its
    checks to no tracking pipeline, and the decision path costs what it did before (`SingleCheckBudgetTest`,
    `Performance\GrantUsageBudgetTest`); every row's `usage` reads `unknown`.

22. **What counts as use (N100).** An allowed decision a held permission allowed counts every live grant route behind
    every held permission covering the action, the subject's and its identity's when the identity grants to it,
    redundant ones included: the direct grant, each role grant that carried it with the ancestor role it reached (a
    `role_permission` route, its `role_grant` route and, for an ancestor, its `role_inherited` route), and the
    identity's grant. A decision one or more statements made, allow or deny, counts every route attaching the policy
    each belongs to, the subject's and its identity's, so a deny-only policy doing its job is used
    (`Usage\DecisionRoutes`). The everyday checks count: `check()`, `can()`, `cannot()`, `any()`, `all()`,
    `authorize()`, `checkMany()`, `canEach()`, the Gate, Blade and the middleware, and a delegated change's own check
    once its administration stage keeps the verdict. Nothing else does, each for a stated reason: a preview and its
    admission (another subject's decision, N86), an explanation and `authorization:why` (N89), `permissionsFor()`
    (introspection, N70), `whereAuthorized()` (decides no record), a review's admission and reads (introspection, N94),
    and the further checks of an administration stage. A permission from a custom `getPermissions()`, and a policy from
    a policy store, a resource, `withPolicies()`, a guardrail or a boundary, is no grant the package can trace, and
    counts nothing.

23. **Finding the contributing grants on the hot path.** While tracking is on, `GrantResolver::permissions()` and
    `policies()` resolve with the routes behind each permission, by its name, and each policy, by its key
    (`Usage\RouteSources`), read from the same rows in the same queries, each also reading where its grants were made
    and when (`RoleGraph::chainsWithin()`, `carriedWithin()`, a routed `RolePolicies::heldThrough()`), so they follow
    the same live and scope rules as the names. `ResolutionCache` keeps them beside the entry, in the memo and the
    store, under a routed kind of its own so an entry kept without them is never read for one; a warm check reads them
    from the memo with no query (`ResolutionCache::routesOf()`). `GrantProvenanceResolver`'s explain-only reads are
    never on this path. A resolution whose hierarchy moved while it ran keeps no routes, and its decisions count none.

24. **Recording (N101).** `Usage\GrantUsageRecorder`, one per worker, notes each route at most once a bucket
    (`authorization.usage.interval` seconds, 3600 by default, at least 60, a whole multiple since the epoch in UTC),
    forgetting what it noted as a bucket begins and past ten batches' worth, and sends what it noted as one queued
    `Usage\RecordGrantUsage` job on the application's `terminating` and after each queued job, processed or failed, or
    once it holds `authorization.usage.batch` observations, on the configured connection and queue. A refused dispatch
    is written to the log channel and never reaches the decision; a check never waits on the store.

25. **Storage (N102).** `Contracts\GrantUsageStore` (`record()`, `lastObserved()`, `coverage()`), bound to
    `Usage\DatabaseGrantUsageStore` and rebindable. `authorization_grant_usage` is keyed by the route's key
    (`Usage\GrantUsageKey`: a SHA-256 digest of the source kind, target, grantee, tenant and application as stored, and
    the reach, the roles the route runs through; the same key a review row of the route carries), keeps the stored
    grant's unique columns, its creation when observed and the last bucket; a write is made only when the observation
    is newer (the grant's creation first, then the bucket), compared in the update itself, so duplicate and
    out-of-order delivery change nothing. `authorization_usage_coverage` holds the periods tracking was on, each flush
    extending the latest or opening one when the gap exceeds two intervals; `authorization:usage-heartbeat` does the
    same with no observations, and records nothing while tracking is off. `authorization:usage-prune` removes the usage
    of routes whose grant no longer exists and the coverage older than `authorization.usage.retention` days.

26. **Regrants.** A grant revoked and made again is a new row created later; an observation through a grant created
    before the current one is ignored (`ObservedUse::isOf()`), and a regrant's observation replaces the old one in the
    store. An expiry or reach rewrite (`GrantTable::writeExpiry()`) keeps `created_at`, and the reach a grant's
    `include_subtree` sets is no part of the key, so the grant keeps its use.

27. **The unused review and the `usage` field (N94).** `ReviewQuery::unused($scope, $since)` reads the live grants of
    each kind to grantees through `StoredRows` a page of the room left at a time, each page's routes looked up in one
    go, keeping the rows with no observed use (`ReviewUsage::isUnobserved()`); it pages, streams and exports as every
    review does, admitted by `authorization:review.read`. Every row gains `usage { status, last_observed_at,
    coverage_from, coverage_until }` (`Reviews\RowUsage`), filled in one batched lookup per page
    (`Reviews\Support\ReviewUsage`): `used` when observed in a bucket ending after the window starts, the window
    running from the later of `since` and the grant's creation to the review's instant; `unused` only when coverage,
    each period taken to reach two intervals past its end, covers the whole window; `unknown` otherwise, while tracking
    is off, and for a row whose source cannot report. A null `last_observed_at` is never proof of non-use. The row keeps
    `version: 1`, since the package is unreleased.

## Success Path

```php
$reviews = app(AccessReview::class);
$scope   = ReviewScope::appliesIn($account, ApplicationSelector::named('admin'));

$holders  = $reviews->review(ReviewQuery::holders($editor, $scope), ActingContext::current());
$holdings = $reviews->review(ReviewQuery::holdings($identity, ReviewScope::rootedWithin($organisation)), $auditor);
$expiring = $reviews->trusted(ReviewQuery::expiring(ReviewScope::everywhere(), now(), now()->addMonth()));

$page = $reviews->page(ReviewQuery::holders($editor, $scope), ActingContext::current(), null, 250);
$next = $reviews->page(ReviewQuery::holders($editor, $scope), ActingContext::current(), $page->nextCursor, 250);

foreach ($reviews->stream(ReviewQuery::holders($editor, $scope), ActingContext::current()) as $row) {
    // one chunk at a time
}

$reviews->export(ReviewQuery::holders($editor, $scope), $auditor, \fopen('holders.jsonl', 'xb'));

$unused = $reviews->review(ReviewQuery::unused($scope, now()->subDays(90)), ActingContext::current());
```

An auditor allowed `authorization:review.read` in the account reviews who holds `editor` there: the direct grants,
then the grants of every role below `editor`, each with its role path, the platform's and the organisation's grants
reaching the account included, nothing granted in a sibling account. A scheduled job lists what expires next month,
across every tenant, as trusted work. The holders are read 250 at a time, each page admitted again and resumed from the
cursor the page before returned, streamed a chunk at a time, or exported as JSON Lines by an auditor holding both review
rights. With usage tracking on, the auditor lists the account's grants nobody used in ninety days, each `unused` where
tracking covered the whole window and `unknown` where it did not.

## Failure / Edge Cases

- A reviewer allowed the right at an organisation's node alone, or denied it in one account, is refused a review rooted
  within the organisation as `administration.scope`, and a review of everywhere likewise.
- A session cap that does not cover the right, or an unmet step-up, refuses the review as an ordinary check would.
- A role permission edge or a role's policy attachment that has expired carries nothing, and a role's policy attached in
  one application or tenant reaches no holder whose grant holds elsewhere.
- A stored hierarchy cycle refuses the review; a role whose owner moved out of the reviewed tenant's chain ends a chain
  there.
- An inactive or deleted-softly holder keeps its rows, marked `inactive`, whether it is read by reference or given as a
  resolved subject; a grant to a grantee whose record is gone is listed as `unknown`.
- A target whose key no definition could have (every definition is keyed by a UUID) is held by no one, on every
  database, without a query, rather than reaching a `uuid` column it cannot be compared with.
- A grant or attachment row naming half a tenant is listed where a check reads it, and a type without a key in a
  review of everywhere too, never in one rooted within a tenant; either is marked `malformed`, its origin scope as
  stored.
- A window whose bounds fall within one second holds no stored expiry, since every expiry is a whole second.
- A cursor changed in any byte, written in any text but its canonical one, issued for another query, scope, reviewer
  or the trusted path, or of another schema version is refused with `InvalidReviewCursorException`; a page of a
  reviewer who lost the right is refused with `AuthorizationException` before its cursor is read.
- A review through a hierarchy hundreds of roles deep pages to its end with cursors of a few kilobytes, since a route
  is keyed by its first role and its length, not by every role it runs through.
- An export without `authorization:review.export` beside the read right is refused before its header is written; one
  refused at a later chunk, or failing, ends with no footer; a sink that is neither a stream nor a callback is refused
  with `InvalidArgumentException`, a stream that takes none of a line with `RuntimeException`, and a row holding
  invalid UTF-8 with `JsonException`.
- A grant created before tracking began, a window a gap of more than two intervals interrupts, a grantee with its own
  `getPermissions()` or `getPolicies()`, and a role's edge or attachment read `unknown`, never `unused`; a regrant reads
  as unused until it is used, whatever the grant it replaced did.
- A queue that refuses the recording job is written to the log and its observations lost, the decision unaffected; a
  worker's latest observations reach the store only when it next sends them.
- A window that does not end after it starts, a limit below one, a target that is no definition, and a subject that
  names no key are refused with `InvalidArgumentException` when the query is built. A configured limit that is not a
  whole number of at least 1 is refused at boot with `InvalidAuthorizationConfigException`, and so is one changed
  after boot when a review reads it.

## Implementation Anchors

- `Reviews\AccessReview` -- `review()`, `page()`, `stream()`, `export()`, their trusted counterparts and the one read.
- `Reviews\ReviewPage`, `Reviews\Support\ReviewPosition`, `Reviews\Support\PageRead` -- a page, where a review
  stands, and a page as read.
- `Reviews\Support\ReviewCursor`, `Exceptions\InvalidReviewCursorException` -- the signed cursors and their refusal.
- `Reviews\Support\Keyset`, `Reviews\Support\GrantRows::after()` -- the keyset a page resumes from.
- `Reviews\Support\JsonLinesExport` -- the JSON Lines format and its sinks.
- `Console\ReviewCommand`, `Console\Support\ReviewInvocation`, `Console\Support\TenantOption`,
  `Console\Concerns\RefusesInvocations` -- `authorization:review`.
- `database/migrations/2026_11_08_000001_add_access_review_indexes.php` -- the review indexes.
- `Reviews\ReviewQuery`, `Reviews\ReviewScope`, `Reviews\ApplicationSelector` -- the typed, immutable inputs.
- `Reviews\ReviewRow`, `Reviews\SupportingGrant`, `Reviews\OriginScope`, `Reviews\ReviewResult` -- the versioned
  output.
- `Reviews\ReviewResource`, `Reviews\ReviewAttributes`, `Reviews\ReviewAdmission` -- the admission, and the
  administration stage `Evaluation\DecisionPipeline::decideGrants()` runs for a review resource.
- `Administration\AdministeredScope::refusalOf()` -- the reach rule shared with delegated administration.
- `Reviews\Support\ReviewRun` -- the scope and instant of one run, and the structural predicates.
- `Reviews\Support\TenantRelations` -- whether role grants and attachments meet in some tenant, in a fixed number of
  queries.
- `Config\ReviewConfigValidator` -- the boot-time validation of `authorization.reviews`.
- `Reviews\Support\HolderRoutes`, `HoldingRoutes`, `StoredRows` -- the five queries.
- `Reviews\Support\RoleChains`, `RoleCarriers` -- the hierarchy and what roles carry.
- `Reviews\Support\GrantRows`, `GrantRow`, `RowCollector`, `ReviewOrder`, `SubjectStates`, `Definitions` -- the reads,
  the rows, the bound and the order.
- `Usage\DecisionRoutes`, `Usage\RouteSources`, `Usage\GrantRoute`, `Usage\StoredGrant`, `Usage\GrantUsageKey` --
  what a decision used, and the routes a resolution keeps beside the cache entry.
- `Usage\GrantUsageRecorder`, `Usage\RecordGrantUsage`, `Usage\UsageBatch`, `Registrars\UsageRegistrar`,
  `Usage\UsageTracking`, `Config\UsageConfigValidator` -- bucketing, flushing and the settings.
- `Contracts\GrantUsageStore`, `Usage\DatabaseGrantUsageStore`, `Usage\UsagePruner`, `Console\UsageHeartbeatCommand`,
  `Console\UsagePruneCommand`, `database/migrations/2026_11_09_000001_create_grant_usage_tables.php` -- storage,
  coverage and pruning.
- `Reviews\Support\ReviewUsage`, `Reviews\RowUsage`, `Reviews\Enums\UsageStatus`, `StoredRows::unused()` -- the
  `usage` field and the unused review.

## Authoritative Tests

- `Reviews\Support\HolderRoutesTest` (Feature) -- direct and inherited roles, permissions and policies through roles and
  ancestors, alternative routes, the hierarchy off, expired edges, intersecting and non-intersecting role policies,
  deny-only policies held, boundaries and resource policies excluded, unseen ancestors, cycles, name collisions.
- `Reviews\Support\HoldingRoutesTest` (Feature) -- own and identity grants, sibling isolation, machines and persons,
  identity mode with complete and incomplete directories, inactive subjects, applicability and roots.
- `Reviews\Support\StoredRowsTest` (Feature) -- every stored kind, the half-open UTC window, non-UTC bounds, dates
  beyond 2038, expired rows, scopes for edges, and the last writer after an actor replacement.
- `Reviews\ReviewAdmissionTest` (Feature) -- the tenant, the subtree and the platform, a child's deny blocking a broad
  review, one application's deny blocking a review of any application, an impersonated reviewer, caps and step-up,
  policies on the attributes, refusals reported and disclosing nothing, scoped disclosure, no manager bound.
- `Reviews\Support\TenantRelationsTest` (Feature) -- grants and attachments meeting in some tenant, settled in a fixed
  number of queries a chunk at a time, written into a grant query, and a subtree that cannot be nested.
- `Config\ReviewConfigValidatorTest` (Unit) -- the boot-time validation of the review limit.
- `Reviews\AccessReviewTest` (Feature) -- trusted and admitted runs, the unresolved reviewer, exact truncation, the
  byte-order total order with unusual references and nullable scopes, the reference-only sentinel, subject states and
  the write connection.
- `Reviews\Support\ReviewRunTest`, `ReviewOrderTest` (Feature) -- applicability against containment, application
  selection, the frozen instant and the byte order on every database.
- `Performance\AccessReviewQueryBudgetTest` -- no query growth with holders, grants, rows, the tenants grants are held
  in, or grants that reach no attachment.
- `Reviews\AccessReviewTest` (Feature) -- pages by cursor to the last, the page limit, cursors serving their own review
  alone, the frozen instant, a right revoked between pages, the live scan, lazy streams admitted per chunk, the exact
  export shape, the export right beside read, determinism and the reference-only sentinel, a step-up or cap part way.
- `Integration\Reviews\ReviewPagingParityTest` -- the whole review, its pages, streams and export alike for every query
  and scope, with nullable scopes, rows naming half a tenant and unusual references, on every database.
- `Reviews\Support\KeysetTest`, `ReviewCursorTest`, `JsonLinesExportTest` (Feature) -- keyset boundaries on equal
  prefixes and nullable parts; signing and every refusal; the format and its sinks.
- `ReviewCommandTest`, `ReviewInvocationTest` (Feature) -- every option, refusal and exit code, `--output` and
  `--force`, JSON-only standard output.
- `Database\ReviewIndexesMigrationTest` (Feature) -- the indexes created and dropped cleanly on custom table names, on
  every database.
- `Performance\AccessReviewPagingBudgetTest` -- five thousand holders across fifty nested tenants and a deep hierarchy:
  the same queries on every page, none at an offset, and a stream's memory bounded by its chunk.
- `Usage\AuthorizationManagerTest`, `Usage\DecisionPipelineTest`, `Usage\DecisionRoutesTest` (Feature) -- every
  route behind an allow, redundant ones included; a deny-only policy; every everyday form counting and every excluded
  path counting nothing; a warm check with no query; an administration stage that refuses; a queue failure.
- `Usage\GrantUsageRecorderTest`, `Usage\UsageRegistrarTest`, `Usage\RecordGrantUsageTest` (Feature) -- bucketing and
  deduplication, one job per request, the size cap and a bounded worker, the flush hooks only while tracking is on.
- `Usage\DatabaseGrantUsageStoreTest`, `Usage\UsagePrunerTest`, `Usage\UsageHeartbeatCommandTest`,
  `Usage\UsagePruneCommandTest` (Feature) -- monotonic, idempotent writes, regrant ordering, coverage periods opening
  and extending, the heartbeat, pruning, on every database.
- `Usage\AccessReviewTest`, `Usage\ReviewUsageTest` (Feature) -- used, unused and unknown, a window before tracking
  began, regrants against rewrites, the unused review paged, streamed and exported with one lookup a page, a rebound
  store, a grantee that cannot report.
- `Usage\RouteSourcesTest`, `Usage\GrantResolverTest`, `Usage\ResolutionCacheTest` (Feature) -- the routes a
  resolution keeps match the review's keys, in the same queries, kept beside the entry and never read from one kept
  without them.
- `Performance\GrantUsageBudgetTest` -- a tracked cold check reads what an untracked one does, and warm tracked checks
  read nothing and keep within the single-check budget.

## Change Triggers

- A change to the row shape or the sort key bumps `ReviewRow::VERSION`, which refuses every cursor issued before it.
- A snapshot export, or a CSV adapter (N97), would be a mode or sink of its own beside the live JSON Lines.
- A new path that decides without acting on the decision (an introspection or a dry run) must keep its pipeline
  untracked, as previews, explanations, listings, scoped queries and reviews are.
- A change to what makes a grant route unique, or to a review row's route, changes `GrantUsageKey`, which forgets every
  use recorded under the old keys.
- A paged identity directory would let identity mode stream very large identities.
- Listing boundaries, guardrails or resource policies would need rows labelled as restrictions, never as holdings.
