# Access reviews

`AccessReview` lists, for periodic reviews and their sign-off (AUTHZ-11.6), who holds a role, a permission or a policy
in a scope, what a subject holds and where, which grants expire within a window, which grants an actor last granted or
changed, and, with [usage tracking](#usage-tracking) on, which grants show no use. Resolve it from the container, where
it is a singleton, and run a typed `ReviewQuery`:

```php
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;

$reviews = app(AccessReview::class);
$scope   = ReviewScope::appliesIn($account, ApplicationSelector::named('admin'));

$result = $reviews->review(ReviewQuery::holders($editor, $scope), ActingContext::current());

$result->rows;        // list<ReviewRow>, in one deterministic order
$result->isTruncated; // true only when a row was left out by the limit
$result->isComplete;  // false only when an identity's principals could not all be listed
$result->toArray();   // each row in its versioned shape

$result->isStoredInventoryOnly; // true only for a review narrowed to an action (see below)

$reviews->trusted(ReviewQuery::expiring(ReviewScope::everywhere(), now(), now()->addMonth())); // a scheduled job
```

**What "holds" means.** A review lists grant routes, never effective access: one row for each route by which a subject
holds a target through the stored grants. A route is a direct grant; a role grant reaching a permission or a policy
through the role or a role above it, and a role held through a role below it; a grant to an identity reaching its
principal; and a grant made at the platform, in an ancestor tenant or at a subtree's root that applies in the reviewed
tenant. Every row a route rests on must be live at the review's instant (an expiry equal to the instant has passed), and
a role's policy reaches its holder only where the role's grant and the attachment hold together, in the same tenant and
application, as a check reads them. Alternative routes through different roles are separate rows, each with its own
`route_expires_at`, so the earliest is not when the holding ends. A policy that only denies is held. A review reads
structure alone, with the same tenant chain, application matching, live-grant and definition-visibility rules a check
reads, and never evaluates a statement, condition, deny or cap, so a holder may well be denied what it holds: for what a
subject may actually do, use `check()`, [`permissionsFor()`](checking-access.md#effective-permissions) or a
[preview](preview-and-explanations.md#preview). A suspended, inactive or soft-deleted subject keeps its live grants in a
review, marked `inactive`, whether it is named by reference or given as a resolved `Subject`, or `unknown` when its
record is gone.

A grant or attachment row that names half a tenant (a type without a key, or the reverse), which the package never
writes, is listed as damaged, never as a clean platform origin: its `grant_state` is `malformed` and its `origin_scope`
shows the tenant columns as stored, the missing half null. A check applies what grants of such a row nowhere and what
restricts of it everywhere (see [Managing roles, permissions and
grants](grants.md#managing-roles-permissions-and-grants)), so it is never a placed grant of a review of what applies; a
review of everywhere, which needs platform-wide admission, lists it all the same, and no review rooted within a tenant
does, since it cannot be shown to lie there. A route resting on such a row is `malformed` too, and reaches a holder only
through a row that holds everywhere.

| Stored tenant    | `appliesIn()` (any tenant, or the platform) | `rootedWithin()` (any tenant) | `everywhere()` |
|------------------|---------------------------------------------|-------------------------------|----------------|
| Key without type | Not listed                                  | Not listed                    | Listed         |
| Type without key | Not listed                                  | Not listed                    | Listed         |

Holders, holdings, expiries and an actor's grants each follow their scope selection.

**The queries.**

| Query                                            | Lists                                                                                                  |
|--------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `ReviewQuery::holders($target, $scope, $direct)` | Every route to a role, permission or policy (a model or reference), or its direct grants alone         |
| `ReviewQuery::holdings($subject, $scope)`        | A `Subject`'s own grants and its identity's that reach it; or an identity's and its listed principals' |
| `ReviewQuery::expiring($scope, $from, $until)`   | Grants, attachments and role permission edges expiring within `[from, until)`, in UTC                  |
| `ReviewQuery::grantedBy($actor, $scope)`         | Grants whose `granted_by` pair is exactly the actor's                                                  |
| `ReviewQuery::unused($scope, $since)`            | Live grants with no observed use since the instant (see [Usage tracking](#usage-tracking))             |
| `forAction($action)`                             | Of holdings, the routes giving the action (see [below](#where-a-subject-holds-an-action))              |
| `withLimit($limit)`                              | The same review returning at most that many rows                                                       |

A permission target means that definition, never a policy statement or wildcard grant that might authorise its action,
and a definition is named by its key, so two sharing a name under another guard or owner are never confused. Holders are
the grantees the grants name: a grant to an identity lists the identity, not its principals. In principal mode
(`holdings()` given a resolved `Subject`) the identity's grants are listed only when they reach the principal (both
machines or neither), each naming the identity as `via_identity`, and a sibling principal's never are. In identity mode
(`holdings()` given an identity's model or reference) the identity's grants and those of every principal the identity
directory lists are read, each row keeping its actual grantee, and `isComplete` is false when the directory says its
list may leave one out; `isComplete` says nothing else, and is true for every other review. Expiring rows are stored
rows, not routes, each marked `live`, `expired` or `malformed` at the review's instant; a role's permission edge and its
policy attachment are kinds of their own. The window's bounds keep their microseconds: an expiry is stored to the whole
second, so a bound with a fraction is compared as the next whole second, which lists exactly the expiries within it.
"Granted by" means the last writer: a regrant, a changed expiry or a changed reach overwrites it, a trusted write names
no actor, and a revoked grant is gone, so the history stays with the audit log the grant events feed.

**The scope.** Each selection is a value of its own, never a null that could mean two things:

| Scope                                      | Reads                                                                                                                     |
|--------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| `ReviewScope::appliesIn($tenant, $app)`    | What a check in the tenant reads: the platform's, the tenant's own and an ancestor's reaching below; null is the platform |
| `ReviewScope::rootedWithin($tenant, $app)` | The grants made in the tenant or below it, wherever else they reach                                                       |
| `ReviewScope::everywhere($app)`            | Every stored grant                                                                                                        |
| `ApplicationSelector::none()`              | The grants for every application, as a check with no application reads them                                               |
| `ApplicationSelector::named($app)`         | Those and the grants for the application named                                                                            |
| `ApplicationSelector::any()`               | Every grant, whatever its application (the default for `rootedWithin()` and `everywhere()`)                               |

Applicability is not containment: a review applying in a tenant includes the platform's grants and an ancestor's that
reach below, never a child's, which is the opposite of what the [grant scope query](administration.md#grant-scope-query)
counts as within. In a review applying in a tenant, only the roles and permissions the tenant sees count, and a role it
does not see ends a hierarchy chain, as in a check. A review admitted in a tenant shows the inherited grants that apply
there, such as a platform grant, but never the holders in other tenants those grants also reach.

**The rows.** A row names references alone, each a morph type and a string key, never a name, email, description,
document or value. Its shape is versioned (`version: 1`):

| Field                                    | Holds                                                                                        |
|------------------------------------------|----------------------------------------------------------------------------------------------|
| `row_key`                                | A key of the route, the same every time                                                      |
| `subject`, `grantee`, `target`           | Who holds it, whom the stored grant names, and the role, permission or policy held           |
| `source_kind`, `source_key`              | The kind of stored row the route starts from, and its key                                    |
| `origin_scope`                           | That row's tenant as stored (null for the platform), application (null for every one), reach |
| `via_identity`, `role_path`              | The identity a grant reaches the subject through, and the roles from the one granted upwards |
| `supporting_grants`                      | Every stored row the route rests on, each with its key, scope and expiry                     |
| `created_at`, `updated_at`, `expires_at` | The starting row's times, in UTC                                                             |
| `route_expires_at`                       | The earliest expiry of every row the route rests on                                          |
| `granted_by`                             | The last actor to grant or change the starting row; null for a trusted write                 |
| `grant_state`, `subject_state`           | `live`, `expired` or `malformed`; `active`, `inactive` or `unknown`                          |
| `usage`                                  | `status` (`used`, `unused` or `unknown`), the last observed use and the coverage             |
| `break_glass`                            | Only on a route from a break-glass activation, its key and justification code                |
| `action_evidence`                        | Only in a review narrowed to an action, what gives it and where (see below)                  |

The rows come in one total order, the same on SQLite, PostgreSQL and MySQL: by source kind, target, grantee, origin
scope (the platform before a tenant, every application before a named one, a role grant before a break-glass
activation of the same scope, and activations by key) and route (the first role of its chain, how many roles the chain
runs through, then the rows it rests on), every string compared byte for byte. A review returns at
most `authorization.reviews.limit` rows (1000 by default; a whole number of at least 1, or boot fails), or the limit
`withLimit()` sets, and reads at least one more to say exactly whether any was left out. Every grant is read on the
write connection, never one query per holder: the roles a review involves are read in a fixed number of queries, then
the grants of all of them together, a page of the limit at a time. Each grant read adds a row for every carrying role or
attachment in its chain, so a page may hold more rows than the limit before they are cut. For a policy, only the role
grants that reach one of its attachments are read, and whether they meet in some tenant is settled once for each
attachment's tenant, never once for each tenant a grant is held in. One subject's holdings are read whole, an identity's
principals 500 at a time.

**The review rights.** The package declares `authorization:review.read`, the right to run a review, and
`authorization:review.export`, the right to export one, which needs both. `review()` admits the review before anything
is read, through `check()` as the reviewer, with its real session, denies, boundaries, guardrails and caps, on a review
resource `authorization:review:{query}` in the reviewed tenant and application. No rank rule applies, and policies read
these keys of it to restrict who may review what:

| Key                                                                               | Value                                                                               |
|-----------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `resource.id`, `resource.type`                                                    | The query (`holders`, `holdings`, `expiring`, `granted_by`), `authorization:review` |
| `resource.tenant.type`, `resource.tenant.id`                                      | The reviewed tenant; missing for the platform and everywhere                        |
| `resource.query`, `resource.scope`                                                | The query, and `applies_in`, `rooted_within` or `everywhere`                        |
| `resource.application_selection`, `resource.application`                          | `none`, `named` or `any`, and the application named                                 |
| `resource.target_type`, `resource.target_id`                                      | The role, permission or policy whose holders are listed                             |
| `resource.subject_type`, `resource.subject_id`                                    | The principal or identity whose holdings are listed                                 |
| `resource.actor_type`, `resource.actor_id`                                        | The actor whose last grants are listed                                              |
| `resource.impersonated`, `resource.impersonator_type`, `resource.impersonator_id` | Whether the reviewer is impersonated, and by whom                                   |

A review of one tenant, in one application or none, is decided at that tenant. A review across a reach, rooted within a
tenant, applying at the platform or of everywhere, is decided again across the reach by the rule delegated
administration uses: just below the reach's tenant, where only a right that reaches below counts, or at platform scope,
and refused as `administration.scope` when anything that denies or caps the reviewer anywhere in the reach could limit
the right, a conditional deny included. So a deny the reviewer holds in one child tenant refuses a review of its
parent's subtree. Applications are weighed the same way: a review of `ApplicationSelector::any()` in one tenant needs
the right held for every application, and is refused when a deny, boundary or guardrail held for any one application
could limit it. A review run while the reviewer is impersonated (`ActingContext::impersonatedBy()`) is refused as
`administration.impersonating` unless the reviewer is also allowed `authorization:administration.impersonated` on it,
across the review's whole reach by the same rule, as a delegated change is, since the impersonator is the one shown what
it discloses. A refused review throws `AuthorizationException` with the one generic line, carrying the reviewer's own
decision (a step-up the right needs included), after recording and reporting it as any refused check, and discloses no
row, count, truncation or completeness.

**The trusted path.** `trusted()` runs a review as trusted system work, for a scheduled job or a command, with no
reviewer and no admission. Nothing falls back to it: `review()` always takes an acting context, and one that cannot be
resolved is refused before the review is reached.

**Paging.** `page()` reads a review a page at a time, and `trustedPage()` as trusted work:

```php
$query  = ReviewQuery::holders($editor, ReviewScope::rootedWithin($organisation));
$cursor = null;

do {
    $page = $reviews->page($query, ActingContext::current(), $cursor, limit: 250);

    foreach ($page->rows as $row) {
        // ...
    }

    $cursor = $page->nextCursor;
} while ($cursor !== null);
```

| `ReviewPage` | Holds                                                                                                 |
|--------------|-------------------------------------------------------------------------------------------------------|
| `rows`       | At most the page's limit of rows (the query's own, `withLimit()` or the configured one, unless given) |
| `nextCursor` | The cursor of the next page; null on the last, so a page followed by no row ends the review           |
| `reviewedAt` | The review's instant, frozen when its first page is read and the same on every page                   |
| `isComplete` | As a result's: false only when an identity's principals could not all be listed                       |
| `isLast()`   | Whether `nextCursor` is null                                                                          |

A page of a review narrowed to an action also says `isStoredInventoryOnly`, as its result does.

A page resumes after the last row of the page before by keyset over the review's one order, never at an offset, so a
page costs the same queries whatever its number, and `review()` is simply the first page of `page()`, through the same
query, admission and rows. A page of a target's direct holders seeks to its keyset through an index leading with the
target and the grantee, and reads no grant before it: on PostgreSQL, the planner can walk the review index in the page's
order and read about the rows it returns; on MySQL, whose index on the target holds digests of the tenant and
application, it reads the target's grants from its keyset on and sorts them for the page, so its work grows with the
target's grants after the page, never with the tenant's. A page of routes through the roles below a target, of an expiry
window or of an actor's grants reads the rows its filter matches from its keyset on and sorts them, so its work grows
with the rows that target's roles, window or actor match; only the sort's top rows are bounded by the page. Every page
is admitted again before anything, its cursor included, is read, so a right revoked between pages refuses the next one
with `AuthorizationException`.

**Cursors.** A cursor is opaque and tamper-evident: an HMAC-SHA256 signature, keyed from the application key
(`app.key`), over its payload and over what it is bound to: the query (its kind, target or subject, scope selection,
tenant, application selector, window, actor, `directOnly` and the action a review of holdings is narrowed to) and the
reviewer (its principal and any impersonator) or the trusted path. Its payload holds the row schema version, the
review's instant and the sort key of the last row returned, whose parts are the references and scope values that row
already shows, never a name or a value; a route is keyed by its first role and its length, so a cursor stays a few
kilobytes at most however deep the role hierarchy runs. A cursor is read only in the one text that encodes it, each part
the canonical, unpadded base64url of its bytes. A cursor used with another query, scope or reviewer, a trusted cursor
given to a reviewer and the reverse, one of another schema version, and one changed in any byte, even to text that
decodes to the same bytes, are each refused with `InvalidReviewCursorException`, whose one message says nothing of why.
The limit is not bound, so a client may change its page size between pages. Signing a cursor needs the application key;
without one, `MissingAppKeyException` is thrown when a cursor is issued or read, and a review that fits on one page
needs none.

**The consistency mode: a live scan.** The review's instant is frozen when its first page is read and carried by the
cursor, so every page classifies each expiry at that instant: a grant that expires between pages is still listed, and
still `live`, on a later page. It is not a database snapshot: a row written or revoked between pages may appear or
disappear (a row written where the scan has already passed is never returned, one written ahead of it is), but a row
present for the whole scan is returned exactly once, in its place in the order.

**Streaming.** `stream($query, $reviewer, $chunk = 1000)` and `trustedStream($query, $chunk)` return a lazy iterable of
every row: nothing is read until it is iterated, then each chunk is read through the same keyset pages, and the
reviewer is admitted again before each, so a refusal part way throws `AuthorizationException` from the iteration. What
a stream holds in memory is bounded by the chunk, however large the tenant; one subject's holdings are read whole for
each chunk, by design.

**Exports.** `export($query, $reviewer, $sink, $chunk = 1000)` and `trustedExport($query, $sink, $chunk)` write the
review as versioned JSON Lines to a writable stream resource, each line written whole, or to a callback given each
line, and return how many rows they wrote. Exporting needs both `authorization:review.read` and
`authorization:review.export` (N96): the two are decided together before the header is written and again before every
chunk, each across a broad reach as the read right is. The first line is a header, then one line a row, in the
review's order, then a footer:

```json lines
{"record":"header","version":1,"query":"holders","scope":{"selection":"applies_in","tenant":{"type":"tenant","id":"acct1"},"application":{"selection":"named","name":"admin"}},"reviewed_at":"2026-11-08T12:00:00.250000Z","scan_started_at":"2026-11-08T12:00:00.250000Z","consistency":"live"}
{"record":"row","version":1,"row_key":"004885d0a74311b154e17bb6365cb7332cfd7ae2bb46526880e6be6593bd8ac5","subject":{"type":"user","id":"17"},"grantee":{"type":"user","id":"17"},"target":{"type":"role","id":"01a1be88-d4d3-72cc-b9bc-620cc97d4906"},"source_kind":"role_grant","source_key":"4:role|36:01a1be88-d4d3-72cc-b9bc-620cc97d4906|4:user|2:17|~|~|~","origin_scope":{"tenant":null,"application":null,"include_subtree":true},"via_identity":null,"role_path":[{"type":"role","id":"01a1be88-d4d3-72cc-b9bc-620cc97d4906"}],"supporting_grants":[{"source_key":"4:role|36:01a1be88-d4d3-72cc-b9bc-620cc97d4906|4:user|2:17|~|~|~","scope":{"tenant":null,"application":null,"include_subtree":true},"expires_at":null}],"created_at":"2026-10-01T09:00:00Z","updated_at":"2026-10-01T09:00:00Z","expires_at":null,"route_expires_at":null,"granted_by":null,"grant_state":"live","subject_state":"active","usage":{"status":"unknown","last_observed_at":null,"coverage_from":null,"coverage_until":null}}
{"record":"footer","version":1,"rows":1,"scan_ended_at":"2026-11-08T12:00:00.412000Z","complete":true}
```

| Record   | Fields                                                                                                                                                                       |
|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `header` | `version`, the `query` kind, the `scope` (selection, tenant or null, application selection and name), `reviewed_at`, `scan_started_at` and `consistency`, always `live`      |
| `row`    | The row's versioned shape (see the fields above), references alone                                                                                                           |
| `footer` | `version`, how many `rows` were written, `scan_ended_at`, and whether it is `complete`: false only for an identity's holdings whose directory could not list every principal |

A review narrowed to an action (see [Where a subject holds an action](#where-a-subject-holds-an-action)) adds two keys
to the end of its header, the `action` and `stored_inventory_only`, always true; every other header keeps its shape.

The output is UTF-8 and deterministic: the same rows at the same instants give the same bytes. Each line is one JSON
object with its keys in a fixed order, slashes and Unicode unescaped, the line and paragraph separators escaped, and
invalid UTF-8 refused with `JsonException` rather than replaced. An export the reviewer stops being admitted to part
way (a revoked right, a step-up no longer met, a session cap that no longer covers the rights), or that fails, stops
there with no footer, so a reader can tell it is incomplete. CSV is not offered yet (N97).

**From the console.** `authorization:review` exports a review as JSON Lines on the trusted path (see
[Exporting an access review from the console](console.md#exporting-an-access-review-from-the-console)).

**Indexes.** The migration `2026_11_08_000001_add_access_review_indexes` adds an index on the `granted_by` pair of each
grant table, which a review of an actor's grants is matched on, and one on the permission of the role permission edges,
which the holders of a permission are found by (MySQL already indexes that column for its foreign key, and keeps that
index). On PostgreSQL it also adds an index on each grant table's target and its grantee's type and key, collated `C`,
the order a page of direct holders is read and resumed in. The other review queries are served by the indexes the
tables already have: on MySQL and SQLite, whose reference columns compare their bytes, a target's grants by each grant
table's unique index. The migration honours the configured table names and connection.

**What is left out.** Boundaries, guardrails and resource-policy attachments restrict or extend what a check decides,
but are not held, so no review lists them. Snapshot exports and CSV are not offered. See
[Access reviews](../design/access-reviews.md) for the design.

## Where a subject holds an action

`forAction($action)` narrows a review of holdings to the routes that give one action, so an integration can find every
tenant, subtree and platform record where a subject holds, say, `audit:read`, without reading each membership in turn:

```php
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;

$query  = ReviewQuery::holdings($person, ReviewScope::everywhere())->forAction('audit:read');
$result = $reviews->review($query, ActingContext::current());

$result->rows;                  // the routes giving audit:read, each with what gives it ($row->evidence)
$result->isStoredInventoryOnly; // true: only the stored grants were read (see below)
$result->isComplete;            // false when the identity directory could not list every principal
```

**What a row means.** The action is literal, an action's name made of letters, digits and `_ - : .`, never a wildcard:
`forAction('audit:*')` is refused with `InvalidArgumentException`, as is `forAction()` on any review but holdings. A row
is a holdings route whose target gives the action:

- a permission whose name covers the action by the rules a check matches a held permission by: case-sensitive, a held
  `audit:*` or `*` covering it, never matched with SQL `LIKE`; held directly, through a role or a role above it, or
  through the identity;
- a policy with a statement naming the action as a check's policy matcher reads it (its `actions` covering the action,
  or its `not_actions` leaving it out), attached directly or to a role; an allow statement naming `principals` applies
  only in a policy attached to a resource, so it gives a holder nothing and is passed over;
- never a role itself: a role grant is no row here, only the permissions and policies the role carries.

A permission or policy whose definition is gone gives nothing and is left out. Principal and identity mode are those of
`holdings()`: an identity's rows include those of every principal its directory lists, and a principal's include its
identity's grants that reach it, never a sibling's. The routes are kept before the rows are ordered and cut to a page,
so a page holds its limit of matching rows in the review's one order, however many routes do not match. Admission,
paging, streaming, exports and the trusted path are those of every review: the reviewer needs
`authorization:review.read` on the holdings review, as for the unfiltered one. The cursor binds the action too, so one
issued for another action or for the unfiltered review is refused. The permissions' names and the policies' documents
are read on the write connection, in a fixed number of queries for each page, never one for each route.

**Evidence and effect.** Each row of a filtered review carries an `ActionEvidence` as `$row->evidence`, and under
`action_evidence` in its array and export shape. Every other review's rows have none and keep their shape, at `version`
1:

- `action`: the action asked about;
- `evidence`: `permission` or `policy_statement`;
- `effect`: `allow` for a permission, or for a policy with an allow statement naming the action; `deny` for a policy
  whose statements naming it only deny; null for a policy whose document cannot be read;
- `guard`: the guard a permission is scoped to; null for every guard and for a policy;
- `complete`: false only for a policy whose stored document is invalid or over the limits, so whether it names the
  action is unknown; the route is kept, never dropped;
- `has_deny`: whether a statement naming the action denies it, so a policy that both allows and denies the action reads
  `effect: allow` with `has_deny: true`;
- `has_conditions`, `has_resource_patterns`, `has_requirements`: whether a statement naming the action carries
  conditions, names resources or states an authentication requirement, each reported and never evaluated;
- `reach`: where the route reaches, compactly.

**Compact reach.** `reach` is read from the route's origin scope and never expanded into the tenants it covers: its
`kind` is `node` (the tenant alone), `subtree` (the tenant and every tenant below it, given by its root) or `platform`
(an explicit record naming no tenant, never an empty list of tenants), beside the `tenant`, `application` (null for
every application) and `include_subtree` an origin scope holds. A route held for one application stays that
application's in a review of `ApplicationSelector::any()`, and permissions scoped to different guards stay separate
rows. A role's policy reaches its holder only where the role's grant and the attachment hold together, so for a policy
carried by a role `reach` is their overlap: the narrower tenant, below it only when both reach below, and the
application either names. The row's `origin_scope` stays the role grant's as stored, as in every review of holdings. A
route resting on a row that names half a tenant keeps its `malformed` grant state, and its `reach` shows that row's
tenant columns as stored, with the application the grant or the attachment names, never every application when either
names one.

**Deny evidence.** A policy that only denies the action is a holding, listed with `effect: deny`: evidence that a stored
grant refuses the action there, never authority.

**It never authorises.** A filtered review is introspection, as every review is: it evaluates no statement, condition,
deny or cap, records no last decision and dispatches no decision event. A permission or an allow statement it lists can
still be defeated by a deny, a boundary, a guardrail, a resource restriction, a session cap, or a condition or
requirement that does not hold. It says where stored grants give the action, never whether an operation succeeds: for
that, call `check()` for the operation, in its tenant and application.

**The stored inventory.** The review reads the stored grants alone. A policy a dynamic `PolicyStore` supplies, and a
policy attached to a resource, can give the action outside them, so a filtered review's result and pages say
`isStoredInventoryOnly` (true), and its export header carries the `action` and `stored_inventory_only: true`. An
unfiltered review says false, and its header keeps its shape. Read the rows as candidates, never as every place the
action is allowed. An identity whose directory may leave a principal out keeps `isComplete` false, on an empty page too.

**An audit-access policy.** To keep an audit-access policy built per membership in step with grants held elsewhere,
read every page, never the first alone, keep the allowing evidence, note what could be missing, and still decide each
operation with `check()`:

```php
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Subject;

$query    = ReviewQuery::holdings($person, ReviewScope::everywhere())->forAction('audit:read');
$cursor   = null;
$places   = [];
$isWhole  = true;

do {
    $page    = $reviews->trustedPage($query, $cursor);
    $isWhole = $isWhole && $page->isComplete;

    foreach ($page->rows as $row) {
        $evidence = $row->evidence;              // never null in a filtered review
        $isWhole  = $isWhole && $evidence->isComplete;

        if ($evidence->effect === PolicyEffect::ALLOW) {
            $places[] = $evidence->toArray()['reach']; // ['kind' => 'subtree', 'tenant' => [...], ...]
        }
    }

    $cursor = $page->nextCursor;
} while ($cursor !== null);

// Then, before showing an audit log in an account, decide the operation itself:
Authorization::for(new Subject($user, $person, $account, 'admin'))->check('audit:read', $log)->isAllowed();
```

`$places` lists where an allow is stored, and `$isWhole` false says a principal or an unreadable policy may add more.
Recompute it when grants, policies, identities or the tenant tree change: the review is a live scan, not a subscription.
From the console, `authorization:review holdings {subject} --everywhere --action=audit:read` exports the same filter
over every stored grant; without `--everywhere` (or another scope option) it reviews only what applies at the platform,
for no application. The command resolves `{subject}` through the console subject resolver, so it reviews in principal
mode, not in the identity mode `$person` gives above.

## Usage tracking

Usage tracking records which grants are used, so a review can tell a grant nobody uses from one whose use was never
watched (N94, N100 to N102). It is off by default, and free when off: a check does no extra work and allocates nothing
for it, no listener is registered and no usage table is read, and every review row's `usage` reads `unknown`. Turn it on
in `config/authorization.php`, or with `AUTHORIZATION_USAGE_ENABLED=true`:

```php
'usage' => [
    'enabled'    => true,
    'interval'   => 3600,   // the bucket, in seconds; at least 60
    'batch'      => 250,    // the most observations one recording job carries
    'connection' => null,   // the queue connection the recording job goes to; null for the default
    'queue'      => null,   // the queue; null for the connection's default
    'retention'  => 400,    // the days coverage is kept
],
```

**The cost.** While tracking is on, a resolution of a grantee's permissions and policies also keeps the routes of the
stored grants behind each, read from the rows it reads already and kept beside its entry in the resolution cache, each
grant and route once however many permissions it gives. A check finds the routes behind its decision only among what it
resolved itself, so a cold check runs the same queries as an untracked one (a subject's identity, say, is never
resolved for tracking when the check did not need it), and a warm check finds the routes at a constant extra cost and
with no query. A cache entry kept before tracking was turned on is never read for one, so turning it on resolves each
grantee once more. The routes are noted in memory and sent to be recorded by a queued job, never on the check. No step
tracking adds ever changes or breaks a check: one that fails is written to the log channel and the decision is
returned as it was made.

**What counts.** Only what a decision rested on counts, by the rules the check itself applied. An allowed decision
counts every live grant route behind the permission that allowed it, redundant ones included: the direct grant, and each
role grant that carried it with the ancestor role it came through. They are the routes of the grantee whose permission
matched: the subject's own, or its identity's only when the subject's did not match, since the check asks for the
identity's only then. A policy counts whenever one of its statements decided, allow or deny, so a policy that only
denies, doing its job, is used, by its attachment to the subject or to its identity. An identity of the other kind (a
machine's person, or a person's machine) gives a check its deny statements alone, so its attachment counts only for a
decision its denies made. These are everyday decisions and count: `check()`, `can()`, `cannot()`, `any()`, `all()`,
`authorize()`, `checkMany()`, `canEach()`, `filterAuthorized()`, the Gate, the Blade directives and the middleware, and
a delegated change's own check. A role check (`hasRole()`, `@role`, `role:`) is no decision and counts nothing.

**What never counts.** Only a decision the application acts on is use, so nothing else counts:

| Path                                                                           | Why it never counts                                                                     |
|--------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| `previewFor()` and its admission                                               | A preview decides about another subject as the caller, who uses none of its grants      |
| `explain()` and `authorization:why`                                            | An explanation runs the check to show it, not to act on it (N89)                        |
| `permissionsFor()` and `heldPermissionsFor()`                                  | A listing of what a subject may do is introspection (N70)                               |
| `whereAuthorized()` and `queryScope()`                                         | A scoped query compiles SQL and decides no record                                       |
| A review's admission and its reads                                             | Reviewing who holds what is introspection, and must not create the use it reports       |
| A delegated change's administration stage                                      | Its further checks weigh the change, and a refused change counts nothing it was allowed |
| A permission from a custom `getPermissions()`                                  | A grantee whose grants the package does not resolve cannot say where they came from     |
| A policy from a store, a resource, `withPolicies()`, a guardrail or a boundary | None of these is a grant a subject holds                                                |
| An identity's grant when the subject's own matched                             | The check never asked for it, so the decision did not rest on it                        |

**The interval.** Observations are bucketed by `interval` seconds, an hour by default: a bucket starts at a whole
multiple of the interval in UTC, so every worker agrees where it starts. Each route is noted at most once a bucket per
worker, and a review says a route was last used within the interval that starts at its `last_observed_at`. A queue
worker or a command notes for as long as it runs; under Octane each request's sandbox notes for itself.

**The queue.** Nothing is sent from within a check, so a check never waits on the queue or the store, the `sync`
connection included. What a worker notes is sent as `RecordGrantUsage` jobs when the request, command or queued job
ends, to the `connection` and `queue` configured. Once a worker notes `batch` observations it sets them aside as a job
of their own, so no job outgrows a queue's limit on a job's size: a job of the default 250 is about 110 KB at worst,
well under SQS's 256 KB, and each observation adds about 450 bytes at worst, so lower `batch` for a queue with a
smaller limit (Beanstalkd's default is 64 KB). A worker sets aside at most ten batches before it ends its request or
job; past that it drops the oldest, and the next job names the earliest bucket dropped, from which the store does not
extend the coverage, so the routes whose use was dropped read `unknown` rather than `unused`. A queue that refuses a
job is written to the log channel, and its observations are dropped and named by the next job in the same way.

**The tables and pruning.** The migration `2026_11_09_000001_create_grant_usage_tables` adds `grant_usage`, one row for
each grant route with the start of the last bucket it was observed in and the creation of the grant it was observed
through, keyed by a stable digest of its source kind, target, grantee, tenant, application and role path (the roles it
runs through, as in `role_path`), and `usage_coverage`, the periods tracking was on, `[from, until)` in UTC. Both honour
the configured table names (`tables.grant_usage`, `tables.usage_coverage`) and connection. A write never moves a route's
last use backwards, so a job delivered twice or out of order changes nothing. The routes are written in the order of
their keys, a hundred to a transaction, with no row read under a lock, so two workers take their locks in the same
order; a transaction that deadlocks or waits too long for a lock is tried again, three times in all, and a job that
still fails extends no coverage. `authorization:usage-prune` removes the usage of every route whose stored grant no
longer exists and the coverage older than `retention` days.

**The heartbeat.** Each recording job extends the current coverage period, or opens a new one when the gap since the
last one ended exceeds two intervals. A site that is tracking but quiet sends no jobs, so schedule the heartbeat at
least once an interval to keep it covered; it records nothing while tracking is off:

```php
Schedule::command('authorization:usage-heartbeat')->hourly();
Schedule::command('authorization:usage-prune')->daily();
```

**The store.** Usage is kept behind `Contracts\GrantUsageStore`: `record(UsageBatch $batch)` keeps a batch, each route
only when its observation is newer, and extends the coverage to the batch's instant, but never across the time since a
`lostSince` the batch names; `lastObserved(array $keys)` returns
what is kept of each route asked about; and `coverage($from, $until)` returns the periods that overlap a window. The
package binds `Usage\DatabaseGrantUsageStore` on the tables above; bind your own to send usage elsewhere. Like the
other seams, a store bound before the package registers stands, and one bound after replaces the default.

**Coverage and unknown.** A row's window runs from the later of the review's `since` and the grant's creation to the
review's instant. Its `usage` is `used` when its route was observed in a bucket that ends after the window starts;
`unused` only when the coverage periods, each taken to run two intervals past its end, cover the whole window and the
route was never observed in it; and `unknown` otherwise: tracking is off, coverage of the window is incomplete (a
window that starts before tracking began, or that a gap interrupts), or the route's source cannot report its use (a
role's permission edge or policy attachment, a grantee with its own `getPermissions()` or `getPolicies()`, or, for a
policy, a policy resolver of your own). A missing observation alone is never taken as proof of non-use.
`coverage_from` and `coverage_until` give the latest coverage period overlapping the window.

**Regrants.** A grant revoked and made again is a new row, created later, and never inherits the old grant's use: an
observation made through a grant created before the current one is ignored. A grant whose expiry or reach
(`include_subtree`) is rewritten in place, neither of which is part of its usage key, keeps its creation, and so its
use.

**The unused review.** `ReviewQuery::unused($scope, $since)` lists the live grants in the scope (roles and permissions
granted, policies attached to grantees) with no observed use since the instant, each `unused` or `unknown`, and leaves
out those used. It pages, streams and exports as every review does, admitted by the same `authorization:review.read`
right, which never counts as use; `authorization:review unused --since=…` exports one. It reads the grants a fixed
chunk at a time, never fewer for the rows a page has kept, so the reads grow with the grants it passes over, never one
for each. Every review row carries `usage`, read in one batched lookup a page, or a chunk for the unused review. The
row's shape stays `version: 1`, since the package is unreleased.

```php
$reviews->trusted(ReviewQuery::unused(ReviewScope::everywhere(), now()->subDays(90)));
```

Recording lags: a worker's observations arrive at the store when its request, command or job ends, so a grant used only
in the last moments may read as unused until then. Coverage is kept for the whole site, so observations a worker lost
without naming them (a process killed before it sent them, say) are lost while other workers' jobs keep the coverage
going.
