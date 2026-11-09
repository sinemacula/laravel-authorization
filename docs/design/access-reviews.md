# Access Reviews

## Purpose

Periodic access reviews and their sign-off need four lists no check gives (AUTHZ-11.6): who holds a role, permission or
policy in a scope, what a subject holds and where, which grants expire within a window, and which grants an actor last
granted or changed. This note explains what a review means by "holds" (N93), the typed query and its scope selections,
the rows and their order, how a review is admitted (N96), and what part 1 of BL-69 (N98) leaves out.

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
   kinds of their own, each marked `live` or `expired` at the review's instant; in a review applying in a tenant, an
   edge is listed only when the tenant sees its role and permission, and a role's policy attachment only when it sees
   the role, as a check reaches either only through that role. `grantedBy()` lists the stored grants whose `granted_by`
   pair is exactly the actor's: the last writer (N95), since a regrant, a changed expiry or reach overwrites it, a
   trusted write names no actor, and a revoked grant is gone.

7. **Reference-only, versioned rows.** A `ReviewRow` names references alone (a morph type and a string key) and plain
   values, never a name, email, description, document or value. Its shape is `version: 1`: `row_key`, `subject`,
   `grantee`, `target`, `source_kind`, `source_key`, `origin_scope`, `via_identity`, `role_path`, `supporting_grants`,
   `created_at`, `updated_at`, `expires_at`, `route_expires_at`, `granted_by`, `grant_state` and `subject_state`. A
   stored row's key is built from the columns that make it unique (target, grantee, tenant and application; role and
   permission for an edge), each part length-prefixed so no two lists of parts share one. A subject is `inactive` when
   it, or the identity of a resolved subject, reports itself inactive or is deleted softly, `unknown` when its record
   is gone or its type names no model, read one query for each morph type among the rows returned.

8. **One total order (`Reviews\Support\ReviewOrder`).** By source kind (in `SourceKind`'s declared order), target,
   grantee, origin scope and route, each nullable component tagged so the platform comes before a tenant and every
   application before a named one, every string compared byte for byte: SQLite through its binary collation,
   PostgreSQL through `C`, MySQL as binary strings, PHP through `strcmp()`. The same rows come in the same order on
   every supported database.

9. **Bounded, on the writer, no query per holder.** A review returns at most its limit (`authorization.reviews.limit`,
   1000 by default, or `withLimit()`), reading one more to say exactly whether one was left out. The holders of a
   target are read a page at a time in the review's order, so what is held never exceeds the limit and its one extra,
   and the queries never grow with the holders: the roles a review involves are read first, then the grants of all of
   them together. One subject's holdings are read whole in a fixed number of queries, then sorted. Every read is on the
   package's write connection.

10. **Admission through `check()` (N96).** `authorization:review.read` and `authorization:review.export` are package
    permissions; exporting needs both. `AccessReview::review($query, $reviewer)` admits the review before anything is
    read: the reviewer's own manager, with its session, denies, boundaries, guardrails and the acting context's caps,
    decides the right on a `ReviewResource` (`authorization:review:{query}`, in the reviewed tenant), with the reviewed
    tenant, or the platform, and the named application, or none, in place. The resource's attributes (see
    `ReviewAttributes`) let policies restrict who may review what; no rank rule applies.

11. **A broad reach is administered whole.** A review of one tenant's node is decided there. At the administration
    stage of the same check, a review rooted within a tenant, applying at the platform or of everywhere is weighed by
    `AdministeredScope::refusalOf()`, the #122 rule, with no lock, rank or self rule: the right is decided again just
    below the reach's tenant, or at platform scope, and refused as `administration.scope` when anything that denies or
    caps the reviewer anywhere in the reach could limit it (`PossessionLimits`), a conditional deny included.

12. **Refusal discloses nothing.** A refused review is recorded and reported as `authorize()` records and reports a
    refusal and throws `AuthorizationException` with the one generic line, carrying the reviewer's own decision, a
    step-up the right needs included; no row, count, truncation flag or completeness is computed.

13. **An explicit trusted path (N75).** `AccessReview::trusted($query)` runs a review as trusted system work, for a
    scheduled job or a command. Nothing falls back to it: `review()` always takes an `ActingContext`, and one that
    cannot be resolved is refused as `subject_unresolved` before a review is reached.

14. **Scoped disclosure.** A review admitted in a tenant reads only what applies there: an inherited grant, such as a
    platform grant or a parent's reaching below, is listed, but never the holders in other tenants it also reaches.

## Success Path

```php
$reviews = app(AccessReview::class);
$scope   = ReviewScope::appliesIn($account, ApplicationSelector::named('admin'));

$holders  = $reviews->review(ReviewQuery::holders($editor, $scope), ActingContext::current());
$holdings = $reviews->review(ReviewQuery::holdings($identity, ReviewScope::rootedWithin($organisation)), $auditor);
$expiring = $reviews->trusted(ReviewQuery::expiring(ReviewScope::everywhere(), now(), now()->addMonth()));
```

An auditor allowed `authorization:review.read` in the account reviews who holds `editor` there: the direct grants,
then the grants of every role below `editor`, each with its role path, the platform's and the organisation's grants
reaching the account included, nothing granted in a sibling account. A scheduled job lists what expires next month,
across every tenant, as trusted work.

## Failure / Edge Cases

- A reviewer allowed the right at an organisation's node alone, or denied it in one account, is refused a review rooted
  within the organisation as `administration.scope`, and a review of everywhere likewise.
- A session cap that does not cover the right, or an unmet step-up, refuses the review as an ordinary check would.
- A role permission edge or a role's policy attachment that has expired carries nothing, and a role's policy attached in
  one application or tenant reaches no holder whose grant holds elsewhere.
- A stored hierarchy cycle refuses the review; a role whose owner moved out of the reviewed tenant's chain ends a chain
  there.
- An inactive or deleted-softly holder keeps its rows, marked `inactive`; a grant to a grantee whose record is gone is
  listed as `unknown`.
- A target whose key no definition could have (every definition is keyed by a UUID) is held by no one, on every
  database, rather than reaching a `uuid` column it cannot be compared with.
- A window that does not end after it starts, a limit below one, a target that is no definition, and a subject that
  names no key are refused with `InvalidArgumentException` when the query is built.

## Implementation Anchors

- `Reviews\AccessReview` -- `review()`, `trusted()` and the run.
- `Reviews\ReviewQuery`, `Reviews\ReviewScope`, `Reviews\ApplicationSelector` -- the typed, immutable inputs.
- `Reviews\ReviewRow`, `Reviews\SupportingGrant`, `Reviews\ReviewResult` -- the versioned output.
- `Reviews\ReviewResource`, `Reviews\ReviewAttributes`, `Reviews\ReviewAdmission` -- the admission, and the
  administration stage `Evaluation\DecisionPipeline::decideGrants()` runs for a review resource.
- `Administration\AdministeredScope::refusalOf()` -- the reach rule shared with delegated administration.
- `Reviews\Support\ReviewRun` -- the scope and instant of one run, and the structural predicates.
- `Reviews\Support\HolderRoutes`, `HoldingRoutes`, `StoredRows` -- the four queries.
- `Reviews\Support\RoleChains`, `RoleCarriers` -- the hierarchy and what roles carry.
- `Reviews\Support\GrantRows`, `GrantRow`, `RowCollector`, `ReviewOrder`, `SubjectStates`, `Definitions` -- the reads,
  the rows, the bound and the order.

## Authoritative Tests

- `Reviews\Support\HolderRoutesTest` (Feature) -- direct and inherited roles, permissions and policies through roles and
  ancestors, alternative routes, the hierarchy off, expired edges, intersecting and non-intersecting role policies,
  deny-only policies held, boundaries and resource policies excluded, unseen ancestors, cycles, name collisions.
- `Reviews\Support\HoldingRoutesTest` (Feature) -- own and identity grants, sibling isolation, machines and persons,
  identity mode with complete and incomplete directories, inactive subjects, applicability and roots.
- `Reviews\Support\StoredRowsTest` (Feature) -- every stored kind, the half-open UTC window, non-UTC bounds, dates
  beyond 2038, expired rows, scopes for edges, and the last writer after an actor replacement.
- `Reviews\ReviewAdmissionTest` (Feature) -- the tenant, the subtree and the platform, a child's deny blocking a broad
  review, caps and step-up, policies on the attributes, refusals reported and disclosing nothing, scoped disclosure.
- `Reviews\AccessReviewTest` (Feature) -- trusted and admitted runs, the unresolved reviewer, exact truncation, the
  byte-order total order with unusual references and nullable scopes, the reference-only sentinel, subject states and
  the write connection.
- `Reviews\Support\ReviewRunTest`, `ReviewOrderTest` (Feature) -- applicability against containment, application
  selection, the frozen instant and the byte order on every database.
- `Performance\AccessReviewQueryBudgetTest` -- no query growth with holders, grants or rows.

## Change Triggers

- Keyset cursors, streaming JSON Lines exports and their indexes (part 2 of BL-69) replace the bounded list, and must
  readmit every page.
- Usage tracking and the unused-grant report (part 3, N94) add a column or store, and must never count a review.
- A paged identity directory would let identity mode stream very large identities.
- Listing boundaries, guardrails or resource policies would need rows labelled as restrictions, never as holdings.
