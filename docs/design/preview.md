# Preview

## Purpose

A "what can this person do?" screen needs the decisions another subject would get, without the caller becoming that
subject (AUTHZ-11.4). This note explains `Authorization::previewFor()`: who previews whom and where, how a preview is
admitted and admitted again, what it records and reports, and why it never confers authority. The package never
impersonates: the guard, the session, the Gate and Blade stay the caller's.

## Invariants

1. **A scoped manager with fixed parties (N87).** `previewFor(object $subject, ?AuthorizationScope $scope = null)`
   returns a clone of the manager carrying an immutable `Preview\PreviewContext`. The context holds the previewer, the
   real caller, the subject the manager it is called on decides about, captured with its session and never inferred
   later from the target, the authenticated user or a listener; the target; and the scope, given or captured with
   `AuthorizationScope::current()` when the preview is built. A job previews through an explicitly named caller,
   `Authorization::for($resolvedSubject)->previewFor($target)`. The previewer's own manager, which decides each
   admission, is built without the scope a `Subject` given to `for()` names (N109), so a preview made from such a
   manager is admitted in the preview's scope and the scopes its decisions are made in, as before. A previewer that
   names no record, a guest included, is refused as `subject_unresolved`, and a target that names no record with
   `InvalidPreviewException`, since no event could name either.

2. **The target has no session.** A resolved `Subject` keeps its principal and identity but loses its session, and a
   model gets `for()` semantics, in the previewer's request. No authentication requirement made of the target is met,
   whatever the previewer has proved: the requirement checker is never asked about the target. Normal precedence still
   applies, so `insufficient_authentication` is the reason only when the requirement alone kept an allow from applying.
   A preview's `authorize()` never throws `InsufficientAuthenticationException`: such a denial throws a plain
   `AuthorizationException`, carrying the decision, since no step-up by the caller could meet a requirement made of the
   target.

3. **The caller's request context.** The `authentication`, `request` and `environment` namespaces are the caller's
   request's, read as they are now. A preview shows the target evaluated in the caller's request context, which is no
   prediction of what the target would see when signed in; a simulator of the target's own request is separate work.

4. **Admission is a check about the previewer (N84).** `authorization:subject.preview`, declared by
   `PackagePermissions` with the catalogue's `authorization:<noun>.<verb>` spelling (the subject its noun), is decided
   through `check()` as the previewer, through the previewer's own manager, with its session, denies, boundaries,
   guardrails and caps, on a `Preview\PreviewResource` naming the target's principal and identity and the tenant and
   application a decision is made in. Its reference is `authorization:preview:{type}:{id}` in that tenant, and
   `Preview\PreviewAttributes` offers `resource.target_type`, `resource.target_id`, `resource.identity_type`,
   `resource.identity_id` and `resource.application`, beside the built-ins `resource.id`, `resource.type`,
   `resource.tenant.type` and `resource.tenant.id` (the tenant, missing at platform scope). A missing key makes a deny
   on it undecidable, so it refuses, as policies fail closed. No rank rule is imposed: an application restricts who
   may be previewed, and where, by policy, so an auditor may inspect senior staff on purpose.

5. **Admission in every scope a decision is made in.** A decision about the target is made where `ResourceScope` puts
   any check: in the preview's scope; in a resource's own tenant when it is the preview's tenant or below it, a child
   tenant's included; just below a tenant, for a query's class of rows below an anchor or a further check across a
   subtree; and at platform scope, for a resource of another tenant a platform-wide grant admits, or every tenant-owned
   resource in a platform preview. `Preview\PreviewAdmission` admits each use in every such scope before the target's
   sources are gathered there: the decision pipeline calls `Previewing::admit()` as `sources()` starts, and for the
   subject a running use decides about, the previewer is decided the right on the preview resource of the scope in
   place, its tenant (none at platform scope), its application and whether it is decided just below the tenant. So a
   deny of the right in a child tenant refuses every answer there, a resource of another tenant needs a platform-wide
   grant of the right, a right at a parent's node alone admits no answer below it, and a preview for no application
   needs the right for every application. A preview distributes no authority, so the ordinary check is exact and
   nothing else is weighed: a deny, conditional or not, refuses only where it matches, at platform scope too; a deny
   the previewer holds in one tenant does not apply at platform scope, as for any check there. A query through the
   preview reads the previewer's anchors beside the target's (`Query\ScopeAnchors`), so each class of rows is uniform
   for both, and each is admitted where it is decided; a class refused refuses the query, whether it holds rows or
   not. Each scope is admitted once per use, keyed as the resolution cache keys it (tenant, below or not, application),
   so a batch over many resources of one tenant costs one admission, not one per resource; a scope is never kept from
   one use to the next.

6. **Revalidated at every use.** `PreviewContext::run()` is one use: each check, each batch, each listing and each
   compile of a query scoped through the preview. It admits the preview in its own scope first, then wherever a
   decision is made (invariant 5). Admission is never kept between uses, so a right revoked after the preview is built,
   or after a query is built, is seen at the next use. The preview is also admitted when it is built, as a use deciding
   nothing about the target. A use sets the request's resolution memo aside and restores it afterwards
   (`ResolutionCache::batch()`), so the caller's own checks read nothing again after a preview, while a write in the
   request still empties it.

7. **A refusal reveals nothing.** A refused admission throws `AuthorizationException`, with the one `denied` line and
   the previewer's own decision, before anything about the target is decided in that scope; a step-up the right needs
   is thrown as `AuthorizationException` too. In a batch, a listing or a query, the refusal refuses the whole call,
   which returns nothing, though the decisions made in it before are reported as any decision is. The refusal is
   decided, recorded and reported as a normal check about the previewer.

8. **One decision path (D22).** `check()`, `can()`, `cannot()`, `any()`, `all()`, `authorize()`, `explain()`,
   `checkMany()`, `canEach()`, `filterAuthorized()`, `permissionsFor(null, ...)` and `whereAuthorized()` given the
   preview go through the manager's one path: once admitted, the scope is put in place for the tenant and application
   (`AuthorizationScope::within()`) and the target is decided in it (`subjectIn()`), the request's scope restored
   afterwards, even when the use throws. A preview's answers equal those of `for($target)` under the same scope and
   state; only admission and recording differ, and a preview refuses where its previewer is not admitted.

9. **Recording (N85, N86).** Every decision about the target dispatches `DecisionEvaluated`, or `AuthorizationFailed`
   for an `authorize()` refusal, with `subject` the target and `previewer` the caller: `CheckBatch` takes the previewer
   and puts it in every provenance it records. When a listener has meanwhile recorded another decision, the
   `AuthorizationFailed` names the preview's scope and its previewer. Previews always dispatch. A preview `check()` or
   `checkMany()` stores the last decision with its provenance as usual. A preview `permissionsFor()` dispatches one
   event per action it evaluates, an exception to N70 for previews alone, and stores none of them, through the
   dispatch-only switch, so the last decision stays the admission's. The admission is a real check about the previewer:
   it records and dispatches as normal, with no previewer. Payloads are references, names and keys, never a value or a
   session.

10. **Explanations (N85).** The right to preview discloses the target's explanation and trace (statements,
    conditions, caps and requirements), never an attribute value or a session detail, which no trace holds. A refused
    preview explains nothing.

11. **Refused in v1.** On a preview, `for()`, `forActor()`, `forUser()`, `previewFor()` and `permissionsFor()` naming
    a subject would change the target, a listing in another tenant or application would change the scope, and
    `withPolicies()` would answer through hypothetical policies: each throws `InvalidPreviewException` before anything
    is decided. A manager carrying a policy override cannot build a preview either, so an override never stands in for
    the previewer's policies. `capped()` is allowed: it caps the target's checks alone, never the previewer's
    admission, and a cap on the caller's manager still caps the admission.

12. **No authority from a preview (N87).** A preview never converts into an `ActingContext`: one built while a preview
    is evaluated, or built from a preview's target (the subject `currentSubject()` returns on it), is refused as
    `administration.previewing`. Every management service call made while a preview is evaluated, from its admission to
    its last decision and the report of its refusal (a callback or a listener it runs, a listener of its
    `AuthorizationFailed` included, trusted or delegated), is refused by `OperationScope::run()` the same way. There is
    no override. `Preview\Previewing`, bound with `scoped()`, holds whether a preview is being evaluated and, weakly,
    the targets built and the subject each running use decides about, so a request or job never sees another's.

13. **Its own writes refused.** `whereAuthorized()` given a preview keeps the rows the target may take the action on,
    and its scope refuses its own writes: compiled for an `update()`, `updateFrom()`, `delete()`, `insertUsing()` or
    `insertOrIgnoreUsing()` of its own builder, or of a builder that nests it whole (`whereExists()`, a nested
    `where()`), it is refused as `preview_write`. A query taking it in as SQL text is not refused (see below).

14. **Gate and Blade stay the caller's.** Nothing rebinds the facade, the Gate or the guard. Gate checks, Blade
    directives and `Authorization::currentSubject()` decide about the caller, also while a preview is evaluated; a
    preview screen uses explicit preview variables.

## Success Path

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;

$preview = Authorization::previewFor($user, AuthorizationScope::tenant($account));

$preview->can('posts:update', $post);
$preview->checkMany($checks);
$preview->permissionsFor(null, AuthorizationScope::tenant($account));

Post::query()->whereAuthorized('posts:view', [], $preview)->select(['id', 'title'])->get();
```

The caller must be allowed `authorization:subject.preview` on the preview resource in the account, and is admitted
again by each of the four uses.

## Failure / Edge Cases

- **The disclosure point.** Rows the target may see are not automatically readable by the previewer: the preview
  answers what the target could do, and the application decides what of it to show, by its own check of the previewer
  or by returning constrained metadata.
- **SQL taken in as text.** A preview-scoped query taken into another as SQL text (`whereIn()`, `fromSub()`,
  `joinSub()`, `selectSub()`, `withCount()` or `has()` with a count) is compiled, and admitted, when it is taken in,
  and the other query reuses that text, as for any scoped query (see `query-scoping.md`): nothing revalidates it when
  the other query runs, and it is not refused as `preview_write` when the other query writes, so
  `Post::query()->whereIn('id', $previewQuery->select('id'))->delete()` deletes the rows the target may see.
- **What a clone cannot sandbox.** A preview guards the package's management services, acting contexts and its own
  queries. It cannot stop a raw Eloquent write on the package's models, pivots or tables, nor a trusted actorless
  service the application calls outside the preview's evaluation: both stay the trusted integration surfaces they
  always are, the application's responsibility.
- **Nested previews.** A preview built inside another's evaluation is admitted on its own; the evaluation mark counts
  both, so nothing either evaluates acts with authority.

## Implementation Anchors

- `Concerns\BuildsScopedManagers::previewFor()` -- the preview clone, the refusals on a preview, and the admission when
  it is built.
- `Preview\PreviewContext` -- the two parties and the scope, and `run()`, one use.
- `Preview\PreviewResource`, `Preview\PreviewAttributes` -- the typed admission resource and its attributes.
- `Preview\PreviewAdmission` -- a use's admissions, one per scope a decision is made in.
- `Preview\Previewing` -- the evaluation mark, the targets and each running use's subject, scoped to the request or
  job; `admit()`, which `Evaluation\DecisionPipeline::sources()` calls.
- `Query\ScopeAnchors` -- the previewer's anchors beside the target's.
- `AuthorizationManager::check()`, `checkMany()`, `permissionsFor()`, `queryScope()` -- the preview path.
- `Evaluation\CheckBatch` -- the previewer in every provenance, and the dispatch-only switch for listings.
- `Query\AuthorizedQuery` -- the refusal of a preview query's own writes, `preview_write`.
- `Administration\ActingContext`, `Support\OperationScope::run()` -- `administration.previewing`.

## Authoritative Tests

- `Preview\PreviewContextTest` (Feature) -- the caller stays who asks, the target has no session, the caller's step-up
  never meets the target's requirement, a refusal before any target result, revocation at the next use, the scope
  restored after an exception, listings in another scope refused.
- `Preview\PreviewAdmissionTest` (Feature) -- tenant, subtree, platform and application; a child tenant's answers
  refused where the right is denied there, through a check, a batch, a listing and a query; rows below a tenant needing
  the right below it; an outside resource needing the platform right; conditional denies at platform scope; policies
  on `resource.target_*`, `resource.tenant.*` and `resource.application`; one admission per scope per use.
- `Preview\AuthorizationManagerTest` (Feature) -- parity with `for()`, ordered events naming both parties, a listing
  reporting each action and storing none, payloads without values, the read-only query and revocation between building
  a query and running it.
- `Preview\BuildsScopedManagersTest` (Feature) -- admission when built, retargeting and policy overrides refused, caps,
  and the Gate, Blade and guard staying the caller's.
- `Preview\PreviewingTest` (Feature) -- a mutation during evaluation refused, acting contexts refused, the evaluation
  mark, each use's subject held with its admission, and the isolation of requests and jobs.

## Change Triggers

- A simulator of the target's own request context, or a target session, would replace invariant 3.
- Hypothetical policies on a preview would need results marked hypothetical before `withPolicies()` is allowed.
- Configurable decision events (BL-72) must keep preview events non-disableable.
- A rank rule for previews would reuse `RankComparison`, never another comparison.
