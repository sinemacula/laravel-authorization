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
   `Authorization::for($resolvedSubject)->previewFor($target)`. A previewer that names no record, a guest included, is
   refused as `subject_unresolved`, and a target that names no record with `InvalidPreviewException`, since no event
   could name either.

2. **The target has no session.** A resolved `Subject` keeps its principal and identity but loses its session, and a
   model gets `for()` semantics, in the previewer's request. No authentication requirement made of the target is met,
   whatever the previewer has proved: the requirement checker is never asked about the target. Normal precedence still
   applies, so `insufficient_authentication` is the reason only when the requirement alone kept an allow from applying.

3. **The caller's request context.** The `authentication`, `request` and `environment` namespaces are the caller's
   request's, read as they are now. A preview shows the target evaluated in the caller's request context, which is no
   prediction of what the target would see when signed in; a simulator of the target's own request is separate work.

4. **Admission is a check about the previewer (N84).** `authorization:subject.preview`, declared by
   `PackagePermissions` with the catalogue's `authorization:<noun>.<verb>` spelling (the subject its noun), is decided
   through `check()` as the previewer, through the previewer's own manager, with its session, denies, boundaries,
   guardrails and caps, on a `Preview\PreviewResource` naming the target's principal and identity and the scope's tenant
   and application. Its reference is `authorization:preview:{type}:{id}` in the scope's tenant, and
   `Preview\PreviewAttributes` offers `resource.target_type`, `resource.target_id`, `resource.identity_type`,
   `resource.identity_id` and `resource.application`, with the built-in `resource.tenant`. No rank rule is imposed: an
   application restricts who may be previewed by policy, so an auditor may inspect senior staff on purpose.

5. **The administered-reach rule (#122).** The right is decided in the scope's tenant, as any resource of that tenant
   is (`ResourceScope`): a tenant outside the previewer's request tenant and its subtree is refused as `tenant_scope`
   unless a platform-wide grant of the right admits it, and a preview with no tenant is decided at platform scope.
   After the allow, `Preview\PreviewAdmission` decides the right again at the scope's node, the tenant alone or the
   platform, in the scope's application, through `AdministeredScope`. A preview for no application needs the right for
   every application. A platform preview reaches every tenant, so anything that could limit the right anywhere (a deny
   naming it, conditional or not, a boundary or guardrail not allowing it whole, a session cap not covering it, see
   `PossessionLimits`) refuses it as `administration.scope`. An application that restricts previews by policy therefore
   previews in tenant scopes.

6. **Revalidated at every use.** `PreviewContext::run()` admits the preview again before every use: each check, each
   batch, each listing and each execution of a query scoped through it. Admission is never kept between uses, so a right
   revoked after the preview is built, or after a query is built, is seen at the next use. The preview is also admitted
   when it is built.

7. **A refusal reveals nothing.** A refused admission throws `AuthorizationException`, with the one `denied` line and
   the previewer's own decision, before anything about the target is decided; a step-up the right needs is thrown as
   `AuthorizationException` too. The refusal is decided, recorded and reported as a normal check about the previewer.

8. **One decision path (D22).** `check()`, `can()`, `cannot()`, `any()`, `all()`, `authorize()`, `explain()`,
   `checkMany()`, `canEach()`, `filterAuthorized()`, `permissionsFor(null, ...)` and `whereAuthorized()` given the
   preview go through the manager's one path: once admitted, the scope is put in place for the tenant and application
   (`AuthorizationScope::within()`) and the target is decided in it (`subjectIn()`), the request's scope restored
   afterwards, even when the use throws. A preview's answers equal those of `for($target)` under the same scope and
   state; only admission and recording differ.

9. **Recording (N85, N86).** Every decision about the target dispatches `DecisionEvaluated`, or `AuthorizationFailed`
   for an `authorize()` refusal, with `subject` the target and `previewer` the caller: `CheckBatch` takes the
   previewer and puts it in every provenance it records. Previews always dispatch. A preview `check()` or `checkMany()`
   stores the last decision with its provenance as usual. A preview `permissionsFor()` dispatches one event per action
   it evaluates, an exception to N70 for previews alone, and stores none of them, through the dispatch-only switch, so
   the last decision stays the admission's. The admission is a real check about the previewer: it records and
   dispatches as normal, with no previewer. Payloads are references, names and keys, never a value or a session.

10. **Explanations (N85).** The right to preview discloses the target's explanation and trace (statements,
    conditions, caps and requirements), never an attribute value or a session detail, which no trace holds. A refused
    preview explains nothing.

11. **Refused in v1.** On a preview, `for()`, `forUser()`, `previewFor()` and `permissionsFor()` naming a subject would
    change the target, a listing in another tenant or application would change the scope, and `withPolicies()` would
    answer through hypothetical policies: each throws `InvalidPreviewException` before anything is decided. A manager
    carrying a policy override cannot build a preview either, so an override never stands in for the previewer's
    policies. `capped()` is allowed: it caps the target's checks alone, never the previewer's admission, and a cap on
    the caller's manager still caps the admission.

12. **No authority from a preview (N87).** A preview never converts into an `ActingContext`: one built while a preview
    is evaluated, or built from a preview's target (the subject `currentSubject()` returns on it), is refused as
    `administration.previewing`. Every management service call made while a preview is evaluated, from its admission to
    its last decision (a callback or a listener it runs, trusted or delegated), is refused by `OperationScope::run()`
    the same way. There is no override. `Preview\Previewing`, bound with `scoped()`, holds whether a preview is being
    evaluated and, weakly, the targets built, so a request or job never sees another's.

13. **Read-only queries.** `whereAuthorized()` given a preview keeps the rows the target may take the action on, and
    its scope is read-only: compiled for an `update()`, `updateFrom()`, `delete()`, `insertUsing()` or
    `insertOrIgnoreUsing()`, of its own query or one it is nested in, it is refused as `preview_write`.

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
  `joinSub()`, `selectSub()`) is compiled, and admitted, when it is taken in, and the other query reuses that text, as
  for any scoped query (see `query-scoping.md`): nothing revalidates it when the other query runs.
- **What a clone cannot sandbox.** A preview guards the package's management services, acting contexts and its own
  queries. It cannot stop a raw Eloquent write on the package's models, pivots or tables, nor a trusted actorless
  service the application calls outside the preview's evaluation: both stay the trusted integration surfaces they
  always are, the application's responsibility.
- **Nested previews.** A preview built inside another's evaluation is admitted on its own; the evaluation mark counts
  both, so nothing either evaluates acts with authority.

## Implementation Anchors

- `Concerns\BuildsScopedManagers::previewFor()` -- the preview clone, the refusals on a preview, and the admission when
  it is built.
- `Preview\PreviewContext` -- the two parties and the scope, `admit()` and `run()`.
- `Preview\PreviewResource`, `Preview\PreviewAttributes` -- the typed admission resource and its attributes.
- `Preview\PreviewAdmission` -- the reach of the admission, after the allow, through `AdministeredScope`.
- `Preview\Previewing` -- the evaluation mark and the targets, scoped to the request or job.
- `AuthorizationManager::check()`, `checkMany()`, `permissionsFor()`, `queryScope()` -- the preview path.
- `Evaluation\CheckBatch` -- the previewer in every provenance, and the dispatch-only switch for listings.
- `Query\AuthorizedQuery` -- the read-only scope and `preview_write`.
- `Administration\ActingContext`, `Support\OperationScope::run()` -- `administration.previewing`.

## Authoritative Tests

- `Preview\PreviewContextTest` (Feature) -- the caller stays who asks, the target has no session, the caller's step-up
  never meets the target's requirement, a refusal before any target result, revocation at the next use, the scope
  restored after an exception, listings in another scope refused.
- `Preview\PreviewAdmissionTest` (Feature) -- tenant, subtree, platform and application, a platform preview refused
  where the right is denied in a tenant, and policies on `resource.target_*`.
- `Preview\AuthorizationManagerTest` (Feature) -- parity with `for()`, ordered events naming both parties, a listing
  reporting each action and storing none, payloads without values, the read-only query and revocation between building
  a query and running it.
- `Preview\BuildsScopedManagersTest` (Feature) -- admission when built, retargeting and policy overrides refused, caps,
  and the Gate, Blade and guard staying the caller's.
- `Preview\PreviewingTest` (Feature) -- a mutation during evaluation refused, acting contexts refused, the evaluation
  mark and the isolation of requests and jobs.

## Change Triggers

- A simulator of the target's own request context, or a target session, would replace invariant 3.
- Hypothetical policies on a preview would need results marked hypothetical before `withPolicies()` is allowed.
- Configurable decision events (BL-72) must keep preview events non-disableable.
- A rank rule for previews would reuse `RankComparison`, never another comparison.
