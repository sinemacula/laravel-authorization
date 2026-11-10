# Impersonation

`Authorization::for($user)` is the low-level seam for evaluating authorization decisions against a principal other
than the ambient one: background job authorization, and any trusted context where the caller knows the target
principal at call time. A screen that shows a person what another subject may do uses `Authorization::previewFor()`
instead, which checks that the caller may preview and reports every decision with both parties (see
[Preview](preview.md)). This note documents the scoped clone semantics, composition with `withPolicies()`, the
effective-permissions API, and the boundary between authorization scoping and request-user identity.

## Invariants

1. **`for()` returns a clone, not a mutation.** The method clones the manager, pins the supplied subject on the clone,
   and returns it. The root manager instance (the request-scoped instance behind the `Authorization` facade) is never
   mutated. Two concurrent `for()` calls produce two independent scopes that cannot interfere with each other or with
   the ambient resolution path.

2. **`for()` keeps the request's tenant and application for a model.** A model named replaces the request's subject
   only: the tenant, application and guard stay the ones the subject resolver reports for the request (none when it
   resolves no subject). A resolved `Subject` is taken as it is, its identity, tenant, application, guard and session
   kept, as an acting context names its actor (see [Delegated administration](delegated-administration.md)), and when
   it names a tenant or an application, each check through the clone is decided there, grants and ambient scope both,
   with the request's restored afterwards (N109, see [the subject resolver](subject-resolver-contract.md)). A check
   never takes its tenant from the caller here otherwise; naming a tenant for a single check is for the administration
   and preview API.

3. **`for()` does NOT change `$request->user()`.** The scoped manager only affects authorization evaluation -- it
   overrides `currentSubject()` on the clone. The Laravel auth guard, `$request->user()`, session state, and any other
   authentication-layer concept remain unchanged. This is a deliberate boundary: impersonation at the auth layer is a
   separate concern with its own security implications.

4. **The scoped clone composes with `withPolicies()` and `capped()`.** Callers can chain
   `for($user)->withPolicies($policies)` to evaluate a hypothetical policy set against a specific principal, and
   `capped($actions)` to cap its checks as well. Each method returns a fresh clone, so the chain produces a scope with
   every override active and no mutation of intermediaries, and every method of the programmatic API (`can()`,
   `cannot()`, `authorize()`, `check()`, `any()`, `all()`, `explain()` and `permissionsFor()`) works on it.

## Usage

### Admin previews user permissions

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;

// Resolve the target user (the subject being previewed).
$targetUser = User::findOrFail($id);

// The caller must hold authorization:subject.preview for the user in the request's tenant and application.
$preview = Authorization::previewFor($targetUser);

// Evaluate a single check as that user, reported with the caller as its previewer.
$canEdit = $preview->can('posts:edit');

// List the actions the user may take in the preview's scope, for a UI; each action is reported.
$permissions = $preview->permissionsFor(null, AuthorizationScope::current());
```

`previewFor()` admits the preview as a check about the caller, and again at every use, so a revoked right is seen at
the next one, and refuses before anything about the target is decided. `permissionsFor()` decides every action of the
permission catalogue through the full staged evaluation (the subject, resource and tenant, the explicit denies, the
guardrails, the permission boundaries, the session caps, the allows and the implicit deny; see
[Evaluation order and deny precedence](evaluation-order-and-deny-precedence.md)) and returns the names of those
allowed, in the catalogue's order -- suitable for rendering permission-picker UIs or capability checklists. The target
has no session, so an action that needs a step-up is not listed for it, whatever the caller has proved. A preview
listing reports each action it evaluates with both parties and stores none of them as the last decision (see
[Preview](preview.md)). Outside a preview, `Authorization::permissionsFor($user, ...)` lists as introspection,
recording and reporting nothing (see [Effective permissions](effective-permissions.md)).

### Hypothetical policy evaluation

A preview refuses hypothetical policies: `withPolicies()` on a preview, or `previewFor()` on a manager carrying an
override, throws `InvalidPreviewException`. Trusted code that needs a hypothetical answer uses `for()`.

Chaining `for($user)->withPolicies([$hypothetical])` evaluates against only the supplied policies, bypassing the target
user's own attached policies, any configured policy store and the policies attached to the resource. A supplied policy
given a resource (`Policy::withResource('post:42')`) is evaluated as a resource policy, so its allows apply only to the
subjects its `principals` name. `withPolicies()` replaces the policies only: the guardrails and the subject's permission
boundaries still cap the decision, their deny statements still count at the deny stage, and the target user's held
permissions are still asked at the allow stage when no allow statement decides, so an override never lifts a cap.

```php
$result = Authorization::for($targetUser)
    ->withPolicies([$hypothetical])
    ->check('reports:generate', null, ['tenant' => 'org-42']); // a policy reads it as input.tenant
```

## Scoped Clone Semantics

`for()` clones the manager and pins the supplied subject on the clone. The clone inherits the decision pipeline (the
evaluator, the policy resolver and the other sources, with any policy override and explicit caps), the last-decision
store and the event dispatcher by reference -- only the subject override is clone-local. `withPolicies()` and
`capped()` clone the manager the same way, each with a new pipeline carrying its override or its cap, so the pipeline
they were called on is never changed.
`forUser()` scopes the same way, to the subject the resolver translates a user into; Laravel's Gate uses it for the user
it hands over.

- **No cross-request leak.** The `Authorization` facade resolves the manager scoped to the current request or job,
  and the scoped clone is a local variable -- it is garbage-collected when the calling scope exits. Long-running
  workers (Octane, queue) are safe.
- **Last-decision store is shared.** A scoped evaluation writes to the same `LastDecisionStore` as the root manager.
  This is intentional -- `Authorization::lastDecision()` always reflects the most recent evaluation regardless of scope,
  which is the behaviour error handlers and audit listeners expect. `any()` and `all()` record every action they decide,
  so after one of them it is the decision of the last action decided.

## Trade-offs

- **No dedicated impersonation event.** The `DecisionEvaluated` event carries a reference to the principal the decision
  was about, so an audit listener can detect that it differs from `$request->user()`. A decision made through
  `previewFor()` also carries the caller as its `previewer`, so "admin X previewed user Y" needs no event of the
  application's own; a decision made through `for()` carries none, since `for()` is a trusted seam, not a preview.
- **The permission step uses the target principal's permissions.** When `for($user)` is active, the held-permission
  check is made at the allow stage, after the caps and only when no allow statement decides, through
  `SubjectGrants::permissionFor()` over the target subject's grantees, its principal and its identity -- the target
  user's permissions, not the caller's, capped by the target user's boundaries, and counted only where the grant they
  came from reaches the resource.

## Implementation Anchors

- `AuthorizationManager::for()`, in `Concerns\BuildsScopedManagers` -- the scoped-clone factory, which reads the
  subject resolver once when it names a model, and takes a resolved `Subject` as it is.
- `AuthorizationManager::withPolicies()` and `capped()` -- the policy-override and capped clones, over
  `Evaluation\DecisionPipeline::withPolicies()` and `capped()`.
- `AuthorizationManager::forUser()` -- the scoped clone for a user the subject resolver translates.
- `AuthorizationManager::currentSubject()` -- the override-aware resolution method.
- `AuthorizationManager::permissionsFor()` -- the actions listed for UI rendering, the subject named as `for()` names
  it.
- `AuthorizationManager::previewFor()`, in `Concerns\BuildsScopedManagers` -- the checked preview (see
  [Preview](preview.md)).

## Authoritative Tests

- `AuthorizationManagerTest::testForOverridesResolver` (Unit) -- `for()` decides about the model named instead of the
  resolver's subject, reading the resolver once, when `for()` is called with a model, to keep the tenant and
  application.
- `BuildsScopedManagersTest::testForAndForUserNameTheSubject` (Feature) -- a resolved `Subject` named through `for()`
  is kept as it is, its identity, tenant, application, guard and session included.
- `AuthorizationManagerTest::testForReturnsCloneNotSelf` (Unit) -- `for()` returns a distinct instance.
- `AuthorizationManagerTest::testForKeepsTheRequestsTenantApplicationAndGuard` (Unit) -- `for()` keeps the request's
  tenant, application and guard.
- `AuthorizationManagerTest::testGrantsRolesAndDeniesAreWeighedAsTheCheckWeighsThem` (Feature, `PermissionsFor`) -- a
  direct grant and a role's permission are listed, and a deny policy wins over RBAC.
- `AuthorizationManagerTest::testAModelIsNamedAsForNamesIt` (Feature, `PermissionsFor`) -- a model is listed as
  `for()` names it.
- `AuthorizationManagerTest::testAGuestIsAllowedNothing` (Feature, `PermissionsFor`) -- a guest is listed nothing.

## Change Triggers

- Adding a dedicated impersonation event requires a new event class and a dispatch call inside `for()` or
  `currentSubject()`.
- The caller context that preserves the original principal alongside the target is `Preview\PreviewContext`, which
  only `previewFor()` sets; a `for()` clone carrying one would make it a preview, admitted and reported as one.
