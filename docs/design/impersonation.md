# Impersonation

`Authorization::for($user)` is the official seam for evaluating authorization decisions against a principal other than
the ambient one. It supports admin-previews-user-permissions workflows, background job authorization, and any context
where the caller knows the target principal at call time. This note documents the scoped clone semantics, composition
with `withPolicies()`, the effective-permissions API, and the boundary between authorization scoping and request-user
identity.

## Invariants

1. **`for()` returns a clone, not a mutation.** The method clones the manager, pins the supplied principal on the clone,
   and returns it. The root manager instance (the singleton behind the `Authorization` facade) is never mutated. Two
   concurrent `for()` calls produce two independent scopes that cannot interfere with each other or with the ambient
   resolution path.

2. **`for()` does NOT change `$request->user()`.** The scoped manager only affects authorization evaluation -- it
   overrides `currentPrincipal()` on the clone. The Laravel auth guard, `$request->user()`, session state, and any
   other authentication-layer concept remain unchanged. This is a deliberate boundary: impersonation at the auth layer
   is a separate concern with its own security implications.

3. **The scoped clone composes with `withPolicies()`.** Callers can chain `for($user)->withPolicies($policies)` to
   evaluate a hypothetical policy set against a specific principal. Each method returns a fresh clone, so the chain
   produces a scope with both overrides active and no mutation of intermediaries.

## Usage

### Admin previews user permissions

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;

// Resolve the target user (the subject being previewed).
$targetUser = User::findOrFail($id);

// Evaluate a single check as that user.
$canEdit = Authorization::for($targetUser)->can('posts:edit');

// Build the full effective-permissions map for a UI.
$permissions = Authorization::for($targetUser)->effectivePermissions();
```

`effectivePermissions()` walks every case of every configured `PermissionEnum` through the full four-step evaluator and
returns an associative array keyed by permission string with boolean values -- suitable for rendering permission-picker
UIs or capability checklists.

### Hypothetical policy evaluation

Chaining `for($user)->withPolicies([$hypothetical])` evaluates against only the supplied policies, bypassing the target
user's own attached policies and any configured policy store. The RBAC fallback still applies -- if the hypothetical
policy does not produce a decisive result, the target user's held permissions are consulted.

```php
$result = Authorization::for($targetUser)
    ->withPolicies([$hypothetical])
    ->evaluate('reports:generate', null, ['tenant' => 'org-42']);
```

## Scoped Clone Semantics

`for()` clones the manager and pins the supplied principal on the clone. The clone inherits the evaluator, policy
resolver, last-decision store, and event dispatcher by reference -- only the principal override is clone-local.

- **No cross-request leak.** The scoped clone is a local variable -- it is garbage-collected when the calling scope
  exits. Long-running workers (Octane, queue) are safe.
- **Last-decision store is shared.** A scoped evaluation writes to the same `LastDecisionStore` as the root manager.
  This is intentional -- `Authorization::lastDecision()` always reflects the most recent evaluation regardless of
  scope, which is the behaviour error handlers and audit listeners expect.

## Trade-offs

- **No dedicated impersonation event.** The `DecisionEvaluated` event carries the principal, so an audit listener can
  detect that the evaluated principal differs from `$request->user()`. Consumers who need an explicit "admin X previewed
  user Y" signal should emit their own event at the call site.
- **RBAC fallback uses the target principal's permissions.** When `for($user)` is active and no policy produces a
  decisive result, the RBAC fallback calls `$user->hasPermission($action)` -- the target user's permissions, not the
  caller's.

## Implementation Anchors

- `AuthorizationManager::for()` -- the scoped-clone factory.
- `AuthorizationManager::withPolicies()` -- the policy-override clone.
- `AuthorizationManager::currentPrincipal()` -- the override-aware resolution method.
- `AuthorizationManager::effectivePermissions()` -- the full permission map used for UI rendering.

## Authoritative Tests

- `AuthorizationManagerTest::testForOverridesResolver` (Unit) -- `for()` bypasses the bound resolver.
- `AuthorizationManagerTest::testForReturnsCloneNotSelf` (Unit) -- `for()` returns a distinct instance.
- `EffectivePermissionsTest::testDirectGrantShowsTrueInEffectiveMap` -- direct grant appears in the map.
- `EffectivePermissionsTest::testExplicitDenyPolicyOverridesDirectGrant` -- deny policy wins over RBAC in the map.
- `EffectivePermissionsTest::testAnonymousPrincipalReturnsAllFalse` -- null principal yields all-false.

## Change Triggers

- Adding a dedicated impersonation event requires a new event class and a dispatch call inside `for()` or
  `currentPrincipal()`.
- Introducing a "caller context" that preserves the original principal alongside the target would require a second
  field on the scoped clone and a contract change on the `DecisionEvaluated` event.
