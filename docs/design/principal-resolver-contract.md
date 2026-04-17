# Principal Resolver Contract

The `PrincipalResolver` contract is a single-method interface that bridges the authorization engine to whatever concept
of "the current principal" the host application uses. It exists so the package carries zero runtime coupling to Laravel's
authentication stack, to `sinemacula/laravel-authentication`, or to any other identity provider. This note explains the
contract, the two shipped implementations, the `for()` scoping override, and the static resolution path used by
middleware and Blade directives.

## Invariants

1. **The contract is the only coupling point with authentication.** No class in the authorization package imports
   `Auth`, `Guard`, `Authenticatable`, or any authentication-layer class except inside `AuthGuardPrincipalResolver` --
   the opt-in resolver that consumers wire when they want the standard Laravel auth stack.

2. **The shipped default resolver returns null.** `NullPrincipalResolver::resolve()` always returns `null`, which makes
   the authorization engine deny every check via the `ImplicitDeny` branch (null principal short-circuits before the
   evaluator runs). This makes the package anonymous-safe out of the box -- it can be installed, configured, and tested
   without an authentication layer present.

3. **`for()` overrides the resolver for a single scoped evaluation.** When the caller uses
   `Authorization::for($user)->can(...)`, the manager clones itself, pins the supplied principal, and never consults the
   bound resolver. This override is the official impersonation / admin-preview seam (see
   `docs/design/impersonation.md`).

4. **The resolver is consulted once per evaluation, not once per request.** The manager calls
   `$this->principalResolver->resolve()` inside `currentPrincipal()` on every `can()`, `authorize()`, or `evaluate()`
   call. Implementations that want request-level memoisation should implement it internally -- the manager does not
   cache the resolved principal.

## Contract

```php
interface PrincipalResolver
{
    public function resolve(): ?object;
}
```

The return type is `?object` rather than a specific interface. The engine does not type-hint any particular principal
shape -- capability is detected via the `AuthorizableIdentity` contract at evaluation time. A resolver that returns an
object which does not implement `AuthorizableIdentity` produces an `ImplicitDeny` at the RBAC fallback step because
the manager cannot call `hasPermission()` on an untyped object.

## Shipped Implementations

### NullPrincipalResolver

The default binding, configured in `authorization.principal_resolver`. Always returns `null`. Useful for:

- Packages that only use the `Authorization::for($user)` explicit-principal path and never rely on ambient resolution.
- Test suites that construct the manager directly and supply principals via `for()`.
- Applications that have not yet wired an authentication layer.

### AuthGuardPrincipalResolver

The standard-app resolver. Reads from Laravel's `Auth::guard($name)->user()` and returns the result when it implements
`Authenticatable`, or `null` otherwise. The guard name defaults to `authorization.defaults.guard` (itself defaulting to
`'web'`) and can be overridden at construction for multi-guard deployments.

Configuration:

```php
// config/authorization.php
'principal_resolver' => \SineMacula\Laravel\Authorization\Resolvers\AuthGuardPrincipalResolver::class,
```

The service provider resolves this class from the container, so constructor dependencies (`AuthFactory`, guard name`)
are injected automatically.

## Scoped Override via `for()`

`Authorization::for($user)` returns a cloned manager with `$principalOverride` pinned to the supplied object and
`$principalOverridden` set to `true`. Every subsequent call on that clone (`can()`, `authorize()`, `evaluate()`,
`effectivePermissions()`) reads from the override instead of the resolver. The clone semantics guarantee that the
override cannot leak to the root manager instance or to other scoped clones -- each `for()` call produces an
independent scope. See `docs/design/impersonation.md` for the full impersonation surface.

## Static Resolution Path

Middleware and Blade directives cannot inject the manager via constructor injection. They reach it through
`AuthorizationManager::instance()` (provided by the `HasContainerInstance` trait), which resolves the singleton from the
container. Middleware calls `Authorization::currentPrincipal()` to get the ambient principal; Blade helpers call
`AuthorizationManager::instance()?->currentPrincipal()`. This keeps the service-locator call in one auditable site.

## Trade-offs

- **One more seam vs. tight coupling.** The resolver contract adds an indirection layer that every `can()` call
  traverses. The alternative -- hard-wiring `Auth::user()` inside the manager -- would save one method call but would
  make the package untestable without a full auth stack and unusable in non-web contexts (queue workers, CLI commands,
  standalone libraries).
- **No request-level caching in the contract.** The manager calls `resolve()` on every evaluation. This is by design --
  a resolver that caches would hide principal changes mid-request (e.g. after an explicit `Auth::login()` call). The
  `AuthGuardPrincipalResolver` delegates to the guard, which already caches internally.

## Implementation Anchors

- `PrincipalResolver` -- the contract interface.
- `NullPrincipalResolver` -- the anonymous-safe default.
- `AuthGuardPrincipalResolver` -- the standard Laravel auth bridge.
- `AuthorizationManager::currentPrincipal()` -- the override + resolver delegation.
- `AuthorizationManager::for()` -- the scoped-clone factory.
- `BladeHelpers::currentPrincipal()` -- the static resolution path for Blade directives.
- `AbstractAuthorizationMiddleware` -- the static resolution path for route middleware.

## Authoritative Tests

- `NullPrincipalResolverTest::testResolveReturnsNull` -- the default resolver always returns null.
- `AuthGuardPrincipalResolverTest::testReturnsAuthenticatableFromConfiguredGuard` -- the guard resolver reads from the
  configured guard.
- `AuthGuardPrincipalResolverTest::testReturnsNullWhenGuardIsAnonymous` -- unauthenticated guard yields null.
- `AuthGuardPrincipalResolverTest::testExplicitGuardOverrideIsHonoured` -- constructor guard override is respected.
- `AuthorizationManagerTest::testForOverridesResolver` (Unit) -- `for()` bypasses the bound resolver.
- `AuthorizationManagerTest::testForReturnsCloneNotSelf` (Unit) -- `for()` returns a distinct instance.

## Change Triggers

- Adding a second resolver dimension (e.g. a fallback chain or a per-guard resolver map) requires updating the manager's
  `currentPrincipal()` method and this note.
- Introducing request-level principal caching inside the manager would change invariant 4 and must be opt-in.
- Wiring a resolver that returns a non-`AuthorizableIdentity` object for a legitimate use case (e.g. an API key token)
  would require the manager's RBAC fallback to handle that branch explicitly.
