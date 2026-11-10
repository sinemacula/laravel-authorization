# Subject Resolver Contract

The `SubjectResolver` contract answers one question for every check that does not name its subject: who is this
request about, in which tenant, and on which application. It is the only coupling point between the authorization
engine and authentication, so the package carries no runtime dependency on `sinemacula/laravel-authentication` or any
other identity provider. This note explains the contract, the `Subject` it returns, the shipped default, the `for()`
and `forUser()` scopes, and how the Gate, middleware, Blade directives and tenant scope reach it.

## Invariants

1. **One resolver answers the subject, the tenant and the application.** There is no separate tenant resolver. The
   active tenant is the one the resolved subject carries, never a value from the request or the check's context
   (AUTHZ-5.4), and the application comes from the same place (AUTHZ-5.6).

2. **No subject means a denial.** `resolve()` returns `null` for an anonymous request or a job acting for no one. Every
   check made without a named subject then short-circuits to `ImplicitDeny` before the evaluator runs.

3. **No tenant means platform rows only.** When there is no subject, or the subject has no tenant, `TenantScope` lets
   through only platform-wide roles and permissions. A missing tenant never makes every tenant's rows visible
   (AUTHZ-5.7).

4. **The Gate's user is translated, not trusted.** Laravel's Gate hands its user to `forUser()`, and the check decides
   about the subject the resolver returns for it (AUTHZ-2.1). In an application without principals that is the user
   itself; one with principals returns the principal the user acts as. A guest (no Gate user) is no subject, so its
   checks deny; it is never decided as the request's own subject.

5. **Nothing outlives the request or job.** The package's default resolver and the tenant it resolves are bound with
   `scoped()`, so the queue worker and Octane build them afresh for each job or request (AUTHZ-12.5). A resolver the
   application binds itself, with `instance()`, `singleton()`, `scoped()` or `bind()`, is kept across that reset.

6. **A binding made first stands (N103), unless the application configured a class (N106).** The contract is bound to
   the package's default only when nothing is bound to it yet (`bindIf()`), so a resolver a sibling package binds before
   the package registers stands, `instance()` included, and one bound afterwards with `bind()`, `singleton()`,
   `scoped()` or `instance()` replaces the default; the default stays reachable under its package-owned key. When
   `authorization.subject_resolver` names a class other than the package's default, the contract is bound to it whatever
   was bound before, since the application's configuration is its explicit choice and a sibling's binding is not; a
   value equal to the default, or none, binds nothing over an earlier binding. A sibling's deferred provider of the
   contract would bind it at its first resolution, after the configured class, so the package loads it before binding:
   as the package registers when the application already knows of it, and otherwise in a `booting()` callback, which
   loads the provider and binds the configured class again when the contract is still deferred as the application boots,
   since Laravel learns of the deferred providers of its configuration and of package discovery only once every eager
   provider has registered. A binding made after the package registers, with no deferred provider of the contract, is
   left standing at boot. Binding the configured class follows Laravel's rules for any binding: an extender registered
   on the contract is applied to it, so one typed to a sibling's class fails, and over a contract already resolved the
   callbacks watching it with `rebinding()` or `refresh()` are called, which may resolve the configured class while the
   package registers. The precedence, highest first, is a binding made after the package registers, then the configured
   class, then a binding made before the package registers, then the package's default. The same holds for every seam
   the package gives a default for, and for every seam the configuration names a class for: the tenant tree, the
   identity directory, the resource tenant resolver, the authentication requirement checker, the session policy source
   and the policy store, which has no default, so a configured store always replaces an earlier binding. The grant hook
   is the one exception (N108): hooks only refuse, so when `authorization.grant_hooks` lists any, the package extends
   the contract and they run before whatever hook it resolves to, bound before the package registered or after, rather
   than replacing it, with `bind()`, `singleton()`, `scoped()` or `instance()` (see `grant-scope.md`, invariant 12).
   Provider order still decides between bindings made outside the package: the later of two wins, and a `bindIf()` made
   after the package registers is skipped. Rebinding the resolver still empties the resolution cache's memo: one bound
   before the package registered, `instance()` included, is watched from its first resolution in each container that
   resolves it, an Octane sandbox included, whether that binding stands or the configured class replaced it, since
   watching it sooner would resolve it while providers register.

7. **A `Subject` decides in its own scope (N109).** `Authorization::for($subject)` with a resolved `Subject` naming a
   tenant or an application decides every check through the manager there, grants and ambient scope both, as
   `AuthorizationScope::within()` around `for()` of the subject in that scope does, and restores the request's scope
   afterwards, even on a throw. A `Subject` naming neither, and a model, are decided in the request's scope.

8. **A tenant is named by its key.** The tenant a `Subject` carries is a model or an `AuthorizableTenant`, named by
   its morph type and `getKey()`, the contract's identifier and a model's primary key, in every grant row, tenant tree
   question, cache key and `Reference`. A tenant's other identifiers (a slug, an external id) are never read.

9. **Configuration fails closed.** `authorization.subject_resolver` must name a class implementing the contract. Null,
   a missing class or a class that does not implement it is refused at boot (AUTHZ-17.2).

## Contract

```php
interface SubjectResolver
{
    public function resolve(): ?Subject;

    public function forUser(object $user): Subject;
}
```

`Subject` is a read-only value:

| Property      | Meaning                                                                                 |
|---------------|-----------------------------------------------------------------------------------------|
| `subject`     | The model decisions are about: a principal, or the user in an application without them. |
| `identity`    | The identity behind a principal, the subject itself without principals, or `null`.      |
| `tenant`      | The active tenant, or `null` for none.                                                  |
| `application` | The application the request came in on, or `null`.                                      |
| `guard`       | The authentication guard the subject was resolved from, or `null`.                      |
| `session`     | The session that signed in this very subject; a requirement checker judges its proofs.  |

Evaluation and RBAC run against `subject`; the decision events carry it in their `principal` field.

A subject that implements `AuthorizableMachine` is a machine principal (AUTHZ-2.4): it is allowed nothing without its
credential's scopes, which the bound `SessionPolicySource` answers for the `Subject` (see [Evaluation Order and Deny
Precedence](evaluation-order-and-deny-precedence.md#session-caps)). A machine is never treated as a person: when a
resolver pairs a machine with a person as its `identity`, or a person with a machine, the identity's roles,
permissions and allow statements never reach the subject, while its deny statements, its boundaries and its inactivity
still do. The shipped
resolver makes the user its own identity, so it never pairs the two.

## Shipped Implementation

`AuthGuardSubjectResolver` is the default binding, configured in `authorization.subject_resolver`. It reads the user
from Laravel's default guard (`auth.defaults.guard`, which `Auth::shouldUse()` changes), the guard Laravel's Gate takes
its user from. The user is the subject and its identity, no tenant is active, and the guard's name is the application
(AUTHZ-13.1). A request with no user has no subject. `forUser()` wraps the user it is handed in the same guard and
application without reading the guard.

The session is the current request's session id only when that session signed in that very user: the guard is a
`SessionGuard` using the request's session, once it has started, and the session's login key names the user, compared
strictly as strings. The user is the one `resolve()` reads, or that same user handed to `forUser()`, as the Gate does. A
user set on the guard without the session (through `once()`, `onceUsingId()`, `onceBasic()` or `setUser()`, so over a
session that may hold another user's login), a user a token or request guard returns, any other user, and every user
outside a session (a console command, a queued job, a stateless request), has none, and a subject without a session
meets no authentication requirement (N34). The request is read from the container on every resolution, never kept. A
resolver of the application's own sets `session` to whatever its requirement checker knows the proofs by, and only for
the user that session authenticated. A checker should still confirm the proofs it finds belong to `$subject->subject`.

So an application with a `web` guard and a `User` model (AUTHZ-1.1) gets `Authorization::can()`, the `role:` and
`permission:` middleware and the Blade directives deciding about the signed-in user with no setup. A deployment that
wants another guard binds the contract to an instance built with that guard's name:

```php
$this->app->singleton(SubjectResolver::class, fn ($app) => new AuthGuardSubjectResolver(
    $app->make('auth'),
    $app->make('config'),
    'api',
    $app,
));
```

Without the container, the resolver reads no session, so its subjects meet no authentication requirement.

## Scoped Subjects via `for()` and `forUser()`

`Authorization::for($model)` returns a cloned manager deciding about the model named, as its own identity, in the
request's tenant, application and guard (see `docs/design/impersonation.md`). Naming the request's own subject keeps
its identity. A subject named this way never has a session, whichever model it is, so no authentication requirement is
met for it. With no subject resolved, the clone has no tenant or application.

`Authorization::for($subject)` with a resolved `Subject` keeps it as it is, its session included, and, when it names a
tenant or an application, decides in the `AuthorizationScope` they make (its tenant, or the platform for none, and its
application). Each decision of the clone, `check()` and `checkMany()` and everything adapting them, the resource
reference `any()`, `all()` and `authorize()` resolve once for their checks, `explain()`, the provenance a refusal is
reported with, and each compile of a query scoped through it, runs inside that scope's `within()`, which puts the tenant
and application in place of the request's and restores them in `finally`, with what the resolution cache held; a scope
already in place is not entered again, so a `Subject` in the request's own scope costs nothing more. `permissionsFor()`
keeps the scope it is given. The scope is read from the subject at each decision, not when the clone is made, so a
tenant that cannot be read is refused with `InvalidTenantException` by the check, before anything is decided, as it was
before the subject's scope was put in place, and a caller wrapping `for()` in its own handling sees it where it did. The
subject lives on the clone alone, so nothing leaks to the manager it was made from or to the next request. `forUser()`,
`previewFor()` and `for()` of a model drop it. Delegated administration and access reviews decide an actor's rights in
the reach they put in place, so they use the internal `forActor()`, which names the acting `Subject` without its scope;
a preview's admitter is built the same way, so a preview keeps its own scope.

`Authorization::forUser($user)` returns a cloned manager deciding about the subject the resolver translates the user
into. The Gate hook uses it for the user Laravel hands over, and so does a Laravel policy class deciding through
`Concerns\DecidesThroughAuthorization`, for the user its method is given. `forUser(null)` decides about a guest: no
subject, so every check of the clone denies as `subject_unresolved`, whoever the request is about.

## Static Resolution Path

Middleware and Blade directives do not have the manager injected. Middleware reaches it as the root of the
`Authorization` facade; Blade helpers reach it through `AuthorizationManager::instance()`, from the
`HasContainerInstance` trait. Both resolve the request's subject through the manager's `currentSubject()`, so they see
the same `Subject` as the facade and the Gate.

The permission checks (the `permission` and `authorize` middleware and the permission directives) decide each action
through the manager's full decision, `can()` and `authorize()`, on that subject: policies, explicit denies, the
permissions held and the subject's tenant. Only the role checks (the `role` middleware and the role directives) read the
model the subject is about, `subject`, and call its `hasRole()`.

`TenantScope` reads the tenant from the `ResolvedTenant` holder, built once per request or job from the bound
resolver, and builds a new holder when the resolver bound now is not the one it came from. Resolving the subject can
itself query a scoped model (a user model that eager-loads its roles, for example); that query sees platform rows only
rather than asking the resolver again without end.

## Trade-offs

- **One seam rather than two.** A single resolver keeps the subject and its tenant consistent: a check can never be
  about one request's principal in another request's tenant. An application whose tenant comes from somewhere other
  than its user still answers it here, in `resolve()`.
- **No caching of the subject in the manager.** The manager asks the resolver on every check, so a login or logout
  mid-request is seen. The shipped resolver delegates to the guard, which caches its user; the tenant is held for the
  request or job by `ResolvedTenant`, and `TenantScope::flushResolvedTenant()` drops it.

## Implementation Anchors

- `Contracts\SubjectResolver` -- the contract.
- `Subject` -- the resolved subject, identity, tenant, application, guard and session.
- `Resolvers\AuthGuardSubjectResolver` -- the shipped default.
- `AuthorizationManager::currentSubject()`, `for()` and `forUser()` -- resolution and the scoped clones;
  `Concerns\BuildsScopedManagers::forActor()` -- an acting subject decided in the scope in place.
- `Registrars\GateRegistrar` -- the Gate hook translating its user; `Concerns\DecidesThroughAuthorization` -- a policy
  class translating its user the same way.
- `Support\ResolvedTenant` and `Scopes\TenantScope` -- the tenant held per request or job.
- `AbstractAuthorizationMiddleware` and `BladeHelpers::currentSubject()` -- the static resolution paths.

## Authoritative Tests

- `AuthGuardSubjectResolverTest` -- the signed-in user as subject, identity, guard and application; no user, no
  subject; the guard given at construction; a user loaded with its roles from the session.
- `SubjectTest` -- the value and `withSubject()`.
- `AuthorizationManagerTest` (Unit) -- `for()` keeps the tenant and application; `forUser()` uses the translation,
  and `forUser(null)` decides about no subject.
- `GateRegistrarTest` -- the Gate's user translated, `Gate::forUser($other)`, and a guest denied;
  `DecidesThroughAuthorizationTest` -- a policy class's user translated, and a guest denied.
- `TenantScopeTest` and `ResolvedTenantTest` -- the subject's tenant scopes the rows; no subject or tenant means
  platform rows only.
- `AuthorizationServiceProviderTest` -- the resolver and tenant rebuilt per job; an application's own binding kept; a
  binding made before registration standing, by `bind`, `singleton`, `scoped` or `instance`, for every seam.
- `AuthorizationServiceProviderTest` and `Registrars\SeamBindingsTest` -- a configured class replacing an earlier
  binding (N106), a deferred provider's included, whether the application knows of it as the package registers or learns
  of it before it boots, and a later binding standing at boot.
- `ConfigValidatorTest` -- the refusals of `subject_resolver`.
- `SubjectScope\AuthorizationManagerTest` (Feature) and `BuildsScopedManagersTest` -- a `Subject` decided in its own
  tenant and application by every method, parity with the `within()` form, the request's scope for a subject naming
  neither, restoration after a throw, `forActor()`, and a preview admitted in its own scope.
- `ReferenceTest` (Unit) -- a tenant referenced by its morph type and key, whatever its other identifiers.

## Change Triggers

- Adding a field to `Subject` (an authentication context, a session) requires updating every resolver and this note.
- Letting a single check name a tenant other than its subject's belongs to the administration and preview API, not to
  `for()`, which decides in the scope its `Subject` names.
- Keying tenants by an identifier other than `getKey()` would change every stored `tenant_id`, so it needs a migration
  and this note.
- Caching the resolved subject inside the manager would change the no-caching trade-off and must stay per request.
