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
   application binds itself, with `instance()`, `singleton()` or `bind()`, is kept across that reset.

6. **Configuration fails closed.** `authorization.subject_resolver` must name a class implementing the contract. Null,
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

`Authorization::forUser($user)` returns a cloned manager deciding about the subject the resolver translates the user
into. The Gate hook uses it for the user Laravel hands over. `forUser(null)` decides about a guest: no subject, so
every check of the clone denies as `subject_unresolved`, whoever the request is about.

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
- `AuthorizationManager::currentSubject()`, `for()` and `forUser()` -- resolution and the scoped clones.
- `Registrars\GateRegistrar` -- the Gate hook translating its user.
- `Support\ResolvedTenant` and `Scopes\TenantScope` -- the tenant held per request or job.
- `AbstractAuthorizationMiddleware` and `BladeHelpers::currentSubject()` -- the static resolution paths.

## Authoritative Tests

- `AuthGuardSubjectResolverTest` -- the signed-in user as subject, identity, guard and application; no user, no
  subject; the guard given at construction; a user loaded with its roles from the session.
- `SubjectTest` -- the value and `withSubject()`.
- `AuthorizationManagerTest` (Unit) -- `for()` keeps the tenant and application; `forUser()` uses the translation,
  and `forUser(null)` decides about no subject.
- `GateRegistrarTest` -- the Gate's user translated, `Gate::forUser($other)`, and a guest denied.
- `TenantScopeTest` and `ResolvedTenantTest` -- the subject's tenant scopes the rows; no subject or tenant means
  platform rows only.
- `AuthorizationServiceProviderTest` -- the resolver and tenant rebuilt per job; an application's own binding kept.
- `ConfigValidatorTest` -- the refusals of `subject_resolver`.

## Change Triggers

- Adding a field to `Subject` (an authentication context, a session) requires updating every resolver and this note.
- Letting a check name a tenant explicitly belongs to the administration and preview API, not to `for()`.
- Caching the resolved subject inside the manager would change the no-caching trade-off and must stay per request.
