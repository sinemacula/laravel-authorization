# Seams and the suite

The package makes the decision, but who the subject is, where tenants sit, what a session has proved and what a
credential carries come from outside it, through contracts in `SineMacula\Laravel\Authorization\Contracts`. Most have a
default that works alone, and under `sinemacula/laravel-iam` sibling packages bind adapters to several of them. Which
binding wins, a class your configuration names, a sibling's or your own, is set out in
[Configuration](configuration.md), and `authorization:check` shows where each seam's binding came from (see [Checking
the configuration](console.md#checking-the-configuration)).

## The contracts the suite binds

| Contract                           | Configured as         | Default alone                                                        | Under `laravel-iam`                                                        |
|------------------------------------|-----------------------|----------------------------------------------------------------------|----------------------------------------------------------------------------|
| `SubjectResolver`                  | `subject_resolver`    | The default guard's user, no tenant, the guard's name as application | One delegating to `laravel-authentication`                                 |
| `AuthenticationContext`            | -                     | The default guard's name, the signed-in user's key and morph type    | `laravel-authentication`'s authentication context                          |
| `AuthenticationRequirementChecker` | `requirement_checker` | Finds every part of every requirement unmet                          | `laravel-mfa`'s requirement check                                          |
| `SessionPolicySource`              | `session.source`      | The subject's own `scopes`, null when it says nothing                | One reading the caller's credential's scopes from `laravel-authentication` |
| `ScopeRegistry`                    | -                     | None bound; `CatalogueScopeRegistry` ships                           | Bound for `laravel-authentication`'s scope registry                        |
| `IdentityDirectory`                | `identity_directory`  | Each user its own identity, under the shipped resolver alone         | `laravel-iam`'s own directory                                              |
| `GrantHook`                        | `grant_hooks`         | `GrantHooks`, holding no hook                                        | `laravel-sso`'s scope widening                                             |

The defaults are `AuthGuardSubjectResolver`, `GuardAuthenticationContext`, `RefusingRequirementChecker`,
`NoSessionPolicy`, `GuardUserIdentityDirectory` and `GrantHooks`. Under any subject resolver but the shipped one,
`GuardUserIdentityDirectory` answers every identity's principals as incomplete, so a grant to any principal that is
weighed for widening is treated as widening. The hooks `grant_hooks` lists run before whatever hook the contract
resolves to, rather than replacing it. Each seam is covered where it is used: [the subject resolver](configuration.md),
[the authentication context](context.md#the-checks-context) and [requirement
checker](context.md#authentication-requirements) (with what `laravel-iam` maps for MFA in [Under the
suite](context.md#under-the-suite)), [the session policy source and the scope
registry](caps.md#session-caps-and-machines), [the identity directory](administration.md#grant-scope-query) and [grant
hooks](administration.md#grant-hooks).

## The rest

The package names no sibling adapter for the other seams; the application binds them when the default does not fit.

| Contract                 | Configured as              | Default                                                                                       |
|--------------------------|----------------------------|-----------------------------------------------------------------------------------------------|
| `TenantTree`             | `tenant_tree`              | `FlatTenantTree`: no tenant has a parent                                                      |
| `ResourceTenantResolver` | `resource_tenant_resolver` | `NoResourceTenant`: no record has a tenant; a model declaring its tenancy is answered from it |
| `PolicyStore`            | `policy_store`             | None bound                                                                                    |
| `PolicyResolver`         | -                          | `DefaultPolicyResolver`: the policy store's policies with the principal's own                 |
| `ActionCatalogue`        | -                          | `DeclaredActionCatalogue`: the permissions the code declares                                  |
| `ContextKeyCatalogue`    | -                          | `DeclaredContextKeyCatalogue`, one per application                                            |
| `RequestContext`         | -                          | `RoutedRequestContext`: the client IP, method and route name                                  |
| `EnvironmentContext`     | -                          | `ClockEnvironmentContext`: the current time, fixed for the check                              |
| `GrantUsageStore`        | -                          | `DatabaseGrantUsageStore`, on the package's tables                                            |
| `ConsoleSubjectResolver` | -                          | `ReferenceSubjectResolver`: loads a `{morphType}:{key}` reference                             |

## What the suite calls

The suite also calls into the package. `ApplicationAccess::mayUse()` answers `laravel-authentication`'s application
access contract, once `laravel-iam` binds that contract to an adapter calling it (see [Application
access](grants.md#managing-roles-permissions-and-grants)). The [grant scope query](administration.md#grant-scope-query)
answers `laravel-iam`'s questions about grants as it composes SSO's principal scope and a tenant's admission. A package
that records or revokes a proof calls `Authorization::forgetDecisionsFor()` (see [Forgetting
decisions](context.md#forgetting-decisions)), and the application reports a change to its tenant tree with
`Authorization::treeChanged()` (see [Tree changes](caching.md#tree-changes)).
`AuthorizationServiceProvider::isPackageDefault()`, `Support\RequestState`, `Diagnostics\Declarations` and
`Config\TableNames`, `Config\ModelClasses` and `Config\DefaultGuard` are for sibling packages too.

## Middleware order

Run authentication first, then MFA step-up, then the package's `permission:`, `authorize:` and `role:` middleware. A
request that is not signed in is then answered by authentication with a `401`, and one not signed in strongly enough by
the step-up middleware, before the package can deny it. The package denies a request with no subject as unauthenticated,
and one decided `insufficient_authentication` with an `InsufficientAuthenticationException`, which renders as a `403`
unless it is mapped to a step-up response (see [The decision and the
exception](context.md#the-decision-and-the-exception)):

```php
Route::middleware(['auth:sanctum', /* step-up middleware */ 'authorize:invoices:refund,invoice'])
    ->post('/invoices/{invoice}/refund', RefundInvoice::class);
```

The package puts `authorize:` right after `SubstituteBindings` in the middleware priority, as Laravel puts `can:`, so it
decides on the bound model. It ranks neither its other middleware nor a step-up middleware, so list them in the order
above.

## Example: an adapter that gives way to the application's

A sibling package supplying credential scopes binds its source only over the package's default, so a source the
application bound or named in its configuration stands, and declares it, so the report names it. It registers after this
package:

```php
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;

public function register(): void
{
    if (!AuthorizationServiceProvider::isPackageDefault($this->app, SessionPolicySource::class)) {
        return;
    }

    $this->app->scoped(TokenScopeSource::class);

    $binding = static fn (Application $app): SessionPolicySource => $app->make(TokenScopeSource::class);

    $this->app->bind(SessionPolicySource::class, $binding);

    Declarations::of($this->app)->adapter(
        SessionPolicySource::class,
        'acme/credentials',
        TokenScopeSource::class,
        Lifetime::SCOPED,
        $binding,
    );
}
```

`isPackageDefault()` is false for a class other than the default that `session.source` names, from the moment the
package registers, though that class is bound only as the application boots, so the adapter never replaces it. The
source is scoped, so each request or job reads its own caller's credential (see [Octane and long-lived
workers](long-lived-workers.md)), and `authorization:check` shows the seam as `declared` by `acme/credentials`.
