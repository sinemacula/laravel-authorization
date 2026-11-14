# Testing

In your tests, `SineMacula\Laravel\Authorization\Testing\Concerns\AuthorizationAssertions` adds `assertCan()`,
`assertCannot()`, `assertHasRole()` and `assertHasPermission()`, and `actingAsIdentity($user, $tenant)` and
`actingAsSubject($subject)`, which make every check without a named subject about that subject, in its tenant. They also
make the subject's identity, or its principal when it has none, the Gate's user, so `Gate::allows()`, `@can` and `can:`
decide about the same subject as the facade without a user signed in; `Gate::forUser()` with the subject's principal or
identity does too. The Gate they bind keeps every ability, policy and callback registered before, and lives in the
test's container, so nothing carries over to the next test. A subject built without a `session` meets no authentication
requirement, so to test one give it a session and bind a checker of your own:

```php
$this->app->instance(AuthenticationRequirementChecker::class, new MetRequirementChecker);
$this->actingAsSubject(new Subject($user, $user, session: 'session-1'));
```

`SineMacula\Laravel\Authorization\Testing\Concerns\TenantTreeContract` checks a tenant tree of your own against the
contract the package reads it by, and `SineMacula\Laravel\Authorization\Testing\FakeTenantTree` is an in-memory tree to
bind in tests of your own (see [Managing roles, permissions and
grants](grants.md#managing-roles-permissions-and-grants)).
