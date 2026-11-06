# Gate Authority

The package is the authority of Laravel's Gate for every ability it declares (AUTHZ-9.1). This note explains the one
`Gate::before` hook through which it answers, which abilities it answers and which fall through to Laravel, the
registration order that decides precedence, whom a Gate check is about, the switch that turns the hook off, and how a
Laravel policy class decides through the package (AUTHZ-9.2) for the abilities the hook leaves to it.

## Invariants

1. **One hook, no defines.** Booting registers a single `Gate::before` callback and defines no ability. The Gate
   contract is not wrapped or replaced, so `Gate::forUser()`, `@can`, the `can:` middleware, `Gate::authorize()` and a
   controller's `authorize()` reach the hook as Laravel's own Gate calls it, and `Gate::forUser()` copies it to the
   Gate it returns.

2. **The declared names, exactly.** The hook answers an ability whose exact name the permission catalogue holds: every
   case of the configured enums, every permission of the configured providers, whatever its guard, and the package's
   own (`PackagePermissions`). The match is by membership, never by pattern, so `posts:*` is answered only when a
   permission of that name is declared. A permission row that exists only in the database is not declared.

3. **Both answers stand.** For a declared ability the hook returns the decision of `check()` (D22), true for an allow
   and false for a deny. Laravel stops at the first before-callback that answers and ignores an after-callback's answer
   once one is given, so no `Gate::define` callback, Laravel policy class or `Gate::after` callback can override
   either.

4. **Everything else falls through.** For any other ability the hook returns null and records no decision, so Laravel
   decides it exactly as without the package.

5. **The first registered answers first.** Laravel runs before-callbacks in registration order and the first non-null
   answer wins. The provider registers the hook right after validating the configuration, before anything else in its
   boot, so a `Gate::before` the application registers once the package has booted never pre-empts it. One registered
   before the package boots still can; that is Laravel's order, documented rather than worked around.

6. **A guest is no subject.** The Gate's user goes through `forUser($user)`, which the subject resolver translates
   into the subject (see `subject-resolver-contract.md`). A guest (no user) is decided as no subject, which denies as
   `subject_unresolved`; it never falls back to the request's own subject.

7. **Cheap on every call.** The hook runs on every Gate check, the application's own included. The declared names are
   read through the permission catalogue on the first check of a request or job and kept as a set
   (`DeclaredAbilities`, bound with `scoped()`), so an undeclared ability costs one set lookup, and booting reads no
   enum or provider for the hook (a provider is read at boot only to check the session scope map, see
   `permission-catalogue-sync.md`).

8. **The switch is explicit.** `authorization.gate.enabled` (default true) is validated strictly as a boolean at boot;
   any other value is refused. When false no hook is registered and nothing is bound for it. `authorization:check`
   reports whether the hook is enabled.

## Success Path

`Gate::allows('posts:update', $post)` for a signed-in user reaches the hook with the user, the ability and the
arguments. `posts:update` is declared, so the arguments are translated into the resource and the caller's values
(`input`), exactly as before the hook existed, the user is translated into the subject, and `check()` decides. Its
allow or deny is the Gate's answer; any define or policy for `posts:update` is never called.

## Failure / Edge Cases

- **Undeclared ability.** `Gate::allows('reports:view')` with nothing declaring it is answered by the application's
  define or policy, or denied by Laravel when there is none. The package records nothing.
- **Database-only row.** A permission created only in the database, and granted, is decided by `Authorization::can()`
  but is not the Gate's to the package.
- **Malformed catalogue.** A declaration that breaks the name rules throws on the first Gate check, as on any other
  read of the catalogue, rather than letting the Gate decide by default.
- **Hook turned off.** With `authorization.gate.enabled` false, the Gate knows none of the package's permissions; the
  package's own API, middleware and directives still decide them.
- **Policy classes.** A Laravel policy class can decide through the package with
  `Concerns\DecidesThroughAuthorization`: each method names its action and calls `decide()`, which makes one
  `forUser($user)->check()` and returns `Response::allow()`, or `Response::deny()` with the reason code as its code and
  the generic `authorization::authorization.denied` line as its message, whatever the reason (N61), never a not-found
  response. No method name is mapped to an action. For a declared ability the hook answers before any policy class
  runs (invariant 3), so the trait serves the abilities the hook leaves to Laravel (invariant 4), and every ability
  when the hook is off. An `insufficient_authentication` denial keeps its code but raises no step-up exception and
  carries no requirements; `authorize()` and `check()` do.

## Implementation Anchors

- `Registrars\GateRegistrar` -- the switch, the hook, and the translation of the Gate's arguments.
- `Support\DeclaredAbilities` -- the declared names, read once per request or job.
- `AuthorizationManager::forUser()` -- the Gate's user translated, a guest as no subject.
- `Concerns\DecidesThroughAuthorization` and `Support\PolicyResponses` -- a policy class deciding through the package,
  and the decision as a policy response.
- `Config\ConfigValidator` -- the strict switch.
- `Console\CheckConfigurationCommand` -- `authorization:check`, one line per check.

## Authoritative Tests

- `GateRegistrarTest` -- allow and deny over a define and a Laravel policy class, precedence both ways, undeclared and
  database-only abilities falling through, provider and package abilities answered, a guest denied, `@can`, `can:`
  and `authorize()` through the hook, and the switch off.
- `DecidesThroughAuthorizationTest` -- a policy method allowed and denied through the Gate with one check, the code
  and the translated message, a reworded line, `insufficient_authentication`, a guest, every resource form and the
  context under `input`; `PolicyResponsesTest` -- every reason's response, each with its code and the generic line.
- `DeclaredAbilitiesTest` -- exact membership, one read per instance, one instance per job.
- `ConfigValidatorTest` -- the strict switch.
- `CheckConfigurationCommandTest` -- the report.
- `GateHookBudgetTest` -- the cost of falling through and of a declared ability.

## Change Triggers

- Answering abilities by pattern, or for undeclared rows, would change what falls through and must update this note.
- Wrapping the Gate contract, or registering the hook anywhere other than first in the provider's boot, changes the
  precedence the README documents.
- Each setting or seam `authorization:check` comes to report adds a line to its output.
- Mapping a policy method's name to an action, raising the step-up exception from the policy-class trait, or turning
  a denial into a not-found response would change what a policy class's response means and must update this note
  and the README.
