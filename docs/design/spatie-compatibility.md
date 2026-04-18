# Spatie Compatibility Surface

`sinemacula/laravel-authorization` ships a deliberate Spatie-compatibility layer so teams migrating from
`spatie/laravel-permission` can move views, controllers, and route declarations verbatim. This note catalogues every
alias the package currently ships, grouped by surface, and flags the intentional omissions.

The canonical API is ours (`givePermission`, `revokePermission`, `hasPermission`, `getPermissions`, `assignRole`,
`revokeRole`, `hasRole`, `getRoles`, `attachPolicy`, `detachPolicy`). Spatie aliases forward to the canonical helper
and are a porting convenience, not a separate code path — they share the same events, cache, and validation.

## Trait method aliases

Source: `src/Traits/HasPermissions.php`, `src/Traits/HasRoles.php`, and `src/Models/Role.php` (the role model has its
own permission-attachment surface and mirrors the same four permission aliases).

| Spatie call            | Our equivalent         | Surface                                     |
|------------------------|------------------------|---------------------------------------------|
| `givePermissionTo()`   | `givePermission()`     | `HasPermissions` trait, `Role` model        |
| `revokePermissionTo()` | `revokePermission()`   | `HasPermissions` trait, `Role` model        |
| `hasPermissionTo()`    | `hasPermission()`      | `HasPermissions` trait, `Role` model        |
| `getPermissionNames()` | `getPermissions()`     | `HasPermissions` trait, `Role` model        |
| `removeRole()`         | `revokeRole()`         | `HasRoles` trait                            |
| `getRoleNames()`       | `getRoles()`           | `HasRoles` trait                            |

Porting example:

```php
// Spatie
$user->givePermissionTo('posts.edit');
$user->revokePermissionTo('posts.edit');
$user->hasPermissionTo('posts.edit');
$user->getPermissionNames();
$user->removeRole('editor');
$user->getRoleNames();

// Ours (canonical) — aliases above forward to these verbatim
$user->givePermission('posts.edit');
$user->revokePermission('posts.edit');
$user->hasPermission('posts.edit');
$user->getPermissions();
$user->revokeRole('editor');
$user->getRoles();
```

`hasPermission()` (and therefore `hasPermissionTo()`) consults both direct grants and role-inherited permissions —
Spatie's split between `hasPermissionTo` and `hasPermissionThroughRole` is folded into a single check; see the
*Deliberate omissions* section.

## Blade directives

Source: `AuthorizationServiceProvider::registerBladeDirectives()`.

The package registers both the canonical short-form directives (`@role`, `@permission`, `@anyrole`, `@allroles`,
`@anypermission`, `@allpermissions`) and the Spatie-shaped `@has…` aliases in parallel. Both families support
`@unless<name>` / `@else<name>` / `@end<name>` automatically via `Blade::if`, and every directive ships a matching
`@endunless<name>` alias so Spatie's `@endunlessrole` / `@endunlesspermission` spellings compile cleanly too
(issue \#86).

Full directive list:

| Canonical            | Spatie-shaped alias   | Semantics                       |
|----------------------|-----------------------|---------------------------------|
| `@role`              | `@hasrole`            | Has any of the listed roles     |
| `@anyrole`           | `@hasanyrole`         | Has any of the listed roles     |
| `@allroles`          | `@hasallroles`        | Has every listed role           |
| `@permission`        | `@haspermission`      | Has any of the listed perms     |
| `@anypermission`     | `@hasanypermission`   | Has any of the listed perms     |
| `@allpermissions`    | `@hasallpermissions`  | Has every listed perm           |

Each of the twelve names above ships the full quartet (`@name`, `@unlessname`, `@elsename`, `@endname`) plus the
Spatie-compatible close (`@endunlessname`).

Porting example:

```blade
{{-- Spatie --}}
@hasrole('admin|editor')
    …
@endhasrole

@hasanypermission(['posts.edit', 'posts.delete'])
    …
@endhasanypermission

@unlessrole('admin')
    …
@endunlessrole

{{-- Ours — the exact same markup works verbatim --}}
@hasrole('admin|editor')
    …
@endhasrole
```

The directives accept an `array|string` — string inputs are split on the pipe (`|`) so Spatie's
`@hasrole('admin|editor')` idiom is honoured, and array inputs (`@hasrole(['admin', 'editor'])`) are passed through
unchanged.

## Route middleware

Source: `AuthorizationServiceProvider::registerRouteMiddleware()` and `src/Http/Middleware/`.

The `role` and `permission` middleware aliases are registered automatically unless a consumer has already bound a
middleware with the same key (existing bindings take precedence). Both aliases accept pipe (`|`) and comma (`,`)
separators — the package flattens both before dispatching, so Spatie's pipe form and Laravel's native comma form
behave identically:

```php
// Spatie
Route::get('/posts', [PostController::class, 'index'])
    ->middleware('role:admin|editor');

Route::delete('/posts/{post}', [PostController::class, 'destroy'])
    ->middleware('permission:posts.delete|posts.purge');

// Ours — the exact same declarations work verbatim,
// and Laravel's native comma form is equally supported:
Route::get('/posts', [PostController::class, 'index'])
    ->middleware('role:admin,editor');
```

Multiple middleware arguments are treated as an OR match: `role:admin,editor` authorises if the principal has *any*
listed role. The "must have all" case is expressed via middleware chaining (`->middleware(['role:admin', 'role:editor'])`).

## Event names

The package deliberately scopes its events by namespace rather than adopting Spatie's unqualified
names. The difference is intentional — a `RoleAssigned` listener that expected the role-catalogue lifecycle trio in
Spatie would silently bind to identity-level assignments in this package, so the namespace makes the scope explicit
on purpose.

| Spatie event                | Our event                                | Why the name differs               |
|-----------------------------|------------------------------------------|------------------------------------|
| `RoleAssigned`              | `Events\Identity\RoleAssigned`           | Explicit identity scope            |
| `RoleRevoked`               | `Events\Identity\RoleRevoked`            | Explicit identity scope            |
| `PermissionAssigned`        | `Events\Identity\PermissionGranted`      | Scope + "granted" per IAM vocab    |
| `PermissionRevoked`         | `Events\Identity\PermissionRevoked`      | Explicit identity scope            |

The `Events\Role\*`, `Events\Permission\*`, and `Events\Policy\*` lifecycle events (`Created`, `Updated`, `Deleted`)
cover the *catalogue* lifecycle — the role/permission/policy rows themselves — and are distinct from the
identity-level events. The `Events\Role\PermissionGranted` / `Events\Role\PermissionRevoked` pair fires when
permissions are attached to or detached from a role, which Spatie does not emit as a distinct event.

The package also ships `AuthorizationFailed` (hard-denial, fired from `authorize()` before the exception is thrown)
and `DecisionEvaluated` (every evaluation path, success or denial) — Spatie has no equivalents; audit consumers
subscribe to these to persist the decision trace.

See each event class under `src/Events/` for the full audit payload — every event carries a stable `@api` contract
and breaking changes require a major version bump.

## Deliberate omissions

The package deliberately does **not** ship the following Spatie surface:

- **`hasPermissionThroughRole()`** — folded into `hasPermission()`. The canonical check always consults both direct
  grants and role-inherited permissions; exposing a separate "through role" check would encourage consumers to ask
  the wrong question for policy evaluation. The `permissions()` relation (direct grants only) and the `roles()`
  relation (role-inherited, transitively resolvable) are both available when a consumer genuinely needs to separate
  the two sources.
- **`hasDirectPermission()`** — consumers that need the direct-only view use the `permissions` relation on the
  identity; the short-circuiting check is not a primitive of the canonical API.
- **`hasExactRoles()`** — not shipped; expressible via `count($user->getRoles()) === N && $user->hasAllRoles([…])`.
- **Role-model role helpers** — Spatie ships `$role->assignRole()` / `$role->hasRole()` for nested role hierarchies.
  This package treats roles as a flat namespace; nested roles are out of scope and there is no role-on-role API.
- **`Role::findByName()` / `Role::findById()` / `Role::findOrCreate()`** — consumers use the Eloquent model's native
  `where()` and `firstOrCreate()` builders; the wrapper methods don't add enough value to justify the API surface.
  The same applies to `Permission` lookups.
- **Guard auto-detection from the HTTP auth stack** — the package resolves the guard via the
  `getAuthorizationGuard()` opt-in hook on the identity model, not by sniffing the active web/api guard at
  authorization time. Multi-guard deployments declare the guard on the model; there is no implicit request-scoped
  guard resolution.
- **Teams / tenancy columns** — Spatie's optional `team_id` scoping column is not shipped. Tenancy is a consumer
  concern; the `conditions` block of a policy document is the supported primitive for scoping decisions to a tenant,
  resource owner, or any other attribute.
- **Wildcard permission classes** — Spatie's `WildcardPermission` helper is not needed; wildcard matching is the
  default behaviour of `hasPermission()` (fnmatch semantics, see `docs/design/wildcard-and-condition-semantics.md`
  when that note lands).

## Not included

Anything not listed above is **not** part of the Spatie compat surface. If you hit a Spatie idiom that doesn't port
cleanly, file an issue — the compat layer exists to make the migration boring, and a gap is a bug in the mapping,
not a sign that you should rewrite the call site.
