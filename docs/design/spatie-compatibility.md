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

Source: `BladeDirectiveRegistrar::register()` and `BladeHelpers`.

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
| `@permission`        | `@haspermission`      | Allowed any of the listed perms |
| `@anypermission`     | `@hasanypermission`   | Allowed any of the listed perms |
| `@allpermissions`    | `@hasallpermissions`  | Allowed every listed perm       |

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

The directives accept an `array|string`, and every entry is split on the pipe (`|`), trimmed, and its empty names
dropped, so Spatie's `@hasrole('admin|editor')` idiom is honoured, `@hasrole(['admin', 'editor'])` names the same two
roles, and `@hasrole('')` admits no one.

The permission directives differ from Spatie's on purpose: they decide each action on the package's full decision, as
`@can` does, not on the permissions held alone. An explicit policy deny hides the block from a subject that holds the
permission, and a policy allow shows it to one that does not. The role directives check role membership on the
subject, as Spatie's do; a role is not an action, so policies do not apply to them.

A second argument is a guard, as in Spatie's `@hasrole('admin', 'api')`. A role directive honours it: only roles of that
authentication guard and guard-agnostic ones count, and a name that is not in `auth.guards` is refused. A permission
directive refuses any guard with an `InvalidCheckArgumentException`, since no guard changes the decision it makes. A
third argument is refused too, rather than dropped.

## Route middleware

Source: `AuthorizationServiceProvider::registerRouteMiddleware()` and `src/Http/Middleware/`.

The `role` and `permission` middleware aliases, and the package's own `authorize` alias, are registered automatically
unless a consumer has already bound a middleware with the same key (existing bindings take precedence). As in Spatie,
the first argument lists alternatives separated by a pipe (`|`), and any one of them admits the request:

```php
// Spatie
Route::get('/posts', [PostController::class, 'index'])
    ->middleware('role:admin|editor');

Route::delete('/posts/{post}', [PostController::class, 'destroy'])
    ->middleware('permission:posts.delete|posts.purge');

Route::get('/api/posts', [PostController::class, 'index'])
    ->middleware('role:admin|editor,api');

// Ours — the exact same declarations work verbatim.
```

A comma does not list alternatives: as in Spatie, the second argument is the guard. `role:` honours it, limiting the
check to the roles of that authentication guard and the guard-agnostic ones. It refuses a name that is not in
`auth.guards`, and a bare name that is also the name of a role, of any tenant, since `role:editor,admin` may be an old
"editor or admin" list rather than the `admin` guard; written as `role:editor,guard=admin`, it is always the guard. So
`role:admin,editor` fails loudly unless `editor` is a guard and no role is called `editor`. `permission:` refuses a
guard, because it decides each action on the package's full decision (policies, explicit denies, the permissions held
and the subject's tenant), which no guard changes; an explicit deny wins over a held permission there, unlike Spatie. A
third argument, or a list that names nothing, is refused. The "must have all" case is expressed via middleware chaining
(`->middleware(['role:admin', 'role:editor'])`).

`authorize:{action},{route parameter}` has no Spatie equivalent: it decides the action on the parameter's bound model,
with the model as the resource, as `Gate::allows($action, $model)` decides it. Like Laravel's `can` middleware, it is
placed right after `SubstituteBindings` in the middleware priority, so it sees the bound model however the route orders
its middleware.

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

The package also ships `AuthorizationFailed` (hard-denial, fired from `authorize()`, and from the `permission` and
`authorize` middleware, before the exception is thrown; a `role` denial is not a decision and fires none) and
`DecisionEvaluated` (every evaluation path, denials, previews and allows as `events.decisions` selects, including a Gate
check whose argument cannot be identified as a resource, which is recorded as an implicit deny with a `null` resource) —
Spatie has no equivalents; audit consumers subscribe to these to persist who each decision was about, its reason, the
statements that decided it and the context keys it read, never their values. The decision itself, with its trace, is
read from `Authorization::lastDecision()`.

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
- **Teams / tenancy columns** — Spatie's optional `team_id` scoping column is not shipped. Roles, permissions and
  policies are owned by the platform or by one tenant through their own `tenant_type` / `tenant_id` columns, and each
  grant carries a scope of its own; `authorization:migrate-spatie` imports Spatie's rows and grants platform-wide,
  through the management services, so each is validated and reported as any other write is. Spatie's string ids are
  kept, but its timestamps are not: each imported role and permission is created through its service, so its
  `created_at` and `updated_at` are the time of the import rather than Spatie's.
- **`guard_name`** — the guard column is `guard`. `authorization:migrate-spatie` maps Spatie's `guard_name` onto it,
  so code that reads `$role->guard_name` reads `$role->guard` instead.
- **Wildcard permission classes** — Spatie's `WildcardPermission` helper is not needed; wildcard matching is the
  default behaviour of `hasPermission()` (fnmatch semantics, see `docs/design/wildcard-and-condition-semantics.md`
  when that note lands).

## Not included

Anything not listed above is **not** part of the Spatie compat surface. If you hit a Spatie idiom that doesn't port
cleanly, file an issue — the compat layer exists to make the migration boring, and a gap is a bug in the mapping,
not a sign that you should rewrite the call site.
