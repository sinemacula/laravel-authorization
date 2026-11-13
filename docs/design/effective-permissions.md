# Effective Permissions

A UI needs the actions a subject may take in a scope, to show or hide its controls (AUTHZ-10.4). This note explains
`permissionsFor()`, which lists them: the scope it lists them in, what makes a listing exact, why it decides every
action through the one decision path rather than computing allows less denies, and why it records nothing.

## Invariants

1. **Exact (N69).** `permissionsFor($subject, $scope, $context)` returns the actions
   `PermissionCatalogue::definitions()` declares (the package's own permissions, the cases of the configured enums and
   the definitions of the configured providers), each name once, in the catalogue's order, for which
   `check($action, $scope->resource, $context)` would allow, in the scope, about the subject, under the same state. An
   action listed that the same check then denies is a bug. Nothing is inferred from wildcard grants, `not_actions` or
   stored permission names: an action the catalogue does not declare is never listed.

2. **One decision path (D22).** The actions are decided as one batch through `CheckBatch`, the path `checkMany()`
   takes: the same pipeline `decide()`, admission stages, `ResourceScope` and policy evaluator, over what the checks
   share read once. There is no second evaluator: denies, conditions, guardrails, boundaries, session caps (a `capped()`
   manager's included), a `withPolicies()` override and authentication requirements are weighed exactly as `check()`
   weighs them. An action whose check would be `insufficient_authentication` is not listed, and one whose check would
   throw makes the listing throw the same exception, failing closed.

3. **The scope (N71).** `Support\AuthorizationScope` names the tenant (a `Reference`, or null for the platform), the
   application (or null for none) and an optional resource in any form `check()` takes. `current()` captures the
   request's tenant and application as the resolvers report them, `platform()` names no tenant and `tenant()` names
   one; null never means "inherit". The scope is applied with `TenantScope::within()`, so the checks see it as the
   ambient grant scope, and the subject's tenant and application are replaced by it (`subjectIn()`), so `subject.tenant`
   reads it too. The request's scope is restored in `finally`, even when a check throws. A scope already in place
   (the same tenant and application, decided in the tenant rather than below it), such as `current()`, is not entered
   again, so the resolution cache's memo is neither set aside nor emptied. Another scope is entered inside a resolution
   cache batch that sets the request's memo aside and puts it back once the scope is restored, unless a write emptied
   the cache meanwhile (`ResolutionCache::batch(..., isAside: true)`).

4. **Admission still applies.** The resource's own tenant goes through `ResourceScope` as for `check()`: a resource
   below the scope's tenant is decided in its own tenant, one outside it at platform scope only when a platform-wide
   grant admits it, else as `tenant_scope`. Naming a resource never replaces the scope's tenant.

5. **The subject (N74).** A resolved `Subject` is used as it is, its identity, guard and session kept. Any other object
   is named as `for()` names it (`currentSubject()->withSubject()`), so it has no session and meets no authentication
   requirement. Null is the manager's current subject, exactly as `check()` takes it: the request's on the facade, the
   named one on `Authorization::for($user)`, and a guest, allowed nothing, on `Authorization::forUser(null)` or when the
   request has none. The subject is resolved before the scope is entered. On a manager from `for()` of a `Subject`
   naming a tenant or an application (N109), the listing's scope still wins: it is listed in the scope given, as it is
   inside `AuthorizationScope::within()`, never in the one the subject names.

6. **Introspection records nothing (N70).** The batch is made with both `isDispatching` and `isStoring` false, two
   switches on the shared path rather than a copy of the decision loop: it stores no last decision and dispatches no
   `DecisionEvaluated`; `AuthorizationFailed` is never dispatched since nothing is authorized. A listing is exempt from
   break-glass reporting too (N142): an action it lists through a break-glass activation is reported by no event. A
   preview's listing is the one exception (N86): it dispatches each action's `DecisionEvaluated` while
   `events.decisions.previews` is on, naming both parties, and an allow that used break-glass whatever the settings,
   with `usedBreakGlass` set, and still stores none of them (see [Preview](preview.md)).

7. **Generic and resource-specific listings differ.** A listing with no resource answers the resource-less check, so an
   allow limited by `resources` or by a resource's attributes does not list its action; a listing for one resource
   answers for that resource. A row's controls take the resource-specific listing.

8. **The consistency boundary.** A listing is a snapshot of the state while it is decided, with the bulk checks'
   boundary (see `bulk-checks.md`). State may change between rendering and the request, so the server still authorizes
   every action when it is taken.

9. **The catalogue.** The catalogue is read from code on each call and touches no database. The configuration is read
   after boot, so an entry of `authorization.permission_enums` or `authorization.permission_providers` the boot
   validation would refuse is refused with `InvalidAuthorizationConfigException` when the catalogue is read, and nothing
   is listed; a definition the catalogue refuses (an invalid name, an empty guard, a name declared twice for a guard
   with different metadata, a provider returning something else) throws `InvalidPermissionCatalogueException`, so
   nothing is listed. A provider that throws makes the listing throw what it throws.

## Success Path

`Authorization::permissionsFor($user, AuthorizationScope::tenant($account, 'admin'))` reads the catalogue, names the
user as `for()` would, and enters the account's scope on the admin application. It decides one `CheckInput` per declared
action, with no resource, as one batch that records nothing: the subject's grants, roles, policies, boundary and caps
and the guardrails are read once for the scope, and each action is decided through the pipeline. Given a resource, it is
told once, in the scope, and every action is decided on that one `ResourceReference`, so its tenant, attached policies
and attributes are read once for the listing: `CheckBatch` keeps a reference several checks share, and what its
attribute provider answered, values or failure, until the last of them is decided, across chunks too. The actions
allowed are returned in the catalogue's order, the request's scope is restored, and the last decision is the one the
request recorded before.

## Failure / Edge Cases

- **A failing attribute provider.** With a resource whose provider fails, the provider is asked once, and only when an
  action's check reads `resource`; that action throws `AttributeProviderFailed`, nothing is listed and the scope is
  restored. An action whose check never reads `resource` does not see the failure.
- **A catalogue that cannot be read.** It throws `InvalidPermissionCatalogueException` before any action is decided.
- **A name for two guards.** It is listed once, where it is first declared.
- **No catalogue.** The package's own permissions are always declared, so a subject allowed none of them lists nothing.
- **Many actions.** Each action is decided in a chunk of `authorization.bulk.chunk_size`, as `checkMany()` decides.

## Implementation Anchors

- `AuthorizationManager::permissionsFor()` -- the subject, the catalogue's actions, the scope entered and the batch.
- `Support\AuthorizationScope` -- the named constructors, `withResource()`, `within()` (which skips a scope already in
  place and sets the memo aside for another) and `subjectIn()`.
- `Evaluation\CheckBatch` -- `isDispatching` and `isStoring`, the switches introspection turns off, and the shared
  reference's attributes kept until its last check.
- `Context\ResourceAttributeBatch` -- one item per shared reference, its bulk or single answer kept for every check.
- `Cache\ResolutionMemo::aside()` -- the request's memo set aside and put back around another scope.
- `Support\PermissionCatalogue::definitions()` -- the actions, refusing a malformed enum or provider list with
  `InvalidAuthorizationConfigException`.
- `Concerns\HasPermissions::permissionsFor()` and the facade's docblock -- the delegates.

## Authoritative Tests

- `Integration\PermissionsFor\ParityPropertyTest` -- generated catalogues, grants, roles, boundaries, guardrails, caps,
  overrides, conditions, requirements, subjects and scopes, each listing compared with a fresh `check()` in the same
  scope, its exceptions included, and the last decision and events left untouched, with cold and warm caches (seeded by
  `AUTHZ_PARITY_SEED`, `AUTHZ_PARITY_RUNS` runs).
- `Feature\PermissionsFor\AuthorizationManagerTest` -- grants, roles and denies, null as the manager's subject and the
  guest, a `Subject` and a model,
  another tenant, an application, a resource of another tenant and of a descendant, a resource-specific listing, the
  context, recording nothing, a failing provider restoring the scope, a throwing permission provider, an unreadable
  catalogue, the catalogue's order and bad enum entries.
- `PermissionsForQueryBudgetTest` -- fifty actions cost the queries five cost, with and without a resource, and with a
  condition reading `resource.*` through plain and bulk providers on a `ResourceReference` and a model; a listing in
  the current scope, and the check after it, cost no query once the request's memo is warm.
- `AuthorizationScopeTest`, `CheckBatchTest`, `PermissionCatalogueTest` and `HasPermissionsTest` -- the scope, the
  recording policy, the skipped entries and the delegate.

## Change Triggers

- Listing anything the catalogue does not declare, or computing a listing from allows and denies, breaks invariant 1.
- A listing that records or reports a decision breaks invariant 6.
- An enumeration contract for custom action catalogues would widen invariant 1's source and must keep it exact.
