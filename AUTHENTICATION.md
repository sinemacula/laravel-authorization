# Flags raised against `sinemacula/laravel-authentication`

Surfaced while restructuring `laravel-authorization` against
`laravel-authentication` as the structural reference. These are points where
authorization's conventions are stricter and authentication should be brought
into line — none are blocking for authorization's v1.0.

---

## Events are `final class`, not `final readonly class`

**Where:** every file under `src/Events/` (verified `PrincipalAssigned.php:16`,
`Refreshed.php:21`).

**Issue:** events are broadcast value objects; their properties should not be
reassignable after construction. Plain `final class` with public
constructor-promoted properties leaves them publicly writable. Authorization's
events use `final readonly class` (e.g. `IdentityRoleAssigned.php:20`), which
enforces single-binding at the language level.

**Note on Eloquent / SerializesModels:** `readonly` applies to the property
binding, not the referent. A `readonly Device $device` property still works
with `SerializesModels` and still permits the underlying model's own state to
change — only the slot itself becomes immutable.

**Fix:** change every `final class` event to `final readonly class`.

---

## Events lack the `@api` docblock tag

**Where:** every file under `src/Events/`.

**Issue:** events are part of the public contract — consumers attach listeners
keyed on the class FQCN and depend on the property surface. Without `@api`,
PHPStan and similar tooling cannot distinguish public-stable surface from
internal implementation, and the semver boundary is implicit. Authorization
marks every event with `@api` (see `IdentityRoleAssigned.php:15`) as part of
the same convention.

**Fix:** add `@api` to the class docblock of every event class.

---

## Exception suffix inconsistency: `InvalidDeviceModelConfiguration`

**Where:** `src/Exceptions/InvalidDeviceModelConfiguration.php`.

**Issue:** every other exception in the package carries the `Exception`
suffix — `DeviceTableAlreadyExistsException`, `UnresolvableIdentityException`,
`InvalidJwtConfigurationException`. This one is the odd-one-out. Inconsistent
naming makes exceptions harder to grep for and breaks the principle that the
class name should announce the kind from the import alone.

**Fix:** rename to `InvalidDeviceModelConfigurationException`.

---

## Unqualified global function calls

**Where:** widespread — `Database/MigrationCollisionGuard.php:48`,
`Exceptions/InvalidDeviceModelConfiguration.php:31-34, 51`,
`Providers/ModelProvider.php:53, 57`, `Guards/AbstractGuard.php:181`,
`Cache/StoreBackedResolutionCache.php:142`,
`Resolvers/DefaultPrincipalResolver.php:62`, `Traits/ActsAsPrincipal.php:48`,
others.

**Issue:** `sprintf(`, `class_exists(`, `is_subclass_of(`, etc. are called as
unqualified names from a non-root namespace. PHP looks up an unqualified call
in the current namespace before falling back to the global one, which:

- Costs a per-call namespace lookup the opcache cannot fully eliminate
- Defeats Slevomat's `SlevomatCodingStandard.Namespaces.FullyQualifiedGlobalFunctions`
  rule that catches typoed namespace-shadowed function calls

Authorization fully qualifies every global call (`\sprintf(`, `\class_exists(`,
`\is_string(`) — see `Evaluation/EvaluationResult.php:149-158`,
`Console/WhyCanCommand.php:83`, `AuthorizationServiceProvider.php` throughout.

**Fix:** prefix every global function call site with `\`. The `qlty fmt`
configuration probably needs the corresponding Slevomat sniff enabled to
prevent regression.

---

## Notes intentionally NOT flagged

- **`MigrationCollisionGuard` instance vs static** — authentication uses an
  instance method with a constructor-injected `Builder` (`final readonly class`,
  testable). Authorization currently uses a static method with the `Schema`
  facade. Authentication's pattern is the better one — that flag belongs in
  `ISSUES.md` against authorization, not against authentication.
- **Co-location of exceptions with their domain** (`Database/`, `Resolvers/`,
  `Jwt/`) — this is the *good* pattern authorization is being aligned with.
- **`Events/Enums/` and `Jwt/Enums/` nesting** — same: this is the pattern
  authorization is adopting, not a defect.
