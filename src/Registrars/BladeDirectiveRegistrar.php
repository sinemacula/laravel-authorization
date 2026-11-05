<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Blade;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;

/**
 * Register Blade directives for role and permission checks.
 *
 * The permission directives decide through the authorization manager's full
 * decision and the role directives check role membership, both on the subject
 * the bound resolver returns (see `BladeHelpers`). Every directive takes its
 * names as a string or a list, with `|` between names
 * (`@role('admin|editor')`), then an optional guard (`@role('admin', 'web')`),
 * which a role directive honours and a permission directive refuses.
 *
 * `Blade::if('role', …)` auto-generates the paired
 * `@role / @unlessrole / @elserole / @endrole` quartet; the same pattern covers
 * `@permission`, `@anyrole`, `@allroles`, `@anypermission`, and
 * `@allpermissions`. Spatie-style aliases (`@hasrole`, `@hasanyrole`,
 * `@hasallroles`, `@haspermission`, `@hasanypermission`, `@hasallpermissions`)
 * are registered in parallel so consumers migrating from Spatie can move their
 * views verbatim.
 *
 * Spatie closes its unless-variants with `@endunless<name>`, whereas
 * `Blade::if` closes its auto-generated variant with `@end<name>`. Every
 * canonical and compat name gets a matching `@endunless<name>` alias that emits
 * the same `endif;`, so both idioms compile cleanly regardless of which closing
 * spelling the consumer reaches for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class BladeDirectiveRegistrar
{
    /**
     * Create a new registrar instance.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     */
    public function __construct(

        /** Framework container consulted for the blade compiler binding. */
        private Application $app,
    ) {}

    /**
     * Register every role / permission Blade directive.
     *
     * The directives are registered only when the `blade.compiler` binding is
     * present, so console-only applications that do not resolve the view layer
     * never pay the registration cost.
     *
     * @return void
     */
    public function register(): void
    {
        if (!$this->app->bound('blade.compiler')) {
            return;
        }

        $roleNames       = ['role', 'anyrole', 'allroles', 'hasrole', 'hasanyrole', 'hasallroles'];
        $permissionNames = ['permission', 'anypermission', 'allpermissions', 'haspermission', 'hasanypermission', 'hasallpermissions'];

        $anyRole = static fn (array|string $roles, ?string $guard = null): bool => BladeHelpers::hasRole($roles, $guard);
        $allRole = static fn (array|string $roles, ?string $guard = null): bool => BladeHelpers::hasAllRoles($roles, $guard);
        $anyPerm = static fn (array|string $permissions, ?string $guard = null): bool => BladeHelpers::hasPermission($permissions, $guard);
        $allPerm = static fn (array|string $permissions, ?string $guard = null): bool => BladeHelpers::hasAllPermissions($permissions, $guard);

        Blade::if('role', $anyRole);
        Blade::if('anyrole', $anyRole);
        Blade::if('allroles', $allRole);
        Blade::if('hasrole', $anyRole);
        Blade::if('hasanyrole', $anyRole);
        Blade::if('hasallroles', $allRole);

        Blade::if('permission', $anyPerm);
        Blade::if('anypermission', $anyPerm);
        Blade::if('allpermissions', $allPerm);
        Blade::if('haspermission', $anyPerm);
        Blade::if('hasanypermission', $anyPerm);
        Blade::if('hasallpermissions', $allPerm);

        foreach ([...$roleNames, ...$permissionNames] as $name) {
            Blade::directive('endunless' . $name, static fn (): string => '<?php endif; ?>');
        }
    }
}
