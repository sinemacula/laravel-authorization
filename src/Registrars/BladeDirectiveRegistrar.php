<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Blade;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;

/**
 * Register Blade directives for role and permission checks.
 *
 * The permission directives decide through the authorization manager's full
 * decision and the role directives check role membership, both on the subject
 * the bound resolver returns (see `BladeHelpers`). Every directive takes its
 * names as a string or a list, with `|` between names
 * (`@role('admin|editor')`), then an optional guard (`@role('admin', 'web')`),
 * which a role directive honours and a permission directive refuses. A third
 * argument is refused rather than dropped.
 *
 * `Blade::if('role', …)` auto-generates the paired `@role / @unlessrole /
 *
 * @elserole / @endrole` quartet; the same pattern covers `@permission`,
 * `@anyrole`, `@allroles`, `@anypermission`, and `@allpermissions`.
 * Spatie-style aliases (`@hasrole`, `@hasanyrole`, `@hasallroles`,
 * `@haspermission`, `@hasanypermission`, `@hasallpermissions`) are registered
 * in parallel so consumers migrating from Spatie can move their views verbatim.
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
    /** @var list<string> The conditional directives registered, each with its `endunless` pair. */
    public const array DIRECTIVES = [
        'role', 'anyrole', 'allroles', 'hasrole', 'hasanyrole', 'hasallroles',
        'permission', 'anypermission', 'allpermissions', 'haspermission', 'hasanypermission', 'hasallpermissions',
    ];

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

        $anyRole = BladeHelpers::hasRole(...);
        $allRole = BladeHelpers::hasAllRoles(...);
        $anyPerm = BladeHelpers::hasPermission(...);
        $allPerm = BladeHelpers::hasAllPermissions(...);

        $directives = [
            'role'              => $anyRole,
            'anyrole'           => $anyRole,
            'allroles'          => $allRole,
            'hasrole'           => $anyRole,
            'hasanyrole'        => $anyRole,
            'hasallroles'       => $allRole,
            'permission'        => $anyPerm,
            'anypermission'     => $anyPerm,
            'allpermissions'    => $allPerm,
            'haspermission'     => $anyPerm,
            'hasanypermission'  => $anyPerm,
            'hasallpermissions' => $allPerm,
        ];

        foreach ($directives as $name => $check) {
            Blade::if($name, self::condition($name, $check));
            Blade::directive('endunless' . $name, static fn (): string => '<?php endif; ?>');
        }
    }

    /**
     * Return the condition a directive compiles into: the check, given the
     * names and the optional guard, refusing any further argument.
     *
     * @param  string  $name
     * @param  \Closure(array<int, string>|string, ?string): bool  $check
     * @return \Closure(array<int, string>|string, ?string, mixed...): bool
     */
    private static function condition(string $name, \Closure $check): \Closure
    {
        return static function (array|string $names, ?string $guard = null, mixed ...$extra) use ($name, $check): bool {
            if ($extra !== []) {
                throw InvalidCheckArgumentException::tooManyDirectiveArguments($name, 2 + \count($extra));
            }

            return $check($names, $guard);
        };
    }
}
